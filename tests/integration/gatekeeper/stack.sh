#!/usr/bin/env bash
# 在本机起一套只供本仓库联调的 Gatekeeper。
#
# Gatekeeper 的代码来自一份只读检出（GK_SRC），这里不往里写任何文件；证书、密钥、下载的二进制都放在
# 本目录的 .run/ 里（已被 git 忽略）。容器、网络、卷都归在独立的 compose 项目 idp-gateway-gk 名下，
# 与本机上其它项目（包括 Gatekeeper 自己的开发栈 idp-gatekeeper）互不相干。
#
# 已发布的 gk.idp.xyz 是生产环境，本脚本和联调都不碰它。
#
#   ./stack.sh up      构建并拉起，等到就绪
#   ./stack.sh down    停掉并删除容器、网络和卷，连同测试客户端的凭据文件（本地构建的镜像保留）
#   ./stack.sh ps      看状态
#   ./stack.sh logs [服务名...]
#   ./stack.sh env     打印联调要用的地址（不打印密钥）
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT=idp-gateway-gk
HYDRA_PORT=27621
BRIDGE_PORT=27622

export GK_SRC="${GK_SRC:-$HOME/.local/src/idp-gatekeeper}"
export GK_RUN="$HERE/.run"
# 授权模型默认是 Gatekeeper 自己的模型加上 provider-account.types.json 里的类型。后者是本仓库的
# 提议，Gatekeeper 的仓库和已发布的实例里都没有；它只存在于这套本地环境。
# 把 GK_OPENFGA_MODEL 指向别的文件可以换成任意模型，包括 Gatekeeper 原样的 deploy/openfga/model.json。
GK_OPENFGA_MODEL="${GK_OPENFGA_MODEL:-}"

# Hydra 官方发布的静态二进制，版本与 Gatekeeper 的 compose 文件写定的镜像版本一致。
HYDRA_VERSION=26.2.0
HYDRA_ASSET="hydra_${HYDRA_VERSION}-linux_static-nosqlite_64bit.tar.gz"
HYDRA_SHA256=7b0bb4f5f25ea08b22694bc4a1d1319c7c94fea9c1b96ae2a1f2f0dbbf6bdfa9

die() { echo "stack.sh: $*" >&2; exit 1; }

compose() {
  docker compose -p "$PROJECT" --env-file "$GK_RUN/stack.env" \
    -f "$GK_SRC/deploy/compose/docker-compose.yml" -f "$HERE/compose.local.yml" "$@"
}

prepare() {
  [ -f "$GK_SRC/deploy/compose/docker-compose.yml" ] || die "找不到 Gatekeeper 的检出：$GK_SRC"
  mkdir -p "$GK_RUN" && chmod 700 "$GK_RUN"

  if [ -z "$GK_OPENFGA_MODEL" ]; then
    GK_OPENFGA_MODEL="$GK_RUN/openfga-model.json"
    jq --slurpfile extra "$HERE/provider-account.types.json" '.type_definitions += $extra[0]' \
      "$GK_SRC/deploy/openfga/model.json" > "$GK_OPENFGA_MODEL.tmp" || die "合并授权模型失败"
    # 内容没变就不动文件：login-consent 挂载的是它。
    if cmp -s "$GK_OPENFGA_MODEL.tmp" "$GK_OPENFGA_MODEL"; then rm -f "$GK_OPENFGA_MODEL.tmp"; else mv "$GK_OPENFGA_MODEL.tmp" "$GK_OPENFGA_MODEL"; fi
  fi
  [ -f "$GK_OPENFGA_MODEL" ] || die "找不到授权模型：$GK_OPENFGA_MODEL"
  export GK_OPENFGA_MODEL

  # 每套环境自己的密钥，只写在 .run/ 里。
  if [ ! -s "$GK_RUN/stack.env" ]; then
    ( umask 077
      { echo "ADMIN_API_KEY=$(openssl rand -hex 24)"
        echo "GK_PDP_AUTH_TOKEN=$(openssl rand -hex 24)"
      } > "$GK_RUN/stack.env" )
  fi

  # 控制面 mTLS 的开发证书：用 Gatekeeper 的脚本生成，但生成在 .run/ 里。
  if [ ! -s "$GK_RUN/certs/ca.crt" ]; then
    cp "$GK_SRC/deploy/compose/gen-certs.sh" "$GK_RUN/gen-certs.sh"
    bash "$GK_RUN/gen-certs.sh" >/dev/null 2>&1 || die "生成证书失败"
  fi

  if [ ! -x "$GK_RUN/hydra/hydra" ]; then
    mkdir -p "$GK_RUN/hydra"
    local tarball="$GK_RUN/hydra/$HYDRA_ASSET"
    curl -fsSL --retry 3 -m 600 -o "$tarball" \
      "https://github.com/ory/hydra/releases/download/v$HYDRA_VERSION/$HYDRA_ASSET" || die "下载 Hydra 失败"
    echo "$HYDRA_SHA256  $tarball" | sha256sum -c --quiet - || die "Hydra 发布包的校验和不符"
    tar -xzf "$tarball" -C "$GK_RUN/hydra" hydra
    rm -f "$tarball"
    chmod 755 "$GK_RUN/hydra/hydra"
  fi

  # 模型内容决定库名：Gatekeeper 只给空库写模型。
  GK_OPENFGA_STORE="idp-gateway-local-$(sha256sum "$GK_OPENFGA_MODEL" | cut -c1-12)"
  export GK_OPENFGA_STORE

  # 项目名必须是我们自己的；Gatekeeper 的 compose 文件里写了它自己的项目名。
  [ "$(compose config --format json | jq -r .name)" = "$PROJECT" ] || die "compose 项目名不是 $PROJECT，拒绝继续"
}

wait_ready() {
  local i
  for i in $(seq 1 90); do
    if curl -fsS -m 3 -o /dev/null "http://127.0.0.1:$HYDRA_PORT/health/ready" 2>/dev/null &&
       curl -fsS -m 3 -o /dev/null "http://127.0.0.1:$BRIDGE_PORT/admin/me" 2>/dev/null; then
      return 0
    fi
    sleep 2
  done
  return 1
}

case "${1:-}" in
  up)
    prepare
    compose build -q
    compose up -d --quiet-pull
    wait_ready || { compose ps -a; die "没有在限定时间内就绪，见 ./stack.sh logs"; }
    echo "就绪。Gatekeeper 检出：$(git -C "$GK_SRC" rev-parse --short HEAD)；授权模型库：$GK_OPENFGA_STORE"
    "$0" env
    ;;
  down)
    prepare
    compose down -v --remove-orphans
    # 卷没了，里面的租户和客户端也就没了；留着它们的凭据文件只会让下一次联调拿着失效的凭据。
    rm -f "$GK_RUN/clients.json" "$GK_RUN/result.json"
    ;;
  ps)
    prepare
    compose ps -a
    ;;
  logs)
    prepare
    shift
    compose logs --no-color --tail 200 "$@"
    ;;
  env)
    echo "GK_ISSUER=http://127.0.0.1:$HYDRA_PORT"
    echo "GK_JWKS_URL=http://127.0.0.1:$HYDRA_PORT/.well-known/jwks.json"
    echo "GK_TOKEN_URL=http://127.0.0.1:$HYDRA_PORT/oauth2/token"
    echo "GK_BRIDGE_URL=http://127.0.0.1:$BRIDGE_PORT"
    echo "GK_SECRETS_FILE=$GK_RUN/stack.env"
    ;;
  *)
    sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
