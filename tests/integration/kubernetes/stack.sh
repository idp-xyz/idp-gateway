#!/usr/bin/env bash
# 在本机起一个只供本仓库用的 kind 集群，用来验证 ADR-0010：standalone 模式的 agentgateway，
# 配置经 ConfigMap 下发。
#
# 集群叫 idp-gateway-k8s。它的 kubeconfig 只写在本目录的 .run/ 里（已被 git 忽略）：本脚本不读也
# 不改 ~/.kube/config，不动本机上别的 kind 集群。网关镜像在本地用锁定的那个二进制打包后装进集群，
# 不经过任何镜像仓库。
#
#   ./stack.sh up      建集群（已存在则沿用），打包并装入网关镜像
#   ./stack.sh down    删除这个集群、它的 kubeconfig 和本地打包的镜像
#   ./stack.sh status  看集群和节点
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
RUN="$HERE/.run"
CLUSTER=idp-gateway-k8s
# 节点镜像和基础镜像都用本机已有的；本机到不了 Docker Hub。
NODE_IMAGE=kindest/node:v1.35.0
BASE_IMAGE=public.ecr.aws/docker/library/alpine:3.22

export PATH="$HOME/.local/bin:$PATH"
# kind 和 kubectl 都只认这一个文件。
export KUBECONFIG="$RUN/kubeconfig"

die() { echo "stack.sh: $*" >&2; exit 1; }

for tool in kind kubectl docker jq; do
  command -v "$tool" >/dev/null || die "找不到 $tool"
done

VERSION="$(jq -r .version "$ROOT/deploy/agentgateway/agentgateway.lock.json")"
IMAGE="idp-gateway-k8s/agentgateway:$VERSION"

exists() { kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; }

build_image() {
  # 二进制由 pin.py 找到并按锁定文件核对；不是锁定的那个发布版就在这里停下。
  local binary context
  binary="$("$ROOT/.venv/bin/python" -c 'import sys; sys.path.insert(0, sys.argv[1]); import pin
try:
    print(pin.resolve()[0])
except pin.PinError as e:
    sys.exit(str(e))' "$ROOT/tests/acceptance/blackbox")" || die "没有可用的 agentgateway $VERSION 二进制"
  context="$RUN/image"
  rm -rf "$context" && mkdir -p "$context"
  cp "$binary" "$context/agentgateway"
  docker build -q -t "$IMAGE" -f - "$context" >/dev/null <<EOF || die "打包镜像失败"
FROM $BASE_IMAGE
COPY agentgateway /usr/local/bin/agentgateway
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/agentgateway"]
EOF
  rm -rf "$context"
}

case "${1:-}" in
  up)
    mkdir -p "$RUN" && chmod 700 "$RUN"
    docker image inspect "$NODE_IMAGE" >/dev/null 2>&1 || die "本机没有节点镜像 $NODE_IMAGE"
    docker image inspect "$BASE_IMAGE" >/dev/null 2>&1 || die "本机没有基础镜像 $BASE_IMAGE"
    build_image
    if exists; then
      kind export kubeconfig --name "$CLUSTER" --kubeconfig "$KUBECONFIG" >/dev/null 2>&1 || die "取不到集群的 kubeconfig"
    else
      kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE" --kubeconfig "$KUBECONFIG" --wait 180s
    fi
    chmod 600 "$KUBECONFIG"
    kind load docker-image "$IMAGE" --name "$CLUSTER" >/dev/null 2>&1 || die "镜像装不进集群"
    echo "就绪。集群 $CLUSTER，节点镜像 $NODE_IMAGE，网关镜像 $IMAGE（本地打包）"
    kubectl get nodes -o wide
    ;;
  down)
    if exists; then
      kind delete cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG"
    fi
    rm -f "$KUBECONFIG" "$RUN/result.json"
    docker image rm "$IMAGE" >/dev/null 2>&1 || true
    ;;
  status)
    exists || die "集群 $CLUSTER 不存在：先运行 ./stack.sh up"
    kubectl get nodes -o wide
    kubectl get pods -A
    ;;
  *)
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
