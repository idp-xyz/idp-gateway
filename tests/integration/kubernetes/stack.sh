#!/usr/bin/env bash
# 在本机起一个只供本仓库用的 kind 集群，用来验证 ADR-0010：standalone 模式的 agentgateway，
# 每份快照一个不可变的 ConfigMap，发布就是滚动替换。
#
# 集群叫 idp-gateway-k8s。它的 kubeconfig 只写在本目录的 .run/ 里（已被 git 忽略）：本脚本不读也
# 不改 ~/.kube/config，不动本机上别的 kind 集群。
#
# 用例要用的三个镜像（锁定的上游 agentgateway 镜像、与黑盒套件相同的前置 nginx、一个带 Python 的
# 工具镜像）都按摘要引用，由集群节点自己去拉：节点要够得着 cr.agentgateway.dev 和 public.ecr.aws。
# 这里不往集群里预装镜像。
#
#   ./stack.sh up      建集群（已存在则沿用）
#   ./stack.sh down    删除这个集群、它的 kubeconfig 和上一次运行的结果
#   ./stack.sh status  看集群和节点
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN="$HERE/.run"
CLUSTER=idp-gateway-k8s
# 节点镜像用本机已有的；本机到不了 Docker Hub。
NODE_IMAGE=kindest/node:v1.35.0
STAGING_CONTAINER=idp-gateway-k8s-staging   # run.py 做离线加载时起的容器

export PATH="$HOME/.local/bin:$PATH"
# kind 和 kubectl 都只认这一个文件。
export KUBECONFIG="$RUN/kubeconfig"

die() { echo "stack.sh: $*" >&2; exit 1; }

for tool in kind kubectl docker; do
  command -v "$tool" >/dev/null || die "找不到 $tool"
done

exists() { kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; }

case "${1:-}" in
  up)
    mkdir -p "$RUN" && chmod 700 "$RUN"
    docker image inspect "$NODE_IMAGE" >/dev/null 2>&1 || die "本机没有节点镜像 $NODE_IMAGE"
    if exists; then
      kind export kubeconfig --name "$CLUSTER" --kubeconfig "$KUBECONFIG" >/dev/null 2>&1 || die "取不到集群的 kubeconfig"
    else
      kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE" --kubeconfig "$KUBECONFIG" --wait 180s
    fi
    chmod 600 "$KUBECONFIG"
    echo "就绪。集群 $CLUSTER，节点镜像 $NODE_IMAGE"
    kubectl get nodes -o wide
    ;;
  down)
    if exists; then
      kind delete cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG"
    fi
    docker rm -f "$STAGING_CONTAINER" >/dev/null 2>&1 || true
    rm -rf "$KUBECONFIG" "$RUN/result.json" "$RUN/tls" "$RUN/staging"
    ;;
  status)
    exists || die "集群 $CLUSTER 不存在：先运行 ./stack.sh up"
    kubectl get nodes -o wide
    kubectl get pods -A
    ;;
  *)
    sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
