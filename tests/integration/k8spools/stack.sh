#!/usr/bin/env bash
# Kind cluster for ADR-0025 egress pool evidence. Own name; kubeconfig only under this .run/.
# Does not read or write ~/.kube/config. Does not touch the cluster named "kind".
#
#   ./stack.sh up | down | status
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN="$HERE/.run"
CLUSTER=idp-gateway-pools
NODE_IMAGE=kindest/node:v1.35.0
STAGING_CONTAINER=idp-gateway-pools-staging

export PATH="$HOME/.local/bin:$PATH"
export KUBECONFIG="$RUN/kubeconfig"

die() { echo "stack.sh: $*" >&2; exit 1; }

for tool in kind kubectl docker; do
  command -v "$tool" >/dev/null || die "missing $tool"
done

exists() { kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; }

case "${1:-}" in
  up)
    mkdir -p "$RUN" && chmod 700 "$RUN"
    docker image inspect "$NODE_IMAGE" >/dev/null 2>&1 || die "missing node image $NODE_IMAGE"
    if exists; then
      kind export kubeconfig --name "$CLUSTER" --kubeconfig "$KUBECONFIG" >/dev/null 2>&1 || die "kubeconfig export failed"
    else
      kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE" --kubeconfig "$KUBECONFIG" --wait 180s
    fi
    chmod 600 "$KUBECONFIG"
    echo "ready: cluster $CLUSTER, node $NODE_IMAGE"
    kubectl get nodes -o wide
    ;;
  down)
    if exists; then
      kind delete cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG"
    fi
    docker rm -f "$STAGING_CONTAINER" >/dev/null 2>&1 || true
    rm -rf "$KUBECONFIG" "$RUN/result.json" "$RUN/tls" "$RUN/staging" "$RUN/bin" "$RUN/images" "$RUN/work"
    ;;
  status)
    exists || die "cluster $CLUSTER missing; run ./stack.sh up"
    kubectl get nodes -o wide
    kubectl get pods -A
    ;;
  *)
    sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
