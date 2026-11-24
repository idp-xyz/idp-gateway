# Kubernetes 出站池清单

[ADR-0025](../../docs/adr/ADR-0025.md)（Proposed）把出站池搬到 Kubernetes：纯 YAML + kustomize，不用 Helm。  
布局：`egress/base/`（生产形状的底稿）和 `egress/overlays/kind/`（本机 kind 测试叠加：去掉 Gatekeeper PDP 参数）。

```bash
# 只看渲染结果（不需要集群）
kubectl kustomize deploy/kubernetes/egress/overlays/kind

# 机制套件（自有集群 idp-gateway-pools，kubeconfig 在套件 .run/）
tests/integration/k8spools/stack.sh up
.venv/bin/python tests/integration/k8spools/run.py
tests/integration/k8spools/stack.sh down
```

镜像配方在 `images/Dockerfile.binary`（`FROM scratch`）。上游 agentgateway 仍按 `deploy/agentgateway/agentgateway.lock.json` 的摘要。  
这不是验收通过。正式门禁仍是 `NOT_RUN`。
