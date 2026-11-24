# Kubernetes 出站池套件（ADR-0025）

> **这不是验收通过。** 正式门禁仍为 `NOT_RUN`。执笔与跑套件的是 AI 编码助手。状态 Proposed。

在本机 kind 集群 `idp-gateway-pools` 上验证出站池：front + agentgateway、gateway-authz×2、provider-signer×2、两个协调器、NetworkPolicy、不可变快照滚动。kubeconfig 只写在本目录 `.run/`（已 git 忽略）；不读不改 `~/.kube/config`，不动名为 `kind` 的另一个项目的集群，不碰生产 Gatekeeper。

## 怎么跑

```bash
export PATH=/usr/local/go/bin:$PATH
cd /home/tops/workspace/idp-gateway
tests/integration/k8spools/stack.sh up
.venv/bin/python tests/integration/k8spools/run.py
.venv/bin/python tests/integration/k8spools/run.py          # 默认再跑一遍
.venv/bin/python tests/integration/k8spools/run.py --control no-netpol
.venv/bin/python tests/integration/k8spools/run.py --control no-coordinators
tests/integration/k8spools/stack.sh down
```

主机回环只占用 **27901–27915**（若占用会先拒绝启动）。节点镜像 `kindest/node:v1.35.0` 须本机已有。

## 用例

| 用例 | 内容 |
|---|---|
| KP8-01 | 拓扑与硬化：副本数、Recreate、PVC Bound、Pod 安全字段、镜像摘要/内容标签 |
| KP8-02 | 经 front 的顺丰替身端到端：JWT、200、调用方不见承运商凭证、两副本租约只取票 1 次 |
| KP8-03a | **先量** kind CNI 是否执行 NetworkPolicy（去掉全部策略后 Pod IP 能通；只留 deny-all 后同 IP 被挡） |
| KP8-03 | 禁止路径拒绝、允许路径仍通（若 03a 不执行则记为未展示） |
| KP8-04 | 经一个 authz Pod IP 用 `gateway-control` 撤销 → 403 ACCOUNT_REVOKED；恢复 → 200 |
| KP8-05 | 共享配额 max 1 → 第二次 429 RATE_LIMITED，无 Authorization |
| KP8-06 | 删一个 authz Pod：统计失败；替身不新取票 |
| KP8-07 | 删 authz-state：503 REVOCATION_STATE_UNAVAILABLE；PVC 上撤销表仍在；配额桶重启即满 |
| KP8-08 | 滚动发布新不可变快照：统计失败；旧 ConfigMap 仍在 |
| KP8-09 | 日志/输出无 app secret、AES、承运商令牌、私钥正文 |

对照（预期坏事发生后退出码 0）：

- `--control no-netpol`：不应用策略时，禁止连接能通
- `--control no-coordinators`：authz 不带租约/状态参数时，两副本取票 ≥ 2 次

## 结果（2026-11-24 实测）

**这不是验收通过。** 正式门禁仍为 `NOT_RUN`。

| 路径 | 开始 (UTC) | 结束 (UTC) | 退出码 | 检查 |
|---|---|---|---|---|
| 默认 run1 | 2026-11-24T11:20:14Z | 2026-11-24T11:21:22Z | 0 | 48/48 |
| 默认 run2 | 2026-11-24T11:22:40Z | 2026-11-24T11:23:47Z | 0 | 48/48 |
| `--control no-netpol` | 2026-11-24T11:17:22Z | 2026-11-24T11:17:28Z | 0 | 6/6 |
| `--control no-coordinators` | 2026-11-24T11:18:26Z | 2026-11-24T11:18:32Z | 0 | 15/15 |

- **NetworkPolicy on kind：执行。** 先删掉命名空间内全部 NetworkPolicy，netpol-b 用 Pod IP 连 netpol-a:8000 得 `OPEN`；再只应用 `default-deny-all`，同连接得 `BLOCKED`。随后完整策略下禁止路径被挡、front 仍 200。
- **KP8-06（删一个 gateway-authz）**：run1 ≈6.9s、16 请求、hard_failures=1；run2 ≈6.7s、16 请求、hard_failures=1；无新承运商取票。
- **KP8-08（滚动发布）**：run1 ≈10.1s、21 请求、hard_failures=0；run2 ≈9.7s、20 请求、hard_failures=0；旧不可变 ConfigMap 仍在。
- 命名空间 `enforce=privileged`（接纳探针/辅助 Pod），`warn`/`audit=restricted`。证书由套件现做。Secret 热重载未单独量（未展示）。Gatekeeper PDP 在 kind 叠加中去掉（未练）。

这不是验收通过。
