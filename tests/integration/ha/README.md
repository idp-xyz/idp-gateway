# 双副本 HA：租约协调 + 证书热重载

这不是验收通过。它只说明：真实的 `sf-token-coordinator` 和两个 `gateway-authz` 进程，加上回环上的顺丰令牌替身，在一台机器上能不能共享同一枚访问令牌、重启后仍拿走同一枚、协调器停了之后失败关闭、以及监听叶子证书不重启就能换。没有 agentgateway，没有 Gatekeeper，没有 `provider-signer`，不接生产。

替身是套件进程里的 `ThreadingHTTPServer`：每次签发新令牌就作废上一枚；`GET /admin/hits` 只回报次数和寿命，不回令牌原文。`expireIn` 取 7200（与承运商生产寿命同形）。冷启动时客户端的 `Acquire` 会带上 `MaxRefreshLead`（10 分钟）；寿命短于这个提前量的刚提交租约，对另一副本会被看成不可用，再发一次 `FETCH`——所以本套件不用短寿命令牌做共享用例。

启动子进程和访问本机之前都会去掉名字里带 `proxy` 的环境变量。工作目录在 `/tmp`（0700），不论成败都删掉。证书和密钥每次现做，不进仓库。日志和套件输出里的令牌、`app_secret`、`encoding_aes_key` 会打成 `[redacted]`。

```bash
export PATH=/usr/local/go/bin:$PATH
cd /home/tops/workspace/idp-gateway
.venv/bin/python tests/integration/ha/run.py
.venv/bin/python tests/integration/ha/run.py --control no-lease-mutual-kick
.venv/bin/python tests/integration/ha/run.py --control wrong-identity
```

默认那一遍不带 `--control`。端口只用 27841–27855。与 fabric（27721–27735）、blackbox / Gatekeeper / sfintl（27611–27619）不重叠。启动前若其中一口已有人在听，套件拒绝启动。

| 端口 | 谁 |
|---|---|
| 27841 | 顺丰令牌替身（明文 HTTP） |
| 27842 | `sf-token-coordinator`（mTLS） |
| 27843 | `gateway-authz` A（mTLS） |
| 27844 | `gateway-authz` B（mTLS） |
| 27845–27855 | 这一段留着，套件不听 |

两个 `gateway-authz` 共用同一 SPIFFE URI（`spiffe://idp.test/ha/gateway-authz`），叶子序列号可以不同。协调器 `--authz-identity` 就是这个 URI。调用方是 `spiffe://idp.test/ha/gateway`，直接 `GET /v1/extauthz/check`；不传 `--gatekeeper-url`，只看本地登记表。五个 `--sf-openapi-lease-*` 都指向协调器；`--sf-openapi-plain-http-host` 是 `127.0.0.1`。

| 用例 | 要看到的 |
|---|---|
| HA-01 | 对 A、B 各 8 路并发判定；替身令牌端点恰好 1 次；16 个 `Authorization` 都是 `Sf-OpenApi …` 且令牌相同；A/B 的 PID 不变 |
| HA-02 | 停掉 B 再起一个空本地缓存的 B；再判定仍是同一枚令牌；承运商调用总数仍是 1 |
| HA-04 | 原子改名换掉 A 的监听叶子（以及协调器服务端叶子）；新握手看到新序列号；A/B/协调器 PID 都不变 |
| HA-03 | 先停协调器，再重启 A 和 B（清空本地缓存，强制走 `Acquire`）；两边都是 503 `INDETERMINATE` / `CREDENTIAL_UNAVAILABLE`；日志有 `lease_unavailable`；承运商不再被调用 |
| cleanup | 27841–27855 上没有人在听 |

`--control no-lease-mutual-kick` 起两个**不带**租约参数的 `gateway-authz`，对着作废旧票的替身；期望承运商至少被叫 2 次，或令牌分叉——说明为什么要有协调器。`--control wrong-identity` 用错误 SPIFFE 打判定口，期望 401，承运商 0 次。对照确认预期失败之后退出码是 0。默认运行不含这两次。

## 这一次

2026-11-24，默认那一遍连续跑了两次，退出码都是 0。每遍 5 个用例、**27/27** 项检查。`--control no-lease-mutual-kick` 是 4/4（承运商 2 次，两个不同令牌）。`--control wrong-identity` 是 4/4（401，承运商 0 次）。两次对照的退出码都是 0。

| 用例 | 结果 |
|---|---|
| HA-01 | 通过。16/16 为 200，承运商 1 次，令牌相同，PID 不变 |
| HA-02 | 通过。重启后的 B 仍拿同一枚，承运商仍是 1 |
| HA-04 | 通过。新序列号握手成功；协调器叶子也换过；PID 不变 |
| HA-03 | 通过。协调器停后空缓存的 A/B 都是 503，`lease_unavailable`，承运商不再增加 |
| cleanup | 通过。套件端口上空闲 |
| no-lease-mutual-kick | 对照成立。承运商 ≥2，令牌分叉 |
| wrong-identity | 对照成立。401，无 `Authorization`，承运商 0 |

这不是验收通过。黑盒没有重跑。正式门禁仍是 `NOT_RUN`。ADR-0021 / ADR-0022 仍是 Proposed。
