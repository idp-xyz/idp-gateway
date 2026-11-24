# 双副本：撤销、封禁与配额协调

这不是验收通过。它只说明：真实的 `authz-state` 和两个 `gateway-authz` 进程，在一台机器上能不能让 A 上的撤销和封禁被 B 看见、让两边共用同一只配额桶，以及协调器停了之后失败关闭。没有 agentgateway，没有 Gatekeeper，没有 Docker，不接生产。凭证是固定的 Bearer，没有承运商。

启动子进程和访问本机之前都会去掉名字里带 `proxy` 的环境变量。工作目录在 `/tmp`（0700），不论成败都删掉。证书和密钥每次现做，不进仓库。日志和套件输出里的 Bearer 令牌会打成 `[redacted]`。

```bash
export PATH=/usr/local/go/bin:$PATH
cd /home/tops/workspace/idp-gateway
.venv/bin/python tests/integration/authzstate/run.py
.venv/bin/python tests/integration/authzstate/run.py --control no-state
.venv/bin/python tests/integration/authzstate/run.py --control wrong-identity
```

默认那一遍不带 `--control`。端口只用 27861–27875。与 HA（27841–27855）、fabric（27721–27735）不重叠。启动前若其中一口已有人在听，套件拒绝启动。

| 端口 | 谁 |
|---|---|
| 27861 | `authz-state`（mTLS） |
| 27862 | `gateway-authz` A（mTLS） |
| 27863 | `gateway-authz` B（mTLS） |
| 27864–27875 | 这一段留着，套件不听 |

两个 `gateway-authz` 共用同一 SPIFFE URI（`spiffe://idp.test/as/gateway-authz`）。协调器 `--authz-identity` 就是这个 URI。调用方是 `spiffe://idp.test/as/gateway`，撤销者是 `spiffe://idp.test/as/revoker`。直接打 `/v1/extauthz/check`；不传 `--gatekeeper-url`。五个 `--authz-state-*` 都指向协调器。A 和 B 各有自己的 `--revocations` 文件，所以撤销不是靠共享同一个文件传过去的。配额文件是 `max_requests=1`、`window_seconds=3600`，按 `provider_account` 分桶。

套件先跑 AS-02，再跑 AS-01。`account-blue` 只有一次共享配额；「另一个操作仍然放行」要在这个账户被撤销之前用掉那一次。

| 用例 | 要看到的 |
|---|---|
| AS-02 | 在 A 上封禁 `tracking.get`；B 对该操作是 403 `OPERATION_BANNED`；B 上 `labels.print` 仍是 200；A、B、协调器的 PID 不变 |
| AS-01 | 在 A 上撤销 `account-blue`；B 的下一次检查是 403 `ACCOUNT_REVOKED`；代次比刚才那次放行更大；A 和 B 的 PID 不变 |
| AS-03 | `account-green` 共享配额最多 1 次：A 第一次 200，B 接着是 429 `RATE_LIMITED`，应答里没有 `Authorization` |
| AS-04 | 停掉协调器；A 和 B 的下一次检查都是 503 `INDETERMINATE` / `REVOCATION_STATE_UNAVAILABLE`，不是 200 |
| cleanup | 27861–27875 上没有人在听 |

`--control no-state` 起两个**不带** `--authz-state-*` 的 `gateway-authz`，配额仍是 `max_requests=1`。同一个账户在 A 和 B 上都是 200：本地桶不共享，这就是协调器要补的那一截。`--control wrong-identity` 用错误 SPIFFE 打判定口，以及用一份解析不了的正文打协调器，都是 401。对照确认预期的事发生之后退出码是 0。默认运行不含这两次。

## 这一次

2026-11-24，默认那一遍连续跑了两次，退出码都是 0。每遍 5 个用例、**16/16** 项检查。`--control no-state` 是 4/4（A、B 都是 200）。`--control wrong-identity` 是 5/5（判定口和协调器都是 401，协调器日志里没有那份坏正文）。默认两遍和两次对照的退出码都是 0。这不是验收通过。正式门禁仍是 `NOT_RUN`。ADR-0023 仍是 Proposed。2026-11-24 另从干净的 `f8dc7c8` 重跑了黑盒，97/97（证据 `69bffbe`）；黑盒不传协调参数，也不启动本套件。

| 用例 | 结果 |
|---|---|
| AS-02 | 通过。封禁之后 B 是 403 `OPERATION_BANNED`，另一操作 200，PID 不变。放行时代次是 1 |
| AS-01 | 通过。B 是 403 `ACCOUNT_REVOKED`，代次变为 2，A 和 B 的 PID 不变 |
| AS-03 | 通过。A 为 200，B 为 429 `RATE_LIMITED`，没有凭证头 |
| AS-04 | 通过。协调器停后 A 和 B 都是 503 `REVOCATION_STATE_UNAVAILABLE`，不是 200 |
| cleanup | 通过。套件端口上空闲 |
| no-state | 对照成立。不带协调参数时 A 和 B 都是 200 |
| wrong-identity | 对照成立。401，坏正文没有进协调器日志 |

这不是验收通过。正式门禁仍是 `NOT_RUN`。ADR-0023 仍是 Proposed。
