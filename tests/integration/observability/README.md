# 回环上的 Trace 证据

这不是验收通过，也不是签过的 SLO。它只说明：`gateway-control compile` 把 `pool.tracing` 写成 `frontendPolicies.tracing` 之后，锁定的 agentgateway 1.7.0 会怎样。二进制是 `~/.local/opt/agentgateway/1.7.0/agentgateway`，SHA-256 要与 `deploy/agentgateway/agentgateway.lock.json` 里的 `c7ef326b7b5702451e94bab55ff484d600d5abdc5344a4cdf7c72fc0bcff9e24` 相同。

```bash
/home/tops/workspace/idp-gateway/.venv/bin/python tests/integration/observability/run.py
/home/tops/workspace/idp-gateway/.venv/bin/python tests/integration/observability/run.py --control drop-tracing
```

默认那一遍不带 `--control`。端口只用 27701–27709。套件退出时这些端口上不能还有人在听。收集器是套件进程里的回环 HTTP 服务，不另起镜像。它对 `application/json` 和 protobuf 都答 HTTP 200，留下原始正文和 `Content-Type`。trace id 只要以 32 位十六进制，或那 16 个原始字节，出现在正文里，就算到了。数据面的内容类型以留下的 `Content-Type` 为准，不按收集器自己的应答猜。

规格是一份小的 AI / A2A 文档，`environment` 是 `TEST`，上游和收集器都是 `127.0.0.1`。调用方带一张只给这一次用的 JWT。不写 `tracing` 的那一份，编出来的 YAML 里没有 `tracing:`。

| 用例 | 要看到的 |
|---|---|
| A | 调用方不送 `traceparent`。上游替身收到一条 W3C `traceparent`。收集器的正文里有同一个 trace id |
| B | 调用方送 `00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01`。上游和收集器保持这个 trace id。span id 可以不同 |
| C | 收集器没有在听。数据面这一笔仍然成功 |
| D | 同一份规格不写 `tracing`。上游看不到 `traceparent`。这是 2026-11-21 量过的那一条，还要成立 |
| authz | `gateway-authz` 用它自己的 `--otlp-traces-url`、`--audit-log`、`--metrics-listen` 做一次放行。审计文件是一行 JSONL、权限 0600，行里没有令牌、secret 或 authorization。明文 `/metrics` 里有 `idp_gateway_authz_decisions_total`。mTLS 端口的 `/metrics` 不是这份指标 |

`--control drop-tracing` 从编出来的文件里删掉 `tracing` 那一块，其余字节与不写 `tracing` 的编译结果相同，然后只跑 A 的请求。A 的「上游出现 traceparent」不成立，这一遍才算对照成功。默认运行不需要这个参数。

`pin-egress.sh` 用 `sed` 摘 `host:` 行，再去掉引号。编出来的 `host: '127.0.0.1:<收集器端口>'` 要能被摘出来。摘不出来才改脚本。

## 这一次

2026-11-23，默认那一遍跑了两次，退出码都是 0。`--control drop-tracing` 跑了一次，退出码是 0。二进制 SHA-256 是 `c7ef326b7b5702451e94bab55ff484d600d5abdc5344a4cdf7c72fc0bcff9e24`。这不是验收通过。

| 用例 | 结果 |
|---|---|
| compile | 通过。不写 tracing 的文件里没有 `tracing:`。删掉 tracing 块之后与那份相同。`pin-egress.sh` 的 `sed` 摘出了 `127.0.0.1:27706`、`127.0.0.1:27705`、`127.0.0.1:27707`。脚本没有改 |
| A | 通过。调用方没送 `traceparent`。上游有一条，标志 `01`。收集器是 `POST /v1/traces`，`Content-Type: application/x-protobuf`，正文里有同一个 trace id |
| B | 通过。trace id 仍是 `4bf92f3577b34da6a3ce929d0e0e4736`。上游 span id 与 `00f067aa0ba902b7` 不同。内容类型仍是 `application/x-protobuf` |
| C | 通过。收集器不在听，数据面仍是 HTTP 200 |
| D | 通过。上游没有 `traceparent` |
| authz | 通过。一次放行。审计一行，权限 0600，行里没有凭证，也没有 `authorization`、`secret`、`bearer`。明文 `/metrics` 有 `idp_gateway_authz_decisions_total`。mTLS 的 `/metrics` 是 404 |
| drop-tracing | 对照成立。上游 `traceparent` 为空，应答 HTTP 200，收集器 0 次 POST。A 看的是 tracing 那一块 |

数据面这两笔的内容类型都是 `application/x-protobuf`。不要把它说成 JSON。`gateway-authz` 和 `provider-signer` 的导出器在代码里写 `application/json`；这一次没有留下它们的 POST 正文。导出要等一批才到，套件最多等 8 秒。两次退出时 27701–27709 上都没有人在听。

更早有一笔是套件里的替身没有把 JSON 写完，网关因此 503。替身改成送完 200 之后，上面这两遍才记。断言没有放宽。
