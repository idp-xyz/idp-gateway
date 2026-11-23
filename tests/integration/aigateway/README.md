# AI：编译结果在回环上

这不是验收通过。2026-11-23 的测量记在 [ADR-0016](../../../docs/adr/ADR-0016.md) V1.4。

`run.py` 用 `gateway-control compile` 把 LLM、MCP、A2A 各编一份，然后用锁定的 agentgateway 1.7.0 启动编译器写出的那份文件。没有 `--control` 时，交给网关的文件与编译器输出逐字节相同。监听、管理地址、回读口和替身都在 `127.0.0.1`。替身在本进程里。主模式不用 docker。没有真实模型、没有真实 MCP 服务、没有真实 agent。

## 怎么跑

```bash
.venv/bin/python tests/integration/aigateway/run.py
.venv/bin/python tests/integration/aigateway/run.py --evidence
.venv/bin/python tests/integration/aigateway/run.py --control llm-no-policies
.venv/bin/python tests/integration/aigateway/run.py --control mcp-no-allowlist
.venv/bin/python tests/integration/aigateway/run.py --control mcp-no-path-rule
.venv/bin/python tests/integration/aigateway/run.py --control a2a-no-policy
.venv/bin/python tests/integration/aigateway/run.py --control no-readback-route
```

要 `/usr/local/go/bin/go`、锁定的 agentgateway 1.7.0，以及仓库的 `.venv`（PyJWT、cryptography、PyYAML）。网关进程和回环客户端都不带 `http_proxy`、`https_proxy`。`--evidence` 写 `evidence/loopback.json`，不能和 `--control` 一起用。证据从干净的工作区跑，文件里的 `commit` 指向被测的那份代码。这份套件自己不写证据。

端口在 `27661-27679`。监听 `27661`，统计 `27663`，就绪 `27664`，回读 `27665`，替身 `27666`，每次启动的管理口是 `27667-27674` 里的一个。`27675-27679` 留在同一段里。已经有进程在听其中一口，套件拒绝启动。只是 TIME-WAIT、没有进程在听，就等到能绑定，最多 90 秒。工作目录在 `/tmp`，不论成败都删掉。要留下它，设 `AIGATEWAY_KEEP_WORK=1`。证书、密钥和令牌每次现做，不进仓库。

规格里的主机名、签发者和受众是 `.example` 或 `.test`，不是产品常量。DNS 名的上游这一步只做过 `--validate-only`，没有在这套回环里跑过。镜像里的 `--in-image` 没有做。这一步的 LLM 只放行两个端点：`POST <前缀>/v1/chat/completions` 和 `GET <前缀>/v1/models`。messages、responses、embeddings 故意拒绝。逐项在 ADR-0016 V1.4。

## 用例

| 用例 | 检查什么 |
|---|---|
| RB-LLM、RB-MCP、RB-A2A | 发布器证书读 `GET /config_dump` 和 `GET /api/runtime` 是 200。另一条路径是 404。不带客户端证书时 TLS 握手失败 |
| AUTH-LLM | 没有 JWT、错受众、错签发者、过期、另一把密钥，都是 401，替身收到 0 次。另一个 Host 是 403，替身收到 0 次。调用方的 JWT 不到替身。网关日志里没有 JWT，也没有密钥材料 |
| AUTH-MCP、AUTH-A2A | 同样的五种 JWT 失败是 401，替身收到 0 次。另一个 Host 是 404，替身收到 0 次 |
| LLM-01 | 相符的 JWT，`POST /llm/v1/chat/completions` 到替身的路径是 `/v1/chat/completions`，`Authorization` 里有密钥文件的内容。调用方送的 Cookie、X-Forwarded-For、X-Provider-Account、X-Not-Registered 不到替身。调用方得到替身的 completion。替身应答的 Location 和 Set-Cookie 不到调用方。编译出的 YAML 里没有这把密钥 |
| LLM-MODELS | `GET /llm/v1/models` 是 200，正文里有规格里的模型名。替身收到 0 次 |
| LLM-PATHS | `POST /llm/other`、`POST /llm/v1/embeddings`、带斜杠的 `POST /llm/v1/chat/completions/`、`GET /llm/v1/chat/completions`、`POST /llm/v1/models` 都是 403，替身收到 0 次。正文里点了规格里的模型名 |
| LLM-UNKNOWN | 规格里没有的模型名是 404，替身收到 0 次。聊天路径上的查询串是否被转到替身，只记录，不作为通过条件 |
| MCP-TLS | `127.0.0.1` 加 `tls_hostname`。initialize、notifications/initialized、tools/list、tools/call 都通。替身看到网关的客户端证书和改写后的 Host。调用方送的 Cookie、X-Forwarded-For、X-Provider-Account、X-Not-Registered 不到替身。深一段是 403。PUT 是 404。带着会话号但不带 JWT 是 401。Location 和 Set-Cookie 到不到调用方、DELETE 之后原会话号还能不能用，只记录，不作为通过条件 |
| MCP-PLAIN | 没有 `tls_hostname` 的明文回环，同一套会话能走完。替身看到的 Host 只记录 |
| MCP-OTHER-CA、MCP-NAME、MCP-DOWN | 目标证书来自另一套 CA、`tls_hostname` 对不上、没有进程在听。各自单独起一次网关。initialize 是 HTTP 500，JSON-RPC 是 -32603，目标应用收到 0 次 |
| A2A-TLS | 卡片是 200，`url` 是 `http://ai.example/agent`。`POST /agent` 到 agent 的路径是 `/`。agent 看到客户端证书、改写后的 Host，名单外的头不到。Location 和 Set-Cookie 不到调用方。`GET /agent`、对卡片路径的 POST、`/.well-known/agent.json`、`/agent/`、`/agent/other` 被拒绝，agent 收到 0 次。DELETE 是 404。调用方送 `X-Forwarded-Proto: https` 时卡片仍是 `http://`，只记录 |
| A2A-OTHER-CA | agent 证书来自另一套 CA。卡片和 POST 都是 503，agent 应用收到 0 次 |

## 对照

对照改的是编译结果，不是描述。描述不跟着结果改。

| `--control` | 做了什么 | 应当看到 |
|---|---|---|
| `llm-no-policies` | 去掉 `llm.policies` | LLM 的加固不通过：另一个 Host 是 200，调用方的四个头到达替身，`/other` 和 embeddings 带着密钥到达替身，Location 和 Set-Cookie 回到调用方 |
| `mcp-no-allowlist` | 去掉 MCP 路由上的 `transformations` | 头的那一项不通过：Cookie 和另外三个头到达目标 |
| `mcp-no-path-rule` | 去掉 MCP 路由上的 `authorization` | 深一段的路径被转到目标 |
| `a2a-no-policy` | 去掉 `a2a: {}` | 卡片那一项不通过：卡片里是 agent 自己的 URL |
| `no-readback-route` | 三份配置都去掉回读路由 | 回读用例不通过，`/config_dump` 和 `/api/runtime` 是 404 |

## 这一轮看到的

2026-11-23，主模式连跑两次，都是 17 个用例、87 项检查通过。套件自己记的用时是 8.21 秒和 8.41 秒。第二次启动前等 TIME-WAIT 60.3 秒，这 60.3 秒不在 8.41 秒里。聊天路径上的 `?x=1` 被转到替身，只记录，不作为通过条件。

五个对照各跑一次，都按设计不通过，描述没有改：

| 对照 | 用例 | 检查 | 套件用时 | 启动前等待 | 和上表不一样的地方 |
|---|---|---|---|---|---|
| `llm-no-policies` | 14/17 | 79/87 | 8.05 秒 | 59.0 秒 | 另一个 Host 是 200 并到达替身；四个调用方头到达替身；`/other`、embeddings、带斜杠的聊天路径都是 200 并带着密钥到达替身；Location 和 Set-Cookie 回到调用方。`GET /llm/v1/chat/completions` 是 400，正文是 `LLM request body must be valid JSON`，替身收到 0 次。`POST /llm/v1/models` 是 501，正文是 `Route 'Models' not implemented`，替身收到 0 次 |
| `mcp-no-allowlist` | 16/17 | 86/87 | 8.27 秒 | 59.6 秒 | 四个调用方头到达目标 |
| `mcp-no-path-rule` | 16/17 | 86/87 | 8.05 秒 | 59.0 秒 | 深一段是 200 |
| `a2a-no-policy` | 16/17 | 86/87 | 8.02 秒 | 59.5 秒 | 卡片 `url` 是 `https://agent.standin.test:27666/internal` |
| `no-readback-route` | 14/17 | 81/87 | 8.19 秒 | 59.5 秒 | 三份配置的 `/config_dump` 和 `/api/runtime` 都是 404 |

工作目录在每次退出时删掉，包括这些对照。`AIGATEWAY_KEEP_WORK` 没有设置。
