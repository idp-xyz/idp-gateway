# 顺丰国际：`deploy/providers/sfintl` 在联调架子上跑

读的是 `deploy/providers/sfintl/agentgateway.yaml` 本身，不是另抄一份。不改 Go，不改 `tests/integration/gatekeeper/run.py`：那一套的 `run.py` 被原样当模块用（取令牌、`seed`、签证书、起进程、停进程、读判定记录都是它的）。单机池上是 `pool.py`，见下面「单机池上」。

> 已发布的 `gk.idp.xyz` 不在这里访问。`--sandbox` 的结果在下面「结果」一节，证据是 `evidence/rig-sandbox.json`。

## 怎么跑

```bash
tests/integration/gatekeeper/stack.sh up                                   # 本机的 Gatekeeper，已经起着就不用
.venv/bin/python tests/integration/sfintl/run.py                           # 上游是替身；约 26 秒
.venv/bin/python tests/integration/sfintl/run.py --mutate NAME             # 对照：只在替身上
.venv/bin/python tests/integration/sfintl/run.py --sandbox --sandbox-credentials /仓库之外/sfintl-sandbox.json
.venv/bin/python tests/integration/sfintl/run.py --evidence                 # 另写 evidence/rig-standin.json；和 --sandbox 一起则写 rig-sandbox.json
```

端口沿用联调那一组（27611-27620 和 27621-27623）。签名器占 **27618**（黑盒套件另有用处，几套不能同时跑）。进程的文件和日志在 `tests/integration/gatekeeper/.run/`，名字以 `sfintl.` 开头；结果在 `tests/integration/sfintl/.run/result-*.json`（都被 git 忽略）。

| 谁 | 是什么 |
|---|---|
| 真的 | 本机的 Gatekeeper（令牌、JWKS、PDP 和 OpenFGA，PDP 经 27623 要客户端证书）、锁定的 agentgateway 1.7.0、`gateway-authz`（产品构建）、`provider-signer`（`./cmd/provider-signer`）、`deploy/providers/sfintl/agentgateway.yaml` 和由 `policy.example.json` 填出来的登记表 |
| 假的 | 承运商（`mock_sfintl.py`，听 27612）、工作负载证书（每次现做的 CA；运行时给 `provider-signer.idp.test` 补一张，不改 `pki.py`）。SF-09 里 `gateway-authz` 换成带 `acceptance` 标签的构建，只为了能让它放行却不给凭证；它还是问着真实的 PDP |

配置文件写的是池的值。联调架子上用精确字符串替换（`run.py` 的 `RIG_VALUES`，每一处核对出现次数，不对就不跑）换回联调的：管理、指标、就绪 `15000/15020/15021` → `27614/27615/27616`；业务监听和回读口 `8081`、`8443` → `27611`、`27619`（含 `networkAuthorization` 里的两处）；`gateway-authz:9443` → `127.0.0.1:27613`（3 处）；证书路径 `tls/` → `.run/tls/`（`cert`、`key`、`root` 各 7 处）；JWKS 的 `file: tls/jwks.json` → 本机 Hydra 的 URL；回读路由转给的 `127.0.0.1:15000` → `27614`；三条路由后端的 `host: provider-signer:9444` → `127.0.0.1:27618`（3 处）。两种跑法都换这一处：网关的后端始终是本机的签名器，承运商的地址是签名器的 `--carrier-url`。换完先 `--validate-only`。网关进程去掉名字里带 `proxy` 的环境变量。

签名器听 `127.0.0.1:27618`，用 `provider-signer` 的证书，`--client-ca` 是这次的 CA，`--gateway-identity` 是网关证书里的 URI，`--carrier-url` 是替身的 `http://127.0.0.1:27612/openapi/api/dispatch`，超时用默认的 8 秒。`gateway-authz` 带 `--sf-openapi-apps`（两个句柄，`token_endpoint` 是替身的 `http://127.0.0.1:27612/openapi/api/token`），Gatekeeper 和撤销的参数与万邦那套相同。`--sf-openapi-apps` 单独就够，不带 `--credentials`、`--developer-tokens`。

## 两种跑法

- **默认**：两个租户各有一个账户（替身上两个应用，`app_key`、`app_secret`、43 字符的 `encoding_aes_key`、`api_username` 每次随机）。全部检查都做。
- **`--sandbox --sandbox-credentials 文件`**：上游是承运商的沙箱（`api-ifsp-sit.sf.global`，明文 HTTP）。文件是 `{"app_key", "app_secret", "encoding_aes_key", "api_username"}`，0600，在仓库之外（在仓库里、权限宽于 0600、不是这四个字段，都拒绝）。一个应用，登记给 blue；green 没有账户。应用文件由套件包一层，写进临时目录（0700，文件 0600），结束时删掉。`gateway-authz` 的 `token_endpoint` 是 `http://api-ifsp-sit.sf.global/openapi/api/token`，并加 `--sf-openapi-plain-http-host api-ifsp-sit.sf.global`。签名器的 `--carrier-url` 是 `http://api-ifsp-sit.sf.global/openapi/api/dispatch`，并加 `--carrier-plain-http-host`。不起替身。

  发到沙箱的只有三个操作的正常请求，凭证是文件里的那一份。`customerOrderNo` 是 `IDPGW-<UTC 日期>-<随机串>`。创建的正文与替身相同，是 2026-11-20 沙箱接受过的那一份（`apiUsername` 来自凭证文件）。凡是创建答了运单号的都记下，结束前取消。`--sandbox` 同时把每张单的创建和取消即时落盘到 `tests/integration/sfintl/.run/orders-<UTC 时间戳>-<进程号>.jsonl`（0600，只记时刻、事件、客单号、运单号、进程号，不含凭证），全部取消后自动删除；若运行中断或还有未取消的单，文件留着，下次 `--sandbox` 启动时会打印提醒。沙箱上，业务拒绝（HTTP 200、`apiResultCode` 0、`success` 假）会再试，直到接受，或从第一次尝试起过了 600 秒；间隔 3 秒、3 秒、6 秒，之后每次 10 秒。别的应答（网关的错误、签名器自己的错误、`apiResultCode` 不是 0）最多连着 6 次，每次隔 3 秒。替身上不睡，最多 6 次。消不掉的写在结果里，标准输出用一排感叹号标出，退出码非零。不发到沙箱的：错的或调用方自己塞的凭证、故障、轮换、故意写坏的正文（签名器在本机就拒绝的那些可以发，它们出不了这台机器）。

  结果里记：从网关进程去掉的代理变量名、沙箱的名字解析到的地址、**签名器**和 **`gateway-authz`** 连着的非回环地址（这两边才跟承运商说话）、每个调用的耗时。

  **沙箱的结果在下面「结果」一节。**

只在替身上能验的检查，在 `--sandbox` 下记为 skipped，附原因，不是通过。见下表。

「什么都没到承运商」两处一起看，检查的文字里写明是哪一处：替身上看 `/admin/hits`（没有 `dispatch`，写明的地方也没有 `token`）；两种跑法都看签名器的日志（从标记之后没有新的 `signer call`，或者 `outcome` 是签名器在联系承运商之前的拒绝）。

沙箱的 app key、应用密钥、AES 密钥、访问令牌、Gatekeeper 的令牌、PDP 令牌、客户端密钥都不写进结果文件、标准输出和日志。SF-10 在跑完之后扫网关、`gateway-authz` 和 `provider-signer` 的日志、标准输出、结果文件。替身上还扫这一次替身发出的每个访问令牌（从记录里收集，不打印）和 `Sf-OpenApi <某物>;` 这种形状。沙箱上读不到访问令牌，改扫应用密钥、AES 密钥，以及 `auth_<8 个以上>` 和 `Sf-OpenApi …;` 这两种形状。

## 替身的四段

`mock_sfintl.py` 开头的注释把四段分开写了：文档里的、2026-11-20 在真实沙箱上量到的、比量到的更严的、我们的假设。套件不把假设说成承运商的行为。订单按应用归属（green 取消不了 blue 的单）是假设，SF-05 的检查文字里写了。故障 `slow`、`cut`、`cancel-not-yet`、`status`、`garbage`、`undecryptable` 各管下一个对得上的 dispatch。管理口要 `X-Poc-Admin`：`/admin/hits`、`/admin/reset`、`/admin/orders`、`/admin/tokens/void`、`/admin/token-lifetime`、`/admin/fault`。每个应答都带 `Set-Cookie` 和 `X-Mock-Provider: sfintl`。

## 用例

| 用例 | 检查什么 |
|---|---|
| SF-01 | blue 的真实 Gatekeeper 令牌：查一个不存在的单号（`wrongData` 的 `status` 是 `4001`）→ 创建（HTTP 200，`apiResultCode` 0，`success` 真，有 `sfWaybillNo`，客单号是我们的）→ 再查（`4002`）→ 取消（`success` 真；沙箱上按上面的办法重试，次数和秒数记在备注里）→ 再查（`4001`）。每一次 `gateway-authz` 的判定是 `ACTIVE_ACCOUNT_GRANT`，`operation_id` 对得上。替身的 `Set-Cookie` 和 `X-Mock-Provider` 不到调用方。创建的访问日志一行里 `provider_reference_id` 是客单号、`provider_request_id` 是运单号。替身：到这里 blue 的应用只取过一次令牌。沙箱上，第一次查询不是 HTTP 200 时，备注里记下 `gateway-authz` 取令牌的行：`msg`、`result`、`elapsed_ms`，有 `cause` 时也记下，别的不记 |
| SF-02 | 订单还在时用同一份正文再创建：HTTP 200，`success` 真，`code` 是 `123052`，运单号不变。替身另做：故障 `cancel-not-yet` 时调用方得到 HTTP 200、`code` `500`、`success` 假，订单还在；再取消成功。这张单取消掉 |
| SF-03 | 只在替身。三份创建，正文是合法的但不寻常（缩进、非 ASCII、`<`、`&`），按原始字节发，并带 `Cookie`、`X-Forwarded-For`、`X-Forwarded-Host`、`X-Forwarded-Proto`、`Forwarded`、`X-Evil-Probe`、`X-Provider-Account: account-blue`，以及第二个 `Authorization`（调用方自己塞的）。每条 dispatch：`refused` 是 null，`plaintext_sha256` 等于调用方字节的 SHA-256，`appKey` 和 `token` 是 blue 的（比对，不打印），三个 nonce 不同，`msgType` 是 `IECS_CREATE_ORDER`，目标恰好是 `/openapi/api/dispatch`；调用方的头、`x-idp-*`、`authorization`、Gatekeeper 令牌和塞进去的凭证都不在记录里；没有新的取令牌。头名只记不判。`Set-Cookie` 不到调用方。三张单都取消 |
| SF-04 | 不带令牌、别的受众、伪造签名，三条路径都做：401，`gateway-authz` 没有被问，签名器没有被叫，承运商没有 dispatch 也没有取令牌 |
| SF-05 | 替身：green 的令牌用的是 green 的应用（dispatch 上是 green 的 `appKey` 和令牌）；green 取消不了 blue 的单（业务 `success` 假；订单按应用归属是替身的假设）。blue 带 `X-Provider-Account: account-green`：403 `ACCOUNT_NOT_GRANTED`，签名器没被叫，承运商什么都没收到。`--sandbox`：green 被拒 403（原因码记下），上面两段跳过；blue 要 green 的账户仍做（403，到不了承运商） |
| SF-06 | 登记表认、Gatekeeper 没有授权的客户端：403 `ACCOUNT_NOT_GRANTED`，签名器没被叫 |
| SF-07 | `GET`、`PUT`、`DELETE`、`PATCH` 打在三条路径上：网关 404，`gateway-authz` 没被问，签名器没被叫。只是前缀或靠近的路径（`/orders/`、`/orders/X`、`/orders-extra`、`/order-cancellations/1`、`/agent-number-queries/x`、`/orders/../orders`、`%2e%2e`、`%2f`、`%252e`、`;x=1`、`%00`、`//orders`、大写、签名器自己的 `/sfintl/v1/orders`、别的承运商的路径、`/providers/sfintl/v2/orders`）：拒绝（>= 400），签名器没被叫，承运商什么都没收到。允许的路径加上 `?x=1`：拒绝（>= 400），承运商什么都没收到；谁拒绝的记在备注里，不另判 |
| SF-08 | 用 blue 的令牌，经网关：`Content-Type: text/plain` → 415 `unsupported_media_type`；JSON 数组、两个对象、空正文、不是 JSON → 400 `body_not_json_object`；超过 1 MiB → 拒绝（>= 400），状态和是谁答的记在备注里。应答是签名器自己的 JSON，承运商没有 dispatch。两种跑法都做（出不了这台机器） |
| SF-09 | 见下 |
| SF-10 | 扫描，见上 |
| SF-11 | 只在单机池上：出口规则。见下面「单机池上」 |
| SF-12 | `gateway-control revoke` 撤销 blue，请求用的是只读的查询：403，应答和判定都是 `ACCOUNT_REVOKED`，签名器没被叫；替身上 green 不受影响；`revocations` 列出来；`restore` 之后 blue 又被服务；`gateway-authz` 是同一个进程 |
| SF-13 | 只在替身。(a) `/admin/tokens/void`：下一个请求 HTTP 200，承运商的 `apiResultCode` 500 原样过来；接着几次仍然失败的次数只记不判。然后按 `gateway-authz` 要的办法（旁边写新文件，再改名盖上去）把 blue 的 `key_version` 改掉：下一个请求做成，替身只见到一次新的取令牌，进程还是同一个，green 的令牌没有再取。(b) `/admin/token-lifetime?seconds=5`，再改一次 `key_version`，做成一个请求；等到这个令牌过了寿命，下一个请求用的是新令牌（又一次取令牌，dispatch 没有被拒）。寿命放回 7200，`key_version` 放回。(c) 换成一份读不成的文件（多一个不认识的成员）：下一个请求仍用最后一份读得成的；第一份放回去，又能做成 |
| SF-14 | 只在替身。`slow` 11 秒：调用方得到签名器自己的 504 `carrier_timeout`，用时在签名器的 8 秒附近（不是网关的 9 秒），承运商恰好一个创建 dispatch，订单在；同一份再创建答 `123052` 和同一个运单号；一共两个创建 dispatch；取消。`cut`：调用方得到签名器的 502（哪一种记在备注里），一个 dispatch，订单在，同样再创建。`status` 503 → 502 `carrier_status`，`carrier_status` 是 503。`garbage` → 502 `carrier_answer_unreadable`。`undecryptable` → 502 `carrier_answer_unreadable`，订单在，取消掉。这些应答都没有 `Set-Cookie` 和 `X-Mock-Provider` |
| SF-15 | 直接打 27618，不经网关，两种跑法都做。没有客户端证书：握手或请求失败。`rogue-gateway`（另一个 CA）：失败。`business-app`（CA 对、身份不对）：403 `caller_not_allowed`。`gateway` 的证书、不带 `Authorization`：403 `credential_malformed`。调用方按名字 `provider-signer.idp.test` 核对。每一项承运商都没有 dispatch |

创建答了运单号的单都记在 `CREATED` 里，不管检查过没过，结束前都取消。剩下的按上面的办法报出来。

### 哪些用例在哪种跑法下跳过

| | 替身（`run.py`） | `--sandbox`（`run.py`） | 池（`pool.py`，替身或 `--sandbox`） |
|---|---|---|---|
| SF-01、02、05 | 全做 | 只在替身上看得到的检查跳过（`Set-Cookie`、取了几次令牌、`cancel-not-yet`、green 的应用和「取消不了别人的单」） | 同 `run.py` 的相应跑法 |
| SF-03、13、14 | 做 | 整个跳过 | 替身：做。`--sandbox`：整个跳过，原因同 `run.py` |
| SF-04、06、07、08、10、15 | 做 | 做。SF-08 的正文到不了承运商 | 做。池上超过 1 MiB 的正文由 `front` 答 413，不到签名器。SF-10 扫的是容器日志。SF-15 打本机 `27645` |
| SF-09 | 做 | 做；最后那个看承运商收到了谁的 `appKey` 的对照跳过 | 整个跳过：池里跑的是产品构建 |
| SF-12 | 做 | 做；撤销前确认 blue 能通的那一次、以及 green 不受影响，跳过 | 整个跳过：池里的 `gateway-authz` 不带 `--revocations` |
| SF-11 | 不做 | 不做 | 做 |

### SF-09：放行却没给凭证

做法同万邦的 WB-09：`gateway-authz` 换成带 `acceptance` 标签的构建，设成放行但不给凭证。请求用的是只读的查询。检查：调用方得不到成功；判定是 `ACTIVE_ACCOUNT_GRANT`（所以拒绝的是网关）；**签名器没有被叫**（看签名器的日志：后端规则拦住了）；承运商什么都没收到。调用方自己的 `Authorization` 放在令牌后面、放在令牌前面，同样。对照（替身）：设回正常，同一个请求带着塞进去的头被做成，承运商看到的是 blue 的 `appKey`，不是塞进去的。做完换回产品构建。`--sandbox` 下被拒绝的请求到不了沙箱，最后那个对照跳过。

## 结果

2026-11-20，agentgateway 1.7.0，上游是替身，连跑三遍。三遍都是 **14/14**，每遍 **284 项检查，没有跳过**。用时 25.2 秒、25.0 秒、26.8 秒。跑完 27611-27620 没有监听，本机 Gatekeeper 的容器还在。创建的单都取消了，替身上没有剩下的。提交 `094c5e5` 之前，审阅者又跑了一遍，也是 14/14。

| 用例 | 检查数 |
|---|---|
| SF-01 / 02 / 03 / 04 / 05 | 15 / 6 / 12 / 36 / 10 |
| SF-06 / 07 / 08 / 09 / 10 | 4 / 99 / 19 / 18 / 5 |
| SF-12 / 13 / 14 / 15 | 12 / 12 / 24 / 12 |

这是联调，不是验收证据；不改变任何验收用例的 `NOT_RUN`。

三遍里看到的（检查都过了，备注里的数字）：

- 创建的访问日志一行：`provider_reference_id` 是这次的 `customerOrderNo`，`provider_request_id` 是 `sfWaybillNo`（`SF6043000100001`，替身从这里起编）。
- `POST /providers/sfintl/v1/orders?x=1`：签名器答 400 `query_not_allowed`，调用方看到的也是 400。网关没有自己拦。
- 超过 1 MiB 的正文：调用方得到签名器的 413 `request_too_large`。
- 令牌被 `/admin/tokens/void` 作废之后，接着的三次查询都是 `apiResultCode` 500。
- `slow`：调用方得到签名器的 504 `carrier_timeout`，三遍用时 8.016 秒、8.012 秒、8.015 秒。
- `cut`：调用方得到签名器的 502 `carrier_unreachable`，用时约 0.01 秒。
- 承运商看到的头名（不判）：`accept-encoding`、`appkey`、`content-length`、`content-type`、`host`、`lang`、`msgtype`、`nonce`、`signature`、`timestamp`、`token`、`user-agent`。

### 对照（2026-11-20，替身上，各跑一遍，`--mutate` 不改仓库里的文件）

每一遍退出码都是 1。括号里是这一遍通过的用例数。

| `--mutate` | 改了什么 | 不通过的用例 |
|---|---|---|
| `bearer-prefix` | 后端规则的前缀改成 `Bearer ` | 5/14。SF-01、02、03、05、08、09、12、13、14：要走通的请求调用方得到 HTTP 403，不是签名器的 JSON。SF-09 里「签名器没被叫」仍过；设回正常的那个对照不过，因为放出来的凭证不是 `Bearer `。超过 1 MiB 的那一次没有 HTTP 状态 |
| `no-backend-rule` | 去掉三条后端 `authorization` 规则 | 13/14。只有 SF-09：不给凭证的请求到了签名器，日志里的 `outcome` 是 `credential_malformed`（调用方自己塞的头没有变成一张能用的凭证）。承运商仍然什么都没收到 |
| `no-backend-tls` | 去掉三条后端 `backendTLS` | 5/14。不过的用例与 `bearer-prefix` 相同。调用方得到 HTTP 400，不是签名器的 JSON。创建的访问日志有这一行，`http.status` 是 400，有 `provider_reference_id`，没有 `provider_request_id`。超过 1 MiB 的那一次没有 HTTP 状态 |
| `wrong-signer-name` | 后端 `backendTLS` 的 `hostname` 改成 `wrong.idp.test` | 5/14。不过的用例与上面相同。调用方得到 HTTP 503，约 0.007 秒。访问日志里没有带这个客单号的行 |
| `create-retry` | 只给创建那条路由加 `retry`（`attempts: 2`，`codes: [502, 503, 504]`） | 13/14。只有 SF-14。`slow`：调用方得到 HTTP 200，用时 8.014 秒，不是签名器的 504；「恰好一个创建 dispatch」和「一共两个」都不过，订单在，再创建是 `123052`。`cut`：HTTP 200，用时 0.009 秒，同样是 dispatch 的条数不过。`status` 503 和 `garbage`：调用方得到 HTTP 200，「订单没有被创建」不过（重试做成了）。`undecryptable`：调用方没有得到签名器的 502 |
| `no-revocations` | `gateway-authz` 不带 `--revocations` 起 | 13/14。只有 SF-12。`gateway-control revoke` 退出码 3、`NO_REVOKER_CONFIGURED`；blue 的下一个请求是 200、判定 `ACTIVE_ACCOUNT_GRANT`，签名器的 `outcome` 是 `ok`，承运商收到了 dispatch。green 那一条也不过：它数的是同一次清空之后的 dispatch，里面还有 blue 这一次。`revocations` 和 `restore` 也不过，因为没有撤销成 |
| `signer-other-identity` | 签名器的 `--gateway-identity` 换成 `business-app` 的 | 4/14。SF-01、02、03、05、08、09、12、13、14：经网关的调用得到签名器的 403 `caller_not_allowed`。SF-15 也不过：`business-app` 的证书现在对得上，不带 `Authorization` 时是 403 `credential_malformed`；网关的证书变成 403 `caller_not_allowed` |
| `signer-long-timeout` | 签名器 `--carrier-timeout 20s` | 13/14。只有 SF-14 的 `slow`：调用方得到 HTTP 504，用时 9.002 秒，正文不是签名器的 `carrier_timeout`。这一条的另外 23 项过了，包括「恰好一个创建 dispatch」 |

这套架子上没有「去掉请求头名单」的对照。签名器不把调用方的任何头带给承运商，承运商的记录显示不出来名单在不在。SF-03 看的是承运商收到的头，不是网关到签名器那一跳的名单。

### 真实沙箱（2026-11-20）

`run.py --sandbox --sandbox-credentials`（0600 的文件，在仓库之外）`--evidence`，在 `094c5e5` 上，没有未提交的文件。两遍。两遍之间没有改任何东西。

第一遍 **13/14**。SF-01 的前两个请求（查询和创建）被网关答 HTTP 503。`gateway-authz` 前两次取令牌失败，日志是 `sf openapi token not fetched`，`result` 是 `unreachable`，用了 127 毫秒和 78 毫秒。判定是 `INDETERMINATE` / `CREDENTIAL_UNAVAILABLE`。没有到签名器，也没有到承运商。0.8 秒之后的第三次取到了，这一遍剩下的都过了。SF-02 创建了一张单并取消，没有剩下的。网络路径上的原因不知道：日志里只有类别，因为请求地址带着应用密钥。紧接着 Python 取了 12 次，一个用适配器那一套传输设置的临时 Go 程序取了 25 次，每次都是新连接，都成功。这一遍的证据文件没有留在仓库里，第二遍写在同一个路径上。上面这段写在提交 `7fd2dd2` 的说明里；那里把 Go 程序的次数写成了 33，写错了，是 25。

第二遍是 `evidence/rig-sandbox.json`。**14/14**。233 项检查：168 过，65 项带原因跳过，0 失败。17.7 秒。SF-03、SF-13、SF-14 整个跳过（只在替身上）。

| 用例 | 过 / 跳过 |
|---|---|
| SF-01 | 13 / 2 |
| SF-02 | 4 / 2 |
| SF-04 | 27 / 9 |
| SF-05 | 4 / 2 |
| SF-06 | 3 / 1 |
| SF-07 | 70 / 29 |
| SF-08 | 13 / 6 |
| SF-09 | 13 / 4 |
| SF-10 | 5 / 0 |
| SF-12 | 8 / 3 |
| SF-15 | 8 / 4 |

SF-01：查一个不存在的单号，`4001`；创建，HTTP 200，`apiResultCode` 0，`success` 真，有 `sfWaybillNo`；再查，`4002`；取消，第一次 `success` 假，第二次（隔 3 秒）成功，备注里 `cancel attempts` 为 2；再查，`4001`。创建的访问日志一行里 `provider_reference_id` 是这次的 `customerOrderNo`，`provider_request_id` 是 `sfWaybillNo`。SF-02：同一份正文再创建，`code` `"123052"`，运单号不变。两张单，运单号 SF6043039280127 和 SF6043039280135，都取消了，没有剩下的。这一遍有 12 个请求到了承运商。经网关的耗时：查询 240 到 770 毫秒（第一次含取令牌），创建 387 到 1155 毫秒，取消 236 到 1701 毫秒。名字 `api-ifsp-sit.sf.global` 解析到 156.59.125.28。签名器和 `gateway-authz` 只连了 156.59.125.28:80。承运商的 `Date` 比这台机器慢 0.1 秒。`gateway-authz` 这一遍取了三次令牌，因为 SF-09 把进程换了两次，每个新进程取一次。沙箱令牌是固定的，没有作废。

离开这台机器的，只有三个操作的正常请求。SF-10 在三份日志、标准输出和结果文件里没有找到 app key、应用密钥、AES 密钥、Gatekeeper 或 PDP 的令牌，也没有像访问令牌或 `Sf-OpenApi` 这种形状的值。提交说明里写了：另外扫了一遍工作区，三个沙箱值都不在。

## 证据（`--evidence`）

`run.py --evidence`、`pool.py --evidence`：只有带这个参数才写 `tests/integration/sfintl/evidence/`。联调架子上对着替身是 `rig-standin.json`，对着沙箱是 `rig-sandbox.json`。池上对着替身是 `pool-standin.json`，对着沙箱是 `pool-sandbox.json`。和 `--mutate`、`--control` 不能一起用。字段与万邦那套相同；`dataset` 里是 `reference_prefix`、`orders_created_and_cancelled`、`orders_left_uncancelled`（运单号）。写完再读一遍，里面有这次的秘密或 `Sf-OpenApi …;`、`auth_<8 个以上>`、`Bearer ` 加 16 个以上字符，就删掉文件、退出码非零。契约测试（`tests/contracts/test_sfintl_config.py`）看有的文件。

`rig-standin.json` 是 2026-11-20 在 `094c5e5` 上对着替身带 `--evidence` 的那一遍：14/14，284 项检查都过，没有跳过，25.5 秒，取消了 9 张单，没有剩下的。`uncommitted_files` 是 0。`rig-sandbox.json` 是上面第二遍，同一提交，未提交文件数也是 0。`pool-standin.json` 见下面「单机池上」。`pool-sandbox.json` 见「池上真实沙箱」。

## 单机池上（`pool.py`，第三步）

```bash
tests/integration/gatekeeper/stack.sh up
.venv/bin/python tests/integration/sfintl/pool.py                                # 上游是替身
.venv/bin/python tests/integration/sfintl/pool.py --sandbox --sandbox-credentials FILE
.venv/bin/python tests/integration/sfintl/pool.py --control no-signer-egress    # 对照：装签名器规则的那一步什么都不做
.venv/bin/python tests/integration/sfintl/pool.py --control no-signer-name      # 对照：发布的配置不写 provider-signer
.venv/bin/python tests/integration/sfintl/pool.py --evidence                     # 另写 evidence/pool-standin.json；和 --sandbox 一起则写 pool-sandbox.json
```

跑的是 `deploy/compose/compose.yml` 加 `gateway-authz.yml` 加 `provider-signer.yml`，再加测试用的 `pool.yml`。`--control no-signer-egress` 再加 `pool_no_signer_egress.yml`。部署文件不改。**搭法**：compose 项目 `idp-gateway-sfintl-pool`，本机端口 `27641`（`front`，调用方从这里进）、`27642`（回读口）、`27643`（发布器离线加载用的临时容器）、`27644`（替身的管理口，只在替身跑法里）、`27645`（签名器的 9444，只为 SF-15；部署文件本身不映射这个端口）。池的目录、证书、`.env` 都在一个临时目录里。`gateway-control`、`gateway-authz`、`provider-signer` 现场静态构建。证书用联调架子本次做的那一套。先放一份只有回读口的配置，`up -d` 起 `agentgateway`、`gateway-authz`、`outsider`、`signer`（替身跑法里先起 `sfintl-standin`），再用 `gateway-control publish` 把 `deploy/providers/sfintl/agentgateway.yaml` 发布上去，再 `up -d`。发布的退出码不是 0 就不往下跑。

- **真的**：本机的 Gatekeeper（PDP 经联调栈的网络 `idp-gateway-gk_default`，按服务名 `pdp-mtls:8443` 找，带客户端证书）、锁定的 agentgateway 1.7.0、现场构建的 `gateway-authz`（产品构建）和 `provider-signer`、发布上去的 `deploy/providers/sfintl/agentgateway.yaml`、`front`、网关命名空间和签名器命名空间里的出口规则。
- **替身**：承运商是池网络里的容器 `sfintl-standin`（profile `standin`，听 8080）。签名器的 `CONFIG` 写 `sfintl-standin:8080`，所以钉住的是它。发布的网关配置不写这个名字。`--sandbox` 时这个容器不起，上游是 `api-ifsp-sit.sf.global:80`。另有 `outsider`：配置里没有它，有规则的命名空间里应连不上。工作负载证书是这次现做的。替身镜像由 `pool.py` 用工具镜像做一次，在里面装联调架子用的那个 `cryptography` 版本；工具镜像里没有这个包。
- **用例**：`run.py` 的用例经钩子跑。SF-09、SF-12 整个跳过，原因在上面的表里。SF-11 是池上加的。超过 1 MiB 的正文，`front` 在到签名器之前答 413。SF-03 不发第二个 `Authorization`（`front` 不把两个 `Authorization` 头交到网关；提交 `1a144d0` 的说明这么写，套件因此不发第二个）。沙箱上哪些检查跳过，与 `run.py --sandbox` 相同，再加 SF-09、SF-12 的整个跳过。
- **SF-11**：签名器的命名空间里，承运商被钉住的地址和端口连得上；另一个容器、另一个端口、IPv6 回环被规则拒绝。网关的命名空间里，`provider-signer:9444`、`gateway-authz:9443` 和回环 `8081` 连得上。对着替身，承运商的地址和端口在网关的命名空间里被拒绝；`--sandbox` 时不连承运商的公网地址，只查这个名字没有被钉在网关那边，并且这台机器上另一个容器被拒绝。`gateway-authz` 自己的命名空间没有出口规则，备注里写了，不是一项检查。errno 113 和 13 是对着替身那一遍记下来的，见下面的结果。
- **对照**（只在替身上）：`no-signer-egress` 让 SF-11 不通过。提交 `1a144d0` 的说明写，只有 SF-11 不通过，三项检查不过。`no-signer-name` 把发布的后端改成 `outsider` 的地址、端口 9444。提交说明写，凡是要签名器的用例都不通过，其余通过。这两次没有证据文件。
- **结束时**无论成败，`docker compose down -v` 自己的项目，删临时目录。只动自己的项目和 `idp-gateway-gk`。

### 结果（2026-11-20，替身）

`pool.py --evidence` 在 `1a144d0` 上、未提交文件数 0，写的是 `evidence/pool-standin.json`。**15 个用例，0 个失败，2 个整个跳过（SF-09、SF-12）。** 266 项检查：264 项过，2 项跳过，0 项失败。从 07:41:46 到 07:43:23（UTC），97 秒。创建并取消了 9 张单，没有剩下的。`publish` 的结局，证据文件里没有；提交 `1a144d0` 的说明写是 `ACTIVE`。六个容器（`agentgateway`、`front`、`netns`、`gateway-authz`、`provider-signer`、`signer`）的环境里没有名字带 `proxy` 的变量。

SF-11 的备注：签名器的命名空间钉住 `sfintl-standin:8080`；网关的命名空间钉住 `127.0.0.1:15000`、`gateway-authz:9443`、`provider-signer:9444`。从签名器的命名空间连：承运商是 0，另一个容器、另一个端口、`gateway-authz` 的 9444 是 113，`[::1]:9` 是 13。从网关的命名空间连：签名器的 9444、`gateway-authz` 的 9443、回环 8081 是 0，承运商和 `outsider` 是 113，`[::1]:9` 是 13。`slow`：调用方得到签名器的 504 `carrier_timeout`，8.008 秒。超过 1 MiB：HTTP 413，不是签名器的 JSON。

提交 `1a144d0` 的说明写，这份证据之前连跑过，都是 15 个用例、264 项检查过、2 项跳过。提交 `149aa0e` 的说明写，取消的重试改完之后对着替身又跑了一遍池，计数与这份证据相同。那一遍没有另写文件。

### 池上真实沙箱

提交 `1a144d0` 写，`--sandbox` 在那个提交里没有跑。提交 `91aa333` 写，随后在同一提交上跑了两遍，两遍都是 SF-01 和 SF-02 没过：取消答业务 `code` `"500"`（`"请求服务发生异常"`），套件当时只试 6 次、每次隔 3 秒；有一遍 SF-01 的第一次查询是 HTTP 503。证据没有留。留下的订单后来手工取消了。有一张单，手工重试了大约两分钟。

预算改成 300 秒之后试了一遍，当时还没有改成 600 秒（提交 `149aa0e` 的说明）。SF-01 过了，取消在第二次被接受（2 次、6.1 秒）。SF-02 的取消被拒 28 次、295.9 秒，用例没过。那张单后来手工取消了。

预算 600 秒的那一遍是 `pool.py --sandbox --evidence`，在干净的 `7ec6f20` 上写的，未提交文件数是 0。证据 `evidence/pool-sandbox.json`，提交 `710acb1`。从 2026-11-20T10:12:38Z 到 10:23:02Z。**15 个用例，0 个失败。** SF-03、SF-09、SF-12、SF-13、SF-14 整个跳过，是沙箱上的设计。217 项检查：157 项过，60 项跳过，0 项失败。SF-01 的 `cancel attempts` 是 44，`cancel seconds` 是 493.595，第 44 次被接受。SF-02 是 2 次、6.455 秒。两张单都取消了，`orders_left_uncancelled` 是空的。提交说明写，清理没有要做的。SF-01 的第一次查询是 HTTP 200，没有记下取令牌失败，`cause` 在沙箱上仍没有见到。SF-10 的 5 项过了。SF-11 的 10 项过了；签名器的命名空间把 `api-ifsp-sit.sf.global:80` 钉在 156.59.125.28。提交说明写调用方一侧的耗时，证据文件里没有逐次的数：创建约 1.0 秒，查询 0.2 到 0.6 秒，取消的中位数 0.24 秒，有一次 3.2 秒。

这一遍之前还有一次中断，只写在提交 `710acb1` 的说明里。当天 17:55（本地时间），同一条命令启动过，会话断了；做到发布配置之后进程被杀掉，清理没有跑，池和本机的 Gatekeeper 栈还留着。下一次按 `pool.py` 自己的拆除把池拆掉，并把栈停了。池的日志跟着没了。套件只在结束时写结果，所以不知道那一次有没有建订单，也不知道单号。如果建了，沙箱上可能还留着最多两张测试单，客单号前缀 `IDPGW-20261120-`，从这里认不出，也取消不了。这台机器上那一次没有留下别的。

2026-11-20 在沙箱上量到的取消，原因不知道，量的是沙箱不是生产：要么下单后几秒内被接受（上午的手工量、联调架子上的两遍、300 秒试跑里 SF-01 的 6.1 秒，以及这一遍的 SF-02，2 次、6.455 秒），要么要到下单之后大约 5 到 8.5 分钟（两张单大约 4 分 45 秒和 5 分钟；一张被拒了 295.9 秒，又过大约 2.5 分钟，下一次才接受；这一遍的 SF-01 从第一次取消尝试起 493.595 秒，约 8.2 分钟，那一次尝试在下单之后不久）。拒绝是 HTTP 200、`apiResultCode` 0、`code` `"500"`、`success` 假。600 秒的预算这一次够用，还剩 106 秒。不是说以后都够。

调用的耗时。提交 `149aa0e` 的说明写：先前池上对着沙箱，套件采样连接的时间被算进了每一次调用，记成每次 1.1 到 2.5 秒的是套件自己的几次 `docker exec`，不是网关。同一些调用在网关自己的访问日志里是 211 到 1107 毫秒。现在 `req()` 在读完应答时记时间，采样在那之后。

## 没有做的

- **池上不做 SF-09 和 SF-12**，原因在表里。这一遍的清理没有要做的（两张单在用例里取消了）。清理真的用满 600 秒，仍没有见过。
- **`orders-*.jsonl` 的中断留盘只在离线单元测试里验过，没有对着真实沙箱中途强杀验过。**
- **请求头名单的对照**没有做，原因在上面。
- **到承运商的 TLS** 没有验。沙箱是明文 HTTP。
- **面单**（`IECS_PRINT_ORDER`）和别的 `msgType`。
- **几个 `gateway-authz` 一起取同一个应用的令牌**，一次重启也是一次新的取令牌，生产上会作废前一枚。沙箱令牌是固定的，验不了。
- **`gateway-authz` 到令牌端点的连接没有出口规则。**
- **取令牌失败仍记一个类别**。传输失败另有 `cause`（`e88a7c5`），一个固定的词，不写错误原文。第一遍沙箱的两次 `unreachable` 发生在这之前，日志里没有 `cause`，分不出更细的原因。
- **`--carrier-timeout` 不短于 9 秒时程序不拒绝**（对照 `signer-long-timeout`）。
- **发给承运商的请求还带着 Go 默认的 `User-Agent` 和 `Accept-Encoding: gzip`。** 替身只记下了头名。
