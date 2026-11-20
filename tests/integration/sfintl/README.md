# 顺丰国际：`deploy/providers/sfintl` 在联调架子上跑

读的是 `deploy/providers/sfintl/agentgateway.yaml` 本身，不是另抄一份。不改 Go，不改 `tests/integration/gatekeeper/run.py`：那一套的 `run.py` 被原样当模块用（取令牌、`seed`、签证书、起进程、停进程、读判定记录都是它的）。

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

  发到沙箱的只有三个操作的正常请求，凭证是文件里的那一份。`customerOrderNo` 是 `IDPGW-<UTC 日期>-<随机串>`。创建的正文与替身相同，是 2026-11-20 沙箱接受过的那一份（`apiUsername` 来自凭证文件）。凡是创建答了运单号的都记下，结束前取消；取消答 `success` 假就再试，最多 6 次，每次隔 3 秒。消不掉的写在结果里，标准输出用一排感叹号标出，退出码非零。不发到沙箱的：错的或调用方自己塞的凭证、故障、轮换、故意写坏的正文（签名器在本机就拒绝的那些可以发，它们出不了这台机器）。

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
| SF-01 | blue 的真实 Gatekeeper 令牌：查一个不存在的单号（`wrongData` 的 `status` 是 `4001`）→ 创建（HTTP 200，`apiResultCode` 0，`success` 真，有 `sfWaybillNo`，客单号是我们的）→ 再查（`4002`）→ 取消（`success` 真；沙箱上按上面的次数重试，次数记在备注里）→ 再查（`4001`）。每一次 `gateway-authz` 的判定是 `ACTIVE_ACCOUNT_GRANT`，`operation_id` 对得上。替身的 `Set-Cookie` 和 `X-Mock-Provider` 不到调用方。创建的访问日志一行里 `provider_reference_id` 是客单号、`provider_request_id` 是运单号。替身：到这里 blue 的应用只取过一次令牌 |
| SF-02 | 订单还在时用同一份正文再创建：HTTP 200，`success` 真，`code` 是 `123052`，运单号不变。替身另做：故障 `cancel-not-yet` 时调用方得到 HTTP 200、`code` `500`、`success` 假，订单还在；再取消成功。这张单取消掉 |
| SF-03 | 只在替身。三份创建，正文是合法的但不寻常（缩进、非 ASCII、`<`、`&`），按原始字节发，并带 `Cookie`、`X-Forwarded-For`、`X-Forwarded-Host`、`X-Forwarded-Proto`、`Forwarded`、`X-Evil-Probe`、`X-Provider-Account: account-blue`，以及第二个 `Authorization`（调用方自己塞的）。每条 dispatch：`refused` 是 null，`plaintext_sha256` 等于调用方字节的 SHA-256，`appKey` 和 `token` 是 blue 的（比对，不打印），三个 nonce 不同，`msgType` 是 `IECS_CREATE_ORDER`，目标恰好是 `/openapi/api/dispatch`；调用方的头、`x-idp-*`、`authorization`、Gatekeeper 令牌和塞进去的凭证都不在记录里；没有新的取令牌。头名只记不判。`Set-Cookie` 不到调用方。三张单都取消 |
| SF-04 | 不带令牌、别的受众、伪造签名，三条路径都做：401，`gateway-authz` 没有被问，签名器没有被叫，承运商没有 dispatch 也没有取令牌 |
| SF-05 | 替身：green 的令牌用的是 green 的应用（dispatch 上是 green 的 `appKey` 和令牌）；green 取消不了 blue 的单（业务 `success` 假；订单按应用归属是替身的假设）。blue 带 `X-Provider-Account: account-green`：403 `ACCOUNT_NOT_GRANTED`，签名器没被叫，承运商什么都没收到。`--sandbox`：green 被拒 403（原因码记下），上面两段跳过；blue 要 green 的账户仍做（403，到不了承运商） |
| SF-06 | 登记表认、Gatekeeper 没有授权的客户端：403 `ACCOUNT_NOT_GRANTED`，签名器没被叫 |
| SF-07 | `GET`、`PUT`、`DELETE`、`PATCH` 打在三条路径上：网关 404，`gateway-authz` 没被问，签名器没被叫。只是前缀或靠近的路径（`/orders/`、`/orders/X`、`/orders-extra`、`/order-cancellations/1`、`/agent-number-queries/x`、`/orders/../orders`、`%2e%2e`、`%2f`、`%252e`、`;x=1`、`%00`、`//orders`、大写、签名器自己的 `/sfintl/v1/orders`、别的承运商的路径、`/providers/sfintl/v2/orders`）：拒绝（>= 400），签名器没被叫，承运商什么都没收到。允许的路径加上 `?x=1`：拒绝（>= 400），承运商什么都没收到；谁拒绝的记在备注里，不另判 |
| SF-08 | 用 blue 的令牌，经网关：`Content-Type: text/plain` → 415 `unsupported_media_type`；JSON 数组、两个对象、空正文、不是 JSON → 400 `body_not_json_object`；超过 1 MiB → 拒绝（>= 400），状态和是谁答的记在备注里。应答是签名器自己的 JSON，承运商没有 dispatch。两种跑法都做（出不了这台机器） |
| SF-09 | 见下 |
| SF-10 | 扫描，见上 |
| SF-11 | 留给单机池上的出口规则。这里没有这个用例，也没有 `pool.py` |
| SF-12 | `gateway-control revoke` 撤销 blue，请求用的是只读的查询：403，应答和判定都是 `ACCOUNT_REVOKED`，签名器没被叫；替身上 green 不受影响；`revocations` 列出来；`restore` 之后 blue 又被服务；`gateway-authz` 是同一个进程 |
| SF-13 | 只在替身。(a) `/admin/tokens/void`：下一个请求 HTTP 200，承运商的 `apiResultCode` 500 原样过来；接着几次仍然失败的次数只记不判。然后按 `gateway-authz` 要的办法（旁边写新文件，再改名盖上去）把 blue 的 `key_version` 改掉：下一个请求做成，替身只见到一次新的取令牌，进程还是同一个，green 的令牌没有再取。(b) `/admin/token-lifetime?seconds=5`，再改一次 `key_version`，做成一个请求；等到这个令牌过了寿命，下一个请求用的是新令牌（又一次取令牌，dispatch 没有被拒）。寿命放回 7200，`key_version` 放回。(c) 换成一份读不成的文件（多一个不认识的成员）：下一个请求仍用最后一份读得成的；第一份放回去，又能做成 |
| SF-14 | 只在替身。`slow` 11 秒：调用方得到签名器自己的 504 `carrier_timeout`，用时在签名器的 8 秒附近（不是网关的 9 秒），承运商恰好一个创建 dispatch，订单在；同一份再创建答 `123052` 和同一个运单号；一共两个创建 dispatch；取消。`cut`：调用方得到签名器的 502（哪一种记在备注里），一个 dispatch，订单在，同样再创建。`status` 503 → 502 `carrier_status`，`carrier_status` 是 503。`garbage` → 502 `carrier_answer_unreadable`。`undecryptable` → 502 `carrier_answer_unreadable`，订单在，取消掉。这些应答都没有 `Set-Cookie` 和 `X-Mock-Provider` |
| SF-15 | 直接打 27618，不经网关，两种跑法都做。没有客户端证书：握手或请求失败。`rogue-gateway`（另一个 CA）：失败。`business-app`（CA 对、身份不对）：403 `caller_not_allowed`。`gateway` 的证书、不带 `Authorization`：403 `credential_malformed`。调用方按名字 `provider-signer.idp.test` 核对。每一项承运商都没有 dispatch |

创建答了运单号的单都记在 `CREATED` 里，不管检查过没过，结束前都取消。剩下的按上面的办法报出来。

### 哪些用例在哪种跑法下跳过

| | 替身（`run.py`） | `--sandbox` |
|---|---|---|
| SF-01、02、05 | 全做 | 只在替身上看得到的检查跳过（`Set-Cookie`、取了几次令牌、`cancel-not-yet`、green 的应用和「取消不了别人的单」） |
| SF-03、13、14 | 做 | 整个跳过 |
| SF-04、06、07、08、10、15 | 做 | 做。SF-08 的正文到不了承运商 |
| SF-09 | 做 | 做；最后那个看承运商收到了谁的 `appKey` 的对照跳过 |
| SF-12 | 做 | 做；撤销前确认 blue 能通的那一次、以及 green 不受影响，跳过 |
| SF-11 | 不做 | 不做 |

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

只有带这个参数才写 `tests/integration/sfintl/evidence/`。对着替身是 `rig-standin.json`，对着沙箱是 `rig-sandbox.json`。和 `--mutate` 不能一起用。字段与万邦那套相同；`dataset` 里是 `reference_prefix`、`orders_created_and_cancelled`、`orders_left_uncancelled`（运单号）。写完再读一遍，里面有这次的秘密或 `Sf-OpenApi …;`、`auth_<8 个以上>`、`Bearer ` 加 16 个以上字符，就删掉文件、退出码非零。契约测试（`tests/contracts/test_sfintl_config.py`）看有的文件。

`rig-standin.json` 是 2026-11-20 在 `094c5e5` 上对着替身带 `--evidence` 的那一遍：14/14，284 项检查都过，没有跳过，25.5 秒，取消了 9 张单，没有剩下的。`uncommitted_files` 是 0。`rig-sandbox.json` 是上面第二遍，同一提交，未提交文件数也是 0。

## 没有做的

- **`pool.py`** 没有写。SF-11（出口规则）留着。`run.py` 里的 `HOOKS` 是留给以后在单机池上跑的。单机池的叠加 compose、`gateway-control publish`、签名器自己的出口规则，都没有做。
- **请求头名单的对照**没有做，原因在上面。
- **到承运商的 TLS** 没有验。沙箱是明文 HTTP。
- **面单**（`IECS_PRINT_ORDER`）和别的 `msgType`。
- **几个 `gateway-authz` 一起取同一个应用的令牌**，一次重启也是一次新的取令牌，生产上会作废前一枚。沙箱令牌是固定的，验不了。
- **`gateway-authz` 到令牌端点的连接没有出口规则。**
- **取令牌失败只记一个类别**，第一遍的两次 `unreachable` 分不出更细的原因。
- **`--carrier-timeout` 不短于 9 秒时程序不拒绝**（对照 `signer-long-timeout`）。
- **发给承运商的请求还带着 Go 默认的 `User-Agent` 和 `Accept-Encoding: gzip`。** 替身只记下了头名。
