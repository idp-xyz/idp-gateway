# 顺丰国际（SF International，IECS 出口电商）沙箱的出站配置

[开发计划](../../../docs/development-plan.md) 1.1 的第二家承运商：一份手写的 agentgateway 配置和一份登记表，照[万邦那一份](../wanbexpress/README.md)的样子，值也是[单机池](../../compose/README.md)的。这家的协议要加密正文、对密文签名，网关做不了，所以路由的上游不是承运商，而是签名适配器 `provider-signer`（[ADR-0014](../../../docs/adr/ADR-0014.md)）。

**这份配置在联调架子上和单机池上，对着替身和真实沙箱都跑过**（[tests/integration/sfintl](../../../tests/integration/sfintl/README.md)，证据 `rig-standin.json`、`rig-sandbox.json`、`pool-standin.json`、`pool-sandbox.json`）。见下面「发布到池」。

现在查过的：锁定的 agentgateway 1.7.0 的 `--validate-only` 接受这份文件；离线的[契约测试](../../../tests/contracts/test_sfintl_config.py)查配置、登记表和 Go 代码里的几个常量互相对得上（操作表、凭证前缀、适配器的默认超时），并查联调套件的替换还在；联调套件把这份文件换上联调的地址后，经网关、`gateway-authz` 和 `provider-signer` 对着替身跑过，也在 2026-11-20 对着真实沙箱跑了两遍。第二遍的证据是 `rig-sandbox.json`（14/14，168 项过、65 项跳过）。第一遍 13/14，前两次取令牌失败，证据没有留在仓库里，写在提交 `7fd2dd2` 的说明里。细节在套件的 README 里。

```
调用方 → 网关 → provider-signer（双向 TLS）→ 承运商
```

`gateway-authz` 向承运商取访问令牌，放行时交出 `Sf-OpenApi appKey;令牌;AES密钥`；网关只把这一个头转给 `provider-signer`，由它拆开、加密正文、签名、发给承运商、把应答解开。

- `agentgateway.yaml`：完整的一份，锁定的 agentgateway 1.7.0 直接能用。业务监听 `8081`（`front` 转给它）、回读口 `8443`、管理、指标、就绪 `15000`、`15020`、`15021`，证书是 `tls/<文件名>`，`gateway-authz` 是池里的服务 `gateway-authz:9443`，`provider-signer` 是 `provider-signer:9444`（都按名字找，出口规则才管得到这两跳），JWKS 是文件 `tls/jwks.json`。后端 `provider-signer:9444` 带 `backendTLS`：网关出示自己的证书，按 `provider-signer.idp.test` 核对对方。
- `policy.example.json`：`gateway-authz --policy` 的登记表，三行。`TENANT-ID-*`、`CLIENT-ID-*` 是占位，部署时填 Gatekeeper 的租户号和 M2M 客户端号（令牌的 `sub`）；`account-blue`、`account-green` 是 Gatekeeper 里 `provider_account` 对象的名字，也是应用文件里句柄 `gatekeeper:sfintl-test/<账户>` 的后半。`upstream_hostname`、`port` 写的是路由的上游，也就是 `provider-signer:9444`；`gateway-authz` 不读这两个字段。`enforce_tls_upstream` 是 `true`，指网关到 `provider-signer` 这一跳；`provider-signer` 到沙箱那一跳是明文，这个字段不管它。
- 环境是 `TEST`，写在路由里（Gatekeeper 的令牌没有 `env`，一个池只信一个签发者）。

## 三个操作

| 调用方的请求 | `provider-signer` 的路径 | `msgType` | 路由 / `x-idp-operation-id` |
|---|---|---|---|
| `POST /providers/sfintl/v1/orders` | `POST /sfintl/v1/orders` | `IECS_CREATE_ORDER` | `sfintl-orders-create` / `orders.create` |
| `POST /providers/sfintl/v1/order-cancellations` | `POST /sfintl/v1/order-cancellations` | `IECS_CANCEL_ORDER` | `sfintl-orders-cancel` / `orders.cancel` |
| `POST /providers/sfintl/v1/agent-number-queries` | `POST /sfintl/v1/agent-number-queries` | `IECS_QUERY_AGENTNO` | `sfintl-agent-numbers-query` / `agent-numbers.query` |

三个路径前缀互相不是对方的前缀，所以一个请求最多对上一条路由。别的方法和路径到不了 `provider-signer`：方法对不上，网关自己答 404；路径以这三个前缀之一开头、却不是恰好这个路径（更深的路径、`..`、编码的斜杠），路由上的 `authorization` 规则答 403。登记表只比较路径前缀，"恰好这一个路径"只写在网关的路由上。`provider-signer` 自己的操作表也只认这三个方法加路径，完全相等。

## 应用文件

`gateway-authz --sf-openapi-apps FILE`。权限 0600 或更严，不进仓库。JSON 对象，键是凭证句柄 `gatekeeper:sfintl-test/<账户>`，值里五个成员都要有，不认识的成员被拒绝。下面的值都是编出来的占位：

```json
{
  "gatekeeper:sfintl-test/account-blue": {
    "token_endpoint": "http://api-ifsp-sit.sf.global/openapi/api/token",
    "app_key": "APP-KEY-PLACEHOLDER",
    "app_secret": "APP-SECRET-PLACEHOLDER",
    "encoding_aes_key": "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
    "key_version": "1"
  }
}
```

- `token_endpoint`：令牌端点，不带查询串；`app_key` 和 `app_secret` 由 `gateway-authz` 自己放进查询串。默认只许 `https`；沙箱是明文，要加 `--sf-openapi-plain-http-host api-ifsp-sit.sf.global`。
- `encoding_aes_key`：43 个字符（末尾补一个 `=` 之后是 32 字节的 base64）。
- `key_version`：改它，`gateway-authz` 缓存里这个句柄的令牌就作废，下一次放行时重新取。
- `--sf-openapi-timeout`：取一次令牌的超时，默认 800 毫秒；路由上 `extAuthz` 等 `gateway-authz` 最多 1 秒，它要留在这 1 秒之内。
- 一个 `app_key` 只能写在一个句柄下。

## `provider-signer` 的启动参数（这份配置期望的）

- `--listen`：端口是 `9444`。
- `--tls-cert`、`--tls-key`：证书要是给 **`provider-signer.idp.test`** 的，网关按这个名字核对（SNI 也是它），并由 `tls/ca.crt` 那个 CA 签发。
- `--client-ca`：签发网关证书的 CA。
- `--gateway-identity`：网关证书（`tls/gateway.crt`）里的 URI。`provider-signer` 只服务这一个对端。
- `--carrier-url`：承运商的 dispatch 地址，完整的。承运商的地址只在这里，不在网关的配置里。沙箱是 `http://api-ifsp-sit.sf.global/openapi/api/dispatch`，要加 `--carrier-plain-http-host api-ifsp-sit.sf.global`。
- `--carrier-timeout`：默认 8 秒。这份配置用默认值，它小于路由的 9 秒；不小于时网关先放弃，`provider-signer` 的 504 就没有人收了。程序只拒绝不大于 0 的值，不拒绝 20 秒（对照 `signer-long-timeout`）。

## 给调用方的话

1. **三层结果，HTTP 200 不等于业务成功。**
   - `provider-signer` 自己的错误：HTTP 状态 4xx、5xx，正文是 `{"error": "...", "detail": "..."}`，`detail` 是固定的英文说明。只有 `carrier_status` 这一种另带一个整数字段 `carrier_status`，是承运商答的 HTTP 状态。

     | HTTP | `error` | 什么时候 |
     |---|---|---|
     | 403 | `caller_not_allowed` | 对端不是配置的那个网关 |
     | 404 | `unknown_operation` | 方法加路径不在操作表里 |
     | 400 | `query_not_allowed` | 请求带了查询串 |
     | 415 | `unsupported_media_type` | `Content-Type` 不是 `application/json` |
     | 403 | `credential_malformed` | `Authorization` 头不是恰好一个，或里面不是可用的 `Sf-OpenApi appKey;令牌;AES密钥` |
     | 413 | `request_too_large` | 正文超过上限（默认 1 MiB） |
     | 400 | `body_not_json_object` | 正文不是恰好一个 JSON 对象 |
     | 500 | `internal` | 请求没能做出来（加密或随机数出错） |
     | 504 | `carrier_timeout` | 承运商没有在 `--carrier-timeout` 内答 |
     | 502 | `carrier_unreachable` | 连不上承运商 |
     | 502 | `carrier_status` | 承运商答的 HTTP 状态不是 200 |
     | 502 | `carrier_answer_unreadable` | 承运商的答复读不了（不是信封、解不开、`appKey` 对不上、太大） |

   - 承运商信封的 `apiResultCode`：为 0 时 HTTP 是 200，`apiResultData` 是 `provider-signer` 解开的 JSON；不为 0 时 HTTP 仍是 200，信封按承运商的字节原样给调用方，不解密。
   - 业务结果在 `apiResultData` 里的 `success` 和 `code`。要 `apiResultCode` 为 0 并且 `success` 为真，才算成功。
2. **正文必须是一个 JSON 对象，`Content-Type: application/json`，不能带查询串。** 调用方发明文，加密和签名不用管。
3. **2026-11-20 在沙箱上量到的（文档没写）：**
   - 新的 `customerOrderNo` 下单成功时，业务应答是 `{"data":{"agentCode","customerOrderNo","directionCode","sfWaybillNo"},"success":true}`，没有 `code`。
   - 订单还在时，用同一个 `customerOrderNo`、同一份正文再下：`success` 为真，`code` 为 `"123052"`，`sfWaybillNo` 是已有的那个，没有新建。
   - 取消。2026-11-20 在沙箱上量到的，原因不知道，量的是沙箱，不是生产。要么下单后几秒内被接受，要么要到下单之后大约 5 到 8.5 分钟才被接受。池上后来有一次，从第一次取消尝试起 493.595 秒才被接受。套件这一次用 600 秒的预算等过了，还剩 106 秒。不是说以后都够。在那之前，业务拒绝是 HTTP 200、`apiResultCode` 0、`{"code":"500","msg":"请求服务发生异常","success":false}`，订单还在。调用方要把被拒的取消再试上几分钟，不是再试几秒。接受之后 `code` 为 `"200"`。
   - 取消之后，同一个 `customerOrderNo` 可以再用，得到新的运单号。
   - 查代理单号（`IECS_QUERY_AGENTNO`）对刚下的单答 `wrongData` 里 `status` 为 `"4002"`（代理单号未生成），取消后是 `"4001"`。
   - 沙箱的 `apiUsername` 要填文档给的测试用户名。
   - 没有量过：同一个 `customerOrderNo` 换一份正文再下；取消不存在的订单。
4. **网关不重试。** 创建超时之后结果是未知的，网关不重放；`front` 也不重放。

## 沙箱只有明文 HTTP

**两段都是明文：`gateway-authz` 向令牌端点取令牌，`provider-signer` 向承运商发请求。正文是 `provider-signer` 加过密的，但 appKey、访问令牌和签名在明文的请求头里，应用密钥在取令牌请求的查询串里，经公网到沙箱。这只对沙箱可以接受。** 要分别给 `gateway-authz` 加 `--sf-openapi-plain-http-host`、给 `provider-signer` 加 `--carrier-plain-http-host`。正式环境是 https；到承运商的 TLS 在这里没有验过。登记表里 `enforce_tls_upstream` 写的是网关到 `provider-signer` 这一跳，`gateway-authz` 不读它。

## 发布到池

叠加文件是 [provider-signer.yml](../../compose/provider-signer.yml)，和 `compose.yml`、`gateway-authz.yml` 一起用，不改那两个文件。变量在 [provider-signer.env.example](../../compose/provider-signer.env.example)，抄进同一个 `.env`。命名空间、出口规则、`gateway-authz` 的命令为什么要整份重写，写在 [deploy/compose](../../compose/README.md) 的「provider-signer（叠加文件）」。

```bash
docker compose -f compose.yml -f gateway-authz.yml -f provider-signer.yml up -d
```

发布用 `gateway-control publish`。池上怎么跑、跑过什么，见[套件](../../../tests/integration/sfintl/README.md)的「单机池上」。

## "默认配置不安全的地方"九项

九项的说明在[黑盒报告](../../../tests/acceptance/blackbox/README.md)。这家的上游是 `provider-signer`，到承运商的请求由它自己做，所以第 1 项和第 9 项与万邦不同：网关的名单保护的是到 `provider-signer` 的这一跳。

| # | 项 | 这份配置里 | 看着的用例 |
|---|---|---|---|
| 1 | Host 原样转发 | 每条路由 `urlRewrite.authority` 写成 `provider-signer.idp.test`。到承运商的 `Host` 由 `provider-signer` 按 `--carrier-url` 自己写，调用方的 `Host` 到不了那里 | **这份配置上没有用例判 `host` 的值**。SF-03 只记下承运商看到的头名（里面有 `host`），并查调用方自己的头没有到 |
| 2 | 路径不做规范性检查 | 每条路由的 `authorization` 规则 `request.path == "..."` 只放行本操作的那一个路径（完全相等），`gateway-authz` 再按同一条规范路径规则判一次，`provider-signer` 的操作表再按方法和路径完全相等查一次。比评审配置里的规则更严，替代了它 | SF-07 |
| 3 | PDP 放行却没给凭证 | 后端规则，前缀 `Sf-OpenApi `。`provider-signer` 另外要求恰好一个 `Authorization` 头、三段都有，不然答 403 `credential_malformed`，不联系承运商 | SF-09（对照见套件 README） |
| 4 | `Location`、`Set-Cookie` 回给调用方 | `responseHeaderModifier.remove`，与万邦同文。`provider-signer` 的答复头是它自己写的，不取自承运商的答复 | SF-01、SF-03、SF-09、SF-14（替身发 `Set-Cookie`，不发 `Location`，所以只看到了 `Set-Cookie` 被去掉） |
| 5 | `Cookie`、`X-Forwarded-*`、`Forwarded` 到承运商 | 后端 `requestHeaderModifier.remove`，与万邦同文。到承运商的请求头是 `provider-signer` 自己写的，没有一个取自调用方 | SF-03。这套架子上没有「去掉名单」的对照：签名器本来就不转发调用方的头，承运商的记录显示不出来名单在不在 |
| 6 | 没有会话密钥时网关改写配置文件 | 文件里没有 `config.session.key`，部署时用环境变量 `SESSION_KEY`；契约测试查文件里没有 `session` | **这份配置上没有用例**：文字与评审配置相同，黑盒的 `P1-CF-01` 对评审配置看着；这里只有契约测试查文件里没有 `session` |
| 7 | 管理接口能改配置 | `config.storage.mode: readOnly`；契约测试查这一行在 | **这份配置上没有用例**：同上，黑盒的 `P1-CF-02`；契约测试查这一行在 |
| 8 | 业务监听开在所有网卡 | `bindAddress: 127.0.0.1`；契约测试查这一行在 | **这份配置上没有用例**：黑盒的 `P1-NL-01`；契约测试查这一行在 |
| 9 | 调用方自己的请求头到承运商 | 后端用同一份名单重建请求头（名单与评审配置同文，契约测试对着它查），发给 `provider-signer`；`provider-signer` 不把调用方的任何请求头带到承运商，所以名单保护的是到 `provider-signer` 的这一跳 | SF-03（`X-Evil-Probe` 没有到）。没有名单对照，原因同第 5 项 |

另外：回读口（8443）和它的一条路由、`frontendPolicies.networkAuthorization` 照万邦那份留着，发布器要用；契约测试对着万邦的文件查这几处和 `config`、`gateways` 一字不差。

## 与万邦那份不同的地方

- 后端是 `provider-signer:9444`，不是承运商；后端带 `backendTLS`（网关的证书、`tls/ca.crt`、对方的名字 `provider-signer.idp.test`）。
- 三条路由都是 `POST`，每条的 `authorization` 规则是完全相等的一个路径；三个路径前缀互不包含，登记表里是三行不同前缀。万邦有三条路由共用 `/parcels` 前缀、靠方法区分。
- 没有 `Accept` 的改写：这家没有 `Accept` 的要求；`Content-Type` 不是 JSON 的请求由 `provider-signer` 以 415 拒绝，网关不改写它。
- 凭证的前缀是 `Sf-OpenApi `，不是 `Hc-OweDeveloper `；凭证来自应用文件，不是开发者令牌文件。
- `urlRewrite` 把 `Host` 写成 `provider-signer.idp.test`，路径前缀写成 `provider-signer` 的路径（`/sfintl/v1/...`）。
- 访问日志里客单号取自请求正文的 `customerOrderNo`，承运商的单号取自应答的 `apiResultData.data.sfWaybillNo`；查询操作在这两处都没有东西。
- 同样的：路由超时 9 秒（`front` 等网关最多 10 秒；`provider-signer` 自己的超时 8 秒，它的 504 先到）、不重试、请求头名单、`responseHeaderModifier.remove`。

## 没有做的

- **面单**（`IECS_PRINT_ORDER`）和别的 `msgType`。操作表里只有上面三个。
- **池上没有接撤销。** 叠加文件给 `gateway-authz` 加的只有 `--sf-openapi-apps` 和 `--sf-openapi-plain-http-host`，不带 `--revocations`。套件的 SF-12 在池上整个跳过。
- **到承运商的 TLS**：沙箱没有，没有验过。
- **`gateway-authz` 到令牌端点的连接没有出口规则。**
- **令牌刷新时旧令牌立刻作废**（承运商文档写的）：`gateway-authz` 不知道承运商把缓存里的令牌作废了。SF-13 在替身上量到：作废之后的下一次请求，和接着的三次，都是 HTTP 200、承运商的 `apiResultCode` 500，原样给调用方；把应用文件里的 `key_version` 改掉（旁边写新文件，再改名盖上去）之后才重新取。已经带着旧令牌在路上的那一个请求没有单独量。
- **取令牌失败仍记一个类别**（`timeout`、`unreachable`、`status N`、`code N`、`bad_answer`），不写地址，也不写错误原文，因为地址里有应用密钥。`timeout` 和 `unreachable` 另有属性 `cause`，一个固定的词（`e88a7c5`）。2026-11-20 第一遍沙箱的两次 `unreachable` 发生在这之前，那两次的日志里没有 `cause`，分不出更细的原因。
- **几个 `gateway-authz` 实例会互相作废令牌**，一次重启也是一次新的取令牌，生产上同样作废前一枚。一个应用只能有一个取令牌的进程。沙箱令牌是固定的，这一条验不了。
- **`--carrier-timeout` 不短于路由的 9 秒时，程序不拒绝。** 给 20 秒，调用方在 9.0 秒得到网关自己的 504（对照 `signer-long-timeout`）。
- **发给承运商的请求还带着 Go 默认的 `User-Agent`（`Go-http-client/1.1`）和 `Accept-Encoding: gzip`。** 替身记下的头名里有这两个（SF-03，只记名字）。
- **访问日志里 `provider_reference_id`、`provider_request_id`**：SF-01 看到创建那一行带着这两个字段，分别是这次的 `customerOrderNo` 和应答里的 `sfWaybillNo`。沙箱那一遍也看到了。查询在这两处都没有东西，没有另查。
- **查询串在网关上没有限制**。SF-07 看到 `POST /providers/sfintl/v1/orders?x=1` 被 `provider-signer` 以 400（`query_not_allowed`）拒绝，调用方看到的也是 400，承运商没有收到。网关自己没有拦。
