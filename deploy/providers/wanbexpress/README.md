# 万邦速达（WanbExpress）沙箱的出站配置

[开发计划](../../../docs/development-plan.md) 3.2 的第一步：为 1.1 的承运商手写的一份 agentgateway 配置和一份登记表。模板是评审过的[黑盒配置](../../../tests/acceptance/blackbox/agentgateway.poc.yaml)里的 `mockcarrier-parcels-get-developer-token`。对着替身跑过，也在单机池上（`deploy/compose` 加 `gateway-authz.yml`）对着替身跑过；两处都在[套件](../../../tests/integration/wanbexpress/README.md)里。

- `agentgateway.yaml`：完整的一份，锁定的 agentgateway 1.7.0 直接能用，写的是[单机池](../../compose/README.md)的值：业务监听 `8081`（`front` 转给它）、回读口 `8443`、管理、指标、就绪 `15000`、`15020`、`15021`，证书是 `tls/<文件名>`，`gateway-authz` 是池里的服务 `gateway-authz:9443`（按名字找，出口规则才管得到这一跳），JWKS 是文件 `tls/jwks.json`（出口规则只放行配置里写着的地址，所以不从 URL 取；签发者仍是签令牌的那个，`http://127.0.0.1:27621` 是本机 Gatekeeper 的）。上游是 `api-sbx.wanbexpress.com:80`。联调架子上的套件把这些值用精确替换换回联调的。
- `policy.example.json`：`gateway-authz --policy` 的登记表。`TENANT-ID-*`、`CLIENT-ID-*` 是占位，部署时填 Gatekeeper 的租户号和 M2M 客户端号（令牌的 `sub`）；`account-blue`、`account-green` 是 Gatekeeper 里 `provider_account` 对象的名字，也是开发者令牌文件里句柄 `gatekeeper:wanbexpress-test/<账户>` 的后半。
- 开发者令牌文件（`gateway-authz --developer-tokens`，0600，不进仓库）的格式见 [ADR-0011](../../adr/ADR-0011.md)：`{"gatekeeper:wanbexpress-test/account-blue": {"account": "客户代码", "token": "开发者令牌"}}`。
- 环境是 `TEST`，写在路由里（Gatekeeper 的令牌没有 `env`，一个池只信一个签发者）。

## 四个操作

| 调用方的请求 | 到承运商 | 路由 / `x-idp-operation-id` |
|---|---|---|
| `GET /providers/wanbexpress/v1/whoami` | `GET /api/whoami` | `wanbexpress-whoami-get` / `whoami.get` |
| `POST /providers/wanbexpress/v1/parcels` | `POST /api/parcels` | `wanbexpress-parcels-create` / `parcels.create` |
| `GET /providers/wanbexpress/v1/parcels/{processCode}` | `GET /api/parcels/{processCode}` | `wanbexpress-parcels-get` / `parcels.get` |
| `DELETE /providers/wanbexpress/v1/parcels/{processCode}` | `DELETE /api/parcels/{processCode}` | `wanbexpress-parcels-delete` / `parcels.delete` |

别的方法和路径到不了承运商：方法对不上，网关自己答 404；路径形状不对（列表、搜索、更深的路径、`..`、编码的斜杠），路由上的 `authorization` 规则答 403。登记表只比较路径前缀，"前缀下恰好一段"这个形状只写在网关的路由上。

## 给调用方的三句话

1. **HTTP 200 不等于业务成功。** 承运商的业务错误也答 200，要看正文里的 `Succeeded`，失败时看 `Error.Code`；网关原样透传，不改写。
2. **`Accept` 由网关写。** 承运商只认 `application/json`；调用方带了别的值也被换掉，不带也会补上。
3. **`ReferenceId` 全局唯一。** 创建超时之后，用同一个客单号、**同一份正文**重下，沙箱会幂等地把已有的那一个答回来（同一个处理号，没有新建）；正文不同才是 `0x100005`（HTTP 200，`Succeeded` 为 false）。网关不重试写操作。查不到的处理号是 HTTP 404、正文为空，不是 200 加错误码。（2026-11-19 在沙箱上量到的，文档没写。）

## 沙箱只有明文 HTTP

**开发者令牌是明文经公网到沙箱的。这只对沙箱可以接受。正式环境的上游必须是 https；到承运商的 TLS（证书、SNI）在这里没有验。** 登记表里 `enforce_tls_upstream` 写了 `false`，`gateway-authz` 不读这个字段。

## 发布到池

池的 `tls/` 里放网关的证书和 `jwks.json`，`gateway-authz.yml` 的变量填好；`docker compose -f compose.yml -f gateway-authz.yml up -d agentgateway`，再 `gateway-control publish --snapshot agentgateway.yaml …`，再 `up -d`（见 [deploy/compose](../../compose/README.md) 的"头一次安装"和"gateway-authz"）。

**`jwks.json` 里可以放几把密钥，换密钥时两把并存。** 网关把 JWKS 的几把密钥按不定的顺序列在运行配置里；发布器的摘要与这个列表的顺序无关（ADR-0010 第 6 条，2026-11-19 修的），所以发布不会因为顺序而被还原。

## "默认配置不安全的地方"九项

九项的说明在[黑盒报告](../../../tests/acceptance/blackbox/README.md)。用例号是[套件](../../../tests/integration/wanbexpress/README.md)的。

| # | 项 | 这份配置里 | 看着的用例 |
|---|---|---|---|
| 1 | Host 原样转发 | 每条路由 `urlRewrite.authority` 写成沙箱的名字 | WB-04（上游收到的 `Host`） |
| 2 | 路径不做规范性检查 | 每条路由的 `authorization` 规则只放行本操作的路径形状（字符是非保留字符，段不以点开头），`gateway-authz` 再按同一条规范路径规则判一次。比评审配置里的规则更严，替代了它 | WB-08 |
| 3 | PDP 放行却没给凭证 | 后端规则，前缀 `Hc-OweDeveloper ` | WB-09（对照见套件 README） |
| 4 | `Location`、`Set-Cookie` 回给调用方 | `responseHeaderModifier.remove`。替身会发 `Set-Cookie`，不发 `Location`，所以只看到了 `Set-Cookie` 被去掉 | WB-01、WB-04、WB-09 |
| 5 | `Cookie`、`X-Forwarded-*`、`Forwarded` 到承运商 | 后端 `requestHeaderModifier.remove` | WB-04 |
| 6 | 没有会话密钥时网关改写配置文件 | 文件里没有 `config.session.key`，部署时用环境变量 `SESSION_KEY`；套件从 `.run/` 下的副本启动 | **这份配置上没有用例**：文字与评审配置相同，黑盒的 `P1-CF-01` 对评审配置看着；这里只有契约测试查文件里没有 `session` |
| 7 | 管理接口能改配置 | `config.storage.mode: readOnly` | **这份配置上没有用例**：同上，黑盒的 `P1-CF-02`；契约测试查这一行在 |
| 8 | 业务监听开在所有网卡 | `bindAddress: 127.0.0.1` | **这份配置上没有用例**：黑盒的 `P1-NL-01`；契约测试查这一行在 |
| 9 | 调用方自己的请求头到承运商 | 后端用同一份名单重建请求头（名单与评审配置同文，契约测试对着它查） | WB-04（`X-Evil-Probe` 没有到） |

另外：回读口（27619）和它的一条路由、`frontendPolicies.networkAuthorization` 照评审配置留着，发布器要用。

## 与评审过的那条路由不同的地方

- 四条路由，`x-idp-verified-env` 是常量 `"TEST"`（联调架子的做法，不是 `jwt.env`）。
- 路径规则换成各操作的形状（见第 2 项）；路径改写按承运商的 `/api/...`。
- 后端多一处 `requestHeaderModifier.set`：`accept: application/json`，在名单之后执行，所以替掉调用方的值。
- 有 `POST` 和 `DELETE` 两条；评审过的那条只有 `GET`。同一个路径前缀 `/parcels` 上三条路由靠方法区分，登记表里是三行同前缀不同方法。
- 路由超时是 9 秒（评审配置是 2 秒，那是对着替身的值）：`front` 等网关最多 10 秒，比它长，调用方看到的是 nginx 的 504。9 秒的依据只有一次沙箱运行，见下面"没有做的"。
- 值是池的，不是黑盒配置里 `.run/` 下的那些；`gateway-authz` 按名字找；JWKS 是 `tls/jwks.json`。

## 没有做的

- **按客单号搜索**（`GET /api/parcels?referenceId=`）。被路径形状拒掉。四条路由上查询串都没有限制，会原样带到承运商。
- **池上的收尾**：看守和开机的两个单元还不带 `gateway-authz.yml`；撤销（`--revocations`、`--revoker-identity`）在池里没有接（联调架子上接了，套件的 WB-12 在那里看）；没有在别的机器上装过；池上对着真实沙箱的一遍由仓库所有者跑。
- **出口规则**。`deploy/compose/pin-egress.sh` 钉住的是名字第一次解析到的地址；沙箱的名字背后是一个负载均衡，解析出两个地址（2026-11-19），它们换了之后要人手工 `forget`。没有对这个名字试过。
- **超时和重试的取舍**。9 秒（受 `front` 的 10 秒限制）比 2026-11-19 量到的最慢一次（经网关第一次创建 8.5 秒）只多半秒，余量很小，而且只有一次运行的数据，不算有依据；`front` 的 10 秒要改的话是 `deploy/compose/front.nginx.conf`。之后的创建 120–870 毫秒，取和删 80–360 毫秒，`whoami` 约 100–200 毫秒。没有重试；写操作超时的结果是未知的，调用方用同一个客单号和同一份正文再下即可。套件的 WB-14（联调架子上，对着替身）看到：超时和应答发到一半断开，承运商都只收到一个 `POST`，再下一次得到的是已有的包裹；断开时调用方得到的是 200 加读不完的正文，不是网关的 5xx。给创建路由加 `retry` 本身不重放超时的请求，再加 `timeout.backendRequestTimeout` 才会（`--mutate create-retry`），这份配置两样都没有。
- 到承运商的 TLS；两个沙箱账户（只有一个账号）；撤销、凭证轮换在联调架子的套件里有用例（WB-12、WB-13，轮换只在替身上），在池上的套件里跳过；对着真实沙箱的撤销一遍由仓库所有者跑。
