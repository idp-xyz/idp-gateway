# 出站网关对接 Gatekeeper：生产变更需求与验收单

| 项 | 内容 |
|---|---|
| 日期 | 2026-11-24 |
| 状态 | Proposal。需 Gatekeeper 团队确认、排期并在 Gatekeeper 自己的仓库与运行环境中实施 |
| 提出方 | `idp-gateway`（出站网关） |
| 接收方 | Gatekeeper 团队 |
| 本仓库已做的事 | 只提出本单。未修改 Gatekeeper 仓库的任何代码，也未向 Gatekeeper 的检出目录写入文件 |
| 联调证据日 | 2026-11-20：Gatekeeper 检出 `f36dc06`，agentgateway `1.7.0`，本机 13/13 |
| 版本基线 | Gatekeeper 须含 `10dc843` 引入的 PDP 字段 `indeterminate`。`f36dc06` 在该提交之后 |

本单是跨团队的生产对接变更请求。文中的线协议、错误码和耗时均来自本仓库已有代码、联调记录和已接受的 ADR。未把未测量的容量数字写成承诺。

## 1. 文档定位与安全红线

### 1.1 这份文档是什么

Gatekeeper 是调用方身份的权威，也是「这个调用方此刻能不能用这个 Provider 账户」的权威。出站网关在登记表放行之后，由 `gateway-authz` 向 Gatekeeper 的 PDP 发 `POST /authz/check`。本单请 Gatekeeper 团队把第 3 节的五项收进 Gatekeeper 自己的模型、客户端登记、令牌声明、PDP 端点和换钥规程，使这些行为在 Gatekeeper 运行的非生产 / 预发布环境上成立。

2026-11-19，仓库所有者把开发计划 1.2、1.3 的五项交给网关一侧，定的是 P2 在什么上面跑、网关按什么做。那不是 Gatekeeper 团队的确认。开发计划 1.3 写明，上生产之前要 Gatekeeper 团队做四件：授权模型、按客户端登记受众、令牌里的环境、先发布后启用的换钥流程。本单把这四件写成变更 1、2、3、5。变更 4 单列：生产 PDP 由 Gatekeeper 自己终结工作负载 mTLS。开发计划 2.3 已记录网关一侧会出示客户端证书；「PDP 只收带证书的连接」仍要 Gatekeeper 做。

凭证正文不在本单的五项里。当前阶段正文由 `gateway-authz` 持有。KMS 托管是阶段 1 轨道 A 的后续 A3 步，见第 4 节。

`docs/integrations/Fabric_and_Gatekeeper_Change_Impact.md` 的状态是 Proposal / Impact Assessment，没有改 Gatekeeper 的正式设计。本单同样不改 Gatekeeper 仓库。跨系统的模型与流程以 Gatekeeper 团队书面接收为准。

### 1.2 安全红线

所有联调、探测和验收只能对着 Gatekeeper 的非生产或预发布环境做。

禁止以生产主机 `gk.idp.xyz` 做测试，禁止把测试租户、测试客户端和测试授权关系建到该环境。本仓库的联调脚本不访问这台主机。开发计划 1.2 已写明：已发布的 `gk.idp.xyz` 是生产环境，任何测试都不访问它。P2 使用的是本机实例，令牌出自带着本机改动的实例，不是 Gatekeeper 团队运行的环境。

预发验收记录要写明：环境名、Gatekeeper 提交号、五项变更已在 Gatekeeper 自己的代码和端点上，而不是本仓库的 `tests/integration/gatekeeper/compose.local.yml`。

### 1.3 项目现状

2026-11-20，在锁定的 agentgateway `1.7.0`（`deploy/agentgateway/agentgateway.lock.json`）和本机改造版 Gatekeeper（检出 `f36dc06`，Hydra v26.2.0 签发令牌与 JWKS）上，加 `--key-rotation` 连跑两遍，`GK-01` 至 `GK-13` 全部通过。JWKS 使用 `file: .run/jwks.json`，由 `gateway-control sync-jwks` 同步：启动时 `--once`，运行中 `--interval 2s`。`GK-12` 两遍都通过，网关没有重启。新密钥签的令牌第一遍第一个请求是 401，之后 2.015 秒被接受；第二遍同样先是 401，之后 1.012 秒被接受。`gateway-authz` 问 PDP 都走了带客户端证书的那一跳。逐项结果在 `.run/result.json`，不入库。这次通过不改变验收矩阵里任何用例的 `NOT_RUN`，也不是生产验收证据。

2026-11-19 的默认 12 个用例（`GK-01` 至 `GK-11` 与 `GK-13`）连跑两遍通过；当天没有重跑 `GK-12`，该用例当时仍是 2026-11-11 的 FAIL。对着更早的 `0920e96`（没有 `indeterminate`），现在的适配器过不了 `GK-08`。

本机 13/13 依赖三处只存在于本地测试栈的改动。这三处不在 Gatekeeper 仓库里，也不在已发布实例里。去掉它们、把 `gateway-authz` 指到生产 Gatekeeper，请求会按第 2 节失败关闭，而不会「差不多能通」：

1. 授权模型补丁。`stack.sh` 把 `tests/integration/gatekeeper/provider-account.types.json` 合并进本机 OpenFGA 模型。Gatekeeper 自己的 `deploy/openfga/model.json` 没有 `provider_account`。
2. 全局受众开关。`compose.local.yml` 把 `TOKEN_AUDIENCE` 设为 `bip-api,idp-egress-gateway`。默认列表只有 `bip-api`。
3. 临时 TLS 终结。`compose.local.yml` 的 `pdp-mtls` nginx 听 `27623`，要求客户端证书，只转发 `POST /authz/check`。Gatekeeper 自己的 PDP 仍在回环的 `27622` 上，明文，且联调还用它建租户、客户端和授权关系。

另有一处网关配置差异，不是 Gatekeeper 代码改动：黑盒配置里的 `x-idp-verified-env: jwt.env` 被换成路由常量 `"TEST"`（五处）。Gatekeeper 的 M2M 令牌没有 `env`。不换的话，`gateway-authz` 会把请求判成 `UNAUTHENTICATED`。本机 13/13 没有覆盖「令牌自带 `env`」这条路。

本机栈是 Gatekeeper 的开发配置：Hydra `--dev`、明文 HTTP、开发用的固定密钥，只是换了管理密钥并给 PDP 加了令牌。不能把本机通过写成生产形态已经验收。

## 2. 现状阻塞总览

下表是五项硬前置。直连当前生产 Gatekeeper（没有这五项）时，网关侧的后果如下。状态码和原因码是 `gateway-authz` 与联调已经对上的行为，不是建议值。

| # | 缺口 | 不改造就直连时的后果 | 本机为何能通过 |
|---|---|---|---|
| 1 | 正式 OpenFGA 模型没有 `provider_account` | PDP 对 `provider_account.use` 不做查询，HTTP 200，正文 `{"decision":false,"reason":"unknown action"}`，不带 `indeterminate`。适配器按 `reason` 以 `unknown action` 开头，读成没有结论。调用方得到 HTTP 503，`result` 为 `INDETERMINATE`，`reason_code` 为 `GRANT_STATE_UNAVAILABLE`。Provider 收不到请求。若 Gatekeeper 改了这个 `reason` 的开头，同一缺口会变成 HTTP 403、`ACCOUNT_NOT_GRANTED`（模型缺失被说成这个调用方没有授权）。这条读法有单元测试；联调套件没有「模型里没有该类型」的用例 | 本机模型被打进了 `provider_account` |
| 2 | M2M 客户端不能按客户端登记受众 `idp-egress-gateway` | 不带 `audience` 时令牌 `aud` 为空数组；带了也只能是该客户端登记过的受众，默认只有 `bip-api`。申请未登记的 `idp-egress-gateway` 时 Hydra 拒绝签发（客户端没有登记它；令牌端点那次拒绝的 HTTP 状态码未记入联调验收项）。网关只认 `idp-egress-gateway` 时，空 `aud` 或 `bip-api` 的令牌在网关被拒，HTTP 401，到不了 `gateway-authz` 和 Provider（`GK-03`）。若为了签发成功把网关受众改成 `bip-api`，任何发给 `bip-api` 的令牌都能用来敲出站网关 | 本机把全局 `TOKEN_AUDIENCE` 加成 `bip-api,idp-egress-gateway`。这个开关不能当生产方案，见变更 2 |
| 3 | M2M 访问令牌没有环境边界 | Hydra 顶层声明白名单没有 `env`，令牌钩子不写它。路由若取 `jwt.env`，`gateway-authz` 看不到 Token 环境，HTTP 403，`result` 为 `DENY`，`reason_code` 为 `UNAUTHENTICATED`（缺 `x-idp-verified-env` 的处理与缺租户、缺主体相同）。令牌带了与路由环境不一致的值时，原因码是 `ENVIRONMENT_MISMATCH`，同样是 403 `DENY`。本机没有走这条比对 | 联调把五处 `jwt.env` 换成路由常量 `"TEST"`：一个网关实例只信一个签发者，环境在部署时写死。签发者配错时没有第二道检查 |
| 4 | 生产 PDP 没有原生工作负载 mTLS | `--gatekeeper-url` 不是回环地址、又未同时给出四个 TLS 参数时，`gateway-authz` 拒绝启动，进程不监听。错误原文：`--gatekeeper-url is not a loopback address, so --gatekeeper-tls-cert, --gatekeeper-tls-key, --gatekeeper-tls-ca and --gatekeeper-name are required: this hop may not rest on a shared token alone`。四个参数只给一部分同样拒绝启动。给了证书则 URL 必须是 `https`，回环也一样。这不是运行期的 401/403 | 本机 PDP URL 走回环上的 nginx `https://127.0.0.1:27623`。证书校验的是 CN，不是 SAN URI，见变更 4 |
| 5 | 版本低于 `10dc843`，或访问令牌签名密钥加进 JWKS 后立即签发 | 低于 `10dc843` 时，OpenFGA 停掉的应答是 `{"decision":false,"reason":"rebac lookup failed"}`，没有 `indeterminate`。适配器把它读成拒绝：调用方 HTTP 403，`ACCOUNT_NOT_GRANTED`。对着 `0920e96` 时 `GK-08` FAIL，其余 10 个用例通过。换钥方面：agentgateway `1.7.0` 按 `jwks.url` 取 JWKS 时，重取间隔跟着 `Cache-Control`。本机 Hydra 的实际头是 `private, no-cache, no-store, must-revalidate`，单独试验里约 982 秒（16 分 22 秒）才重取；没有这个头时相同。新密钥签的令牌在此之前是 401。2026-11-11 的 `GK-12` 走 `jwks.url`、期望 60 秒内接受，结果 FAIL。`hydra create jwks` 是加进去就签发，做不到「先只发布」 | 联调要求检出在 `10dc843` 或之后，实测检出是 `f36dc06`。JWKS 改走文件，`sync-jwks --interval 2s` 原子替换后再被网关重载，所以 `GK-12` 能在数秒内接受。这是「已经开始签发」之后的同步速度，不是生产换钥规程本身 |

登记表、撤销和操作封禁若已拒绝，`gateway-authz` 不会去问 PDP。Gatekeeper 只能把登记表收窄，不能放宽。不带 `--gatekeeper-url` 时不问 PDP，行为与未接 Gatekeeper 时相同。问 PDP 的顺序在配额和发放凭证之前。

## 3. 五项必需变更

### 变更 1：OpenFGA 正式授权模型合入 `provider_account`

#### 背景

PDP 把模型里的「类型.关系」当作动作，因此模型里一旦有下面的类型，`provider_account.use` 就可以问，不必为这个动作改 PDP 的分支。本机加上该类型之后，`GK-01`、`GK-02`、`GK-05`、`GK-06`、`GK-07` 通过。

M2M 令牌的 `sub` 是客户端 ID（UUID），与 `client_id` 相同。PDP 把该客户端归一成 `user:<client_id>`。网关不规定主体类型必须叫 `user`，要求是：同一个客户端每次被问到的主体稳定，并与 `POST /authz/check` 里的 `subject.id`、上下文元组一致。

`tenant_id` 是租户 UUID，由令牌钩子从客户端元数据写入。登记表里的 `allowed_service_ids`、`allowed_tenants`、`accounts_by_tenant` 填的都是这些 UUID。

账户标识、租户标识和主体标识要能原样写进授权元组。`gateway-authz` 只接受匹配 `^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$` 的值。冒号、`#`、`*` 会被授权引擎当成语法。对不上的标识不会去问 PDP，直接按没有授权处理（HTTP 403，`ACCOUNT_NOT_GRANTED`）。UUID 落在这个字符集里。

#### 变更要求

把下列类型合入 Gatekeeper 正式授权模型（预发与之后的生产使用同一模型定义）。关系名保持 `org`、`caller`、`use`。

```text
type provider_account
  relations
    define org:    [org]                          # 账户属于哪个租户
    define caller: [user]                         # 谁被授予了这个账户
    define use:    caller and member from org     # 能用 = 获授，并且属于账户所属的租户
```

本仓库打进本机模型的 OpenFGA 类型定义在 `tests/integration/gatekeeper/provider-account.types.json`，与上面的 DSL 是同一含义：`use` 是 `caller` 与「沿 `org` 取到的 `member`」的交集；`org` 的直接类型是 `org`，`caller` 的直接类型是 `user`。

持久授权由 Gatekeeper 管理 API 写入，并留在 Gatekeeper 的审计里。本机联调写入并维持的两条是：

- `org:<租户 UUID>` — `org` — `provider_account:<账户>`
- `user:<客户端 UUID>` — `caller` — `provider_account:<账户>`

调用方属于哪个租户不由 Gatekeeper 事先存。`gateway-authz` 用已验签令牌的 `tenant_id`，在每次检查里带一条上下文元组。

若 Gatekeeper 要把 M2M 客户端收成另一种主体类型，须在回复里给出稳定映射，并保证对同一客户端的 `subject.id` 与元组用户字段不变。在此之前，按现有归一：`user:<client_id>`。

#### 线协议

`gateway-authz` 发 `POST {gatekeeper-url}/authz/check`，`Content-Type: application/json`，`Authorization: Bearer <PDP 令牌>`。不跟随重定向。令牌只发给配置的那个地址。一次询问的时限是 300 毫秒（代码常量 `DefaultTimeout`）。网关等 `gateway-authz` 的时限是 1 秒。这两个数是当前实现的上限，不是容量承诺。

```json
{
  "subject": {"id": "<令牌的 sub，M2M 为客户端 UUID>"},
  "action": "provider_account.use",
  "resource": {"type": "provider_account", "id": "<账户>"},
  "context": {
    "tenant_id": "<令牌的 tenant_id>",
    "contextual_tuples": [
      {"user": "user:<sub>", "relation": "member", "object": "org:<tenant_id>"}
    ]
  }
}
```

`provider_account.use` 为真，当且仅当：该主体是这个账户的 `caller`，并且是该账户 `org` 关系所指向的那个 `org` 的 `member`。`member` 由上面的 `contextual_tuples` 在这一次检查中给出。因此蓝租户的令牌申请绿租户的账户时，上下文里的 `org` 对不上账户所属的租户，结果为拒绝（`GK-06`）。

PDP 的四种应答都是 HTTP 200。适配器不把 HTTP 200 当成允许。

| 情况 | PDP 正文 | 适配器 | 调用方 |
|---|---|---|---|
| 有授权 | `{"decision":true,"reason":"rebac:use"}` | 有授权 | 继续后续步骤。联调 `GK-01` / `GK-02` 最终 HTTP 200 |
| 未授予该账户，或账户属于别的租户 | `{"decision":false,"reason":"rebac denied"}` | 没有授权 | HTTP 403，`result` `DENY`，`reason_code` `ACCOUNT_NOT_GRANTED` |
| 背后查询失败（OpenFGA 停了） | `{"decision":false,"indeterminate":true,"reason":"rebac lookup failed"}` | 没有结论 | HTTP 503，`result` `INDETERMINATE`，`reason_code` `GRANT_STATE_UNAVAILABLE` |
| 动作不在模型里 | `{"decision":false,"reason":"unknown action"}` | 没有结论。`reason` 以 `unknown action` 开头才这样读；不带 `indeterminate` | HTTP 503，`GRANT_STATE_UNAVAILABLE` |

读法：带 `"indeterminate": true` 的应答一律是没有结论，不管 `decision` 和 `reason` 写什么。`decision` 为 `true` 且不带该标记，是有授权。其余读得出的 `decision: false` 是没有授权，不再依赖 `rebac denied` 这句措辞。唯一仍看措辞的是「动作不在模型里」。Gatekeeper 自己的三个 SDK 也按 `unknown action` 这个开头认「动作没有映射」。

PDP 非 200、正文读不出 `decision`、连接失败、握手失败，同样是没有结论，调用方 503 `GRANT_STATE_UNAVAILABLE`，不是 403。

#### 验收标准

- 预发模型含 `provider_account` 的 `org`、`caller`、`use`，且 `use` 为「`caller` 并且是账户所属 `org` 的 `member`」。
- 用第 3 节的 JSON 询问已授权的账户，PDP 200 且 `decision` 为 `true`。
- `GK-01`、`GK-02`、`GK-05`、`GK-06`、`GK-07` 在预发上按第 5 节通过。
- 收回 `caller` 后的下一个请求即 403，恢复后的下一个请求即放行，不重启网关、不重启 `gateway-authz`（`GK-07`）。
- 模型里没有该动作时的 `unknown action` 行为保持可辨认，直到该类型已进入预发和将要上线的模型。类型进入之后，正常的 `provider_account.use` 不再走这条分支。

### 变更 2：按客户端登记专属受众 `idp-egress-gateway`

#### 背景

出站网关只接受受众 `idp-egress-gateway`。这是网关一侧 2026-11-19 的决定，与黑盒套件使用的受众相同。

已核实的 M2M 访问令牌（Hydra `client_credentials`）与黑盒套件自签令牌不同：

| 声明 | 黑盒套件自签令牌 | Gatekeeper 的 M2M 令牌 |
|---|---|---|
| `sub` | 服务名，如 `parcel-service` | 客户端 ID（UUID），与 `client_id` 相同 |
| `tenant_id` | 租户代号，如 `tenant-blue` | 租户 UUID |
| `env` | `TEST` | 没有这个声明 |
| `aud` | `idp-egress-gateway` | 不带 `audience` 参数时是空数组；带参数时只能是该客户端登记过的受众。每个 M2M 客户端登记的是 `TOKEN_AUDIENCE` 列表，默认只有 `bip-api` |
| `scp` | — | 不带 `scope` 参数时为空；登记的是 `m2m org:<租户>` |

创建 M2M 客户端的管理 API 没有受众参数。本机能签出 `idp-egress-gateway`，是因为改了全局 `TOKEN_AUDIENCE`，不是因为某个客户端单独登记了它。

全局开关不能作为生产方案，有两条已写明的原因：

- 之后新建的每一个 M2M 客户端都能申请出站网关的受众。
- 按 Gatekeeper 代码，用户令牌在没有指定受众时会默认带上列表里的全部受众。这一点只读了代码，没有实测。全局列表里若含 `idp-egress-gateway`，用户令牌可能在未点名的情况下带上出站网关受众。请 Gatekeeper 在回复里确认或更正这一点。

不能复用 `bip-api`。`bip-api` 是发给别的服务的默认受众。网关若改认 `bip-api`，任何发给 `bip-api` 的令牌都能敲出站网关的门。`GK-03` 挡的就是空 `aud` 和 `bip-api`。

#### 变更要求

- 为出站网关保留专属受众字符串 `idp-egress-gateway`。
- 受众按 M2M 客户端登记。未登记该受众的客户端，令牌端点不得为它签出 `aud` 含 `idp-egress-gateway` 的访问令牌。
- 管理 API 要能在创建或更新某一个 M2M 客户端时指定它的受众，而不是只改进程级 `TOKEN_AUDIENCE`。
- 生产与预发都不要用「把 `idp-egress-gateway` 追加进全局 `TOKEN_AUDIENCE`」来代替按客户端登记。
- 未获得出站资格的客户端保持只能登记它们自己的受众（例如仍使用 `bip-api` 的客户端继续只拿 `bip-api`）。

#### 线协议

调用方向 Hydra 令牌端点申请 `audience=idp-egress-gateway`。仅当该客户端已登记这个受众时，访问令牌的 `aud` 包含 `idp-egress-gateway`。

网关 JWT 校验不接受空 `aud`，也不接受只有 `bip-api` 的令牌。这两种令牌的已测结果是 HTTP 401，且 `gateway-authz` 与 Provider 都没有收到请求。

#### 验收标准

- 已登记 `idp-egress-gateway` 的预发 M2M 客户端可以签出该受众，并用它通过 `GK-01` / `GK-02`。
- 同一客户端不带 `audience`（`aud` 为空）或受众为 `bip-api` 时，出站网关 HTTP 401（`GK-03`）。
- 未登记 `idp-egress-gateway` 的另一个 M2M 客户端申请该受众时，拿不到能通过网关的令牌。
- 新建一个未明确登记该受众的 M2M 客户端，不能仅因为进程级 `TOKEN_AUDIENCE` 而签出 `idp-egress-gateway`。
- 用户令牌是否会在未指定受众时带上全部受众：以 Gatekeeper 团队的书面说明为准，并在预发上抽一条用户令牌核对。本仓库尚未实测用户令牌。

### 变更 3：M2M 访问令牌的环境边界

#### 背景

`gateway-authz` 把已验签的 Token 环境与路由环境做比对。环境缺失时原因码是 `UNAUTHENTICATED`；环境不一致时是 `ENVIRONMENT_MISMATCH`。两者都是 HTTP 403、`result` `DENY`，Provider 拿不到凭证。

Gatekeeper 的 M2M 令牌目前没有 `env`。联调能跑，是因为网关配置把环境写成了常量，签发者与环境的对应关系只存在于这份网关配置里。签发者一旦配错，Token 环境和路由环境来自同一处配置，没有第二道检查。

P2 本机实例沿用「一个签发者只属于一个环境」，是因为不改 Gatekeeper 令牌钩子就写不出 `env`。开发计划 1.3 把「令牌里带环境」列为上生产之前要 Gatekeeper 做的一件。本机做法停在备选方案，不能代替预发和生产的推荐方案。

#### 变更要求

推荐方案：令牌钩子写入顶层声明 `env`，并把 `env` 加入 Hydra 的顶层声明白名单，使该声明出现在访问令牌里。值与该客户端所属环境一致，并与出站网关该路由使用的环境相同。声明名使用 `env`，与网关现有的 `jwt.env` 读取一致。允许的取值表请 Gatekeeper 与网关共同写明（本仓库联调常量只用过 `"TEST"`，黑盒自签令牌的值也是 `TEST`；单元测试用 `PROD` 触发过 `ENVIRONMENT_MISMATCH`。本单不新造一套环境枚举）。

备选方案：若预发周期内做不到令牌钩子，则另出一份书面约定，一个签发者严格绑定一个环境。一份签发者不得同时给两个环境签访问令牌。网关一个池只配置这一个签发者。书面约定要列出签发者标识与环境的对照，并写明代价：Token 环境不再来自令牌，`ENVIRONMENT_MISMATCH` 这条比对在该池上不会被令牌触发；签发者配错时没有第二道检查。

推荐方案生效之后，网关路由恢复使用 `jwt.env`，不再用路由常量代替令牌里的环境。

#### 线协议

推荐方案下，访问令牌含顶层声明 `env`。网关把它转成 `x-idp-verified-env`。`gateway-authz` 的输入缺这个值时返回 403 `UNAUTHENTICATED`；值与路由环境不一致时返回 403 `ENVIRONMENT_MISMATCH`。

备选方案下，令牌可以继续没有 `env`。环境只由「该签发者的部署绑定」决定。这不是令牌上的密码学绑定。

#### 验收标准

- 推荐方案：预发令牌解析后能看到 `env`；与路由环境一致的令牌可以通过 `GK-01`；把该声明改成另一个环境值之后，调用方得到 403，`reason_code` 为 `ENVIRONMENT_MISMATCH`，Provider 收不到请求。
- 备选方案：书面对照表已签署；预发池只信任表中的那一个签发者；验收记录写明未启用 `ENVIRONMENT_MISMATCH` 的令牌比对，以及代价。
- 两种方案都禁止用生产 `gk.idp.xyz` 做对照试验。

### 变更 4：生产 PDP 端点原生终结工作负载 mTLS

#### 背景

`gateway-authz` 问 PDP 时出示工作负载证书，并用指定的 CA 和名字验证 PDP 一端。启动参数：

- `--gatekeeper-url`：PDP 基址。与 `--gatekeeper-token-file` 成对出现。
- `--gatekeeper-tls-cert`、`--gatekeeper-tls-key`、`--gatekeeper-tls-ca`、`--gatekeeper-name`：四个一起给，或四个都不给。
- URL 不是回环地址时，四个必须给，且方案必须是 `https`。回环上的明文 `http` 只存在于本机这种试验。给了客户端证书之后，即便回环也必须是 `https`。
- `--gatekeeper-tls-ca` 是签发 PDP 服务端证书的 CA。系统自带的根证书不被信任。
- `--gatekeeper-name` 是校验服务端证书时要对上的名字。本机 nginx 用的名字 `pdp.gatekeeper.idp.test` 只属于本机栈，不是生产名字。
- Bearer 令牌照带。令牌文件权限须为 `0600` 或更严，否则拒绝加载。

问不到、握手不成、对端证书不对，都是没有结论：调用方 HTTP 503，`GRANT_STATE_UNAVAILABLE`，不是策略拒绝的 403。

本机证明的是网关一侧会出示证书。PDP 前面的 nginx（`pdp-mtls`，端口 `27623`）要求并验证本次运行的工作负载 CA，只转发 `POST /authz/check`，其他路径 404。Gatekeeper 进程自己的 `27622` 仍然开着。

本机身份校验是 CN，不是 SAN URI。该 nginx 没有按 SAN URI 取值的变量，镜像里也没有 njs，因此它认的是：客户端证书通过 CA 验证，且 subject CN 等于 `gateway-authz`。`GK-13` 里同一个 CA 签的 `business-app` 被挡在 403。一张 CN 写成 `gateway-authz`、URI 却是别的身份的证书会被这层 nginx 放过。本机这套 PKI 里 CN 就是证书的名字，这个缺口没有堵上。

不带客户端证书无法用 `gateway-authz` 的参数单独造出来（四个参数一起给）。别的 CA 签的证书不在 nginx 信任的 CA 里，Go 客户端不会把它发出去，线上看起来像没有证书。`GK-13` 另用不带证书的直接请求确认 nginx 答 400（套件允许握手直接失败或 400）。

证书在 `gateway-authz` 启动时读一次。轮换和吊销、Gatekeeper 自己的 PDP 要求客户端证书、生产形态的证书签发，本机都没有做。

网关到 `gateway-authz` 那一跳已经是工作负载 mTLS。PDP 这一跳的 Bearer 是过渡，不能单独充当非回环地址上的认证。

#### 变更要求

- 预发（以及之后的生产）PDP 由 Gatekeeper 自己的端点终结 TLS，要求客户端证书。不再依赖本仓库的 `pdp-mtls` nginx。
- 数据面检查地址是 `https`，且不是一个不校验客户端证书的旁路。本机那种「`27622` 明文 PDP 仍可用」不能留在预发的数据面上。管理 API（建租户、客户端、元组）与 `POST /authz/check` 分开；管理口不得成为绕过 mTLS 的检查口。
- 服务端验证客户端证书的签发 CA，并校验 `gateway-authz` 的身份。身份字段采用客户端证书的 SAN URI，或在问题 4 的回复里写明的、双方据此实现的那一个字段。只比对 CN 不够：CN 为 `gateway-authz` 而 SAN URI 不是约定身份的证书必须拒绝。
- 只接受约定的 `gateway-authz` 身份调用 `POST /authz/check`。同一 CA 的其他工作负载身份拒绝。
- Bearer 令牌在过渡期可以继续要求（当前 `--gatekeeper-url` 与 `--gatekeeper-token-file` 必须成对）。它是附加检查。非回环部署不能只靠这枚共享令牌。退役条件由 Gatekeeper 在回复里给出。
- 服务端证书的名字与签发 CA 交给网关配置 `--gatekeeper-name` 和 `--gatekeeper-tls-ca`。不要要求网关信任公共根证书商店来认这张 PDP 证书。

`--gateway-identity` 是调用 `gateway-authz` 自身时用的证书 URI，属于网关到 `gateway-authz` 那一跳。它和 PDP 这一跳的客户端证书是两段信任，不要合成一个字段。

#### 线协议

已通过 mTLS 和 Bearer 的检查请求仍是变更 1 的 `POST /authz/check` JSON。身份不合格或没有客户端证书时，连接在 TLS 层失败，或由终结点拒绝，PDP 不返回可被适配器读成「有授权」或「没有授权」的 `decision`。`gateway-authz` 把这种失败记成没有结论。

本机直接探测（只说明现状，预发要用 SAN URI 规则替换 CN 规则）：

| 客户端 | 本机 nginx |
|---|---|
| 无证书 | 问不到：握手失败，或 HTTP 400 |
| 同一 CA，CN 为 `business-app` | HTTP 403 |
| 本次 CA 签发、CN 为 `gateway-authz` | `POST /authz/check` 可达，PDP 按模型回答；其他路径 HTTP 404 |
| 别的 CA，或同一 CA 的其他身份，配进 `gateway-authz` | 调用方 HTTP 503，`GRANT_STATE_UNAVAILABLE`，不是 `ACCOUNT_NOT_GRANTED` |

#### 验收标准

- `gateway-authz` 使用非回环的 `https` PDP 地址，四个 TLS 参数齐全，可以启动。缺任一参数时进程拒绝启动（错误原文见第 2 节）。
- `GK-13` 在预发终结点上通过：无证书问不到；错误 CA 与非约定身份使调用方得到 503 `GRANT_STATE_UNAVAILABLE`，Provider 收不到请求；换回约定身份的证书后放行。联调换证书时重启的是 `gateway-authz`（证书启动时读一次），不要求网关重启。
- 增加本机没有堵住的一条：CN 为 `gateway-authz`、SAN URI 不是书面约定身份的证书被拒绝，调用方同样是 503 而不是 403 `ACCOUNT_NOT_GRANTED`。
- 正确身份的 `POST /authz/check` 得到与授权模型一致的 `decision`。
- 不要求客户端证书的 PDP 地址不能对预发数据面开放。
- 验收记录写明：证书轮换、吊销和生产签发未包含在本机 13 项里。若本次预发也不测轮换，记录保持「未覆盖」，不写成已验收。

### 变更 5：版本基线（`indeterminate`）与「先发布、后启用」

#### 背景

`indeterminate` 由 Gatekeeper `10dc843` 加入。PDP 没能求出判定时带上它，HTTP 状态和 `decision` 仍可以是 200 与 `false`。适配器已按该字段读取。拒绝不再取决于 `rebac denied` 的措辞。

更早版本在查询失败时与拒绝无法区分。`0920e96` 上 `GK-08` 失败：OpenFGA 停着时调用方看到 403，`gateway-authz` 记成 `ACCOUNT_NOT_GRANTED`。

访问令牌的验签公钥方面，生产形态按 ADR-0010 第 8 条把 JWKS 放在配置快照的文件里，不让网关按 URL 自己去取。配套组件是 `gateway-control sync-jwks`（`internal/jwkssync`）：从 Hydra 拉取 JWKS，校验后原子替换文件。空密钥集、重复的 `kid`、带私钥参数的密钥，以及非 200 应答，都拒绝写入，原文件不动。`--max-stale` 与 `--empty-on-stale` 一起用时，失败超过期限会把文件写成空密钥集，验证失败关闭。该进程停了，文件不再更新，网关不会因此报错，继续信任文件里已有的密钥。

不能依赖 agentgateway `1.7.0` 对 `jwks.url` 的默认定时重取。2026-11-11 用记录每次读取的假 IdP 量过（网关启动约 3 秒后往 JWKS 加一把新密钥，旧密钥保留；不是联调用例）：

| JWKS 响应的 `Cache-Control` | 再次读取 | 新密钥签的令牌被接受 |
|---|---|---|
| `max-age=60` | 启动后第 66 秒、第 132 秒 | 66 秒。另两次试验的间隔是 63 秒，不是固定值 |
| `private, no-cache, no-store, must-revalidate`（本机 Hydra 的实际头） | 第 982 秒（16 分 22 秒） | 16 分 22 秒 |
| 没有这个头 | 第 982 秒 | 16 分 22 秒 |

三种情况下，旧密钥签的令牌到试验结束仍然通过。没有对着 Hydra 本身等满 16 分钟。`max-age=60` 仍比 `GK-12` 使用的 60 秒上限略长。更短的 `max-age` 没有试过。上游草稿里提到的最短一分钟，尚未进入锁定的 `1.7.0`。

同一天对重取失败的观察（响应带 `max-age=60`）：连接被断开时，网关告警 `failed to refresh resource`，约每 15 到 18 秒重试，恢复后的下一次重试成功。IdP 答 503 并带 JSON 错误体时，网关把错误体当密钥文档解析，失败后继续用原来的密钥，且在随后观察的 207 秒内没有再读（后 100 秒 IdP 已恢复）。错误体若恰好是一份能解析的密钥文档会怎样，没有试。`--validate-only` 对 `jwks` 下的未知字段不报错：写上 `maxAge` 得到 `Configuration is valid!`，但 `1.7.0` 不会按它生效。

因此本单不把「缩短 `Cache-Control`」或「等上游在未知 `kid` 时立即重取」当作换钥方案。未知 `kid` 立即重取的议题与修复 PR 在 2026-11-11 查阅时都没有进入 `1.7.0`，也没有里程碑。JWKS URL 不可达时，`1.7.0` 拒绝启动（`failed to load JWKS`）。文件形式没有这个启动依赖。

`GK-12` 在 2026-11-20 测的是文件路径：`hydra create jwks` 把新密钥加进访问令牌密钥集并立即用它签发，旧密钥仍在 JWKS 里；`sync-jwks --interval 2s` 原子替换文件后，两遍都是第一个请求 401，然后分别在 2.015 秒和 1.012 秒被接受，网关没有重启。套件上限 `ROTATION_WAIT` 是 60 秒，这是本机用例的等待上限，不是生产延迟承诺。ADR-0015 另有一次回环观察：文件里加上 `kid-2` 之后 1.213 秒被接受；在 `--empty-on-stale` 把文件写成空密钥集后，网关在 0.306 秒内答 401。这些同样是单机观察。

Gatekeeper 控制台目前轮换的是 ID 令牌的密钥集。访问令牌的密钥集（网关验的是它）在 login-consent 的代码里没有找到轮换入口。只要有人在 Hydra 上换了访问令牌密钥并立即签发，按 URL 取 JWKS 的网关会在下一次重取之前拒绝新令牌。

#### 变更要求

- 预发与将用于对接的 Gatekeeper 版本包含 `10dc843` 的 `indeterminate` 语义。查询失败的 `POST /authz/check` 返回 HTTP 200，`decision` 为 `false`，且 `"indeterminate": true`。
- 为访问令牌签名密钥写明并实现「先发布、后启用」：
  1. 新密钥先进入 Hydra 对外的访问令牌 JWKS，此阶段仍用旧密钥签发。旧密钥留在 JWKS 中。
  2. `gateway-control sync-jwks` 拉到含新密钥的 JWKS 并原子替换网关使用的文件。联调间隔是 2 秒；预发与生产的间隔由部署确定，本单不规定秒数。
  3. 按 ADR-0010，验签公钥在快照文件里。新密钥要进入网关正在使用的那份 JWKS，并完成一次发布。等待时间长于「发现 JWKS 变了，再做一次发布」。开发计划 1.3 第 5 条用的就是这个窗口，不是 Hydra 默认缓存的 16 分钟，也不是本机 2 秒轮询的实测值。
  4. 窗口过去之后，才用新密钥签发访问令牌。
  5. 仍有未过期旧令牌的期间，旧密钥留在 JWKS 内。
- `hydra create jwks` 这种「加进去就签发」不能当作该规程。需要一种只把公钥放进 JWKS、尚未用它签访问令牌的操作。控制台若仍只轮换 ID 令牌密钥集，要为访问令牌密钥集提供明确入口，并在规程里写清操作者和审计。
- 缩短 `Cache-Control: max-age` 可以作为观察手段，不作为本单的交付条件。网关启动不依赖 JWKS URL 可达。

#### 线协议

变更 1 的四行 PDP 对照在本变更下固定为：

| 情况 | `decision` | `indeterminate` | `reason`（本次实测原文） | 调用方 |
|---|---|---|---|---|
| 有授权 | `true` | 无，或可省略 | `rebac:use` | 允许继续 |
| 明确拒绝 | `false` | 无或不为 `true` | `rebac denied` | 403 `ACCOUNT_NOT_GRANTED` |
| 查询失败 | `false` | `true` | `rebac lookup failed` | 503 `GRANT_STATE_UNAVAILABLE` |
| 动作不在模型 | `false` | 无 | 以 `unknown action` 开头 | 503 `GRANT_STATE_UNAVAILABLE` |

`"indeterminate": true` 优先于 `decision` 和 `reason`。

换钥期间网关看到的 JWKS 是文件。新 `kid` 尚未进入该文件时，用新密钥签的令牌被网关拒绝（本机观察到的第一个请求是 401）。文件被原子替换且网关重载之后，新令牌被接受，旧 `kid` 仍在集合内时旧令牌继续被接受。

#### 验收标准

- 预发 Gatekeeper 的提交号写入记录，且行为包含 `indeterminate`。`GK-08`：停 OpenFGA 后 PDP 仍 HTTP 200 并带 `"indeterminate": true`；调用方 HTTP 503，`reason_code` 为 `GRANT_STATE_UNAVAILABLE`，不是 403 `ACCOUNT_NOT_GRANTED`；Provider 收不到请求；恢复后不重启网关和 `gateway-authz` 即放行。
- 换钥演练按「先发布、后启用」执行一轮：新密钥已出现在网关正在使用的 JWKS 文件中、且对应发布完成之前，不用它签发；开始签发之后，新令牌被接受，旧令牌在重叠期内仍被接受，网关进程不重启。
- 记录里可以附上本机 `GK-12` 的 2.015 秒与 1.012 秒，并注明那是 `--interval 2s`、立即签发、单机、两遍的观察。这些秒数不是预发或生产的延迟承诺，也不是压测结论。
- 不把 16 分 22 秒、63 秒、66 秒或 60 秒写成 Gatekeeper 必须满足的 SLO。60 秒只是本机 `GK-12` 用例的等待上限。

## 4. 中期协同项（A3 · 凭证托管与 KMS / Credential Broker）

本节不是五项必需变更的验收项，也不要求与第 3 节同一迭代交付。它对应阶段 1 轨道 A 的后续 A3 步，供 Gatekeeper 排期时与五项分开签字。

### 4.1 当前阶段谁持有凭证正文

ADR-0003（Accepted，2026-11-21）现在覆盖的范围是：Gatekeeper 是调用方身份的权威，也是账户能不能用的权威。本机联调测的是这一部分。凭证正文不在 Gatekeeper，也不在 Secret Manager。正文放在哪里由已经 Accepted 的 ADR-0011 决定：由 `gateway-authz` 持有。接受 ADR-0003 的这一次，不把秘密搬回 Gatekeeper，也不加 KMS。

ADR-0003 的推荐决策仍保留基线表述：Gatekeeper 集中身份、服务授权、第三方账户 Grant 与 Credential Broker，Secret Manager/KMS 管密钥材料。该表述不是本阶段已经在跑的实现。ADR-0011 写明：Gatekeeper 的模型里当时还没有 Provider 账户类型，Broker 仍是基线提案；端口已经把「账户授权」（`ports.Grants`）和「凭证正文」（`ports.CredentialSource`）分开。判定通过之后，由 `gateway-authz` 把本次请求的 `Authorization` 放进 ExtAuthZ 允许响应，网关只复制这一个头。以后若改由 Broker 提供正文，换的是 `CredentialSource` 的实现，网关复制响应头的那一段不用改。

ADR-0011 同时写明：指定了 Secret Manager 之后，加一种来源，不删除文件来源。没有接上 Secret Manager 的环境仍要用文件跑测试。文件权限是 `0600` 或更严。秘密不进配置快照，快照正文也不能用环境变量引用把秘密带进去（ADR-0010 第 11 条）。

因此本期 Gatekeeper 继续只回答 `ports.Grants`。不要求实现 `credentials/materialize`，不要求 PDP 在允许响应里回传 Provider 秘密。`docs/integrations/Fabric_and_Gatekeeper_Change_Impact.md` 里的 `/v1/extauthz/check` 下发凭证、`/v1/egress/credentials/prepare` 等仍是提案，证据来自 Mock，不是 Gatekeeper 的实现。ADR-0008（Accepted）写明：`credentials/materialize` 不实现，`secure_binding_handle` 不签发，`credentials/prepare` 只返回计划、不返回秘密。现行 ExtAuthZ 允许响应里的 `Authorization` 由本仓库的 `gateway-authz` 填入。

Gatekeeper 里收回账户授权（`GK-07`）与 `gateway-authz` 自己的撤销表（ADR-0012）是两层。本单不合并这两层。

### 4.2 中期如何对接 `ports.CredentialSource`

若后续由 Gatekeeper 提供录入界面，对齐方式如下。界面与 KMS 的具体 API 由 Gatekeeper 在问题 6 的回复里提出，本单不指定路径。

- 录入是只写不回显。操作者提交 Provider 侧的密钥材料后，界面与任何后续的读接口都不把材料原文返回给浏览器、日志或管理 API 的响应。材料进入 KMS / Secret Manager，不写入 Gatekeeper 关系数据库的明文列（变更影响清单对 Secret 存储的要求）。
- 交给网关侧的是句柄和版本，不是正文。本仓库已经使用的句柄形式是 `gatekeeper:<绑定>/<账户>`，例如占位 `gatekeeper:wanbexpress-test/account-blue`。绑定里带 Provider 与环境，账户名与授权模型里的 `provider_account` id 对齐。
- `key_version` 是运维写明的版本字符串（非空、可见 ASCII）。OAuth 客户端凭证来源的缓存键包含句柄、令牌端点、`client_id`、`scope`、`audience`、`key_version`，以及只留在内存中的客户端密钥摘要。版本变化后，该句柄下已缓存的 Provider 令牌作废，下一次放行重新取。KMS 适配器应保留这样一个由操作者推进的 `key_version`，使轮换不依赖进程重启。
- `gateway-authz` 侧新增的是另一个 `ports.CredentialSource`：用句柄向 KMS（或只对 `gateway-authz` 工作负载开放的取回接口）取得材料，放进 `ports.Secret`。日志、错误和 JSON 里是占位符，只有写向上游请求时才取出原值。现有 `0600` 文件来源保留给离线与黑盒测试。一个句柄只出现在一个来源里。
- 账户能不能用仍走 PDP（变更 1）。凭证来源只在登记表、撤销、Gatekeeper 授权都放行之后才被问到。Gatekeeper 不通过放宽 Grant 来代替凭证文件，也不在检查响应里夹带秘密。
- 取回接口若存在，只接受已认证的 `gateway-authz` 工作负载，与变更 4 的身份字段一致。其他工作负载不能读材料。

A3 未实现之前，预发可以继续用权限受控的文件把测试账户的凭证交给 `gateway-authz`。那些文件不进 Git，不进本单，也不进验收证据。

## 5. 预发布环境联调验收清单（`GK-01`–`GK-13`）

在 Gatekeeper 团队提供的非生产 / 预发布环境上重跑与 `tests/integration/gatekeeper/run.py` 同目标的 13 项。默认一轮含 `GK-01` 至 `GK-11` 与 `GK-13`；`GK-12` 在换钥规程演练时跑。13 项都要通过，才算本单的联调验收通过。

退出条件同时满足才算该用例通过。Provider 必须是验收双方面同意的替身或沙箱，并且能证明：调用方的 IDP 令牌没有出现在 Provider 收到的请求里；放行时 Provider 收到的是该账户自己的凭证。本机用的是黑盒套件的 `mock_provider.py`，不是承运商生产接口。

`GK-08`、`GK-09`、`GK-10` 的本机脚本把调用方状态码断言为「大于等于 400」，并断言 `gateway-authz` 记为 `GRANT_STATE_UNAVAILABLE`。产品代码对「没有结论」写的是 HTTP 503。README 的结果表也写成 503。预发退出条件采用 503，避免用 403 `ACCOUNT_NOT_GRANTED` 蒙混查询失败。

| 用例 | 验收目标 | 预期状态码 | 退出条件 |
|---|---|---|---|
| `GK-01` | 蓝租户的真实 M2M 令牌：Gatekeeper 确认授权，Provider 收到蓝账户凭证 | 调用方 HTTP 200 | Provider 恰好收到一个请求；凭证是蓝账户的；调用方令牌未到达 Provider；`gateway-authz` 记为 `ACTIVE_ACCOUNT_GRANT` |
| `GK-02` | 绿租户，与 `GK-01` 对称 | 调用方 HTTP 200 | 同上，账户为绿账户。两租户不串用凭证 |
| `GK-03` | 同一客户端，但令牌不是发给出站网关的：不带 `audience`（`aud` 为空），或受众为 `bip-api` | HTTP 401 | 两种令牌都是 401；`gateway-authz` 没有新的判定记录；Provider 收不到请求 |
| `GK-04` | 别的密钥签名，声明照抄一份真实令牌 | HTTP 401 | 401；到不了 `gateway-authz` 和 Provider |
| `GK-05` | 登记表承认该客户端，Gatekeeper 里没有这个账户的授权 | HTTP 403 | 正文 `reason_code` 为 `ACCOUNT_NOT_GRANTED`；`gateway-authz` 记同一原因码；Provider 收不到请求 |
| `GK-06` | 蓝租户申请绿租户的账户 | HTTP 403 | `gateway-authz` 记 `ACCOUNT_NOT_GRANTED`；Provider 收不到请求 |
| `GK-07` | 在 Gatekeeper 删除该账户的 `caller` 元组后立刻再请求；再写回 | 收回后 HTTP 403；绿租户仍 HTTP 200；恢复后 HTTP 200 | 收回后原因码 `ACCOUNT_NOT_GRANTED`，Provider 收不到蓝租户这次请求；绿租户不受影响；恢复后的下一次蓝租户请求放行。期间不重启网关、不重启 `gateway-authz`、不重启 Gatekeeper |
| `GK-08` | 停 OpenFGA。PDP 进程仍在，检查仍 HTTP 200 | 调用方 HTTP 503 | PDP 正文含 `"indeterminate": true`（实测 `reason` 为 `rebac lookup failed`）。调用方 `reason_code` 为 `GRANT_STATE_UNAVAILABLE`，不是 `ACCOUNT_NOT_GRANTED`。Provider 收不到请求。恢复 OpenFGA 后，不重启网关和 `gateway-authz`，请求再次放行 |
| `GK-09` | PDP 不可达 | 调用方 HTTP 503 | 原因码 `GRANT_STATE_UNAVAILABLE`；Provider 收不到请求；PDP 恢复后不重启网关和 `gateway-authz` 即放行 |
| `GK-10` | `gateway-authz` 配置了错误的 PDP Bearer | 调用方 HTTP 503 | 原因码 `GRANT_STATE_UNAVAILABLE`；Provider 收不到请求。换回正确令牌并让 `gateway-authz` 使用它之后放行。令牌原文不进日志、不进证据 |
| `GK-11` | 同一条连接上连续 300 次判定：每次都问 Gatekeeper，以及只看登记表 | 两种都放行（本机为成功状态） | 300 次都放行。耗时只记录、不设门槛。不得因慢于或快于下面的本机数字而判失败 |
| `GK-12` | 访问令牌签名密钥轮换，网关不重启 | 旧令牌在重叠期 HTTP 200。先发布、后启用做完再签发时，新令牌应被接受 | 按变更 5 的规程执行，而不是只跑「加进 JWKS 就签发」。新密钥进入网关正在使用的 JWKS 并完成发布之后才签发；签发后的新令牌被接受；旧密钥仍在集合内时旧令牌仍被接受；网关进程不重启。本机「立即签发」路径观察到的首包 401 以及 2.015 秒、1.012 秒只作附录，不作为通过与否的秒数门槛 |
| `GK-13` | `gateway-authz` 到 PDP 的证书不对：别的 CA，或同一 CA 的其他身份。另测无证书、以及 CN 与 SAN URI 不一致 | 错证书时调用方 HTTP 503。无证书问不到 PDP 判定。正确证书恢复后放行 | 错证书：503，`GRANT_STATE_UNAVAILABLE`，正文不是 `ACCOUNT_NOT_GRANTED`，Provider 收不到请求。无证书：握手失败或被终结点拒绝，不能得到 `decision: true`。同一 CA 的非约定身份被拒绝。CN 写成 `gateway-authz` 但 SAN URI 不是约定身份的证书被拒绝（本机 nginx 未测到这一条，预发必须测）。约定身份恢复后放行。PDP 令牌、Provider 凭证和客户端密钥不出现在网关与 `gateway-authz` 的日志里 |

### 5.1 本机耗时（只说明量级）

以下数字来自单连接、顺序请求、同一台机器，不是压测，不是容量试验，也不是本单批准的延迟 SLO。预发不必复现这些毫秒数。`GK-11` 不设耗时门槛。

2026-11-11，经回环明文，以网关身份在一条连接上连续问 `gateway-authz` 300 次（三轮的范围；第三轮机器上还有别的负载）：

| | p50 | p90 | p99 |
|---|---|---|---|
| 只看登记表 | 0.28–0.30 ms | 0.34–0.38 ms | 0.5–0.75 ms |
| 每次再问 Gatekeeper | 1.41–1.53 ms | 1.96–2.19 ms | 3.05–3.5 ms |

单独调一次 PDP 的 p50 约 1.1 毫秒。每个放行的请求大约多 1 毫秒，与一次 PDP 调用同量级。

2026-11-19 起这一跳经 nginx 的 TLS。`GK-11` 里每次都问 Gatekeeper 的 p50 在 1.6 毫秒左右，p99 2.7 毫秒，同一条连接上握手只付一次。没有重做上面那张 2026-11-11 的表。

同一套本机环境里，一个放行请求走完全程大约 44 毫秒，被拒绝的请求不到 1 毫秒。多出来的时间在网关到 Mock Provider 那一跳，与 Gatekeeper 无关，原因没有查。

适配器对 PDP 的时限是 300 毫秒，网关等 `gateway-authz` 的时限是 1 秒。这是当前代码里的上限。

### 5.2 本机 13 项没有覆盖、预发记录里保持未覆盖的内容

除非本次预发另写用例并留下证据，否则下面各项保持未覆盖，不能写进「已验收」：

- 生产形态的 Gatekeeper（本机是 Hydra `--dev`、明文 HTTP、开发固定密钥）。
- 用户令牌（授权码流程）、Mode B 的 Broker 路由、写操作路由。
- 并发与负载。第 5.1 节是单连接顺序请求。
- 授权结果缓存。现在每个请求都问 PDP。
- 工作负载证书的轮换、吊销和生产签发。
- 模型里没有 `provider_account` 时的 `unknown action` 路径（只有单元测试）。类型合入之后，用 `GK-05` 证明「真的没有授权」仍是 403，用 `GK-08` 证明「没查成」是 503。

## 6. 请 Gatekeeper 团队逐条回复的问题

请对每一条给出：结论（接受 / 接受但调整 / 拒绝）、预发可用的时间或迭代、以及若调整时的差异说明。拒绝或调整时请写出替代提案。在回复之前，本仓库不会把生产 `gateway-authz` 指向 `gk.idp.xyz` 或任何未完成下列五项的 Gatekeeper。

1. 授权模型。是否把第 3 节变更 1 的 `provider_account`（`org` / `caller` / `use`，`use` = `caller` 且 `member from org`）合入正式 OpenFGA 模型？M2M 客户端是否继续归一为 `user:<client_id>`？若否，请给出稳定的主体类型，以及 `subject.id` 与上下文元组的字段如何对应变更 1 的 JSON。

2. 受众。是否按 M2M 客户端登记 `idp-egress-gateway`，并给管理 API 增加按客户端设置受众的参数？是否确认生产不使用全局 `TOKEN_AUDIENCE` 追加该受众，也不让出站网关改认 `bip-api`？请同时确认或更正：用户令牌在未指定受众时是否会带上 `TOKEN_AUDIENCE` 列表中的全部受众（本仓库只读了代码，没有实测）。

3. 环境。采用推荐方案（令牌钩子写入 `env`，并加入 Hydra 顶层声明白名单），还是备选方案（一份书面约定：一个签发者严格绑定一个环境）？若选推荐方案，请给出 `env` 的取值表。若选备选方案，请附签发者与环境的对照，并确认接受这个代价：Token 环境与路由环境都出自网关部署配置，`ENVIRONMENT_MISMATCH` 不会被令牌触发。

4. PDP mTLS。预发 PDP 是否由 Gatekeeper 原生终结 TLS 并要求客户端证书？服务端校验 `gateway-authz` 时读取的身份字段是 SAN URI，还是你们写明的另一个字段？请确认 CN 与该字段不一致时拒绝。管理 API 与 `POST /authz/check` 是否分离，且数据面不保留无客户端证书的检查口？Bearer 令牌过渡期是否保留，退役条件是什么？服务端证书的名字和 CA 如何交给 `--gatekeeper-name` 与 `--gatekeeper-tls-ca`？

5. 版本与换钥。用于对接的预发构建是否包含 `10dc843` 的 `indeterminate`（请给出提交号）？访问令牌签名密钥能否先进入 JWKS 而暂不签发？从「公钥已发布」到「开始用它签发」的等待，是否按「长于 sync-jwks 发现变化并完成一次网关发布」来定，而不是按 Hydra 默认 `Cache-Control` 的约 16 分钟重取来定？访问令牌密钥集的正式轮换入口由谁操作（控制台当前看到的是 ID 令牌密钥集）？

6. A3 排期。是否确认本期凭证正文仍由 `gateway-authz` 持有，Gatekeeper 本期只做账户授权，不在 PDP 响应里返回 Provider 秘密，也不把秘密明文写入关系数据库？中期是否计划提供只写不回显的录入，以及 KMS 句柄 `gatekeeper:<绑定>/<账户>` 与 `key_version`？若计划提供，请说明取回接口只对哪个工作负载身份开放，以及它如何对应 `ports.CredentialSource`（加一种来源，保留文件来源给测试）。请给出是否纳入后续迭代，而不是与五项绑在同一次预发验收里。

回复请同时指定预发环境的名称与接入方式。该环境不得是生产 `gk.idp.xyz`。

## 附：本单核对过的仓内依据

- `tests/integration/gatekeeper/README.md`：13 个用例、M2M 令牌形状、`provider_account`、PDP JSON、`10dc843` 的 `indeterminate`、`Cache-Control` 与 `sync-jwks`、mTLS 的 CN 与 SAN URI。
- `tests/integration/gatekeeper/run.py`：各用例的状态码断言、`ROTATION_WAIT = 60`、路由常量 `"TEST"`、`GK-13` 对 400/403/503 的检查。
- `tests/integration/gatekeeper/provider-account.types.json`、`tests/integration/gatekeeper/compose.local.yml`：本机模型补丁、`TOKEN_AUDIENCE` 与 `pdp-mtls`。
- `internal/egressauthz/adapters/gatekeeper/grants.go`、`cmd/gateway-authz/main.go`：检查 JSON、`unknown action`、非回环拒绝启动的原文、300 毫秒时限。
- `docs/development-plan.md` 第 1.2、1.3、2.3 节。
- `docs/integrations/Fabric_and_Gatekeeper_Change_Impact.md`。
- `docs/adr/ADR-0003.md`、`docs/adr/ADR-0011.md`：凭证正文由 `gateway-authz` 持有；本次接受不把秘密搬回 Gatekeeper，也不加 KMS。
- `docs/adr/ADR-0008.md`、`docs/adr/ADR-0010.md` 第 8 条与第 11 条、`docs/adr/ADR-0015.md`：ExtAuthZ 复制 `Authorization`、JWKS 在快照文件中、`sync-jwks`。
- `docs/production-release-plan.html` 第 2 节：阶段 1 轨道 A 中，KMS 托管列为后续 A3，不与五项前置绑成同一次验收。
