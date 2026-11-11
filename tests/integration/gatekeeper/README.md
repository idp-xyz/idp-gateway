# 与 Gatekeeper 的联调

在本机起一套真实的 Gatekeeper，让它签发的 M2M 令牌经真实的 agentgateway 到 `gateway-authz`，再由 `gateway-authz` 去问 Gatekeeper 的 PDP：这个调用方能不能用这个 Provider 账户。

> 已发布的 `gk.idp.xyz` 是**生产环境**。这里的脚本不访问它；租户、客户端和授权关系只建在本机实例里。  
> Gatekeeper 的代码来自一份**只读检出**，这里不往里写任何文件。  
> 联调通过不改变验收矩阵里任何用例的 `NOT_RUN`。

## 怎么跑

```bash
git clone https://github.com/idpxyz/idp-gatekeeper ~/.local/src/idp-gatekeeper   # 一次；别处的检出用 GK_SRC 指定
tests/integration/gatekeeper/stack.sh up        # 构建并拉起，约半分钟（第一次要下载镜像和 Hydra）
.venv/bin/python tests/integration/gatekeeper/run.py
tests/integration/gatekeeper/stack.sh down      # 删除容器、网络、卷和测试客户端的凭据
```

检出要在 Gatekeeper `10dc843` 或之后，原因见下面第 3 点。检出更新之后，下一次 `stack.sh up` 会重新构建。

| 谁 | 是什么 |
|---|---|
| 真的 | Gatekeeper（Hydra v26.2.0 签发的令牌与 JWKS、login-consent 的 PDP、OpenFGA）、agentgateway 1.7.0（`deploy/agentgateway/agentgateway.lock.json` 锁定的构建，即上游镜像里的那个二进制；启动前核对，做法与黑盒套件相同）、`gateway-authz` 的产品构建 |
| 假的 | Provider（黑盒套件的 `mock_provider.py`）、工作负载证书（每次运行现做的 CA） |

本机实例是独立的 compose 项目 `idp-gateway-gk`，只在回环地址上发布两个端口：`27621`（Hydra 公共端点）和 `27622`（login-consent：管理 API 与 PDP）。它与 Gatekeeper 自己的开发栈相比改了什么，写在 `compose.local.yml` 的开头。联调本身占用黑盒套件的 `27611`–`27616` 和 `27619`（配置里的回读口，联调不用它，但网关会打开它），两者不能同时跑。

证书、随机生成的管理密钥和 PDP 令牌、测试客户端的密钥都在 `.run/` 里（已被 git 忽略）。

## 只存在于本机实例里的东西

Gatekeeper 的授权模型（`deploy/openfga/model.json`）里没有"Provider 账户"这种对象。`stack.sh` 默认把 `provider-account.types.json` 里的一个类型加进**本机实例**的模型：

```text
type provider_account
  relations
    define org:    [org]                          # 账户属于哪个租户
    define caller: [user]                         # 谁被授予了这个账户
    define use:    caller and member from org     # 能用 = 获授，并且属于账户所属的租户
```

这是本仓库的提议。它不在 Gatekeeper 的仓库里，也不在已发布的实例里；`gateway-authz` 的 Gatekeeper 适配器在这个类型进入 Gatekeeper 自己的模型之前，对任何别的 Gatekeeper 实例都只会得到"没有结论"（下面第 3 点）。

本机实例的 `TOKEN_AUDIENCE` 也改过：在默认的 `bip-api` 之外加了 `idp-egress-gateway`，原因见下面第 1 点。

## 结果

2026-11-11，Gatekeeper `f36dc06`，agentgateway 1.7.0：默认的 11 个用例全部通过；加上 `--key-rotation` 后的第 12 个用例 FAIL（见下面第 4 点）。逐项结果写在 `.run/result.json`，不入库；这里没有像黑盒套件那样的证据文件。

同一天早些时候对着 Gatekeeper `0920e96` 是同样的结果，那时适配器还靠 `reason` 的措辞认拒绝。现在的适配器对着 `0920e96` 过不了 GK-08（见下面第 3 点）。

| 用例 | 内容 | 结果 |
|---|---|---|
| GK-01、02 | 两个租户各自的真实 M2M 令牌：Gatekeeper 确认授权，Provider 收到该租户账户的凭证，调用方的令牌没有到达 Provider | PASS |
| GK-03 | 同一个客户端、但不是发给出站网关的令牌（`aud` 为空，或 `bip-api`）：401 | PASS |
| GK-04 | 别的密钥签名、声明照抄真实令牌：401 | PASS |
| GK-05 | 登记表认的客户端，在 Gatekeeper 里没有账户授权：403 `ACCOUNT_NOT_GRANTED` | PASS |
| GK-06 | 蓝租户申请绿租户的账户：403 | PASS |
| GK-07 | 在 Gatekeeper 里收回授权，下一个请求即被拒绝；恢复后即放行；不重启任何进程 | PASS |
| GK-08 | OpenFGA 停了：503 `GRANT_STATE_UNAVAILABLE`，Provider 收不到请求；恢复后自动恢复 | PASS |
| GK-09 | PDP 不可达：同上 | PASS |
| GK-10 | `gateway-authz` 拿着错误的 PDP 令牌：同上 | PASS |
| GK-11 | 一次判定的耗时，问与不问 Gatekeeper（仅记录） | PASS |
| GK-12（`--key-rotation`） | Hydra 换了访问令牌的签名密钥，网关不重启、60 秒内接受新密钥签的令牌 | **FAIL** |

网关配置就是黑盒套件的 `agentgateway.poc.yaml`，只换了三处：签发者、JWKS 的来源（文件换成 Hydra 的地址）、"Token 环境"的来源。

## 联调中看清的事

### 1. 真实的 M2M 令牌和黑盒套件假设的不一样

| | 黑盒套件自己签的令牌 | Gatekeeper 的 M2M 令牌（Hydra `client_credentials`） |
|---|---|---|
| `sub` | 服务名，如 `parcel-service` | 客户端 ID（UUID），与 `client_id` 相同 |
| `tenant_id` | 租户代号，如 `tenant-blue` | 租户 UUID，由令牌钩子从客户端元数据写入 |
| `env` | `TEST` | **没有这个声明**（Hydra 的顶层声明白名单里没有它） |
| `aud` | `idp-egress-gateway` | 不带 `audience` 参数时是**空数组**；带参数时只能是客户端登记过的受众，而每个 M2M 客户端登记的就是 Gatekeeper 的 `TOKEN_AUDIENCE` 列表（默认只有 `bip-api`） |
| `scp` | — | 不带 `scope` 参数时为空；登记的是 `m2m org:<租户>` |

后果，都已在联调里验证：

- 网关路由里的 `x-idp-verified-env: jwt.env` 取不到值，`gateway-authz` 把每个请求都判成 `UNAUTHENTICATED`。联调里把它改成了路由常量（一个网关实例只信一个签发者，签发者属于哪个环境在部署时就定了）。**"Token 环境"到底从哪里来，需要定。**
- 按 Gatekeeper 的默认配置，令牌里拿不到 `idp-egress-gateway` 这个受众（Hydra 拒绝：客户端没有登记它），网关只能把受众配成 `bip-api`，也就是任何发给 `bip-api` 的令牌都能拿来敲出站网关的门。创建 M2M 客户端的管理 API 没有受众参数。本机实例是把 `TOKEN_AUDIENCE` 改成 `bip-api,idp-egress-gateway` 才拿到专属受众的；这个开关很粗：之后新建的**每个** M2M 客户端都能申请出站网关的受众，而且按它的代码，用户令牌在没有指定受众时默认带上列表里的全部受众（这一点只读了代码，没有实测）。**按客户端登记受众需要 Gatekeeper 改。**
- 登记表里的 `allowed_service_ids`、`allowed_tenants`、`accounts_by_tenant` 填的都得是 UUID。

### 2. PDP 能回答"能不能用这个账户"，前提是模型里有这个类型

Gatekeeper 的 PDP 把模型里的"类型.关系"自动当作动作，所以加了上面的类型之后不用改它一行代码，`provider_account.use` 就能问。`gateway-authz` 发的是：

```json
{"subject": {"id": "<令牌的 sub>"},
 "action": "provider_account.use",
 "resource": {"type": "provider_account", "id": "<账户>"},
 "context": {"tenant_id": "<令牌的 tenant_id>",
             "contextual_tuples": [{"user": "user:<sub>", "relation": "member", "object": "org:<tenant_id>"}]}}
```

调用方属于哪个租户，由 `gateway-authz` 根据已验签的令牌随请求带过去，Gatekeeper 不用存。授权关系（账户属于哪个租户、谁是获授调用方）通过 Gatekeeper 的管理 API 写入，在它那边有审计记录。

在 `gateway-authz` 里，这一问排在登记表和撤销检查之后：登记表拒绝的请求不会去问，Gatekeeper 只能把登记表收窄，不能放宽。不带 `--gatekeeper-url` 启动时不问，行为与之前完全相同。

### 3. PDP 对"没有授权"和"没查成"都答 200，用 `indeterminate` 字段区分

直接问本机实例的 PDP 得到的应答（2026-11-11，Gatekeeper `f36dc06`），状态码都是 200：

| 情况 | PDP 的应答 | 适配器读成 |
|---|---|---|
| 有授权 | `{"decision":true,"reason":"rebac:use"}` | 有授权 |
| 没有被授予这个账户，或账户属于别的租户 | `{"decision":false,"reason":"rebac denied"}` | 没有授权：403 `ACCOUNT_NOT_GRANTED` |
| OpenFGA 停了 | `{"decision":false,"indeterminate":true,"reason":"rebac lookup failed"}` | 没有结论：503 `GRANT_STATE_UNAVAILABLE` |
| 问的动作不在模型里 | `{"decision":false,"reason":"unknown action"}` | 没有结论：503 `GRANT_STATE_UNAVAILABLE` |

`indeterminate` 是 Gatekeeper `10dc843` 加的：PDP 没能求出判定（它背后的查询失败了）时带上它，状态码和 `decision` 不变。适配器按两个字段读应答：带 `"indeterminate": true` 的是没有结论，不管 `decision` 和 `reason` 写的是什么；`decision` 为 `true` 是有授权；其余是没有授权。**拒绝不再取决于 `reason` 的措辞。** 此前适配器只把 `rebac denied` 这一个 `reason` 当作拒绝，Gatekeeper 改了措辞，拒绝就会全部变成 503。

两点要知道：

- **Gatekeeper 要在 `10dc843` 或之后。** 更早的版本在 OpenFGA 停掉时答的是 `{"decision": false, "reason": "rebac lookup failed"}`，没有这个字段，和拒绝没有区别。拿现在的适配器对着 `0920e96` 跑了一遍：GK-08 FAIL，OpenFGA 停着的时候调用方看到 403，`gateway-authz` 记成 `ACCOUNT_NOT_GRANTED`；其余 10 个用例通过。
- **"动作不在模型里"仍然靠 `reason` 认。** 这种应答不带 `indeterminate`（PDP 不做查询就答了，OpenFGA 停着的时候也是这样答），适配器按 `reason` 以 `unknown action` 开头来认，读成没有结论：它说的是模型里还没有 Provider 账户这个类型，不是这个调用方没有授权。Gatekeeper 自己的三个 SDK 也按这个开头认"动作没有映射"。它改了措辞的后果比以前小：模型里没有这个类型的实例从 503 变成 403 `ACCOUNT_NOT_GRANTED`，有这个类型的实例不受影响。上表第四行是拿一个模型里没有的动作名直接问 PDP 得到的；适配器怎么读它只有单元测试，联调里没有这个用例。

### 4. 换了签名密钥，网关要到下一次定时重取 JWKS 才认新密钥

按地址取 JWKS 时，agentgateway 1.7.0 会定时重取，间隔跟着 JWKS 响应的缓存头走。用一个记录每次读取的假 IdP 量过（2026-11-11，单独的试验，不在用例里；每种响应头下网关启动 3 秒后往 JWKS 里加一把新密钥，旧的留着）：

| JWKS 响应的 `Cache-Control` | 网关再次读取 JWKS | 新密钥签的令牌多久后被接受 |
|---|---|---|
| `max-age=60` | 启动后第 66 秒、第 132 秒 | 66 秒 |
| `private, no-cache, no-store, must-revalidate` | 第 982 秒（16 分 22 秒） | 16 分 22 秒 |
| 没有这个头 | 第 982 秒 | 16 分 22 秒 |

第二行就是本机 Hydra 实际返回的响应头。三种情况下，旧密钥签的令牌到试验结束时仍然通过。`max-age=60` 时的间隔在另外两次试验里是 63 秒，不是固定值。由此：

- 给本机 Hydra 换了访问令牌的签名密钥之后，新密钥签的令牌要等到下一次定时重取才被接受，按它的响应头最长是 16 分多钟（没有对着 Hydra 本身等满这个时间）。`run.py --key-rotation`（用例 GK-12）期望 60 秒内接受，所以 FAIL。
- 本节原先的结论是"JWKS 只在加载配置时取一次"，依据是换密钥后等了 16 分钟没有恢复。**这个结论是错的。** 那次等待与重取周期只差二十几秒，当时的具体时间点没有留下记录，无法核对是不是刚好没等到。
- 改写配置文件让网关重新加载配置之后等了 20 秒，没有重新取；重启网关后立刻恢复（此前的手工观察，这次没有重测）。
- JWKS 地址不可达时网关**拒绝启动**（`failed to load JWKS`）。用文件形式的 JWKS 时没有这个依赖。
- JWKS 改用文件时（黑盒套件的做法），**只要重写那个文件**，网关在 10 秒内接受新密钥签的令牌，不用重启，也不用碰配置文件（此前的手工观察，这次没有重测）。

上游的情况（2026-11-11 查；都没有进入 1.7.0，两个议题也都没有标里程碑）：

- [#2798](https://github.com/agentgateway/agentgateway/issues/2798)：令牌的 kid 不在已有 JWKS 里时不会立即重取。未关闭；修它的 PR [#3037](https://github.com/agentgateway/agentgateway/pull/3037) 没有合并就关了。维护者在议题里说明了远端 JWKS 有定时重取（他说的是 15 分钟，上面量到的是 16 分 22 秒）、文件形式在文件变化时重读。
- [#3616](https://github.com/agentgateway/agentgateway/issues/3616)：JWKS 不可达时网关加载配置失败。未关闭；维护者同意应当改成只让那一个签发者失效，其余照常加载。
- PR [#4142](https://github.com/agentgateway/agentgateway/pull/4142)（草稿）：给远端 JWKS 加"最长信任时长"（`jwks.maxAge`），并把非 2xx 响应当作取失败。

定时重取**失败**时 1.7.0 的表现（同一天实测，JWKS 响应带 `max-age=60`，到了该重取的时候让假 IdP 出故障）：

- **连接被断开**：网关记一条 `failed to refresh resource` 告警，每 15 到 18 秒重试一次；IdP 恢复后的下一次重试即成功，之后回到正常周期。
- **IdP 答 503 并带一个 JSON 错误体**：网关把这个响应体当成新的密钥文档去加载，解析失败（`Failed to reload config: failed to load JWKS: missing field keys`），于是继续用原来的密钥。但它**不重试**：之后的 207 秒里没有再读过 JWKS，其中后 100 秒 IdP 已经恢复正常。下一次读取多半要等默认周期，试验没有等到那时候。错误体如果恰好是一份能解析的密钥文档会怎样，没有试。
- 两种情况下已有的密钥都继续被信任，试验里（故障持续两到三分多钟）没有看到时限。G02、G04 要求"JWKS 不可用时只在批准的 TTL 内复用已验证的公钥"，1.7.0 没有能设这个时限的配置项；上面那个 PR 要加的就是它。
- 顺带发现：1.7.0 的 `--validate-only` 对 `jwks` 下面的未知字段不报错。在 `jwks` 里写上 `maxAge: 1h` 或任意不存在的字段，结果都是 `Configuration is valid!`；同样的未知字段写在上一层 `jwtAuth` 下面会被拒绝。也就是说，照着那个 PR 写了 `maxAge`，配置能过校验，但不起任何作用。

要让出站网关跟得上签名密钥的更换，有三条路，可以叠加：

| | 谁改什么 | 换密钥后新令牌被拒的最长时间 | 代价与前提 |
|---|---|---|---|
| 先发布、后启用 | Gatekeeper：新密钥先进 JWKS，过一个重取周期（按现在的响应头至少 17 分钟）再用它签发 | 0 | 要 Hydra 能"加进密钥集但暂不签发"。GK-12 用的 `hydra create jwks` 是加进去就签发 |
| 缩短重取周期 | Gatekeeper：让 JWKS 响应带 `Cache-Control: max-age=60`，或在它前面加一层改这个头 | 63 到 66 秒（实测）；重取那一刻 IdP 正好答 5xx 时会长得多，见上 | 每个网关实例每分钟读一次 JWKS。仍比 GK-12 期望的 60 秒略长；更短的值没有试过，上游 PR 的描述里说最短是一分钟 |
| JWKS 走文件，另做同步 | 本仓库：一个把 Hydra 的 JWKS 同步到文件的组件，现在不存在 | 同步周期加 10 秒以内 | 多一个要部署、要监控的组件：它停了文件就不再更新，网关不会报错。好处是网关启动不再依赖 JWKS 地址可达，"旧公钥最多再用多久"也可以由这个组件来管 |

等上游做"遇到未知 kid 就立即重取"不算一条路：议题开了三个多月，唯一的修复 PR 没有合并，没有时间表。

Gatekeeper 的控制台目前轮换的是 ID 令牌的密钥集；访问令牌的密钥集（网关验的是它）在 login-consent 的代码里没有出现，也就是没有找到它的轮换入口。所以这件事眼下不会被控制台的一次点击触发，但只要有人在 Hydra 上换了这把密钥，按地址取 JWKS 的出站网关就会在下一次定时重取之前拒绝所有新令牌。

### 5. 多问一次 Gatekeeper 的代价

以网关的身份在一条连接上连续问 `gateway-authz` 300 次（本机，回环，Gatekeeper 在容器里）：

| | p50 | p90 | p99 |
|---|---|---|---|
| 只看登记表 | 0.28–0.30 ms | 0.34–0.38 ms | 0.5–0.75 ms |
| 每次再问 Gatekeeper | 1.41–1.53 ms | 1.96–2.19 ms | 3.05–3.5 ms |

这是 2026-11-11 三轮运行的范围（第三轮时这台机器上还有别的负载）。每个放行的请求多出大约 1 毫秒，和单独调一次 PDP 的耗时相当（单独量是 p50 1.1 毫秒）。适配器给这一问的时限是 300 毫秒，网关等 `gateway-authz` 的时限是 1 秒。这组数字只说明量级：单连接、顺序、同一台机器。

另外要知道：这套环境里一个放行的请求经网关走完全程大约 44 毫秒，而被拒绝的请求不到 1 毫秒。多出来的时间在网关到 Mock Provider 那一跳上，与 Gatekeeper 无关；原因没有查。

## 需要 Gatekeeper 一侧决定的

第 4 条 Gatekeeper 已经定了。其余的都没有动，也不该由本仓库动：

1. 授权模型里要不要有 Provider 账户这个类型，长什么样。M2M 客户端现在被 PDP 归一成 `user:<client_id>`，要不要单独的类型也在这里。
2. 出站网关的专属受众，以及 M2M 客户端怎么登记它。
3. 令牌里要不要带环境；不带的话，按签发者区分环境是否就是约定。
4. PDP 怎么区分"拒绝"和"没查成"。已定：没查成的应答带 `"indeterminate": true`（Gatekeeper `10dc843`），适配器已改用它，见上面第 3 点。
5. 给 `gateway-authz` 的 PDP 访问方式：现在是一个共享的 Bearer 令牌，Gatekeeper 自己的注释建议再加 mTLS。
6. 访问令牌的签名密钥怎么换：新密钥先发布、过一个重取周期再启用，还是让 JWKS 响应带上可缓存的时长（见上面第 4 点的三条路）。

### 网关这一侧的建议

2026-11-11 复核时定的。这是网关一侧希望 Gatekeeper 怎么决定，以及这样希望的理由；决定权在 Gatekeeper，这些没有与它的负责人确认过，也没有改动它的任何东西。

| | 建议 | 理由 |
|---|---|---|
| 1 | 采用这里试过的 `provider_account` 类型。M2M 客户端归成哪种主体类型，网关侧没有要求，只要 PDP 对同一个客户端给出的主体稳定 | 加了这个类型之后 PDP 一行代码不用改，`GK-01`、`02`、`05`、`06`、`07` 都通过 |
| 2 | 给出站网关一个专属受众，并且**按客户端登记**。不要用全局的 `TOKEN_AUDIENCE` | 没有专属受众，任何发给 `bip-api` 的令牌都能拿来敲出站网关的门，`GK-03` 挡的就是这个。全局开关会让之后新建的每个 M2M 客户端都能申请这个受众 |
| 3 | 令牌里带环境：由令牌钩子写入 `env`，并把它加进 Hydra 的顶层声明白名单。至少要约定一个签发者只属于一个环境 | 不带也能跑，联调就是按签发者区分的。但那样"令牌的环境"和"路由的环境"都出自同一份网关配置，签发者配错时没有第二道检查；带了，`gateway-authz` 现有的那条比对就仍然有用 |
| 4 | PDP 用状态码或单独的字段区分"拒绝"和"没查成"。**Gatekeeper 已经定了**：单独的字段 `indeterminate`（`10dc843`），状态码仍是 200 | 当时两者只差 `reason` 里的一个字符串。适配器已改成按这个字段认"没查成"，拒绝不再取决于措辞（上面第 3 点） |
| 5 | `gateway-authz` 到 PDP 用工作负载 mTLS，共享的 Bearer 令牌只作过渡 | 与 ADR-0008 第 5 条一致：网关到 `gateway-authz` 那一跳已经是这样（`P1-AZ-11`、`P1-TL-01`）。这一跳的适配器现在只会带 Bearer 令牌，还不会出示客户端证书；它对非回环地址只接受 https，这一条只有单元测试。Gatekeeper 定了之后这边要跟着做 |
| 6 | 先发布、后启用：新密钥先进 JWKS，过一段约定的时间再用它签发 | 网关侧按 ADR-0010 第 8 条把 JWKS 放在快照里，不按地址去取，那段时间要长于"发现 JWKS 变了，加一次发布"。不建议只靠缩短缓存时长：那样网关启动仍然依赖 JWKS 地址可达，重取遇到 5xx 时的表现也不好（上面第 4 点） |

第 3 条建议带环境，与联调现在的做法（路由常量）不同。Gatekeeper 定下来之前，联调和黑盒套件各自保持现状。

## 没有覆盖的

- 生产形态的 Gatekeeper：这里是它的开发配置（Hydra `--dev`、明文 HTTP、开发用的固定密钥，只是换了管理密钥并给 PDP 加了令牌）。
- 模型里没有 `provider_account` 类型的 Gatekeeper 实例：适配器把 `unknown action` 读成没有结论，这一条只有单元测试（上面第 3 点）。
- `gateway-authz` 到 PDP 的 TLS：本机是回环上的明文；适配器对非回环地址只接受 https，这一条只有单元测试。
- 用户令牌（授权码流程）、Mode B 的 Broker 路由、写操作路由。
- 并发与负载；上面的耗时是单连接顺序请求。
- 授权结果的缓存：现在每个请求都问。
