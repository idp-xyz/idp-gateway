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

| 谁 | 是什么 |
|---|---|
| 真的 | Gatekeeper（Hydra v26.2.0 签发的令牌与 JWKS、login-consent 的 PDP、OpenFGA）、agentgateway 1.7.0（`deploy/agentgateway/agentgateway.lock.json` 锁定的发布版，启动前核对，做法与黑盒套件相同）、`gateway-authz` 的产品构建 |
| 假的 | Provider（黑盒套件的 `mock_provider.py`）、工作负载证书（每次运行现做的 CA） |

本机实例是独立的 compose 项目 `idp-gateway-gk`，只在回环地址上发布两个端口：`27621`（Hydra 公共端点）和 `27622`（login-consent：管理 API 与 PDP）。它与 Gatekeeper 自己的开发栈相比改了什么，写在 `compose.local.yml` 的开头。联调本身占用黑盒套件的 `27611`–`27616`，两者不能同时跑。

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

这是本仓库的提议。它不在 Gatekeeper 的仓库里，也不在已发布的实例里；`gateway-authz` 的 Gatekeeper 适配器在这个类型进入 Gatekeeper 自己的模型之前，对任何别的 Gatekeeper 实例都只会得到"没有结论"。

本机实例的 `TOKEN_AUDIENCE` 也改过：在默认的 `bip-api` 之外加了 `idp-egress-gateway`，原因见下面第 1 点。

## 结果

2026-11-11，Gatekeeper `0920e96`，agentgateway 1.7.0：默认的 11 个用例全部通过；加上 `--key-rotation` 后的第 12 个用例 FAIL（见下面第 4 点）。逐项结果写在 `.run/result.json`，不入库；这里没有像黑盒套件那样的证据文件。

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

### 3. PDP 对"没有授权"和"没查成"都答 200

OpenFGA 停掉时，PDP 仍然返回 `200 {"decision": false, "reason": "rebac lookup failed"}`，和真正的拒绝（`"rebac denied"`）只差 `reason` 这个字符串。适配器现在只把 `rebac denied` 当作拒绝，其余一律当作没有结论（网关答 503，不记成策略拒绝）。这依赖一个没有写进任何契约的字符串：**Gatekeeper 改了措辞，拒绝就会全部变成 503。** 需要它用状态码或单独的字段区分这两种情况。

### 4. agentgateway 的 JWKS 只在加载配置时取一次

- JWKS 地址不可达时网关**拒绝启动**（`failed to load JWKS`）。用文件形式的 JWKS 时没有这个依赖。
- 给本机 Hydra 换了访问令牌的签名密钥之后，新密钥签的令牌一直是 401，旧密钥签的仍然通过。等了 16 分钟没有恢复；改写配置文件让网关重新加载配置之后等了 20 秒，也没有重新取；重启网关后恢复。可用 `run.py --key-rotation` 重现（用例 GK-12）。
- JWKS 改用文件时（黑盒套件的做法），**只要重写那个文件**，网关在 10 秒内接受新密钥签的令牌，不用重启，也不用碰配置文件。

也就是说，要让出站网关跟得上签名密钥的更换，现成的路是：网关读文件，另有一个东西把 Hydra 的 JWKS 同步到文件里。这个"东西"现在不存在。后两条观察是手工做的，没有写成用例。

Gatekeeper 的控制台目前轮换的是 ID 令牌的密钥集；访问令牌的密钥集（网关验的是它）在 login-consent 的代码里没有出现，也就是没有找到它的轮换入口。所以这件事眼下不会被控制台的一次点击触发，但只要有人在 Hydra 上换了这把密钥，按地址取 JWKS 的出站网关就会拒绝所有新令牌，直到被重启。

### 5. 多问一次 Gatekeeper 的代价

以网关的身份在一条连接上连续问 `gateway-authz` 300 次（本机，回环，Gatekeeper 在容器里）：

| | p50 | p90 | p99 |
|---|---|---|---|
| 只看登记表 | 0.28–0.29 ms | 0.34–0.35 ms | 0.5–0.7 ms |
| 每次再问 Gatekeeper | 1.41–1.44 ms | 1.96–2.03 ms | 3.4–3.5 ms |

这是 2026-11-11 在 1.7.0 上连跑两轮的范围。每个放行的请求多出大约 1 毫秒，和单独调一次 PDP 的耗时相当（单独量是 p50 1.1 毫秒）。适配器给这一问的时限是 300 毫秒，网关等 `gateway-authz` 的时限是 1 秒。这组数字只说明量级：单连接、顺序、同一台机器。

另外要知道：这套环境里一个放行的请求经网关走完全程大约 44 毫秒，而被拒绝的请求不到 1 毫秒。多出来的时间在网关到 Mock Provider 那一跳上，与 Gatekeeper 无关；原因没有查。

## 需要 Gatekeeper 一侧决定的

这些都没有动，也不该由本仓库动：

1. 授权模型里要不要有 Provider 账户这个类型，长什么样。M2M 客户端现在被 PDP 归一成 `user:<client_id>`，要不要单独的类型也在这里。
2. 出站网关的专属受众，以及 M2M 客户端怎么登记它。
3. 令牌里要不要带环境；不带的话，按签发者区分环境是否就是约定。
4. PDP 怎么区分"拒绝"和"没查成"。
5. 给 `gateway-authz` 的 PDP 访问方式：现在是一个共享的 Bearer 令牌，Gatekeeper 自己的注释建议再加 mTLS。

## 没有覆盖的

- 生产形态的 Gatekeeper：这里是它的开发配置（Hydra `--dev`、明文 HTTP、开发用的固定密钥，只是换了管理密钥并给 PDP 加了令牌）。
- `gateway-authz` 到 PDP 的 TLS：本机是回环上的明文；适配器对非回环地址只接受 https，这一条只有单元测试。
- 用户令牌（授权码流程）、Mode B 的 Broker 路由、写操作路由。
- 并发与负载；上面的耗时是单连接顺序请求。
- 授权结果的缓存：现在每个请求都问。
