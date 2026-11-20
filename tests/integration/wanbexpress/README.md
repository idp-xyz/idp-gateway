# WanbExpress：`deploy/providers/wanbexpress` 在联调架子上跑

[开发计划](../../../docs/development-plan.md) 3.2。第一步（`run.py`）在联调架子上，第二步（`pool.py`）在单机池上，见下面"单机池上"。读的是 `deploy/providers/wanbexpress/agentgateway.yaml` 本身，不是另抄一份。不改 Go，不改 `tests/integration/gatekeeper/run.py`：那一套的 `run.py` 被原样当模块用（取令牌、`seed`、签证书、起进程、停进程、读判定记录都是它的），所以它仍是 12/12，没有重跑的必要。

> 已发布的 `gk.idp.xyz` 是生产环境，这里不访问它。真实沙箱那一遍（`--sandbox`）由仓库所有者带着自己的凭证跑，`run.py` 对着真实沙箱的结果在下面，`pool.py --sandbox` 没有跑过。

## 怎么跑

```bash
tests/integration/gatekeeper/stack.sh up                                   # 本机的 Gatekeeper，已经起着就不用
.venv/bin/python tests/integration/wanbexpress/run.py                      # 上游是替身；约两秒
.venv/bin/python tests/integration/wanbexpress/run.py --mutate NAME        # 对照：故意改坏配置的一处，只在替身上
.venv/bin/python tests/integration/wanbexpress/run.py --sandbox --sandbox-credentials /仓库之外/wanbexpress-sandbox.json
```

端口沿用联调那一组（27611-27620 和 27621-27623），所以和联调、黑盒、compose 套件都不能同时跑。进程的文件和日志在 `tests/integration/gatekeeper/.run/`，结果在 `tests/integration/wanbexpress/.run/result-*.json`（都被 git 忽略）。

| 谁 | 是什么 |
|---|---|
| 真的 | 本机的 Gatekeeper（令牌、JWKS、PDP 和 OpenFGA，PDP 经 27623 要客户端证书）、锁定的 agentgateway 1.7.0、`gateway-authz`（产品构建）、`deploy/providers/wanbexpress/agentgateway.yaml` 和由 `policy.example.json` 填出来的登记表 |
| 假的 | 承运商（`mock_wanbexpress.py`）、工作负载证书（每次现做的 CA）。WB-09 里 `gateway-authz` 换成带 `acceptance` 标签的构建，只为了能让它"放行却不给凭证"；它还是问着真实的 PDP |

`deploy/providers/wanbexpress/agentgateway.yaml` 写的是池的值，联调架子上用精确字符串替换（`run.py` 的 `RIG_VALUES`，每一处核对出现次数，不对就不跑）把它们换回联调的：三个本机端口（管理、指标、就绪 `15000/15020/15021` → `27614/27615/27616`）、业务监听和回读口（`8081`、`8443` → `27611`、`27619`，含 `networkAuthorization` 里的两处）、`gateway-authz:9443` → `127.0.0.1:27613`（4 处）、证书路径 `tls/` → `.run/tls/`（`cert`、`key`、`root` 各 5 处）、JWKS 的 `file: tls/jwks.json` → 本机 Hydra 的 URL、回读路由转给的 `127.0.0.1:15000` → `27614`。对着替身时另把四条路由后端的 `host: api-sbx.wanbexpress.com:80` 换成替身的地址（出现次数不是 4 就不跑）。`urlRewrite.authority` 不换，所以替身看到的 `Host` 就是沙箱的名字。

## 两种跑法

- **默认**：两个租户各有一个账户（替身上两个账号，随机生成）。全部检查都做。
- **`--sandbox --sandbox-credentials 文件`**：上游是真实的沙箱（`api-sbx.wanbexpress.com:80`，明文 HTTP）。文件是 `{"account": "客户代码", "token": "开发者令牌"}`，0600，**在仓库之外**（在仓库里就拒绝）：一个沙箱账号，登记给 blue 租户，green 没有账户。`gateway-authz` 要的句柄格式由套件包一层，写进 `tempfile.mkdtemp` 做的临时目录（0700，文件 0600），进程结束时无论成败都删掉。网关进程在去掉了所有名字里带 `proxy` 的环境变量的环境里起；结果里记下去掉的变量名、沙箱的名字解析到的地址、网关进程实际连着的非回环地址、每个调用的耗时。创建的包裹：`ReferenceId` 是 `IDPGW-日期-随机串`，不带 `AutoConfirm`（显式 false），正文是文档的示例请求，用完删除；凡是沙箱答了 `ProcessCode` 的创建（包括 WB-03 里本该失败的第二次）都记下并在结束时删掉；删不掉的处理号写在结果里，并在标准输出里用一排感叹号标出，退出码非零。WB-01 的 whoami 没有被承运商接受时，不再往沙箱发别的（只剩那些到不了沙箱的用例）。
  只在替身上能验的检查（替身收到了什么：WB-04 整个、各用例里的"承运商什么都没收到"、WB-09 的对照；两个账户的隔离）在 `--sandbox` 下**跳过，结果里记为 skipped，不是通过**。

沙箱的账号和令牌、Gatekeeper 的令牌、PDP 令牌、客户端密钥都不写进结果文件、标准输出和日志；WB-10 在跑完之后扫网关和 `gateway-authz` 的日志、标准输出、结果文件，找这一次的每个秘密和任何 `Hc-OweDeveloper …;` 形式的值。

## 替身照文档做了什么，哪些是我们的假设

照文档：`Authorization` 恰好一个、格式 `Hc-OweDeveloper 账号;令牌;随机数`（缺或格式错 403，账号令牌不对 401）；`Accept` 要 `application/json`；`whoami`；创建的信封，`Status` 是 `Original`（`AutoConfirm` 为 true 时 `Confirmed`）；取回；删除只在确认交运之前。

**照 2026-11-19 在真实沙箱上量到的**（文档没写）：同一个 `ReferenceId`、正文相同再创建，HTTP 200、`Succeeded` 真、答回已有的处理号；正文不同，HTTP 200、`Succeeded` 假、`0x100005`、Message 带客单号和已有的处理号、`SystemError` 为 null、没有 `Data`；删除之后客单号可以再用；再删一次已删的，HTTP 200、`Succeeded` 真；查不到或已删除的处理号，HTTP 404、正文为空、没有 `Content-Type`。

**替身比沙箱今天严的两处，照文档从严**：随机数用过就拒（403，沙箱两次都接受）；`Accept` 不是 `application/json` 就拒（406，状态码是我们定的，沙箱答 200 JSON）。这两处保留，`no-accept` 对照靠它。

**别的假设（我们的，文档和量到的都没写）**：删除已确认的包裹答 `0x100002`；创建只查 `ReferenceId`、`ShippingAddress`、`ItemDetails` 非空；替身每个应答都带一个 `Set-Cookie`（为了看网关去不去掉它）。

## 用例

| 用例 | 检查什么 |
|---|---|
| WB-01 | blue 的真实 Gatekeeper 令牌经网关调 `whoami`：200，`Succeeded` 真，`Data` 是该账户的账号（只记对不对），判定是 `ACTIVE_ACCOUNT_GRANT`、操作 `whoami.get`，承运商的 `Set-Cookie` 没到调用方（替身） |
| WB-02 | 创建 → 按处理号取回（`ReferenceId`、处理号对得上）→ 删除；删除后再取：HTTP 404（承运商答 404，网关原样给调用方），两种跑法都判 |
| WB-03 | 同一个 `ReferenceId`：正文相同再创建，HTTP 200、`Succeeded` 真、处理号与第一次相同；改一个字段（`WeightInKg`）再创建，HTTP 200、`Succeeded` 假、`Error.Code` 是 `0x100005`，原样到调用方；凡是答了处理号的都记下并删除 |
| WB-04 | 替身：三个请求，每个上游恰好一个 `Authorization`，形状对、是 blue 账户自己的账号和令牌，随机数三个互不相同；`Accept` 恰为 `application/json`（调用方带的是 `text/html`）；`Host` 是沙箱的名字；`x-provider-account`、`cookie`、转发类的头、调用方自造的 `X-Evil-Probe`、`x-idp-*` 都没到；调用方的 Gatekeeper 令牌和它自己塞的 `Authorization` 没到；另记下上游看到的头名（观察，不判：`accept`、`authorization`、`host`） |
| WB-05 | 不带令牌、别的受众、伪造签名：401，`gateway-authz` 没有被问，替身没收到 |
| WB-06 | 替身：green 的令牌得到 green 的账户，上游看到的是 green 的凭证；blue 指定 green 的账户：403 `ACCOUNT_NOT_GRANTED`，替身没收到。`--sandbox`：green 被拒 403（原因码记下，不判），其余跳过 |
| WB-07 | 登记表认、Gatekeeper 没有授权的客户端：403 `ACCOUNT_NOT_GRANTED`，替身没收到 |
| WB-08 | 没有路由的方法（`PUT`、`PATCH`、`POST`/`DELETE` 到 `whoami`、`PUT /parcels`）：网关答 404，`gateway-authz` 没有被问；路径不对（`bags`、列表、搜索、`/parcels/`、更深的路径、`..`、`%2e%2e`、`%2f`、`%252e`、`;x=1`、`%00`、`//`、承运商自己的 `/api/whoami`、别的 Provider）和方法对但形状不对（`POST /parcels/X`、`DELETE /parcels`）：都被拒（>= 400），替身没收到。另记一条不判的观察：`GET /parcels/X?note=q` 的查询串原样到了承运商 |
| WB-09 | 见下 |
| WB-10 | 扫描，见上 |

### WB-09：PDP 放行却没给凭证

做法同黑盒的 `P1-DT-02`：`gateway-authz` 换成带 `acceptance` 标签的构建（本机回环上、要操作者证书和一个这次运行的口令才开的控制口，仍然问着真实的 Gatekeeper），把它设成"放行但不给凭证"。检查：调用方得到 >= 400；`gateway-authz` 记的是放行（`ACTIVE_ACCOUNT_GRANT`），所以拒绝的是网关；答案不是承运商的；承运商什么都没收到；调用方自己塞的 `Authorization: Hc-OweDeveloper …` 放在令牌后面，同样被拒、没到上游，放在令牌前面网关答 401。再设回正常，同一个请求带着调用方塞的头：200，承运商收到的是 `gateway-authz` 给的凭证，没有调用方塞的。做完换回产品构建。对照（后端规则去掉，或前缀改成 `Bearer `）见下。黑盒还有一个不做对照的"默认行为"观察（把规则去掉启动，记放过什么）；这里没有另做，由 `no-backend-rule` 的对照代替。`--sandbox` 下这个用例照跑（请求都被网关拒绝，不会到沙箱），"承运商什么都没收到"和最后的对照请求跳过。

## 结果

2026-11-19，仓库 `a978aaa` 加上这一轮的改动，agentgateway 1.7.0，Gatekeeper `f36dc06`，上游是替身，连跑两遍：**两遍都是 10/10，每遍 113 项检查，没有跳过**。每遍约两秒。

| 用例 | 检查数 |
|---|---|
| WB-01 / 02 / 03 / 04 / 05 | 5 / 7 / 7 / 10 / 9 |
| WB-06 / 07 / 08 / 09 / 10 | 5 / 3 / 48 / 15 / 4 |

这是联调，不是验收证据；不改变任何验收用例的 `NOT_RUN`。

### 对照（2026-11-19，替身上，改完跑一遍整套，`--mutate` 不改仓库里的文件）

| `--mutate` | 改了什么 | 不通过的用例 |
|---|---|---|
| `bearer-prefix` | 后端规则的前缀改回 `Bearer ` | WB-01、02、03、04、06、09（4/10）：所有请求被网关拒绝 |
| `no-backend-rule` | 去掉后端规则 | 只有 WB-09：不给凭证的请求到了替身，替身答 403 |
| `no-accept` | 去掉写 `Accept` 的那一处 | WB-01、02、03、04、06、09（4/10）：调用方没带 `Accept`，替身（我们的假设）答 406；WB-04 里调用方带 `text/html` 时它原样到了上游 |
| `no-header-filter` | 去掉后端上过滤请求头的名单 | 只有 WB-04：`X-Evil-Probe` 到了上游（按名字去掉的那几个仍被去掉） |
| `delete-any-method` | `DELETE` 路由改成不限方法 | 只有 WB-08：`PUT`、`PATCH` 到了 `gateway-authz`。承运商仍什么都没收到：登记表的方法对不上，`gateway-authz` 拒绝。也就是说路由上的方法限制不是唯一的一道，WB-08 查的是"网关自己先拦"这一层 |

## 单机池上（`pool.py`，第二步）

```bash
tests/integration/gatekeeper/stack.sh up
.venv/bin/python tests/integration/wanbexpress/pool.py                                        # 上游是替身，约半分钟
.venv/bin/python tests/integration/wanbexpress/pool.py --sandbox --sandbox-credentials FILE   # 上游是真实沙箱
.venv/bin/python tests/integration/wanbexpress/pool.py --control no-egress                    # 对照：出口规则的两个服务什么都不装
.venv/bin/python tests/integration/wanbexpress/pool.py --control no-pdp-tls                   # 对照：gateway-authz 缺 --gatekeeper-tls-*，和缺一个变量
```

跑的是 `deploy/compose/compose.yml` 加 `deploy/compose/gateway-authz.yml` 加测试用的叠加文件 `pool.yml`，都不改。**搭法**：compose 项目 `idp-gateway-wanb-pool`，本机端口 `27631`（`front`，调用方从这里进）、`27632`（回读口）、`27633`（发布器离线加载用的临时容器）、`27634`（替身的管理口，只在替身跑法里）；池的目录、证书、`.env`、`gateway-authz` 的文件都在一个 `tempfile.mkdtemp` 的临时目录里（`gateway-control` 和 `gateway-authz` 现场静态构建）；证书用联调架子本次做的那一套，因为本机栈里 PDP 前面的 nginx 信的是这一套 CA。起的先后同"头一次安装"：先放一份只有回读口的配置，`up -d agentgateway gateway-authz outsider [wanb-mock]`，再用 `gateway-control publish` 把 `deploy/providers/wanbexpress/agentgateway.yaml`（只换后端；`--sandbox` 时原样）发布上去，再 `up -d`，`confirm` 对上了 `front` 才开。JWKS 是 `tls/jwks.json`，取自本机 Hydra，只留现在签令牌的那把（原因见 `deploy/providers/wanbexpress/README.md` "发布到池"）。

- **PDP**：测试叠加里 `gateway-authz` 加入联调栈的 docker 网络 `idp-gateway-gk_default`（external），按服务名 `pdp-mtls:8443` 找 PDP，带客户端证书。没有改 `tests/integration/gatekeeper/` 下的东西。
- **替身**：叠加里的服务 `wanb-mock`（profile `standin`），配置里的后端换成 `wanb-mock:8000`，所以出口规则钉的是它。另有 `outsider`：配置里没有它，网关的命名空间里应连不上。
- **用例**：WB-01 到 WB-08、WB-10 原样用；WB-09 跳过并写明原因（要把 `gateway-authz` 换成验收构建，池里跑的是产品构建）；WB-04 有一处不同：`front` 对带两个 `Authorization` 头的请求自己答 400，请求到不了网关，所以不再塞第二个头，改查 `front` 的 400 和承运商什么都没收到；日志扫描扫的是 `agentgateway`、`gateway-authz`、`front` 三个容器的日志。
- **WB-11（只在池上）**：出口规则在起作用。从 `netns` 的网络命名空间里（一个临时容器接在它上面）：规则里钉的地址就是上游名字解析到的那些（替身：钉的恰是 `wanb-mock` 的地址；沙箱：非空，且是该名字解析出的地址之内，结果里记下）；配置登记的上游地址和端口连得上，`gateway-authz` 的地址和端口、回环 `8081` 连得上；`outsider`、登记地址上的另一个端口、`gateway-authz` 的另一个端口、网关的指标端口连不上（被规则拒绝，`113`）。不往公网发探测；`--sandbox` 下对沙箱的地址只做一次 TCP 连接，不发任何内容，也没有凭证。
- **结果里另记**：池里各容器的环境里有没有名字带 `proxy` 的变量；上游名字解析到的地址和规则里钉的地址；每个调用的耗时；`gateway-control publish` 的结局。
- **结束时**无论成败，`docker compose down -v` 自己的项目，删临时目录。只动自己的项目和 `idp-gateway-gk`。

### 结果（2026-11-19，替身，两遍）

两遍都是 11/11。每遍 108 项检查，其中 1 项是 WB-09 整个跳过，别的没有跳过。`publish` 都是 `ACTIVE`。容器里没有代理变量（`agentgateway`、`front`、`netns`、`gateway-authz` 都查了）。`WB-11` 钉住的是 `127.0.0.1:15000`、`gateway-authz:9443`、`wanb-mock:8000`，各是对应容器的地址。

| 对照 | 结果 |
|---|---|
| `--control no-egress` | 10/11：只有 WB-11 不通过。没有钉住任何地址，`outsider`、替身的另一个端口、`gateway-authz` 的另一个端口、网关的指标端口都连得上（WB-01 到 WB-10 照常通过：出口规则不影响正常的调用，这一条只有 WB-11 看得见） |
| `--control no-pdp-tls` | `gateway-authz` 缺 `--gatekeeper-tls-*` 起不来，退出码 1：`--gatekeeper-url is not a loopback address, so --gatekeeper-tls-cert, --gatekeeper-tls-key, --gatekeeper-tls-ca and --gatekeeper-name are required: this hop may not rest on a shared token alone`。缺一个变量（`GATEWAY_AUTHZ_PDP_CA`）：`docker compose config` 退出码 1，`required variable GATEWAY_AUTHZ_PDP_CA is missing a value: see gateway-authz.env.example` |

`--pool --sandbox` 的代码路径用一次性的办法（上游是池里的替身、凭证是造的）走通过，没有对真实的沙箱跑；那一遍里 WB-11 在沙箱那一支按预期不通过（钉的是替身，不是沙箱的名字），别的通过，临时目录和容器结束后都不在，造的令牌在结果和日志里是 0 处。

### 池上真实沙箱的结果

2026-11-19，在开发机上，`pool.py --sandbox`，凭证文件同上。连跑两遍都是 11/11：98 项检查，65 项通过，33 项跳过（只有替身上看得到的那些，和整个 `WB-09`），没有不通过的。

- 万邦的快照经 `gateway-control publish` 发布到池上，两遍都是 `ACTIVE`；调用方经 `front` 进来，`gateway-authz` 是池里另一个容器，带客户端证书问 Gatekeeper 的 PDP；请求从带着出口规则的命名空间里出去，到了沙箱。验证授权、创建、取回、删除都成了，包裹都删了。
- 出口规则钉住的：沙箱的名字在 80 端口上的两个地址（`47.106.164.236`、`47.107.36.179`，与命名空间里解析到的相同），`gateway-authz:9443` 的容器地址，回环上的回读路由。从命名空间里连：这几处连得上；网络上另一个容器、`gateway-authz` 的另一个端口、网关的指标端口被规则拒绝。没有往公网发探测。
- 四个容器（`agentgateway`、`front`、`netns`、`gateway-authz`）的环境里都没有代理变量。
- 令牌和这种认证头的值，在标准输出、结果文件和三个容器的日志里都是 0 处。
- 耗时（经 `front`）：创建 274 到 459 毫秒，取 214 到 293 毫秒，删除 236 到 293 毫秒。每一种都比联调架子上（网关是本机进程）慢 150 到 200 毫秒，原因没有查。
- **这里没有验的**：承运商实际收到的头和两个账户的隔离（同上，只在替身上）；到承运商的 TLS；沙箱的地址换了之后出口规则怎样（两遍里解析到的都是这两个）；两把密钥的 JWKS（见下一条）；装到另一台机器上。
- **发布器的一个毛病，在这里绕开了**：JWKS 里有两把密钥时，网关报告的密钥顺序每次启动不同，发布器的摘要对顺序敏感，`publish` 大约三次里有一次对不上而退回（`RESTORED`）。套件在池的 JWKS 里只放签令牌的那一把。这是 Sonnet 做这一步时看到的，我还没有单独复现；修它要改 Go。

## 真实沙箱的结果

2026-11-19，凭证文件是仓库所有者给的，放在仓库之外（0600）；Gatekeeper `f36dc06`（本机实例），agentgateway 1.7.0，在开发机上跑。网关进程起在去掉了代理环境变量的环境里，连着的对端是 `47.106.164.236:80` 和 `47.107.36.179:80`，就是沙箱的名字解析到的两个地址。

| 哪一遍 | 结果 |
|---|---|
| 第 1 遍（`b658361`） | 9/10。`WB-03` 不通过：它照文档期望重复的客单号答 `0x100005`，沙箱对正文相同的重复创建答的是成功和已有的处理号。网关没有问题，错的是照文档写的期望 |
| 改了替身和 `WB-03` 之后，连跑两遍 | 都是 10/10：103 项检查，67 项通过，36 项跳过（只有替身上看得到的那些），没有不通过的 |

- 这是第一次经过整条链的真实调用：Gatekeeper 签的令牌，agentgateway 验证，`gateway-authz` 问 Gatekeeper 的 PDP 并给出凭证，请求到了承运商的沙箱。验证授权、创建、按处理号取回、删除都成了。
- 三遍创建的包裹都删掉了，结果里"要手工删除的"是空的。客单号是 `IDPGW-` 开头的。
- 令牌和这种认证头的值，在标准输出、结果文件、网关和 `gateway-authz` 的日志里都是 0 处（套件自己扫一遍，我另外扫了一遍）。
- 耗时（经网关）：第 1 遍的第一次创建 8.5 秒，是唯一一次超过 1 秒的；其余的创建 105 到 275 毫秒，取 50 到 360 毫秒，删除 73 到 102 毫秒，验证授权 50 到 200 毫秒。
- 沙箱的行为与文档不同或文档没写的几处，是另外直接对着沙箱量的（不经网关，一个包裹，用完删除），写在上面"替身的假设"和 [deploy/providers/wanbexpress/README.md](../../../deploy/providers/wanbexpress/README.md) 里。
- **这里没有验的**：承运商实际收到的头（只在替身上看得到）；两个账户之间的隔离（只有一个沙箱账号）；到承运商的 TLS（沙箱只有明文 HTTP）；从 compose 池里发出去（这里的网关是本机进程，没有出口规则）。这些结果算不算验收证据（开发计划 1.6）没有定。
