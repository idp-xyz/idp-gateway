# WanbExpress：`deploy/providers/wanbexpress` 在联调架子上跑

[开发计划](../../../docs/development-plan.md) 3.2 的第一步。读的是 `deploy/providers/wanbexpress/agentgateway.yaml` 本身，不是另抄一份。不改 Go，不改 `tests/integration/gatekeeper/run.py`：那一套的 `run.py` 被原样当模块用（取令牌、`seed`、签证书、起进程、停进程、读判定记录都是它的），所以它仍是 12/12，没有重跑的必要。

> 已发布的 `gk.idp.xyz` 是生产环境，这里不访问它。真实沙箱那一遍（`--sandbox`）由仓库所有者带着自己的凭证跑，**代码没有对着真实的沙箱跑过**。

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

对着替身时，配置只换一处：四条路由后端的 `host: api-sbx.wanbexpress.com:80` 换成替身的地址（精确字符串替换，出现次数不是 4 就不跑）。`urlRewrite.authority` 不换，所以替身看到的 `Host` 就是沙箱的名字。

## 两种跑法

- **默认**：两个租户各有一个账户（替身上两个账号，随机生成）。全部检查都做。
- **`--sandbox --sandbox-credentials 文件`**：上游是真实的沙箱（`api-sbx.wanbexpress.com:80`，明文 HTTP）。文件是 `{"account": "客户代码", "token": "开发者令牌"}`，0600，**在仓库之外**（在仓库里就拒绝）：一个沙箱账号，登记给 blue 租户，green 没有账户。`gateway-authz` 要的句柄格式由套件包一层，写进 `tempfile.mkdtemp` 做的临时目录（0700，文件 0600），进程结束时无论成败都删掉。网关进程在去掉了所有名字里带 `proxy` 的环境变量的环境里起；结果里记下去掉的变量名、沙箱的名字解析到的地址、网关进程实际连着的非回环地址、每个调用的耗时。创建的包裹：`ReferenceId` 是 `IDPGW-日期-随机串`，不带 `AutoConfirm`（显式 false），正文是文档的示例请求，用完删除；凡是沙箱答了 `ProcessCode` 的创建（包括 WB-03 里本该失败的第二次）都记下并在结束时删掉；删不掉的处理号写在结果里，并在标准输出里用一排感叹号标出，退出码非零。WB-01 的 whoami 没有被承运商接受时，不再往沙箱发别的（只剩那些到不了沙箱的用例）。
  只在替身上能验的检查（替身收到了什么：WB-04 整个、各用例里的"承运商什么都没收到"、WB-09 的对照；两个账户的隔离）在 `--sandbox` 下**跳过，结果里记为 skipped，不是通过**。

沙箱的账号和令牌、Gatekeeper 的令牌、PDP 令牌、客户端密钥都不写进结果文件、标准输出和日志；WB-10 在跑完之后扫网关和 `gateway-authz` 的日志、标准输出、结果文件，找这一次的每个秘密和任何 `Hc-OweDeveloper …;` 形式的值。

## 替身照文档做了什么，哪些是我们的假设

照文档：`Authorization` 恰好一个、格式 `Hc-OweDeveloper 账号;令牌;随机数`（缺或格式错 403，账号令牌不对 401，随机数只含字母数字 `-` `_`）；`Accept` 要 `application/json`；`whoami`；创建的信封，`ReferenceId` 全局唯一，重复是 HTTP 200 加 `Succeeded: false`、`Error.Code` `0x100005`；`Status` 是 `Original`（`AutoConfirm` 为 true 时 `Confirmed`）；取回；删除只在确认交运之前。

**我们的假设（文档没写）**：随机数用过就拒（403；文档说以后的版本会限定）；`Accept` 不对答 406；处理号不存在或不是这个账户的，HTTP 200、`Error.Code` `0x100001`；删除已确认的包裹答 `0x100002`；删除成功答 `{"Succeeded": true, "Error": null}`（文档说删除"无明确返回数据格式"）；创建只查 `ReferenceId`、`ShippingAddress`、`ItemDetails` 非空；替身每个应答都带一个 `Set-Cookie`（为了看网关去不去掉它）。承运商真正怎么回应，要等真实沙箱。

## 用例

| 用例 | 检查什么 |
|---|---|
| WB-01 | blue 的真实 Gatekeeper 令牌经网关调 `whoami`：200，`Succeeded` 真，`Data` 是该账户的账号（只记对不对），判定是 `ACTIVE_ACCOUNT_GRANT`、操作 `whoami.get`，承运商的 `Set-Cookie` 没到调用方（替身） |
| WB-02 | 创建 → 按处理号取回（`ReferenceId`、处理号对得上）→ 删除；删除后再取：替身答"查不到"（沙箱上只记录，不判） |
| WB-03 | 同一个 `ReferenceId` 再创建：HTTP 200、`Succeeded` 假、`Error.Code` 是 `0x100005`，原样到调用方；第一个包裹删除 |
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

2026-11-19，仓库 `a978aaa` 加上这一轮的改动，agentgateway 1.7.0，Gatekeeper `f36dc06`，上游是替身，连跑两遍：**两遍都是 10/10，每遍 111 项检查，没有跳过**。每遍约两秒。

| 用例 | 检查数 |
|---|---|
| WB-01 / 02 / 03 / 04 / 05 | 5 / 7 / 5 / 10 / 9 |
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

## 真实沙箱的结果

（仓库所有者跑完后填。）
