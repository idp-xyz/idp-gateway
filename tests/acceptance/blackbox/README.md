# 黑盒套件 — 真实 agentgateway 上的认证、授权与凭证注入

> **性质**：黑盒回归，不是验收。`tests/acceptance/acceptance_matrix.csv` 的 95 条用例与六个 STD-CP 门禁保持 `NOT_RUN`。用例编号沿用 PoC 阶段的 `P1-*`。
> **结果**：59 个用例，agentgateway 1.7.0 上 58 PASS、1 FAIL。FAIL 的是 `P1-SS-04`：网关自己仍然接受带两个 `Host` 头的请求，处置见"未解决"。证据：`evidence/p1-run-agentgateway-1.7.0.json`。
> **环境**：agentgateway **1.7.0**，即 `deploy/agentgateway/agentgateway.lock.json` 锁定的构建（上游容器镜像里的那个二进制，镜像按摘要锁定；二进制取出来在本机直接运行，不在容器里；它的 SHA-256 记在证据里，每次运行前按锁定文件核对，对不上就不运行）、本仓库的 `gateway-authz`、Mock 本地 Broker、Mock Provider，全部在本机回环地址。只测这一个构建。网关到 `gateway-authz`、Broker 到 `gateway-authz` 两段是双向 TLS，证书由每次运行临时生成的 CA 签发。
> **PDP 是本仓库的 `cmd/gateway-authz`，带 `acceptance` 标签构建**：产品代码加上本套件用的控制接口（看它收到了什么、让它答 500、变慢、放行却不给凭证、撤销账户）。跑的不是产品构建。它从文件读登记表和凭证，撤销状态在内存里；已部署的 Gatekeeper 没有被调用，调用方 Token 是用每次运行临时生成的密钥签的。
> **名字还没改**：下文、用例标题、证书和端口名里的"Gatekeeper""PDP"，指的都是这个进程。PoC 阶段这个位置上是一个 Python Mock（`mock_gatekeeper.py`，已删除，见基线标签 `baseline-v1.0-poc`）。

## 回答了什么问题

G04 §4 要求用 PoC 比较三种凭证返回模式，G04 §9 列了 PoC 必须证明的结论。本 PoC 的回答：

| 问题 | 结论 | 依据 |
|---|---|---|
| agentgateway 能否按请求注入由 PDP 选定的第三方凭证（模式 A）？ | **能**。HTTP ExtAuthZ 的允许响应带 `Authorization` 头，网关按 `includeResponseHeaders` 把它（且只把它）写到上游请求。 | `P1-AZ-01/02/04`、`P1-CR-01` |
| 两租户、两账户能否隔离？ | **能**。租户身份取自已验签 JWT；蓝租户请求绿账户被拒；撤销蓝账户后下一个蓝请求即被拒，绿不受影响。 | `P1-AZ-03`、`P1-RV-01` |
| 调用方能否伪造租户或可信上下文？ | **不能**。伪造的 `x-idp-*`、`X-Tenant-ID` 到不了 PDP；PDP 看到的是网关按 JWT 声明和路由常量写入的值。 | `P1-AZ-05` |
| 内部 JWT 会不会到第三方？第三方凭证会不会回到调用方？ | **都不会**。Provider 只收到 Provider 凭证；PDP 收不到调用方 JWT，也收不到任何 Bearer 凭证；网关整轮运行的日志里没有 Provider 凭证、调用方 JWT 或密钥。 | `P1-CR-01/02/03/04` |
| 网关到 PDP 能否用工作负载 mTLS，PDP 能否据此只认网关？ | **能**。网关出示自己的证书，并且只接受工作负载 CA 为指定名字签发的 PDP 证书；PDP 从已验证的客户端证书取调用方身份。没有证书或证书来自别的 CA，连 TLS 都建立不了；同一信任域里不是网关的工作负载（业务应用、本地 Broker）拿到 401，拿不到凭证。冒充 PDP 的服务（名字对、CA 不对）收不到网关的任何请求。 | `P1-AZ-11`、`P1-CR-03`、`P1-TL-01` |
| PDP 故障时是否默认拒绝？ | **是**。PDP 返回 500、超时、进程不在，请求都没有到达 Provider。 | `P1-FC-01/02/03` |
| 非幂等写会不会被网关重放？ | **不会**（未配置重试策略时）。上游超时返回 504、上游断连返回 503，Provider 各只收到一次。 | `P1-WR-02/03` |
| 固定凭证（模式 C）够不够？ | **只够单账户**。跑得通，但两个租户以同一个账户到达 Provider。 | `P1-MC-01` |
| 模式 B（本地 Broker/Sidecar）？ | **跑得通，隔离、撤销、默认拒绝与模式 A 相同**。Gatekeeper 只被问决策，它发出的任何内容里都没有 Provider 凭证；凭证由 Broker 从本地存储取出，只走回环。代价见下面"三种取凭证方式的比较"。 | `P1-MB-01/02/03/04` |
| `backendAuth.key.expression` 比复制响应头更好吗？ | **能用，结果相同，没有观察到安全上的差别**。 | `P1-KX-01/02/03` |
| 换了配置文件之后，能否确认这个实例上生效的是哪一份？ | **单个实例上能**。换文件不用重启，约 0.3 秒生效；加载不了的文件被整份拒绝，网关报告失败和原因，继续用上一份。网关报告的运行配置（`/config_dump`）算出的摘要随配置变，文件换回后回到原值。多个实例之间的情况在 `tests/integration/kubernetes` 里。注意事项见下面"配置回读"。 | `P1-RB-01/02` |
| 发布器能否从别的机器读到这些，又不把网关的管理地址交出去？ | **能**。网关另开一个要客户端证书的监听，只认发布器的身份，只把这两个 GET 转给本机的管理地址。管理地址上别的东西（关停、改日志级别、调试、写配置）在这个监听上一概没有；别的调用方连回应都得不到。 | `P1-RB-03` |

## 三种取凭证方式的比较

| | 模式 A：复制响应头 | 模式 A：`key.expression` | 模式 B：本地 Broker | 模式 C：固定凭证 |
|---|---|---|---|---|
| 按租户选账户 | 能 | 能 | 能 | 不能 |
| Provider 凭证经过哪里 | Gatekeeper 的响应 → 网关 | 同左 | Broker 本地存储 → 回环 → 网关；不出现在 Gatekeeper 的任何响应里 | 网关上的文件 |
| Gatekeeper 的接口 | `/v1/extauthz/check` | 同左，响应不变 | `/v1/egress/authorizations/decision`，只回决策和凭证句柄 | 不调用 |
| 多出来的东西 | 无 | 无 | 一个进程、一份本地凭证存储、一段回环通信 | 无 |

`key.expression` 的做法：ExtAuthZ 的 `metadata` 把 PDP 响应里的 `authorization` 头读进 `extauthz.credential`，再由 `backendAuth.key.expression` 写到上游请求，不再用 `includeResponseHeaders`。这条路由的写法是先在单独的试验里试出来的，试验中看到三点（不在证据文件里；证据文件证明的是现在这条路由的行为）：

- backend 上的 `authorization` 规则**先于** `backendAuth` 执行。照搬模式 A 路由上"必须有 `Authorization` 头"的规则，每个请求都会被拒（这时头还没写上）；要改成判断 `extauthz.credential`。写错的后果是全部拒绝，不是放行。
- 不加这条规则时，PDP 放行却没给凭证的请求会被不带凭证地转发，与"默认配置不安全的地方"第 3 项相同。
- `metadata` 也读得到响应体（`json(response.body)`），所以凭证可以不放在头里。契约目前规定凭证正文不出现在任何响应体里，本 PoC 没有改这一点。

模式 B 跑下来暴露的三件事：

- **回环端口上，密钥文件是唯一的屏障**。Broker 在回环地址上监听，网关用一个密钥文件证明自己；本机任何能读到这个文件的进程都能向 Broker 要到凭证（`P1-MB-04` 的对照项）。真实部署要靠 Unix Socket 或 Pod 内网络隔离，这一点没有测。
- **多了一处持有凭证的地方**。Broker 的本地存储里有该网关池用得到的全部账户凭证，它如何下发、轮换、吊销，设计里还没有。
- **决策契约缺一个字段**。`DecisionRequest` 原先没有地方放"调用方 Token 是为哪个环境签发的"，Broker 无从转达，PDP 也就拒绝不了 PROD Token 用在 TEST 池上。已在 `contracts/gatekeeper/openapi.yaml` 里加上可选的 `token_environment`（提案）。

## 配置回读

G03 要求发布之后逐个实例回读，确认生效的是批准的那一份（`GW-FR-014`、`GW-FR-041`）。网关的管理地址上有两个接口用得上：`/api/runtime` 的 `configReload` 说最近一次加载文件成没成功，`/config_dump` 给出它实际在用的配置。`P1-RB-01/02` 在被测的那个网关上换文件再换回来，看这两个接口怎么说。用的时候要知道：

- **单看 `synchronized: true` 不够**。`configReload` 只有 `synchronized` 和 `lastError` 两个字段，没有版本号，也没有加载时间；文件已经换了而网关还没重载的那一刻，它同样是 `true`。"这一份已经生效"要两条同时成立：`/config_dump` 的摘要等于期望值，并且 `synchronized` 为 `true`。
- **`/api/config/effective` 不能用来确认**。它显示的是磁盘上的文件，文件被拒绝时照样显示被拒绝的内容（`P1-RB-02` 的 `api_config_effective_shows_the_rejected_file`）。
- **期望的摘要要从网关那里取**。`/config_dump` 是网关内部的表示，不是文件原文，不能拿文件的哈希去比；要先让一个实例加载这份文件，取它的摘要作基准。单独试过（不在证据里）：一份只有两条路由的小配置，在重新启动的另一个实例上摘要相同；这里的评审配置，空闲时、有流量前后、隔几秒之后摘要都相同，`/config_dump` 的内容里没有那次运行的任何凭证或私钥。跨实例比对时要去掉 `config` 段再算：那一段里有随运行环境变的值（比如工作线程数跟着 CPU 限额走），见 `tests/integration/kubernetes/README.md` 第 4 点。
- 拒绝是整份的：被拒绝的文件里即使有没问题的路由，也不会生效。
- **摘要里有什么、没有什么**（单独试过，不在证据里）。`/config_dump` 里有路由、策略、后端、监听地址，有 `backendTLS` 引用的证书和 CA 的正文，有 JWKS 里各把密钥的 `kid`。没有私钥，没有凭证文件的内容，没有 JWKS 的密钥本身。所以：换了证书，摘要会变；JWKS 里同一个 `kid` 换了一把密钥，或者固定凭证文件换了内容，摘要不变。按地址取 JWKS 时，身份提供方加一把密钥，摘要也跟着变，哪怕没有任何发布。拿摘要跨实例、跨时间比对时要先把证书正文换成占位，JWKS 要随配置一起下发，见 ADR-0010 第 6、8 条。

**回读口**（`P1-RB-03`）。上面两个接口都在管理地址上，而管理地址不能离开回环（见下面第 7 项）。发布器在别的机器上，要读到它们，走的是评审配置里的另一个监听（`27619`）：

- 监听带 TLS，并要求客户端证书（`tls.root` 指向工作负载 CA）。没有证书、证书来自别的 CA，握手就失败。
- `frontendPolicies.networkAuthorization` 只放行发布器的身份（证书里的 SPIFFE ID）。同一个 CA 签发的其它工作负载，包括网关自己、Broker、业务应用，连接被直接断开。
- 这个监听上只有一条路由：`GET /config_dump` 和 `GET /api/runtime`，路径精确匹配，转给本机的管理地址。读到的内容与直接问管理地址相同。
- 管理地址上别的路径和方法在这里都是 404：关停、改日志级别、写配置、调试和性能分析接口、界面。出站路由不在这个监听上，回读路由也不在收业务请求的监听上。

这是让网关代理它自己的管理地址。上游文档没有把这写成一种用法；换版本时由 `P1-RB-03` 把关。

## 默认配置不安全的地方

下面八项**不配置就是不安全的**，都是跑出来的，不是读文档读出来的。"不处理时的默认行为"每次运行都在被测的这个二进制上重新观察：`run.py` 在跑用例之前，把评审过的配置去掉下面各项的处理，用它启动网关两次，一次不给会话密钥（第 6 项），一次给了密钥看它放过什么（其余各项），把看到的记在证据的 `agentgateway.start_without_session_key_rewrites_config_file` 和 `agentgateway.unmitigated_defaults` 里（各项后面括号里是对应的字段）。它们是观察值，不是检查项：换了版本后默认行为变了不算失败，但要回头看对应的处理是否仍然需要、是否仍然够用。处理之后的效果由用例检查。第 1、2 项最初是第一次运行的失败项；第 3、4 项是随后对照 G03 §5 把期望收紧才暴露的。现在的 `agentgateway.poc.yaml` 已逐项处理。

1. **Host 原样转发**（`host_header_the_provider_received`）。上游收到的是调用方发来的 `Host: egress-api.idp.test`。必须为每条路由配置 `urlRewrite.authority`。
2. **路径不做规范性检查**（`request_targets_on_the_route_without_a_pdp`）。`%252e%252e`（双重编码）、`%00`、`;x=1` 被原样转发到上游。现在由两层拦截：路由 `authorization` 规则只放行由非保留字符组成、段不以点开头的路径；`gateway-authz`（`internal/egressauthz/domain`）用同一条规则。无 PDP 的模式 C 路由证明了网关这一层单独有效。带 ExtAuthZ 的路由上 PDP 先被调用，这些请求是被 PDP 拒绝的。
3. **PDP 放行但没给凭证时，请求照样转发**（不带任何凭证；`pdp_allows_without_a_credential`）。现在在 backend 上加了 `authorization` 规则，没有 `Authorization` 头就由网关拒绝。
4. **Provider 的 `Location`、`Set-Cookie` 原样回给调用方**（`provider_answers_302_with_a_cookie`）。网关不跟随 302，但会把跳转目标和 Cookie 交给调用方。现在用 `responseHeaderModifier.remove` 去掉。
5. **调用方的 `Cookie`、`X-Forwarded-*`、`Forwarded` 原样传给 Provider**（`caller_headers_the_provider_received`）。现在用 `requestHeaderModifier.remove` 去掉。
6. **没有会话密钥时，网关启动会改写自己的配置文件**。`config.session.key` 未设置时，网关生成一个密钥并写回启动它的那个文件。第一次在 1.7.0 上运行时，仓库里受版本管理的 `agentgateway.poc.yaml` 就这样被加了三行（已还原，没有提交）。对按摘要审批、部署后回读对账的配置发布（G03）来说，这意味着运行中的文件不再是批准的那个文件，而且里面多了一个密钥。处理：用环境变量 `SESSION_KEY` 提供密钥，实测可阻止改写；`run.py` 另外只让网关从 `.run/` 下的副本启动，仓库里的文件它碰不到。`P1-CF-01` 检查网关运行时所用的文件与仓库里的逐字节一致；证据的 `start_without_session_key_rewrites_config_file` 记录了不提供密钥时的实际行为（`true`）。第 7 项的 `storage.mode: readOnly` 是第二道：有了它，即使没有密钥网关也不往文件里写（证据的 `start_without_session_key_rewrites_config_file_with_storage_read_only` 为 `false`，由 `P1-CF-02` 检查）；这时会话 ID 不加密，网关会记一条警告，所以密钥仍然要给。另外两个单独试过、不在证据文件里的观察：配置文件只读时网关只记一条警告然后照常启动；`session.key: disabled` 这个写法配置校验接受，本套件没有用它。
7. **管理接口能改运行中的配置，还会改写配置文件**（`write_through_the_admin_api`）。网关的管理地址上有一套给自带 UI 用的接口。默认的存储模式下，向它发一个 PUT（`/api/config/resources/...`）就能给运行中的配置加资源，网关还把改动写回启动它的那个文件。评审配置里管理地址只绑了回环，但本机任何进程都够得着；而 G03 要求运行配置只有发布器一个来源，G01 的 `GW-FR-046` 要求限制原生管理 UI 的写路径。处理：`config.storage.mode: readOnly`。同样的 PUT 得到 403，网关报告的运行配置（`/config_dump`）和文件都不变（`P1-CF-02`）。这一项和 `config` 段的其它设置一样，只在启动时读取。**`readOnly` 管的只是配置的写入**：设了它之后，向管理地址发 `POST /quitquitquit` 照样关停网关，`POST /logging?level=…` 照样改日志级别（单独试过，不在证据里）。上游的安全策略也写明管理接口不是一道面向不可信调用方的边界。所以管理地址只能留在回环上，不能为了回读把它开给别的机器；回读另走一个监听，见上面的"回读口"。
8. **收业务请求的监听默认开在本机所有网卡上**（`callers_listener_bound_to`）。不写 `bindAddress` 时端口监听的是 `*`，谁连得到这台机器，谁就能绕过前置组件直接连网关。处理：`bindAddress: 127.0.0.1`。监听只在回环上，从本机的另一个地址连它会被拒绝，前置组件成了别的机器进来的唯一入口（`P1-NL-01`）。管理、指标、就绪端口本来就绑在回环上；评审配置里唯一对外的端口是回读口。这个字段从 1.6.0 起就有（上游发布说明），本文件原先说"配置 Schema 没有监听器的绑定地址字段"，那是错的。

## 未解决

- **`P1-SS-04` FAIL：带两个 `Host` 头的请求被接受**（RFC 9112 §3.2 要求 400）。网关用第一个做路由，第二个不会到达上游；上游 `Host` 已被第 1 项改写，所以没有形成越权，但请求本身应当被拒。配置层面没有办法：配置 Schema 里没有相关开关；CEL 规则里也识别不出来，`request.headers["host"]` 取不到值，`request.host` 只反映第一个（这是单独试验的结果，不在证据文件里）。这个用例保留为 FAIL，因为它记录的是网关自身的行为。处置分两头：
  - **前置组件**。在网关前面放了一个 nginx 1.30.6（`front.nginx.conf`，监听 `127.0.0.1:27620`，转发到 `27611`）。经它发送时，两个 `Host`（顺序正反、两个相同、写请求）和没有 `Host` 的请求都由 nginx 自己答 400，网关日志里没有新增记录，PDP 和 Provider 什么也没收到（`P1-FP-01`）。另外三个用例确认加了这一跳之后原有性质不变：租户隔离、Provider 收到的头和请求体、401/403/404（`P1-FP-02`）；Provider 变慢或断连时写请求只到达一次，nginx 没有重放（`P1-FP-03`）；指定上游和路径变形仍然到不了 Provider，nginx 把路径原样交给网关，拒绝它们的仍是网关和 PDP，只有 `%00` 是 nginx 直接拒的（`P1-FP-04`）。**限制**：其余用例仍直接打网关端口。这个端口现在只绑回环（上面第 8 项），别的机器连不上它，只能经前置组件进来；同一台机器上的进程仍然可以直接连它。Kubernetes 上对应的做法是把前置组件和网关放在同一个 Pod 里，Pod 对外只有前置组件的端口，见 `tests/integration/kubernetes`。这里验证的是这一个 nginx 版本加这份配置，正式的入口组件要重新跑。
  - **上游**。在只有两条路由、没有任何策略的最小配置上单独复现过：网关按第一个 `Host` 路由，后端只收到第一个，第二个被丢弃；没有 `Host` 的请求网关会答 400。也就是说网关自己前后一致，风险出在它前面有一个按另一个 `Host` 做判断的组件时。报告在 `docs/upstream/UPSTREAM_REPORT_duplicate_host.md`，**已于 2026-11-11 提交，上游还没有答复**；agentgateway 的 `SECURITY.md` 要求拿不准是否属于安全问题时走私下报告，所以走的是私下渠道（公告 `GHSA-gccc-c8q8-cjmm`，只有报告方和上游维护者能打开）。
- **请求头是"删黑名单"而不是"放白名单"**。G03 §5 要求只传播 Provider 允许的头。本 PoC 只做到了按名字删除，调用方的任意自定义头（如 `X-Client-Trace`）仍会到达 Provider。
- **PDP 不可用与策略拒绝无法区分**。PDP 超时或不在时调用方得到 403，与正常拒绝相同；PDP 返回 500 时调用方得到 500。PDP 证书不被信任、网关自己的证书不被接受时同样是 403。G01 的失败来源区分（`GW-FR-043`）在这一点上没有满足。
- **mTLS 证明的是"谁在调用 PDP"，不是"调用方 Token 里写了什么"**。租户和服务身份仍然是网关转述的：PDP 相信它们，是因为对面是网关。网关被攻破等于这些声明可以伪造，这一点 mTLS 不改变。
- **规范路径规则很严**：不允许 `%`，所以路径段里不能有需要编码的字符。真实 Provider 的 Operation 如果需要，得按 Operation 单独登记放宽，不能全局放开。

## 没有覆盖

`gateway-authz` 跑的是验收构建，登记表和凭证来自为这次运行写的文件，撤销在内存里（没有真实身份源、授权库、Secret Manager、Provider 令牌端点），没有调用已部署的 Gatekeeper；Provider 是回环 Mock；本地 Broker 是 Mock，存储是一个 JSON 文件。mTLS 只在网关到 PDP、Broker 到 PDP 两段上是真的，CA 和证书每次运行临时生成：没有 SPIFFE Workload API，没有证书轮换和吊销；调用方到网关、网关到 Provider 是明文 HTTP。单进程，没有限流、负载；多副本和配置的滚动替换在 `tests/integration/kubernetes` 里，用的是一份没有 JWT 和 ExtAuthZ 的小配置。回读口只在这一个实例上、用为这次运行现做的发布器证书试过；这套用例里没有发布器，真的发布器（`cmd/gateway-control`）在 `tests/integration/compose` 里对着一份没有 JWT 和 ExtAuthZ 的小配置跑。没有 gRPC ExtAuthZ、决策缓存、CONNECT、gRPC 上游、HMAC 签名、对 Provider 的 mTLS；没有 DNS 重绑定和网络层出口 ACL。完整列表在证据文件的 `scope_limits`。

## 运行

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt   # 一次
.venv/bin/python tests/acceptance/blackbox/run.py                                   # 锁定的 agentgateway；约 30 秒；没有 FAIL 才返回 0
.venv/bin/python tests/acceptance/blackbox/run.py --agentgateway /path/to/agentgateway   # 锁定的那个二进制放在别处时
.venv/bin/python tests/acceptance/blackbox/run.py --check-evidence                  # 不运行；证据是不是当前这些文件跑出来的
```

需要 Go 工具链：脚本每次都用 `go build -tags acceptance` 把 `cmd/gateway-authz` 构建到 `.run/` 下再启动它。

只跑 `deploy/agentgateway/agentgateway.lock.json` 锁定的那个 agentgateway 构建：上游容器镜像里的二进制。第一次先运行 `.venv/bin/python tests/acceptance/blackbox/pin.py --fetch`，它按摘要拉镜像、取出二进制、核对后放到 `~/.local/opt/agentgateway/<版本>/agentgateway`。不带 `--agentgateway` 时先找这个路径，没有再找 `PATH` 上的 `agentgateway`；找到的二进制要与锁定文件里的版本、提交和 SHA-256 都一致，否则脚本拒绝运行（`pin.py`，`--agentgateway` 指定的也一样）。证据文件是 `evidence/p1-run-agentgateway-<版本>.json`，只有锁定版本的这一份。

脚本先检查端口段是否空闲、用 `--validate-only` 校验配置，再启动五个进程和一个 nginx 容器，跑完全部停掉。跑用例之前，网关还会被短暂地另外启动三次（见"默认配置不安全的地方"）：用去掉处理的配置启动两次，一次不给会话密钥，一次观察它放过什么；再用评审过的配置、不给会话密钥启动一次。三次都从 `.run/` 下的临时文件启动，观察完就停掉，用例不对着它们跑。nginx 需要本机有 docker：镜像是 nginx 官方的非特权版本，按摘要固定（见 `run.py` 的 `FRONT_IMAGE`），本地没有时会拉取一次；容器以非 root、只读根文件系统、不带任何 capability 运行，用宿主机网络，只监听回环。docker 或镜像不可用时脚本拒绝运行，不会跳过那四个用例。网关从 `tests/acceptance/blackbox/.run/` 下的配置副本启动，会话密钥经环境变量 `SESSION_KEY` 提供（原因见上面第 6 项）。每次运行生成新的 JWT 签名密钥、会话密钥、工作负载 CA 与证书、Mock 凭证，放在 `tests/acceptance/blackbox/.run/`（已忽略），不写入证据。

| 端口 | 用途 |
|---|---|
| 27611 | 网关收业务请求的监听（仅回环，见"默认配置不安全的地方"第 8 项） |
| 27612 | Mock Provider |
| 27613 | `gateway-authz`（TLS，要求客户端证书） |
| 27614 / 27615 / 27616 | 网关管理 / 指标 / 就绪（仅回环） |
| 27617 | "禁止目标"：任何路由都不该到达，用来证明没有越权出站 |
| 27618 | Mock 本地 Broker（模式 B） |
| 27619 | 网关的回读口（TLS，要求发布器的客户端证书；所有网卡） |
| 27620 | 前置 nginx（仅回环），转发到 27611 |

`27610` 由 `deploy/agentgateway/agentgateway.local.example.yaml` 使用。`tests/integration/kubernetes` 在发布前做离线加载时也临时占用本机的 `27619`，`tests/integration/compose` 占用 `27618`–`27620`，它们都不能和这套用例同时跑。

端口段选在 `27610-27622`，是因为它低于内核给出站连接分配源端口的临时端口范围（本机为 44620–48715，Linux 默认 32768–60999）。最初用的是 `47611-47617`，落在本机临时范围内：有一次运行中网关绑定就绪端口 47616 时报 `Address in use`、整轮没跑起来，而该端口在运行前后都是空闲的。占用者没有被直接抓到，最可能的解释是某个出站连接临时拿它做了源端口。脚本现在会在端口段与临时范围重叠时拒绝启动。

## 文件

- `agentgateway.poc.yaml`：原生配置。五条出站路由（两条模式 A，一条模式 B，一条模式 C，一条用 `key.expression` 的模式 A），外加回读口和它的一条路由。
- `pin.py`：按 `deploy/agentgateway/agentgateway.lock.json` 找到并核对 agentgateway 二进制，`--fetch` 时从锁定的镜像里把它取出来；联调套件（`tests/integration/gatekeeper/`）和 Kubernetes 套件（`tests/integration/kubernetes/`）也用它。
- PDP 不在这个目录里：是仓库根下的 `cmd/gateway-authz`，双向 TLS，按客户端证书里的身份决定谁能调哪个端点；实现了 `contracts/gatekeeper/openapi.yaml` 的 `/v1/extauthz/check`（模式 A）和 `/v1/egress/authorizations/decision`（模式 B）。本套件用的控制接口在 `cmd/gateway-authz/hooks_on.go`，只有带 `acceptance` 标签的构建里才有。
- `mock_broker.py`：Mock 本地 Broker。`pki.py`：每次运行的 CA、证书和 TLS 连接。
- `mock_provider.py`：记录收到的每个请求；`policy.poc.json`：两租户两账户的授权数据。
- `front.nginx.conf`：前置 nginx 的配置。给 agentgateway 上游的报告（英文，含最小复现）在 `docs/upstream/`。
- `run.py`：用例与期望。`evidence/p1-run-agentgateway-<版本>.json`：最近一次运行的逐项检查与观察值，含二进制、锁定文件与配置的 SHA-256。

## 期望是怎么定的

期望取自 G01/G03/G04，写在 `run.py` 里，不达标记 FAIL，不改期望迁就结果。运行历史：

1. 第一次运行 37/39。失败的是 Host 转发和路径绕过（上面第 1、2 项），据此改了网关配置和 PDP 参考实现。
2. 随后对照 G03 §5 **收紧**了三处期望（无凭证时必须由网关拒绝、`Location` 不得回给调用方、`X-Forwarded-*` 不得传给 Provider），并新增 `P1-SS-04`。收紧后暴露出第 3、4 项和重复 `Host` 的问题；第 5 项的处理与检查是同时加上的。
3. 在 1.6.0 上定格为 39/40。
4. 把同一份配置和同一套用例原样拿到 1.7.0 上：同样是 39/40，失败的同样是 `P1-SS-04`。这次运行暴露了第 6 项，据此新增 `P1-CF-01`，并把网关改为从副本启动、经环境变量拿会话密钥。
5. 两个版本定格为 40/41。
6. 网关到 PDP 的共享密钥换成双向 TLS，`P1-AZ-11`、`P1-CR-03` 的期望随之收紧（原来查"没有密钥就 401"，现在查"没有证书连不上，证书身份不是网关就 401"），新增 `P1-TL-01`、`P1-CR-04`；加入模式 B（`P1-MB-01..04`）和 `key.expression` 路由（`P1-KX-01..03`）。新增的 9 个用例在 `run.py` 里第一次运行就全部通过；在此之前，mTLS 和 `key.expression` 的配置写法已经在单独的试验里试过。当时 1.7.0 为 49/50，1.6.0 为 46/47 加 3 个 SKIP。
7. 为 `P1-SS-04` 加了前置 nginx 和 `P1-FP-01..04`。`P1-SS-04` 本身没有动，仍然 FAIL。新增的 4 个用例第一次运行就通过；之后只给 `P1-FP-01` 加了一条对照检查（单个 `Host` 的请求确实会在网关日志里留下记录），用来说明"网关日志没有新增"这条检查不是空的。当前 1.7.0 为 53/54，1.6.0 为 50/51 加 3 个 SKIP。

8. PDP 从 Python Mock 换成本仓库的 `gateway-authz`（Go，验收构建）。网关配置里只改了注释，用例和期望没有动。换完第一次运行 37/54：`run.py` 直接调 PDP 时从来不发 `Host` 头，Python Mock 不在乎，Go 的 HTTP 服务端按 RFC 9112 §3.2 答 400，于是控制接口全部失效，靠它们注入故障和读取记录的用例跟着失败。改的是 `run.py` 的客户端（补上 `Host` 头），不是期望。之后两个版本的结果与换之前逐项相同：1.7.0 的 282 项检查、1.6.0 的 260 项检查，没有一项变化。一个不在检查里的差别：网关到 `gateway-authz` 协商出的是 HTTP/2，到 Python Mock 时是 HTTP/1.1（证据的 `gateway_authz.http_versions_seen_from_the_gateway`）。
9. `gateway-authz` 加了可选的一步：登记表放行之后再向 Gatekeeper 的 PDP 确认账户授权。黑盒套件不启用它（不带 `--gatekeeper-url`），`run.py`、配置和期望都没有动；因为服务的源码变了，两个版本各重跑一次，逐项结果与上一份证据相同。启用这一步时的表现在 `tests/integration/gatekeeper/` 里测。
10. 目标版本只留一个：agentgateway 锁定为 1.7.0（`deploy/agentgateway/agentgateway.lock.json`），1.6.0 不再测，它的证据文件已从目录里删除（git 历史里还有）。`run.py` 启动网关前按锁定文件核对二进制。原先单独放着、只有 1.7.0 接受的 `key.expression` 路由并进了 `agentgateway.poc.yaml`，"二进制不接受就记 SKIP"的分支随之去掉。用例和期望没有动。重跑后仍是 53/54，282 项检查的结果与上一份 1.7.0 证据逐项相同。
11. 前五项默认行为改为每次运行都观察并记进证据（`agentgateway.unmitigated_defaults`），不再靠 PoC 早期在 1.6.0 上的观察；在 1.7.0 上五项都与原先的描述一致。为了能观察到第 4 项里的 Cookie，Mock Provider 的 302 响应加了 `Set-Cookie`。`P1-SS-02` 的期望原文本来就写着不把 Provider 的 Cookie 交给调用方，但此前 Mock 不发 Cookie，这半句没有被检查到；现在补了一条检查（`Set-Cookie not passed to the caller`）。其余用例和期望没有动。重跑后仍是 53/54；除新增的这一条外，282 项检查的结果与上一份证据逐项相同。
12. 检查网关自带的管理接口时发现：默认的存储模式下，对它发一个 PUT 就能改运行中的配置，网关还把改动写回配置文件。评审配置加了 `config.storage.mode: readOnly`，新增 `P1-CF-02`（写入被拒绝，运行中的配置和文件都不变，没有会话密钥时网关也不往文件里写）。这成了"默认配置不安全的地方"第 7 项，默认行为同样每次运行都观察；第 6 项的默认行为相应改在去掉处理的配置上观察。其余用例和期望没有动。重跑后是 54/55；除新增的这个用例外，283 项检查的结果与上一份证据逐项相同。
13. 新增 `P1-RB-01/02`：在被测的网关上把配置文件换成多一条路由的版本、再换成一份加载不了的版本，每次都换回评审过的那份，检查网关怎么报告、实际在用的是哪一份。两个用例第一次运行就通过。此前这些只单独试过一次。其余用例和期望没有动。重跑后是 56/57；除新增的两个用例外，290 项检查的结果与上一份证据逐项相同。
14. 复核 ADR-0010 时改了三处。其一，被测的二进制换了：锁定的对象从发布页上的独立二进制改成上游容器镜像里的那一个（两者是同一个提交的两个构建），因为要部署的是镜像。其二，评审配置给收业务请求的监听加了 `bindAddress`（"默认配置不安全的地方"第 8 项），新增 `P1-NL-01`，默认行为的观察里多了一项。其三，评审配置加了回读口，新增 `P1-RB-03`。两个新用例第一次运行就通过；回读口的写法事先在单独的试验里试过。其余用例和期望没有动。重跑后是 58/59；除新增的两个用例外，307 项检查的结果与上一份证据逐项相同，而上一份证据是在另一个构建上跑的。不做处理时的默认行为，除新增的那一项外，两个构建上也相同。
15. `gateway-authz` 的 Gatekeeper 适配器改成按 PDP 应答里的 `indeterminate` 字段区分"没查成"和拒绝（见 `tests/integration/gatekeeper/README.md` 第 3 点）。黑盒套件不启用这一步，`run.py`、配置和期望都没有动；因为服务的源码变了，重跑一次：仍是 58/59，326 项检查的结果与上一份证据逐项相同。
16. 仓库里多了控制面的命令 `cmd/gateway-control` 和它的上下文 `internal/gatewayconfig`；`internal/platform/workloadtls` 加了客户端一侧的 TLS 配置，`gateway-authz` 用的服务端一侧行为没有变。证据的源码哈希覆盖 `cmd/` 和 `internal/` 下所有非测试的 Go 文件，所以重跑一次。`run.py`、配置和期望都没有动：仍是 58/59，326 项检查的结果与上一份证据逐项相同。
17. `gateway-control` 多了 `reconcile` 和 `restart` 两条命令，`internal/gatewayconfig` 跟着多了记录和重启网关容器的部分；`gateway-authz` 自己的代码没有动。证据的源码哈希覆盖 `cmd/` 和 `internal/` 下所有非测试的 Go 文件，所以重跑一次。`run.py`、配置和期望都没有动：仍是 58/59，326 项检查的结果与上一份证据逐项相同。
18. `gateway-control` 多了第四条命令 `place`（网关启动之前把记录的那一份配置放到位），是随单机的部署文件 `deploy/compose` 一起加的；`gateway-authz` 自己的代码没有动。证据的源码哈希覆盖 `cmd/` 和 `internal/` 下所有非测试的 Go 文件，所以重跑一次。`run.py`、配置和期望都没有动：仍是 58/59，326 项检查的结果与上一份证据逐项相同。

没有任何期望被放宽过。

第 8 条和第 10 至 15 条里的检查数在 2026-11-11 更正过。原先写的数比证据文件里的少：1.7.0 的每个都少 9，1.6.0 的少 6（原先依次写的是 273 和 254、273、273、274、281、298、317）。更正时把 git 历史里的每一份证据重新数了一遍，各次"逐项相同"的比较也重新做了一遍，结论没有变。那几次提交的说明里写的仍是原先的数。

证据记着它跑的时候的锁定文件、配置、策略、Mock、前置 nginx 配置、`run.py`、`pin.py` 和 `gateway-authz` 源码的哈希。`run.py --check-evidence` 把它们和仓库当前文件比一遍；有不一致的就要重跑。顺序是先提交代码，再从干净的工作区跑，最后单独提交证据，这样证据里的 `repository_commit` 指向的就是被测的那份代码。
