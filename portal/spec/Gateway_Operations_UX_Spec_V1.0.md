# IDP Gateway Operations — UI/UX 设计规格 V1.0

> **定位**：IDP Internal Engineering Portal 中的 Gateway Operations **模块**，不是新增独立 Gateway Portal。
> **现状**：`../prototypes/gateway-operations.html` 为零依赖离线交互 **Mock**；没有接入 agentgateway、Gatekeeper、API Fabric 或第三方真实 API。页面中所有 KPI、配置、Trace、凭证引用、实例健康及审批结果均是模拟。
> **设计遵循**：IDP-SCG-STD-001 V1.0：CORE + 能力触发的 PROFILE + TECH；专业体验 STD-CP4，工程质量 STD-CP5、正式发布 STD-CP6。待具名责任人审定。

## 1. 角色、信息架构与边界

**入口**：IDP 内部工程门户 / Gateway Operations（单一导航入口）。

| 页面 | 核心目标 | 权威数据系统 | 默认权限 |
|---|---|---|---|
| 01 Dashboard | 请求量、成功率、P95/P99、策略拒绝、实例健康、待审发布 | Telemetry / Gateway / Gateway Publication 投影 | gateway.read |
| 02 API Routes | 检索 Ingress/Egress/AI 路由，查看上游/配置版本/归属 | Gateway 配置投影 + Fabric 契约目录 | gateway.route.read |
| 03 Access Policies | 查看服务身份、租户、操作、外部账户授权及有效期 | Gatekeeper 权威策略，Portal 只读投影 | gateway.policy.read |
| 04 Traffic Explorer | Trace 检索、响应分类、失败阶段定位、脱敏导出 | OpenTelemetry / 可观测后端 | gateway.trace.read |
| 05 Config Releases | 版本差异、审批结果、发布状态、回读、回滚与审计 | Fabric 发布治理 + Gateway 配置状态机 | gateway.release.read |
| 06 Gateway Instances | Ingress/Egress/AI 实例池、可用区、容量、故障响应 | Gateway Runtime / orchestrator / Telemetry | gateway.instance.read |

**严格禁止**：由 Gateway Operations 管理生产第三方账户 Secret 明文、直接绕过 Gatekeeper 修改权限、直接绕过 Fabric/网关发布工作流下发任意路由、任意URL开放代理、展示未经脱敏的请求/响应正文。

## 2. 角色及操作矩阵（需 Gatekeeper 权威授权）

| 操作 | Viewer | Engineer | Security Reviewer | Operator |
|---|---|---|---|---|
| 查看 Dashboard / Route / Policy / Trace（可按租户/产品过滤） | 按范围 | 按范围 | 按范围 | 按范围 |
| 查看配置差异 | 可 | 可 | 可 | 可 |
| 提交路由草稿、配置候选 | 否 | 是 | 否 | 否 |
| 批准高风险配置 | 否 | 否 | 是 | 否 |
| 部署已批准配置 | 否 | 否 | 否 | 是 |
| 回滚受控版本 | 否 | 否 | 否 | 是 |
| 获取第三方密钥或令牌明文 | **所有角色禁止** | **禁止** | **禁止** | **禁止** |

**生产规则**：真实服务端必须执行 RBAC/ABAC + 租户与数据域范围校验；前端按钮显隐只是体验提示，不是安全边界。高风险配置采用职责分离，批准者与部署者不得通过同一身份任意绕过。

## 3. 六个核心管理视图的关键交互、反馈与空状态（统一 Console 共 18 个主导航）

### UX-01 Dashboard
- 四项关键指标（请求量、成功率、P95、策略拒绝）并显示时间窗、环境、数据采集来源、延迟/新鲜度。P99 和错误预算应进入正式后端字段；原型只展示部分指标。
- 可跳转到错误 Trace、告警详情、实例池、最近配置版本。监控数据不存在时显示 `Data unavailable`，不得伪装成 0 或 Healthy。

### UX-02 API Routes
- 全文检索 + Traffic Domain (Ingress/Egress/AI) + Status 过滤，Route ID 主键、协议、允许 Method/Path、Upstream、Env、Version、Risk、Owner。
- 点击行展开只读详情；新建只能提交 RouteIntent DRAFT；禁止填任意目标 URL。未审批路由不得生产生效。
- 上游地址应避免泄露内部敏感拓扑给无权限人员。第三方账户只显示 CredentialRef，不显示凭证内容。

### UX-03 Access Policies
- 基于 Gatekeeper 权威服务身份 × 租户 × API Operation × External Account 展示允许/拒绝，支持策略版本、失效期限与缓存 TTL。
- 刷新/授权失败时不能保留“允许”假象；可展示明确的 `Decision unavailable / deny by default` 状态。
- 不允许在此界面建立新的外部账户授权；应链接 Gatekeeper 授权流程。

### UX-04 Traffic Explorer
- Trace ID、Route ID、Tenant（仅有权范围）、Status、Latency、决策类型、上游错误分类。
- 强制移除 Bearer Token、API Key、Cookie、Secret、请求体中的个人数据；默认按最小需要展示。对复杂敏感数据应在服务端脱敏，不能仅依靠 UI 隐藏。
- 对写操作 504 不得展示为业务失败；正确的领域结果状态为 `UNKNOWN / Needs Reconciliation`。

### UX-05 Config Releases
- 明确区分 `DRAFT → VALIDATED → REVIEW → APPROVED → ROLLOUT → RECONCILED (ACTIVE)`、`FAILED/REVERTED/SUPERSEDED`；不可将点击“部署”直接等同于真实生效。
- 实际对账应显示 expected/observed digest、每实例 revision、回读结果、策略生效时刻和回滚证据；仅 Gateway 物理实例确认才可标识 Active。
- 高风险发布必须具有安全审批、预检、分批执行、回滚预案和独立审计。Demo 仅模拟批准/部署/回滚按钮及角色；不实现真实状态机。

### UX-06 Gateway Instances
- Ingress/Egress/AI 使用不同实例池和安全域。应显示 Availability、SLO、P95/P99、容量与实例健康。
- 实例健康不等于提供商可用；上游故障与 Gatekeeper 故障须分别分类。
- 故障模拟在原型里只修改本地数组，绝不对生产实例发起管理动作。

## 4. 前后端接口边界（提案，不是现存 API）

| API BFF/Read Model（候选） | 用途 | 权威来源 |
|---|---|---|
| `GET /operations/overview?environment=` | 聚合 KPI/告警，返回 data_freshness | Telemetry + Gateway |
| `GET /operations/routes`、`GET /operations/routes/{id}` | Route 查询/详情 | Gateway 配置投影 |
| `GET /operations/policies` | 权限投影；仅授权数据域 | Gatekeeper |
| `GET /operations/traces` | 服务端脱敏 Trace | Telemetry Backend |
| `GET /operations/releases`、`GET /operations/releases/{id}` | 发布快照、差异与各实例状态 | Fabric 发布 / Gateway Reconciler |
| `POST /operations/release-intents` | 创建候选；需服务端授权 | API Fabric 集成入口 |
| `POST /operations/releases/{id}:approve` | 安全复核；需服务端授权 | Fabric 权威审批流程 |
| `POST /operations/releases/{id}:deploy` | 部署；需服务端授权、乐观锁和幂等键 | Gateway Config Controller |
| `POST /operations/releases/{id}:rollback` | 回滚；需审批和审计 | Gateway Config Controller |
| `GET /operations/instances` | 实例、池、故障域 | Gateway Runtime |

候选路径只为接口分工示意，不属于已正式发布的 OpenAPI 契约。跨系统不可绕过 Gatekeeper/Fabric 的领域权威。高风险写 API 必须采用 `If-Match`/版本前置条件与 `Idempotency-Key`，明确错误码与审计关联。

## 5. 状态与可访问性

- 展示 loading / empty / error / permission denied / stale / partial failure 六类数据状态；特别区分 `NOT_RUN`、`PENDING_APPROVAL` 和 `ACTIVE`。
- 所有交互元素提供可见焦点、键盘可达和语义标签。正式实施须达到 WCAG 2.2 AA 可访问性验收；当前原型不宣称已经满足全部 WCAG。
- 1400px 桌面优先；小屏视图应具备表格横向滚动、导航堆叠；不得隐藏审批结果和风险信息。
- 时间采用环境所在操作时区且明确时区；数据展示应提供最后刷新时间、采集窗口。Mock 中时间仅示例。
- 设计语言：中性浅底、信息密度适中、状态色必须配文字和形状，禁止只用颜色区分授权。

## 6. 原型操作与可测行为

1. 使用 `../prototypes/gateway-operations.html` 在浏览器中离线打开。
2. 左侧导航切换 18 个主页面；顶部切换环境（Production/Staging）和演示角色。
3. Routes 可检索、筛选、查看详情；Policies 显示 Gatekeeper 决策投影；Trace 查看脱敏时间线。
4. Releases 中选择 Security Reviewer 批准 CFG-1843，再切换 Operator 模拟部署/回滚。Viewer 无法操作。
5. Instances 可以模拟降级与恢复；可重置本地状态。
6. 所有统计、权限和发布状态都保存在当前浏览器内存，不调用真实接口；刷新页面清空操作记录。

## 7. 验收与证据

见 `../../tests/ux/acceptance_matrix.csv`：UI-AT-001 起的 UX 场景均为 **NOT_RUN**（正式用户/安全验收）。原型浏览器交互的自动化测试若实际成功，记录在 `../../tests/evidence/ux-prototype-browser-tests.txt`，只证明 Mock 交互正常，不能证明真实 Gateway 集成或生产授权正确。

## 8. 仍需冻结的决定

- Gateway Operations 最终是 Fabric 工程门户中的菜单模块，还是统一 Engineering Shell 的远程微前端：优先模块，不新建门户产品。
- BFF API 命名、服务端分页、部署 Provider (file/Git/K8s) 的更新行为由真实集成 PoC 锁定。
- Gatekeeper 现有权限模型的正式操作码与审计字段待核定，不能让 UI 成为第二个授权权威。

## 同版增补：统一管理体验的功能范围

当前原型由六个运维页面扩展为 **18 个导航页面**，并以子页签覆盖 agentgateway 的 Traffic/Gateway、LLM、MCP、Tools 能力，同时加入 IDP 的第三方 API 接入向导、租户与外部账户权限投影、A2A 可信 Agent 目录。具体逐项映射参见 [Agentgateway UI Capability Matrix](Agentgateway_UI_Capability_Matrix_V1.0.md)。本次仅是 Mock UI；对原生接口的适配、真实配置发布、Secret 保护和权限执行仍为 `NOT_RUN`。


## 同版增补：Message Inspector / 报文诊断器（V1.0）

**现状**：`Traffic Explorer → 选择 Trace` 已有四阶段 HTTP 报文的零依赖离线 Mock：01 应用入站、02 Gateway 外发、03 第三方响应、04 Gateway 返回；可展开脱敏 Header / Body，并展示 401/403/429 未转发、504 结果未知、502 上游错误等示例。**这不代表真实 agentgateway 具备四点完整报文持久化，也不代表真实脱敏和租户授权已经执行。**

**正式设计原则**：

1. `gateway.trace.read` 仅授予脱敏元数据读取，不自动包含报文体。报文体应单独授予 `gateway.message.read_sanitized`，且由服务端针对租户、数据分级、关联业务和操作者目的授权。生产中的 Viewer 默认无 Body 查看权限；前端隐藏不等于服务端保护。
2. 只在必要时选择性捕获、采样或临时开启报文诊断（具有指定 Route、Tenant、时间窗口、过期时间和审批）；**默认不存储请求/响应完整 Body**，保留必要的调用元数据、Trace ID、策略判定、上游 Request ID、错误码与延迟。
3. 在**进入日志存储/导出之前**按字段级规则移除或脱敏 OAuth/JWT/API Key、Cookie、地址、姓名、电话、Email、支付、清关申报以及其他受保护字段。禁止在明文数据先进入日志库之后才靠 UI 隐藏。不得无约束地收集 `request.body`/`response.body` 或 prompt；负载必须受大小、类型和保留期限限制。
4. 访问日志元数据、请求入站视图和客户端返回视图可利用 agentgateway 原生观测能力；**Gateway 完成认证注入、路径重写之后的精确外发报文**，以及**上游响应和最终客户端响应间的精确差异**，若仅靠现有日志无法证明，须通过经验证的处理链、受控 ExtProc 或专用诊断适配器补足，不能假定可自动还原。
5. 对 gRPC 展示 Service/Method、Metadata（脱敏）、Status、Trailer、大小与时间线；Protobuf 内容仅在授权、Schema 可解析且数据分级允许时解码，不默认把二进制正文当 UTF-8。Streaming 默认仅保留元数据和有限样本。
6. 业务错误诊断须区分 `401 JWT`、`403 Gatekeeper AccountGrant`、`429 Gateway/Provider`、`502 Upstream`、`504 UNKNOWN`、DNS/TLS、Connector 业务错误；504 写操作明确提示查询/对账，**禁止一键重放非幂等请求**。
7. 报文访问、导出、临时捕获启停均为高风险受审计操作。原型目前仅有合成数据的脱敏 JSON 导出，真实服务端签名、授权、访问审计及防泄露测试均为 `NOT_RUN`。
8. 统一 `trace_id`、`request_id`、`gateway_route_id`、`provider_request_id`、`tenant_id`、`provider_account_ref`（仅脱敏引用）、`config_revision` 和时间戳，诊断界面必须明确呈现某一阶段 `NOT_SENT`、`NOT_OBSERVED`、`TRUNCATED`、`NOT_CAPTURED`，不能伪造未捕获的报文。

**拟增加的只读接口（非已实现）**：`GET /operations/traces/{trace_id}/messages` 与 `GET /operations/traces/{trace_id}/diagnosis`。其中 messages 接口须强制范围授权、字段脱敏、大小限制与访问审计；优先返回状态与分级可见证据，不直接返回未经处理的代理原始字节。

**参考技术**：agentgateway 官方 Access Logs / CEL Body variables / ExtProc / agctl tracing。官方确认使用 `request.body` 和 `response.body` 可能触发缓冲或截断；具体性能、异常与数据泄露风险必须在选定版本进行 PoC 验证。


## 本版整改：Traffic Governance 与真实数据验证边界

- Traffic Explorer 已增加同页的 `Traffic Governance` 面板：ProviderAccount Quotas、Upstream Health、Config Reconciliation 三项合成数据卡片与只读 Drill-down。**不可视为真实限流/熔断/回读功能**。
- 正式 BFF 需分别读取 Gateway Metrics、Quota Coordinator、Provider 响应、Config Reconciler 的权威投影；必须展示数据来源、新鲜度、环境、影响租户及配置版本。
- UI 只展示**业务意图与生效证据**，不能凭点击按钮直接改写 Agentgateway 原生配置；发布审批与账户授权分别遵守 Fabric 与 Gatekeeper 的权威。
- `GW-UX-063..071` 验收包括账户配额、429 来源、熔断健康、Config Drift、Capture Grant、服务端 ABAC 和静态预检不等于已部署等事项，全部 `NOT_RUN`。
- 需要在真实环境通过权限/性能/安全验收才能清除所有 MOCK 标记。


## Message Inspector — 双链路 Request / Response 配对布局

采用两行 × 两列的语义布局，避免孤立的“03 上游 → Gateway”导致误读：

| 通信链路 | Request（左列） | Response（右列） |
|---|---|---|
| Hop A：应用 ↔ Gateway | 01 · 应用 → Gateway，Method/Target/Headers/Body | 04 · Gateway → 应用，Status/Headers/Body |
| Hop B：Gateway ↔ 上游 | 02 · Gateway → 第三方，实际外发 Target/脱敏 Header/Body | 03 · 第三方 → Gateway，实际接收状态/Headers/Body |

界面还应呈现**请求转换对比**与**响应映射对比**，单独展示按时间顺序的四阶段执行时间线。业务写操作上游超时仅代表响应未观测，结果必须显示 `UNKNOWN`，不可把 Gateway 生成的 504 混淆成提供商返回的 504。

每个面板应有状态行、Header、Body 以及缺失/截断/权限受限标识。正常请求可展开双面板、对比请求重写；403 需显示没有外发请求而有 Gateway 拒绝响应；504 需显示已外发、上游响应缺失、Gateway 504。Body 永不默认采集；前端 Mock 的角色切换不等于生产 ABAC。

候选只读接口：`GET /operations/traces/{traceId}/messages?view=paired`；应由经过 Gatekeeper 授权的诊断 BFF 返回已脱敏的数据结构，包含四个观测点、证据状态、配置摘要与关联 ID，而不是直接通过浏览器访问代理内存或秘密材料。此路径只是一份接口设计，不是已实现的 API。
