# G05 — Go 工程实施、运维、可靠性与质量基线

> **编号** G05 · Engineering & Operations · **版本** V1.0 · **状态** DESIGN_DRAFT / 真实运行 NOT_RUN  
> 上位标准：IDP-SCG-STD-001 V1.0，CORE + TECH + GO 候选适用，是否启用 BENTO_GO/AI 需正式 Manifest 及能力触发评估。**不将 data plane 的 Rust 实现视为自行研发的 Go 领域模块。**

## 0. 工程原则

**Build**：业务专属 Gateway Control Adapter、Gatekeeper ExtAuthZ Adapter、Credential Broker、Snapshot Publisher/Reconciler、监控与审计集成。  
**Reuse**：agentgateway 受控版本的稳定代理、JWT、TLS、路由、限流、观测能力及已有部署工具；成熟 Secret Manager、OpenTelemetry、Git/CI。  
**Do not build**：第二套 Go 反向代理内核、公共 BIP、万能 Header 改写 DSL、和 Fabric 重叠的 API Catalog/开发者门户。

Go Control 代码应符合 `idp-bento-go` 仓库现行可验证版本的真实接口；当前**未锁定**确切 Bento-Go 发布/Commit，故下述包结构仅为建议，不冒称已经适配现有基座。

## 1. 候选 Go 目录与依赖方向

```text
cmd/gateway-controller/main.go
cmd/gateway-reconciler/main.go
internal/gatewayconfig/domain/            # Snapshot、RouteIntent 状态、发布不变量
internal/gatewayconfig/application/       # ApproveIntent、StageSnapshot、Reconcile
internal/gatewayconfig/ports/             # FabricPublisher、GatewayRuntime、Audit、Clock
internal/gatewayconfig/adapters/agentgw/  # agentgateway 配置、状态、回滚适配
internal/gatewayconfig/adapters/fabric/   # 受控发布输入，不能读取 Fabric DB 私表
internal/gatewayconfig/adapters/storage/  # PostgreSQL、不可变制品、Outbox
internal/gatewayconfig/adapters/telemetry/
internal/authzbridge/                    # Gatekeeper ↔ Envoy/HTTP ExtAuthZ 适配
pkg/contract/                            # 仅公共 API/配置 Schema，不放业务模型
```

**依赖规则**：`domain` 不导入 agentgateway SDK、PostgreSQL、HTTP client；`application` 只经 Port 编排；`adapters` 负责网络和存储；不允许 Fabric、Gatekeeper 通过共享数据库跨边界读写。即便未来控制器独立部署，也不能将 REST 传输 DTO 直接当聚合状态。

## 2. 关键用例与一致性实现

| Use Case | 请求 | 原子事实 | 外部副作用 | 恢复 |
|---|---|---|---|---|
| `CreateRouteIntent` | Fabric 批准意图 | 登记新命令及幂等键 | 无 | 重发幂等 |
| `ValidateSnapshot` | Intent + 受控策略 | 静态检查结果和内容摘要 | 可调用官方 schema/校验器 | 失败不可推进 |
| `PublishSnapshot` | 期望版本 CAS | Desired Generation 及 Outbox | Agentgateway 按池应用 | 重试 + Observed Reconcile |
| `PromoteCanary` | canary 健康证据 | 批次审批 | 调整实例池配置/流量 | 失败回滚 |
| `RevokePolicy` | Gatekeeper 高优先变更 | 防护动作与审计 | 请求拒绝/配置变更/缓存失效 | 直至回读有效 |
| `ReconcileRuntime` | 所有实例状态 | 记录 Observed | 不改动业务 API Release | 漂移报警与恢复 |

Publisher 和 Reconciler 可以通过 PostgreSQL Outbox + 独立 Worker 实现，前提是正式选择和验证；本阶段不新增 Kafka/NATS 作为架构必选。异步发布使用至少一次尝试、幂等 Key、事务性状态变更与实测对账，不承诺外部系统的 Exactly Once。

## 3. 配置、制品及发布流水线

**CI**：Source → 源码/依赖扫描 → Schema/契约检查 → 静态授权负向检查 → Route/Policy 编译 → agentgateway 官方版本 CLI Schema/启动检查 → 临时环境 HTTP/ExtAuthZ PoC → 签名/摘要 → 人工或受控签核。  
**CD**：批准 Snapshot → 灰度池 → 运行观察 → 扩容分批 → 校验每实例摘要和健康 → 标 ACTIVE → 持续对账。任何真实运行测试没完成时，阶段证据不得标 PASS。

`tests/evidence/` 只存真实测试证明或清楚标注的样例，不允许为了通过门禁编造日志、时间或性能数字；`scripts/validate_baseline.py` 是**离线文档与示例检查器**，不是 agentgateway 配置验收器。

## 4. 可观测性体系

| 信号 | 建议维度 | 禁止/注意 |
|---|---|---|
| Gateway Request Metrics | pool, env, route_id, operation_id, HTTP status, upstream | 不将 account_id、token、用户 ID 作为 Prometheus 高基数标签 |
| AuthZ Decision | service, tenant_hash, policy_version, allow/deny/indeterminate | 不记录令牌原文；不要在普通 Span 加秘密 |
| Provider Call | provider_id, operation_id, response_class, duration | 第三方错误码必须与 Gateway 错误码分类区分 |
| Configuration | desired/observed digest, instance status, rollback duration | 聚合成功率不掩盖少数副本漂移 |
| Token Broker | cache hit, refresh latency, denied grant, revocation lag | 不暴露 Access Token、Refresh Token、签名密钥 |

统一 `traceparent` 与 `x-idp-request-id`，请求 ID 不替代可校验的 JWT；对外 Header 的身份与追踪内容按信任域清洗。采样策略不能抹除关键安全审计事件。

## 5. 容量与性能验证设计

比较三个基线：**Direct → Provider Mock**、**Gateway L7（只代理）→ Mock**、**Gateway L7（JWT+ExtAuthZ+Credential）→ Mock**。所有测量在同一上游延迟分布、同网络/硬件/连接池配置下进行，报告 p50/p95/p99、吞吐、CPU、内存、连接数、错误分类、Token Broker 刷新峰值。包含以下工作负载：

- A. 读接口小 JSON（Tracking/Rate Quote），读写比例可调。
- B. 大文件与高并发流（label PDF、manifest），检查 Body 流式行为及限制。
- C. 写操作（创建面单/订舱 Mock），严格禁止代理重放。
- D. gRPC unary 和 streaming，检验消息顺序、Metadata、deadline、status。
- E. 故障状态：Broker 抖动、DNS 失败、提供商 429、半开连接、进程关闭、网关池滚动升级。

**阈值治理**：基于生产使用量、第三方 SLA、业务端到端超时预算确定绝对/相对延迟与可用性阈值；当前所有数值仅作测量计划。没有真实负载数据就不要宣称“网关性能比直连更好”。

## 6. 故障策略、运行手册与故障隔离

**不同池**：Public Ingress、Internal Egress、AI Gateway 独立镜像/Secret/NetworkPolicy/审计和扩缩容；共享的是版本化策略及工具链而非全部实例。对于供货商按区域和数据等级继续拆分。实现统一地址时，通过内部服务发现解析到正确入口池，不把域名高可用理解为单进程高可用。

**Runbook 编号**：

| Runbook | 触发 | 首个处置 | 恢复证据 |
|---|---|---|---|
| RB-01 | AuthZ 5xx/超时激增 | 高风险请求拒绝，调查 Gatekeeper/链路 | PDP 恢复 + 负向授权通过 |
| RB-02 | Token Refresh/Secret 错误 | 冻结相关 Provider Account，防止级联重试 | Token 源状态与正确账户签发 |
| RB-03 | Config drift | 停止扩大发布，核查 Snapshot SHA | 所有目标实例一致/故障实例隔离 |
| RB-04 | Provider 429/5xx | 遵循 Provider Retry-After 和领域重试策略 | 流量恢复，不重放写操作 |
| RB-05 | SSRF/任意代理嫌疑 | 立刻阻断有关路由与凭证授权 | 网络阻断、审计追溯、修复验证 |
| RB-06 | Gateway pool 不可用 | 受控区域切换/回退；高风险未授权拒绝 | 故障域隔离及流量指标恢复 |
| RB-07 | 证书/密钥轮换失败 | 停止新发布，回退到安全受控密钥版本 | 双端信任验证、旧版本撤销 |

## 7. 安全供给链、技术版本与运维

推荐从 agentgateway **官方 1.7.x 支持线**选定具体版本，但必须验证源码/镜像来源、许可证、依赖漏洞、配置 Schema 与运行构建。只引用官方版本支持页不足以锁定镜像 digest 或证明生产可用。升级按版本差异、迁移方案、契约回归、回滚与 Canary 分池进行。Go 版本需按实际 `idp-bento-go` 模块和支持矩阵确定，不能仅用语言偏好推导兼容。

**生产前至少确认**：证书及 Secret 管理、最小权限工作负载、出站网络策略、全链路超时、控制面备份与恢复、审计留存、联系人及值守、分池回滚权限和测试过程可重放。

## 8. 与标准六门禁的精确映射

| 门禁 | 本项目需要的真实证据 | 当前 |
|---|---|---|
| STD-CP1 范围与采用 | Manifest、能力触发、Owner/风险/ADR 具名批准 | NOT_RUN |
| STD-CP2 领域与事实 | 权威表、Context Map、模型、不变量与反例 | 设计稿待评审 |
| STD-CP3 契约与恢复 | 真实 ExtAuthZ、Broker、gRPC/REST、故障恢复实测 | NOT_RUN |
| STD-CP4 专业体验 | 本项目已有 Gateway Console；必须执行任务、可访问性、角色与权限测试 | NOT_RUN，不能 N/A |
| STD-CP5 工程与质量 | 构建、测试、安全、性能、故障注入、镜像和 SBOM | NOT_RUN |
| STD-CP6 发布与运营 | 运行手册、审批、演练、发布及发布后证据 | NOT_RUN |

**不允许**将离线 JSON/YAML 解析检查等价为 CP5 PASS。CP4 不能未经审批自动标 N/A；CP6 的发布后验证未发生时必须保留 NOT_RUN。

## 9. 参考资料

- [agentgateway supported versions](https://agentgateway.dev/docs/kubernetes/latest/release-notes/versions/)
- [agentgateway backend authentication](https://agentgateway.dev/docs/standalone/latest/documentation/configuration/security/backend-authn/)
- [agentgateway external authz](https://agentgateway.dev/docs/standalone/latest/documentation/configuration/security/external-authz/)
- [agentgateway configuration update](https://agentgateway.dev/docs/standalone/latest/documentation/setup/update/)
- [OpenTelemetry](https://opentelemetry.io/docs/)
- [RFC 9700 OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html)


## 10. Gateway Operations 前端与运维实现边界（G05 · V1.0 同版更新）

原型入口：[gateway-operations.html](../portal/prototypes/gateway-operations.html)。原型为单文件零依赖 HTML/CSS/JS，提供 18 个主导航和六个核心运维视图、路由与策略过滤、详情 Drawer、脱敏 Trace、环境/角色切换、审批/部署/回滚演示和实例故障模拟；所有数据是 in-memory Mock，不做 fetch、网络请求或持久化。

正式实现建议接入现有 IDP Engineering UI Shell 与设计系统，采用 Gateway Operations BFF 聚合查询，服务端分页、权限范围过滤、审计、缓存新鲜度、错误和降级状态。网关原生管理 UI 仅供受控运维或调试，生产配置必须经 Fabric/Config Controller 的批准发布接口，不在浏览器里直接写入 agentgateway 原生配置。

必须执行独立的 UI/UX 自动化测试、可访问性评审、权限绕过负向测试、浏览器兼容性测试、安全头部检查和跨系统权限一致性验收。UX 场景见 [75 条验证矩阵](../tests/ux/acceptance_matrix.csv)，真正集成仍为 NOT_RUN。


## 同版设计增补：统一 Gateway Console

UI 实施：单一 IDP Console 按协议能力模块化实现，后端使用 Gateway Control Adapter（Go），不 Fork 上游 UI 或网关代理内核；受控发布与只读诊断分开，记录版本差异与上游兼容性。

详情参见 `portal/spec/Agentgateway_UI_Capability_Matrix_V1.0.md`（自本工程根目录）。


## 同版增补：报文采集与故障诊断工程方案

**信号分层**：默认 `agentgateway access log → OpenTelemetry Collector → 脱敏/过滤后日志存储`；`OpenTelemetry trace → Tempo/Jaeger 类 Trace 存储`；请求计数、P95/P99、拒绝原因经指标通道采集。日志主要记录 method/route/status/latency/decision/trace_id/provider_request_id，不默认启用完整 Body。

**条件捕获**：在受控测试/故障分析中，官方 CEL 提供 `request.body` / `response.body`，但 Body 缓冲限制、截断及 Streaming 语义须遵循运行版本。若需精准比较 Gateway 认证注入/URI Rewrite 前后信息，评估经过验证的 ExtProc 或等价事件观测点；ExtProc 是处理器并可能增加延迟及失败依赖，**不应为了常规日志而强制所有 API 同步调用 ExtProc**。

**诊断呈现**：按 `Trace ID + Hop + Config Revision + Provider Request ID` 关联四阶段证据，每阶段保留 `CAPTURED/NOT_CAPTURED/TRUNCATED/NOT_SENT/TIMEOUT/REDACTED`；Request/Response Header 与 Body 仅展示经服务端授权和脱敏后的有限内容。gRPC 应单独支持方法、Metadata、Status、Trailer 与分帧/流式限制。

**故障分类**：401（身份）、403（账户授权）、429（网关与提供商不同限额）、502（上游）、504（已发送写请求的结果未知）、TLS/DNS（连接层）、Schema/业务码（域适配层）。应显示故障阶段而非笼统“网关错误”。

**性能与隐私验收**：测量开启/关闭捕获时的 CPU、内存、请求/响应 P95/P99、带宽、存储成本；限制单报文大小和采样率；日志注入与跨租户读取负面用例必须通过。默认 Body 捕获为关闭；任何生产临时捕获需自动过期与审计。

官方参考： <https://agentgateway.dev/docs/standalone/latest/documentation/observability/access-logs/view/> ； <https://agentgateway.dev/docs/standalone/latest/documentation/configuration/traffic-management/extproc/> ； <https://agentgateway.dev/docs/standalone/latest/documentation/operations/trace-requests/> 。


## 11. 补强后的实施包与运维基线

### 11.1 Go 工程边界（继续基于已有框架）

建议 `gatewaycontrol/intent`（中立契约）、`gatewaycontrol/compiler/agentgateway`（原生配置适配）、`gatewaycontrol/publisher`（CAS、签名快照、Canary、Reconcile）、`gatewaycontrol/observability`（只读运行投影）；Gatekeeper 自己实现 `credential/registry`、`credential/broker`、`authorization`。不要创建一个跨系统读写所有数据的中央 Gateway DB。

**离线工具**：`scripts/preflight_intents.py` 只有结构检查和部分拒绝列表，不能代替 agentgateway 原生配置编译、TLS/网络策略、运行时授权；输出必须明确 `native_agentgateway_config_generated=false`。该预检器是生产流水线的一道初始关卡，不能直接作为 CD 的生产放行证据。

### 11.2 可观测性与 SLO 规范

每个请求至少关联：`trace_id`,`request_id`,`route_id`,`config_digest`,`authz_decision_id`,`provider_request_id`（如存在）、`tenant_ref`（可见范围内）、`provider_account_ref`（脱敏）及 `failure_origin`。区别不可信客户端自报字段与网关实际观察值。

核心监控：池级请求量/拒绝率、P50/P95/P99、Active Connections、连接失败、DNS/TLS 错误、Circuit State、ProviderAccount Quota Consumption、Token Broker 刷新失败、Config Desired/Observed Drift、Capture Session 状态。**上述字段不意味着 agentgateway 原生全部提供**；需分别验证其来源和可采集性。

初始 SLO 目标必须与容量工作负载一起批准；在缺少真实硬件/部署区域/流量模型的情况下，禁止捏造 99.99% 或固定毫秒延迟作为已达标事实。

### 11.3 Runbook 与紧急响应

参考 `operations/incident-runbook.md`：401/403 排查 Gatekeeper 信任与授权，429 区分本地与 Provider，502/504 分辨 DNS/TLS/连接超时和真实上游返回；504 写操作不可默认重放。

- 快照发布：固定二进制/镜像 digest、固定 schema、SBOM/签名、可回滚 artifact；预检→Canary→批量→回读→观察→ACTIVE。
- 变更失败：按故障域停更、恢复上一个批准快照、核验 observed digest；安全撤销不能因配置回滚而逆向放行。
- Gateway 数据面故障：按池故障注入验证；不允许 Fabric/Console 不可用导致现存请求无条件失败。对需要在线 PDP 的高风险新授权可 fail-closed。
- 隐私事件：立即停用 Capture Session、隔离存储、审计访问路径、按适用法域执行通知与清理。

### 11.4 不得宣称的生产能力

目前**没有**真实 agentgateway 原生配置验证、网络安全、动态 Secret Injection、负载、蓝绿发布或可信报文捕获结果。全部运行门禁和生产调试均 `NOT_RUN`。


## 双 Hop Request / Response 观测实现规范

在与 agentgateway 固定版本进行真实验证后，BFF 的 Message Inspector Read Model 应按两个 Hop 将四个 Observation 组织在一条 Trace 中：`INGRESS_REQUEST`、`EGRESS_REQUEST`、`UPSTREAM_RESPONSE`、`DOWNSTREAM_RESPONSE`。响应与请求按 Trace ID、Route ID、Config Digest、Tenant Ref、Client Request ID 和 Provider Request ID 关联。

每份观测记录需要显式的 `capture_status`（包含 `METADATA_ONLY`、`CAPTURED_SANITIZED`、`NOT_SENT`、`NOT_OBSERVED`、`TRUNCATED`、`NOT_CAPTURED`）、正文长度和截断标记。按 HTTP Method/Target、响应 Status、Headers、Body、Content-Type、HTTP/gRPC Metadata 和 Trailers 分类输出，避免将捕获未发生误显示成空报文。

生产默认只记录元数据，Body 捕获按审批设置 TTL、范围、大小、采样、加密存储与到期删除。UI 侧任何复制、导出与查询都必须经服务器端 ABAC 校验并审计。真正的性能开销与采集能力需要在代理配置、ExtProc/Telemetry 顺序及大包/流式协议测试中确认，不能由离线 UI 推断。
