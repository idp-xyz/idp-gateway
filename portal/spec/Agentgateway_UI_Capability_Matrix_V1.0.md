# IDP Gateway Console — agentgateway UI 能力映射与实现边界 V1.0

> **基线范围**：参考 agentgateway **官方开源 Standalone UI** 的主要可视化管理能力；不复制官方页面源码或视觉资源。本文件属于 IDP Gateway V1.0 同版设计增补，非真实联调或生产准入证据。  
> **原型状态**：OFFLINE MOCK，尚未调用 agentgateway、Gatekeeper、API Fabric、真实 LLM/MCP/A2A 服务；所有运行时验收均 `NOT_RUN`。

## 设计结论

- **完整纳入官方开源 UI 的主要管理能力是合理目标**，但不建议把原生 UI 的所有低层功能直接暴露为默认业务配置界面。
- 使用统一的 **IDP Gateway Console** 负责用户交互，用模块化管理 API 显示或提交配置意图；以 **agentgateway** 为运行时数据面。
- 保留 **Gatekeeper** 对身份、授权、第三方账户和密钥的权威；保留 **API Fabric** 对 API Catalog、契约、批准发布的权威；业务 Port/ACL 不转移到 Gateway。
- 生产配置以 **唯一受控发布通道** 生效。agentgateway 原生 UI 仅用于受权限保护的只读检查、排障或隔离实验环境，不允许与 IDP Console 共同直写同一生产配置。
- 开源项目为 **Apache-2.0** 许可。若将来直接复用上游源码/组件，应做版本与第三方依赖的 LICENSE/NOTICE 审核、保留所需版权声明；本轮 UI 使用独立设计与实现。

## 逐项功能覆盖

| 官方开源 UI 能力/对象 | IDP Console 对应界面 | 该次原型 | 工程实现计划/真实权威 |
|---|---|---|---|
| Gateway Home / Overview | 运营总览 | **Mock** KPI / 风险与导航 | Observability 查询，Cross-Plane Read Models |
| Traffic / Gateways / Listeners | 监听器与网关 | **Mock** 清单/详情 | agentgateway Gateway/Listener 适配器 |
| Traffic / Routes / Matches | 路由与接口（原页） | **Mock** 路由详情、查询 | RouteIntent → Approved Config → Reconcile |
| Backends / Targets / Weights / TLS | 上游服务 | **Mock** 详情和权重 | 路由配置/后端健康检查 |
| Traffic Route Policies | 路由与接口、访问授权 | **Mock** 策略关联 | Gateway Policy Adapter + Gatekeeper AuthZ |
| LLM / Models / Virtual Models | LLM 模型与服务商 | **Mock** 模型清单/策略 | 模型路由、权重、条件、故障回退适配 |
| LLM / Providers | LLM 模型与服务商 → 服务商 | **Mock** 提供商清单 | Provider 注册与 Secret 引用 |
| LLM / Policies | LLM 策略与护栏 | **Mock** 策略卡片 | Gateway Policy Adapter |
| LLM / Guardrails | LLM 策略与护栏 → Guardrails | **Mock** 请求/响应防护 | Guardrail 配置、审计、数据分级 |
| LLM / Virtual API Keys | 虚拟密钥与客户端 | **Mock** 元数据 | Gatekeeper/密钥工作流；不可明文展示 |
| LLM / Cost / Analytics / Logs | LLM 成本与分析 | **Mock** 指标、脱敏日志 | 使用量采集、账单估算、Telemetry |
| LLM / Client Setup | 虚拟密钥与客户端 → Client Setup | **Mock** 配置片段 | 已发布 URL/模型/权限的派生视图 |
| MCP / Servers / Transports | MCP 服务与工具 | **Mock** 服务清单 | MCP Registry/Proxy 适配与验收 |
| MCP / Tools / Resources | MCP 服务与工具 → Tools & Resources | **Mock** 发现结果 | Gateway MCP Discovery + AuthZ |
| MCP / Policies | MCP 服务与工具 → MCP Policies | **Mock** 规则和关系 | Gateway Policy + Gatekeeper |
| MCP / Playground | MCP Playground | **模拟** JSON 校验与 Allow/Deny | 需要有权限的真实 MCP 工具安全测试 |
| A2A Agent 接入能力 | A2A Agents | **IDP 扩展 Mock** | Agent Endpoint / Trust / A2A Capability，非声称官方 UI 完全相同 |
| Tools / CEL Playground | CEL / 配置 / 设置 → CEL | **固定模拟**，绝不执行任意表达式 | 与对应版本 CEL Parser / TypeChecker 联调 |
| Tools / Raw Configuration | CEL / 配置 / 设置 → Configuration | **IDP 意图 JSON 只读** | 原生 schema 适配、校验、发布、对账 |
| Tools / Settings UI / OIDC / CORS | CEL / 配置 / 设置 → Settings | **Mock** 设置卡片 | Gatekeeper SSO、UI 管理入口隔离 |
| Tools / Settings Observability | CEL / 配置 / 设置 → Settings | **Mock** 跟踪与日志设置 | OTel / Logging pipeline |
| IDP 独有：External Provider onboarding | API 接入向导、第三方提供商 | **模拟** 三步向导、检查 | 路由意图、账户权限、外部 Token Broker |
| IDP 独有：Publication approval / rollback | 配置发布（原页） | **模拟** 审批/发布/回滚 | API Fabric + Gateway Controller 唯一发布权威 |
| IDP 独有：Multi-pool operations | 实例与故障域（原页） | **模拟** 生产/测试实例、故障 | Runtime metrics & incident response |

> **覆盖说明**：该表是可视化与信息架构功能覆盖，不表示实现了官方 UI 的每一个具体字段、每个策略插件及原生配置 schema；尤其不能将 Mock 功能标为真实可用。正式功能等价性必须以锁定版本的官方配置 schema、代码审查和端到端测试重新盘点。

## UI/UX 应优先于传统网关资源视图的体验

1. **业务意图先行**：从“谁访问哪个外部业务能力”配置，而非直接从路由和 JSON/YAML 对象开始。
2. **一步到底的关联导航**：API → 服务 / 租户 → Provider Account → Policy → Trace → Release。
3. **明确多权威边界**：Gatekeeper 持有身份/账户、Fabric 持有契约/发布授权、Gateway 只执行与回读；UI 汇聚不改写所有权。
4. **先模拟后发布**：配置编辑、校验、冲突检查、差异影响、批准、灰度、回读和回滚全链路可追溯。
5. **默认安全**：禁止开放出站代理、禁显 Secret、禁用生产任意 YAML 直改、高风险操作职责分离。
6. **版本升级可持续**：建立 upstream-version compatibility matrix；通过 adapter 做能力探测，避免硬编码单一版本字段。

## 真实实施不可省略的验收

- agentgateway **Standalone/Kubernetes** 模式下 UI/API 行为不同，尤其 Kubernetes UI 只读；必须固定 Runtime 版本与配置存储模式。
- 外部 OAuth Client Credentials、Provider 账户动态选择、Token 刷新与敏感 Header 注入，不能从普通 Backend Authentication 功能推断已自动完成；需要 Gatekeeper PoC。
- LLM virtual model 的条件、权重、failover，MCP OAuth/Tool authorization、A2A trust 需要真实协议测试。
- Route/Policy 修改必须由一个批准发布渠道执行，原生 UI 不允许绕过；验证可审计回读和漂移检测。
- 对外部 API 的 GET、POST、gRPC、SSE/Streaming 分别验证 Header、Body、状态码、错误恢复、负载及安全。
- 前端可访问性、中文术语一致性、密码不可见、权限越权、移动/宽屏布局需执行正式验收。

## 官方参考

- agentgateway 开源仓库 / Apache-2.0：<https://github.com/agentgateway/agentgateway>
- Standalone UI 官方导航与能力：<https://agentgateway.dev/docs/standalone/latest/documentation/setup/ui/launch-ui/>
- Standalone / Kubernetes 差异：<https://agentgateway.dev/docs/standalone/latest/documentation/about/introduction/>
- Routes 与匹配：<https://agentgateway.dev/docs/standalone/latest/documentation/configuration/routes/>
- Kubernetes UI 只读说明：<https://agentgateway.dev/docs/kubernetes/latest/documentation/observability/ui/>


## 统一平台补强（同版 V1.0）

| 功能 | 管理体验 | 权威/真实数据来源 | 当前实现 |
|---|---|---|---|
| ProviderAccount Quotas | 账户×租户×Operation 额度与 429 分类 | Gateway/Quota Coordinator + Provider | 仅同页 Mock 看板 |
| Upstream Health / Circuit | 连接、超时、熔断状态 | agentgateway 指标与独立健康检测 | 仅同页 Mock |
| Config Drift | Desired/Applied/Observed 多副本摘要对比 | Gateway Publisher/Reconciler | 仅同页 Mock |
| Capture Grants / Sensitive Export | Route+Tenant+TTL+审计授权 | Gatekeeper + 隔离证据存储 | Message Inspector Mock；服务端 NOT_RUN |
