# G06 — 验证策略、交付批次与正式验收

> **编号** G06 · Verification & Acceptance · **版本** V1.0 · **状态** DESIGN_DRAFT。  
> 离线静态检查仅属于 `STATIC_CHECK`；所有需启动真实 agentgateway、Gatekeeper 和第三方沙箱才能完成的测试，均为 **NOT_RUN**，不得虚报通过。

## 0. 验收哲学

**先验证“能否安全工作”，再验证“是否值得统一强制路径”**。不接受以 API Gateway 功能清单替代实际多租户动态凭证测试；不接受以 Mock Server 的正常返回替代失败场景或真实身份验证；不接受以配置文件解析通过声称 Gateway 运行中可用。

## 1. 分层验证与证据类型

| 层级 | 类型 | 执行方式 | 证据要求 |
|---|---|---|---|
| V0 | 文档和中立契约静态一致性 | 本包 `scripts/validate_baseline.py` + `unittest` | stdout、依赖、退出码、SHA 摘要 |
| V1 | agentgateway config/syntax | 已固定的官方版本二进制及官方 schema/CLI | 二进制版本、完整指令、真实输出 |
| V2 | 认证与策略 | Gatekeeper 真/测试 JWT、真实 Gateway ExtAuthZ 对接 | 正负请求、认证决策、Secret 泄密检查 |
| V3 | 真实 Provider Sandbox | 2 租户/2 账户/创建与查询操作 | Trace、Provider correlation、外部确认 |
| V4 | 高可用与性能 | 多副本、故障注入、负载生成器 | 资源、延迟分布、错误率、持续时间 |
| V5 | 安全与发布 | SSRF、账户越权、密钥轮换、生产发布恢复 | 具名批准、PoC 证据、运维演练 |

V0 不包含企业级漏洞扫描、网关运行测试、服务认证性能或生产条件。若某项因契约变化失效，应按变更影响重验，不要求所有无关测试机械重跑。

## 2. 重点验收场景

1. **JWT 严格验证**：同一服务身份的合法 JWT 可在允许环境访问，错误 iss/aud/alg/签名/过期/撤销场景拒绝。Gateway 必须鉴别 Token 类型与客户端权威。
2. **跨租户隔离**：相同 Provider 多账户并存，A 不能访问 B；改变 Header/URI/account ID 无法绕过 Gatekeeper 的复合授权。
3. **第三方凭证处理**：Gateway 执行认证，第三方只收到其认可 Token；不记录或转发内部 JWT；失效/刷新/吊销时反应在规定窗口内。
4. **出站 L7 正确透传**：对 Path/Query/Body/Header/Status 按允许契约观察，异常字符、URI 规范化、重定向不形成新的未授权目标。
5. **CONNECT 对照**：以官方 Tunnel 与 Route 模式分别测量可见信息，验证不误用 CONNECT 实现动态 HTTP 认证注入。
6. **gRPC**：Unary 与 Stream 的 deadline/metadata/status，识别认证中间件在流内能否保证安全。
7. **运行可靠性**：Gatekeeper PDP、JWKS、Token Broker、DNS、Provider、Gateway 分别故障，确认 Fail Closed、无写请求重放、配置可回退。
8. **部署一致性**：同一 GatewayPool 多副本的 Desired 和 Observed 摘要一致，部分成功必须显示 PARTIAL/UNKNOWN。
9. **Provider 限流**：多租户与共享 Account 配额不互相挤占、可明确区分 Provider 429 与 Gateway 429。
10. **运营审计**：能通过 Trace 和 Snapshot 信息重构授权事实、上游状态及发布责任；日志中没有 Secret/Token。

`tests/acceptance_matrix.csv` 提供逐条 ID、FR 映射、前置条件、预期结果、状态与证据占位标记；没有运行过的行保持 `NOT_RUN`，不把自带 Mock 逻辑测试伪装成运行验证。

## 3. 风险优先验证矩阵

| 风险维度 | 必需样例 | 失败时处理 |
|---|---|---|
| 认证入口 | 未认证、错误签名、Key Rotation、OIDC/JWKS 故障 | Block P1/P2 |
| 资源授权 | Cross Tenant/Account/Env/Operation、无 Grant、撤销 | Block P1/P2 |
| 凭证外发 | Token 注入、Header 剥离、Scope、缓存污染 | Block P2 |
| 出站网络 | SSRF、重定向、DNS 重绑定、内网/IPv6 | Block P2 |
| gRPC HTTP | Streaming、超时、Header/Body、Provider Error | 按已承诺协议阻断 |
| 异步及故障 | 重试副作用、代理失效、配置漂移、Broker 超时 | Block 生产 |
| 效率与 SLO | direct vs gateway 三类基线 | 超出经批准预算阻断 |
| 运营 | 发布/回滚、Secret 轮换、值守 | Block CP6 |

## 4. 验收所需环境

- **Dev Mock**：固定 loopback upstream 和本地测试账户；仅用于结构验证，不使用真实 Provider Secret。
- **Stage / Test**：隔离 VPC、受控 Gatekeeper Issuer、测试 Secret Manager、真实 agentgateway 版本、可观测组件、多副本部署。
- **Provider Sandbox**：真实 Provider 沙箱账号、两个独立账户、隔离 token，测试数据合法；不可在不具备合同授权时自行模拟成官方 API。
- **Pre-Production**：与生产一致的网关配置发布方式、硬件/SLO、故障域和回滚机制。

必须在测试报告记录 `agentgateway image digest`、`Gatekeeper commit`、`Gateway adapter commit`、`Policy digest`、`Env`、`Clock`、`Dataset`、`Operator`、`Evidence URIs`。没有这些元数据无法复现时，证据状态为不充分而不是 PASS。

## 5. 安全测试与外部权限

安全测试的 Provider 账号必须获得合法使用授权；不要对真实第三方系统执行未经许可的渗透或压测。SSRF 等攻击性测试应在受控 Mock 环境与隔离网络中完成，确认网络策略/网关阻断而不请求真实内部敏感服务。

## 6. 发布门禁对照

| 阶段 | 入口条件 | 放行条件 | 当前状态 |
|---|---|---|---|
| D0 文档候选基线 | G01–G06 与机器契约成形 | 文档 QA 成功，ADR/Manifest 仍可 Proposed | 静态检查可执行，设计待审 |
| D1 功能 PoC | D0 已评审/必要风险已确认 | JWT/AuthZ、L7、Token 负向测试真实通过 | NOT_RUN |
| D2 Provider Sandbox | D1 通过 | 多租户账户、失效/刷新、结果不确定真实通过 | NOT_RUN |
| D3 生产候选 | D2 通过 | 性能/安全/HA/回滚/运维实测达批准 SLO | NOT_RUN |
| D4 正式发布 | STD-CP1–CP5 适用门禁有效 | 有权审批 + 受控发布 + 发布后真实验证 | NOT_RUN |

## 7. 交付包目录与审查清单

- **文档**：G01–G06 Markdown + 对应 HTML，统一索引 `index.html`；每份文档需包含权威、约束、验证。
- **ADR**：明确选型、Ingress/Egress/AI 分池、Gatekeeper 认证/凭证、Fabric 发布边界、BIP 取消、Runtime/失败策略、ACL。
- **机器资产**：Gatekeeper OpenAPI、RouteIntent JSON Schema、AuthZ Decision Schema、Policy 样例、agentgateway 本地示例、Mock 数据。
- **测试**：`tests/acceptance_matrix.csv`、安全与契约离线测试、真实测试证据目录 `tests/evidence/`。
- **Manifest**：技术 Profile 采用及六门禁的候选状态，**具名责任人与审批不得虚构**。
- **引用资料**：官方文档来源、规范版本、依赖和技术适用性保留条件。

## 8. 当前版本已验证与未验证

**可验证（本机可运行）**：文档存在、基础相对路径、JSON/YAML 语法、JSON Schema/fixture、策略样例的非开放目标和基本拒绝逻辑、ZIP 条目与哈希。实测结果见 `tests/evidence/static-validation.json` 和 `CHECKSUMS.sha256`（生成时间与工具执行见实际证据，不以正文宣称已全部执行）。

**未验证**：真实 agentgateway 启动和配置 API、Gatekeeper/ExtAuthZ/mTLS 的生产对接、第三方 OAuth、REST/gRPC 端到端、多实例 HA、性能指标、安全渗透、发布恢复及上位规范正式门禁。**这些必须始终标 NOT_RUN，直到有可核验证据。**


## 9. STD-CP4 专业体验补充与独立 UX 验收（G06 · V1.0 同版更新）

由于本项目的内部工程管理模块包含人工操作，STD-CP4 不应标记 N/A。新增 [Gateway Operations UX 设计规格](../portal/spec/Gateway_Operations_UX_Spec_V1.0.md) 与 [UX 验收矩阵](../tests/ux/acceptance_matrix.csv)：共 **75 条 UI/UX 场景**，全部 `NOT_RUN`（正式 UI/权限/可访问性验收）。当前 95 条运行时验收场景继续保持 `NOT_RUN`，两套矩阵分别追踪不得混为已通过。

原型浏览器自动化仅验证静态 HTML/JS 交互行为，不能代替实际 Gatekeeper RBAC/ABAC、多租户数据保护、agentgateway 配置回读、发布审计、错误恢复或生产可访问性验收。须分别提交真实浏览器截图/测试日志、真实后端联调与验收报告。


## 同版设计增补：统一 Gateway Console

新增验收约束：以官方开源 UI 功能矩阵核对 Gateway/Traffic/LLM/MCP/Tools 的可用性；区分 Mock UI PASS 与 Gateway/Gatekeeper/Fabric 真正联调 NOT_RUN；新增角色隔离、密钥不泄漏、配置冲突与恢复演练。

详情参见 `portal/spec/Agentgateway_UI_Capability_Matrix_V1.0.md`（自本工程根目录）。

> 本次统一 Console 设计增补后 UX 正式验收矩阵共有 **75 项**，状态全部保持 `NOT_RUN`；95 条 Gateway 真实验收仍保持 `NOT_RUN`。


## 同版增补：报文诊断验收门槛

新增 UX 正式验收用例 `GW-UX-AT-055` 至 `GW-UX-AT-062`，状态全部 `NOT_RUN`。其中包含：四阶段消息证据链、前后请求转换差异、401/403 未向外转发、504 写操作 UNKNOWN、Secret/PII 采集前脱敏、租户/角色访问隔离及审计、按需捕获的上限与性能、gRPC Metadata/Status/Streaming。离线 Mock 的页面渲染或合成数据导出不等于上述真实验收通过。


## 11. 生产阻断缺口的新增追溯与准入规则

- 功能总量：**50 FR + 19 NFR**。原 30 FR / 12 NFR 的编号不变，新增 `GW-FR-031..050`、`GW-NFR-13..19`，逐项追溯 `tests/acceptance_matrix.csv`；新增 **20+7** 个对应运行用例，全部 NOT_RUN。
- 新增 `tests/protocol-compatibility.csv`、`tests/operational-exercises.csv` 和 `governance/gap-remediation-matrix.csv` 作为执行清单，不得把设计文本映射为 PASS。
- `tests/contracts/test_route_preflight.py` 的结果只能证明**离线配置意图语义**，不证明真实 Gateway Runtime、AuthZ、DNS/SSRF、Quota Coordinator、Capture 及 Snapshot 生效。
- PoC 的唯一生产结论门槛：选定镜像 digest/配置版本，以真实 Gatekeeper、Gateway、Provider Mock/Sandbox 进行正反向安全测试。多租户账户隔离、凭证撤销、配额越界、DNS 重解析、非幂等 UNKNOWN、配置半失败和四阶段诊断应全部有可重复证据。
- UI/UX 正式案例新增 `GW-UX-063..071`，涵盖账户配额、Upstream Health、配置漂移和诊断证据权限；其验证仍为 NOT_RUN，离线 Mock 只能证明界面行为。

### 11.1 逐层验收顺序（不能跳步）

| 阶段 | 真实产出证据 | 失败时行为 |
|---|---|---|
| A. Native Config | 配置 Schema、CLI/启动、版本/镜像摘要 | 拒绝发布，不生成 ACTIVE |
| B. Identity/Broker | 已验证身份、双租户双账户、Token 生命周期、撤销传播 | 失败关闭并记录脱敏审计 |
| C. Traffic/Protocol | 配额、并发、健康/熔断、HTTP/gRPC/SSE、异常处理 | 异常状态可区分且可恢复 |
| D. Rollout/Resilience | Canary、Partial/Unknown、漂移、故障回滚 | 恢复有效批准快照并重新观察 |
| E. Observability/Security | 四阶段证据采集精度、脱敏前拦截、服务端 ABAC | 禁止未授权正文泄露 |
| F. Formal Signoff | STD-CP1–CP6 具名门禁与运营接收 | 无签核不得生产 |


## Message Inspector Request / Response 专项验收

除既有 95 条运行时验收外，UX 验收还覆盖 4 项成对报文场景（`GW-UX-AT-072..075`）；因此正式 UX 场景总数为 **75**，全部保持 `NOT_RUN`。原型自测结果只能说明合成数据界面交互正常。

1. 对 HTTP 200：同一 Trace 必须看见两个 Hop，分别存在 Request/Response；请求状态行与响应状态行绝不能混放，且显示 Headers 和 Body 采集状态。
2. 对请求改写和响应映射：可核对入站 Target、外发 Target、上游 Status、下游 Status，凭证值仅能显示安全脱敏标记。
3. 对 401/403/429：上游 Request 为 `NOT_SENT`，上游 Response 为 `NOT_OBSERVED/NOT_REACHED`，但下游 Gateway 错误 Response 必须可见。
4. 对 504：上游 Request 为已发送、上游 Response 为 `NOT_OBSERVED`，下游 Gateway 504 可见；写操作须标注 `UNKNOWN / reconciliation required`。

正式通过依赖真实 agentgateway 原生路由与 BFF 服务端采集、授权、脱敏、导出审计及双租户负向验证。
