# 与现有 API Fabric 和 Gatekeeper 文档的定点变更清单

> **状态** Proposal / Impact Assessment，**未自动修改** 原 API Fabric F01–F08 或 Gatekeeper 正式设计，以免覆盖已批准内容或产生版本分叉。

## API Fabric

- F01：补充 Consumer API 对应的 Egress Route 绑定与发布意图；并不将第三方 Provider 契约包装为我方自有 API。
- F02：明确 Gateway 为独立运行数据面、Gatekeeper 为身份及凭证权威，不因取消 BIP 改写原治理控制面设计。
- F03：区分 Fabric `PublicationSlot = Target × APIAsset` 与 Gateway `RouteBinding`，用稳定 ID 引用，禁止跨数据库共享写主。
- F04：为 Provider Consumer 契约定义 Auth Scheme 元数据、变更影响及验证方式；Secret 永不进入契约。
- F05：补充 ExtAuthZ Cache、Account Grant 与 Public Portal 的授权独立性，以及消费者 API 不自动对外公开。
- F07/F08：增加 Gateway 配置生效回读、撤销、失败和安全场景的真实验收证据；不得把文档发布视为 Gateway ACTIVE。

## Gatekeeper

- 增加 ExternalProvider、ProviderAccount、CredentialReference、ExternalAccessGrant、TokenLease 的设计评审。
- 决策 API 与 Broker API 仅允许 Gateway 受信任工作负载访问；第三方 Token 的签发权威依然属于 Provider。
- 域间策略：Gatekeeper 不需要代理业务请求；用户/服务身份认证不自动等于第三方账户授权。
- Secret 存储通过 Secret Manager/KMS，不在 Gatekeeper 关系数据库明文保存；提出撤销/Token Lease/审计 SLA 并实测。

## 业务产品与 TELOS

- 业务 Port/ACL 保持类型化；对外网络访问改为受控 Egress 逻辑路由，默认不暴露 Provider Secret。
- 非幂等命令仍由业务领域做结果查询、对账、幂等与人工恢复。
- TELOS AI Gateway 不经 BIP；与业务 Egress 分池部署且工具权限不等于网关路由权限。

## 需要具名批准的冲突决议

1. 统一 Egress 为默认与“外部直接 Port/Adapter”旧建议的关系：Port/ACL 保留，默认 Adapter 的运输目的地改为 Gateway，不改变业务模型。
2. “所有内部应用都通过 Gateway 地址”仅默认涵盖内部业务产品访问第三方业务 API；内部产品互调是否强制转发，保持独立决策。
3. 若 agentgateway PoC 的动态凭证注入无法满足多租户安全，不允许假称已实现；替代方案须重走 ADR-0001/0003/0004。

## V1.0 缺口整治后的必要接口契约变更（待权威系统实施）

- **Fabric**：发布 Intent 的 `RouteIntent` 应引用统一 `contracts/gateway/route-intent.schema.json`；Ingress / Egress / AI 采用分支模型，不能要求所有接口具有 ProviderAccount。新增 `policy_bundle_ref`、编译产物摘要、期望 generation、Canary/Observed 的回读关联；Fabric 不负责直接编译 agentgateway 原生配置。
- **Gatekeeper**：原 `credentials/materialize` 仅适合狭窄 Header 注入；新增候选 `/v1/egress/credentials/prepare` 类型化 CredentialUse（Header Injection / Trusted Request Signer / mTLS Identity Reference）。所有 API 仅为提案，必须完成真实 ExtAuthZ/BackendAuth 版本与协议兼容测试；不能将这份内部 OpenAPI 误当 agentgateway 原生 ExtAuthZ wire 协议。
- **P1 PoC 之后的修正（同为提案，待目标系统 Owner 接收）**：
  - Gatekeeper 需要提供的是一个 **HTTP ExtAuthZ 端点**（`contracts/gatekeeper/openapi.yaml` 的 `/v1/extauthz/check`）：允许时在响应头里按请求下发 Provider 凭证，只接受已认证的网关工作负载调用。`credentials/materialize` 不实现，`secure_binding_handle` 不签发；`credentials/prepare` 只返回计划、不返回秘密。依据与剩余风险见 `decisions/ADR-0008.md`，证据来自 Mock Gatekeeper，不是 Gatekeeper 的实现。
  - 决策结构新增必填 `revocation_epoch`，决策请求新增 `method`、`path`、`config_digest` 与可选 `delegated_subject`、`token_environment`（后者是模式 B 试跑时发现缺的：没有它，PDP 拒绝不了一个环境的 Token 用在另一个环境的池上）。
  - `/v1/extauthz/check` 的调用方身份取自 mTLS 客户端证书：Gatekeeper 需要能区分网关与其它工作负载，只对网关身份下发凭证。PoC 里这一点是用 Mock 和临时 CA 验证的。
  - Fabric 提交的请求体是 `RoutePublicationIntent` 信封（`idempotency_key`、`release_ref`、`target_id` + 内嵌 `intent`），发布状态以同一契约里的 `ReleaseState` 为唯一词表。
- **运营**：Gateway Console 的 Quota、Circuit、Desired/Applied/Observed、CaptureGrant 数据分别由运行时、发布器、Gatekeeper 和安全证据服务提供；UI 本身不决定 ProviderAccount 权限、不成为第二个配置发布主。
- **安全**：默认不捕获正文；诊断读取和导出在服务端按角色、租户、审批用途及时间窗检查。需明确采集点和真正外发报文是否在签名/重写后被观察到。
- **证据**：本次只更新 Gateway 自身设计，不写入或修改原 API Fabric F01–F08 或 Gatekeeper 正式仓库；任何跨系统模型/流程变更需目标系统 Owner 明确接收并签字。
