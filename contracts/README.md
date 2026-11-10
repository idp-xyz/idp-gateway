# API 与策略契约资产（设计候选）

- `gatekeeper/openapi.yaml`: **IDP 自定义** Gatekeeper Control API，Gateway 专用 mTLS；不是 Envoy/agentgateway ExtAuthZ gRPC wire schema。
- `gatekeeper/authz-decision.schema.json`: **IDP 中立决策结构**，用于 Mock/校验；实际要经 `GatewayAuthzAdapter` 映射到 Envoy gRPC/agentgateway HTTP ExtAuthZ。
- `fabric/route-publication-intent.openapi.yaml`: Fabric → Gateway Config Publisher 的管理意图；不是运行时 HTTP Route。
- `gateway/route-intent.schema.json`: IDP 中立路由意图 JSON Schema；不代表直接可被 agentgateway 识别。

所有样例值为虚构占位，不能从示例推导真实服务域名、第三方授权或密钥。生效配置必须使用指定版本的 agentgateway 官方 schema/真实运行实例进行验证。

## V1.0 同版补强

- `gateway/route-intent.schema.json` 是唯一的三分支 Intent Schema（Ingress/Egress/AI）；Fabric `route-publication-intent.openapi.yaml` 使用相对 `$ref` 指向它，避免双份不一致的 API 模型。
- `gateway/route-intent.{ingress,ai}.example.json` 与 `gateway/route-intent.example.json` 是三组正例；`tests/contracts/invalid-route-intents.json` 是互斥/权限负例。
- `gateway/diagnostic-event.schema.json` 定义四阶段可观察事实和 `NOT_SENT` / `NOT_OBSERVED` / `TRUNCATED` / `NOT_CAPTURED` 状态，不允许把未记录的报文推断为已经发送的字节。
- `gateway/policies/traffic-policy.*`、`credential-binding.*`、`diagnostic-capture.*` 为中立治理策略 **仅供候选**，不能直接当 native agentgateway 语法或已实现的 Gateway 功能。
- Gatekeeper `credentials/prepare` 为新候选接口；旧 `credentials/materialize` 标记为 `deprecated`，需确认调用方兼容后才可退役。
