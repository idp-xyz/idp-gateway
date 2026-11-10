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

## P1 PoC 之后的契约修正

- **决策制品只有一份定义**：`gatekeeper/openapi.yaml` 的 `DecisionResponse` 直接 `$ref` 到 `gatekeeper/authz-decision.schema.json`，并新增必填的 `revocation_epoch`；`DecisionRequest` 补上 `method`、`path`、`config_digest` 与可选的 `delegated_subject`。
- **凭证兑换路径**：Header 注入类凭证只在 `/v1/extauthz/check` 的允许响应头里、按请求下发给已认证的网关工作负载（`tests/acceptance/blackbox` 跑过的就是这个交换）。没有任何接口在响应正文里返回凭证；`credentials/materialize` 不实现，`secure_binding_handle` 不签发。见 `docs/adr/ADR-0008.md`。
- **发布信封**：`fabric/route-publication-intent.openapi.yaml` 的请求体是 `RoutePublicationIntent`（`idempotency_key`、`release_ref`、`target_id` + 内嵌 `intent`），RouteIntent 仍只有 `gateway/route-intent.schema.json` 一份定义；示例见 `fabric/route-publication-intent.example.json`。
- **发布状态只有一套**：同一文件的 `ReleaseState` 是唯一词表，与 G03 §3 一致；Console 上的 REVIEW/ROLLOUT/RECONCILED/REVERTED 是它的展示标签。
- **RouteIntent**：INGRESS 与 AI 分支不再允许携带 `upstream_*`、`redirect_policy`、`operation_id`。
- **诊断事件**：`sanitized_headers` 由黑名单改为白名单（名称小写），值不得形似凭证；`NOT_SENT`/`NOT_OBSERVED` 的阶段不得带状态码、头或正文。
- `tests/contracts/test_contract_consistency.py` 与 `test_bypass_regressions.py` 固定以上各条。
