# IDP Gateway · Incident Response Runbook（设计候选 V1.0）

> 所有命令与动作必须在真实环境验证、完成职责分离与 runbook 演练后才用于生产；当前全部 NOT_RUN。

## 首先收集五个不可混淆的事实

1. 请求可信 Trace / Request ID；Gateway Pool / Instance / Config Digest；环境、已脱敏租户/账户引用。
2. 是 Gateway 自己拒绝，还是确实收到 Provider 401/403/429/5xx？若请求未外发，阶段状态为 `NOT_SENT`。
3. 是否观察到上游响应？对已外发的创建/支付/订舱/清关等非幂等写操作，超时必须记为 `UNKNOWN` 并通过业务侧查询/对账。
4. Gatekeeper PDP/Broker/Auth Server 是否正常？高风险授权失败默认拒绝，不临时跳过安全策略。
5. 当前 Desired/Applied/Observed 配置是否一致？近期发布是否引入变化？

## 事件到操作映射

| 现象 | 首要排查 | 绝对禁令 |
|---|---|---|
| 401 from Gateway | JWT `iss/aud/alg/exp`, JWKS 缓存/时钟 | 不允许跳过签名验证 |
| 403 from Gatekeeper | Tenant、服务身份、账户 grant、operation、撤销代次 | 不允许凭 X-Tenant-ID 强制放行 |
| 401/403 from Provider | 第三方 Token/Scope/账户状态，签名/证书 | 不允许打印 Authorization 明文 |
| 429 from Gateway | ProviderAccount Quota、Tenant Subquota、协调器、Retry-After | 不允许无限放宽全局额度 |
| 429 from Provider | 第三方真实配额响应与账户冷却 | 不得将 Provider 429 当本地拒绝 |
| 502 / DNS / TLS | 解析、证书、SNI、网络策略、Circuit State | 不允许关闭 TLS 验证绕过 |
| 504 after upstream send | 请求是否确实外发、第三方 Request ID、业务去重/查询 | 不允许盲目重放非幂等写请求 |
| Config PARTIAL/UNKNOWN | Snapshot digest、Canary/副本读回、配置编译、审计 | 不允许页面直接修改原生生产配置 |
| Message Capture leak | 立即停用会话、阻断导出、保全受控审计、合规响应 | 不允许明文 dump 到工单/聊天 |

## 故障演练最低集合

见 `tests/acceptance/operational-exercises.csv`，在安全隔离环境验证单实例、单区域、PDP、Broker、DNS/TLS、Quota Coordinator、配置半发布及恢复。所有实际结果由测试环境自动写入不可变证据；不要手工把 `NOT_RUN` 改为 PASS。
