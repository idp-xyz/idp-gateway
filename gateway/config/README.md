# agentgateway 配置例子（安全警告）

`agentgateway.local.example.yaml` 仅供展示 Standalone 1.7.x 的路由语法轮廓，**并非可以直接暴露给业务网络的受保护 Gateway**：当前示例没有 JWT/ExtAuthZ、TLS、真实 Secret Manager 对接，也尚未经过本环境官方 agentgateway 配置检查。只用于隔离本地 Mock 研究。

真正的配置应由 `RouteIntent` / `PolicyBundle` 经受控 Adapter 编译，按受控版本读取官方 `https://agentgateway.dev/schema/config`，以真实 agentgateway CLI/实例验证 JWT、ExtAuthZ、上游认证与完整的 TLS/NetworkPolicy，再经批准发布。绝不能从这个 Demo 自动推导生产模板。

动态第三方凭证注入必须对官方 ExtAuthZ Header 接收机制进行验证；普通 CONNECT 透传不能替代 L7 应用认证。

## 生产预检新增要求

先运行 `python scripts/preflight_intents.py contracts/gateway/route-intent.example.json`；若返回 `STATIC_PREFLIGHT_OK_NOT_DEPLOYABLE`，仅表示**本地中立意图未发现已实现检查器可见的错误**。

严禁因此跳过固定版本 agentgateway 官方 Schema/CLI/二进制运行、网络 Egress/DNS/TLS、Gatekeeper/PDP 多租户、流式协议及负载/安全验证。`gateway/policies/traffic-policy.example.json` 描述账户级额度意图，并没有启动任何分布式限流协调器。
