# agentgateway 配置例子（安全警告）

`agentgateway.local.example.yaml` 仅供展示 Standalone 路由语法轮廓，**并非可以直接暴露给业务网络的受保护 Gateway**：当前示例没有 JWT/ExtAuthZ、TLS、真实 Secret Manager 对接。它已通过 agentgateway 1.6.0 与 1.7.0 的 `--validate-only` 语法检查，但从未启动运行。只用于隔离本地 Mock 研究。

**端口约定**：本项目保留 `27610-27620` 端口段，不使用 3000/8080 等常见开发端口；该段低于 Linux 临时端口范围（默认 32768–60999），不会被出站连接临时占用。`27610` 为本示例监听端口，`27619` 为本示例的占位上游（无进程监听），`27611-27618` 和 `27620` 由 P1 PoC 使用（见 `poc/p1/README.md`）。注意 agentgateway 1.6.0 和 1.7.0 的监听器都没有绑定地址字段，启动后端口对本机所有网卡开放，必须由网络层限制来源；1.7.0 在环境里没有 `SESSION_KEY` 时启动，还会把生成的密钥写进配置文件。

带 JWT、ExtAuthZ 与凭证注入、且**实际运行过**的配置见 `poc/p1/agentgateway.poc.yaml`。

真正的配置应由 `RouteIntent` / `PolicyBundle` 经受控 Adapter 编译，按受控版本读取官方 `https://agentgateway.dev/schema/config`，以真实 agentgateway CLI/实例验证 JWT、ExtAuthZ、上游认证与完整的 TLS/NetworkPolicy，再经批准发布。绝不能从这个 Demo 自动推导生产模板。

动态第三方凭证注入必须对官方 ExtAuthZ Header 接收机制进行验证；普通 CONNECT 透传不能替代 L7 应用认证。

## 生产预检新增要求

先运行 `python scripts/preflight_intents.py contracts/gateway/route-intent.example.json`；若返回 `STATIC_PREFLIGHT_OK_NOT_DEPLOYABLE`，仅表示**本地中立意图未发现已实现检查器可见的错误**。

预检对出站上游采用**白名单**：EGRESS 意图的 Provider、环境、上游主机与端口、Operation、方法、路径前缀和凭证绑定必须与 Provider 注册表中的一行完全吻合，否则拒绝。注册表默认取 `gateway/policies/egress-policy.example.json`，可用 `--provider-registry <file>` 指定；注册表为空则拒绝全部出站意图。保留域名/IP 黑名单仅作为第二道独立检查。

严禁因此跳过固定版本 agentgateway 官方 Schema/CLI/二进制运行、网络 Egress/DNS/TLS、Gatekeeper/PDP 多租户、流式协议及负载/安全验证。`gateway/policies/traffic-policy.example.json` 描述账户级额度意图，并没有启动任何分布式限流协调器。
