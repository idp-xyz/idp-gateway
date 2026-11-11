# agentgateway：版本锁定与配置例子

## 版本锁定

本项目只对着一个 agentgateway 发布版开发和测试，写在 `agentgateway.lock.json` 里：

| 字段 | 内容 |
|---|---|
| `version`、`git_revision` | 发布版号，以及该二进制用 `--version` 报告的提交 |
| `release`、`released` | 上游发布页与发布日期 |
| `sha256` | 用到的发布产物各自的 SHA-256，与发布页公布的一致；目前只有 `agentgateway-linux-amd64` |

当前锁定 **1.7.0**。2026-11-11 核对时它是上游最新的正式发布版。

黑盒套件和 Gatekeeper 联调在启动网关之前都会核对二进制（`tests/acceptance/blackbox/pin.py`）：版本、提交、SHA-256 有一项与锁定文件对不上就拒绝运行。它们先找 `~/.local/opt/agentgateway/<version>/agentgateway`，没有再找 `PATH` 上的 `agentgateway`；先找到的那个不是锁定的发布版时直接报错，不再往下找。

换版本时：

- 只跟上游的正式发布版，不用预发布版。先读新版本发布说明里的破坏性变更。
- `agentgateway.lock.json` 的各个字段一起改，`docs/governance/project-manifest.json` 里 `AGENTGATEWAY` 的 `version` 和 `source` 跟着改（`tests/contracts` 里有一条测试检查两处一致）。
- 把新二进制放到上面的路径，重跑黑盒套件和联调；旧版本的证据文件删掉，不留作对照。

这份锁定只决定开发和测试用哪个二进制。来源方面只核对了二进制与发布页公布的摘要一致；G05 §7 要求的许可证、依赖漏洞核查和具名批准都没有做，容器镜像的 digest 也没有锁。

## 配置例子（安全警告）

`agentgateway.local.example.yaml` 仅供展示 Standalone 路由语法轮廓，**并非可以直接暴露给业务网络的受保护 Gateway**：当前示例没有 JWT/ExtAuthZ、TLS、真实 Secret Manager 对接。它已通过 agentgateway 1.7.0 的 `--validate-only` 语法检查，但从未启动运行。只用于隔离本地 Mock 研究。

**端口约定**：本项目保留 `27610-27620` 端口段，不使用 3000/8080 等常见开发端口；该段低于 Linux 临时端口范围（默认 32768–60999），不会被出站连接临时占用。`27610` 为本示例监听端口，`27619` 为本示例的占位上游（无进程监听），`27611-27618` 和 `27620` 由 P1 PoC 使用（见 `tests/acceptance/blackbox/README.md`）。注意 agentgateway 的监听器没有绑定地址字段，启动后端口对本机所有网卡开放，必须由网络层限制来源；在环境里没有 `SESSION_KEY` 时启动，它还会把生成的密钥写进配置文件。

带 JWT、ExtAuthZ 与凭证注入、且**实际运行过**的配置见 `tests/acceptance/blackbox/agentgateway.poc.yaml`。

真正的配置应由 `RouteIntent` / `PolicyBundle` 经受控 Adapter 编译，按受控版本读取官方 `https://agentgateway.dev/schema/config`，以真实 agentgateway CLI/实例验证 JWT、ExtAuthZ、上游认证与完整的 TLS/NetworkPolicy，再经批准发布。绝不能从这个 Demo 自动推导生产模板。

动态第三方凭证注入必须对官方 ExtAuthZ Header 接收机制进行验证；普通 CONNECT 透传不能替代 L7 应用认证。

## 生产预检新增要求

先运行 `python scripts/preflight_intents.py contracts/gateway/route-intent.example.json`；若返回 `STATIC_PREFLIGHT_OK_NOT_DEPLOYABLE`，仅表示**本地中立意图未发现已实现检查器可见的错误**。

预检对出站上游采用**白名单**：EGRESS 意图的 Provider、环境、上游主机与端口、Operation、方法、路径前缀和凭证绑定必须与 Provider 注册表中的一行完全吻合，否则拒绝。注册表默认取 `contracts/gateway/policies/egress-policy.example.json`，可用 `--provider-registry <file>` 指定；注册表为空则拒绝全部出站意图。保留域名/IP 黑名单仅作为第二道独立检查。

严禁因此跳过固定版本 agentgateway 官方 Schema/CLI/二进制运行、网络 Egress/DNS/TLS、Gatekeeper/PDP 多租户、流式协议及负载/安全验证。`contracts/gateway/policies/traffic-policy.example.json` 描述账户级额度意图，并没有启动任何分布式限流协调器。
