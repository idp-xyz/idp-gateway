# P1 PoC — 真实 agentgateway 上的认证、授权与凭证注入

> **性质**：技术可行性 PoC，不是验收。`tests/acceptance_matrix.csv` 的 95 条用例与六个 STD-CP 门禁保持 `NOT_RUN`。
> **结果**：40 个用例，39 PASS，1 FAIL（`P1-SS-04`，见"未解决"）。证据：`evidence/p1-run.json`。
> **环境**：agentgateway **1.6.0**（本机已安装的版本；设计目标 1.7.x 未测）、Mock Gatekeeper、Mock Provider，全部在本机回环地址。

## 回答了什么问题

G04 §4 要求用 PoC 比较三种凭证返回模式，G04 §9 列了 PoC 必须证明的结论。本 PoC 的回答：

| 问题 | 结论 | 依据 |
|---|---|---|
| agentgateway 能否按请求注入由 PDP 选定的第三方凭证（模式 A）？ | **能**。HTTP ExtAuthZ 的允许响应带 `Authorization` 头，网关按 `includeResponseHeaders` 把它（且只把它）写到上游请求。 | `P1-AZ-01/02/04`、`P1-CR-01` |
| 两租户、两账户能否隔离？ | **能**。租户身份取自已验签 JWT；蓝租户请求绿账户被拒；撤销蓝账户后下一个蓝请求即被拒，绿不受影响。 | `P1-AZ-03`、`P1-RV-01` |
| 调用方能否伪造租户或可信上下文？ | **不能**。伪造的 `x-idp-*`、`X-Tenant-ID` 到不了 PDP；PDP 看到的是网关按 JWT 声明和路由常量写入的值。 | `P1-AZ-05` |
| 内部 JWT 会不会到第三方？第三方凭证会不会回到调用方？ | **都不会**。Provider 只收到 Provider 凭证；PDP 收到的是网关工作负载凭证而非调用方 JWT。 | `P1-CR-01/02/03` |
| PDP 故障时是否默认拒绝？ | **是**。PDP 返回 500、超时、进程不在，请求都没有到达 Provider。 | `P1-FC-01/02/03` |
| 非幂等写会不会被网关重放？ | **不会**（未配置重试策略时）。上游超时返回 504、上游断连返回 503，Provider 各只收到一次。 | `P1-WR-02/03` |
| 固定凭证（模式 C）够不够？ | **只够单账户**。跑得通，但两个租户以同一个账户到达 Provider。 | `P1-MC-01` |
| 模式 B（本地 Broker/Sidecar）？ | **未测**。 | — |

## 默认配置不安全的地方

下面五项在 agentgateway 1.6.0 上**不配置就是不安全的**，都是跑出来的，不是读文档读出来的。第 1、2 项是第一次运行的失败项；第 3、4 项是随后对照 G03 §5 把期望收紧才暴露的；第 5 项的"默认行为"来自一次单独的探测（一条不带任何策略的路由，把 `Cookie`、`X-Forwarded-*`、`Forwarded`、`Authorization`、`Host` 全部原样转发），这次探测不在证据文件里，证据文件只证明处理之后这些头不再到达 Provider。现在的 `agentgateway.poc.yaml` 已逐项处理。

1. **Host 原样转发**。上游收到的是调用方发来的 `Host: egress-api.idp.test`。必须为每条路由配置 `urlRewrite.authority`。
2. **路径不做规范性检查**。`%252e%252e`（双重编码）、`%00`、`;x=1` 被原样转发到上游。现在由两层拦截：路由 `authorization` 规则只放行由非保留字符组成、段不以点开头的路径；PDP 参考实现（`scripts/policy_reference.py`）用同一条规则。无 PDP 的模式 C 路由证明了网关这一层单独有效。带 ExtAuthZ 的路由上 PDP 先被调用，这些请求是被 PDP 拒绝的。
3. **PDP 放行但没给凭证时，请求照样转发**（不带任何凭证）。现在在 backend 上加了 `authorization` 规则，没有 `Authorization` 头就由网关拒绝。
4. **Provider 的 `Location`、`Set-Cookie` 原样回给调用方**。网关不跟随 302，但会把跳转目标交给调用方。现在用 `responseHeaderModifier.remove` 去掉。
5. **调用方的 `Cookie`、`X-Forwarded-*`、`Forwarded` 原样传给 Provider**。现在用 `requestHeaderModifier.remove` 去掉。

## 未解决

- **`P1-SS-04` FAIL：带两个 `Host` 头的请求被接受**（RFC 9112 §3.2 要求 400）。网关用第一个做路由；上游 `Host` 已被第 1 项改写，所以没有形成越权，但请求本身应当被拒。1.6.0 的配置里没找到拒绝它的办法，需要在入口前置组件处理或向上游确认。
- **请求头是"删黑名单"而不是"放白名单"**。G03 §5 要求只传播 Provider 允许的头。本 PoC 只做到了按名字删除，调用方的任意自定义头（如 `X-Client-Trace`）仍会到达 Provider。
- **监听地址无法限制**。1.6.0 的 `gateways.<name>` 和 `binds[]` 都没有绑定地址字段，`47611` 对本机所有网卡开放（证据里记录为 `*:47611`）。管理、指标、就绪端口可以也已经绑到 `127.0.0.1`。
- **PDP 不可用与策略拒绝无法区分**。PDP 超时或不在时调用方得到 403，与正常拒绝相同；PDP 返回 500 时调用方得到 500。G01 的失败来源区分（`GW-FR-043`）在这一点上没有满足。
- **规范路径规则很严**：不允许 `%`，所以路径段里不能有需要编码的字符。真实 Provider 的 Operation 如果需要，得按 Operation 单独登记放宽，不能全局放开。

## 没有覆盖

Gatekeeper 是 Mock（没有真实身份源、授权库、Secret Manager、Provider 令牌端点）；Provider 是回环 Mock；所有链路都没有 TLS/mTLS，网关到 PDP 用共享密钥代替工作负载 mTLS；单进程，没有多副本、配置滚动、限流、负载；没有 gRPC ExtAuthZ、决策缓存、CONNECT、gRPC 上游、HMAC 签名、mTLS 客户端身份；没有 DNS 重绑定和网络层出口 ACL。完整列表在证据文件的 `scope_limits`。

## 运行

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt   # 一次
.venv/bin/python poc/p1/run_poc.py                                   # 约 20 秒；全部通过才返回 0
```

需要 `agentgateway` 在 `PATH` 上。脚本先检查端口段是否空闲、用 `agentgateway --validate-only` 校验配置，再启动四个进程，跑完全部停掉。每次运行生成新的签名密钥和 Mock 凭证，放在 `poc/p1/.run/`（已忽略），不写入证据。

| 端口 | 用途 |
|---|---|
| 47611 | 网关监听（所有网卡，见"未解决"） |
| 47612 | Mock Provider |
| 47613 | Mock Gatekeeper（ExtAuthZ） |
| 47614 / 47615 / 47616 | 网关管理 / 指标 / 就绪（仅回环） |
| 47617 | "禁止目标"：任何路由都不该到达，用来证明没有越权出站 |

`47610`、`47619` 由 `gateway/config/agentgateway.local.example.yaml` 使用，`47618` 空闲。

## 文件

- `agentgateway.poc.yaml`：原生配置，三条路由（两条模式 A，一条模式 C）。
- `mock_gatekeeper.py`：HTTP ExtAuthZ Mock，决策用 `scripts/policy_reference.py`；线上形态见 `contracts/gatekeeper/openapi.yaml` 的 `/v1/extauthz/check`。
- `mock_provider.py`：记录收到的每个请求；`policy.poc.json`：两租户两账户的授权数据。
- `run_poc.py`：用例与期望。`evidence/p1-run.json`：最近一次运行的逐项检查与观察值，含二进制与配置的 SHA-256。

## 期望是怎么定的

期望取自 G01/G03/G04，写在 `run_poc.py` 里，不达标记 FAIL，不改期望迁就结果。运行历史：

1. 第一次运行 37/39。失败的是 Host 转发和路径绕过（上面第 1、2 项），据此改了网关配置和 PDP 参考实现。
2. 随后对照 G03 §5 **收紧**了三处期望（无凭证时必须由网关拒绝、`Location` 不得回给调用方、`X-Forwarded-*` 不得传给 Provider），并新增 `P1-SS-04`。收紧后暴露出第 3、4 项和重复 `Host` 的问题；第 5 项的处理与检查是同时加上的。
3. 当前 39/40。没有任何期望被放宽过。

`validate_baseline.py` 会核对证据里的配置、策略哈希与仓库当前文件一致；改了配置或 `policy_reference.py` 之后要重跑 PoC。
