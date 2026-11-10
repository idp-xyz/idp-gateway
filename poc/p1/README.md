# P1 PoC — 真实 agentgateway 上的认证、授权与凭证注入

> **性质**：技术可行性 PoC，不是验收。`tests/acceptance_matrix.csv` 的 95 条用例与六个 STD-CP 门禁保持 `NOT_RUN`。
> **结果**：41 个用例，在 agentgateway 1.6.0 和 1.7.0 上各 40 PASS、1 FAIL（都是 `P1-SS-04`，见"未解决"）。证据：`evidence/p1-run-agentgateway-1.6.0.json`、`evidence/p1-run-agentgateway-1.7.0.json`。
> **环境**：agentgateway **1.6.0** 与 **1.7.0**（官方发布的二进制，SHA-256 与发布页公布的一致并记在证据里；同一份配置不加修改在两个版本上运行）、Mock Gatekeeper、Mock Provider，全部在本机回环地址。

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
| 换到设计目标 1.7.x 结论还成立吗？ | **在 1.7.0 上成立**。同一份配置两个版本都接受；41 个用例的每一项检查和观察到的状态码逐条相同，唯一的差别是下面"默认配置不安全的地方"第 6 项。 | 两份证据文件 |

## 默认配置不安全的地方

下面六项**不配置就是不安全的**，都是跑出来的，不是读文档读出来的。前五项的默认行为是在 1.6.0 上观察到的；1.7.0 上验证的是处理之后的配置同样有效，没有重测不处理时的默认行为。第 6 项是 1.7.0 新出现的。第 1、2 项是第一次运行的失败项；第 3、4 项是随后对照 G03 §5 把期望收紧才暴露的；第 5 项的"默认行为"来自一次单独的探测（一条不带任何策略的路由，把 `Cookie`、`X-Forwarded-*`、`Forwarded`、`Authorization`、`Host` 全部原样转发），这次探测不在证据文件里，证据文件只证明处理之后这些头不再到达 Provider。现在的 `agentgateway.poc.yaml` 已逐项处理。

1. **Host 原样转发**。上游收到的是调用方发来的 `Host: egress-api.idp.test`。必须为每条路由配置 `urlRewrite.authority`。
2. **路径不做规范性检查**。`%252e%252e`（双重编码）、`%00`、`;x=1` 被原样转发到上游。现在由两层拦截：路由 `authorization` 规则只放行由非保留字符组成、段不以点开头的路径；PDP 参考实现（`scripts/policy_reference.py`）用同一条规则。无 PDP 的模式 C 路由证明了网关这一层单独有效。带 ExtAuthZ 的路由上 PDP 先被调用，这些请求是被 PDP 拒绝的。
3. **PDP 放行但没给凭证时，请求照样转发**（不带任何凭证）。现在在 backend 上加了 `authorization` 规则，没有 `Authorization` 头就由网关拒绝。
4. **Provider 的 `Location`、`Set-Cookie` 原样回给调用方**。网关不跟随 302，但会把跳转目标交给调用方。现在用 `responseHeaderModifier.remove` 去掉。
5. **调用方的 `Cookie`、`X-Forwarded-*`、`Forwarded` 原样传给 Provider**。现在用 `requestHeaderModifier.remove` 去掉。
6. **（仅 1.7.0）没有会话密钥时，网关启动会改写自己的配置文件**。`config.session.key` 未设置时，1.7.0 生成一个密钥并写回启动它的那个文件；1.6.0 不会。第一次在 1.7.0 上运行时，仓库里受版本管理的 `agentgateway.poc.yaml` 就这样被加了三行（已还原，没有提交）。对按摘要审批、部署后回读对账的配置发布（G03）来说，这意味着运行中的文件不再是批准的那个文件，而且里面多了一个密钥。处理：用环境变量 `SESSION_KEY` 提供密钥，实测可阻止改写；`run_poc.py` 另外只让网关从 `.run/` 下的副本启动，仓库里的文件它碰不到。`P1-CF-01` 检查网关运行时所用的文件与仓库里的逐字节一致；证据的 `start_without_session_key_rewrites_config_file` 记录了每个版本在不提供密钥时的实际行为（1.6.0 为 `false`，1.7.0 为 `true`）。另外两个单独试过、不在证据文件里的观察：配置文件只读时 1.7.0 只记一条警告然后照常启动；`session.key: disabled` 只有 1.7.0 接受，1.6.0 会拒绝整份配置，所以两个版本共用的文件里不能这样写。

## 未解决

- **`P1-SS-04` FAIL：带两个 `Host` 头的请求被接受**（RFC 9112 §3.2 要求 400）。1.6.0 与 1.7.0 行为相同。网关用第一个做路由，第二个不会到达上游；上游 `Host` 已被第 1 项改写，所以没有形成越权，但请求本身应当被拒。配置层面没有办法：两个版本的配置 Schema 里都没有相关开关；CEL 规则里也识别不出来，`request.headers["host"]` 取不到值，`request.host` 只反映第一个（这是在两个版本上单独试验的结果，不在证据文件里）。需要在入口前置组件处理，或向上游提出。
- **请求头是"删黑名单"而不是"放白名单"**。G03 §5 要求只传播 Provider 允许的头。本 PoC 只做到了按名字删除，调用方的任意自定义头（如 `X-Client-Trace`）仍会到达 Provider。
- **监听地址无法限制**。1.6.0 和 1.7.0 的配置 Schema 都没有监听器的绑定地址字段，`27611` 对本机所有网卡开放（两份证据里都记录为 `*:27611`）。管理、指标、就绪端口可以也已经绑到 `127.0.0.1`。
- **PDP 不可用与策略拒绝无法区分**。PDP 超时或不在时调用方得到 403，与正常拒绝相同；PDP 返回 500 时调用方得到 500。G01 的失败来源区分（`GW-FR-043`）在这一点上没有满足。
- **规范路径规则很严**：不允许 `%`，所以路径段里不能有需要编码的字符。真实 Provider 的 Operation 如果需要，得按 Operation 单独登记放宽，不能全局放开。

## 没有覆盖

Gatekeeper 是 Mock（没有真实身份源、授权库、Secret Manager、Provider 令牌端点）；Provider 是回环 Mock；所有链路都没有 TLS/mTLS，网关到 PDP 用共享密钥代替工作负载 mTLS；单进程，没有多副本、配置滚动、限流、负载；没有 gRPC ExtAuthZ、决策缓存、CONNECT、gRPC 上游、HMAC 签名、mTLS 客户端身份；没有 DNS 重绑定和网络层出口 ACL。完整列表在证据文件的 `scope_limits`。

1.7.0 的发布说明里有一项与本 PoC 直接相关但没有试的新能力：`backendAuth.key.expression`，后端凭证由 CEL 表达式算出，可以取自外部授权服务返回的值。它可能让凭证不必作为请求头经过网关的头处理链，值得在 ADR-0008 批准前与现在的做法比较。

## 运行

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt   # 一次
.venv/bin/python poc/p1/run_poc.py                                   # PATH 上的 agentgateway；约 20 秒；全部通过才返回 0
.venv/bin/python poc/p1/run_poc.py --agentgateway /path/to/agentgateway   # 换一个版本的二进制
```

每个 agentgateway 版本写各自的证据文件 `evidence/p1-run-agentgateway-<版本>.json`。本机的 1.6.0 在 `/usr/local/bin`；1.7.0 是从官方发布页下载、核对 SHA-256 后放在用户目录下的，没有替换系统里的 1.6.0。

脚本先检查端口段是否空闲、用 `--validate-only` 校验配置，再启动四个进程，跑完全部停掉。网关从 `poc/p1/.run/` 下的配置副本启动，会话密钥经环境变量 `SESSION_KEY` 提供（原因见上面第 6 项）。每次运行生成新的签名密钥、会话密钥和 Mock 凭证，放在 `poc/p1/.run/`（已忽略），不写入证据。

| 端口 | 用途 |
|---|---|
| 27611 | 网关监听（所有网卡，见"未解决"） |
| 27612 | Mock Provider |
| 27613 | Mock Gatekeeper（ExtAuthZ） |
| 27614 / 27615 / 27616 | 网关管理 / 指标 / 就绪（仅回环） |
| 27617 | "禁止目标"：任何路由都不该到达，用来证明没有越权出站 |

`27610`、`27619` 由 `gateway/config/agentgateway.local.example.yaml` 使用，`27618` 空闲。

端口段选在 `27610-27619`，是因为它低于内核给出站连接分配源端口的临时端口范围（本机为 44620–48715，Linux 默认 32768–60999）。最初用的是 `47611-47617`，落在本机临时范围内：有一次运行中网关绑定就绪端口 47616 时报 `Address in use`、整轮没跑起来，而该端口在运行前后都是空闲的。占用者没有被直接抓到，最可能的解释是某个出站连接临时拿它做了源端口。脚本现在会在端口段与临时范围重叠时拒绝启动。

## 文件

- `agentgateway.poc.yaml`：原生配置，三条路由（两条模式 A，一条模式 C）。
- `mock_gatekeeper.py`：HTTP ExtAuthZ Mock，决策用 `scripts/policy_reference.py`；线上形态见 `contracts/gatekeeper/openapi.yaml` 的 `/v1/extauthz/check`。
- `mock_provider.py`：记录收到的每个请求；`policy.poc.json`：两租户两账户的授权数据。
- `run_poc.py`：用例与期望。`evidence/p1-run-agentgateway-<版本>.json`：该版本最近一次运行的逐项检查与观察值，含二进制与配置的 SHA-256。

## 期望是怎么定的

期望取自 G01/G03/G04，写在 `run_poc.py` 里，不达标记 FAIL，不改期望迁就结果。运行历史：

1. 第一次运行 37/39。失败的是 Host 转发和路径绕过（上面第 1、2 项），据此改了网关配置和 PDP 参考实现。
2. 随后对照 G03 §5 **收紧**了三处期望（无凭证时必须由网关拒绝、`Location` 不得回给调用方、`X-Forwarded-*` 不得传给 Provider），并新增 `P1-SS-04`。收紧后暴露出第 3、4 项和重复 `Host` 的问题；第 5 项的处理与检查是同时加上的。
3. 在 1.6.0 上定格为 39/40。
4. 把同一份配置和同一套用例原样拿到 1.7.0 上：同样是 39/40，失败的同样是 `P1-SS-04`。这次运行暴露了第 6 项，据此新增 `P1-CF-01`，并把网关改为从副本启动、经环境变量拿会话密钥。
5. 当前两个版本都是 40/41。没有任何期望被放宽过。

`validate_baseline.py` 会核对每份证据里的配置、策略哈希与仓库当前文件一致；改了配置或 `policy_reference.py` 之后，两个版本都要重跑。
