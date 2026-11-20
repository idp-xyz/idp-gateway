# 架构决策记录（ADR）

> 每项决策的状态写在各篇正文开头。2026-11-21，仓库所有者把 ADR-0001 至 ADR-0008 定为 Accepted。ADR-0009 是 Accepted，它只决定仓库结构。同日，仓库所有者把 ADR-0010 至 ADR-0017 定为 Accepted。截至 2026-11-20，这八篇还是 Proposed，是设计建议，不是已经执行的技术审批、生产基线或运行验收。
>
> 2026-11-19 仓库所有者定：项目不用角色分离和具名批准，ADR 的状态由仓库所有者决定（[governance/README.md](../governance/README.md)）；各篇里"由仓库所有者决定""留给仓库所有者"就是这个意思。

| 编号 | 决策 |
|---|---|
| [ADR-0001](ADR-0001.md) | agentgateway 作为首选数据面实现 |
| [ADR-0002](ADR-0002.md) | Ingress / Egress / AI 分离部署 |
| [ADR-0003](ADR-0003.md) | Gatekeeper 为 IAM 与外部凭证权威 |
| [ADR-0004](ADR-0004.md) | 外部 API 默认经过统一 L7 Egress |
| [ADR-0005](ADR-0005.md) | 取消独立 BIP 产品 |
| [ADR-0006](ADR-0006.md) | Fabric 发布批准与 Gateway 运行配置解耦 |
| [ADR-0007](ADR-0007.md) | 零信任策略与失败默认拒绝 |
| [ADR-0008](ADR-0008.md) | 出站凭证经 HTTP ExtAuthZ 响应头按请求注入 |
| [ADR-0009](ADR-0009.md) | 进入开发阶段的仓库结构与 Go 技术基线 |
| [ADR-0010](ADR-0010.md) | 数据面用 standalone 模式，配置以不可变快照发布 |
| [ADR-0011](ADR-0011.md) | 出站凭证由 gateway-authz 持有，按账户现取 |
| [ADR-0012](ADR-0012.md) | 撤销状态由 gateway-authz 落盘，写入口只认一个工作负载身份 |
| [ADR-0013](ADR-0013.md) | 发布历史：先定端口和数据，第一个实现落在池旁边的文件里 |
| [ADR-0014](ADR-0014.md) | 要改写正文的承运商协议由受限的签名适配器承担（第一家：顺丰国际） |
| [ADR-0015](ADR-0015.md) | 用受控的文件同步保持 JWKS 更新与有界陈旧期（gateway-control sync-jwks） |
| [ADR-0016](ADR-0016.md) | RouteIntent 预检与出站配置编译器（gateway-control compile） |
| [ADR-0017](ADR-0017.md) | 出站流量治理：按账户限流、入口并发上限与承运商被动熔断 |

ADR-0001 至 0007 随原始设计基线交付。ADR-0008 是其后依据 [P1 PoC 报告](../../tests/acceptance/blackbox/README.md) 的实测结果提出的。ADR-0010 回答 ADR-0009 留下的部署形态问题，依据同一份报告里的配置回读用例和 [kind 集群上的发布验证](../../tests/integration/kubernetes/README.md)；它在 2026-11-11 做过一次技术复核并据此修订为 V1.1，那次复核不是决定。同日的 V1.2 记入了仓库所有者对运行平台的决定（先单机 docker compose，以后再上 Kubernetes）和[单机上的发布验证](../../tests/integration/compose/README.md)；这也不是决定。V1.3 记入写单机发布器（`cmd/gateway-control`）时看清的一条规则：快照里不能有对环境变量的引用；同样不是决定。2026-11-12 的 V1.4 记入发布器新增的对账和带重启的发布；同日的 V1.5 记入[单机的部署文件](../../deploy/compose/README.md)和它规定的启动先后（网关启动之前先把确认过的那一份配置放到位，回读对上了才收请求）；同日的 V1.6 记入看守（`gateway-control keep`）：池里的容器死了由它跑启动命令起回来，平时由它定时对账；2026-11-17 的 V1.7 记入告警：看守每看完一眼给出指标，由一份 Prometheus 规则决定什么时候该叫人。这四次同样不是决定。同日的 ADR-0011 提议出站凭证正文由 gateway-authz 持有、按账户现取；这也是提案，ADR-0003 与 ADR-0008 的正文没有改。仓库所有者在 2026-11-18 同意照它动手，那是开工的许可，不是决定。同日的 V1.1 记入它的第一步（固定令牌加每个请求一个随机数）的实现和对着替身的验证；承运商的沙箱没有被调用。同日的 ADR-0012 提议撤销状态存在哪里、谁能改，回答 ADR-0009 留下的另一半；仓库所有者当天同意照它动手，同样是开工的许可，不是决定。它的 V1.1 记入实现和在黑盒套件里的验证。2026-11-18 的 ADR-0011 V1.2 记入它的第二步（OAuth2 客户端凭证，向令牌端点取令牌、按账户缓存）的实现和对着替身令牌端点的验证；那是 2026-11-18 在 V1.1 那一步之后做的第二步，没有对着任何真实的令牌端点，同样不是决定。2026-11-18 的 ADR-0010 V1.8 记入出口的规则（网关所在的网络命名空间里，新的外出连接只许去配置里写着的地址，池因此多了两个服务）；它补记的是开发计划 3.1 已经做了的事，同样不是决定。2026-11-19 的 ADR-0012 V1.2 记入操作员撤销账户用的三条命令（`gateway-control revoke`、`restore`、`revocations`）：各对着 `gateway-authz` 的撤销接口发一次请求，“不知道”和“撤销已经生效但没有写下去”各是单独的结局；V1.1 写的“操作员的命令没有做”由它取代；状态仍是 Proposed。2026-11-19 的 ADR-0013 提议发布历史怎么存（应用层一个端口，第一个实现是池旁边的文件，Bento-Go 和 PostgreSQL 等第二台机器或接 Fabric 时再进来）；仓库所有者当天看过，把它列出的六项都定成照推荐的做，那是开工的许可，不是决定；写这一句时还没有动手。2026-11-19 的 ADR-0013 V1.1 记入它的两个阶段：Go 代码（`releases`、`release`、`rollback` 三条新命令，`publish`、`restart`、`reconcile`、`keep` 多了 `--history-dir`）和部署（只有看守和操作员的命令碰历史，开机的路上不碰），以及在真的池上的验证；状态仍是 Proposed，没有具名批准。2026-11-20 的 ADR-0014 提议：第二家承运商顺丰国际要求加密请求正文、对密文签名，这两件事放进一个新的、只用标准库的受限签名适配器进程（`provider-signer`），凭证仍只由 `gateway-authz` 持有，网关的既有防线不动；这在请求路径上多一个二进制。仓库所有者当天看过，把它列出的五项都定成照推荐的做，那是开工的许可，不是决定。V1.1 记入第零步到第二步：路由后端的 `backendTLS` 在锁定的 1.7.0 上会出示客户端证书；Go 代码、替身和联调架子上的套件；经网关对着真实沙箱的两遍（当时写入 [rig-sandbox.json](../../tests/integration/sfintl/evidence/rig-sandbox.json)，后来被提交 `e1b01ed` 覆盖，见 [套件 README](../../tests/integration/sfintl/README.md)）。同日的 V1.2 记入第三步：签名器在单机池里单独一个网络命名空间，出口规则用未改的 `pin-egress.sh` 只跑 `once`（没有常驻的再钉），配置经 `gateway-control publish` 发布，池上的套件对着替身跑过（当时写入 [pool-standin.json](../../tests/integration/sfintl/evidence/pool-standin.json)，后来被提交 `e1b01ed` 覆盖）。池上对着真实沙箱在 `7ec6f20` 上跑过，15 个用例、没有失败（当时写入 [pool-sandbox.json](../../tests/integration/sfintl/evidence/pool-sandbox.json)，后来被提交 `e1b01ed` 覆盖）。状态仍是 Proposed。ADR-0009 第 3 条的决定那一句没有改，同日在它下面记了一笔。同日的 ADR-0014 V1.3 记入面单 `IECS_PRINT_ORDER`（`labels.print`，提交 `95e2b90`）：写代码之前在仓库之外量过沙箱，网关只交回含 `data.url` 的 JSON，不代理 OSS；对着替身的联调架子是 14/14（327 项检查），池上是 15/15（307 项通过、2 项跳过）。四条路由的证据在提交 `e1b01ed`（跑在干净的 `4416f89`）：替身联调 14 个用例、327 项都过；替身池 15 个用例、309 项里 307 过、2 跳过；沙箱联调 14 个用例、275 项里 200 过、75 跳过；沙箱池 15 个用例、259 项里 189 过、70 跳过；没有剩下未取消的订单。逐项在 [tests/integration/sfintl/README.md](../../tests/integration/sfintl/README.md) 的「四条路由」和 [ADR-0014](ADR-0014.md) V1.3。同日的 ADR-0015 提议用 `gateway-control sync-jwks` 把 JWKS 写到文件，并给出有界的陈旧期（提交 `e94602e`）；Gatekeeper 联调 `GK-12` 连跑两遍通过，13/13，新密钥分别在 2.015 秒和 1.012 秒被接受，网关没有重启。同日的 ADR-0016 提议 RouteIntent 预检和出站配置编译器 `gateway-control compile`（提交 `e78d62e`）；万邦和顺丰各四条路由，编出来与手写的黄金文件结构相同，`native_validated` 为 true。同日的 ADR-0017 提议出站流量治理（提交 `6c5659d`）：`gateway-authz --rate-limits` 按账户限流，入口的并发上限和 `localRateLimit` 在锁定的 1.7.0 上生效，`provider-signer` 有被动熔断；静态 `host:` 的熔断没有生效。这四篇当时的状态仍是 Proposed。仓库所有者当天说「我没有第三家了，其他的全都做」，是开工的许可，不是决定。2026-11-21，仓库所有者把 ADR-0010 至 ADR-0017 定为 Accepted。当时 ADR-0001 至 ADR-0008 还是 Proposed。上文各处「状态仍是 Proposed」是记入当天的记录。同日，仓库所有者把 ADR-0001 至 ADR-0008 定为 Accepted。
