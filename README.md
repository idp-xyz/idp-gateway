# IDP Gateway

出站（Egress）API 网关：数据面用 agentgateway，本仓库是围绕它的 Go 代码、契约、部署配置和测试。

> **状态**：开发阶段。95 条正式验收用例与六个 STD-CP 门禁全部 `NOT_RUN`；三项运行验证（agentgateway、Gatekeeper 与 ExtAuthZ、Provider 沙箱）2026-11-19 起是 `RUN`，各自的保留见 [design-status.json](docs/governance/design-status.json)。ADR-0009 是 Accepted，其余 ADR-0001 至 0008 和 ADR-0010 至 0014 仍是 Proposed。  
> 设计基线交付包与 PoC 的原貌在标签 `baseline-v1.0-poc`；之后的目录结构见 [ADR-0009](docs/adr/ADR-0009.md)。

## 目录

| 目录 | 内容 |
|---|---|
| `cmd/gateway-authz` | 请求路径上的服务：agentgateway 的 HTTP ExtAuthZ 端点，判定后按请求发放 Provider 凭证（四种来源：固定 Bearer 令牌文件、开发者令牌加每个请求一个随机数、向令牌端点取的 OAuth2 客户端凭证令牌、顺丰国际开放平台的应用文件 `--sf-openapi-apps`，向承运商取访问令牌并交出 `Sf-OpenApi`）；另有一个改撤销表的接口，只认一个工作负载身份 |
| `cmd/provider-signer` | 网关和顺丰国际之间的适配器：拆开 `gateway-authz` 交出的 `Sf-OpenApi` 凭证，加密并签名正文，发给承运商，把应答解开。启动参数见 `deploy/providers/sfintl/README.md` |
| `internal/egressauthz` | 上面这个服务的判定规则、协议适配与端口 |
| `cmd/gateway-control` | 控制面的命令行，不在请求路径上。现在有十一条命令。前五条管的是单机上的一个池（ADR-0010 第 10 条）：`publish` 把一份网关配置发布上去，没生效就把上一份放回去；`restart` 发布要重启网关才生效的配置；`reconcile` 对账，池和记录对不上时把最后一次得到确认的那一份放回去；`place` 在网关启动之前把那一份放到位，由部署文件在启动时跑；`keep` 是常驻的看守，池里的容器死了它跑启动命令把它们起回来，平时定时对账，并在一个地址上给出指标供告警。后三条是操作员撤销 Provider 账户用的（ADR-0012 V1.2），各对着一个 `gateway-authz` 的撤销接口发一次请求，用撤销者自己的证书走双向 TLS：`revoke` 撤销一个账户（原因必填），`restore` 取消撤销，`revocations` 读整张表；结局和退出码见 `gateway-control revoke --help`，问不到时结局是“不知道”，不自动重试。最后三条是池的发布历史（ADR-0013）：`releases` 列出历史并与池的记录比，`release --id` 看一条和它的每一步，`rollback --to` 回到历史里一份到过生效的快照（是一次新的发布）；`publish`、`restart`、`reconcile`、`keep` 给了 `--history-dir` 就记，看守用它给停在半路的发布补上结局，不给就没有历史。RouteIntent 的编译、发布的状态和审批都还没有 |
| `internal/gatewayconfig` | 上面这个命令的规则、端口与适配：快照、运行配置的摘要、单机上的下发和记录、回读、发布前的离线加载、重启网关容器、看一个池的容器在不在跑并跑它的启动命令 |
| `internal/platform` | 与上下文无关的技术件 |
| `internal/architecture` | 包依赖方向的测试 |
| `contracts/` | OpenAPI 与 JSON Schema |
| `deploy/agentgateway/` | 数据面的版本锁定（`agentgateway.lock.json`：上游 1.7.0 的容器镜像，按摘要）与原生配置（目前只有一份示意样例） |
| `deploy/providers/wanbexpress/` | 为 1.1 的承运商万邦速达的沙箱手写的一份 agentgateway 配置和一份登记表样例，四个操作。对着替身在联调架子上跑过，也对着真实沙箱跑过；经 `gateway-control publish` 发布到 compose 池之后，对着替身和真实沙箱都跑过。证据在 `tests/integration/wanbexpress/evidence/`（`rig-standin.json`、`rig-sandbox.json`、`pool-standin.json`、`pool-sandbox.json`），见该目录 README |
| `deploy/providers/sfintl/` | 为 1.1 的第二家承运商顺丰国际手写的一份 agentgateway 配置和一份登记表样例，三个操作，上游是 `provider-signer`。对着替身在联调架子上跑过，也对着真实沙箱跑过；经 `gateway-control publish` 发布到 compose 池（叠加 `provider-signer.yml`）之后，对着替身和真实沙箱都跑过。证据在 `tests/integration/sfintl/evidence/`（`rig-standin.json`、`rig-sandbox.json`、`pool-standin.json`、`pool-sandbox.json`），见该目录 README |
| `deploy/compose/` | 单机上一个池的部署文件（docker compose；`gateway-authz.yml` 是 `gateway-authz` 的叠加文件）：网关、它前面的 nginx，和启动的先后；`pin-egress.sh` 装出口的规则；另有叠加文件 `provider-signer.yml`（顺丰国际的签名器：自己的网络命名空间，出口规则仍用这份脚本）；另有两个 systemd 单元，一个在开机时启动这个池，一个是看守；另有一份 Prometheus 告警规则，看的是看守给出的指标。两个单元没有装到哪台机器上跑过，告警送到谁那里也没有做，真的重启一台机器也没有验证过，见该目录 README |
| `tests/acceptance/` | 正式验收矩阵；`blackbox/` 是对着真实 agentgateway 跑的黑盒用例 |
| `tests/integration/gatekeeper/` | 与本机起的一套真实 Gatekeeper 的联调 |
| `tests/integration/wanbexpress/` | `deploy/providers/wanbexpress/` 的配置在联调架子上的套件：真实的 Gatekeeper、网关和 `gateway-authz`，承运商是替身；`--sandbox` 另可对着真实的沙箱跑（凭证文件在仓库之外），`--mutate` 做对照；`pool.py` 把同一份配置发布到 `deploy/compose` 的单机池上跑，并看出口规则 |
| `tests/integration/sfintl/` | `deploy/providers/sfintl/` 的配置在联调架子上的套件：真实的 Gatekeeper、网关、`gateway-authz` 和 `provider-signer`，承运商是替身；`--sandbox` 另可对着真实的沙箱跑（凭证文件在仓库之外；证据 `tests/integration/sfintl/evidence/rig-sandbox.json`），`--mutate` 做对照；`pool.py` 把同一份配置发布到 `deploy/compose` 的单机池上跑（叠加 `provider-signer.yml`），用 `gateway-control publish` 发布，并看签名器自己的出口规则。对着替身的证据是 `tests/integration/sfintl/evidence/pool-standin.json`，对着沙箱的是 `pool-sandbox.json`，见该目录 README |
| `tests/integration/kubernetes/` | 在本机的一个 kind 集群里验证 ADR-0010 在 Kubernetes 上的发布方式：不可变的快照，滚动替换，逐个副本回读 |
| `tests/integration/compose/` | 在本机用 docker compose 验证 ADR-0010 在单机上的做法，跑的就是 `deploy/compose` 的部署文件。发布：换掉挂载目录里的配置文件，网关不重启，经回读口确认。启动：先把确认过的那一份放到位，回读对上了才收请求。容器死了：看守把它们起回来。`cmd/gateway-control` 的五条命令都在这里对着真的网关跑，看守的指标和一个真的 Prometheus 也在这里；两个 systemd 单元之间的关系另由 `units.py` 在用户级的 systemd 里用替身命令跑；出口的规则是不是装上了，也由套件看（`SH-22`） |
| `tests/integration/egressnet/` | 在一个隔离的 docker 网络里看锁定的 agentgateway 1.7.0 按名字找后端、名字后来指到别处时去哪里，再看 `deploy/compose/pin-egress.sh` 拦不拦得住。解析器和服务器都是替身 |
| `tests/contracts`、`tests/security`、`scripts/` | 针对契约的离线检查与尚未移植的 Python 参考实现 |
| `docs/` | G01–G06 设计文档、[ADR](docs/adr/README.md)、[开发计划](docs/development-plan.md)、治理记录、运行手册 |

## 构建与测试

```bash
go build ./... && go vet ./... && go test ./...
go vet -tags acceptance ./... && go test -tags acceptance ./cmd/...        # 黑盒套件用的验收构建，不是产品

python3 -m venv .venv && .venv/bin/pip install -r requirements.txt        # 一次
.venv/bin/python -m unittest discover -s tests/contracts -p 'test_*.py'
.venv/bin/python -m unittest discover -s tests/security -p 'test_*.py'
.venv/bin/python tests/acceptance/blackbox/pin.py --fetch                  # 一次：从锁定的镜像里取出 agentgateway 二进制（需要 docker）
.venv/bin/python tests/acceptance/blackbox/run.py                          # 需要上面取出的二进制（见 deploy/agentgateway/README.md）、go 和 docker

tests/integration/gatekeeper/stack.sh up                                   # 本机起一套 Gatekeeper（需要它的只读检出）
.venv/bin/python tests/integration/gatekeeper/run.py                       # 与黑盒套件共用端口，不能同时跑
.venv/bin/python tests/integration/wanbexpress/run.py                       # 用同一套本机 Gatekeeper，承运商是替身；端口同上
.venv/bin/python tests/integration/sfintl/run.py                           # 用同一套本机 Gatekeeper，承运商是替身，中间是 provider-signer；端口同上

tests/integration/kubernetes/stack.sh up                                   # 本机起一个 kind 集群（自己的 kubeconfig，不动别的集群）
.venv/bin/python tests/integration/kubernetes/run.py                       # 约四分钟；跑完用 stack.sh down 删掉集群

.venv/bin/python tests/integration/compose/run.py                          # 十分钟左右；自己起 compose 项目，跑完自己拆（需要 docker 和 go）
python3 tests/integration/compose/units.py                                 # 一分钟左右；两个 systemd 单元之间的关系，命令换成替身（需要用户级的 systemd）

python3 scripts/agentgateway_release.py                                    # 锁定的 agentgateway 是否仍是上游最新发布版（要联网）
```

黑盒用例说明与最近一次结果见 [tests/acceptance/blackbox/README.md](tests/acceptance/blackbox/README.md)；与 Gatekeeper 联调的做法和结论见 [tests/integration/gatekeeper/README.md](tests/integration/gatekeeper/README.md)；Kubernetes 上的发布验证见 [tests/integration/kubernetes/README.md](tests/integration/kubernetes/README.md)；单机 docker compose 上的验证见 [tests/integration/compose/README.md](tests/integration/compose/README.md)，单机的部署文件怎么用见 [deploy/compose/README.md](deploy/compose/README.md)。本机用到的端口：示例配置 `27610`；黑盒和联调架子 `27611-27620`，本机 Gatekeeper `27621-27623`；compose 套件 `27618-27622`；egressnet `27630`；万邦的池 `27631-27634`；顺丰国际的池 `27641-27645`。重叠的不能同时跑。

已发布的 Gatekeeper（`gk.idp.xyz`）是生产环境：本仓库的任何测试都不访问它，联调只对本机实例。

## 读设计文档时要知道的

G01–G06 是 V1.0 设计基线的原文，只改过文件路径、两处提到的 agentgateway 版本（G03、G04；目标版本现在只有锁定的 1.7.0）和 G03 §7 里描述示例配置的一句话；2026-11-19 又按仓库所有者的决定，把"具名批准""签核"一类管项目自身的措辞改成"由仓库所有者决定"（[governance/README.md](docs/governance/README.md)），产品功能里的批准没有动。其中提到的 `portal/`、`tests/ux`、`tests/evidence`、`validate_baseline.py`、`build_html.py` 和各 HTML 页面已随 ADR-0009 移出主干，要看请检出标签 `baseline-v1.0-poc`。

| 文档 | 作用 |
|---|---|
| [G01 产品需求](docs/G01_Requirements.md) | 50 FR、19 NFR、范围与风险 |
| [G02 系统架构](docs/G02_Architecture.md) | 三平面权威、领域模型、失败与部署 |
| [G03 路由配置](docs/G03_Routing_and_Configuration.md) | RouteIntent、发布状态机、对账、回滚 |
| [G04 身份安全](docs/G04_Identity_and_Security.md) | 授权、凭证、威胁、缓存 |
| [G05 工程运维](docs/G05_Engineering_and_Operations.md) | 观测、CI/CD、SLO、HA |
| [G06 验收交付](docs/G06_Testing_and_Acceptance.md) | 需求到测试的追溯、门禁、证据规范 |
