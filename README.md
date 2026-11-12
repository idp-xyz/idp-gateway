# IDP Gateway

出站（Egress）API 网关：数据面用 agentgateway，本仓库是围绕它的 Go 代码、契约、部署配置和测试。

> **状态**：开发早期。95 条正式验收用例与六个 STD-CP 门禁全部 `NOT_RUN`；ADR-0001 至 0008 和 ADR-0010 仍是 Proposed。  
> 设计基线交付包与 PoC 的原貌在标签 `baseline-v1.0-poc`；之后的目录结构见 [ADR-0009](docs/adr/ADR-0009.md)。

## 目录

| 目录 | 内容 |
|---|---|
| `cmd/gateway-authz` | 请求路径上的服务：agentgateway 的 HTTP ExtAuthZ 端点，判定后按请求发放 Provider 凭证 |
| `internal/egressauthz` | 上面这个服务的判定规则、协议适配与端口 |
| `cmd/gateway-control` | 控制面的命令行，不在请求路径上。现在有四条命令，管的是单机上的一个池（ADR-0010 第 10 条）：`publish` 把一份网关配置发布上去，没生效就把上一份放回去；`restart` 发布要重启网关才生效的配置；`reconcile` 对账，池和记录对不上时把最后一次得到确认的那一份放回去；`place` 在网关启动之前把那一份放到位，由部署文件在启动时跑。RouteIntent 的编译、发布的状态和审批都还没有 |
| `internal/gatewayconfig` | 上面这个命令的规则、端口与适配：快照、运行配置的摘要、单机上的下发和记录、回读、发布前的离线加载、重启网关容器 |
| `internal/platform` | 与上下文无关的技术件 |
| `internal/architecture` | 包依赖方向的测试 |
| `contracts/` | OpenAPI 与 JSON Schema |
| `deploy/agentgateway/` | 数据面的版本锁定（`agentgateway.lock.json`：上游 1.7.0 的容器镜像，按摘要）与原生配置（目前只有一份示意样例） |
| `deploy/compose/` | 单机上一个池的部署文件（docker compose）：网关、它前面的 nginx，和启动的先后；另有开机用的 systemd 单元。真的重启一台机器没有验证过，见该目录 README |
| `tests/acceptance/` | 正式验收矩阵；`blackbox/` 是对着真实 agentgateway 跑的黑盒用例 |
| `tests/integration/gatekeeper/` | 与本机起的一套真实 Gatekeeper 的联调 |
| `tests/integration/kubernetes/` | 在本机的一个 kind 集群里验证 ADR-0010 在 Kubernetes 上的发布方式：不可变的快照，滚动替换，逐个副本回读 |
| `tests/integration/compose/` | 在本机用 docker compose 验证 ADR-0010 在单机上的做法，跑的就是 `deploy/compose` 的部署文件。发布：换掉挂载目录里的配置文件，网关不重启，经回读口确认。启动：先把确认过的那一份放到位，回读对上了才收请求。`cmd/gateway-control` 的四条命令都在这里对着真的网关跑 |
| `tests/contracts`、`tests/security`、`scripts/` | 针对契约的离线检查与尚未移植的 Python 参考实现 |
| `docs/` | G01–G06 设计文档、[ADR](docs/adr/README.md)、治理记录、运行手册 |

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

tests/integration/kubernetes/stack.sh up                                   # 本机起一个 kind 集群（自己的 kubeconfig，不动别的集群）
.venv/bin/python tests/integration/kubernetes/run.py                       # 约四分钟；跑完用 stack.sh down 删掉集群

.venv/bin/python tests/integration/compose/run.py                          # 六分钟左右；自己起 compose 项目，跑完自己拆（需要 docker 和 go）

python3 scripts/agentgateway_release.py                                    # 锁定的 agentgateway 是否仍是上游最新发布版（要联网）
```

黑盒用例说明与最近一次结果见 [tests/acceptance/blackbox/README.md](tests/acceptance/blackbox/README.md)；与 Gatekeeper 联调的做法和结论见 [tests/integration/gatekeeper/README.md](tests/integration/gatekeeper/README.md)；Kubernetes 上的发布验证见 [tests/integration/kubernetes/README.md](tests/integration/kubernetes/README.md)；单机 docker compose 上的验证见 [tests/integration/compose/README.md](tests/integration/compose/README.md)，单机的部署文件怎么用见 [deploy/compose/README.md](deploy/compose/README.md)。本项目在本机只使用 `27610-27622` 端口段；四套用例共用其中的端口，不能同时跑。

已发布的 Gatekeeper（`gk.idp.xyz`）是生产环境：本仓库的任何测试都不访问它，联调只对本机实例。

## 读设计文档时要知道的

G01–G06 是 V1.0 设计基线的原文，只改过文件路径、两处提到的 agentgateway 版本（G03、G04；目标版本现在只有锁定的 1.7.0）和 G03 §7 里描述示例配置的一句话。其中提到的 `portal/`、`tests/ux`、`tests/evidence`、`validate_baseline.py`、`build_html.py` 和各 HTML 页面已随 ADR-0009 移出主干，要看请检出标签 `baseline-v1.0-poc`。

| 文档 | 作用 |
|---|---|
| [G01 产品需求](docs/G01_Requirements.md) | 50 FR、19 NFR、范围与风险 |
| [G02 系统架构](docs/G02_Architecture.md) | 三平面权威、领域模型、失败与部署 |
| [G03 路由配置](docs/G03_Routing_and_Configuration.md) | RouteIntent、发布状态机、对账、回滚 |
| [G04 身份安全](docs/G04_Identity_and_Security.md) | 授权、凭证、威胁、缓存 |
| [G05 工程运维](docs/G05_Engineering_and_Operations.md) | 观测、CI/CD、SLO、HA |
| [G06 验收交付](docs/G06_Testing_and_Acceptance.md) | 需求到测试的追溯、门禁、证据规范 |
