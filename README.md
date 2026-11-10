# IDP Gateway — 工程设计基线 V1.0

> **IDP Gateway** / agentgateway 首选候选 / Go Control & Gatekeeper 适配 / 2026-11-10  
> **状态：设计候选（DESIGN_DRAFT）· NOT APPROVED · 正式验收与全部门禁 NOT_RUN**  
> P1 PoC 已在 agentgateway 1.6.0 与 1.7.0 + Mock Gatekeeper/Provider 上运行（1.7.0：50 个用例 49 个通过；1.6.0：跑了 47 个、46 个通过；有未解决项），见 [poc/p1/README.md](poc/p1/README.md)；它不是验收证据。

本包是按 **IDP-SCG-STD-001《供应链 DDD 产品与工程设计统一规范 V1.0》** 建立的第一版 **可审查、可追溯、可静态校验** 工程基线。不是部署好的网关，也不证明已通过 Gatekeeper/Provider 实际集成、安全或性能测试。

## 核心决策

- 首选 agentgateway **官方开源**通用代理数据面；保留变更选型的 ADR 机制，不自研 Go 代理内核。
- Gatekeeper 统一身份与外部 API 账户使用授权，Secret Manager 保护密钥；Gateway 执行代理认证、外发凭证附加。
- 各业务应用使用 DDD Port/ACL，默认通过统一 Egress 逻辑地址访问登记的第三方 REST/gRPC API；不强制内部所有服务互调绕行。
- Fabric 负责契约、Catalog、Release、Publication 和审批；Ingress/Egress/AI 独立部署实例池。
- **取消独立 BIP 平台**；需复杂 EDI/SFTP/批量同步时以领域专用 Connector/Worker 实现。

## 文档索引

| 章节 | 作用 |
|---|---|
| [G01 产品需求](docs/G01_Requirements.md) | 50 FR、19 NFR、范围、风险与 PoC 验收 |
| [G02 系统架构](docs/G02_Architecture.md) | Context Map、三平面权威、领域模型、失败与部署 |
| [G03 路由配置](docs/G03_Routing_and_Configuration.md) | RouteIntent、发布状态机、L7/CONNECT、对账、回滚 |
| [G04 身份安全](docs/G04_Identity_and_Security.md) | Gatekeeper 授权/凭证、威胁、缓存、Broker、Token |
| [G05 工程运维](docs/G05_Engineering_and_Operations.md) | Go DDD 结构、观测、CI/CD、SLO、HA、Runbook |
| [G06 验收交付](docs/G06_Testing_and_Acceptance.md) | 需求→测试追溯、门禁、真实证据规范 |

**其它资产**：[`decisions/`](decisions/README.md)（ADR-0001..0008）、`poc/p1/`（P1 PoC）、`governance/project-manifest.json`、`contracts/` (OpenAPI/JSON Schema)、`gateway/config/`（仅示意）、`gateway/policies/`、`tests/acceptance_matrix.csv`、`scripts/validate_baseline.py`、`scripts/build_html.py`。

## 离线静态验证

```bash
python3 scripts/validate_baseline.py
python3 -m unittest discover -s tests/security -p 'test_*.py'
```

这只验证本包资产结构与 Mock 安全策略，不验证真实 agentgateway 行为。启动真实服务前须固定具体 1.7.x 版本/镜像 digest 并执行官方 schema/CLI 校验。

依赖见 `requirements.txt`（`python3 -m venv .venv && .venv/bin/pip install -r requirements.txt`，之后用 `.venv/bin/python` 运行上面的命令）。真实 agentgateway 上的 PoC：`.venv/bin/python poc/p1/run_poc.py`（需要本机有 docker，用来运行网关前面的 nginx）。本项目只使用 `27610-27620` 端口段。

## 阅读顺序

建议从离线 [index.html](index.html) 进入；浏览器不联网也能打开正文和本包生成的 SVG 图。也可以只打开单文件的 [离线阅读器](IDP_Gateway_V1.0_Offline_Reader.html)。

Markdown 是源，HTML 是生成物：改了 Markdown 之后运行 `.venv/bin/python scripts/build_html.py`，它重新生成各页面的正文、侧边栏导航和离线阅读器的各章节，页面外壳的其余部分（页眉、页脚、样式）保持不动；`validate_baseline.py` 会在 HTML 落后于 Markdown 时报错。要给另一份 Markdown 生成页面，在该脚本的 `PAGES` 里加一行；要改侧边栏，改该脚本的 `NAV`。`index.html` 没有 Markdown 源，只有侧边栏由脚本生成，其余手工维护；`portal/prototypes/` 脚本不碰。

## Gateway Operations UI/UX（同版增补）

- [统一 Gateway Console 离线交互原型](portal/prototypes/gateway-operations.html)（所有 KPI/权限/审批/实例均 Mock）
- [UI/UX 产品与工程规格](portal/spec/Gateway_Operations_UX_Spec_V1.0.md)
- [75 条 UX 验收矩阵](tests/ux/acceptance_matrix.csv)，正式验收 `NOT_RUN`
- [门户目录说明](portal/README.md)

不新建 Gateway Portal；建议在既有 Engineering Portal 下增加 Gateway Operations 模块。新增 UI 专业体验标准 STD-CP4 适用，但测试和具名验收尚未完成。

## agentgateway 开源 UI 能力完整纳入自研管理体验的设计方向（同版增补）

- 不 Fork agentgateway UI，不复制底层 Rust 代理。对开源 UI 的 Gateway、Traffic、LLM、MCP、Tools 功能进行能力映射，使用我们自己的信息架构与交互。
- [统一 Gateway Console 原型](portal/prototypes/gateway-operations.html)：保留原六页并扩展至 18 个导航页面，均为离线 Mock。
- [能力矩阵与集成边界](portal/spec/Agentgateway_UI_Capability_Matrix_V1.0.md)：注明官方能力、IDP 自研能力及需要真实 API 接入的事项。
- Go 管理层应使用版本化 Provider Adapter，并实现单一配置发布权威，禁止原生 UI 与自研 Console 同时直写生产配置。
- 本轮增补仅执行前端原型与本地测试；实际可用性、安全、负载和生产发布均保持 `NOT_RUN`。

## Traffic Explorer — Message Inspector 同版增补

已在同一原型的 Traffic Explorer 中新增四阶段的 Header / Body 报文对照（**全部合成 Mock，不是生产抓包**）：应用入站、Gateway 外发、第三方响应、Gateway 返回。支持 401/403 未发上游、504 写操作 `UNKNOWN`、角色限制和脱敏 JSON 示例导出；见 `portal/previews/10_message_inspector.png`。正式的报文采集、服务端隔离、加密存储、按需捕获与 gRPC 观测均仍须真实实施与验收（`NOT_RUN`）。


## 本版 P0/P1 生产缺口补强（不新增版本）

- **50 FR / 19 NFR**；**95 条**运行验收、**75 条** UX 正式验收；原来的 G01–G06 与历史编号保持不变。
- 新的 RouteIntent `oneOf` 分支（INGRESS/EGRESS/AI）、三组合法示例及错误配置反例；Fabric OpenAPI 改为引用这份唯一的契约权威。
- Gatekeeper `credentials/prepare` 类型化候选契约（OAuth2/API Key、Signer、mTLS Reference）；`materialize` 标记为不完整的旧候选，**不允许直接部署**。P1 PoC 之后，Header 注入类凭证的下发路径改定为 ExtAuthZ 允许响应头，见 `decisions/ADR-0008.md`（Proposed）。
- `gateway/policies/traffic-policy.*`、`diagnostic-capture.*`、`credential-binding.*` 与四阶段诊断事件 Schema。
- `scripts/preflight_intents.py`：**静态预检，不输出原生代理配置**；`tests/contracts/` 与 `tests/security/` 中有更多可执行负向测试。
- `governance/gap-remediation-matrix.csv`（15 个缺口）、协议清单、故障演练、`operations/incident-runbook.md`。
- Console 在 Traffic Explorer 同页新增 ProviderAccount Quota、Upstream Health 和 Config Drift 的**合成 Mock 视图**。

**重要**：这批改善只完成设计、契约、离线 Mock 和检查；真实 Gatekeeper Credential Broker、环境网络策略、限流协调器与安全报文采集均未实现、未联测。agentgateway 二进制此后只在 P1 PoC 中用过（1.6.0 与 1.7.0，对接 Mock Gatekeeper/Provider，见 `poc/p1/README.md`）；具体版本尚未锁定，由 RouteIntent 编译原生配置的 Publisher 仍未实现、未验证。


## 新增离线测试与文档入口

```bash
cd idp-gateway
python3 scripts/preflight_intents.py contracts/gateway/route-intent.example.json
python3 scripts/validate_baseline.py
python3 -m unittest discover -s tests/contracts -p 'test_*.py'
python3 -m unittest discover -s tests/security -p 'test_*.py'
```

- [15 项缺口与需求对应清单](governance/gap-remediation-matrix.csv)
- [上线前故障处置 Runbook](operations/incident-runbook.md)
- [HTTP/gRPC/Streaming 兼容清单](tests/protocol-compatibility.csv)
- [账户/网关/授权/网络故障演练清单](tests/operational-exercises.csv)
- [新 Traffic Governance 合成看板截图](portal/previews/11_traffic_governance.png)

**所有结果均是离线、本地、Mock 或静态验证，不代表已部署或达到生产 SLO。**

## 成对请求 / 响应诊断

[Traffic Explorer](portal/prototypes/gateway-operations.html) 的 Message Inspector 按两个 Hop 并排显示 Request / Response 共四份观察点，并显示请求目标改写、响应映射与 403/504 的不可观测状态；全为本地脱敏 Mock。真实采集与 API 实施保持 `NOT_RUN`。
