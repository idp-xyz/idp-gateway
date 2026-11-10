# IDP Gateway V1.0 — Quality & Delivery Report

> **日期**：2026-11-10 · **范围**：本机生成的设计交付包（静态材料），非真实网关服务认证。  
> **规范来源**：IDP-SCG-STD-001 V1.0 (2026-11-09)。

## 已执行（真实本地结果）

- 文档与工程资产静态检查：**11 PASS、0 FAIL**，对应 `tests/evidence/static-validation.json`。
- 离线策略参考单元测试：**16 通过**，见 `tests/evidence/mock_policy_tests.txt`。该参考策略只测试 Mock 数据、没有 JWT 验签与真实网关请求。
- 上位标准正式 Manifest JSON Schema：**结构校验通过**。但 Owner、法人/法域、Go 版本未指定；Manifest 语义采用与正式签核 **未通过、不得发布**。
- 需求追溯：**50 FR + 19 NFR 全覆盖**，另加 26 项风险/反例，共 **95 条真实集成/运行验收用例，全部 `NOT_RUN`**。
- 文档：6 份 Markdown + 6 份 HTML；4 张 SVG + PNG 架构图；7 项 Proposed ADR、独立 Fabric/Gatekeeper 变更影响清单。
- **Gateway Operations UI/UX**：已完成同版 V1.0 统一 18 页导航离线交互 Mock 与规格，完成原有 35 项 + 新增 46 项本地浏览器检查（见 `tests/evidence/ux-prototype-browser-tests.txt`），75 条正式 UX 需求验收全部 `NOT_RUN`（见 `tests/ux/acceptance_matrix.csv`）。截图全部是模拟数据，不是实际网关监控。上游开源 UI 的功能映射及未实现边界详见 `portal/spec/Agentgateway_UI_Capability_Matrix_V1.0.md`。

## 未执行（全部不能标为 PASS）

- agentgateway 真实二进制/镜像加载配置、JWKS、ExtAuthZ、后端 Token 动态注入、gRPC Streaming。
- Gatekeeper/Secret Manager Credential Broker 端到端真实验证与多租户负向测试。
- 实际 FedEx/UPS 或其他第三方沙箱调用、Token 轮换、写操作 UNKNOWN 恢复。
- 多副本/灾备故障注入、性能压测、渗透测试和正式发布/运行观察。
- STD-CP1～CP6 正式具名门禁批准。
- Gateway Operations 正式 UI 权限、多租户数据隔离、WCAG 2.2 AA、真实数据联调、实际发布/回滚及操作审计验收。

## 仍待决策的架构风险

1. 多租户动态 Token 注入是否能在所选版本 agentgateway L7 + ExtAuthZ 机制下满足隔离：**高优先级 PoC 阻断项**。
2. 多供应商签名场景是否需要受限 Signer Sidecar：**逐 Provider 评审，不默认在 Gateway 代理层重写报文**。
3. Gateway 增量 p95/p99 延迟、可用性和集中故障风险：**需要与域内直连做真实可重复对比**。
4. 统一 Egress 地址的适用范围：**第三方 HTTP/gRPC 业务接口默认统一；内部服务互调不无条件绕行**。

## 交付与升级原则

保持一个 `idp-gateway/` 规范树，修改同一基线中的内容直至正式确认；未完成具名批准前不创建 V1.1 等版本分支。正式实现的 go.mod、agentgateway 镜像 digest、Secret/Policy 真实配置和运行证据将以可审计变更加入现有目录。

## 同版补充：Message Inspector 离线验证

- 2026-11-10 在无真实网络/凭证的隔离浏览器中执行 Message Inspector 测试：**PASS**（见 `tests/evidence/message-inspector-browser-tests.txt`）。核查范围为 504 UNKNOWN、403 NOT_SENT、200 响应、Viewer 正文受限、Engineer 展示合成脱敏 Body、合成 JSON 导出及 JS 无错误。
- `tests/ux/acceptance_matrix.csv` 新增 `GW-UX-AT-055..062` 共 8 条报文诊断/安全正式验收，全部 `NOT_RUN`。
- **不能据此推断** agentgateway 的四阶段实报文可见、ExtProc 性能、真实敏感信息采集前脱敏、真实多租户服务端授权或 gRPC Streaming 已实现。


## V1.0 同版缺口整治 — 质量证据追加

- 新增 15 项正式缺口追溯：`governance/gap-remediation-matrix.csv`；项目依然为 `DESIGN_DRAFT`。
- 新增 20 FR、7 NFR，分别映射单独 `NOT_RUN` 运行验收，总计 **95 条运行验收**。
- RouteIntent 分支正/反例、Traffic Policy、Credential Binding、Diagnostic Capture 与 Event Schema 可通过离线工具验证。
- `scripts/preflight_intents.py` 明确不输出 native config，不进行 DNS/网络地址安全的全量保证，不得作为生产发布授权。
- `scripts/diagnostic_reference.py` 的唯一合法默认处理是**不捕获正文**；绝不代表生产报文采集/脱敏已经实现。
- UX：新增 Traffic Governance 合成看板和只读钻取；**75 条正式 UX 验收均 NOT_RUN**。
- 真正的 agentgateway 固定版本原生验证、Egress 多租户动态凭证注入、实时报文捕获、分布式限流、熔断、Canary、灰度回滚、负载/渗透测试依然 **NOT_RUN**。


## V1.0 同版整治的本机最终执行证据（非运行时）

- **静态资产检查**：11/11 PASS，`tests/evidence/static-validation.json`。
- **路由/策略离线契约测试**：15/15 PASS，涉及三类 RouteIntent、六类无效正反例、共享额度 Schema、危险目标及完全重叠路由。
- **安全参考测试**：23/23 PASS，含原有 16 项离线授权参考测试、7 项默认不捕获正文的诊断范围测试。
- **浏览器新增 Mock 烟测**：11/11 PASS，在 Chromium 离线 HTML 上验证额度、上游健康、配置漂移的只读钻取及原导航不回归。
- **Node.js JS 静态语法**：PASS。
- **RouteIntent CLI 预检**：PASS，并返回 `STATIC_PREFLIGHT_OK_NOT_DEPLOYABLE`，不生成可部署配置。
- 整体六组执行证据见 `tests/evidence/remediation-execution.json` 与 `remediation-unit-tests.txt`。
- **受控生产验收**：95 条运行、75 条 UX 仍全部 NOT_RUN；当前工程不可称已完成生产 Gateway 实施。

## Request / Response 成对诊断（本地检查）

- 两个 Hop 各含一个 Request 和一个 Response，组成四份可审计的报文观察点。Mock 浏览器检查结果见 `tests/evidence/paired-message-inspector-tests.txt`。
- `contracts/gateway/diagnostic-event.paired-200.example.json` 展示成对结构；字段与 Schema 的离线校验并不构成生产采集能力验证。
- 新增 4 条 UX 正式验收（072–075）；正式验收矩阵 **75 条均 NOT_RUN**。
- ChatGPT 文件下载服务的实际客户端可达性无法通过 ZIP 自检证明；文件大小、校验和与解压属于不同层面的检查。
