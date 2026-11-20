# 工程治理：仓库所有者决定，证据说话

## 这个项目怎么管自己

2026-11-19 仓库所有者定的：

> 这是一个技术软件，无需执行人和批准人分离的方式，增加了业务复杂度

所以这个项目不用角色分离，也不用具名批准、正式签核。这个仓库只有一位所有者在推进，范围、先后、ADR 的状态、门禁和验收用例的状态，都由仓库所有者决定。一项验证算不算做过，看有没有可以核对的证据：跑了什么、在哪些提交和镜像上、看到了什么；不看有没有人签字，测试报告也不记执行人。同一天所有者还说："我们在开发阶段，无需考虑生产部署。"

这一条只管"项目怎么管自己"。产品设计里的批准（API Fabric 批准路由意图、Gatekeeper 批准凭证的使用、Console 里 Viewer/Engineer/Security Reviewer/Operator 的职责分离、诊断采集先批准）是系统要实现的功能，不受它影响。

## Manifest

`project-manifest.json` 仍然照上位 IDP-SCG-STD-001 V1.0 的官方 Manifest JSON 结构，`standard-project-manifest.schema.json` 由同一标准 HTML 中的 `manifest-schema` 精确提取，结构与类型校验可以通过。结构不动、字段不删：

- `owners` 里的 `UNASSIGNED-*`，`legal_entities`、`jurisdictions`、`toolchain` 里的 `UNRESOLVED-*`，是有意不填的。本项目不指定八个责任人角色，也不编造法人和法域；这些占位不再是"待解决"。`toolchain` 想填，等实际锁定 Go 工具链版本再填。
- `adoption` 保持 `DRAFT`、`approved_by` 为 `null`。
- 这份 schema 里的 `project_overlay` 只允许 `id`、`version`、`reference` 三个字段，不允许放别的内容，所以"本项目不采用角色分离"没有地方写进 Manifest，只写在这篇 README。

`design-status.json` 单独记录六门禁与运行验证的状态，不向上位 Manifest 塞入未知字段。

## 门禁：各自要有什么证据

状态值怎么变的规则：有证据就可以变，由仓库所有者决定。证据是仓库里的文件，写明跑了什么、在哪些提交和镜像上、看到了什么。验收用例离开 `NOT_RUN`，要在矩阵里填写指向仓库内证据文件的 `evidence_uri`。

- STD-CP1（范围与采用）：Profile 适用性、Manifest 与 ADR 的采用情况，由仓库所有者决定并写下来。
- STD-CP2（领域与事实）：领域事实与权威、反例与模型审查，留下审查的记录。
- STD-CP3（契约与恢复）：Gatekeeper / Gateway 与 Provider 的契约、授权和恢复验证，要对着真实的对端跑。
- STD-CP4（专业体验）：有人工操作 UI，要有任务与可访问性测试的运行记录；是否把 UI 纳入交付由仓库所有者决定，N/A 也是这样决定、写下来，不能预先认定通过。
- STD-CP5（工程与质量）：真实构建、集成、安全、负载和故障测试的运行记录。
- STD-CP6（发布与运营）：发布方式、运行手册和发布后实际验证的运行记录。现在是开发阶段，不考虑生产部署，这一项不在眼下的工作范围里。

2026-11-19，仓库所有者定了把 `design-status.json` 里三项运行验证从 `NOT_RUN` 改成 `RUN`：`agentgateway`、`gatekeeper_extauthz`、`provider_sandbox`。`RUN` 的意思是跑过、证据在仓库里，不是"全部通过"；每一项看到了什么、没有看到什么（保留），写在同一个文件的 `runtime_verification_notes` 里。`security_penetration`、`performance`、`production` 没有证据，仍是 `NOT_RUN`。六个门禁和验收矩阵里的用例还没有人对着证据逐项评估，仍是 `NOT_RUN`，那不是"缺批准"。

## 已有的运行结果，和它们为什么还不是门禁证据

结果记在 `design-status.json` 的 `poc` 下，各套件的 README 里有详细的数字。它们回答"技术上走不走得通"；是否算门禁或验收用例的证据，要对着下面的事实逐项评估：

- `tests/acceptance/blackbox`：真实 agentgateway 1.7.0，Gatekeeper 和 Provider 都是替身；97 个用例 96 个通过。
- `tests/integration/gatekeeper`：本机运行的真实 Gatekeeper（检出 `f36dc06`，带本机改动，不是 Gatekeeper 团队运行的环境），Provider 是替身；默认 12 个用例都通过。
- `tests/integration/wanbexpress`（2026-11-19）：真实 Gatekeeper（同上）、真实 agentgateway、真实的承运商沙箱；联调架子上 10/10、compose 池上 11/11，只有替身上看得到的检查是跳过的。只有一个沙箱账号，两个账户的隔离只在替身上验过；沙箱只有明文 HTTP，到承运商的 TLS 没有验。
- 被测的 agentgateway 锁在上游镜像的摘要上（`deploy/agentgateway/agentgateway.lock.json`）；来源、许可证和已知漏洞核查过一遍，没有验证镜像签名（记在 `deploy/agentgateway/README.md`）。
- 没有做的：生产部署、性能、HA、UI。

## UI/UX 范围冻结

基线里同时存在"人工 UI 不在本期必交范围"（G01 §1）和一个 18 页 Console 原型加 75 条 UX 用例。处理如下：

- Manifest 的 `capabilities.user_interface` 为 `true`，与"STD-CP4 适用"的表述一致。这只是承认 UI 资产存在并触发 STD-CP4，不代表 UI 已纳入交付范围；是否纳入由仓库所有者决定。
- **冻结**：在 P1 PoC 的遗留问题处置完、仓库所有者决定 ADR-0008 之前，不新增 Console 页面、不扩充 UX 用例、不修改 `portal/prototypes/`。已有的 UI 资产保留原样。
- 解冻条件和决定人记录在 `design-status.json` 的 `scope_freeze`。
