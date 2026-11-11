# 工程治理与审批状态

`project-manifest.json` **严格采用上位 IDP-SCG-STD-001 V1.0 的官方 Manifest JSON 结构**，由同一标准 HTML 中的 `manifest-schema` 精确提取 `standard-project-manifest.schema.json`。结构与类型校验可以通过；但 `UNASSIGNED-*`、`UNRESOLVED-*` 是明确待解决的占位，**不是具名责任人或真实法域**。因此 Manifest **并未通过正式语义采用/审批**。

`design-status.json` 单独记录六门禁与运行测试的 `NOT_RUN`，不向上位 Manifest 塞入未知字段。当前 adoption.status 为 `DRAFT`，未记录任何真实批准、waiver 或 deviation。

## Profile 适用性

CORE + TECH + GO 为候选；因 AI/LLM/MCP/A2A 被纳入当前项目目标范围，将 `AI = true` 并包含 AI Profile；是否实现所有 AI 能力按正式采用规则计算。本期未锁定 Bento-Go 的实际来源与确切版本，因此不触发 BENTO_GO。

## 门禁

- STD-CP1：具名 Owner、真实法域/法人、Profile 适用性、Manifest/ADR 采用批准。
- STD-CP2：领域事实与权威、反例与模型审查。
- STD-CP3：Gatekeeper / Gateway 与 Provider 的契约、授权和恢复验证。
- STD-CP4：有人工操作 UI 时需任务与可访问性测试；无 UI 时经批准 N/A，不能预先认定通过。
- STD-CP5：真实构建、集成、安全、负载和故障测试。
- STD-CP6：发布授权、运行手册和发布后实际验证。

**必须保持全部 NOT_RUN，直到有真实执行和具名批准。**

## PoC 证据不是门禁证据

`tests/acceptance/blackbox` 在真实 agentgateway 1.7.0 上用 Mock Gatekeeper 和 Mock Provider 跑过，结果记在 `design-status.json` 的 `poc` 下。它回答"技术上走不走得通"，不改变任何门禁、`runtime_verification` 或验收用例的 `NOT_RUN`：Gatekeeper 与 Provider 都是 Mock，版本只是为开发和测试锁定的（`deploy/agentgateway/agentgateway.lock.json`，没有做 G05 §7 要求的核查），没有具名执行人与批准。验收用例要离开 `NOT_RUN`，必须在矩阵里填写指向仓库内证据文件的 `evidence_uri`，`scripts/validate_baseline.py` 会检查。

## UI/UX 范围冻结

基线里同时存在"人工 UI 不在本期必交范围"（G01 §1）和一个 18 页 Console 原型加 75 条 UX 用例。处理如下：

- Manifest 的 `capabilities.user_interface` 改为 `true`，与 README 中"STD-CP4 适用"的表述一致。这只是承认 UI 资产存在并触发 STD-CP4，不代表 UI 已获批纳入交付范围；是否纳入由产品 Owner 决定，目前 Owner 未指定。
- **冻结**：在 P1 PoC 的遗留问题处置完、ADR-0008 获具名批准之前，不新增 Console 页面、不扩充 UX 用例、不修改 `portal/prototypes/`。已有的 UI 资产保留原样。
- 解冻条件与责任人记录在 `design-status.json` 的 `scope_freeze`。
