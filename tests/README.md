# 测试资产与真实证据约束

`acceptance_matrix.csv` 含 95 个场景，覆盖 G01 的 50 项功能需求（GW-AT，50 个）与 19 项非功能需求（GW-NAT，19 个），另有 26 个额外风险/反例（GW-ST）。所有真实网关集成、Provider、负载、HA 和安全测试当前 **NOT_RUN**。

可运行的离线检查：`python3 scripts/validate_baseline.py`、`python3 -m unittest discover -s tests/contracts -p 'test_*.py'` 与 `python3 -m unittest discover -s tests/security -p 'test_*.py'`（依赖见根目录 `requirements.txt`），只验证示例策略、静态结构和安全判定参考逻辑，并不代替真实 Gatekeeper/agentgateway/提供商端到端测试。输出证据 `tests/evidence/static-validation.json` 是本地执行报告。

`test_bypass_regressions.py`（两个目录各一份）固定了评审中发现的绕过：它们先对着交付时的实现写成失败用例，再把参考实现从"拒绝看起来坏的"改成"只接受已知好的"。`tests/contracts/test_contract_consistency.py` 固定契约之间的一致性。

在真实 agentgateway 上运行的 PoC 在 `poc/p1/`，它的证据不改变本目录任何用例的 `NOT_RUN`。验收用例离开 `NOT_RUN` 时必须填写指向仓库内文件的 `evidence_uri`。
