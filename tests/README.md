# 测试资产与真实证据约束

`acceptance_matrix.csv` 含 68 个场景，覆盖 G01 的 30 项功能需求，其中 26 个是额外风险/反例。所有真实网关集成、Provider、负载、HA 和安全测试当前 **NOT_RUN**。

可运行的离线检查：`python3 scripts/validate_baseline.py` 与 `python3 -m unittest discover -s tests/security -p 'test_*.py'`，只验证示例策略、静态结构和安全判定参考逻辑，并不代替真实 Gatekeeper/agentgateway/提供商端到端测试。输出证据 `tests/evidence/static-validation.json` 是本地执行报告。
