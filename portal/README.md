# Gateway Operations 交互式原型

- **离线入口**：[Gateway Operations 统一交互原型](prototypes/gateway-operations.html)
- **UI/UX 工程规范**：[Gateway Operations UX Spec V1.0](spec/Gateway_Operations_UX_Spec_V1.0.md)
- **UX 验收矩阵**：[`../tests/ux/acceptance_matrix.csv`](../tests/ux/acceptance_matrix.csv)

全部页面是本地 Mock，采用内存模拟数据；零依赖，离线运行，不访问生产接口。导航、查询、详情、角色审批、发布模拟和实例模拟不等于正式运行行为。运营后台不是独立产品，建议置于现有 IDP 内部工程门户。

- [agentgateway UI 能力覆盖与来源](spec/Agentgateway_UI_Capability_Matrix_V1.0.md)（HTTP、LLM、MCP、Tools 等能力的 IDP 对照及实现边界）。


## 最新 V1.0 Traffic Governance 同页补强

`Traffic Explorer` 增加账户级 Quotas、Upstream Health、Config Drift 三卡片及只读抽屉；全部是本地合成值，支持原有 18 个页面的统一导航。不单独开发另一套管理后台。正式验收以 `tests/ux/acceptance_matrix.csv` 的 75 项为准，均未运行真实环境。
