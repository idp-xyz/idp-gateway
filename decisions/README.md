# 架构决策记录（ADR）

> 每项决策的状态写在各篇正文开头。截至 2026-11-10，8 项全部是 **Proposed（待具名批准）**：它们是设计建议，不是已经执行的技术审批、生产基线或运行验收。

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

ADR-0001 至 0007 随原始设计基线交付。ADR-0008 是其后依据 [P1 PoC 报告](../poc/p1/README.md) 的实测结果提出的。
