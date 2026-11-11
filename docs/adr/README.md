# 架构决策记录（ADR）

> 每项决策的状态写在各篇正文开头。截至 2026-11-11，ADR-0001 至 0008 和 ADR-0010 是 **Proposed（待具名批准）**：它们是设计建议，不是已经执行的技术审批、生产基线或运行验收。ADR-0009 是 Accepted，它只决定仓库结构。

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
| [ADR-0009](ADR-0009.md) | 进入开发阶段的仓库结构与 Go 技术基线 |
| [ADR-0010](ADR-0010.md) | 数据面用 standalone 模式，配置由发布器以文件下发 |

ADR-0001 至 0007 随原始设计基线交付。ADR-0008 是其后依据 [P1 PoC 报告](../../tests/acceptance/blackbox/README.md) 的实测结果提出的。ADR-0010 回答 ADR-0009 留下的部署形态问题，依据同一份报告里的配置回读用例。
