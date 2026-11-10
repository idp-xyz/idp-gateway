# IDP Gateway V1.0 — 文件交付说明

> 下列三个 ZIP 与独立原型 HTML 是原始交付时的附件，**不在本仓库中**；仓库内容即解压后的完整工程。`CHECKSUMS.sha256` 对应仓库当前文件，不对应这些 ZIP。

- `IDP_Gateway_Engineering_Baseline_V1.0.zip`：完整设计工程，含 G01–G06、架构图、源契约、策略/测试工具、HTML 交互原型、截图。
- `IDP_Gateway_V1.0_Essential_Source.zip`：完整的可编辑正文、JSON/YAML 契约、HTML 原型、脚本与测试，**省略可重新生成的 PNG 截图与 PNG 架构预览**；SVG 图保留。它是优先下载的轻量化核心工程包，不可混称完整含图版。
- `IDP_Gateway_V1.0_Visual_Assets.zip`：完整包内 PNG 图片的独立补充包；在同一个目录里解压两个 ZIP 可还原全部文件（除质量报告中的 ZIP 校验信息外，文件内容一致）。
- `IDP_Gateway_Operations_V1.0_Interactive_Prototype.html`：独立离线原型，可直接用浏览器打开；数据均为 Mock。
- `IDP_Gateway_V1.0_Offline_Reader.html`：独立离线阅读器。

下载服务是否正常属于客户端与附件服务行为，ZIP 完整性检查不等于用户浏览器实际下载成功。
