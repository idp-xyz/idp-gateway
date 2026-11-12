# agentgateway：版本锁定与配置例子

## 版本锁定

本项目只对着一个 agentgateway 构建开发和测试：上游发布的容器镜像，按摘要写在 `agentgateway.lock.json` 里。

| 字段 | 内容 |
|---|---|
| `version`、`git_revision` | 发布版号，以及镜像里的二进制用 `--version` 报告的提交 |
| `release`、`released` | 上游发布页与发布日期 |
| `image` | 镜像仓库和标签（标签只是给人看的）、多平台索引的摘要 `index`、各平台清单的摘要 `manifests`、二进制在镜像里的路径 `binary` |
| `sha256` | 测试启动的那个二进制的 SHA-256：linux/amd64 镜像里的 `/app/agentgateway` |

当前锁定 **1.7.0**。2026-11-11 核对时它是上游最新的正式发布版。

部署时引用 `<repository>@<index>`，不引用标签：标签可以被改指别的镜像，摘要不能。单机的部署文件（`deploy/compose/compose.yml`）里写的就是这个引用。

**测的就是要部署的那个构建。** 发布页上另有一个独立的二进制（`agentgateway-linux-amd64`）。它和镜像里的不是同一个构建：同一个提交，前者链接 musl，后者链接 glibc，两个文件的 SHA-256 不同。本项目原先测的是前者。改锁镜像时，把当时的黑盒套件（提交 `128ca4a`）原样在后者上跑了一遍：57 个用例、307 项检查的结果与前者逐项相同（单独比对，不在证据里）。此后只测镜像里的这一个。

黑盒套件和 Gatekeeper 联调把这个二进制从镜像里取出来，在本机直接启动，不在容器里跑；Kubernetes 上和单机 docker compose 上的下发验证跑的是镜像本身。

```bash
.venv/bin/python tests/acceptance/blackbox/pin.py --fetch   # 需要 docker：按摘要拉镜像，取出二进制，核对后放到 ~/.local/opt/agentgateway/<version>/agentgateway
.venv/bin/python tests/acceptance/blackbox/pin.py           # 现在会用哪个二进制，它是不是锁定的那个
```

本项目跟随上游最新的正式发布版。要知道锁定的版本是否已经落后：

```bash
python3 scripts/agentgateway_release.py     # 要联网；只用标准库
```

它列出比锁定版本新的正式发布版，以及影响范围包含锁定版本的已发布安全公告；两样都没有时退出码为 0，有任何一样为 1，问不到为 2。上游已发布的安全公告至今都是在新的 minor 版本里修的，没有把修复回补到旧的版本线，所以"有新发布版"和"有影响当前版本的公告"通常同时出现。

黑盒套件和 Gatekeeper 联调在启动网关之前都会核对二进制（`tests/acceptance/blackbox/pin.py`）：版本、提交、SHA-256 有一项与锁定文件对不上就拒绝运行。它们先找 `~/.local/opt/agentgateway/<version>/agentgateway`，没有再找 `PATH` 上的 `agentgateway`；先找到的那个不是锁定的构建时直接报错，不再往下找。本机 `PATH` 上如果另有一个 agentgateway（别的项目装的，或旧版本），不用动它：有了上面那份副本，这里用不到它；没有副本时它会被拒绝。

换版本时：

- 只跟上游的正式发布版，不用预发布版。先读新版本发布说明里的破坏性变更。
- `agentgateway.lock.json` 的各个字段一起改。`image.index` 和各平台的摘要用 `docker buildx imagetools inspect <仓库>:<标签>` 查。`sha256` 是取出来的二进制的摘要：先改 `image`，运行 `pin.py --fetch`，它会报出取到的二进制的 SHA-256 并拒绝安装，把这个值写进 `sha256` 再运行一次。这个值不是另一道来源核对（镜像已经是按摘要拉的），它的用处是让之后每次测试启动的都是这一个文件。
- `docs/governance/project-manifest.json` 里 `AGENTGATEWAY` 的 `version` 和 `source` 跟着改（`tests/contracts` 里有一条测试检查两处一致）。
- `deploy/compose/compose.yml` 和 `deploy/compose/.env.example` 里网关镜像的默认值跟着改（`tests/contracts` 里也有测试检查它们与锁定文件一致）。
- 重跑黑盒套件、Gatekeeper 联调、Kubernetes 上的下发验证（`tests/integration/kubernetes`）和单机上的下发验证（`tests/integration/compose`）；旧版本的证据文件删掉，不留作对照。单机上的下发靠的是网关在配置文件被改名替换之后仍然重载：这是在上游源码和它自己的一条测试里看到的实现，换版本时要重新确认。
- 发布器（`cmd/gateway-control`）另外依赖这个版本上看到的几样行为，换版本时由单机下发验证的 `SH-08` 至 `SH-11` 把关：
  - 网关解析配置文件之前，先拿加载它的那个进程的环境变量替换正文里的 `$名字`、`${名字}`，`$$` 是字面的 `$`（上游 `crates/agentgateway/src/types/local.rs`）。发布器据此拒绝正文里带这类引用的快照（`internal/gatewayconfig/domain/environment.go`）。上游要是多认一种写法，这条检查就漏掉一种，所以除了重跑用例，还要对着新版本的这段源码再看一遍。
  - 网关拒绝一份配置文件时怎么说原因：启动时写在标准错误上以 `Error: ` 开头的那一行，运行中是 `/api/runtime` 的 `configReload.lastError`。
  - 发布器从回读口读的字段：`/config_dump` 整份（算摘要，取 `config` 段），`/api/runtime` 的 `build.version`、`build.gitRevision`、`ui.configStoreMode`、`configReload.synchronized`。
  - 配置文件被删掉时网关不退出：它报告读不到文件，继续跑原来那份，文件放回去之后照常重载（`SH-10`）。
  - 发布器的记录里有 `/config_dump` 的 `config` 段逐项的指纹，对账拿它判断网关是不是带着别的设置重启过（`SH-11`）。新版本的 `config` 段多一项、少一项或者换了写法，指纹就对不上。
- 单机的部署（`deploy/compose`）另外记着这个版本上看到的一样行为，由 `SH-15` 把关：后端的名字是网关第一次用到它时才解析的；那一次解析不了，那条路由就一直答 503，名字解析得了之后也不恢复，重启网关才好。新版本上这一点要是变了，`SH-15` 会不通过；那时把 `deploy/compose/README.md` 和 ADR-0010 里说这件事的两处改掉。
- 换了镜像之后，发布器的记录还是在旧的构建上做的，对账会报告 `UNCONFIRMED`；单机的池这时启动，`front` 不会开。把在用的那份快照拿新镜像再 `publish` 一次，记录才跟到新的构建上（这一步只有单元测试；换镜像本身怎么做还没有设计）。
- 提交证据之前看一眼它的 diff 里 `agentgateway.unmitigated_defaults` 有没有变：那是新二进制在不做处理时的默认行为。变了，就回头看 `tests/acceptance/blackbox/agentgateway.poc.yaml` 里对应的处理是否仍然需要、是否仍然够用。
- 把下面这张核查表重做一遍。

### 对锁定的镜像做过的核查

2026-11-11 做的。这是一次核查的记录，不是批准：G05 §7 要求的具名批准没有。

| 项 | 做了什么，结果如何 |
|---|---|
| 镜像从哪来 | 上游 1.7.0 的发布说明写的镜像名是 `cr.agentgateway.dev/agentgateway:v1.7.0`，当天这个标签解析到锁定的索引摘要。镜像标签（OCI label）里记的源码提交、二进制自己报告的提交，都与锁定文件一致。索引上附着 BuildKit 生成的构建证明，写的是上游仓库的一次 GitHub Actions 运行和同一个提交 |
| 签名 | **没有验证。** 没有查上游是否给镜像签名，本机也没有验签工具。上面那份构建证明本身没有验过签，它证明不了镜像是谁构建的 |
| 许可证 | Apache-2.0（上游仓库在锁定提交上的 `LICENSE`，镜像标签也这样写）。没有逐个查依赖的许可证 |
| 镜像里的系统包 | 基础镜像是 Chainguard 的 `glibc-dynamic`（wolfi），7 个包。trivy 0.76.2（漏洞库更新于 2026-11-10）没有报出已知漏洞 |
| 网关自己的依赖 | 镜像没有附 SBOM，trivy 也没能从二进制里读出依赖，所以查的是源码在锁定提交上的 `Cargo.lock`（827 个包）。命中 5 条已知公告（3 条 HIGH、2 条 MEDIUM），全部在 `rmcp` 0.10.0 上：`CVE-2026-42559`、`CVE-2026-63127`、`CVE-2026-63128`、`CVE-2026-64684`、`GHSA-c9xm-49cp-xcr9`。这个版本在 `crates/agentgateway/Cargo.toml` 里列在 `[dev-dependencies]` 下（上游测试用的旧版 SSE 客户端），不编进发布的二进制；编进去的是 `rmcp` 3.6.0，没有命中。锁文件比二进制的实际依赖宽，所以"没有命中"的结论对二进制成立，"命中"的要像这样逐条看 |
| 上游公告 | `scripts/agentgateway_release.py`：1.7.0 是最新的正式发布版，没有影响它的已发布安全公告 |
| 镜像里有什么 | 以 65532 用户运行，入口是 `/app/agentgateway`。没有 shell，也没有 wget、curl：进不到容器里去读它的管理地址，见 ADR-0010 第 5 条 |
| 没有查的 | 内嵌管理界面的前端依赖；arm64 的镜像（只记了摘要，没有跑过） |

## 配置例子（安全警告）

`agentgateway.local.example.yaml` 仅供展示 Standalone 路由语法轮廓，**并非可以直接暴露给业务网络的受保护 Gateway**：当前示例没有 JWT/ExtAuthZ、TLS、真实 Secret Manager 对接。它已通过 agentgateway 1.7.0 的 `--validate-only` 语法检查，但从未启动运行。只用于隔离本地 Mock 研究。

**端口约定**：本项目保留 `27610-27622` 端口段，不使用 3000/8080 等常见开发端口；该段低于 Linux 临时端口范围（默认 32768–60999），不会被出站连接临时占用。`27610` 为本示例监听端口，`27611-27620` 由黑盒套件使用（见 `tests/acceptance/blackbox/README.md`），`27621-27622` 是联调用的本机 Gatekeeper。本示例的占位上游是一个文档保留地址（`192.0.2.1`，RFC 5737），那里没有任何服务。

agentgateway 的监听器不写 `bindAddress` 时对本机所有网卡开放，本示例写了 `bindAddress: 127.0.0.1`。在环境里没有 `SESSION_KEY` 时启动，它还会把生成的密钥写进配置文件；它的管理地址上还有能改运行配置的接口，默认会把改动写回配置文件，要关掉得设 `config.storage.mode: readOnly`。后两样本示例没有处理，处理过并跑过的写法见 `tests/acceptance/blackbox/README.md` 的"默认配置不安全的地方"。

带 JWT、ExtAuthZ 与凭证注入、且**实际运行过**的配置见 `tests/acceptance/blackbox/agentgateway.poc.yaml`。

真正的配置应由 `RouteIntent` / `PolicyBundle` 经受控 Adapter 编译，按受控版本读取官方 `https://agentgateway.dev/schema/config`，以真实 agentgateway CLI/实例验证 JWT、ExtAuthZ、上游认证与完整的 TLS/NetworkPolicy，再经批准发布。绝不能从这个 Demo 自动推导生产模板。

动态第三方凭证注入必须对官方 ExtAuthZ Header 接收机制进行验证；普通 CONNECT 透传不能替代 L7 应用认证。

## 生产预检新增要求

先运行 `python scripts/preflight_intents.py contracts/gateway/route-intent.example.json`；若返回 `STATIC_PREFLIGHT_OK_NOT_DEPLOYABLE`，仅表示**本地中立意图未发现已实现检查器可见的错误**。

预检对出站上游采用**白名单**：EGRESS 意图的 Provider、环境、上游主机与端口、Operation、方法、路径前缀和凭证绑定必须与 Provider 注册表中的一行完全吻合，否则拒绝。注册表默认取 `contracts/gateway/policies/egress-policy.example.json`，可用 `--provider-registry <file>` 指定；注册表为空则拒绝全部出站意图。保留域名/IP 黑名单仅作为第二道独立检查。

严禁因此跳过固定版本 agentgateway 官方 Schema/CLI/二进制运行、网络 Egress/DNS/TLS、Gatekeeper/PDP 多租户、流式协议及负载/安全验证。`contracts/gateway/policies/traffic-policy.example.json` 描述账户级额度意图，并没有启动任何分布式限流协调器。
