# 测试

| 位置 | 是什么 | 怎么跑 |
|---|---|---|
| 各 Go 包旁的 `*_test.go` | 单元测试 | `go test ./...` |
| `acceptance/acceptance_matrix.csv` 等三张矩阵 | 正式验收用例（95 个场景：GW-AT 50、GW-NAT 19、GW-ST 26）、协议兼容清单、故障演练清单。全部 **NOT_RUN** | 尚未执行 |
| `acceptance/blackbox/` | 对着真实 agentgateway 的黑盒用例，被测的 PDP 是本仓的 `gateway-authz` | 见该目录 README |
| `integration/gatekeeper/` | 与真实 Gatekeeper 的联调：在本机起一套 Gatekeeper，真实的 M2M 令牌经 agentgateway 到 `gateway-authz`，再由它去问 Gatekeeper 的 PDP | 见该目录 README；需要 docker |
| `integration/kubernetes/` | 在本机的一个 kind 集群里验证 ADR-0010 的做法：锁定的上游镜像，多个副本；每份快照一个不可变的 ConfigMap，发布是滚动替换；经网关的回读口逐个副本回读 | 见该目录 README；需要 kind、kubectl 和 docker |
| `integration/compose/` | 在本机用 docker compose 验证 ADR-0010 在单机上的做法：锁定的上游镜像跑在容器里，配置目录挂载进去；发布是把目录里的配置文件整份换掉，网关不重启；经网关的回读口确认 | 见该目录 README；需要 docker |
| `contracts/` | 契约之间、契约与黑盒配置之间的一致性；RouteIntent 预检与诊断事件的反例；agentgateway 版本锁定与项目清单一致；`scripts/agentgateway_release.py` 的判断逻辑（用固定数据，不联网） | `python -m unittest discover -s tests/contracts -p 'test_*.py'` |
| `security/` | 诊断采集授权参考实现的反例 | `python -m unittest discover -s tests/security -p 'test_*.py'` |

黑盒用例和 `integration/` 下的三套用例通过都不改变验收矩阵里任何用例的 `NOT_RUN`。验收用例离开 `NOT_RUN` 时必须填写指向仓库内文件的 `evidence_uri`。

`contracts/` 与 `security/` 里的 Python 检查对应 `scripts/` 下还没有移植成 Go 的参考实现（RouteIntent 预检、诊断采集）。出站判定规则已经移植，Go 版本及其测试在 `internal/egressauthz/domain`。
