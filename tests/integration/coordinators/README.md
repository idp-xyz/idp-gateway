# 单机池上的两个 `gateway-authz` 副本和两个协调器

这不是验收通过。它只说明：在 `deploy/compose` 的单机池上叠加 [`coordinators.yml`](../../../deploy/compose/coordinators.yml)，跑两个 `gateway-authz` 副本时，顺丰国际的访问令牌只取一次（[ADR-0022](../../../docs/adr/ADR-0022.md)），撤销和配额在两个副本之间是同一份（[ADR-0023](../../../docs/adr/ADR-0023.md)），两个协调器停了都失败关闭。三篇 ADR（含 [ADR-0021](../../../docs/adr/ADR-0021.md)）仍是 Proposed，正式门禁仍是 `NOT_RUN`。

真的部分：本机的 Gatekeeper（`stack.sh up` 起的那一套，Hydra 的令牌、PDP 走双向 TLS）、锁定的 agentgateway 1.7.0、`gateway-control publish` 发布的 `deploy/providers/sfintl/agentgateway.yaml`、front、两边的出口规则、`provider-signer`、两个 `gateway-authz` 副本、`sf-token-coordinator`、`authz-state`，都是 `deploy/compose` 的文件起的容器。替身：承运商（`tests/integration/sfintl/mock_sfintl.py`，新令牌作废旧令牌）。证书每次现做。生产的 Gatekeeper（gk.idp.xyz）不碰。

```bash
export PATH=/usr/local/go/bin:$PATH
cd /home/tops/workspace/idp-gateway
tests/integration/gatekeeper/stack.sh up                                     # 本机 Gatekeeper；本套件不起它
.venv/bin/python tests/integration/coordinators/pool.py                      # coordinators.yml，gateway-authz 两个副本
.venv/bin/python tests/integration/coordinators/pool.py                      # 第二遍
.venv/bin/python tests/integration/coordinators/pool.py --control no-coordinators
tests/integration/gatekeeper/stack.sh down                                   # 用完收掉
```

## 怎么搭的

- **机器是 `tests/integration/sfintl/pool.py` 的。** 本套件把它当模块导进来用（它导入 `run.py` 也是这样），用它的发布、替身镜像（`idp-gateway-sfintl-pool-standin:<cryptography 版本>`，已有就不重建）和 `sfintl/pool.yml`。compose 项目是自己的：`idp-gateway-coord-pool`。叠加的文件依次是 `compose.yml`、`gateway-authz.yml`、`provider-signer.yml`、`coordinators.yml`（对照不带）、`sfintl/pool.yml`、本目录的 `pool.yml`（只加一条：`gateway-authz` 两个副本，`deploy.replicas: 2`）。
- **端口只用 27881–27895**，启动前逐个看有没有人在听，有就不启动。

  | 端口 | 谁 |
  |---|---|
  | 27881 | front（业务请求） |
  | 27882 | 网关的回读口 |
  | 27883 | 发布时离线加载的临时容器 |
  | 27884 | 承运商替身 |
  | 27885 | `provider-signer`（`sfintl/pool.yml` 发布的） |
  | 27886–27895 | 留着，不听 |

- **两个副本是同一个服务**：同一条命令、同一张证书、同一个 SPIFFE URI。协调器的 `--authz-identity` 是 `gateway-authz` 给 PDP 出示的那张客户端证书上的 URI（`spiffe://idp.test/egress/gateway-authz`）；`coordinators.yml` 让它对两个协调器也出示这一张。协调器的服务端证书是本套件在 rig 的 PKI 里加的两张（`sf-token-coordinator.idp.test`、`authz-state.idp.test`），同一个 CA。
- **撤销文件是两份，不是一份。** `coordinators.yml` 把 `--revocations` 放在每个容器自己的 tmpfs（`/authz/mirror`）里，入口的 shell 在文件不在时写一份空表再 exec `gateway-authz`。CO-01 查两个容器各有自己的 tmpfs、那里没有绑定挂载或卷；CO-03 读两个副本各自的文件：没接撤销的那个副本，文件里没有那个账户，它照样拒绝，所以拒绝来自 `authz-state`，不是来自文件。
- **哪个副本做的判定**：每个经 front 的请求带一个自己的 `traceparent`。网关保留其中的 trace id，换上自己的 span id，再发给 `gateway-authz`；判定日志记下这个值。套件按 trace id 在两个副本的日志里找，每个请求应当恰好在一个副本里出现一次。
- **直接问某一个副本**：在项目网络上起一个一次性容器，用网关的证书打 `/v1/extauthz/check`（判定），或用撤销者的证书跑 `gateway-control revoke/restore`。输出里只有状态码、原因码和令牌 SHA-256 的前 16 位，不打印凭证。
- **收尾**：不论怎么结束，`docker compose down --volumes`，再按项目标签删剩下的容器、网络、卷，删临时目录。只碰这个项目和本机的 Gatekeeper。

## 用例

| 用例 | 要看到的 |
|---|---|
| CO-01 | 两个容器、两个地址；网关所在命名空间里 `gateway-authz` 解析到这两个地址；网关的出口规则把 `gateway-authz:9443` 钉在这两个地址上，两个都连得通；两个副本的启动行都是租约、`authz-state`（撤销和配额）都开着；各自的 tmpfs；20 个蓝租户查询经 front 都是 200，每个恰好由一个副本判定，记下各副本判了几个 |
| CO-02 | 直接问两个副本都给 `Sf-OpenApi`，令牌相同（比摘要前缀）；替身的令牌端点为蓝应用只被调用 1 次；20 次分发带的是同一枚令牌，没有一次在令牌检查上被拒；`sf-token-coordinator` 日志里 acquire 只答过一次 `FETCH`、提交一次。重启一个副本（缓存清空）后：直接问它，还是那枚令牌；再 10 个查询经 front 都是 200；令牌端点仍是 1 次，`FETCH` 仍是 1 次 |
| CO-03 | 经副本 1 用 `gateway-control revoke` 撤销蓝账户：之后 6 个蓝查询经 front 都是 403 `ACCOUNT_REVOKED`，由哪个副本判的都一样；直接问副本 2 也是 403；副本 2 自己的撤销文件里没有蓝，副本 1 的有；承运商什么都没收到；绿不受影响。经副本 2 `restore`：经 front 和直接问两个副本都恢复 200 |
| CO-04 | 配额只有一条：`labels.print`、按账户、每小时 1 次。绿的第一次打印经 front 是 200；第二次经 front 是 429 `RATE_LIMITED`，由另一个副本判的，没有 `Authorization`，承运商没收到第二次分发；直接问没判第一次的那个副本，也是 429，带 `Retry-After`；蓝的查询不受限 |
| CO-05 | 先经副本 1 撤销绿（留给 CO-06）。停 `authz-state`：4 个蓝查询经 front 都是 503，副本判的是 `REVOCATION_STATE_UNAVAILABLE`；直接问两个副本都是 503 `INDETERMINATE`；承运商什么都没收到；两个副本还在跑。这时重启副本 2：它以退出码 1 退出，没有监听（启动时必须先拿到快照） |
| CO-06 | 再起 `authz-state`，等它重新监听、健康检查过；副本 2 这才起得来。绿在两个副本上仍是 403 `ACCOUNT_REVOKED`，`authz-state` 的状态文件里有绿；经副本 2 恢复绿。绿再打印一次：200。CO-04 用掉的那只桶又满了，因为配额桶只在内存里（ADR-0023 写明的限制，这里是看到它，不是说它对） |
| CO-07 | 停 `sf-token-coordinator`（`authz-state` 在跑），两个副本都重启（缓存清空）：3 个蓝查询经 front 都是 503，副本判的是 `CREDENTIAL_UNAVAILABLE`；直接问两个副本都是 503 `INDETERMINATE`；两个副本日志里都有新的 `lease_unavailable`；令牌端点没有再被调用，也没有分发；整遍下来蓝应用只取过一次令牌 |
| CO-08 | 网关、两个副本、签名器、两个协调器的日志，本次输出，结果记录里，没有本次的任何秘密（两个应用的 app key、app secret、AES 密钥，替身发出的访问令牌，PDP 令牌，Gatekeeper 客户端密钥和令牌），也没有 `Sf-OpenApi` 的值 |
| cleanup | 项目的容器、网络、卷都没了；27881–27895 空着；一次性容器不在；临时目录删了 |

副本重启之后换了地址时（见下面"看到的"），套件做部署 README 里写的两步：`docker compose run --rm --no-deps egress forget`，再 `docker compose restart agentgateway`。做之前和之后各发 6 个请求经 front，记下有几个没有到任何副本；做完之后 6 个都要由副本判定。这两项检查只在地址换了的那一遍出现。

`--control no-coordinators`：同样两个副本，**不带** `coordinators.yml`（`provider-signer.yml` 原来的命令，没有 `--revocations`）。

| 用例 | 要看到的（看到了就是对照成立，退出码 0） |
|---|---|
| CTL-01 | 两个副本、两个地址、都钉住；启动行是没有租约、没有 `authz-state`、撤销表在内存里；20 个查询由哪个副本判的 |
| CTL-02 | 直接按 副本 1、副本 2、副本 1 的顺序问：令牌端点为蓝应用至少被调用 2 次，两个副本手里的令牌不同；两个副本都判了的话，承运商在令牌检查上拒掉了一些分发（一个副本的令牌被另一个作废了） |
| CTL-03 | 对副本 1 `gateway-control revoke`：退出码 3，`NO_REVOKER_CONFIGURED`。没有 `--revocations` 就没有撤销接口，所以这里看不到"一边撤销、另一边看不到"，看到的是根本撤销不了 |
| CTL-04、cleanup | 同 CO-08、cleanup |

## 这一次

2026-11-24（北京时间下午），仓库在 `d95969e` 上，工作区里是这次的改动（还没有提交）。Gatekeeper 检出 `f36dc06`，agentgateway 1.7.0，WSL2 里 Ubuntu 24.04 上的 docker 29.8.1、compose v5.5.1。

| 哪一遍 | 起止（UTC，用例部分） | 退出码 | 用例 | 检查 |
|---|---|---|---|---|
| 默认，第一遍 | 08:48:11–08:48:49 | 0 | 9/9 | 74/74 |
| 默认，第二遍 | 08:49:21–08:50:00 | 0 | 9/9 | 74/74 |
| `--control no-coordinators` | 08:50:28–08:50:35 | 0 | 5/5 | 21/21 |

两遍默认运行看到的一样，数字如下：

| 用例 | 检查 | 看到的 |
|---|---|---|
| CO-01 | 10/10 | 两个地址都解析到、都钉住；20 个查询副本 1、副本 2 各判 10 个 |
| CO-02 | 10/10 | 两个副本同一枚令牌；令牌端点 1 次；协调器 `FETCH` 1、`VALID` 1、提交 1。重启副本 1（两遍地址都没变）后：同一枚令牌，10 个查询 5/5，`FETCH` 仍 1、`VALID` 2 |
| CO-03 | 12/12 | 撤销后代次 1；6 个查询全部 403，两个副本各判 3 个；副本 2 的文件代次 0、没有账户，副本 1 的文件代次 1、有蓝；恢复后代次 2 |
| CO-04 | 6/6 | 第一次打印 200，第二次 429 由另一个副本判；直接问那个副本 429，`Retry-After: 3599` |
| CO-05 | 8/8 | 4 个查询全部 503，两个副本各判 2 个 `REVOCATION_STATE_UNAVAILABLE`；重启的副本 2 退出码 1，最后一行 `gateway-authz: authz state: authz state unreachable` |
| CO-06 | 6/6 | 绿在两个副本上 403（代次 3），状态文件里有绿；恢复（代次 4）后打印 200 |
| CO-07 | 10/10 | 两个副本重启后有地址换了（见下）；处理之后 3 个查询全部 503 `CREDENTIAL_UNAVAILABLE`；`lease_unavailable` 两个副本分别从 0 到 10、0 到 18；令牌端点 0 次 |
| CO-08 | 8/8 | 八处都干净 |
| cleanup | 4/4 | |

对照：CTL-01 7/7（20 个查询各判 10 个；其中 11 个 `apiResultCode 0`，9 个是承运商替身的"令牌无效"，`apiResultCode 500`，签名器照原样以 HTTP 200 交回），CTL-02 3/3（令牌端点 2 次；副本 1 两次给的是同一枚，副本 2 是另一枚；之后 10 个查询各判 5 个，10 次分发里 5 次在令牌检查上被拒），CTL-03 1/1（退出码 3，`NO_REVOKER_CONFIGURED`），CTL-04 6/6，cleanup 4/4。

开发时另跑过几遍，没有算在上面。头一遍暴露了两件事，改了之后才是上面的结果：tmpfs 在容器重启之后变成 root 的 0755，入口写不了撤销文件，副本退出（`coordinators.yml` 因此把 `mode=1777` 写明了）；网关会换掉 `traceparent` 里的 span id，所以改成按 trace id 找判定。

## 看到的

- **agentgateway 把 extAuthz 分到了两个副本上。** 三遍里，凡是记了由谁判定的一组请求，都是两个副本轮流判：20 个是 10 和 10，10 个是 5 和 5，6 个是 3 和 3，4 个是 2 和 2，3 个是 2 和 1；CO-04 的两次打印也落在两个副本上。没有出现粘在一个副本上的情况。这是观察到的，配置里没有写负载均衡的方式，也没有查 agentgateway 的代码怎么选。
- **副本重启后可能换地址，网关这边要人跟上。** 两遍默认运行里，CO-02 重启副本 1、CO-06 再起副本 2 时地址没变；CO-07 把两个都重启后，第一遍两个都换了（副本 1 从 `.8` 到 `.6`，副本 2 从 `.9` 到 `.8`，即副本 1 原来的地址），第二遍副本 1 换了（`.9` 到 `.3`）。`pin-egress.sh` 一个名字只解析一次，新地址不在规则里，要 `egress forget`。`forget` 之后规则对了，网关还在用它之前解析到的旧地址：6 个请求里有 3 个没有到任何副本，网关自己答 503（失败关闭，不是放行）。`docker compose restart agentgateway` 之后 6 个都由副本判定，两边各 3 个。网关自己要过多久才会去重新解析，没有量。看守（`gateway-control keep`）不做这两步。
- **`gateway-authz` 的"sf openapi token fetched"不说令牌从哪来。** 配了租约协调器时，这一行的意思是本副本的缓存装上了一枚令牌，可能是协调器答 `VALID` 给的，也可能是答 `FETCH` 之后自己向承运商取的。两遍里两个副本各有一行，替身却只被问过一次。判断"谁向承运商取了"要看替身的记录，或者协调器日志里 acquire 答的是 `FETCH` 还是 `VALID`。
- **健康检查在协调器日志里留下一行 `TLS handshake error ... EOF`。** `nc -z` 连上就断。两遍里 `sf-token-coordinator` 各 1 行，`authz-state` 各 2 行（CO-06 重启过一次）。起来之后一小时才查一次，所以平时不会多。
- **没有 tmpfs 的 `mode` 时，docker 29.8.1 第一次启动给 1777，同一个容器之后每次启动给 root 的 0755。** 在本项目名下单独起了一个容器量的：`--tmpfs`、`--mount type=tmpfs` 都是这样，写明 `mode=1777` 就不会。`compose.yml` 里 `front` 和出口那两步的 `/tmp` 也没有写 `mode`；它们在容器重启之后会怎样，这次没有看。

## 没有做到的

- 协调器各只有一个，在同一台机器上，和池一样是单点。协调器停了是失败关闭（503），这里看到了；它们自己的高可用、多机，没有做。
- 两个副本在同一台机器、同一个 docker 网络里。多机、跨机房、网络分区没有试。
- `gateway-authz` 到两个协调器的连接没有出口规则，协调器自己也没有。这一次也没有加。
- 证书都是单个文件挂进去的。宿主机上改名换掉的证书，容器里看不到，所以 ADR-0021 的热重载在这几个挂载上用不上；这一次没有在池里换证书。
- 配额桶只在内存里：CO-06 看到 `authz-state` 重启之后桶是满的。撤销表在状态文件里，重启之后还在。
- `authz-state` 停着时重启副本，副本起不来（CO-05）；它回来之后要有人把副本起回来。`restart: "no"`，看守和 systemd 单元都没有带上 `coordinators.yml`。
- 副本换了地址时的 `egress forget` 和重启网关，是套件替人做的；网关不重启要多久才恢复，没有量。
- 只对着替身跑了。顺丰的沙箱、真实承运商的令牌寿命和作废规则，没有在这个池上试。
- 撤销只试了账户，没有试操作封禁（`ban`/`unban`）在池里的样子；封禁在 [`tests/integration/authzstate`](../authzstate/README.md) 里跑过。
- 对照只能看到"没有 `--revocations` 就撤销不了"，看不到"两个副本各一份撤销表"那种分叉：不带 `coordinators.yml` 的池里本来就没有撤销表。

这不是验收通过。正式门禁仍是 `NOT_RUN`。ADR-0021、ADR-0022、ADR-0023 仍是 Proposed。
