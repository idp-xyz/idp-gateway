# 单机池上的两个 `gateway-authz` 副本和两个协调器

这不是验收通过。它只说明：在 `deploy/compose` 的单机池上叠加 [`coordinators.yml`](../../../deploy/compose/coordinators.yml)，跑两个 `gateway-authz` 副本时，顺丰国际的访问令牌只取一次（[ADR-0022](../../../docs/adr/ADR-0022.md)），撤销和配额在两个副本之间是同一份（[ADR-0023](../../../docs/adr/ADR-0023.md)），两个协调器停了都失败关闭。三篇 ADR（含 [ADR-0021](../../../docs/adr/ADR-0021.md)）仍是 Proposed，正式门禁仍是 `NOT_RUN`。

真的部分：本机的 Gatekeeper（`stack.sh up` 起的那一套，Hydra 的令牌、PDP 走双向 TLS）、锁定的 agentgateway 1.7.0、`gateway-control publish` 发布的 `deploy/providers/sfintl/agentgateway.yaml`、front、两边的出口规则、`provider-signer`、两个 `gateway-authz` 副本、`sf-token-coordinator`、`authz-state`，都是 `deploy/compose` 的文件起的容器。替身：承运商（`tests/integration/sfintl/mock_sfintl.py`，新令牌作废旧令牌）。证书每次现做。生产的 Gatekeeper（gk.idp.xyz）不碰。

```bash
export PATH=/usr/local/go/bin:$PATH
cd /home/tops/workspace/idp-gateway
tests/integration/gatekeeper/stack.sh up                                     # 本机 Gatekeeper；本套件不起它
.venv/bin/python tests/integration/coordinators/pool.py                      # coordinators.yml，gateway-authz 两个副本，之后是看守
.venv/bin/python tests/integration/coordinators/pool.py                      # 第二遍
.venv/bin/python tests/integration/coordinators/pool.py --control no-coordinators
.venv/bin/python tests/integration/coordinators/pool.py --control keep-no-tend   # 看守不带 --tend（ADR-0024 的对照）
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
  | 27886 | 看守的指标（`--metrics-listen`，只在 KP 用例里） |
  | 27887–27895 | 留着，不听 |

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

### 看守（KP，[ADR-0024](../../../docs/adr/ADR-0024.md)，Proposed）

默认运行在 CO-07 之后起一个真的看守（`gateway-control keep`），CO 那几个用例跑的时候它不在。它由本脚本直接起，不经 systemd，和 [`tests/integration/compose`](../compose/README.md) 起看守的做法一样：项目名、六个 compose 文件、变量文件和环境都与本脚本自己跑 `docker compose` 时的相同，每 1 秒看一眼，其余是默认值，指标开在 27886。参数是 `--tend-pinned gateway-authz --tend-pinned provider-signer --tend signer --tend sf-token-coordinator --tend authz-state`。要看到池坏着的样子时，本脚本像一次发布那样占着池（对配置目录里的锁文件 `flock`），看守看到了也不动手，放开之后才动手。

| 用例 | 要看到的 |
|---|---|
| KP-00 | 看守启动。头一行：三个常驻的都在跑，列出五个服务；`sf-token-coordinator`（CO-07 停的）没在跑，它跑了启动命令（`action` 是 `start`，修好了）；头一眼只记下地址，没有 `moved`。协调器健康，经 front 的查询 200 |
| KP-01 | `docker kill` 一个副本：看守那一行说它没在跑、跑了启动命令；副本重新监听；它要是换了地址，看守接着让网关跟上；之后 6 个查询经 front 都是 200，各由一个副本判定。记下秒数 |
| KP-02 | 占着池，`docker kill` 掉 `authz-state`：4 个查询都是 503，副本判的是 `REVOCATION_STATE_UNAVAILABLE`（失败关闭）；看守那一行说 `busy`，没有动手。放开：看守跑启动命令，`authz-state` 健康，查询又是 200。记下秒数 |
| KP-04 | `docker kill` 签名器的进程 `signer`（占着它命名空间的 `provider-signer` 不动）：看守跑启动命令，查询又是 200。记下秒数 |
| KP-03 | 占着池，让副本 1 重启到另一个地址：`docker stop`，另起一个没有 compose 标签的容器占住它空出来的地址，`docker start`，再删掉那个容器（docker 给的是网络上最小的空地址，不占住的话多半给回原来那个）。核对地址确实变了、直接问它是 200、名字解析到新地址、规则没有钉它；6 个查询里有没有到任何副本的（网关自己答 503）；看守那一行有 `moved`、`busy`，没有动手。放开：看守 `forget+stop+start`，修好了，对账 `IN_SYNC`；网关和 `front` 是新起的，`netns` 没动；规则钉住了现在的地址；6 个查询 6 个都由副本判定，都是 200；`repins_total` 加了 1。记下看守那一行和秒数 |
| 收尾 | 看守收到 SIGTERM 以 0 退出，标准错误上什么都没有。它写的每一行算进 CO-08 查秘密的范围 |

`--control keep-no-tend`：同一个池（带 `coordinators.yml`，两个副本），不跑 CO 用例，看守**不带** `--tend`、`--tend-pinned`。

| 用例 | 要看到的（看到了就是对照成立，退出码 0） |
|---|---|
| KP-00 | 头一行：三个常驻的都在跑，没有动手，行里没有 `tended`、`tended_why`、`moved`、`tended_after` |
| KP-01 | `docker kill` 一个副本，等 10 秒（10 眼）：它还是退出码 137，看守没有写一行带动作的。本脚本占着池把它起回来，地址换了就做那两步 |
| KP-02 | `docker kill` 掉 `authz-state`：查询 503；10 秒之后它还没在跑，看守没有动手。本脚本把它起回来 |
| KP-03 | 同样让副本 1 重启到另一个地址：有查询没有到任何副本；10 秒之后再 6 个查询，仍有没到的，规则仍没钉新地址，看守没有动手 |
| KP-05、cleanup | 同 CO-08、cleanup |

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

## 这一次：看守（KP，ADR-0024）

2026-11-24（北京时间傍晚），仓库在 `72afa82` 上，工作区里是 ADR-0024 的改动（还没有提交）。Gatekeeper 检出 `f36dc06`，agentgateway 1.7.0，docker 29.8.1、compose v5.5.1。跑之前 `stack.sh up`，三遍都跑完之后 `stack.sh down`。

| 哪一遍 | 起止（UTC，用例部分） | 退出码 | 用例 | 检查 |
|---|---|---|---|---|
| 默认，第一遍 | 09:53:24–09:54:36 | 0 | 14/14 | 101/101 |
| 默认，第二遍 | 09:55:23–09:56:36 | 0 | 14/14 | 101/101 |
| `--control keep-no-tend` | 09:56:55–09:57:55 | 0 | 6/6 | 28/28 |

CO-01 到 CO-07 的检查与上一次相同，62 项都过；CO-08 多查了一处（看守写的每一行和它的标准错误），9/9；cleanup 4/4；KP 用例 26 项。KP 两遍看到的一样：

| 用例 | 检查 | 看到的 |
|---|---|---|
| KP-00 | 5/5 | 头一行：三个常驻的都在跑；五个服务都列出来，`sf-token-coordinator` 是 `exited (2)`；`action` 是 `start`，`repaired` 为真，没有 `moved`。看守启动到这一行 2.93、2.95 秒 |
| KP-01 | 3/3 | 杀掉副本 2：看守那一行 `tended_why` 是 `gateway-authz: …-gateway-authz-2 is not running (exited (137))`，`start`，修好了。副本两遍都回到原来的地址（`.8`），看守没有让网关跟上一次。杀掉到看守那一行 3.78、3.73 秒，到副本重新监听 3.92、3.80 秒，到 6 个查询都由副本判定、都是 200 4.69、4.60 秒 |
| KP-02 | 5/5 | 占着池时：4 个查询都是 503，两个副本各判 2 个 `REVOCATION_STATE_UNAVAILABLE`；看守那一行 `busy`。放开到看守那一行 3.29、3.11 秒，到第一个 200 3.31、3.21 秒 |
| KP-04 | 2/2 | 杀掉 `signer`：看守 `start`，修好了。到看守那一行 2.79、4.10 秒，到第一个 200 2.89、4.16 秒 |
| KP-03 | 11/11 | 副本 1 重启到 `.10`（第一遍从 `.4`，第二遍从 `.5`），直接问它是 200；名字解析到 `.10` 和 `.8`，规则钉的是旧地址和 `.8`。6 个查询：3 个没有到任何副本（网关自己答 503），3 个由副本 2 判定、200。看守那一行：`busy`，`moved` 是 `["gateway-authz 192.168.48.10"]`。放开之后那一行：`action` `forget+stop+start`，`repaired` 为真，对账 `IN_SYNC`，网关和 `front` 的启动时刻变了、`netns` 没变。规则钉住了两个现在的地址；6 个查询 6 个由副本判定，各 3 个，都是 200；`idp_gateway_pool_repins_total` 1，`idp_gateway_pool_unfollowed_addresses` 0。放开到看守那一行（`forget`、停、`up -d` 都做完）4.37、4.68 秒，到 front 又开门 4.41、4.71 秒，到 6 个都由副本判定 5.77、6.14 秒 |
| 收尾 | 1/1 | 看守收到 SIGTERM 以 0 退出，标准错误上什么都没有 |

对照（看守不带 `--tend`）：KP-00 1/1（头一行里没有新的四项）；KP-01 2/2（副本死了 10 秒还是退出码 137，看守没有写带动作的行；这 10 秒之后的 6 个查询都由活着的那个副本判定、都是 200）；KP-02 5/5（4 个查询 503；10 秒之后 `authz-state` 还没在跑）；KP-03 7/7（副本 1 从 `.8` 到 `.10`；6 个查询 6 个都没有到任何副本，10 秒之后再 6 个还是这样，规则仍没钉 `.10`，看守没有动手）；KP-05 9/9；cleanup 4/4。对照里 KP-03 是全部没到、不是一半，多半是网关从 KP-01 起就没再把请求发给副本 2；没有查。

开发时另跑过三遍默认路径，没有算在上面，都是 13/14，不通过的都是 KP-03，用的是当时的做法：在副本跑着的时候 `docker network disconnect` 再带着原来的别名 `connect`。第一遍 docker 五次都给回同一个地址。第二遍先让另一个容器占住旧地址，副本换到了新地址，看守 `forget+stop+start` 之后 6 个查询都到了副本，但新地址上的那个副本自己答了 3 个 503 `REVOCATION_STATE_UNAVAILABLE`。第三遍先直接问它：60 秒里 16 次都是 503。之后改成上面的重启。

`tests/integration/compose/run.py` 在同一个工作区上跑了一遍（不带新参数的看守）：30 个用例、304/304，退出码 0，818 秒，在 `stack.sh up` 之前跑的（端口重叠）。

## 看到的

- **agentgateway 把 extAuthz 分到了两个副本上。** 三遍里，凡是记了由谁判定的一组请求，都是两个副本轮流判：20 个是 10 和 10，10 个是 5 和 5，6 个是 3 和 3，4 个是 2 和 2，3 个是 2 和 1；CO-04 的两次打印也落在两个副本上。没有出现粘在一个副本上的情况。这是观察到的，配置里没有写负载均衡的方式，也没有查 agentgateway 的代码怎么选。
- **副本重启后可能换地址，网关这边要人跟上。** 两遍默认运行里，CO-02 重启副本 1、CO-06 再起副本 2 时地址没变；CO-07 把两个都重启后，第一遍两个都换了（副本 1 从 `.8` 到 `.6`，副本 2 从 `.9` 到 `.8`，即副本 1 原来的地址），第二遍副本 1 换了（`.9` 到 `.3`）。`pin-egress.sh` 一个名字只解析一次，新地址不在规则里，要 `egress forget`。`forget` 之后规则对了，网关还在用它之前解析到的旧地址：6 个请求里有 3 个没有到任何副本，网关自己答 503（失败关闭，不是放行）。`docker compose restart agentgateway` 之后 6 个都由副本判定，两边各 3 个。网关自己要过多久才会去重新解析，没有量。看守（`gateway-control keep`）不带参数时不做这两步；带了 `--tend-pinned gateway-authz` 时它做（KP-03），第二步是它自己的停、起，不是 `restart agentgateway`。
- **`gateway-authz` 的"sf openapi token fetched"不说令牌从哪来。** 配了租约协调器时，这一行的意思是本副本的缓存装上了一枚令牌，可能是协调器答 `VALID` 给的，也可能是答 `FETCH` 之后自己向承运商取的。两遍里两个副本各有一行，替身却只被问过一次。判断"谁向承运商取了"要看替身的记录，或者协调器日志里 acquire 答的是 `FETCH` 还是 `VALID`。
- **健康检查在协调器日志里留下一行 `TLS handshake error ... EOF`。** `nc -z` 连上就断。两遍里 `sf-token-coordinator` 各 1 行，`authz-state` 各 2 行（CO-06 重启过一次）。起来之后一小时才查一次，所以平时不会多。
- **没有 tmpfs 的 `mode` 时，docker 29.8.1 第一次启动给 1777，同一个容器之后每次启动给 root 的 0755。** 在本项目名下单独起了一个容器量的：`--tmpfs`、`--mount type=tmpfs` 都是这样，写明 `mode=1777` 就不会。只有镜像里本来没有的挂载点是这样（`/authz/mirror`）。2026-11-24 同一台 docker 29.8.1 上补量了 `compose.yml` 那个壳镜像：镜像里的 `/tmp` 本来就是 root 的 1777，挂 tmpfs 之后 stop/start 三轮、`docker restart` 三轮都是 1777；按 `front` 的样子（只读根、镜像默认用户、`front.nginx.conf`）stop/start 三轮，nginx 每次都起来了。所以 `front` 和出口那两步的 `/tmp` 不用写 `mode`。
- **docker 给容器的是网络上最小的空地址。** 一个副本单独重启，多半拿回原来的地址（CO-02、CO-06、KP-01 都是）；两个一起重启，后起的那个拿到先起的那个空出来的（CO-07）。KP-03 因此要另一个容器先占住旧地址。
- **在跑着的 `gateway-authz` 自己的地址变了，它对每个判定都答 503。** 开发时的做法（`docker network disconnect` 再 `connect`）下看到的：直接问 16 次、60 秒，都是 503 `REVOCATION_STATE_UNAVAILABLE`。多半是它到 `authz-state` 的连接还是从旧地址开的；没有查它的客户端。重启换的地址是新进程，没有这个问题。

## 没有做到的

- 协调器各只有一个，在同一台机器上，和池一样是单点。协调器停了是失败关闭（503），这里看到了；它们自己的高可用、多机，没有做。
- 两个副本在同一台机器、同一个 docker 网络里。多机、跨机房、网络分区没有试。
- `gateway-authz` 到两个协调器的连接没有出口规则，协调器自己也没有。这一次也没有加。
- 证书都是单个文件挂进去的。宿主机上改名换掉的证书，容器里看不到，所以 ADR-0021 的热重载在这几个挂载上用不上；这一次没有在池里换证书。
- 配额桶只在内存里：CO-06 看到 `authz-state` 重启之后桶是满的。撤销表在状态文件里，重启之后还在。
- `authz-state` 停着时重启副本，副本起不来（CO-05）；它回来之后要有人把副本起回来。`restart: "no"`，systemd 单元没有带上 `coordinators.yml`。看守带上 `--tend` 时会起（KP 那几个用例，看守由脚本直接起）；带着这些参数的看守没有在 systemd 里跑过。
- CO 用例里副本换了地址时的 `egress forget` 和重启网关，是套件替人做的（那时看守不在）；网关不重启要多久才恢复，没有量。
- 看守的 KP 用例没有试：`provider-signer`（签名器的命名空间）单独死了，`egress-watch` 死了，看守启动之前地址就已经换了，扩容、缩容，`forget` 自己失败（这几样只有单元测试，或者没有）。
- 只对着替身跑了。顺丰的沙箱、真实承运商的令牌寿命和作废规则，没有在这个池上试。
- 撤销只试了账户，没有试操作封禁（`ban`/`unban`）在池里的样子；封禁在 [`tests/integration/authzstate`](../authzstate/README.md) 里跑过。
- 对照只能看到"没有 `--revocations` 就撤销不了"，看不到"两个副本各一份撤销表"那种分叉：不带 `coordinators.yml` 的池里本来就没有撤销表。

这不是验收通过。正式门禁仍是 `NOT_RUN`。ADR-0021、ADR-0022、ADR-0023、ADR-0024 仍是 Proposed。
