# API Fabric 发布回环

这不是验收通过。它只说明：真实的 `gateway-fabric`、`gateway-authz`、`gateway-control`，加上锁定的 agentgateway 1.7.0，在一台机器上能不能把一条发布意图走到 `ACTIVE`，并且负向检查会拦住不该放行的请求。

池是本机二进制 `~/.local/opt/agentgateway/1.7.0/agentgateway`。SHA-256 必须是 `c7ef326b7b5702451e94bab55ff484d600d5abdc5344a4cdf7c72fc0bcff9e24`，与 `deploy/agentgateway/agentgateway.lock.json` 相同。离线加载用 `--staging-image`，镜像是 `cr.agentgateway.dev/agentgateway@sha256:60216aafb03d37f94e952ff3d51d2f630a65b10ecaebdc0a864882f92610c45b`。镜像必须已经在本机，套件不拉取。临时容器的名字含 `idp-gateway-fabric`。别的容器不动。

`PublishedDigest` 含 `gateways` 里的端口。套件不改这些端口。容器有自己的网络命名空间，所以和本机二进制绑同一组端口不冲突。容器里的回读口是 27722，映射到本机 27726。

上游主机名取自 `/etc/hosts` 里已经指向回环的 DNS 名。这一台是 `tops.localdomain` → `127.0.1.1`。替身绑在这个地址上。不改 `/etc/hosts`。

启动子进程和访问本机之前都会去掉名字里带 `proxy` 的环境变量。

```bash
/home/tops/workspace/idp-gateway/.venv/bin/python tests/integration/fabric/run.py
/home/tops/workspace/idp-gateway/.venv/bin/python tests/integration/fabric/run.py --control skip-authz-reload
/home/tops/workspace/idp-gateway/.venv/bin/python tests/integration/fabric/run.py --control bad-binding
```

默认那一遍不带 `--control`。端口只用 27721–27735。

| 端口 | 谁 |
|---|---|
| 27721 | 池的业务监听，`127.0.0.1` |
| 27722 | 池的回读口；容器里也是这个端口 |
| 27723 | admin |
| 27724 | stats |
| 27725 | readiness |
| 27726 | 临时容器回读口映射到本机的地址 |
| 27727 | 承运商替身 |
| 27728 | `gateway-authz` |
| 27729 | `gateway-fabric` |
| 27730–27735 | 这一段留着，套件不听 |

| 用例 | 要看到的 |
|---|---|
| FB-01 | 发布前 parcels 是 404。`POST /v1/route-intents` 是 202，`state` 是 `DRAFT`。未完成时另一把键是 409。终态 `ACTIVE`，两个摘要相等且非空。合法 JWT 经网关得到 200。替身看到 `Hc-OweDeveloper`，看不到调用方 JWT。`gateway-authz` 不重启，`policy_version` 变了 |
| FB-02 | 键顺序不同、语义相同的正文再次 POST，仍是第一次的 202，`state` 仍是 `DRAFT`；GET 仍是 `ACTIVE`。同键改 `approval_ref` 是 409。新键配过时的 `expected_generation: 0` 是 409，而且不占这把键；改成当前代次再发，得到 202 |
| FB-03 | 第二条路由走到 `ACTIVE`，代次到 2。两条路由都能访问。再更新第一条的 `approval_ref`，新版本 `ACTIVE`，旧记录在 `state.json` 里是 `SUPERSEDED`，另一条仍是 `ACTIVE` |
| FB-04 | 未知字段、重复键、`api_key`、`client_secret`、`${SECRET_VAR}`、`PROD` 明文例外、目录外的操作、不对的上游、两个方法、不对的 `target_id` 或 `gateway_pool`、未登记的绑定，都是 422。快照、策略文件、代次都不变 |
| FB-05 | 没有客户端证书，握手完不成。同一 CA 的其他 SPIFFE URI，POST 和 GET 都是 401。两个 `Host` 头是 400。不存在的 `intent_id` 是 404，正文不回显路径。发布器证书调 `/v1/extauthz/check` 和 `/v1/egress/revocations` 都是 401，应答没有 `Authorization` |
| FB-06 | `gateway-control revoke` 之后下一笔是 403，`restore` 之后是 200。`ban` 之后该操作是 403，另一条路由仍是 200，`unban` 之后是 200。代次和快照不变 |
| FB-07 | 把损坏的 JSON 原子换上策略文件。合法请求仍是 200，`policy_version` 仍是旧的。换回原文件之后仍是 200 |
| FB-08 | 快照已经写上、回读口随网关进程消失。状态是 `UNKNOWN`，不是 `ACTIVE`、`FAILED` 或 `OVERTAKEN`。网关和 `gateway-fabric` 重新起来之后，对账把这条记成 `FAILED`，原路由是 200，漂移的那条路由没有留在数据面上 |

`--control skip-authz-reload` 让 `gateway-authz` 一直读旧策略文件。FB-01 必须到不了 `ACTIVE`。`--control bad-binding` 把绑定改成 `OAUTH2_AUTHORIZATION_CODE`。FB-01 必须是 422。对照模式确认预期的失败之后退出码是 0。默认运行不含这两次。

## 这一次

2026-11-24，默认那一遍连续跑了两次，退出码都是 0。每遍 9 个用例、90/90 项检查。`--control skip-authz-reload` 是 5/5，终态 `FAILED`，parcels 是 404，代次仍是 0。`--control bad-binding` 是 6/6，POST 是 422，原因 `binding`，parcels 是 404。两次对照的退出码都是 0。

| 用例 | 结果 |
|---|---|
| FB-01 | 通过。发布前 parcels 404，whoami 200。202 的三个字段是 `intent_id`、`release_ref`、`DRAFT`。进行中的另一把键是 409，`publish_in_progress`，键没有留下。终态 `ACTIVE`，两个摘要相等且非空。经网关的 POST 是 200。替身一条请求，`Hc-OweDeveloper` 开头，没有调用方 JWT，也没有 `X-Provider-Account`。`policy_version` 变成 `wanbexpress-fabric-g0-…`。网关和 `gateway-authz` 都是原来的进程。代次 1。日志里没有 `address already in use` |
| FB-02 | 通过。重放正文与第一次的 202 相同，含 `DRAFT`。GET 仍是 `ACTIVE`。同键异体 409，`idempotency_key_reused`。过时代次 409，`generation_conflict`，键未占用。快照和策略文件的 SHA-256 不变，代次仍是 1。同一把新键改成代次 1 得到 202 |
| FB-03 | 通过。whoami `ACTIVE`，摘要相等。parcels 仍是 `ACTIVE`。两条都是 200。代次 2。更新 `approval_ref` 之后新版本 `ACTIVE`，`state.json` 里旧记录是 `SUPERSEDED`，whoami 仍是 `ACTIVE`。代次 3。两条仍是 200 |
| FB-04 | 通过。12 种拒绝都是 422。代次、快照、策略文件、幂等键集合都不变 |
| FB-05 | 通过。无证书的客户端读不到 HTTP 应答。错误身份的 POST 和 GET 都是 401。两个 `Host` 头是 `HTTP/1.1 400`。未知 `intent_id` 是 404，正文没有这个 id。发布器证书打判定口和撤销口都是 401，没有 `Authorization` 头 |
| FB-06 | 通过。`revoke` 的下一笔 403，`restore` 的下一笔 200。`ban parcels.create` 的下一笔 403，whoami 仍是 200。`unban` 的下一笔 200。代次和快照不变 |
| FB-07 | 通过。坏 JSON 换上之后请求仍是 200，`policy_version` 不变。换回之后仍是 200，版本仍是那一个 |
| FB-08 | 通过。回读中断后状态是 `UNKNOWN`。记录里没有 `OVERTAKEN`。对账之后是 `FAILED`。原路由 200。`GET /providers/wanbexpress/v1/parcels/ABC123` 不是 200。`policy_version` 回到发布前的值 |
| cleanup | 通过。没有名字含 `idp-gateway-fabric` 的容器 |
| skip-authz-reload | 对照成立。202 之后终态 `FAILED`。parcels 404。快照未换。代次 0 |
| bad-binding | 对照成立。422，原因 `binding`。没有 202。parcels 404。代次 0。快照和策略文件未换 |

这不是验收通过。黑盒没有重跑。正式门禁仍是 `NOT_RUN`。
