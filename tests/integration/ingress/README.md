# 入口：编译结果在单机池上

这不是验收通过。2026-11-23 的测量记在 [ADR-0016](../../../docs/adr/ADR-0016.md) V1.3。

`pool.py` 用 `gateway-control compile` 编一份入口规格，再用 `gateway-control publish` 发到 `deploy/compose/compose.yml`。那份 compose 文件不改。替身在本目录的 `pool.yml` 里。调用方只打 `front`，不打网关自己的业务端口。没有 `gateway-authz`，没有 ExtAuthZ，没有承运商凭证。

## 怎么跑

```bash
.venv/bin/python tests/integration/ingress/pool.py
.venv/bin/python tests/integration/ingress/pool.py --evidence     # 写 evidence/pool-standin.json
.venv/bin/python tests/integration/ingress/pool.py --control no-readback-route
.venv/bin/python tests/integration/ingress/pool.py --control no-path-rule
.venv/bin/python tests/integration/ingress/pool.py --control backend-untrusted-ca
```

要 docker、`/usr/local/go/bin/go`、锁定的 agentgateway 1.7.0 二进制，以及仓库的 `.venv`（PyJWT、cryptography、PyYAML）。`--evidence` 把这一次运行记到 `evidence/pool-standin.json`，与万邦、顺丰的池套件同一个做法：先提交代码，从干净的工作区跑，证据单独提交，文件里的 `commit` 指向被测的那份代码。它不能和 `--control` 一起用：对照不是这份配置的证据。

本机端口只占 `27651`（front）、`27652`（回读口）、`27653`（发布器的临时容器）。`27654` 留着不用。都绑 `127.0.0.1`。和黑盒、compose、万邦、顺丰的池不能同时跑。

compose 项目名是 `idp-gateway-ingress-test`。结束时不论成败都 `docker compose down -v`，再删自己的容器、网络和临时目录。证书、密钥和令牌每次现做，不进仓库，也不进证据文件。

规格里的主机名、签发者、受众是 `.example` 或 `.test`。`listen_port` 是 8081，`readback_port` 是 8443，这是 `compose.yml` 和 `front.nginx.conf` 用的端口。上游名字是 `stand-in.ingress.example`，在 compose 网络上是替身的别名。出口规则只放行发布文件里写了的地址，替身从这条规则出去，不绕开。

## 用例

| 用例 | 检查什么 |
|---|---|
| IN-01 | `gateway-control publish` 退出码 0，结局是 `ACTIVE`。证据里留下那一行 |
| IN-02 | 不带令牌是 401，替身收到 0 次 |
| IN-03 | 相符的 JWT，`GET` 登记路径是 200，正文是替身的。替身看到网关的客户端证书。替身看到的 Host 是规格里的 authority |
| IN-04 | 替身的记录里没有 `Authorization`。另送 `Cookie`、`X-Forwarded-For` 和未登记的 `X-Not-Registered`，记下哪些到了替身。编译器的转发名单是 `accept`、`content-type`、`traceparent`。名单之外的头到达就是一项不通过，不把名单放宽。2026-11-23 到达的是这三项加上 Host。`traceparent` 的 trace id 与调用方送的相同，span id 被网关换成新的 |
| IN-05 | 登记路径上的 `HEAD`。记下状态，以及替身看到的方法和路径 |
| IN-06 | 未登记的方法 `POST`。状态是 403、404 或 405，替身收到 0 次。2026-11-23 的状态是 404 |
| IN-07 | 深一段的 `/v1/shipments/123` 是 403 或 404，替身收到 0 次。只在字符串上共用前缀的 `/v1/shipmentsX` 同样要求。2026-11-23 前者是 403，后者是 404 |
| IN-08 | 错受众、错签发者、过期、另一把密钥签名。每次都是 401，替身收到 0 次 |
| IN-09 | 另一个 Host。状态是 403 或 404，替身收到 0 次。2026-11-23 的状态是 404 |
| IN-10 | 替身应答带 `Location` 和 `Set-Cookie`。这两项都不到调用方 |
| IN-11 | 经 front 送两个 Host 头。nginx 答 400，正文是它自己的错误页。替身收到 0 次 |
| IN-12 | `docker compose stop` 再 `up -d`。记下 confirm 的退出码。place 和 confirm 都是 0 时池才算回来，然后 IN-03 再做一次 |
| IN-13 | 在网关的网络命名空间里新开连接。发布文件没有点名的地址被拒绝（`connect` 返回 113），替身的地址连得上。做法与 `tests/integration/wanbexpress/pool.py` 的出口用例相同 |
| IN-14 | 网关日志和替身记录里没有 JWT，也没有私钥材料。front 和替身容器的日志一并扫 |

## 对照

对照改的是这一次编译出来的文件，或者替身出示的证书。不改 `compose.yml`。

| `--control` | 改了什么 | 应当不通过的用例 |
|---|---|---|
| `no-readback-route` | 去掉回读路由再发布 | IN-01。发布器读不到 `/config_dump`，确认不了 |
| `no-path-rule` | 去掉精确路径的授权规则再发布 | IN-07。深一段的路径到达替身 |
| `backend-untrusted-ca` | 替身出示另一套 CA 的证书 | IN-03。网关拒绝替身，替身的应用收不到请求 |

2026-11-23 这三处都按上面不通过。`no-readback-route` 的 `publish` 退出码是 1，临时网关上 `GET /config_dump` 是 404；confirm 随后退出码 3，front 没有起来。`no-path-rule` 下 `/v1/shipments/123` 是 200 并且到了替身，`/v1/shipmentsX` 仍是 404。`backend-untrusted-ca` 下 IN-03 是 503 `upstream connection failed`，替身记录是 0 次；要等替身 200 的用例同样是 503。逐项在 ADR-0016 V1.3。

## 不覆盖

没有真实后端，没有真实签发者。入口池不在 `compose.yml` 里。主机名不是产品常量。没有压测。没有 `gateway-authz`。不跑黑盒套件、compose 套件、万邦套件或顺丰套件。不把任何正式门禁或验收用例标成已跑。
