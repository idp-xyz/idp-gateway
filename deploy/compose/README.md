# 单机上的一个网关池（docker compose）

运行平台的第一期是单机上的 docker compose（[ADR-0010](../../docs/adr/ADR-0010.md) 第 10 条；这篇 ADR 是建议，待具名批准）。这个目录是它的部署文件：一台机器上的一个池，池里一个网关实例。

> **单点。** 这台机器或它的 docker 停了，经它出去的调用全部中断。作为第一期可以接受；G01 要的分池和高可用，要到多机或 Kubernetes 才谈得上。  
> **验证到哪一步。** [`tests/integration/compose`](../../tests/integration/compose/README.md) 跑的就是这里的 `compose.yml`。其中"断电"是把容器强行杀掉来模拟的：真的重启一台机器，和 `idp-gateway-pool.service` 这个单元，都没有跑过。见文末"没有验证的"。

## 这里有什么

| 文件 | 是什么 |
|---|---|
| `compose.yml` | 一个池：五个服务，和它们启动的先后 |
| `front.nginx.conf` | 网关前面那层 nginx 的配置。各条指令与黑盒套件跑过的那一份相同，只差两个地址 |
| `.env.example` | 要填的变量，每一项的意思写在里面。复制成 `.env` 再填 |
| `idp-gateway-pool.service` | systemd 单元：开机时启动这个池，关机时停下它 |

发布器是 [`cmd/gateway-control`](../../cmd/gateway-control/main.go)，在本机上运行；`compose.yml` 里有两步跑的也是它。

## 一个池

| 服务 | | 做什么 |
|---|---|---|
| `netns` | 常驻 | 什么都不做，只占着网络命名空间和本机上的两个端口。`front` 和网关都接在它里面，相当于 Kubernetes 上同一个 Pod 里的两个容器；两个可以各自重启 |
| `place` | 跑完就退出 | 网关启动之前，把这个池上最后一次得到确认的那份配置放回目录里（`gateway-control place`）。它失败，网关不启动 |
| `agentgateway` | 常驻 | 网关：锁定的上游镜像，按摘要引用。配置目录和证书目录都是只读挂进去的 |
| `confirm` | 跑完就退出 | 网关起来之后对一次账（`gateway-control reconcile`）：经回读口确认网关在跑的就是那一份。它的退出码不是 0，`front` 不启动 |
| `front` | 常驻 | nginx。对外收业务请求的只有它；它没有启动时，业务端口上没有人应答 |

`docker compose up -d` 启动：`netns` 和 `place` 一起开始，两个之间没有先后；`netns` 起来了、`place` 也以退出码 0 跑完了，网关才启动；然后是 `confirm`；它的退出码是 0，才是 `front`。`docker compose stop` 停下。本机上只映射两个端口：业务端口（`CALLERS_LISTEN`），和只在回环上的回读口（`READBACK_PORT`）。

五个容器都没有重启策略（`restart: "no"`），docker 自己不去起其中任何一个：由 docker 起来的网关不经过 `place`，读到的是目录里当时放着的文件，不管有没有人确认过它。

## 准备

要有：Linux，docker 和 docker compose（测过的是 docker 29.8.1、compose 5.5.1），构建发布器用的 Go。

1. **发布器**。
   ```bash
   CGO_ENABLED=0 go build -trimpath -o gateway-control ./cmd/gateway-control
   ```
   必须是静态链接的。`place` 和 `confirm` 把这个文件挂进一个没有 glibc 的镜像里跑；默认方式构建出来的是动态链接的，在里面起不来（`exec /usr/local/bin/gateway-control: no such file or directory`）。在本机上发布用的也是这同一个文件。
2. **两个账号**。`CONTROL_USER` 是在本机上跑 `gateway-control` 的那个账号，`place` 和 `confirm` 以它的身份运行；`GATEWAY_USER` 是网关进程的身份。测过的只有两个是同一个账号的情况。
3. **池的目录**（`POOL_DIR`），下面两个子目录：
   - `config/`：属主是 `CONTROL_USER`，权限 0755。网关读的 `config.yaml`、发布器的锁文件和记录都在这里。除了发布器，谁都不要往里写。
   - `tls/`：网关用的证书和私钥（回读口的服务端证书、去问 PDP 用的客户端证书、CA），快照里按 `tls/<文件名>` 引用。发布器的证书不放在这里。
4. **会话密钥**：一个权限 0600 的文件，只有一行 `SESSION_KEY=<64 个十六进制字符>`。路径填进 `GATEWAY_ENV_FILE`。
5. **发布器的证书**：读回读口用的客户端证书和私钥，以及签发回读口证书的 CA。
6. **`.env`**：`cp .env.example .env`，逐项填。漏填的，`docker compose` 会说出是哪一个。

快照（发布器下发的那个网关配置文件）要守下面几条，部署文件是照着它们写的。样子见 `tests/integration/compose/run.py` 的 `gateway_config`。

- 收业务请求的监听在 `127.0.0.1:8081`。`front` 听 8080，把请求转到这里。
- 回读口在 8443，要客户端证书，只转发 `/config_dump` 和 `/api/runtime` 两个 GET。
- 管理、指标、就绪端口只绑回环，不占 8080、8081、8443。
- 存储模式 `readOnly`；证书按 `tls/<文件名>` 引用；正文里不引用环境变量（发布器会拒绝这种快照）。
- 路由的超时定得比 10 秒短：`front` 等网关最多 10 秒，超过了调用方看到的是 nginx 的 504，不是网关的。

## 头一次安装

1. 把第一份快照放到 `POOL_DIR/config/config.yaml`，权限 0644。
2. `docker compose up -d agentgateway`。只起 `netns`、`place` 和网关。这个池还没有记录，`place` 没有可放的（`NO_RECORD`），网关从放着的那个文件启动；`front` 没有启动，请求进不来。
3. 用发布器把同一份快照发布一次：`gateway-control publish --snapshot <那份文件> …`。放着的正是它，网关也报告它在生效，发布器只把它记下来（`ACTIVE`，不再写文件）。从这以后这个池有了记录。
4. `docker compose up -d`。`confirm` 对上了，`front` 启动，请求进得来了。
5. 要开机自己起来，再装 `idp-gateway-pool.service`，做法写在那个文件开头。

第 2 步直接跑 `docker compose up -d` 结果一样，只是它会以非零码结束：`confirm` 这时是 `UNCONFIRMED`。

## 日常

`gateway-control` 在本机上跑，用 `CONTROL_USER` 那个账号。各条命令做什么、结局和退出码是什么，见 [`tests/integration/compose/README.md`](../../tests/integration/compose/README.md) 第 8 到 11 点。

要读回读口的三条命令（`publish`、`restart`、`reconcile`）都带下面这一组参数，值与 `.env` 里的相同：

```bash
POOL="--config-dir $POOL_DIR/config --read-back 127.0.0.1:$READBACK_PORT --read-back-name $READBACK_NAME
      --tls-cert $PUBLISHER_CERT --tls-key $PUBLISHER_KEY --tls-ca $READBACK_CA"
```

`publish` 和 `restart` 在发布之前要另起一个临时容器加载这份快照，为此还要一组：

```bash
STAGING="--image <compose.yml 里网关用的那个镜像，按摘要>
         --staging-name <临时容器的名字> --staging-publish 127.0.0.1:<本机上一个空闲的端口> --staging-container-port 8443
         --staging-tls-dir <挂给临时容器的证书目录> --staging-work-dir <放候选配置的目录>"
```

临时容器挂哪一套证书还没有定：挂 `POOL_DIR/tls`，它也就拿到了池的私钥；另备一套，读它的回读口要另给证书（`--staging-tls-cert` 等三个参数），测试里用的是后一种。

| 要做的 | 怎么做 |
|---|---|
| 发布一份快照，网关不重启 | `gateway-control publish --snapshot <文件> $POOL $STAGING` |
| 发布一份要重启网关才能全部生效的快照 | `gateway-control restart --snapshot <文件> --container idp-gateway-pool-agentgateway-1 $POOL $STAGING`。池会中断一下 |
| 对账 | `gateway-control reconcile $POOL`，或者 `docker compose up -d`（见下） |
| 重启 `front` | `docker compose restart front`。网关不动 |
| 停，再起 | `docker compose stop`，`docker compose up -d` |

**`docker compose up -d` 可以随时再跑。** 常驻的三个容器在跑就不动，`place` 和 `confirm` 各重新跑一遍。所以在一个跑着的池上，它就是对一次账：放着的不是记录的那一份，`place` 把它放回去，网关重新加载，`confirm` 确认。命令的退出码不是 0，就是没对上，看 `docker compose logs place confirm`。有一种非零是已经收拾好了的：`confirm` 赶在网关重新加载之前去读，会自己再放一次，结局是 `RESTORED`（退出码 4）；这时再跑一次是 0。对着这份部署文件的测试里没有碰到过。

**不经过 `place` 的重启。** `docker compose restart agentgateway` 和 `docker restart` 直接重启网关：目录里放着什么，它就带着什么起来。要这样重启，先跑一次 `docker compose up -d`，退出码是 0 再重启。

## 启动时会发生什么

机器开机时由 `idp-gateway-pool.service` 跑 `docker compose up -d`；手工跑也一样。

| 启动时的情况 | 发生什么 | 之后 |
|---|---|---|
| 放着的就是记录的那一份 | `place` 不写（`IN_PLACE`），网关起来，`confirm` 是 `IN_SYNC`，`front` 启动。测试里从命令开始到第一个请求得到应答是 1.7 到 1.8 秒；机器忙的时候慢过，有一次是 6.5 秒 | |
| 放着的不是记录的那一份：发布器死在半路留下的，有人绕过发布器写的，网关加载不了的，或者文件没了 | `place` 把记录的那一份放回去，网关带着它起来，其余同上 | 不用做什么。原来放着的是哪一份，在 `docker compose logs place` 里 |
| 这个池还没有记录 | 网关从放着的文件起来；`confirm` 是 `UNCONFIRMED`（退出码 3），`front` 不启动 | 发布一次，再 `up -d`（"头一次安装"的第 3、4 步） |
| 记录读不成样子 | `place` 以退出码 1 结束，网关不启动 | 要人来看 `config/.config.yaml.confirmed`。确定该生效的是哪一份快照之后，把坏的记录挪走，照"头一次安装"做。这样收拾没有单独测过，走的是头一次安装的那几步 |
| 另一次发布正占着这个池 | `place` 以退出码 1 结束（`another publication … in progress`）。已经在跑的容器不受影响 | 等那次发布做完，再 `up -d` |
| 网关起不来，或者在 `CONFIRM_TIMEOUT` 之内读不到它 | `confirm` 是 `UNKNOWN`（退出码 5），`front` 不启动 | 看 `docker compose logs agentgateway`，修好之后再 `up -d` |
| 网关的构建不是做记录时的那个（换过镜像） | `confirm` 是 `UNCONFIRMED`，`front` 不启动。这一条只有单元测试，没有在部署文件上跑过 | 把在用的那份快照再发布一次 |

`up -d` 以非零码结束时，开机的那个单元的状态是 `failed`。

**对不上就不开门。** `confirm` 没有通过，`front` 就不启动，这个池不通，直到有人来处理。这是有意的取舍：宁可不通，也不带着一份没有确认过的配置收请求。批准 ADR-0010 的人可以改这个取舍。

## 停

`docker compose stop` 的先后（测试里量到的）：

1. `front` 收到 SIGQUIT：不再接新连接，把在途的请求做完才退出。最多等 60 秒。
2. 然后网关收到 SIGTERM：把在途的请求做完才退出。最多等到快照里的 `connectionTerminationDeadline`；容器的停止时限是 60 秒，前者要比它短。
3. 最后是 `netns`。

测试里停的时候有一个还要 3 秒左右才做完的请求，它做完了，得到 200。

## 要知道的

- **网关或 `front` 自己崩了，不会自己起来。** 没有重启策略（原因见上）。要起来，跑 `docker compose up -d`，它经过 `place` 和 `confirm`。崩溃之后自动恢复还没有做。
- **`netns` 这个容器单独死了，池就断了，只跑 `up -d` 修不好。** 网关和 `front` 还在跑，却连不到了；`up -d` 把 `netns` 重新起来，那两个仍接在原来的命名空间里，`confirm` 读不到网关，`front` 的端口上没有人应答。要先 `docker compose stop` 再 `docker compose up -d`。
- **发布器死在半路而机器没有重启时，没有谁会自动去对账。** 启动这个池时会对一次；平时不会。留在目录里的那份没有人确认过的文件网关已经加载了，直到有人跑 `gateway-control reconcile` 或 `docker compose up -d`。定时去跑还没有做。
- **后端的名字，要在网关第一次用到它之前就解析得了。** 网关是在第一个请求用到一个后端的名字时才去解析它的。那一次解析不了（名字还不存在），这条路由就一直答 `503 dns resolution failed`，名字解析得了之后也不恢复：测试里等了 20 秒，另一次单独的实验里等了 240 秒，都没有恢复；重启网关之后立刻就好。多久会自己恢复没有量到。解析器够不着（而不是名字不存在）时是不是也这样，没有测。
- **映射出来的端口不经过本机防火墙的 INPUT 规则。** 这是 docker 的做法，这里没有测。`CALLERS_LISTEN` 写成 `0.0.0.0:端口` 就是对所有网卡开放；要限制来源，把地址写成具体的网卡地址，或者在 docker 自己的规则链里限制。
- **`place` 和 `confirm` 每次启动各留一份 JSON 在自己容器的日志里**（`docker compose logs place confirm`）。日志写到哪里、留多久、容器的资源上限，都没有定：用的是 docker 的默认值。
- **一台机器上不止一个池**没有做：`compose.yml` 里的项目名是固定的，发布器做离线加载用的临时容器、端口和目录也要每个池各一套。

## 没有验证的

- **真的重启一台机器。** 测试里的"断电"是把三个常驻容器同时强行杀掉，再跑 `docker compose up -d`。docker 守护进程重启之后各容器是什么状态、单元在开机过程中跑得是不是时候，都没有看过。
- **`idp-gateway-pool.service` 本身。** 只用 `systemd-analyze verify` 查过写法（systemd 255），没有装到哪台机器上跑过。
- 崩溃之后的自动恢复；定时对账。
- 换镜像（升级 agentgateway）在这个部署上怎么做。
- `GATEWAY_USER` 和 `CONTROL_USER` 是两个不同的账号时，文件的属主和权限怎么定。
- 启动时本机上还没有镜像：`up -d` 会先去拉。镜像仓库那时够不着会怎样没有试过，测试时镜像已经在本机上。
- 别的环境。测的是 WSL2 里的 Ubuntu 24.04 上的 docker 29.8.1，不是一台普通的 Linux 主机；别的 docker 版本、Docker Desktop、arm64 都没有测。
- 其余没有覆盖的见 [`tests/integration/compose/README.md`](../../tests/integration/compose/README.md) 的"没有覆盖的"。
