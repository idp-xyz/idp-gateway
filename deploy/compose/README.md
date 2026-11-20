# 单机上的一个网关池（docker compose）

运行平台的第一期是单机上的 docker compose（[ADR-0010](../../docs/adr/ADR-0010.md) 第 10 条；这篇 ADR 是建议，待具名批准）。这个目录是它的部署文件：一台机器上的一个池，池里一个网关实例。

> **单点。** 这台机器或它的 docker 停了，经它出去的调用全部中断。作为第一期可以接受；G01 要的分池和高可用，要到多机或 Kubernetes 才谈得上。  
> **验证到哪一步。** [`tests/integration/compose`](../../tests/integration/compose/README.md) 跑的就是这里的 `compose.yml`，看守也是对着它跑的。其中"断电"是把容器强行杀掉来模拟的：真的重启一台机器没有做过。两个 systemd 单元没有装到哪台机器上跑过：它们之间的关系在用户级的 systemd 里用替身跑过，它们里面写的命令不经 systemd 原样跑过。见文末"没有验证的"。

## 这里有什么

| 文件 | 是什么 |
|---|---|
| `compose.yml` | 一个池：七个服务，和它们启动的先后 |
| `front.nginx.conf` | 网关前面那层 nginx 的配置。各条指令与黑盒套件跑过的那一份相同，只差两个地址 |
| `pin-egress.sh` | 装出口规则的脚本：网关所在的网络命名空间里，新的外出连接只许去配置里写着的地址（见"出口的规则"） |
| `.env.example` | 要填的变量，每一项的意思写在里面。复制成 `.env` 再填 |
| `idp-gateway-pool.service` | systemd 单元：开机时启动这个池，关机时停下它 |
| `idp-gateway-pool-keep.service` | systemd 单元：看守。池里的容器死了把它们起回来，平时每分钟对一次账（见"看守"） |
| `idp-gateway-pool.rules.yml` | 告警规则（Prometheus）：看的是看守给出的指标（见"告警"） |

发布器是 [`cmd/gateway-control`](../../cmd/gateway-control/main.go)，在本机上运行；`compose.yml` 里有两步跑的也是它，看守也是它的一条命令。

## 一个池

| 服务 | | 做什么 |
|---|---|---|
| `netns` | 常驻 | 什么都不做，只占着网络命名空间和本机上的两个端口。`front` 和网关都接在它里面，相当于 Kubernetes 上同一个 Pod 里的两个容器；两个可以各自重启 |
| `place` | 跑完就退出 | 网关启动之前，把这个池上最后一次得到确认的那份配置放回目录里（`gateway-control place`）。它失败，网关不启动 |
| `egress` | 跑完就退出 | 网关启动之前，在它所在的网络命名空间里装上出口的规则（`pin-egress.sh once`）。它失败，网关不启动 |
| `agentgateway` | 常驻 | 网关：锁定的上游镜像，按摘要引用。配置目录和证书目录都是只读挂进去的 |
| `confirm` | 跑完就退出 | 网关起来之后对一次账（`gateway-control reconcile`）：经回读口确认网关在跑的就是那一份。它的退出码不是 0，`front` 不启动 |
| `front` | 常驻 | nginx。对外收业务请求的只有它；它没有启动时，业务端口上没有人应答 |
| `egress-watch` | 常驻 | 每两秒跑一遍同一个脚本（`pin-egress.sh watch`）：发布换上来的配置里多出来的后端，靠它放行。看守不数它 |

`docker compose up -d` 启动：`netns` 和 `place` 一起开始，两个之间没有先后；`netns` 起来了、`place` 也以退出码 0 跑完了，才是 `egress`；它也以 0 跑完了，网关才启动；然后是 `confirm`；它的退出码是 0，才是 `front`。`egress-watch` 在 `egress` 跑完之后启动，别的都不等它。`docker compose stop` 停下。本机上只映射两个端口：业务端口（`CALLERS_LISTEN`），和只在回环上的回读口（`READBACK_PORT`）。

七个容器都没有重启策略（`restart: "no"`），docker 自己不去起其中任何一个：由 docker 起来的网关不经过 `place` 和 `egress`，读到的是目录里当时放着的文件，不管有没有人确认过它。容器死了，把它们起回来的是看守：它跑的也是 `docker compose up -d`。

## 出口的规则

锁定的网关按名字找后端，名字后来指到哪里它就去哪里，没有哪项设置能让它不跟（[`tests/integration/egressnet`](../../tests/integration/egressnet/README.md)）。所以限制放在它所在的网络命名空间里：`pin-egress.sh` 读配置目录里的 `config.yaml`，新的外出连接只放行下面这些，别的一律拒绝，IPv6 的也是。

- 配置里每一处 `host: 名字:端口`：那个名字**第一次**解析到的各个 IPv4 地址，只在那个端口上。写的是 IPv4 地址时照写的放行；回读路由转给的管理地址 `127.0.0.1:<管理端口>` 就是这样放行的。
- 解析器：Docker 给容器的那一个，和它去问的上游解析器（`resolv.conf` 里 `# ExtServers:` 那一行写着的）。
- 回环上的 `127.0.0.1:8081`：`front` 把业务请求转给网关。回环上别的端口（网关的指标、就绪端口）与别的地址一样被拒绝。
- 已经建立的连接上的往来。

用的时候要知道：

- **一个名字只解析一次。** 钉住的地址记在规则里，跟着这个网络命名空间走：网关重启、`egress-watch` 重启、再跑 `docker compose up -d`，都不重新解析；`netns` 换过（停了再起，机器重启），才从头来。还没解析出来过的名字会接着试。
- **后端的地址真的换了**，要人来说一声：`docker compose run --rm --no-deps egress forget`。它丢掉全部钉住的地址，按现在的解析重新钉。在那之前，去那个后端的请求得到 503。地址经常变的后端（CDN、多地域）不合用。
- **钉的是第一次解析到的地址**，信的是那一刻的解析器；没有一份独立的"登记的地址"可以对照。它防的是之后被改指。
- **发布换上来的配置里多了一个后端**，要等 `egress-watch` 下一遍（两秒之内）才连得通。它没在跑时，新的后端一直连不通，已经放行的不受影响；谁都不会因此收到通知，看守不数它。`docker compose up -d` 会把它起回来。
- **被规则拒绝的连接**，网关那边看到的是"no route to host"，不是"connection refused"。
- **只认这一种写法**：一行一个 `host: 名字:端口`。别的写法（写在花括号里的，带协议前缀的）认不出来，认不出来的不放行。
- 装规则的两个容器以 root 运行，除了 `NET_ADMIN` 没有别的 capability，所以读配置靠的是文件对所有人可读：发布器写的是 0644，目录要 0755。镜像（`EGRESS_IMAGE`）只用里面的 iptables。
- `egress-watch` 与 `netns` 共用 PID 命名空间：`netns` 一死它就跟着死，不会留在已经没用的那个网络命名空间里。

## 准备

要有：Linux，docker 和 docker compose（测过的是 docker 29.8.1、compose 5.5.1），构建发布器用的 Go；装两个单元还要 systemd（查写法、跑替身用的是 255）。

1. **发布器**。
   ```bash
   CGO_ENABLED=0 go build -trimpath -o gateway-control ./cmd/gateway-control
   ```
   必须是静态链接的。`place` 和 `confirm` 把这个文件挂进一个没有 glibc 的镜像里跑；默认方式构建出来的是动态链接的，在里面起不来（`exec /usr/local/bin/gateway-control: no such file or directory`）。在本机上发布用的也是这同一个文件。
2. **两个账号**。`CONTROL_USER` 是在本机上跑 `gateway-control` 的那个账号，`place` 和 `confirm` 以它的身份运行，看守也是，所以它要用得了 docker；`GATEWAY_USER` 是网关进程的身份。测过的只有两个是同一个账号的情况。
3. **池的目录**（`POOL_DIR`），下面三个子目录：
   - `config/`：属主是 `CONTROL_USER`，权限 0755。网关读的 `config.yaml`、发布器的锁文件和记录都在这里。除了发布器，谁都不要往里写。
   - `tls/`：网关用的证书和私钥（回读口的服务端证书、去问 PDP 用的客户端证书、CA），快照里按 `tls/<文件名>` 引用。发布器的证书不放在这里。
   - `history/`：发布历史（见"发布历史"）。属主是 `CONTROL_USER`，权限 0700。**要先建好**：命令不自己建它，也不检查它的属主和权限。网关、`front`、`egress` 的容器都不挂它，`compose.yml` 里没有哪个服务提到它。
     ```bash
     install -d -m 0700 -o <CONTROL_USER> "$POOL_DIR/history"
     ```
4. **会话密钥**：一个权限 0600 的文件，只有一行 `SESSION_KEY=<64 个十六进制字符>`。路径填进 `GATEWAY_ENV_FILE`。
5. **发布器的证书**：读回读口用的客户端证书和私钥，以及签发回读口证书的 CA。
6. **`.env`**：`cp .env.example .env`，逐项填。漏填的，`docker compose` 会说出是哪一个。每一行只写 `名字=值`：值不加引号，后面不跟注释，里面不要有空白、`$`、`#` 和反斜杠。读这个文件的除了 docker compose 还有 systemd（看守的单元），别的写法两边读出来不一样；看守启动时会核对，不合要求就不启动（见"看守"）。

快照（发布器下发的那个网关配置文件）要守下面几条，部署文件是照着它们写的。样子见 `tests/integration/compose/run.py` 的 `gateway_config`。

- 收业务请求的监听在 `127.0.0.1:8081`。`front` 听 8080，把请求转到这里。
- 回读口在 8443，要客户端证书，只转发 `/config_dump` 和 `/api/runtime` 两个 GET。
- 管理、指标、就绪端口只绑回环，不占 8080、8081、8443。
- 存储模式 `readOnly`；证书按 `tls/<文件名>` 引用；正文里不引用环境变量（发布器会拒绝这种快照）。
- 路由的超时定得比 10 秒短：`front` 等网关最多 10 秒，超过了调用方看到的是 nginx 的 504，不是网关的。

## 头一次安装

1. 把第一份快照放到 `POOL_DIR/config/config.yaml`，权限 0644。再建历史目录：`install -d -m 0700 -o <CONTROL_USER> "$POOL_DIR/history"`（"准备"第 3 点）。它要在看守启动之前、第一次带历史的发布之前就在：看守的单元和下面第 3 步都要用它。
2. `docker compose up -d agentgateway`。只起 `netns`、`place`、`egress` 和网关。这个池还没有记录，`place` 没有可放的（`NO_RECORD`），网关从放着的那个文件启动；`front` 没有启动，请求进不来。
3. 用发布器把同一份快照发布一次：`gateway-control publish --snapshot <那份文件> … $HISTORY`（`$HISTORY` 见"日常"）。放着的正是它，网关也报告它在生效，发布器只把它记下来（`ACTIVE`，不再写文件）。从这以后这个池有了记录。
4. `docker compose up -d`。`confirm` 对上了，`front` 启动，请求进得来了。
5. 要开机自己起来、容器死了自己起回来，再装两个单元：`idp-gateway-pool.service` 和 `idp-gateway-pool-keep.service`，做法写在各自文件的开头。

第 2 步直接跑 `docker compose up -d` 结果一样，只是它会以非零码结束：`confirm` 这时是 `UNCONFIRMED`。

第 2、4 步也可以交给看守（`SH-18`）：第 1 步之后启动它。它跑启动命令，网关起来了，`confirm` 没有可对的，`front` 不开；它隔得越来越久再试，不碍事。第 3 步做完，它下一次对账时（一分钟之内）看到账对上了，不等到原定的时候，下一眼就跑启动命令把 `front` 开了。

## 日常

`gateway-control` 在本机上跑，用 `CONTROL_USER` 那个账号。各条命令做什么、结局和退出码是什么，见 [`tests/integration/compose/README.md`](../../tests/integration/compose/README.md) 第 8 到 11 点；三条历史的命令见第 17 点。

要读回读口的三条命令（`publish`、`restart`、`reconcile`）都带下面这一组参数，值与 `.env` 里的相同：

```bash
POOL="--config-dir $POOL_DIR/config --read-back 127.0.0.1:$READBACK_PORT --read-back-name $READBACK_NAME
      --tls-cert $PUBLISHER_CERT --tls-key $PUBLISHER_KEY --tls-ca $READBACK_CA"
```

要记历史的命令（`publish`、`restart`、`rollback`、`releases`、`release`）再带一组，值是固定的：`--history-dir` 是 `POOL_DIR/history`，`--pool` 是 `compose.yml` 里的项目名 `idp-gateway-pool`（看守的单元里写的也是它，不新增 `.env` 变量）：

```bash
HISTORY="--history-dir $POOL_DIR/history --pool idp-gateway-pool"
```

**手工跑这几条命令时不给 `$HISTORY`，就没有历史**，这一次发布在历史里查不到（见"发布历史"和"要知道的"）。

`publish` 和 `restart` 在发布之前要另起一个临时容器加载这份快照，为此还要一组：

```bash
STAGING="--image <compose.yml 里网关用的那个镜像，按摘要>
         --staging-name <临时容器的名字> --staging-publish 127.0.0.1:<本机上一个空闲的端口> --staging-container-port 8443
         --staging-tls-dir <挂给临时容器的证书目录> --staging-work-dir <放候选配置的目录>"
```

临时容器挂哪一套证书还没有定：挂 `POOL_DIR/tls`，它也就拿到了池的私钥；另备一套，读它的回读口要另给证书（`--staging-tls-cert` 等三个参数），测试里用的是后一种。

| 要做的 | 怎么做 |
|---|---|
| 发布一份快照，网关不重启 | `gateway-control publish --snapshot <文件> $POOL $STAGING $HISTORY --note "<为什么>"` |
| 发布一份要重启网关才能全部生效的快照 | `gateway-control restart --snapshot <文件> --container idp-gateway-pool-agentgateway-1 $POOL $STAGING $HISTORY`。池会中断一下 |
| 看发布过什么 | `gateway-control releases $HISTORY --config-dir $POOL_DIR/config`；一条的详情：`gateway-control release $HISTORY --id <编号>`（见"发布历史"） |
| 回到更早的一份 | `gateway-control rollback --to <编号> $POOL $STAGING $HISTORY --note "<为什么>"`（见"发布历史"） |
| 对账 | 看守每分钟做一次（见"看守"）。要现在就对一次：`gateway-control reconcile $POOL`（要顺手给停在半路的发布补结局，再加 `$HISTORY`），或者 `docker compose up -d`（见下） |
| 重启 `front` | `docker compose restart front`。网关不动 |
| 停，再起 | 装了两个单元：`systemctl stop idp-gateway-pool.service`，`systemctl start idp-gateway-pool.service`。没有装：`docker compose stop`，`docker compose up -d`。见"停" |
| 看看守做过什么 | `journalctl -u idp-gateway-pool-keep.service` |

**`docker compose up -d` 可以随时再跑。** 常驻的三个容器在跑就不动，`place` 和 `confirm` 各重新跑一遍。所以在一个跑着的池上，它就是对一次账：放着的不是记录的那一份，`place` 把它放回去，网关重新加载，`confirm` 确认。命令的退出码不是 0，就是没对上，看 `docker compose logs place confirm`。有一种非零是已经收拾好了的：`confirm` 赶在网关重新加载之前去读，会自己再放一次，结局是 `RESTORED`（退出码 4）；这时再跑一次是 0。对着这份部署文件的测试里没有碰到过。

**不经过 `place` 的重启。** `docker compose restart agentgateway` 和 `docker restart` 直接重启网关：目录里放着什么，它就带着什么起来。要这样重启，先跑一次 `docker compose up -d`，退出码是 0 再重启。看守在跑时这样重启会怎样没有测：它要是正好在网关停着的那一下看了一眼，会去跑启动命令。

**看守在跑时，这几条命令极少数时候会撞上它正在对账的那一下。** `publish`、`restart`、`reconcile` 以退出码 1 结束，`docker compose up -d` 里的 `place` 或 `confirm` 也是，说的都是 `another publication to this pool is in progress`。池没有被碰过，再跑一次。它每分钟对一次账，账对得上时一次只占 0.01 秒左右。

## 启动时会发生什么

机器开机时由 `idp-gateway-pool.service` 跑 `docker compose up -d`；手工跑也一样，看守把池起回来时跑的也是它。

| 启动时的情况 | 发生什么 | 之后 |
|---|---|---|
| 放着的就是记录的那一份 | `place` 不写（`IN_PLACE`），网关起来，`confirm` 是 `IN_SYNC`，`front` 启动。测试里从命令开始到第一个请求得到应答是 1.7 到 1.8 秒；机器忙的时候慢过，有一次是 6.5 秒 | |
| 放着的不是记录的那一份：发布器死在半路留下的，有人绕过发布器写的，网关加载不了的，或者文件没了 | `place` 把记录的那一份放回去，网关带着它起来，其余同上 | 不用做什么。原来放着的是哪一份，在 `docker compose logs place` 里 |
| 这个池还没有记录 | 网关从放着的文件起来；`confirm` 是 `UNCONFIRMED`（退出码 3），`front` 不启动 | 发布一次，再 `up -d`（"头一次安装"的第 3、4 步） |
| 记录读不成样子 | `place` 以退出码 1 结束，网关不启动 | 要人来看 `config/.config.yaml.confirmed`。确定该生效的是哪一份快照之后，把坏的记录挪走，照"头一次安装"做。这样收拾没有单独测过，走的是头一次安装的那几步 |
| 另一次发布正占着这个池 | `place` 以退出码 1 结束（`another publication … in progress`）。已经在跑的容器不受影响 | 等那次发布做完，再 `up -d` |
| 网关起不来，或者在 `CONFIRM_TIMEOUT` 之内读不到它 | `confirm` 是 `UNKNOWN`（退出码 5），`front` 不启动 | 看 `docker compose logs agentgateway`，修好之后再 `up -d` |
| 网关的构建不是做记录时的那个（换过镜像） | `confirm` 是 `UNCONFIRMED`，`front` 不启动。这一条只有单元测试，没有在部署文件上跑过 | 把在用的那份快照再发布一次 |

`up -d` 以非零码结束时，开机的那个单元的状态是 `failed`。看守照样启动，上表里要"再 `up -d`"的那一步由它来做：它隔一阵再跑一次启动命令（10 秒起，越隔越久，最长 5 分钟），毛病去掉之后的那一次就起来了。池的单元这时仍是 `failed`；要它回到 `active`，再 `systemctl start` 它一次。

**对不上就不开门。** `confirm` 没有通过，`front` 就不启动，这个池不通，直到有人来处理。这是有意的取舍：宁可不通，也不带着一份没有确认过的配置收请求。看守不改这一条：它再试时走的是同一条启动命令，对不上照样不开门。批准 ADR-0010 的人可以改这个取舍。

## 看守

`gateway-control keep` 是常驻的，守着这一个池；由 `idp-gateway-pool-keep.service` 跑，身份是 `CONTROL_USER` 那个账号。它做两件事：

- **每 5 秒看一眼三个常驻容器**：`netns`、网关和 `front`。下文说的"三个常驻容器"都是这三个；第四个常驻的 `egress-watch` 它不看。有没在跑的，它跑启动命令 `docker compose up -d`。这与开机时是同一条命令，所以照样是 `place` 和 `egress` 在先，`confirm` 对上了才开 `front`。它自己不直接启动哪个容器，也不重启在跑着的容器。
- **网关在跑时每分钟对一次账**，做的就是 `gateway-control reconcile`。发布器死在半路留下的文件、有人绕过发布器写的文件，到这时被收回去。

| 它看到的 | 它做什么 |
|---|---|
| 三个都在跑 | 到时候对一次账，别的不做 |
| 网关或 `front` 没在跑：崩了，被杀掉，被人停了 | 跑启动命令。在跑的容器不动 |
| `netns` 没在跑，网关或 `front` 却还在跑（它们这时谁也连不到，只跑启动命令修不好） | 先把这两个停下（`docker compose stop front agentgateway`，照常等在途的请求做完），再跑启动命令。它只在这一种情况下停容器 |
| 另一次发布正占着这个池 | 不动手，下一眼再看。带重启的发布会让网关停一下，那不是它死了 |
| 跑了启动命令却没修好：网关起不来，还没有记录，记录坏了 | 隔得越来越久再试：10 秒、20 秒、40 秒……最长 5 分钟。这期间 `front` 没开，账照样对。等着的时候账对上了（第一份发布刚做完，或者网关这才读得到），它不等到原定的时候，下一眼就再试 |
| 对账时放着的不是记录的那一份 | 把记录的那一份放回去（`RESTORED`），写出原来放着的是哪一份 |
| 对账的结局是 `RESTART_PENDING`、`UNKNOWN` 或 `UNCONFIRMED` | 只写出来。它不重启网关：重启会让池中断，什么时候做由人定（不给快照的 `gateway-control restart`） |
| 对账之后，历史里有一条停在半路、没有结局的发布 | 给它补上结局（见"发布历史"）。补不成不影响上面任何一行 |

网关死了到它回来有多久：最长是看一眼的间隔，加上启动命令把它起起来的一两秒。测试里（`SH-16`）网关被强行杀掉之后，请求有 5 秒出头得到 502，然后照常；`front` 一直开着。

单元里它还带着 `--history-dir ${POOL_DIR}/history --pool idp-gateway-pool`：每一次对账之后，给历史里停在半路的发布补上结局。**历史有毛病时它不停**：目录不在、读不成、日志坏了，它照常启动、照常看三个容器、照常对账、照常把死掉的容器起回来，对账的结局和退出码也不变，只是不补历史：目录打不开时它启动时在标准错误上说一句；对账之后补不成时，它写的那一行里有 `history_notes`（它有事才写，所以不是每一分钟都有）（`SH-30`）。

三个间隔是默认值，可以改（`--interval`、`--reconcile-interval`、`--max-backoff`）。默认的间隔在测试里只有 `SH-16` 的头几步用；别的步骤为了跑得快，把看一眼的间隔设成 1 秒，对账的间隔设成 5 秒或 1 秒，所以"越隔越久"量到的是 2、4、8、16 秒，到 5 分钟封顶只有单元测试。

**它在跑的时候，这个池停不住。** `docker compose stop` 停下的容器，它下一眼就起回来（`SH-18`）。要让池停着，先停它；见"停"。

**它写什么。** 一行一份 JSON，写到标准输出，装了单元时在 `journalctl -u idp-gateway-pool-keep.service -o cat` 里。有事才写：动过容器的，往回放过文件的，以及池的样子或对账的结局与上一行不同的。一个安稳的池，启动时一行，之后不出声。

| 项 | 意思 |
|---|---|
| `condition`、`why` | 三个常驻容器合起来的样子和依据：`whole` 都在跑；`down` 有没在跑的；`orphaned` 网关或 `front` 接着的命名空间已经不在了 |
| `busy` | 另一次发布正占着这个池，这一次该做的没有做 |
| `action` | 对容器做了什么：空着是没有动；`start` 跑了启动命令；`stop+start` 先停下接错了命名空间的，再跑启动命令 |
| `repaired`、`start_error`、`retry_in_seconds` | 动手之后三个容器是不是都在跑了；启动命令没成功时它最后说的那一句；没修好时离下一次再试还有几秒 |
| `reconcile` | 这一次对账的结果，与 `gateway-control reconcile` 写的是同一种；这一次没有对账时是 `null` |
| `pool`、`after` | 动手之前、之后三个容器各自的状态 |
| `error` | 这一眼没看成（比如问不到 docker），或者有一步没做成 |
| `history_notes` | 对账时发布历史那一边要说的：补不成（历史目录不在、读不成、日志坏了）、没有补，及原因。没有话说时这一项不出现；`reconcile` 里的 `history_settled` 是这一次补上结局的发布的编号 |

**这些行没有人看，它说的事就没有人知道**：修不好，`RESTART_PENDING`，`UNKNOWN`。它安稳的时候不出声，所以它不出声也说明不了它还在跑。要有人知道，靠的是下面的"告警"。

**两个单元。** 怎么装写在两个文件的开头。看守的单元里要改的是 `User=`、`Group=`（`CONTROL_USER` 的那个账号，要用得了 docker）和两处目录；`--pool` 是 `compose.yml` 的项目名，不要改（改了，历史里就是另一个池）。它跟着池的单元走：

| 做什么 | 发生什么 |
|---|---|
| `systemctl start idp-gateway-pool.service`，开机时也是 | 启动命令跑完，看守才启动。启动命令以非零码结束时池的单元是 `failed`，看守照样启动，照上面的表隔一阵再试 |
| `systemctl stop idp-gateway-pool.service` | 看守先停，它手上的那条 docker compose 命令让它跑完；然后才是 `docker compose stop` |
| `systemctl restart idp-gateway-pool.service` | 看守停，池停，池起，看守起 |
| 池的单元是 `failed` 时 `systemctl stop` 它 | 看守停了，**`docker compose stop` 却不会跑**：单元不是 `active`，systemd 不跑它的停止命令。看守这之前把池起来了的话容器还在跑，要再手工跑一次 `docker compose stop` |
| 看守自己死了，或者有人直接给它发信号 | systemd 过 5 秒把它重新起来，池不受影响。要停它得用 `systemctl` |
| 看守以退出码 2 结束 | 不再重新起，单元的状态是 `failed`：命令行或者 `.env` 写得不对，再起一次也一样。是哪里不对在日志里。改好之后 `systemctl start idp-gateway-pool.service`：池的单元已经是 `active` 时，这只把看守带起来，启动命令不再跑 |
| `systemctl stop idp-gateway-pool-keep.service` | 只停看守，池照常跑，只是没有人守着了；池的单元下一次启动或重启时它跟着起来。这一条没有单独跑过 |

它一开始就装不起来时（账号不是配置目录的属主，证书读不了）以退出码 1 结束，systemd 每 5 秒再起它一次，原因每次都在日志里。

**它启动时核对 `.env`。** 它跑 docker compose 时，环境里带着 systemd 从 `.env` 读出来交给它的那些变量，而 docker compose 先用环境里的变量，没有的才去读文件。两边读法不同的行（值后面跟着注释的，带引号的，带 `$` 的）会让它跑的启动命令拿到的设置与开机时的不同：容器被重建，或者起不来。所以它只接受"准备"第 6 点的那种写法；环境里另有同名而值不同的变量时它也不启动。它指出是哪个文件的哪一行、哪个变量，值不写出来（`SH-18`）。

**验证到哪一步。** 真的看守对着真的网关和这份部署文件跑过，由测试脚本直接起，不经 systemd（`SH-16` 到 `SH-18`）。两个单元里写的命令原样跑过，也不经 systemd：在一个放着 `compose.yml` 和 `.env` 的目录里，不另给 docker compose 项目名和文件（`SH-19`）。两个单元之间的关系，也就是上面这张表，在用户级的 systemd 里用替身命令跑过（[`units.py`](../../tests/integration/compose/units.py)）。两个单元没有装到哪台机器上跑过，见"没有验证的"。

## 发布历史

[ADR-0013](../../docs/adr/ADR-0013.md)（Proposed）。每一次发布在历史里是一条记录：谁发起的、什么时候、发布的是哪一份快照、每一步和结局；快照的全文按它的 SHA-256 存着，所以能回到更早的一份。

**在哪里，谁碰它。** `POOL_DIR/history`，池的目录下的第三个子目录，0700，归 `CONTROL_USER`，要先建好（"准备"第 3 点）。里面是 `releases.log`（只追加，一行一个 JSON，0600）和 `snapshots/`（0700，每份快照一个文件，名字是内容的 SHA-256，0600）。碰它的只有两样：**看守**（每分钟对账之后给停在半路的发布补结局，没有这样的发布时只读）和**操作员手工跑的** `publish`、`restart`、`rollback`、`releases`、`release`（都要给 `$HISTORY`）。**开机的路上不碰它**：`compose.yml` 里没有哪个服务挂它，`place` 和 `confirm` 不给 `--history-dir`。所以历史目录丢了、日志坏了，机器照样起得来，池照样通；给停在半路的发布补结局由看守的对账做，不在开机时做（`SH-30`）。

**一条记录的样子。** `STAGED`（离线加载通过）、`APPLYING`（换文件之前；带重启的发布里重启网关之前也有一行）、`OBSERVING`（等网关报告），然后是结局：`ACTIVE`，或 `FAILED`（这份被放回去了，没有生效），或 `UNKNOWN`（没能确认放回去）。每一步都先写后做：`APPLYING` 写不进去，这一步就不做，池什么都没有动（`publish` 以退出码 1 结束）。`SUPERSEDED` 不是写下去的：读的时候，后来有更晚的 `ACTIVE`，前一条就显示成它。

**三条新命令。**

```bash
# 发布一份，留一句话（备注最长 512 字节，没有人核实，不要往里放秘密）
gateway-control publish --snapshot new.yaml $POOL $STAGING $HISTORY --note "加路由 x，工单 1234"

# 看这个池发布过什么，并与池的记录比
gateway-control releases $HISTORY --config-dir $POOL_DIR/config

# 一条的详情：每一步、发起人（发布器证书上的身份和操作系统账号，进程自己报的）、备注（标着未经核实）
gateway-control release $HISTORY --id 12

# 回到第 9 条放上去的那一份
gateway-control rollback --to 9 $POOL $STAGING $HISTORY --note "12 之后 x 路由 404"
```

**回滚是一次新的发布。** 它从历史里取出那份快照，走 `publish` 的全部检查和确认（不引用环境变量，用现在的镜像离线加载，池要对得上记录，回读确认），记成新的一条，记着它回到的是第几条；历史里已有的各行一个字不改。回到的那一份要重启网关才生效（启动设置不同）：默认是 `RESTART_REQUIRED`，什么都不动；加 `--with-restart --container <网关容器>` 才重启（这一条没有在真的池上跑过，只有单元测试）。

**回滚被拒绝**（结局 `REFUSED`，退出码 3，池没有动，不占编号）：编号不存在；那一条没有到过 `ACTIVE`（`FAILED`、`UNKNOWN`、`OVERTAKEN` 的都不行）；那份快照就是现在放着的；老快照用现在的镜像加载不了。快照文件被改过、与它的 SHA-256 对不上，或者历史读不成：退出码 1，池没有动（`SH-28`）。

**几个要认得的字。**

| 看到的 | 是什么，怎么办 |
|---|---|
| `ACTIVE_NOT_RECORDED`，`publish` 退出码 8 | 这份快照已经在池里生效、池的记录也换了，只是历史里 `ACTIVE` 那一行没有写进去。池没有问题。先查历史目录为什么写不了（磁盘满、权限、目录不在）；之后再跑一次同样的 `publish`，它给停着的那一条补上结局，不另开一条（`SH-27`），或者等看守下一次对账补。`restart` 和 `rollback` 这样停下来的，由看守或 `reconcile $POOL $HISTORY` 补。脚本里调用 `publish` 的要认得这个退出码：不是成功，也不是什么都没变。在真的池上卡不准这一瞬间，这个结局本身只有单元测试 |
| `OVERTAKEN` | 一条停在半路没有结局的，后来又有更晚的发布开始了，对账给它补的结局：它有没有生效过，不知道（没有借用 `FAILED`）。看比它晚的那一条 |
| 补成 `FAILED`（步骤名 `reconcile`） | 发布器死在半路（被杀、断电），对账把记录的那一份放回去了；这一条的快照没有生效。原因里写着池的记录确认的是哪一份。带重启的发布做到一半被杀时，网关可能已经带着新的启动设置在跑，这一条仍补成 `FAILED`，对账的结局是 `RESTART_PENDING`，用不给快照的 `restart` 把启动设置带回来（`SH-26`） |
| 补成 `ACTIVE`（步骤名 `reconcile` 或 `publish-again`） | 池的记录确认的就是这份、确认在这一条开始之后：事后补上的结局，原因里写明 |
| `releases` 的 `comparison` 是 `mismatch`（对不上） | 池的记录确认的那份，不是历史里最后一条 `ACTIVE` 的快照。池在跑什么以池的记录和网关的回读为准，历史只说发布器记得做过什么。常见的原因：有人手工跑发布时没给 `$HISTORY`（再带着历史发布一次，同一份也行，就又对得上，`SH-29`）；收尾那一行没有写上，看守还没来补；历史目录被换成旧的一份，或者丢了；有人绕过发布器改了配置文件。不要为了让它对上去改日志 |
| `comparison` 是 `nothing_to_compare`、`record_unreadable` | 池没有记录、历史里也没有 `ACTIVE`；或者池的记录读不成样子（要人看 `config/.config.yaml.confirmed`，见"启动时会发生什么"） |
| 看守输出里的 `history_notes` | 历史有毛病、没有补上。池不受影响；看守的标准错误和这一项里有原因。修好历史目录（建回来、改权限、把坏的日志挪走后从备份放回）之后恢复 |

## 告警

看守在 `.env` 里 `KEEPER_METRICS_LISTEN` 的那个地址上给出指标（`http://地址/metrics`，Prometheus 的文本格式），每看完一眼更新一次。Prometheus 隔一阵来读，照 [`idp-gateway-pool.rules.yml`](idp-gateway-pool.rules.yml) 里的规则决定什么时候该叫人。

> **做到哪一步。** 规则说的是什么时候该叫人。叫到谁、怎么叫（Alertmanager 的路由和接收人）不在这个仓库里，没有做。Prometheus 自己停了由谁发现，也不在这里。

**接上 Prometheus。** 抓取任务要叫 `idp-gateway-keeper`：头一条规则靠这个名字知道该有一个看守、现在读不到它。

```yaml
rule_files:
  - /etc/prometheus/idp-gateway-pool.rules.yml   # 本目录里的那一份
scrape_configs:
  - job_name: idp-gateway-keeper
    static_configs:
      - targets: ["127.0.0.1:9617"]              # .env 里 KEEPER_METRICS_LISTEN 的那个地址
```

- Prometheus 要够得着那个地址。它跑在容器里时够不着本机的回环，这时把 `KEEPER_METRICS_LISTEN` 写成它够得着的那个本机地址。
- 这些数没有设防，够得着这个地址的都读得到。里面没有配置的内容，也没有凭证。那个地址上只有 `/metrics`，只读。
- `KEEPER_METRICS_LISTEN` 写成 地址:端口，地址不能省。`.env` 里漏了这一项时看守不启动（退出码 2，单元停在 `failed`）：不然告警就悄悄没有了。那个地址被别的进程占着时它也不启动（退出码 1，systemd 每 5 秒再起它一次）。

**它给出的数。** 看守重新启动之后，各个次数从 0 算起。

| 名字 | 意思 |
|---|---|
| `idp_gateway_keeper_info{project=…}` | 总是 1；标签是它守着的 compose 项目 |
| `idp_gateway_keeper_start_time_seconds` | 它启动的时刻 |
| `idp_gateway_keeper_look_interval_seconds`、`idp_gateway_keeper_reconcile_interval_seconds` | 它多久看一眼、多久对一次账 |
| `idp_gateway_keeper_looks_total` | 看完了多少眼 |
| `idp_gateway_keeper_last_look_timestamp_seconds` | 上一眼是什么时候看完的；头一眼还没有看完时是它启动的时刻 |
| `idp_gateway_keeper_last_look_failed` | 上一眼没看成，或者有一步没做成，是 1。原因在它写的那一行的 `error` 里 |
| `idp_gateway_pool_condition{condition=…}` | 上一眼看完时三个常驻容器合起来的样子，成立的那个是 1：`whole`、`down`、`orphaned`，或者 `unknown`（没看成）。动过手的，是动手之后的样子 |
| `idp_gateway_pool_busy` | 上一眼时一次发布正占着这个池，该做的没有做，是 1 |
| `idp_gateway_pool_unrepaired_attempts` | 接连几次跑了启动命令却没修好；修好了回到 0 |
| `idp_gateway_pool_starts_total` | 跑过多少次启动命令 |
| `idp_gateway_pool_reconcile_outcome{outcome=…}` | 上一次对账的结局，是哪个哪个是 1；还没有对过账时都是 0。网关没在跑时不对账，这里留着的是之前的那一次 |
| `idp_gateway_pool_last_reconcile_timestamp_seconds` | 上一次对账是什么时候做完的；还没有对过时是 0 |
| `idp_gateway_pool_snapshots_put_back_total` | 对账时把记录的那一份放回去过多少次。启动命令里 `place` 放回去的不算在这里 |

**规则。** 各条的时长是执笔时取的，没有对着真实的要求调过。

| 规则 | 什么时候响 | 严重程度 |
|---|---|---|
| `GatewayKeeperDown` | 连着 1 分钟读不到看守：它没有在跑（没有装单元，单元停在 `failed`，被停了），或者够不着。别的规则读的都是看守自己给的数，它没了它们就都不响，所以这一条是底 | critical |
| `GatewayKeeperStalled` | 看守读得到，但超过 10 分钟没有看完一眼 | critical |
| `GatewayKeeperLookFailing` | 连着 2 分钟每一眼都没看成：问不到 docker，占不了池，记录读不成样子 | warning |
| `GatewayPoolNotWhole` | 三个常驻容器不是都在跑，连着 2 分钟。网关崩了、看守几秒之后把它起回来的那一种不响 | critical |
| `GatewayPoolNotConfirmed` | 对账的结局连着 5 分钟是 `UNKNOWN` 或 `UNCONFIRMED` | critical |
| `GatewayPoolRestartPending` | 对账的结局连着 5 分钟是 `RESTART_PENDING` | warning |
| `GatewayPoolBroughtBack` | 看守在过去 15 分钟里跑过启动命令：池里有容器死过。不等时长，过了 15 分钟自己停 | warning |
| `GatewayPoolSnapshotPutBack` | 看守在过去 15 分钟里把记录的那一份放回去过：目录里放过一份没人确认过的文件 | warning |

开机时池没有起来（启动命令以非零码结束，池的单元是 `failed`）没有单独的规则。看守照样启动，接着去试：`GatewayPoolBroughtBack` 响；一直起不来，2 分钟之后 `GatewayPoolNotWhole` 响。看守也没有装时是 `GatewayKeeperDown`。

**验证到哪一步。**

- 真的看守给出的数，在池出各种事时读过（`SH-20`）：安稳的时候，一次发布占着池而网关死了的时候，网关起不来的时候，有人绕过发布器写了文件的时候。
- 一个真的 Prometheus 读真的看守，装着这份规则（`SH-21`）。往回放文件、把网关起回来，各自的那一条响了。看守停掉，`GatewayKeeperDown` 真的等满 1 分钟之后响了。`GatewayPoolNotWhole` 看到的是它在等时长，网关回来之后撤掉，没有响。
- 各条的时长，是 `promtool` 对着造的数查的（[`rules.test.yml`](../../tests/integration/compose/rules.test.yml)）。
- 没有对着真的看守让规则响过的：`RESTART_PENDING`、`UNKNOWN`、`UNCONFIRMED`，看守没看成，看守不再看。
- 告警送出去（Alertmanager）没有跑过。测试里的 Prometheus 每秒读一次，平时是 15 秒：两次读之间发生又过去的事它看不到，除了那两条数次数的。

## gateway-authz（叠加文件）

池里的网关每个请求都要向 `gateway-authz` 要判定和凭证（配置里的 `extAuthz`）。`gateway-authz.yml` 是它的部署文件，是一个叠加文件，不改 `compose.yml`：

```bash
docker compose -f compose.yml -f gateway-authz.yml up -d
```

- **一个独立的服务，不在 `netns` 里。** 它在项目的默认网络上，有自己的网络命名空间。网关在配置里按名字找它，`extAuthz.host: gateway-authz:9443`，所以到它这一跳也是 `pin-egress.sh` 钉住的一个 `host: 名字:端口`，和后端一样；`pin-egress.sh` 不用改。到它仍是双向 TLS：网关出示 `tls/gateway.crt`，只认这个服务的证书（配置里 `backendTLS.hostname` 写的名字）。
- **加固照 `place` 和 `confirm`**：镜像按摘要引用，只是个壳；跑的是本机上的 `gateway-authz`，挂进去（静态链接：`CGO_ENABLED=0 go build -trimpath -o gateway-authz ./cmd/gateway-authz`）；`read_only`、`cap_drop: ALL`、`no-new-privileges`、不是 root、`restart: "no"`。读的文件都是只读挂进去的。
- **变量**写在 [`gateway-authz.env.example`](gateway-authz.env.example)，抄进同一个 `.env`；它们没有放进 `.env.example`，因为只有这个叠加文件读它们。缺了哪个，`docker compose` 会说是哪一个：`GATEWAY_AUTHZ`（二进制）、`GATEWAY_AUTHZ_USER`、`GATEWAY_AUTHZ_POLICY`（登记表）、`GATEWAY_AUTHZ_CREDENTIALS_DIR`（放 `developer-tokens.json` 的**目录**，在仓库之外；挂目录是因为文件被改名换掉之后 `gateway-authz` 才重读，单挂文件会一直看到旧的）、`GATEWAY_AUTHZ_TLS_CERT` 和 `_TLS_KEY`（它的服务端证书）、`GATEWAY_AUTHZ_GATEWAY_CA`、`GATEWAY_AUTHZ_GATEWAY_IDENTITY`（网关证书的身份）、`GATEWAY_AUTHZ_PDP_URL`、`_PDP_NAME`、`_PDP_TOKEN_FILE`、`_PDP_CERT`、`_PDP_KEY`、`_PDP_CA`。
- **到 PDP**：地址不是回环，所以 `--gatekeeper-tls-cert`、`-key`、`-ca` 和 `--gatekeeper-name` 四个都要给，缺一个它不启动（2.3 的规则）。
- **还没有的**：撤销（`--revocations`）没有接；看守和开机的两个单元跑的是只有 `compose.yml` 的命令，要带上叠加文件得改那两个单元；`.env` 里除 `docker compose` 外还有看守读，上面几项照它的写法。这个叠加文件和万邦的配置一起，在 [`tests/integration/wanbexpress/pool.py`](../../tests/integration/wanbexpress/README.md) 里跑过，没有装到别的机器上。

## 停

看守在跑时先停它，不然停下的容器会被它起回来。装了两个单元时：`systemctl stop idp-gateway-pool.service`，它先停看守，再跑 `docker compose stop`。

`docker compose stop` 的先后（测试里量到的）：

1. `front` 收到 SIGQUIT：不再接新连接，把在途的请求做完才退出。最多等 60 秒。
2. 然后网关收到 SIGTERM：把在途的请求做完才退出。最多等到快照里的 `connectionTerminationDeadline`；容器的停止时限是 60 秒，前者要比它短。
3. 最后是 `netns`。

测试里停的时候有一个还要 3 秒左右才做完的请求，它做完了，得到 200。

## 要知道的

- **容器死了，把它们起回来的是看守，不是 docker。** 容器没有重启策略（原因见"一个池"）。看守没有在跑时（没有装它的单元，或者它的单元是 `failed`），死了的容器不会自己起来：要跑 `docker compose up -d`，它经过 `place` 和 `confirm`。
- **`netns` 这个容器单独死了，池就断了，只跑 `up -d` 修不好。** 网关和 `front` 还在跑，却连不到了；`up -d` 把 `netns` 重新起来，那两个仍接在原来的命名空间里，`confirm` 读不到网关，`front` 的端口上没有人应答。看守遇到这种情况会先把那两个停下再启动（`SH-16`）；没有看守时要先 `docker compose stop` 再 `docker compose up -d`。
- **发布器死在半路留下的文件，最长要过一分钟才被收回去。** 那份没有人确认过的文件，网关加载得了的话已经在跑它，直到看守下一次对账。没有看守时没有谁会自动去对账：启动这个池时会对一次，平时要有人跑 `gateway-control reconcile` 或 `docker compose up -d`。
- **看守只管把容器起回来和对账，别的它不做。** 启动设置还差一次重启（`RESTART_PENDING`），读不到网关（`UNKNOWN`），怎么试都起不来：它写在自己的输出里，也在它给出的指标里。有没有人知道，看 Prometheus 接没接上、告警送不送得出去（见"告警"）；送出去的那一半不在这个仓库里。
- **网关刚启动的头几毫秒里，换上去的文件它看不到。** 看守的对账正好落在那时（见过的情形是带重启的发布做到一半、发布器被强行杀掉），那一次的结局是 `UNKNOWN`；下一次对账（默认一分钟一次）把同一份再放一遍就好了，不用人管。`UNKNOWN` 的告警要连着 5 分钟才响。
- **看守自己停了，池照常跑，只是没有人守着了。** 它被杀掉由 systemd 重新起来；它的单元是 `failed` 时（`.env` 或命令行写得不对）不会。Prometheus 接上了的话，1 分钟之后 `GatewayKeeperDown` 响；没有接上，就没有谁知道。
- **后端的名字，最好在网关第一次用到它之前就解析得了。** 网关是在第一个请求用到一个后端的名字时才去解析它的。那一次名字不存在，这条路由就答 `503 dns resolution failed`，名字有了之后也要等：网关照着解析器给的否定缓存时间（RFC 2308）办事，在这段时间之内不再去问，到时候自己恢复，不用重启。这段时间由你的解析器定，公网上常见的是一小时（测试里量过：这台机器的上游对不存在的名字给的是 3600 秒；一个 600 秒的替身，名字解析得了之后等了 20 秒、50 秒仍是 503）。等不了就重启网关（`docker compose restart agentgateway`），立刻就好。解析器只是出错、没应答、够不着（53 端口上没有人听，或者那台机器不在），或者回答里没有可以缓存的时间时，不会这样：名字一解析得了，下一个请求就恢复。
- **出口的规则是 `docker compose up -d` 装的，绕过它起来的网关没有规则管着。** `netns` 换过之后，新的网络命名空间里什么规则都没有；`up -d` 每次都先跑 `egress` 再起网关，所以经它起来的没有这个问题。手工 `docker start` 或 `docker restart` 把 `netns` 和网关一起重启，网关就在一个没有规则的命名空间里了，和绕过 `place` 是同一类事。只重启网关不要紧：命名空间没有换，规则还在。
- **映射出来的端口不经过本机防火墙的 INPUT 规则。** 这是 docker 的做法，这里没有测。`CALLERS_LISTEN` 写成 `0.0.0.0:端口` 就是对所有网卡开放；要限制来源，把地址写成具体的网卡地址，或者在 docker 自己的规则链里限制。
- **`place` 和 `confirm` 每次启动各留一份 JSON 在自己容器的日志里**（`docker compose logs place confirm`）。日志写到哪里、留多久、容器的资源上限，都没有定：用的是 docker 的默认值。
- **历史只在这台机器上。** 备份和异地都没有做；机器没了历史就没了。池的记录也在这台机器上，所以没有更糟，但历史没有它就查不到发布过什么。
- **历史没有防篡改，只有文件权限。** 有这个账号的人能改日志；改快照文件读的时候会被 SHA-256 发现，改日志不会。"谁发起的"是发布器进程自己报的（证书上的身份和操作系统账号），备注是操作员自己写的，都没有人核实。
- **不带 `--history-dir` 就没有历史。** 手工跑 `publish` 时漏给，这一次发布在历史里查不到；`releases` 会指出历史和池的记录对不上（`mismatch`），没有别的拦截。看守的单元里是写死的，不会漏。
- **历史目录必须先建好。** 带历史的 `publish`、`restart`、`rollback` 在它不在、写不进去、日志坏了时以退出码 1 结束，池没有被动（先写后做）；`reconcile` 和看守不会因此停，只是不补历史。命令不检查历史目录的属主和权限（0700、归 `CONTROL_USER` 是这里要求的，没有谁核对）。
- **历史不自动清理。** 每次发布存一份快照（同样的内容只存一份）、写几行日志；快照有多大、一年会有多少，没有量过。要清理，手工做，并且不要删最近一条 `ACTIVE` 的快照和它前面一条的快照。
- **一台机器上不止一个池**没有做：`compose.yml` 里的项目名是固定的，发布器做离线加载用的临时容器、端口和目录也要每个池各一套；两个单元也是照一个池写的。

## 没有验证的

- **真的重启一台机器。** 测试里的"断电"是把三个常驻容器同时强行杀掉，再跑 `docker compose up -d`，或者让看守去跑。docker 守护进程重启之后各容器是什么状态、两个单元在开机过程中跑得是不是时候，都没有看过。
- **两个 systemd 单元装在一台机器上的样子。** 没有装过。做过的是三样：用 `systemd-analyze verify` 查写法（systemd 255）；两个单元之间的关系，在用户级的 systemd 里用替身命令跑（`units.py`，那里去掉了 `User=`、`Group=` 和对 `docker.service` 的依赖）；两个单元里写的命令原样跑，不经 systemd（`SH-19`）。没有看过的：系统级的 systemd，`User=` 换了账号之后用不用得了 docker，与 `docker.service` 的先后，开机和关机。
- **docker 守护进程重启或者崩溃时**，看守和池的单元各会怎样。看守问不到 docker 时只把错误写出来、不动手，这一条只有单元测试。
- **看守正跑着启动命令时被强行杀掉。** 被叫停（SIGTERM）时它把这条命令跑完才退出（`SH-18`）。被强行杀掉时那条命令会不会留下一个起了一半的池，没有看过；照它的做法，重新起来之后它会看到没在跑的容器，再跑一次启动命令。
- **看守在跑时有人手工动容器**：`docker restart` 网关，或者手工跑的 `docker compose up -d` 与看守跑的那一条同时进行。
- **`netns` 被重新启动过、而网关和 `front` 一直在跑**时看守的处理（它也当成接错了命名空间，先停再启动）只有单元测试；跑过的是 `netns` 死着的那一种。
- **出口的规则对着真实的外部后端。** 池里试过的后端是同一个 compose 网络里的名字，由 Docker 的解析器自己答；要去问上游解析器的名字，只在 `tests/integration/egressnet` 里对着替身解析器试过。放行上游解析器靠的是 Docker 写在 `resolv.conf` 里的一行注释，放行 Docker 的解析器靠的是它改写查询端口的做法：换了 docker 版本这两样变了会怎样没有试，测的是 29.8.1。
- **`egress` 这一步失败。** 它失败网关就不启动，靠的是与 `place` 相同的启动条件；试过的是 `place` 失败（`SH-13`），和 `egress` 读不了配置（配置文件是 0600，`SH-22`）：`docker compose up -d` 以非零码结束，`egress` 在标准错误上说 `cannot read`，网关、`confirm`、`front`、`egress-watch` 都没有启动；改回 0644 再跑启动命令就好了。`egress` 的别的失败方式（比如 iptables 装不上）没有试。
- **`egress-watch` 死了而 `netns` 还在。** 照做法，装好的规则还在，新的后端不再被放行；没有试，也没有告警看着它。
- **发布历史的几处没有试过。** 磁盘满、文件系统只读（试过的是目录和日志文件不可写，`SH-25`）；历史目录的属主不是 `CONTROL_USER` 时怎么办；看守的单元带着历史在系统级 systemd 里跑（`SH-19` 只是原样跑那条命令，历史目录是空的）；`rollback --with-restart`；`ACTIVE_NOT_RECORDED` 和退出码 8 本身，以及收尾那一笔恰好在换文件之后写不进去的那一瞬间（真的池上卡不准，只有单元测试）。
- 换镜像（升级 agentgateway）在这个部署上怎么做。
- `GATEWAY_USER` 和 `CONTROL_USER` 是两个不同的账号时，文件的属主和权限怎么定。
- 启动时本机上还没有镜像：`up -d` 会先去拉。镜像仓库那时够不着会怎样没有试过，测试时镜像已经在本机上。
- 别的环境。测的是 WSL2 里的 Ubuntu 24.04 上的 docker 29.8.1，不是一台普通的 Linux 主机；别的 docker 版本、Docker Desktop、arm64 都没有测。
- 其余没有覆盖的见 [`tests/integration/compose/README.md`](../../tests/integration/compose/README.md) 的"没有覆盖的"。
