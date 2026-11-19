#!/usr/bin/env python3
"""在本机用 docker compose 验证单机上的一个网关池。跑的就是正式的部署文件（deploy/compose/compose.yml），
只另外套上一个会回话的后端（echo.yml）。网关跑在容器里，配置目录挂载进去；发布就是把目录里的配置文件整份
换掉（写临时文件，再改名盖上去），网关不重启；之后经回读口确认它在跑的是哪一份。

    .venv/bin/python tests/integration/compose/run.py        # 十分钟左右；自己起，跑完自己拆（需要 docker 和 go）

真的部分：docker compose 和部署文件本身、锁定的上游 agentgateway 镜像（按摘要引用）、网关前面的那层 nginx
（与黑盒套件同一个镜像，配置只差端口）、网关自己的回读口（双向 TLS），以及发布器（cmd/gateway-control，
现场用 Go 构建：SH-09 起由本脚本在本机上跑它；部署文件的 place 和 confirm 两步跑的也是这同一个文件）。
配置是一份只有几条路由的小文件，路由的后端是同一个 compose 网络里一个会回话的小服务；没有 JWT、ExtAuthZ
和凭证，那些由黑盒套件覆盖。

一个池在单机上是什么（deploy/compose/compose.yml 里的七个服务，按文件里的先后）：
    netns         什么都不做，只占着网络命名空间和本机上的两个端口。front 和网关都接在它里面，相当于
                  Kubernetes 上的同一个 Pod；两个可以各自重启。
    place         跑完就退出。网关启动之前，把记录里确认过的那一份配置放到位（gateway-control place）。
    egress        跑完就退出。网关启动之前，在它所在的网络命名空间里装上规则（pin-egress.sh once）：
                  新的外出连接只许去配置里写着的地址。
    agentgateway  收业务请求的监听、管理和指标端口只绑回环；另开一个回读口（本机回环 27619），要发布器的
                  客户端证书，只转发 /config_dump 和 /api/runtime 两个 GET。配置目录以只读方式挂进容器。
    confirm       跑完就退出。网关起来之后对一次账（gateway-control reconcile）；对上了，front 才启动。
    front         nginx。对外收业务请求的只有它（本机回环 27620）。
    egress-watch  常驻。每两秒跑一遍同一个脚本：配置里后来多出来的后端靠它放行。看守不数它。
另有 echo（echo.yml）：路由的后端，不属于部署文件。

SH-01 到 SH-08 由本脚本扮演发布器：往挂载的目录里写文件，从本机经回读口读网关在跑什么。这几条看的是
网关和这种发布方式本身。SH-09 到 SH-11 换成真的发布器的三条命令（publish、reconcile、restart），本脚本
在旁边看，并且替它制造麻烦：把它强行杀掉，绕过它往目录里写文件、删文件，带着坏文件重启网关。
SH-12 到 SH-14 看部署文件：断电之后再启动的先后，启动时对不上会怎样，停，头一次安装。断电是把三个常驻
容器同时强行杀掉来模拟的；真的重启一台机器没有做过。SH-15 是网关自己的一个性质，开机的先后与它有关。
SH-16 到 SH-18 看看守（gateway-control keep）：真的看守在本机上跑着，本脚本去杀容器、杀发布器、绕过发布器写文件、
占着配置目录的锁，看它怎么收拾，什么时候不动手。看守在这里不经 systemd：由本脚本直接起，docker compose 的项目和
文件由参数给它。它在两个 systemd 单元里的那一面（跟着池的单元启停，死了被重新起来）由同目录的 units.py 用替身看。
SH-19 把两个单元文件里写的命令原样跑一遍，仍然不经 systemd：在一个放着 compose.yml 和 .env 的目录里跑，docker compose
的项目和文件都不另给，由它自己在那个目录里找。这一条里的池用的是部署文件自己的项目名，不带这套用例的前缀；这台机器上
已经有叫这个名字的项目时，这一条不动它，也就不通过。
SH-22 看出口的规则在这个池里是不是真的装上了（它排在 SH-15 后面跑，那时池是好好的）：从网关所在的网络命名空间里
往外连，配置里写着的连得上，别的被拒绝；断电之后再启动，新的命名空间里规则先于网关装好。名字改指之后会怎样不在
这里，在 tests/integration/egressnet。
SH-20 和 SH-21 看告警：看守在一个地址上给出指标（--metrics-listen），SH-20 由本脚本直接去读，看池出了各种事时这些数
是不是跟着变；SH-21 起一个真的 Prometheus（按摘要引用的镜像，主机网络，只听回环）来读同一个看守，装着部署目录里的
那份规则，看各条规则对着真的看守响不响，并在同一个镜像里跑 promtool（规则的写法，和 rules.test.yml 里造的数）。
告警送到谁那里（Alertmanager）不在这里。
SH-23 到 SH-30 看发布历史（docs/adr/ADR-0013.md）：真的发布器和真的看守带着 --history-dir，历史目录现建在本次运行的池的目录下
（compose.yml 不改，哪个容器都不挂它）。SH-23 排在 SH-19 前面跑：要在历史目录出现之前查"不给 --history-dir 时什么都不写"；
别的排在告警的用例后面。它们看带历史的发布、先写后做、发布器被杀之后看守补结局、收尾那一行没写上、回滚、漏给参数，以及开机
的路上不碰历史（历史目录不在、日志写坏，断电再启动照常）。

占用本机回环上的 27618 到 27622，与黑盒套件、Gatekeeper 联调和 Kubernetes 套件的端口重叠，不能同时跑。
"""
from __future__ import annotations
import base64, calendar, collections, fcntl, hashlib, http.client, json, os, re, secrets, shutil, signal, socket, stat, subprocess, sys, threading, time, traceback
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
DEPLOY = ROOT / 'deploy/compose'   # 正式的部署文件：这套用例跑的池就是它描述的那一个
BLACKBOX = ROOT / 'tests/acceptance/blackbox'
KUBERNETES = ROOT / 'tests/integration/kubernetes'
sys.path[:0] = [str(BLACKBOX), str(KUBERNETES)]
import pin  # noqa: E402
import pki  # noqa: E402
import probe  # noqa: E402  Kubernetes 套件的那个：这里用它发"两个 Host 头"的函数，它的 echo 也是这里的后端

RUN = HERE / '.run'
POOL = RUN / 'pool'   # 池的目录。挂进网关容器的是它下面的两个：config 由发布器写，tls 是网关自己的证书
PKI = RUN / 'pki'     # 本次运行的全套证书。发布器的证书只在这里，不进网关容器
POOL_ENV = RUN / 'pool.env'   # 本次运行的 .env：部署文件要的各个变量
# 真的发布器（SH-09 到 SH-11）用的东西：现场构建的二进制；它做离线加载用的另一套证书（另一个 CA）、挂进临时容器的
# 证书目录、放候选配置的目录；要发布的快照文件。
CONTROL = RUN / 'control'
CONTROL_BINARY = CONTROL / 'bin' / 'gateway-control'
ONLY_IN_STAGING = 'only-in-staging.crt'   # 只有离线加载那边才有的一个文件
RECORD = '.config.yaml.confirmed'         # 发布器留在配置目录里的记录
# SH-19 的安装目录：compose.yml、front.nginx.conf 和 .env 放在一起，像一台真的机器上那样。两个单元里的命令在这里面跑。
HOSTED = RUN / 'deployed'
HOSTED_MARK = RUN / 'deployed.started'   # SH-19 起过那个池的记号：拆的时候凭它删那个项目的网络
MONITOR = RUN / 'prometheus'   # SH-21 给 Prometheus 的配置
# 发布历史（SH-23 到 SH-30，docs/adr/ADR-0013.md）：池的目录下的第三个子目录，与 config、tls 并列。网关、front 和 egress 的
# 容器都不挂它（compose.yml 不改）。池的名字这里用本套用例的项目名 PROJECT；SH-19 里看守的单元写的是部署文件的项目名。
HISTORY = POOL / 'history'
HISTORY_LOG = HISTORY / 'releases.log'
HISTORY_SNAPSHOTS = HISTORY / 'snapshots'
STALE = (POOL, PKI, CONTROL, HOSTED, MONITOR, RUN / 'staging', RUN / 'single', RUN / 'expansion')   # 每次运行前后都清掉
LOCK = pin.lock()
# 两个镜像都不由本脚本交给 compose：部署文件自己按摘要写着。这里的两个值是拿来核对的（SH-01）。
GATEWAY_IMAGE = pin.image_reference(LOCK)   # 上游镜像，按多平台索引的摘要引用
# 与黑盒套件同一个前置 nginx（tests/contracts 里有一条测试检查几套用例和部署文件一致）。
FRONT_IMAGE = ('public.ecr.aws/nginx/nginx-unprivileged:stable-alpine'
               '@sha256:c3fc8fa482be50ef709c6438eb1bc98d50dbfe5a9b48be90711b8814f4dfd701')
# 回话的后端用它：只是一个带 Python 的镜像。
TOOLS_IMAGE = ('public.ecr.aws/docker/library/python:3.13-alpine'
               '@sha256:1e1f6334529d1fb26a2ef619d7cffb30a7c7d7cc1cc7338ebee283a58d1aeaca')

PROJECT = 'idp-gateway-compose'
# 部署文件自己写的项目名。SH-19 之外的用例都另给项目名（PROJECT）；SH-19 不给，用的就是这个。
DEPLOYED_PROJECT = yaml.safe_load((DEPLOY / 'compose.yml').read_text(encoding='utf-8'))['name']
SCRATCH = f'{PROJECT}-scratch'   # 另起的那个网关容器：发布前的离线加载用它，"只挂单个文件"的对照也用它
HOST = {'front': 27620, 'readback': 27619, 'scratch': 27618, 'metrics': 27621, 'prometheus': 27622}   # 本机回环上的端口
# 告警（SH-20、SH-21）。看守在 METRICS 上给出指标；规则是部署目录里的那一份；JOB 是规则里写的抓取任务名。
METRICS = f"127.0.0.1:{HOST['metrics']}"
RULES = DEPLOY / 'idp-gateway-pool.rules.yml'
RULE_TESTS = HERE / 'rules.test.yml'
JOB = 'idp-gateway-keeper'
# 这台机器上平台自己的监控跑的就是这个镜像（3.14.0）；promtool 也在里面。
PROMETHEUS_IMAGE = 'prom/prometheus@sha256:5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0'
PROMETHEUS = f'{PROJECT}-prometheus'
# netns 占着的那个网络命名空间里的端口：front 和网关都接在里面。
PORT = {'front': 8080, 'callers': 8081, 'readback': 8443, 'admin': 15000, 'stats': 15020, 'readiness': 15021}
ECHO_PORT = 8000
GATEWAY_FILES = ('gateway-readback.crt', 'gateway-readback.key', 'gateway.crt', 'gateway.key', 'ca.crt')
RUN_AS = f'{os.getuid()}:{os.getgid()}'
LOADED = {'synchronized': True, 'lastError': None}
SESSION_KEY = secrets.token_hex(32)
SERVICES = ('netns', 'place', 'egress', 'agentgateway', 'confirm', 'front', 'egress-watch')   # 部署文件里的七个，按文件里的先后
LONG_RUNNING = ('netns', 'agentgateway', 'front')                   # 其中看守数的那三个常驻的
EGRESS = ('egress', 'egress-watch')                                 # 装出口规则的两个：一步跑完就退出，一个常驻
CONFIRM_SECONDS = 10                                                # confirm 这一步等网关的时限
probe.PORTS = {'front': HOST['front']}   # probe.two_hosts 往哪个端口发


def pool_settings() -> dict:
    """部署文件要的各个变量在这次运行里的值：运维会写进 .env 的那些。"""
    return {
        'CALLERS_LISTEN': f"127.0.0.1:{HOST['front']}", 'READBACK_PORT': str(HOST['readback']), 'READBACK_NAME': pki.READBACK_NAME,
        'POOL_DIR': str(POOL), 'GATEWAY_USER': RUN_AS, 'CONTROL_USER': RUN_AS, 'GATEWAY_ENV_FILE': str(POOL / 'gateway.env'),
        'GATEWAY_CONTROL': str(CONTROL_BINARY),
        'PUBLISHER_CERT': str(PKI / 'publisher.crt'), 'PUBLISHER_KEY': str(PKI / 'publisher.key'), 'READBACK_CA': str(PKI / 'ca.crt'),
        # 只有看守的单元才读的一项：它在哪个地址上给出指标。
        'KEEPER_METRICS_LISTEN': METRICS,
        # 可以不设的一项，默认 60 秒。这里设短：有几步是故意让 confirm 读不到网关的，每一步都要等满它。
        'CONFIRM_TIMEOUT': f'{CONFIRM_SECONDS}s',
    }


def example_variables() -> dict:
    """deploy/compose/.env.example 里的变量。required 是要填的（"名字=" 开头的行）；
    optional 是可以不设的（写成注释 "# 名字=默认值" 的行）。"""
    found = {'required': [], 'optional': []}
    for line in (DEPLOY / '.env.example').read_text(encoding='utf-8').splitlines():
        named = re.match(r'(# )?([A-Z][A-Z0-9_]*)=', line)
        if named:
            found['optional' if named.group(1) else 'required'].append(named.group(2))
    return found


def compose_environment() -> dict:
    """docker compose 进程的环境。部署文件的变量只从 pool.env 来：跑脚本的这个 shell 里碰巧有同名的变量，
    或者设了 COMPOSE_ 开头的变量，都不带进去。另加 echo.yml 要的两个。"""
    example = example_variables()
    hidden = set(example['required']) | set(example['optional'])
    inherited = {k: v for k, v in os.environ.items() if k not in hidden and not k.startswith('COMPOSE_')}
    return {**inherited, 'TOOLS_IMAGE': TOOLS_IMAGE, 'PROBE': str(KUBERNETES / 'probe.py')}


def die(message: str):
    print('run.py:', message, file=sys.stderr)
    raise SystemExit(2)


def docker(*argv: str, timeout: float = 300) -> subprocess.CompletedProcess:
    return subprocess.run(['docker', *argv], capture_output=True, text=True, timeout=timeout)


def compose(*argv: str, timeout: float = 300) -> subprocess.CompletedProcess:
    """对着这套用例的池跑 docker compose：部署文件，套上 echo.yml，变量取自本次运行的 pool.env。"""
    return subprocess.run(['docker', 'compose', '-p', PROJECT, '--env-file', str(POOL_ENV),
                           '-f', str(DEPLOY / 'compose.yml'), '-f', str(HERE / 'echo.yml'), *argv],
                          capture_output=True, text=True, timeout=timeout, env=compose_environment())


# ---- 一份快照：发布器要下发的那个文件 ---------------------------------------------------------------
def gateway_config(routes: list[str], unloadable: str | None = None, deadline: int = 45,
                   root: str = 'tls/ca.crt', names: dict | None = None, stats: int | None = None) -> str:
    """网关的配置文件。unloadable 指的那条路由带一个不存在的字段：整份文件网关加载不了。
    deadline 是 config 段里的一项设置（收到终止信号后，在途的请求最多再做多少秒）。
    root 是那条形状与真实的池相同的路由验证 PDP 用的 CA 文件；names 给个别路由另起名字（默认是 route-<路由>）。
    stats 另指指标端口（也在 config 段里，也只绑回环）。"""
    def route(name: str) -> dict:
        r = {'name': (names or {}).get(name, f'route-{name}'), 'gateways': ['callers'], 'hostnames': [f'{name}.test'],
             'policies': {'timeout': {'requestTimeout': '30s'}},
             'backends': [{'host': f'echo:{ECHO_PORT}'}]}
        if name == unloadable:
            r['notAFieldOfARoute'] = True
        return r

    # 一条形状与真实的池相同的路由：先经双向 TLS 去问 PDP。这里没有 PDP，这条路由也不会被请求。
    # 有了它，/config_dump 里才有证书正文，期望摘要"不计证书正文"的算法才有东西可验。
    pdp_shaped = {'name': 'route-pdp-shaped', 'gateways': ['callers'], 'hostnames': ['pdp-shaped.test'],
                  'policies': {'extAuthz': {
                      'host': f'echo:{ECHO_PORT}', 'failureMode': 'deny',
                      'policies': {'backendTLS': {'cert': 'tls/gateway.crt', 'key': 'tls/gateway.key', 'root': root,
                                                  'hostname': pki.GATEKEEPER_NAME}},
                      'protocol': {'http': {'path': '"/v1/extauthz/check"'}}}},
                  'backends': [{'host': f'echo:{ECHO_PORT}'}]}

    document = {
        'config': {
            'adminAddr': f"127.0.0.1:{PORT['admin']}", 'statsAddr': f"127.0.0.1:{stats or PORT['stats']}",
            'readinessAddr': f"127.0.0.1:{PORT['readiness']}",
            'storage': {'mode': 'readOnly'},
            # 只设"在途的请求最多再做多久"。Kubernetes 上还设了"收到终止信号后再照常接多久"，那是在等
            # 端点被摘除；单机上只有这一个实例，多接几秒只是把重启推后几秒。
            'connectionTerminationDeadline': f'{deadline}s'},
        'frontendPolicies': {'networkAuthorization': {'rules': [
            {'allow': f"destination.port == {PORT['callers']}"},
            {'allow': f"destination.port == {PORT['readback']} && source.spiffeId == \"{pki.ID['publisher']}\""}]}},
        'gateways': {
            'callers': {'port': PORT['callers'], 'bindAddress': '127.0.0.1', 'protocol': 'HTTP'},
            'read-back': {'port': PORT['readback'],
                          'tls': {'cert': 'tls/gateway-readback.crt', 'key': 'tls/gateway-readback.key', 'root': 'tls/ca.crt'}}},
        'routes': [route(name) for name in routes] + [pdp_shaped, {
            'name': 'read-back', 'gateways': ['read-back'],
            'matches': [{'path': {'exact': '/config_dump'}, 'method': 'GET'}, {'path': {'exact': '/api/runtime'}, 'method': 'GET'}],
            'policies': {'timeout': {'requestTimeout': '2s'}},
            'backends': [{'host': f"127.0.0.1:{PORT['admin']}"}]}],
    }
    return yaml.safe_dump(document, sort_keys=False)


class Snapshot:
    """一份配置文件，连同它的名字。名字带内容的摘要：内容不同，名字就不同。"""

    def __init__(self, routes: list[str], unloadable: str | None = None, deadline: int = 45, **other):
        self.routes, self.text = routes, gateway_config(routes, unloadable, deadline, **other)
        self.sha256 = hashlib.sha256(self.text.encode()).hexdigest()
        self.id = self.sha256[:12]
        self.expected = None   # 离线加载之后才有：期望的运行配置摘要


# ---- 运行配置的摘要（算法与 Kubernetes 套件相同）----------------------------------------------------
def without_certificates(node):
    """证书正文换成占位：证书不在快照里，换证书不经过发布。"""
    if isinstance(node, dict):
        return {k: without_certificates(v) for k, v in node.items()}
    if isinstance(node, list):
        return [without_certificates(v) for v in node]
    if isinstance(node, str) and node.lstrip().startswith('-----BEGIN CERTIFICATE-----'):
        return '<certificate>'
    return node


def published_digest(dump: dict, certificates: bool = False) -> str:
    """/config_dump 里由发布的文件决定的那部分的摘要，与键的顺序无关。去掉 config 段（启动时定下的设置，
    里面有随运行环境变的值）；certificates 为假时证书正文不计入。"""
    document = {k: v for k, v in dump.items() if k != 'config'}
    if not certificates:
        document = without_certificates(document)
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


# ---- 发布器能做的两件事：往目录里写文件，经回读口读 --------------------------------------------------
def publish(snapshot: Snapshot, directory: Path = POOL / 'config') -> float:
    """发布器在单机上做的那一步：在挂载的目录里写一个临时文件，落盘，再改名盖掉 config.yaml。
    改名是原子的：网关读到的要么是旧的整份，要么是新的整份。返回做完的时刻。"""
    scratch = directory / f'.config.yaml.{snapshot.id}'
    with open(scratch, 'wb') as f:
        f.write(snapshot.text.encode())
        f.flush()
        os.fsync(f.fileno())
    os.replace(scratch, directory / 'config.yaml')
    entry = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(entry)
    finally:
        os.close(entry)
    return time.monotonic()


def read_back(port: int, path: str, tls: Path = PKI, cert: str | None = 'publisher', method: str = 'GET') -> dict:
    """经回读口发一个请求，出示指定的证书（None：不出示）。"""
    try:
        conn = pki.GatekeeperConnection(port, pki.client_context(tls, cert), 3, pki.READBACK_NAME)
        conn.request(method, path, body=None if method == 'GET' else b'', headers={'Host': pki.READBACK_NAME})
        response = conn.getresponse()
        body = response.read()
        conn.close()
    except (OSError, ValueError, http.client.HTTPException) as e:
        return {'status': None, 'error': f'{type(e).__name__}: {str(e)[:80]}'}
    try:
        return {'status': response.status, 'json': json.loads(body)}
    except ValueError:
        return {'status': response.status, 'text': body[:120].decode('latin1')}


def observe(port: int = HOST['readback'], tls: Path = PKI) -> dict:
    """发布器经回读口看到的：运行配置的摘要、上一次加载的结果、存储模式、构建、config 段。读不到的项是 None。"""
    dump, runtime = read_back(port, '/config_dump', tls), read_back(port, '/api/runtime', tls)
    document = dump.get('json') if dump['status'] == 200 and isinstance(dump.get('json'), dict) else None
    state = runtime.get('json') if runtime['status'] == 200 and isinstance(runtime.get('json'), dict) else {}
    return {'digest': published_digest(document) if document else None,
            'digest_with_certificates': published_digest(document, certificates=True) if document else None,
            'config': (document or {}).get('config') or {},
            'reload': state.get('configReload'), 'storage': (state.get('ui') or {}).get('configStoreMode'),
            'build': state.get('build') or {}}


# ---- 另起一个网关容器 -------------------------------------------------------------------------------
def scratch_gateway(config_mount: str, tls: Path, session_key: str | None = None) -> subprocess.CompletedProcess:
    """用锁定的镜像另起一个网关容器，回读口映射到本机回环的 27618。config_mount 是配置怎么挂进去。"""
    docker('rm', '-f', SCRATCH)
    return docker('run', '-d', '--name', SCRATCH, '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                  '--user', RUN_AS, '-p', f"127.0.0.1:{HOST['scratch']}:{PORT['readback']}",
                  '-v', config_mount, '-v', f'{tls}:/work/tls:ro', '-w', '/work',
                  '-e', f'SESSION_KEY={session_key or secrets.token_hex(32)}', GATEWAY_IMAGE, '-f', 'config/config.yaml')


def stage(snapshot: Snapshot) -> dict:
    """发布器在发布前做的那一步：用锁定的镜像另起一个容器加载这份快照，经回读口读它报告的运行配置。
    证书是另外现做的一套（另一个 CA），与池里的无关。加载不了的文件在这里就被拒绝。"""
    work = RUN / 'staging'
    shutil.rmtree(work, ignore_errors=True)
    (work / 'config').mkdir(parents=True)
    (work / 'config' / 'config.yaml').write_text(snapshot.text, encoding='utf-8')
    pki.issue(work / 'tls')
    started = scratch_gateway(f"{work / 'config'}:/work/config:ro", work / 'tls')
    if started.returncode != 0:
        die(f'离线加载用的容器起不来：{started.stderr.strip()[-300:]}')
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            state = docker('inspect', '-f', '{{.State.Running}} {{.State.ExitCode}}', SCRATCH).stdout.split()
            if state and state[0] == 'false':
                logs = docker('logs', SCRATCH)
                return {'loaded': False, 'exit_code': int(state[1]), 'said': (logs.stdout + logs.stderr).strip().split('\n')[-1][:200]}
            seen = observe(HOST['scratch'], work / 'tls')
            if seen['digest']:
                return {'loaded': True, **seen}
            time.sleep(0.2)
        return {'loaded': False, 'exit_code': None, 'said': '20 秒内回读口没有给出运行配置'}
    finally:
        docker('rm', '-f', SCRATCH)
        shutil.rmtree(work, ignore_errors=True)


# ---- 真的发布器 -------------------------------------------------------------------------------------
def build_control():
    """现场构建 cmd/gateway-control，并布置它做离线加载用的东西：另一套证书（另一个 CA）；挂进临时容器的
    证书目录，里面比池的那个多一个文件。"""
    go = shutil.which('go') or '/usr/local/go/bin/go'
    CONTROL_BINARY.parent.mkdir(parents=True)
    try:
        # 静态链接：同一个文件还要挂进部署文件的 place 和 confirm 两个容器里跑，那个镜像里没有 glibc。
        built = subprocess.run([go, 'build', '-trimpath', '-o', str(CONTROL_BINARY), './cmd/gateway-control'],
                               cwd=ROOT, capture_output=True, text=True, timeout=600, env={**os.environ, 'CGO_ENABLED': '0'})
    except OSError as e:
        die(f'构建 gateway-control 需要 Go：{e}')
    if built.returncode != 0:
        die(f'gateway-control 构建不出来：{built.stderr.strip()[-600:]}')
    pki.issue(CONTROL / 'pki')
    (CONTROL / 'tls').mkdir()
    for name in GATEWAY_FILES:
        shutil.copy2(CONTROL / 'pki' / name, CONTROL / 'tls' / name)
    shutil.copy2(CONTROL / 'pki' / 'ca.crt', CONTROL / 'tls' / ONLY_IN_STAGING)
    (CONTROL / 'work').mkdir()
    (CONTROL / 'snapshots').mkdir()


def pool_flags() -> list[str]:
    """三条命令都要的：池的配置目录，回读口和读它用的证书。"""
    return ['--config-dir', str(POOL / 'config'), '--read-back', f"127.0.0.1:{HOST['readback']}", '--read-back-name', pki.READBACK_NAME,
            '--tls-cert', str(PKI / 'publisher.crt'), '--tls-key', str(PKI / 'publisher.key'), '--tls-ca', str(PKI / 'ca.crt')]


def staging_flags() -> list[str]:
    """publish 和 restart 另外要的：离线加载用的镜像、临时容器和读它用的证书。"""
    return ['--image', GATEWAY_IMAGE, '--staging-name', SCRATCH, '--staging-publish', f"127.0.0.1:{HOST['scratch']}",
            '--staging-container-port', str(PORT['readback']),
            '--staging-tls-dir', str(CONTROL / 'tls'), '--staging-work-dir', str(CONTROL / 'work'),
            '--staging-tls-cert', str(CONTROL / 'pki' / 'publisher.crt'), '--staging-tls-key', str(CONTROL / 'pki' / 'publisher.key'),
            '--staging-tls-ca', str(CONTROL / 'pki' / 'ca.crt')]


def snapshot_file(snapshot: Snapshot) -> str:
    path = CONTROL / 'snapshots' / f'{snapshot.id}.yaml'
    path.write_text(snapshot.text, encoding='utf-8')
    return str(path)


def control_command(snapshot: Snapshot, *extra: str) -> list[str]:
    return [str(CONTROL_BINARY), 'publish', '--snapshot', snapshot_file(snapshot), *pool_flags(), *staging_flags(), *extra]


def restart_command(snapshot: Snapshot | None, target: str, *extra: str) -> list[str]:
    """gateway-control restart 的命令行。target 是要重启的容器；snapshot 为 None 时不给快照，
    用的是这个池上最后一次得到确认的那一份。"""
    chosen = ['--snapshot', snapshot_file(snapshot)] if snapshot else []
    return [str(CONTROL_BINARY), 'restart', '--container', target, *chosen, *pool_flags(), *staging_flags(), *extra]


def history_flags(*extra: str) -> list[str]:
    """带着历史的命令要的：历史目录和池的名字（ADR-0013）。extra 另加，如 --note。"""
    return ['--history-dir', str(HISTORY), '--pool', PROJECT, *extra]


def reconcile_command(*extra: str) -> list[str]:
    return [str(CONTROL_BINARY), 'reconcile', *pool_flags(), *extra]


def control_result(code: int, stdout: str, stderr: str, started: float) -> dict:
    try:
        report = json.loads(stdout) if stdout.strip() else {}
    except ValueError:
        report = {'unparsed': stdout[:300]}
    return {'exit': code, 'report': report, 'stderr': stderr.strip()[-300:], 'seconds': round(time.monotonic() - started, 2)}


def run_control(command: list[str]) -> dict:
    """跑一次真的发布器。-> 它的退出码、写到标准输出的那份 JSON、标准错误的末尾、用了多少秒。"""
    started = time.monotonic()
    done = subprocess.run(command, capture_output=True, text=True, timeout=180)
    return control_result(done.returncode, done.stdout, done.stderr, started)


def control(snapshot: Snapshot, *extra: str) -> dict:
    """让真的发布器发布这份快照。extra 是另加的参数（SH-24 起带 --history-dir 等）。"""
    return run_control(control_command(snapshot, *extra))


def control_reconcile(*extra: str) -> dict:
    """让真的发布器对一次账。"""
    return run_control(reconcile_command(*extra))


def control_restart(snapshot: Snapshot | None, target: str, *extra: str) -> dict:
    """让真的发布器做一次带重启的发布。"""
    return run_control(restart_command(snapshot, target, *extra))


def control_together(first: Snapshot, second: Snapshot) -> tuple[dict, dict]:
    """两次发布几乎同时开始：second 比 first 晚半秒。"""
    started = time.monotonic()
    running = subprocess.Popen(control_command(first), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(0.5)
    late = control(second)
    stdout, stderr = running.communicate(timeout=180)
    return control_result(running.returncode, stdout, stderr, started), late


def control_interrupted(snapshot: Snapshot) -> dict:
    """让真的发布器发布这份快照；它刚把文件换上去，就给它发 SIGTERM。signalled 为假表示没等到它换文件。"""
    started = time.monotonic()
    running = subprocess.Popen(control_command(snapshot), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    replaced = wait_for(lambda: on_disk() == snapshot.text or running.poll() is not None, 60, every=0.01)
    signalled = replaced is not None and running.poll() is None
    if signalled:
        running.send_signal(signal.SIGTERM)
    else:
        running.kill()
    stdout, stderr = running.communicate(timeout=180)
    return {**control_result(running.returncode, stdout, stderr, started), 'signalled': signalled}


def control_killed(snapshot: Snapshot, during: str = 'swap', extra: tuple = ()) -> dict:
    """让真的发布器发布这份快照，中途把它强行杀掉（SIGKILL）：它来不及收拾。
    during 是 'swap'：它刚把文件换上去；是 'staging'：它做离线加载用的临时容器刚出现。
    killed 为假表示没等到那一刻。"""
    if during == 'swap':
        def reached() -> bool:
            return on_disk() == snapshot.text
    else:
        def reached() -> bool:
            return bool(scratch_containers())
    running = subprocess.Popen(control_command(snapshot, *extra), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    seen = wait_for(lambda: reached() or running.poll() is not None, 60, every=0.01)
    killed = seen is not None and running.poll() is None
    running.kill()
    running.wait(30)
    return {'killed': killed, 'exit': running.returncode}


def restart_killed(snapshot: Snapshot, target: str, extra: tuple = ()) -> dict:
    """让真的发布器做一次带重启的发布；docker 刚把网关容器重新起来，并且它在回读口上答得上话了（发布器还在等它
    报告），就把发布器强行杀掉。killed 为假表示没等到那一刻；answered 是看到网关重新起来之后过了多少秒它在回读口上
    答话，没等到重启是 None。等到答话才杀，是因为网关刚启动的头几毫秒里，换上去的文件它看不到：看守正好在那时对账的话，
    要到再下一次对账才收拾好（详见 README）。"""
    def started() -> str:
        return docker('inspect', '-f', '{{.State.StartedAt}}', target).stdout.strip()
    before = started()
    running = subprocess.Popen(restart_command(snapshot, target, *extra), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    seen = wait_for(lambda: started() not in ('', before) or running.poll() is not None, 90, every=0.01)
    answered = None
    if seen is not None:
        answered = wait_for(lambda: read_back(HOST['readback'], '/config_dump')['status'] == 200 or running.poll() is not None,
                            10, every=0.01)
    killed = seen is not None and answered is not None and running.poll() is None
    running.kill()
    running.wait(30)
    return {'killed': killed, 'exit': running.returncode, 'answered': answered}


def restart_interrupted(snapshot: Snapshot, target: str, after: float, on_swap=None) -> dict:
    """让真的发布器做一次带重启的发布；它把文件换上去 after 秒之后，像在终端里按 Ctrl-C 那样，给它所在的
    整个前台进程组发 SIGINT。on_swap 在文件刚换上去时被调用。signalled 为假表示没等到它换文件。
    group 是发信号那一刻那个进程组里的进程；elsewhere 是发布器当时不在那个进程组里的子进程。"""
    started = time.monotonic()
    running = subprocess.Popen(restart_command(snapshot, target), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                               start_new_session=True)
    replaced = wait_for(lambda: on_disk() == snapshot.text or running.poll() is not None, 60, every=0.01)
    signalled = replaced is not None and running.poll() is None
    group, elsewhere = [], []
    if signalled:
        if on_swap:
            on_swap()
        time.sleep(after)
        for line in subprocess.run(['ps', '-eo', 'pid=,ppid=,pgid=,args='], capture_output=True, text=True).stdout.splitlines():
            fields = line.split(None, 3)
            if len(fields) < 4:
                continue
            _, parent, pgid, args = fields
            if int(pgid) == running.pid:
                group.append(args.split()[0].rsplit('/', 1)[-1])
            elif int(parent) == running.pid:
                elsewhere.append(' '.join(args.split()[:2]))
        signalled = running.poll() is None
        if signalled:
            os.killpg(running.pid, signal.SIGINT)
    else:
        running.kill()
    stdout, stderr = running.communicate(timeout=180)
    return {**control_result(running.returncode, stdout, stderr, started), 'signalled': signalled, 'group': group, 'elsewhere': elsewhere}


def releases() -> dict:
    """gateway-control releases：这个池的发布历史，和它与池的记录对不对得上。"""
    return run_control([str(CONTROL_BINARY), 'releases', *history_flags(), '--config-dir', str(POOL / 'config')])


def release_detail(number: int) -> dict:
    """gateway-control release --id：一条的详情和每一步。-> 发布器这一次运行的结果（退出码、输出的 JSON…）。"""
    return run_control([str(CONTROL_BINARY), 'release', *history_flags(), '--id', str(number)])


def rollback(number: int, *extra: str) -> dict:
    """gateway-control rollback --to：回到历史里第 number 条放上去的那一份快照。"""
    return run_control([str(CONTROL_BINARY), 'rollback', '--to', str(number), *pool_flags(), *staging_flags(), *history_flags(), *extra])


def history_rows() -> list[dict]:
    """releases.log 里的每一行，按先后；读不了（没有这个文件）时是空的。"""
    try:
        return [json.loads(line) for line in HISTORY_LOG.read_text(encoding='utf-8').splitlines() if line.strip()]
    except (OSError, ValueError):
        return []


def release_steps(number: int) -> list[str]:
    """日志里第 number 条依次写下的各步：状态，带步骤名的写成 APPLYING(replace-file)。"""
    return [row['state'] + (f"({row['step']})" if row.get('step') else '') for row in history_rows() if row.get('release') == number]


def shown(number: int) -> dict:
    """release --id 给出的那一条（读不到是空的）。"""
    return release_detail(number)['report'].get('release') or {}


def listed(listing: dict, number: int) -> dict:
    """releases 的输出里第 number 条那一行。"""
    return next((row for row in listing['report'].get('releases') or [] if row.get('number') == number), {})


def history_newest() -> int:
    return max((row.get('release', 0) for row in history_rows()), default=0)


def pool_now() -> dict:
    """池此刻的样子，拿来比"这条命令没有碰池"：配置文件、池的记录、网关的进程、回读的摘要、历史的日志、存下的快照。"""
    gateway = container('agentgateway')
    return {'file': on_disk(), 'record': (POOL / 'config' / RECORD).read_bytes(), 'process': (gateway.get('id'), gateway.get('pid'), gateway.get('started')),
            'digest': observe()['digest'],
            'log': HISTORY_LOG.read_bytes() if HISTORY_LOG.exists() else None,
            'snapshots': sorted(p.name for p in HISTORY_SNAPSHOTS.iterdir()) if HISTORY_SNAPSHOTS.exists() else None}


def outcome(done: dict) -> tuple:
    """发布器一次运行的退出码和结局。"""
    return done['exit'], done['report'].get('outcome')


def on_disk() -> str | None:
    """池的配置目录里现在放着的配置文件；没有这个文件时是 None。"""
    try:
        return (POOL / 'config' / 'config.yaml').read_text(encoding='utf-8')
    except FileNotFoundError:
        return None


def scratch_containers() -> list[str]:
    """离线加载用的那个临时容器（在不在跑都算）；没有时是空的。"""
    return docker('ps', '-a', '-q', '--filter', f'name=^/{SCRATCH}$').stdout.split()


def record() -> dict:
    """发布器留在配置目录里的记录：这个池上最后一次得到确认的那一份。读不出来时是空的。"""
    try:
        return json.loads((POOL / 'config' / RECORD).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}


def leftovers() -> dict:
    """发布器用过之后留在本机上的东西。"""
    return {'离线加载用的容器': scratch_containers(),
            '放候选配置的目录': sorted(p.name for p in (CONTROL / 'work').iterdir()),
            '配置目录': sorted(p.name for p in (POOL / 'config').iterdir())}


# 发布器用过之后该是这样：临时容器不在了，放候选配置的目录是空的，配置目录里只有配置文件、它的锁文件和记录。
CLEAN = {'离线加载用的容器': [], '放候选配置的目录': [], '配置目录': [RECORD, '.config.yaml.lock', 'config.yaml']}


def docker_events(name: str, since: float) -> list[str]:
    """docker 自 since（Unix 时间）以来对这个容器做过的事，按先后；kill 后面带着发的是哪个信号。"""
    done = docker('events', '--since', f'{since:.3f}', '--until', str(int(time.time()) + 1), '--filter', f'container={name}',
                  '--format', '{{.Action}} {{index .Actor.Attributes "signal"}}')
    return [' '.join(line.split()) for line in done.stdout.splitlines() if line.strip()]


def gateway_said(name: str, since: float) -> list[str]:
    """网关容器自 since（Unix 时间）以来写到标准错误上的、说它为什么退出的那几行。"""
    lines = docker('logs', '--since', f'{since:.3f}', name).stderr.splitlines()
    return [' '.join(line.split()) for line in lines if line.startswith('Error') or 'os error' in line]


def long_request(front: str, route: str, seconds: float) -> dict:
    """从 front 的容器里直接向网关收业务请求的监听发一个耗时的请求。不经 nginx：它等后端最多 10 秒。"""
    started = time.monotonic()
    done = docker('exec', front, 'wget', '-q', '-S', '-T', '90', '-O', '/dev/null', '--header', f'Host: {route}.test',
                  f"http://127.0.0.1:{PORT['callers']}/sleep/{seconds}", timeout=120)
    status = next((line.split()[1] for line in done.stderr.splitlines() if line.strip().startswith('HTTP/')), None)
    return {'status': status, 'seconds': round(time.monotonic() - started, 2), 'exit': done.returncode}


def strings_in(node, found: set | None = None) -> set:
    """一份 JSON 文档里所有的字符串值和键。"""
    found = set() if found is None else found
    if isinstance(node, dict):
        for key, value in node.items():
            found.add(key)
            strings_in(value, found)
    elif isinstance(node, list):
        for value in node:
            strings_in(value, found)
    elif isinstance(node, str):
        found.add(node)
    return found


# ---- 观察 -------------------------------------------------------------------------------------------
def container(service: str) -> dict:
    """compose 里一个服务的容器现在的样子；没有这个容器时是空的。"""
    found = compose('ps', '-q', '-a', service).stdout.split()
    inspected = json.loads(docker('inspect', found[0]).stdout or '[]') if found else []
    if not inspected:
        return {}
    c = inspected[0]
    return {'id': c['Id'], 'name': c['Name'].lstrip('/'), 'running': c['State']['Running'], 'started': c['State']['StartedAt'],
            'finished': c['State']['FinishedAt'], 'exit': c['State']['ExitCode'], 'status': c['State']['Status'],
            'pid': c['State']['Pid'],
            'restarts': c['RestartCount'], 'image': c['Config']['Image'], 'network': c['HostConfig']['NetworkMode'],
            'published': {port: sorted(f"{b['HostIp']}:{b['HostPort']}" for b in bindings)
                          for port, bindings in (c['NetworkSettings'].get('Ports') or {}).items() if bindings},
            'mounts': {m['Destination']: {'type': m['Type'], 'source': m['Source'], 'writable': m['RW']} for m in c.get('Mounts') or []}}


def moment(stamp: str) -> float:
    """docker 报告的时刻（2026-11-12T05:44:06.178863186Z）-> Unix 时间。从没发生过的（0001-01-01…）是 0。"""
    whole, _, fraction = stamp.rstrip('Z').partition('.')
    if not whole or whole.startswith('0001'):
        return 0.0
    return calendar.timegm(time.strptime(whole, '%Y-%m-%dT%H:%M:%S')) + float('0.' + (fraction or '0'))


def step(service: str) -> dict:
    """部署文件里跑完就退出的一步（place 或 confirm）最近一次运行。-> 退出码、它写到标准输出的那份 JSON、
    标准错误的末尾、开始和结束的时刻。容器不存在、还在跑或者从没跑过时 exit 是 None。"""
    return step_of(container(service))


def step_of(c: dict) -> dict:
    """同 step；c 是那一步的容器（container 或 hosted 给出的样子）。"""
    if not c or c['running'] or not moment(c['started']):
        return {'exit': None, 'report': {}, 'stderr': '', 'started': 0.0, 'finished': 0.0}
    logs = docker('logs', '--since', c['started'], c['id'])   # 以前各次运行的输出也在这个容器的日志里：只要最近这一次的
    try:
        report = json.loads(logs.stdout) if logs.stdout.strip() else {}
    except ValueError:
        report = {'unparsed': logs.stdout[:300]}
    return {'exit': c['exit'], 'report': report, 'stderr': logs.stderr.strip()[-300:],
            'started': moment(c['started']), 'finished': moment(c['finished'])}


def same_process(before: dict, after: dict) -> bool:
    """还是那个容器、那一次启动、那个进程。"""
    return bool(before) and bool(after.get('running')) and after.get('restarts') == 0 \
        and all(before.get(k) == after.get(k) for k in ('id', 'started', 'pid'))


def get(virtual_host: str, path: str, timeout: float = 8) -> dict:
    """经 front 的端口发一个请求，用一条新连接。-> 状态码和应答正文的开头；没有得到应答时是出了什么错。"""
    try:
        conn = http.client.HTTPConnection('127.0.0.1', HOST['front'], timeout=timeout)
        conn.request('GET', path, headers={'Host': virtual_host, 'Connection': 'close'})
        response = conn.getresponse()
        body = response.read()
        conn.close()
        return {'status': response.status, 'body': body[:200].decode('latin1')}
    except (OSError, http.client.HTTPException) as e:
        return {'status': None, 'error': f'{type(e).__name__}: {str(e)[:80]}'}


def routes_seen(names: list[str]) -> dict:
    """经 front 的端口逐个问这些路由，得到的状态码。"""
    return {name: get(f'{name}.test', '/quick')['status'] for name in names}


def from_another_container() -> dict:
    """从同一个 compose 网络上的另一个容器（echo）去连 netns 占着的那个网络命名空间里的各端口。
    0 是连上了，111 是被拒绝。"""
    code = ('import json, socket\n'
            'seen = {}\n'
            f'for name, port in {PORT!r}.items():\n'
            '    with socket.socket() as s:\n'
            '        s.settimeout(3)\n'
            "        seen[name] = s.connect_ex(('netns', port))\n"
            'print(json.dumps(seen))\n')
    done = docker('exec', container('echo').get('id', '-'), 'python', '-c', code)
    try:
        return json.loads(done.stdout)
    except ValueError:
        return {'error': (done.stderr or done.stdout).strip()[-200:]}


# 在池的网络命名空间里试着连几个地址（参数，写成 地址:端口），再解析一次后端的名字。connect 的结果：0 是连上了；
# 113（EHOSTUNREACH）是被 pin-egress.sh 的规则拒绝，IPv6 上是 13（EACCES）；111 是对方自己拒绝。
CONNECT = r'''
import json, socket, sys
seen = {}
for target in sys.argv[1:]:
    host, port = target.rsplit(":", 1)
    with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET) as s:
        s.settimeout(3)
        seen[target] = s.connect_ex((host.strip("[]"), int(port)))
try:
    seen["echo"] = socket.gethostbyname("echo")
except OSError as failed:
    seen["echo"] = f"{type(failed).__name__}: {failed}"
print(json.dumps(seen))
'''
# 对着一个地址连上若干秒，每种结果各有多少次。
HAMMER = r'''
import collections, json, socket, sys, time
host, port, seconds = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
seen, end = collections.Counter(), time.time() + seconds
while time.time() < end:
    with socket.socket() as s:
        s.settimeout(0.3)
        seen[str(s.connect_ex((host, port)))] += 1
    time.sleep(0.002)
print(json.dumps(seen))
'''
REFUSED_HERE, REFUSED_HERE_V6 = 113, 13


def from_the_pool(code: str, *argv: str) -> dict:
    """在池的网络命名空间里跑一段 Python（一个接在 netns 上的临时容器，不属于这个 compose 项目），它打印一份 JSON。"""
    done = docker('run', '--rm', '--network', f"container:{container('netns').get('id', '-')}", TOOLS_IMAGE, 'python', '-c', code, *argv)
    try:
        return json.loads(done.stdout)
    except ValueError:
        return {'error': (done.stderr or done.stdout).strip()[-300:]}


def pinned() -> dict:
    """池的网络命名空间里现在钉着的：{"名字:端口": [地址, …]}。读法是让 egress 这个服务另跑一个临时容器去列规则。"""
    listed = compose('run', '--rm', '--no-deps', '--entrypoint', 'iptables', 'egress', '-S', 'IDP_EGRESS').stdout
    found = {}
    for line in listed.splitlines():
        words = line.replace('"', '').split()
        if '--comment' in words and '-d' in words and words[words.index('--comment') + 1].startswith('pin:'):
            found.setdefault(words[words.index('--comment') + 1][4:], []).append(words[words.index('-d') + 1].split('/')[0])
    return {key: sorted(addresses) for key, addresses in found.items()}


def backend_reachable() -> bool:
    """从网关所在的网络命名空间里（netns 容器）按名字直接去问后端：答了，就是名字解析得了，后端也在。"""
    return docker('exec', container('netns').get('name', '-'), 'wget', '-q', '-T', '3', '-O', '/dev/null',
                  f'http://echo:{ECHO_PORT}/quick').returncode == 0


# ---- 断电，再启动 -----------------------------------------------------------------------------------
def power_cut() -> bool:
    """断电的样子：部署文件里常驻的三个容器同时被强行杀掉（SIGKILL），谁都来不及收拾。后端 echo 不动。
    -> 三个是不是都停了。"""
    docker('kill', *(container(name).get('name', '-') for name in LONG_RUNNING))
    return not any(container(name).get('running') for name in LONG_RUNNING)


def pool_events(since: float) -> list[str]:
    """docker 自 since（Unix 时间）以来给部署文件里的容器发过的信号，和它们的退出，按先后：
    "kill 服务 信号" 和 "die 服务"。装出口规则的两个不算：谁都不等它们，它们停在哪一刻与别的没有先后。"""
    done = docker('events', '--since', f'{since:.3f}', '--until', str(int(time.time()) + 1),
                  '--filter', f'label=com.docker.compose.project={PROJECT}', '--format',
                  '{{.TimeNano}} {{.Action}} {{index .Actor.Attributes "com.docker.compose.service"}} {{index .Actor.Attributes "signal"}}')
    rows = [line.split() for line in done.stdout.splitlines()]
    rows = [row for row in rows if len(row) >= 3 and row[0].isdigit() and row[1] in ('kill', 'die')
            and row[2] in SERVICES and row[2] not in EGRESS]
    return [' '.join(row[1:]) for row in sorted(rows, key=lambda row: int(row[0]))]


class Knock:
    """一直敲业务端口：每 0.05 秒对给定的每条路由各发一个请求（每个一条新连接），记下每个请求发出的时刻、
    结果回来的时刻（Unix 时间）和得到的状态码；没有得到应答时状态码是 None。请求各发各的，不等前一个回来：
    netns 刚起来那一会儿发出的请求会悬 1 秒左右，不能让它挡住后面的。"""

    def __init__(self, routes: tuple):
        self.routes, self.log, self.stop = routes, [], threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _ask(self, route: str):
        at = time.time()
        status = get(f'{route}.test', '/quick', 2)['status']
        self.log.append({'route': route, 'at': at, 'back': time.time(), 'status': status})

    def _run(self):
        asking = []
        while not self.stop.is_set():
            for route in self.routes:
                asking.append(threading.Thread(target=self._ask, args=(route,), daemon=True))
                asking[-1].start()
            self.stop.wait(0.05)
        for one in asking:
            one.join(5)

    def finish(self) -> list:
        """-> 全部请求，按结果回来的先后。"""
        self.stop.set()
        self.thread.join(10)
        return sorted(self.log, key=lambda q: q['back'])


def boot(routes: tuple = ('a',), start=None) -> dict:
    """跑一次部署文件的启动命令（docker compose up -d，开机时那个单元跑的就是它），这期间一直有人在敲业务端口。
    时刻都是 Unix 时间。start 给的是另一种跑法（由看守来跑这条命令时用）：一个函数，等到启动命令跑完才返回，
    返回它成没成（0 是成了）和它最后说的那一行。
    -> exit、said：命令的退出码和它最后说的那一行；began、seconds：命令开始的时刻和用了多少秒；
       place、confirm：这两步这一次的结果（见 step）；started：五个容器各自最近一次启动的时刻；
       answers：每条路由上各种结果各有多少个；first：第一个应答是什么时候到的（一个都没有时是 None），
       first_sent：得到它的那个请求是什么时候发出的；unanswered：在那之前落空的请求有多少个。"""
    knock, began = Knock(routes), time.time()
    if start is None:
        up = compose('up', '-d')
        code, said = up.returncode, (up.stderr.strip().splitlines() or [''])[-1].strip()
    else:
        code, said = start()
    seconds = round(time.time() - began, 2)
    if code == 0:
        wait_for(lambda: get(f'{routes[0]}.test', '/quick')['status'] is not None, 10)
    time.sleep(1)   # front 开了之后再敲一秒：每条路由都问到几次
    log = knock.finish()
    answered = min((q for q in log if q['status'] is not None), key=lambda q: q['back'], default=None)
    first = answered['back'] if answered else None
    return {'exit': code, 'said': said, 'began': began, 'seconds': seconds,
            'place': step('place'), 'confirm': step('confirm'),
            'started': {name: moment(container(name).get('started') or '') for name in SERVICES},
            'answers': {route: dict(collections.Counter(str(q['status']) for q in log if q['route'] == route)) for route in routes},
            'first': first, 'first_sent': answered['at'] if answered else None,
            'unanswered': sum(1 for q in log if q['status'] is None and (first is None or q['back'] <= first))}


def in_order(seen: dict, holder_was_up: bool = False) -> bool:
    """这一次启动是按部署文件说的先后来的：place 跑完，网关才启动；网关启动了，confirm 才跑；confirm 跑完，
    front 才启动。netns 在网关之前启动；holder_was_up 为真时，它是这次命令之前就起来了的。"""
    at, place, confirm = seen['started'], seen['place'], seen['confirm']
    holder = 0 < at['netns'] <= seen['began'] if holder_was_up else seen['began'] <= at['netns'] <= at['agentgateway']
    return (holder and seen['began'] <= place['started'] <= place['finished'] <= at['agentgateway']
            <= confirm['started'] <= confirm['finished'] <= at['front'])


def gated(seen: dict, route: str = 'a') -> bool:
    """confirm 跑完之前，业务端口上没有给出过一个应答（这期间落空的请求不少于 10 个）；之后这条路由有请求得到 200。
    比的是应答到的时刻，不是请求发出的时刻：netns 刚起来那一会儿发出的请求，连接会悬 1 秒左右才有结果，
    那时 front 要是已经开了，它得到的就是应答（量到过：启动命令开始后 0.35 秒发出，1.37 秒得到应答）。"""
    return (seen['first'] is not None and 0 < seen['confirm']['finished'] <= seen['first'] and seen['unanswered'] >= 10
            and seen['answers'].get(route, {}).get('200', 0) >= 1)


def timeline(seen: dict) -> dict:
    """一次启动里各件事发生的时刻：相对于启动命令开始的秒数。没有发生的是 None。"""
    def relative(at):
        return round(at - seen['began'], 2) if at else None
    return {'netns 启动': relative(seen['started']['netns']), 'place 跑完': relative(seen['place']['finished']),
            '网关启动': relative(seen['started']['agentgateway']), 'confirm 跑完': relative(seen['confirm']['finished']),
            'front 启动': relative(seen['started']['front']), '第一个应答到达': relative(seen['first']),
            '得到它的那个请求发出': relative(seen['first_sent']), '命令返回': seen['seconds']}


def wait_for(predicate, seconds: float, every: float = 0.05):
    """-> predicate() 第一次成立时过了多少秒；到时还不成立则 None。"""
    started = time.monotonic()
    while time.monotonic() - started < seconds:
        if predicate():
            return round(time.monotonic() - started, 2)
        time.sleep(every)
    return None


# ---- 看守 -------------------------------------------------------------------------------------------
KEEPERS = []   # 本次运行起过的看守。拆的时候先停它们：看守在跑的话，会把正在拆的池再起起来


class Keeper:
    """本机上跑着的一个真的看守（gateway-control keep）。它不经 systemd：由本脚本直接起，docker compose 的项目、
    文件和变量文件，与本脚本自己跑 docker compose 时给的相同。它写到标准输出的每一行 JSON 连同到的时刻
    （at，Unix 时间）记在 lines 里，写到标准错误上的记在 said 里。
    settings 为真时，它的环境里带着部署文件的各个变量：看守的单元由 systemd 读了 .env 交给它的就是这样。
    more 是另外放进它环境里的变量。
    SH-19 把这些都另给：command 是整条命令行（看守的单元里写的那一条），cwd 是它在哪个目录里跑，environment 是它的环境。"""

    def __init__(self, *extra: str, settings: bool = False, env_file: Path = POOL_ENV, more: dict | None = None,
                 command: list | None = None, cwd: Path | None = None, environment: dict | None = None):
        self.lines, self.said = [], []
        if command is None:
            command = [str(CONTROL_BINARY), 'keep', *pool_flags(), '--compose-project', PROJECT, '--compose-env-file', str(env_file),
                       '--compose-file', str(DEPLOY / 'compose.yml'), '--compose-file', str(HERE / 'echo.yml'), *extra]
        if shutil.which('setpriv'):   # 本脚本被强行杀掉时让看守跟着死：不然它留在本机上，一直守着一个没人管的池
            command = ['setpriv', '--pdeathsig', 'KILL', *command]
        if environment is None:
            environment = {**compose_environment(), **(pool_settings() if settings else {}), **(more or {})}
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment, cwd=cwd)
        KEEPERS.append(self)
        self.readers = [threading.Thread(target=self._read, daemon=True), threading.Thread(target=self._listen, daemon=True)]
        for reader in self.readers:
            reader.start()

    def _read(self):
        for line in self.process.stdout:
            try:
                self.lines.append({'at': time.time(), **json.loads(line)})
            except ValueError:
                self.lines.append({'at': time.time(), 'unparsed': line[:300]})

    def _listen(self):
        for line in self.process.stderr:
            self.said.append(line.rstrip())

    def mark(self) -> int:
        """它现在写到了第几行：把它交给 wait 或 next，就只看这之后的。"""
        return len(self.lines)

    def wait(self, want, seconds: float, since: int = 0, count: int = 1) -> list:
        """等它从第 since 行起写出 count 行符合 want 的。-> 那几行，按先后；到时还不够的，有几行是几行。"""
        def found() -> list:
            return [line for line in self.lines[since:] if want(line)]
        wait_for(lambda: len(found()) >= count, seconds)
        return found()[:count]

    def next(self, want, seconds: float, since: int = 0) -> dict:
        """等它从第 since 行起写出一行符合 want 的。-> 那一行；到时没有等到是空的。"""
        return (self.wait(want, seconds, since) or [{}])[0]

    def children(self) -> list[str]:
        """它这时的子进程各自的命令行。"""
        found = subprocess.run(['ps', '-o', 'args=', '--ppid', str(self.process.pid)], capture_output=True, text=True).stdout
        return [line.strip() for line in found.splitlines() if line.strip()]

    def composing(self) -> bool:
        """它这时是不是正跑着启动命令：docker compose … up -d 是它的子进程。"""
        return any(line.endswith(' up -d') for line in self.children())

    def stop(self, how: int = signal.SIGTERM, seconds: float = 60) -> dict:
        """给它发一个信号（默认是 SIGTERM：叫停它），等它退出；已经退出了的不再发。
        -> 退出码，从发信号到退出过了多少秒，退出的时刻，它在标准错误上说过的。"""
        began = time.monotonic()
        if self.process.poll() is None:
            self.process.send_signal(how)
        try:
            code = self.process.wait(seconds)
        except subprocess.TimeoutExpired:
            self.process.kill()
            code = self.process.wait(30)
        at = time.time()
        for reader in self.readers:
            reader.join(5)
        return {'exit': code, 'seconds': round(time.monotonic() - began, 2), 'at': at, 'stderr': list(self.said)}

    def ended(self, seconds: float = 15) -> dict:
        """等它自己退出，不给它发信号；到时还在跑的才叫停它。-> 同 stop。"""
        wait_for(lambda: self.process.poll() is not None, seconds)
        return self.stop()


def whole(line: dict) -> bool:
    """看守的一行说的是不是三个常驻容器都在跑。"""
    return line.get('condition') == 'whole'


def acted(line: dict) -> bool:
    """看守的一行说的是不是它动过容器。"""
    return bool(line.get('action'))


def reconciled(line: dict) -> dict:
    """看守的一行里那一次对账的结果；那一次没有对账时是空的。"""
    return line.get('reconcile') or {}


def restored(line: dict) -> bool:
    return reconciled(line).get('outcome') == 'RESTORED'


def member(line: dict, when: str, service: str) -> dict:
    """看守的一行里某个容器的样子。when 是 'pool'（动手之前）或 'after'（动手之后）。"""
    return (line.get(when) or {}).get(service) or {}


def brief(line: dict) -> dict:
    """看守写的一行里要紧的几项；三个容器各自的样子略去。"""
    account = reconciled(line)
    return {**{k: line.get(k) for k in ('condition', 'why', 'busy', 'action', 'start_error', 'repaired', 'retry_in_seconds', 'error')},
            'reconcile': [account.get('outcome'), account.get('reason')] if account else None}


def patient(command, tries: int = 5) -> dict:
    """跑一次发布器的命令（command 是 control、control_reconcile 那样的调用）。看守在跑时，它正好撞上看守在对账的
    那一瞬间的话，会说有另一次发布在进行、什么都不做（退出码 1）：隔一会儿再来。"""
    for _ in range(tries):
        done = command()
        if not (done['exit'] == 1 and 'another publication' in done['stderr']):
            break
        time.sleep(0.3)
    return done


# ---- 告警：看守的指标，和读它的 Prometheus -------------------------------------------------------------
def scrape(address: str = METRICS, path: str = '/metrics', method: str = 'GET') -> dict:
    """读一次看守的指标。-> status；content_type；allow；series（名字{标签} -> 值）；types（名字 -> gauge 或 counter）。
    那个地址上没有人时 status 是 None。"""
    host, port = address.rsplit(':', 1)
    connection = http.client.HTTPConnection(host, int(port), timeout=3)
    try:
        connection.request(method, path)
        response = connection.getresponse()
        body = response.read().decode('utf-8', 'replace')
    except (OSError, http.client.HTTPException) as error:
        return {'status': None, 'error': f'{type(error).__name__}: {error}', 'series': {}, 'types': {}}
    finally:
        connection.close()
    series, types = {}, {}
    for line in body.splitlines() if response.status == 200 else []:
        if line.startswith('# TYPE '):
            name, kind = line.split()[2:4]
            types[name] = kind
        elif line and not line.startswith('#'):
            name, _, value = line.rpartition(' ')
            series[name] = float(value)
    return {'status': response.status, 'content_type': response.getheader('Content-Type'), 'allow': response.getheader('Allow'),
            'series': series, 'types': types}


def standing(series: dict, name: str) -> list[str]:
    """一组取值里此刻是 1 的那几个：idp_gateway_pool_condition 的，或者 idp_gateway_pool_reconcile_outcome 的。"""
    return sorted(key.split('"')[1] for key, value in series.items() if key.startswith(name + '{') and value == 1)


def pool_is(condition: str) -> bool:
    return standing(scrape()['series'], 'idp_gateway_pool_condition') == [condition]


def account_is(outcome_name: str) -> bool:
    return standing(scrape()['series'], 'idp_gateway_pool_reconcile_outcome') == [outcome_name]


def promtool(*argv: str) -> subprocess.CompletedProcess:
    """在 Prometheus 的镜像里跑 promtool。它只拿到两个文件：部署目录里的规则，和 rules.test.yml；不接网络。"""
    inside = {path: f'/repo/{path.relative_to(ROOT)}' for path in (RULES, RULE_TESTS)}
    mounts = [word for path, target in inside.items() for word in ('-v', f'{path}:{target}:ro')]
    return docker('run', '--rm', '--network', 'none', '--read-only', '--tmpfs', '/tmp', '--cap-drop', 'ALL',
                  '--security-opt', 'no-new-privileges', '--user', '65534:65534', *mounts,
                  '--entrypoint', 'promtool', PROMETHEUS_IMAGE, *(inside.get(word, word) for word in argv))


def prometheus_up() -> subprocess.CompletedProcess:
    """起一个真的 Prometheus：主机网络，只听回环。它每秒读一次看守、每秒算一次规则（平时是 15 秒，这里为了不等）；
    规则就是部署目录里的那一份，抓取任务的名字是规则里写的那个。"""
    MONITOR.mkdir(exist_ok=True)
    (MONITOR / 'prometheus.yml').write_text(yaml.safe_dump({
        'global': {'scrape_interval': '1s', 'evaluation_interval': '1s'},
        'rule_files': ['/etc/prometheus/rules.yml'],
        'scrape_configs': [{'job_name': JOB, 'static_configs': [{'targets': [METRICS]}]}]}), encoding='utf-8')
    docker('rm', '-f', PROMETHEUS)
    # tmpfs 默认属主是 root：--user 换成了本机用户之后，Prometheus 在 /prometheus 里建不了文件，立刻以 1 退出
    # （queries.active: permission denied）。把 uid/gid 写上，它才写得进去。
    return docker('run', '-d', '--name', PROMETHEUS, '--network', 'host', '--read-only', '--cap-drop', 'ALL',
                  '--security-opt', 'no-new-privileges', '--user', RUN_AS,
                  '--tmpfs', f'/prometheus:uid={os.getuid()},gid={os.getgid()},mode=0755',
                  '-v', f"{MONITOR / 'prometheus.yml'}:/etc/prometheus/prometheus.yml:ro", '-v', f'{RULES}:/etc/prometheus/rules.yml:ro',
                  PROMETHEUS_IMAGE, '--config.file=/etc/prometheus/prometheus.yml', '--storage.tsdb.path=/prometheus',
                  f"--web.listen-address=127.0.0.1:{HOST['prometheus']}")


def prometheus(path: str) -> dict:
    """问那个 Prometheus 的 HTTP 接口。-> 它答的 data；问不到、或者答的不是 success 时是空的。"""
    connection = http.client.HTTPConnection('127.0.0.1', HOST['prometheus'], timeout=5)
    try:
        connection.request('GET', path)
        answer = json.loads(connection.getresponse().read())
    except (OSError, http.client.HTTPException, ValueError):
        return {}
    finally:
        connection.close()
    return (answer.get('data') or {}) if answer.get('status') == 'success' else {}


def alerts() -> dict:
    """Prometheus 此刻的告警：名字 -> pending（条件成立了，还没到时长）或 firing（响了）。一条都没有时是空的。"""
    found = {}
    for alert in prometheus('/api/v1/alerts').get('alerts') or []:
        name = alert['labels']['alertname']
        if found.get(name) != 'firing':
            found[name] = alert['state']
    return found


def strays() -> list[int]:
    """本脚本上一次被强行杀掉时可能留在本机上的进程：本次运行目录里的那个 gateway-control（看守），
    和对着这套用例的项目、或者在 SH-19 的安装目录里跑着的 docker compose。"""
    found = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            argv = [word.decode(errors='replace') for word in (entry / 'cmdline').read_bytes().split(b'\0') if word]
            directory = os.readlink(entry / 'cwd')
        except OSError:
            continue
        composing = 'compose' in argv and (any(argv[i:i + 2] == ['-p', PROJECT] for i in range(len(argv))) or directory == str(HOSTED))
        if argv and (argv[0] == str(CONTROL_BINARY) or composing):
            found.append(int(entry.name))
    return found


def unit_commands(name: str) -> dict:
    """deploy/compose 里一个单元文件写的命令（ExecStart=、ExecStop=），切成词：行尾的反斜杠接下一行，按空白切。"""
    found = {}
    for line in (DEPLOY / name).read_text(encoding='utf-8').replace('\\\n', ' ').splitlines():
        key, assigned, value = line.partition('=')
        if assigned and key in ('ExecStart', 'ExecStop'):
            found[key] = value.split()
    return found


def filled_in(words: list[str], settings: dict) -> list[str]:
    """把各个词里的 ${名字} 换成 settings 里的值，一个词还是一个词。看守的单元的 ExecStart 由 systemd 这样填
    （值取自 EnvironmentFile；真的 systemd 填出来是什么，units.py 的 UN-01 看过）。没有这个名字就是出了错。"""
    return [re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}', lambda found: settings[found.group(1)], word) for word in words]


def hosted() -> dict:
    """SH-19 的那个池：部署文件自己的项目名下各服务的容器现在的样子，按 docker compose 贴的标签找。
    directory 和 files 是 docker compose 记在容器上的项目目录和它用的 compose 文件。"""
    ids = docker('ps', '-a', '-q', '--no-trunc', '--filter', f'label=com.docker.compose.project={DEPLOYED_PROJECT}').stdout.split()
    found = {}
    for c in (json.loads(docker('inspect', *ids).stdout or '[]') if ids else []):
        labels = c['Config'].get('Labels') or {}
        found[labels.get('com.docker.compose.service')] = {
            'id': c['Id'], 'name': c['Name'].lstrip('/'), 'running': c['State']['Running'], 'started': c['State']['StartedAt'],
            'finished': c['State']['FinishedAt'], 'exit': c['State']['ExitCode'], 'pid': c['State']['Pid'], 'restarts': c['RestartCount'],
            'directory': labels.get('com.docker.compose.project.working_dir'),
            'files': labels.get('com.docker.compose.project.config_files')}
    return found


def hosted_networks() -> list[str]:
    return docker('network', 'ls', '--filter', f'label=com.docker.compose.project={DEPLOYED_PROJECT}', '--format', '{{.Name}}').stdout.split()


def remove_hosted():
    """SH-19 起的那个项目不带这套用例的前缀，所以只删认得出是本脚本起的：容器按 docker compose 记下的项目目录认
    （本次运行的安装目录）；网络没有这个标签，凭 SH-19 开始时留下的记号删，而且要那个项目已经没有容器了。"""
    rows = [line.split() for line in docker('ps', '-a', '--filter', f'label=com.docker.compose.project.working_dir={HOSTED}',
                                            '--format', '{{.ID}} {{.Label "com.docker.compose.project"}}').stdout.splitlines()]
    rows = [row for row in rows if len(row) == 2]
    if rows:
        docker('rm', '-f', '-v', *(row[0] for row in rows))
    projects = {row[1] for row in rows}
    if HOSTED_MARK.exists():
        projects.add(HOSTED_MARK.read_text(encoding='utf-8').strip())
    for project in sorted(p for p in projects if p):
        mine = f'label=com.docker.compose.project={project}'
        if not docker('ps', '-a', '-q', '--filter', mine).stdout.split():
            for network in docker('network', 'ls', '-q', '--filter', mine).stdout.split():
                docker('network', 'rm', network)
    HOSTED_MARK.unlink(missing_ok=True)


def differing(a: dict, b: dict) -> list[str]:
    return sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))


class Load:
    """从本机经 front 的端口发请求：每秒 20 个快请求（每个一条新连接），另有几条线各自接连发慢请求。
    每个请求何时发出、何时回来、结果如何都记在 log 里；时刻是相对于流量开始的秒数。"""

    def __init__(self, route: str = 'a', rate: float = 20.0, slow_workers: int = 2, slow_seconds: float = 2.0):
        self.route, self.rate, self.slow_seconds = route, rate, slow_seconds
        self.log, self.guard, self.stop, self.requests = [], threading.Lock(), threading.Event(), []
        self.started = time.monotonic()
        self.threads = [threading.Thread(target=self._slow, daemon=True) for _ in range(slow_workers)]
        self.threads.append(threading.Thread(target=self._quick, daemon=True))
        for thread in self.threads:
            thread.start()
        time.sleep(3)   # 先有几秒不受打扰的流量

    def now(self) -> float:
        return round(time.monotonic() - self.started, 2)

    def _one(self, kind: str, path: str, timeout: float) -> bool:
        at = self.now()
        got = get(f'{self.route}.test', path, timeout)
        entry = {'at': at, 'done': self.now(), 'kind': kind,
                 'outcome': str(got['status']) if got['status'] is not None else got['error'].split(':')[0]}
        if got['status'] != 200:
            entry['detail'] = ' '.join((got.get('error') or got.get('body') or '').split())
        with self.guard:
            self.log.append(entry)
        return got['status'] == 200

    def _slow(self):
        while not self.stop.is_set():
            if not self._one('slow', f'/sleep/{self.slow_seconds}', self.slow_seconds + 20):
                self.stop.wait(0.1)   # 失败的请求立刻就回来了：不紧接着重发，免得把失败的个数撑大

    def _quick(self):
        tick = 0
        while not self.stop.is_set():
            request = threading.Thread(target=self._one, args=('quick', '/quick', 8), daemon=True)
            request.start()
            self.requests.append(request)
            tick += 1
            time.sleep(max(0.0, self.started + tick / self.rate - time.monotonic()))

    def finish(self) -> dict:
        self.stop.set()
        for thread in self.threads:    # 先等发请求的那几条线停下，再等它们发出去的请求回来
            thread.join(40)
        for thread in self.requests:
            thread.join(40)
        self.log.sort(key=lambda q: q['at'])
        failures = [q for q in self.log if q['outcome'] != '200']
        counts = {kind: dict(collections.Counter(q['outcome'] for q in self.log if q['kind'] == kind)) for kind in ('quick', 'slow')}
        return {'seconds': self.now(), **counts, 'not_200': len(failures), 'failures': failures[:60]}


class Results:
    def __init__(self):
        self.cases, self.current, self.broke_in = [], None, None

    def case(self, cid: str, title: str):
        self.current = {'id': cid, 'title': title, 'checks': [], 'notes': {}}
        self.cases.append(self.current)
        print(f'  ...  {cid}  {title}', flush=True)

    def check(self, what: str, ok) -> bool:
        self.current['checks'].append({'check': what, 'ok': bool(ok)})
        return bool(ok)

    def note(self, key: str, value):
        if key in self.current['notes']:   # 同名的两条，后一条会悄悄盖掉前一条
            raise AssertionError(f"{self.current['id']} 里有两条记录都叫 {key!r}")
        self.current['notes'][key] = value

    def broke(self, error: Exception):
        """本脚本自己在半路出了错（要在 except 里调用）：已经查到的照样报出来，出错的这个用例算没通过；
        它后面的用例没有跑。"""
        if self.current is None:
            self.case('-', '第一个用例开始之前')
        self.broke_in = self.current['id']
        self.current['checks'].append({'check': f'本脚本在这里出了错，后面的都没有跑：{type(error).__name__}: {error}', 'ok': False})
        self.current['notes']['出错的地方'] = traceback.format_exc().strip().splitlines()[-8:]

    def failed(self) -> list:
        return [c for c in self.cases if not all(k['ok'] for k in c['checks'])]

    def report(self):
        for c in self.cases:
            bad = [k['check'] for k in c['checks'] if not k['ok']]
            print(f"  {'FAIL' if bad else 'PASS'}  {c['id']}  {c['title']}")
            for what in bad:
                print(f'          ✗ {what}')
            for key, value in c['notes'].items():
                print(f'          {key}: {value}')


def no_failures(r: Results, traffic: dict, what: str):
    r.note(f'{what}：快请求 / 慢请求的结果', f"{traffic.get('quick')} / {traffic.get('slow')}，历时 {traffic.get('seconds')} 秒")
    if traffic.get('failures'):
        r.note(f'{what}：没有得到 200 的请求（至多列 60 个）', traffic['failures'])
    r.check(f'{what}：发出去的请求不少于 100 个', sum((traffic.get('quick') or {}).values()) >= 100)
    r.check(f'{what}：没有一个请求失败', traffic.get('not_200') == 0 and bool(traffic.get('quick')) and bool(traffic.get('slow')))


def restart_under(traffic: Load) -> dict:
    """重启网关容器，front 不动；traffic 一直在发，网关回来之后再发 3 秒。-> 量到的，时刻是相对于流量开始的秒数。"""
    began = traffic.now()
    command = compose('restart', '--timeout', '60', 'agentgateway')
    ended = traffic.now()
    back = wait_for(lambda: observe()['digest'] is not None, 30)
    time.sleep(3)
    result = traffic.finish()
    quick = [q for q in traffic.log if q['kind'] == 'quick']
    return {'restarted': command.returncode == 0 and back is not None, 'began': began, 'ended': ended, 'result': result,
            'quick': quick, 'refused': [q for q in quick if q['outcome'] != '200'],
            'in_flight': [q for q in traffic.log if q['kind'] == 'slow' and q['at'] < began < q['done']],
            'answers': sorted({f"{q['outcome']}：{q['detail']}" for q in traffic.log if q['outcome'] != '200'})}


def note_restart(r: Results, what: str, seen: dict):
    """单机上只有这一个实例，重启期间新来的请求没有别处可去。量到的记下来，不设期望。"""
    refused, result = seen['refused'], seen['result']
    r.note(f'{what}：重启命令从开始到返回（相对于流量开始的秒数）', f"{seen['began']} 到 {seen['ended']}")
    r.note(f'{what}：当时在途的慢请求各自做完的时刻', [q['done'] for q in seen['in_flight']])
    r.note(f'{what}：没有得到 200 的快请求', f"{len(refused)} 个，发出的时刻从 {refused[0]['at']} 到 {refused[-1]['at']}" if refused else '没有')
    r.note(f'{what}：没有得到 200 的请求得到的是什么', seen['answers'])
    r.note(f'{what}：快请求 / 慢请求的结果', f"{result['quick']} / {result['slow']}，历时 {result['seconds']} 秒")


def outage(traffic: Load) -> dict:
    """一段流量里的一次重启（在 traffic.finish() 之后调用）。重启开始的时刻取第一个没有得到 200 的快请求发出的时刻。
    spanning 是在那之前发出、在那之后才做完并得到 200 的慢请求；cut 是做了半秒以上却没有得到 200 的慢请求
    （被拒绝的请求立刻就回来，做了一阵才失败的是被切断的）。"""
    quick = [q for q in traffic.log if q['kind'] == 'quick']
    slow = [q for q in traffic.log if q['kind'] == 'slow']
    refused = [q for q in quick if q['outcome'] != '200']
    began = refused[0]['at'] if refused else None
    return {'refused': refused, 'began': began, 'last': quick[-20:],
            'spanning': [q for q in slow if began is not None and q['outcome'] == '200' and q['at'] < began < q['done']],
            'cut': [q for q in slow if q['outcome'] != '200' and q['done'] - q['at'] >= 0.5],
            'answers': sorted({f"{q['outcome']}：{q['detail']}" for q in traffic.log if q['outcome'] != '200'})}


def note_outage(r: Results, what: str, seen: dict, result: dict):
    """发布器重启网关的那一次，量到的记下来，不设期望。"""
    refused = seen['refused']
    r.note(f'{what}：没有得到 200 的快请求', f"{len(refused)} 个，发出的时刻从 {refused[0]['at']} 到 {refused[-1]['at']}" if refused else '没有')
    r.note(f'{what}：跨过重启开始那一刻的慢请求各自做完的时刻', [q['done'] for q in seen['spanning']])
    r.note(f'{what}：没有得到 200 的请求得到的是什么', seen['answers'])
    r.note(f'{what}：快请求 / 慢请求的结果', f"{result['quick']} / {result['slow']}，历时 {result['seconds']} 秒")


# ---- 起和拆 -----------------------------------------------------------------------------------------
def prepare():
    """本次运行的东西，照着部署文件的 README 布置：池的目录（config 和 tls 两个子目录），给网关的环境变量文件，
    和一份 .env。证书现做；网关容器只拿到它自己的那几个文件。"""
    RUN.mkdir(exist_ok=True)
    os.chmod(RUN, 0o700)
    for stale in STALE:
        shutil.rmtree(stale, ignore_errors=True)
    pki.issue(PKI)
    (POOL / 'config').mkdir(parents=True)
    (POOL / 'tls').mkdir()
    for name in GATEWAY_FILES:
        shutil.copy2(PKI / name, POOL / 'tls' / name)
    session = POOL / 'gateway.env'
    session.touch(mode=0o600)
    session.write_text(f'SESSION_KEY={SESSION_KEY}\n', encoding='utf-8')
    # .env：.env.example 里要填的每一项都给了值，没有给它不认识的。
    settings, example = pool_settings(), example_variables()
    unfilled = set(example['required']) - set(settings)
    unknown = set(settings) - set(example['required']) - set(example['optional'])
    if unfilled or unknown or not example['required']:
        die(f'deploy/compose/.env.example 与本脚本给的变量对不上：没有给的 {sorted(unfilled)}，它没有的 {sorted(unknown)}')
    POOL_ENV.write_text(''.join(f'{name}={value}\n' for name, value in settings.items()), encoding='utf-8')


def teardown():
    """看守、容器、网络和本次运行的证书都不留；留下的只有 .run/result.json。"""
    for keeper in KEEPERS:   # 先停看守，再拆它守着的池
        keeper.stop(seconds=30)
    for pid in strays():
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    remove_hosted()
    if POOL_ENV.exists():
        compose('down', '--volumes', '--remove-orphans', '--timeout', '5')
    # 上一次运行死在半路时 pool.env 可能已经不在了，compose 读不了部署文件：按项目的标签直接删。
    mine = f'label=com.docker.compose.project={PROJECT}'
    left = docker('ps', '-a', '-q', '--filter', mine).stdout.split()
    if left:
        docker('rm', '-f', '-v', *left)
    for network in docker('network', 'ls', '-q', '--filter', mine).stdout.split():
        docker('network', 'rm', network)
    docker('rm', '-f', SCRATCH)
    docker('rm', '-f', PROMETHEUS)
    for stale in STALE:
        shutil.rmtree(stale, ignore_errors=True)
    POOL_ENV.unlink(missing_ok=True)


def main() -> int:
    # 被叫停时也照样拆：不然留下的看守会一直守着这个池。
    for number in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, lambda received, _: sys.exit(128 + received))
    try:
        return run()
    finally:
        teardown()


def run() -> int:
    for name, port in HOST.items():
        with socket.socket() as s:
            s.settimeout(0.3)
            if s.connect_ex(('127.0.0.1', port)) == 0:
                die(f'端口 {port} 已被占用（另一套用例在跑？）')
    versions = {'docker': docker('version', '--format', '{{.Server.Version}}').stdout.strip(),
                'compose': docker('compose', 'version', '--short').stdout.strip()}
    if not versions['docker'] or not versions['compose']:
        die('需要 docker 和 docker compose')
    teardown()   # 上一次没跑完留下的
    prepare()
    build_control()
    r = Results()
    try:
        cases(r)
    except Exception as error:   # 本脚本自己出了错（部署文件被改坏了时会这样）：前面查到的不能跟着丢掉
        r.broke(error)
    print(f"\ndocker {versions['docker']}，compose {versions['compose']}，agentgateway {LOCK['version']}（{GATEWAY_IMAGE}）")
    r.report()
    failed = r.failed()
    (RUN / 'result.json').write_text(json.dumps({**versions, 'agentgateway': LOCK['version'], 'image': GATEWAY_IMAGE,
                                                 'front_image': FRONT_IMAGE, 'broke_in': r.broke_in, 'cases': r.cases},
                                                ensure_ascii=False, indent=1), encoding='utf-8')
    print(f"\n{len(r.cases) - len(failed)}/{len(r.cases)}（详细结果在 {RUN / 'result.json'}）")
    if r.broke_in:
        print(f'本脚本在 {r.broke_in} 出了错，它后面的用例没有跑。')
    return int(bool(failed))


def cases(r: Results):
    """全部用例，一个接一个：后面的用例接着用前面的留下的池。"""
    one, two, bad = Snapshot(['a']), Snapshot(['a', 'b']), Snapshot(['a', 'b', 'c'], unloadable='c')
    tuned = Snapshot(['a', 'b'], deadline=46)   # 与 two 只差 config 段里的一项

    r.case('SH-01', '用部署文件启动一个池：网关在容器里，从挂载进去的目录启动；还没有确认过的发布时，front 不开')
    staged = stage(one)
    r.check('发布前，锁定的镜像在另一个容器里加载了这份快照', staged.get('loaded'))
    one.expected = staged.get('digest')
    publish(one)   # 第一份文件由本脚本直接放进目录：这个池上还没有确认过任何发布，没有记录
    # 后端不属于部署文件，先单独起来：egress 这一步只放行它跑的时候解析得了的名字，真的池里后端早就在别处了。
    # 池启动时后端的名字还解析不了会怎样，是 SH-15。
    compose('up', '-d', 'echo')
    first = compose('up', '-d')   # 部署文件的启动命令
    if wait_for(lambda: observe()['digest'] is not None, 30) is None:
        die('30 秒内回读口没有给出运行配置：' + first.stderr.strip()[-400:] + compose('logs', '--tail', '20', 'agentgateway').stdout[-600:])
    placed, confirmed, closed = step('place'), step('confirm'), get('a.test', '/quick')
    r.note('还没有记录时 docker compose up -d：退出码，和它最后说的', [first.returncode, (first.stderr.strip().splitlines() or [''])[-1].strip()])
    r.note('还没有记录时：place 和 confirm 的退出码、结局', [outcome(placed), outcome(confirmed)])
    r.note('front 没有启动时，往业务端口发请求得到的', closed.get('error'))
    r.check('目录里还没有记录时启动（docker compose up -d）：place 没有可放的（NO_RECORD，退出码 0），网关照样从目录里的文件起来',
            outcome(placed) == (0, 'NO_RECORD') and placed['report'].get('replaced') is False and bool(container('agentgateway').get('running')))
    r.check('...confirm 没有可对的（UNCONFIRMED，退出码 3）：up 以非零码结束，front 没有启动，业务端口上没有人应答',
            outcome(confirmed) == (3, 'UNCONFIRMED') and first.returncode != 0 and container('front').get('status') == 'created'
            and closed['status'] is None)
    # SH-01 到 SH-08 由本脚本扮演发布器，不留记录，confirm 过不了：这里绕过它，直接把 front 起起来。
    opened = compose('up', '-d', '--no-deps', 'front')
    if opened.returncode != 0 or wait_for(lambda: get('a.test', '/quick')['status'] == 200, 20) is None:
        die(f'front 起不来：{opened.stderr.strip()[-600:]}')
    gateway, front, holder, seen = container('agentgateway'), container('front'), container('netns'), observe()
    r.check('四个容器都在跑：netns、agentgateway、front，和后端 echo', all(container(name).get('running') for name in (*LONG_RUNNING, 'echo')))
    r.note('三个常驻容器的镜像', {name: container(name).get('image') for name in LONG_RUNNING})
    r.check('网关容器跑的是按摘要引用的锁定镜像，它报告的版本和提交与锁定文件一致；front 和 netns 是与黑盒套件相同的那个 nginx 镜像',
            gateway.get('image') == GATEWAY_IMAGE and front.get('image') == holder.get('image') == FRONT_IMAGE
            and (seen['build'].get('version'), seen['build'].get('gitRevision')) == (LOCK['version'], LOCK['git_revision']))
    policies = {name: json.loads(docker('inspect', '-f', '{{json .HostConfig.RestartPolicy}}', container(name).get('id', '-')).stdout or '{}')
                for name in SERVICES}
    r.check('七个容器都没有重启策略：docker 自己不会去起其中任何一个',
            all(policy.get('Name') in ('no', '') and not policy.get('MaximumRetryCount') for policy in policies.values()) and len(policies) == 7)
    mounts = gateway.get('mounts') or {}
    r.note('网关容器的挂载', mounts)
    r.check('配置是整个目录挂进去的，只读；证书目录也只读',
            mounts.get('/work/config') == {'type': 'bind', 'source': str(POOL / 'config'), 'writable': False}
            and mounts.get('/work/tls') == {'type': 'bind', 'source': str(POOL / 'tls'), 'writable': False})
    r.check('发布器的证书不在网关容器拿到的目录里', not list((POOL / 'tls').glob('publisher*')))
    r.check('发布器从本机经回读口读到：配置已加载，存储模式 readOnly', seen['reload'] == LOADED and seen['storage'] == 'readOnly')
    r.check('网关报告的摘要等于发布前在另一个容器里算出的期望值', one.expected is not None and seen['digest'] == one.expected)
    # 离线加载用的是另一套证书。证书正文在 /config_dump 里，所以算摘要时要先把它换成占位。
    r.check('证书正文计入时，与离线加载的那次不同',
            seen['digest_with_certificates'] is not None and seen['digest_with_certificates'] != staged.get('digest_with_certificates'))
    r.note('config 段里，池里的网关与离线加载的那次不同的项', differing(seen['config'], staged.get('config') or {}))
    r.check('经 front 的端口，路由 a 有、路由 b 没有', routes_seen(['a', 'b']) == {'a': 200, 'b': 404})
    r.note('本机上映射出来的端口', {name: container(name).get('published') for name in LONG_RUNNING})
    r.check('本机上只映射了两个端口，都只在回环上：业务端口和回读口。占着它们的是 netns；front 和网关没有自己的端口，接在 netns 的网络命名空间里',
            holder.get('published') == {f"{PORT['front']}/tcp": [f"127.0.0.1:{HOST['front']}"],
                                        f"{PORT['readback']}/tcp": [f"127.0.0.1:{HOST['readback']}"]}
            and gateway.get('published') == {} and front.get('published') == {}
            and gateway.get('network') == front.get('network') == f"container:{holder.get('id')}")
    connect = from_another_container()
    r.note('从同一个网络上的另一个容器连各端口的结果（0 是连上了，111 是被拒绝）', connect)
    r.check('从另一个容器连不上网关收业务请求的监听、管理、指标和就绪端口（都只绑回环）',
            connect.get('callers') == connect.get('admin') == connect.get('stats') == connect.get('readiness') == 111)
    r.check('...连得上的只有 front 的端口和回读口', connect.get('front') == connect.get('readback') == 0)
    left = sorted(p.name for p in (POOL / 'config').iterdir())
    r.note('两步跑过之后配置目录里有什么', left)
    r.check('place 和 confirm 是以本机上跑脚本的这个用户的身份跑的：它们留在配置目录里的锁文件属于这个用户，只有属主能读写',
            left == ['.config.yaml.lock', 'config.yaml'] and (POOL / 'config' / '.config.yaml.lock').stat().st_uid == os.getuid()
            and stat.S_IMODE((POOL / 'config' / '.config.yaml.lock').stat().st_mode) == 0o600)
    steps = {service: container(service) for service in ('place', 'confirm')}
    r.check('place 不接任何网络，拿到的只有配置目录和发布器的二进制；发布器的证书只挂给 confirm',
            steps['place'].get('network') == 'none'
            and set(steps['place'].get('mounts') or {}) == {'/pool/config', '/usr/local/bin/gateway-control'}
            and set(steps['confirm'].get('mounts') or {}) == {'/pool/config', '/usr/local/bin/gateway-control',
                                                             '/publisher/tls.crt', '/publisher/tls.key', '/publisher/ca.crt'}
            and not any(destination.startswith('/publisher') for destination in mounts))
    twice = probe.two_hosts('127.0.0.1', 'a')
    r.check('带两个 Host 头的请求在 front 就被拒绝：400，应答的是 nginx', twice.get('status') == 400 and twice.get('server') == 'nginx')
    others = {who: read_back(HOST['readback'], '/config_dump', cert=cert)['status']
              for who, cert in (('同一个 CA 的另一个工作负载', 'business-app'), ('没有证书', None), ('另一个 CA 签的发布器证书', 'rogue-publisher'))}
    admin_only = {f'{method} {path}': read_back(HOST['readback'], path, method=method)['status']
                  for method, path in (('POST', '/quitquitquit'), ('POST', '/logging?level=debug'), ('GET', '/debug/tasks'), ('GET', '/ui'))}
    r.check('回读口不回答别的调用方', set(others.values()) == {None})
    r.check('回读口上，管理地址的其余接口一个都没有（关停、改日志级别、调试、界面）：全是 404', set(admin_only.values()) == {404})

    r.case('SH-02', '发布：把目录里的文件整份换掉，网关不重启；期间一直有流量')
    staged = stage(two)
    two.expected = staged.get('digest')
    r.check('新快照离线加载成功，期望摘要与上一份不同', staged.get('loaded') and two.expected not in (None, one.expected))
    before, traffic = container('agentgateway'), Load()
    publish(two)
    took = wait_for(lambda: observe()['digest'] == two.expected, 10)
    time.sleep(3)
    result, seen = traffic.finish(), observe()
    r.note('从改名到回读口报告新摘要过了多少秒', took)
    r.check('网关报告的摘要变成了新快照的期望值', took is not None and seen['digest'] == two.expected)
    r.check('它报告这次加载成功', seen['reload'] == LOADED)
    r.check('路由 b 生效了', routes_seen(['a', 'b']) == {'a': 200, 'b': 200})
    r.check('网关没有重启：还是那个容器、那个进程', same_process(before, container('agentgateway')))
    no_failures(r, result, '换文件期间')

    r.case('SH-03', '一份网关加载不了的快照：离线加载先拒绝；硬换上去，网关拒绝整份文件，继续用上一份')
    staged = stage(bad)
    r.note('离线加载的结果', staged)
    r.check('发布前，离线加载就拒绝了这份文件，并说出原因',
            staged.get('loaded') is False and staged.get('exit_code') not in (0, None) and bool(staged.get('said')))
    before, traffic = container('agentgateway'), Load()
    publish(bad)
    took = wait_for(lambda: (observe()['reload'] or {}).get('synchronized') is False, 10)
    time.sleep(3)   # 如果它还会做别的（退出、换上这份文件里的一部分），这时该看得见了
    seen = observe()
    r.note('从改名到网关报告加载失败过了多少秒', took)
    r.note('网关给出的原因', (seen['reload'] or {}).get('lastError'))
    r.check('网关经回读口报告这次加载失败，并给出原因', took is not None and bool((seen['reload'] or {}).get('lastError')))
    r.check('它在跑的仍是上一份：摘要没有变，原有的路由照常，被拒绝的文件里的路由 c 没有生效',
            seen['digest'] == two.expected and routes_seen(['a', 'b', 'c']) == {'a': 200, 'b': 200, 'c': 404})
    r.check('网关没有重启', same_process(before, container('agentgateway')))
    publish(two)   # 发布器把上一份放回去
    back = wait_for(lambda: (observe()['reload'] or {}).get('synchronized') is True, 10)
    time.sleep(2)
    result, seen = traffic.finish(), observe()
    r.note('把上一份放回去之后，过了多少秒报告加载成功', back)
    r.check('把上一份放回去之后，网关报告加载成功，摘要仍是那一份', back is not None and seen['reload'] == LOADED and seen['digest'] == two.expected)
    no_failures(r, result, '从硬换上去到放回去')

    r.case('SH-04', '回滚：把更早的那份快照换回去；期间一直有流量')
    before, traffic = container('agentgateway'), Load()
    publish(one)
    took = wait_for(lambda: observe()['digest'] == one.expected, 10)
    time.sleep(3)
    result, seen = traffic.finish(), observe()
    r.note('从改名到回读口报告那份快照的摘要过了多少秒', took)
    r.check('摘要回到那份快照的期望值，路由 b 没有了',
            took is not None and seen['digest'] == one.expected and seen['reload'] == LOADED and routes_seen(['a', 'b']) == {'a': 200, 'b': 404})
    r.check('网关没有重启', same_process(before, container('agentgateway')))
    no_failures(r, result, '回滚期间')

    r.case('SH-05', '对照：只挂 config.yaml 这一个文件时，整份替换到不了容器里')
    single = RUN / 'single'
    single.mkdir()
    (single / 'config.yaml').write_text(one.text, encoding='utf-8')
    started = scratch_gateway(f"{single / 'config.yaml'}:/work/config/config.yaml:ro", POOL / 'tls')
    up = wait_for(lambda: observe(HOST['scratch'])['digest'] is not None, 20)
    r.check('另起一个网关容器，只把这一个文件挂进去：起来了，摘要等于期望值',
            started.returncode == 0 and up is not None and observe(HOST['scratch'])['digest'] == one.expected)
    (single / 'config.yaml').write_text(two.text, encoding='utf-8')   # 就地改写：还是原来那个文件
    in_place = wait_for(lambda: observe(HOST['scratch'])['digest'] == two.expected, 10)
    r.note('就地改写之后过了多少秒，网关报告新摘要', in_place)
    r.check('就地改写同一个文件，容器里看得到，网关重载了', in_place is not None)
    publish(one, single)   # 发布器的做法：写临时文件再改名
    time.sleep(5)
    seen = observe(HOST['scratch'])
    r.note('改名 5 秒之后网关报告的加载结果', seen['reload'])
    r.check('写临时文件再改名：本机上的文件已经是另一份，容器里的网关还在跑原来那份',
            (single / 'config.yaml').read_text(encoding='utf-8') == one.text and seen['digest'] == two.expected)
    docker('rm', '-f', SCRATCH)

    r.case('SH-06', 'config 段的改动，换文件不生效，要重启网关；单机上重启一次是什么样')
    key = 'terminationMaxDeadline'   # /config_dump 的 config 段里，connectionTerminationDeadline 叫这个名字
    staged = stage(tuned)
    tuned.expected = staged.get('digest')
    running, wanted = observe()['config'].get(key), (staged.get('config') or {}).get(key)
    r.note(f'config 段的 {key}：池里的网关在跑的 / 这份快照离线加载时的', f'{running} / {wanted}')
    r.check('这份快照与前面那份只差 config 段里的一项：两份的期望摘要相同（摘要不含 config 段）',
            staged.get('loaded') and tuned.expected == two.expected and wanted not in (None, running))
    before, front_before = container('agentgateway'), container('front')
    publish(tuned)
    took = wait_for(lambda: observe()['digest'] == tuned.expected, 10)
    seen = observe()
    r.check('换上这份文件：路由部分生效了，网关报告加载成功', took is not None and seen['reload'] == LOADED and routes_seen(['a', 'b']) == {'a': 200, 'b': 200})
    r.check('config 段没有跟着变：网关报告的仍是启动时的值', seen['config'].get(key) == running and same_process(before, container('agentgateway')))
    restart = restart_under(Load())   # 重启时两个 2 秒的请求各还剩 1 秒左右
    seen, after = observe(), container('agentgateway')
    r.check('重启网关容器：换了一个进程，front 没有动',
            restart['restarted'] and bool(after.get('running')) and after.get('id') == before.get('id')
            and after.get('pid') != before.get('pid') and same_process(front_before, container('front')))
    r.check('重启之后 config 段是这份快照的值，摘要仍等于期望值', seen['config'].get(key) == wanted and seen['digest'] == tuned.expected)
    r.check('重启之后请求照常', seen['reload'] == LOADED and routes_seen(['a', 'b']) == {'a': 200, 'b': 200})
    r.check('重启时在途的慢请求都做完了，没有被切断',
            len(restart['in_flight']) == 2 and all(q['outcome'] == '200' for q in restart['in_flight']))
    note_restart(r, '在途的请求各还剩 1 秒左右', restart)

    r.case('SH-07', '单机上重启网关：新来的请求被拒绝多久，取决于在途的请求还要多久')
    before = container('agentgateway')
    idle = restart_under(Load(slow_workers=0))
    middle = container('agentgateway')
    r.check('没有在途的请求时重启：换了一个进程，之后请求照常',
            idle['restarted'] and bool(middle.get('running')) and middle.get('pid') != before.get('pid')
            and observe()['reload'] == LOADED and routes_seen(['a']) == {'a': 200})
    note_restart(r, '没有在途的请求', idle)
    busy = restart_under(Load(slow_seconds=6.0))   # 重启时两个 6 秒的请求各还剩 3 秒左右
    after = container('agentgateway')
    r.check('有在途的请求时重启：换了一个进程，之后请求照常',
            busy['restarted'] and bool(after.get('running')) and after.get('pid') != middle.get('pid')
            and observe()['reload'] == LOADED and routes_seen(['a']) == {'a': 200})
    r.check('重启时在途的请求（各还剩 3 秒左右）都做完了，没有被切断',
            len(busy['in_flight']) == 2 and all(q['outcome'] == '200' for q in busy['in_flight']))
    # 网关等在途的请求做完才退出，这期间它已经不接新连接：从第一个被拒绝的快请求起，到在途的请求做完之前。
    first, drained = (busy['refused'] or [{}])[0].get('at'), min((q['done'] for q in busy['in_flight']), default=None)
    waiting = [q for q in busy['quick'] if first is not None and drained is not None and first <= q['at'] <= drained - 0.3]
    r.check('在途的请求做完之前，新来的快请求全部被拒绝（不少于 30 个）', len(waiting) >= 30 and all(q['outcome'] != '200' for q in waiting))
    r.check('被拒绝的时间比没有在途请求的那次长 2 秒以上',
            len(busy['refused']) - len(idle['refused']) >= 40)   # 每秒 20 个
    note_restart(r, '在途的请求各还剩 3 秒左右', busy)

    r.case('SH-08', '网关解析配置文件之前，先拿环境变量替换正文里的 $名字')
    session_key = secrets.token_hex(32)
    written = 'x-$HOSTNAME-${NO_SUCH_VARIABLE:-fallback}-$$HOSTNAME-\\$HOSTNAME-$'
    expanding = Snapshot(['a', 'x', 'y'], names={'x': written, 'y': 'y-$SESSION_KEY'})
    work = RUN / 'expansion'
    work.mkdir()
    publish(expanding, work)
    started = scratch_gateway(f'{work}:/work/config:ro', POOL / 'tls', session_key)
    up = wait_for(lambda: observe(HOST['scratch'])['digest'] is not None, 20)
    hostname = docker('inspect', '-f', '{{.Config.Hostname}}', SCRATCH).stdout.strip()
    loaded, seen = observe(HOST['scratch']), strings_in(read_back(HOST['scratch'], '/config_dump').get('json'))
    r.check('另起一个网关容器加载一份带 $ 的文件：起来了', started.returncode == 0 and up is not None and len(hostname) >= 8)
    r.note('配置文件里写的路由名', written)
    r.note('网关报告的路由名（HOSTNAME 是容器里的一个环境变量，值是容器的主机名）', sorted(s for s in seen if s.startswith('x-')))
    r.check('$名字 换成了环境变量的值；${名字:-默认值} 在没有这个变量时换成了默认值；$$ 成了一个 $；'
            '反斜杠不起转义的作用；后面不跟名字的 $ 原样留着',
            f'x-{hostname}-fallback-$HOSTNAME-\\{hostname}-$' in seen and written not in seen)
    r.check('$SESSION_KEY 一样被换了：会话密钥进了运行配置，从回读口读得到', f'y-{session_key}' in seen)
    undefined = Snapshot(['a', 'x'], names={'x': 'x-$NO_SUCH_VARIABLE'})
    publish(undefined, work)
    failed = wait_for(lambda: (observe(HOST['scratch'])['reload'] or {}).get('synchronized') is False, 10)
    now = observe(HOST['scratch'])
    said = str((now['reload'] or {}).get('lastError'))
    r.note('引用一个没有的环境变量时，网关给出的原因', said)
    r.check('引用了一个没有的环境变量：整份文件加载失败，网关继续跑上一份',
            failed is not None and 'NO_SUCH_VARIABLE' in said and now['digest'] is not None and now['digest'] == loaded['digest'])
    docker('rm', '-f', SCRATCH)
    staged = stage(undefined)
    r.check('离线加载同样拒绝这份文件', staged.get('loaded') is False and staged.get('exit_code') not in (0, None))

    r.case('SH-09', '真的发布器（cmd/gateway-control）：发布，拒绝，没生效就把上一份放回去')
    config_file = POOL / 'config' / 'config.yaml'
    three = Snapshot(['a', 'b', 'd'], deadline=46)   # 池里的网关是带着 46 秒那一项重启的（SH-06）
    before, traffic = container('agentgateway'), Load()
    done = control(three)
    time.sleep(3)
    result, seen, report = traffic.finish(), observe(), done['report']
    r.note('发布一份新快照：发布器的输出', report)
    r.note('发布一份新快照：发布器用了多少秒（其中离线加载要另起一个容器）', done['seconds'])
    r.check('发布一份新快照：退出码 0，结局 ACTIVE', outcome(done) == (0, 'ACTIVE') and report.get('replaced') is True)
    r.check('目录里的文件就是这份快照；发布器报告的两个名字是这份和上一份文件的 SHA-256',
            on_disk() == three.text and report.get('snapshot') == three.sha256 and report.get('previous') == tuned.sha256)
    r.check('网关报告加载成功；本脚本从回读口算出的摘要，等于发布器离线加载得到的期望值，也等于它自己最后读到的',
            seen['reload'] == LOADED and seen['digest'] is not None
            and seen['digest'] == report.get('expected_digest') == (report.get('observed') or {}).get('digest'))
    r.check('新路由 d 生效了；网关没有重启',
            routes_seen(['a', 'b', 'd']) == {'a': 200, 'b': 200, 'd': 200} and same_process(before, container('agentgateway')))
    no_failures(r, result, '发布器发布期间')
    active, inode = seen['digest'], config_file.stat().st_ino

    def untouched() -> bool:
        """配置文件还是发布器上一次放的那一个（没有被重写过），网关还在跑它。"""
        now = observe()
        return config_file.stat().st_ino == inode and on_disk() == three.text and now['digest'] == active and now['reload'] == LOADED

    again = control(three)
    r.check('再发布同一份：退出码 0，ACTIVE，没有再写文件',
            outcome(again) == (0, 'ACTIVE') and again['report'].get('replaced') is False and untouched())
    refused = control(Snapshot(['a', 'b', 'c'], unloadable='c', deadline=46))
    r.note('网关加载不了的快照：发布器给出的原因', refused['report'].get('reason'))
    r.check('网关加载不了的快照：退出码 3，结局 REFUSED，原因是网关自己说的；池没有被碰过',
            outcome(refused) == (3, 'REFUSED') and 'notAFieldOfARoute' in str(refused['report'].get('reason'))
            and refused['report'].get('replaced') is False and untouched())
    referring = control(Snapshot(['a', 'b', 'x'], deadline=46, names={'x': 'x-$HOSTNAME'}))
    r.note('带环境变量的快照：发布器给出的原因', referring['report'].get('reason'))
    r.check('带环境变量的快照（见 SH-08）：退出码 3，结局 REFUSED；池没有被碰过',
            outcome(referring) == (3, 'REFUSED') and '$HOSTNAME' in str(referring['report'].get('reason'))
            and referring['report'].get('replaced') is False and untouched())
    restart = control(Snapshot(['a', 'b', 'd', 'h'], deadline=45))
    r.note('要重启才能全部生效的快照：发布器给出的原因', restart['report'].get('reason'))
    r.check('config 段与网关启动时不同的快照（见 SH-06）：退出码 3，结局 RESTART_REQUIRED，指出了不同的那一项；池没有被碰过',
            outcome(restart) == (3, 'RESTART_REQUIRED') and restart['report'].get('restart') == ['terminationMaxDeadline']
            and restart['report'].get('replaced') is False and untouched())

    lacking = Snapshot(['a', 'b', 'd', 'e'], deadline=46, root=f'tls/{ONLY_IN_STAGING}')
    before, traffic = container('agentgateway'), Load()
    done = control(lacking)
    time.sleep(3)
    result, seen, report = traffic.finish(), observe(), done['report']
    r.note('离线加载得了、池里加载不了的快照：发布器的输出', report)
    r.note('离线加载得了、池里加载不了的快照：发布器用了多少秒', done['seconds'])
    r.check('一份快照引用了只有离线加载那边才有的文件：发布器换上去了，退出码 4，结局 RESTORED',
            outcome(done) == (4, 'RESTORED') and report.get('replaced') is True and report.get('expected_digest') not in (None, '', active))
    r.check('它给的原因是池里的网关自己说的：读不到那个文件', ONLY_IN_STAGING in str(report.get('reason')))
    r.check('上一份回到了目录里；网关报告加载成功，摘要是上一份的；那份快照里的路由 e 没有生效',
            on_disk() == three.text and seen['reload'] == LOADED and seen['digest'] == active
            and (report.get('observed') or {}).get('digest') == active
            and routes_seen(['a', 'b', 'd', 'e']) == {'a': 200, 'b': 200, 'd': 200, 'e': 404})
    r.check('网关没有重启', same_process(before, container('agentgateway')))
    no_failures(r, result, '从发布器换上去到它放回去')

    stopped = control_interrupted(Snapshot(['a', 'b', 'd', 'i'], deadline=46))   # 一份没有毛病的快照
    seen, report = observe(), stopped['report']
    r.note('刚换上文件就收到 SIGTERM：发布器的退出码、结局和原因', [stopped['exit'], report.get('outcome'), report.get('reason')])
    r.note('刚换上文件就收到 SIGTERM：发布器从开始到退出用了多少秒', stopped['seconds'])
    r.check('发布器刚把文件换上去就收到 SIGTERM：它没有立刻退出，先把上一份放回去并得到确认，退出码 4，结局 RESTORED',
            stopped['signalled'] and outcome(stopped) == (4, 'RESTORED') and 'interrupted' in str(report.get('reason'))
            and on_disk() == three.text and seen['reload'] == LOADED and seen['digest'] == active
            and (report.get('observed') or {}).get('digest') == active
            and routes_seen(['a', 'b', 'd', 'i']) == {'a': 200, 'b': 200, 'd': 200, 'i': 404})

    broken = Snapshot(['a', 'b', 'c'], unloadable='c', deadline=46)
    four, five = Snapshot(['a', 'b', 'd', 'f'], deadline=46), Snapshot(['a', 'b', 'd', 'g'], deadline=46)
    publish(broken)   # 绕过发布器，往目录里放一份网关加载不了的文件
    spoiled = wait_for(lambda: (observe()['reload'] or {}).get('synchronized') is False, 10)
    unready = control(four)
    r.note('池不干净时：发布器给出的原因', unready['report'].get('reason'))
    r.check('有人绕过发布器放了一份坏文件、网关正报告加载失败时：退出码 3，结局 POOL_NOT_READY，目录里的文件它没有动',
            spoiled is not None and outcome(unready) == (3, 'POOL_NOT_READY') and unready['report'].get('replaced') is False
            and on_disk() == broken.text)
    publish(three)   # 把目录收拾好
    cleaned = wait_for(lambda: observe()['reload'] == LOADED and observe()['digest'] == active, 10)
    first, late = control_together(four, five)
    r.note('两次发布同时进行：晚到的那一次说了什么', late['stderr'])
    r.check('两次发布同时进行：先到的成功，晚到的退出码 1，什么都没做',
            cleaned is not None and outcome(first) == (0, 'ACTIVE') and late['exit'] == 1 and not late['report']
            and 'another publication' in late['stderr'] and on_disk() == four.text
            and routes_seen(['f', 'g']) == {'f': 200, 'g': 404})
    left = leftovers()
    r.note('发布器用过之后', left)
    r.check('发布器没有留下别的东西：离线加载用的容器不在了，放候选配置的目录是空的，配置目录里只有配置文件、它的锁文件和发布器的记录',
            left == CLEAN)

    r.case('SH-10', '对账（gateway-control reconcile）：池和记录对不上时，把最后一次得到确认的那一份放回去')
    gateway, kept, inode = container('agentgateway'), record(), config_file.stat().st_ino
    same = control_reconcile()
    r.note('池就是记录的样子时对账用了多少秒', same['seconds'])
    r.check('池就是记录的样子：退出码 0，结局 IN_SYNC，什么都没有写',
            outcome(same) == (0, 'IN_SYNC') and same['report'].get('replaced') is False and same['report'].get('snapshot') == four.sha256
            and config_file.stat().st_ino == inode and same_process(gateway, container('agentgateway')))
    r.note('记录里有哪些项', sorted(kept))
    r.check('记录是配置目录里的一个文件，只有属主能读写；记的是上一次成功发布的那份快照（内容整份带着）和网关当时报告的摘要、构建',
            stat.S_IMODE((POOL / 'config' / RECORD).stat().st_mode) == 0o600 and kept.get('format') == 1 and kept.get('adopted') is False
            and kept.get('snapshot') == four.sha256 and base64.b64decode(kept.get('content') or '').decode() == four.text
            and kept.get('digest') == first['report'].get('expected_digest')
            and (kept.get('version'), kept.get('revision')) == (LOCK['version'], LOCK['git_revision']))
    startup, running = kept.get('startup') or {}, observe()['config']
    r.note('会话密钥在不在网关报告的 config 段里', SESSION_KEY in json.dumps(running))
    r.check('记录里的启动设置每一项只有指纹（64 个十六进制字符）：项目就是网关 config 段里除了随环境变的两项之外的那些，会话密钥不在记录里',
            len(startup) > 20 and set(startup) == set(running) - {'dns', 'numWorkerThreads'}
            and all(isinstance(v, str) and len(v) == 64 and not v.strip('0123456789abcdef') for v in startup.values())
            and SESSION_KEY not in json.dumps(kept))

    six, seven = Snapshot(['a', 'b', 'd', 'j'], deadline=46), Snapshot(['a', 'b', 'd', 'k'], deadline=46)
    killed = control_killed(six)
    loaded = wait_for(lambda: routes_seen(['j']) == {'j': 200}, 10)
    r.check('发布器刚把一份没有毛病的快照换上去就被强行杀掉（SIGKILL）：文件留在了那里，网关加载了它，记录里仍是上一份',
            killed['killed'] and killed['exit'] == -signal.SIGKILL and on_disk() == six.text and loaded is not None
            and record().get('snapshot') == four.sha256)
    blocked = control(seven)
    r.note('没对账就发布另一份：发布器给出的原因', blocked['report'].get('reason'))
    r.check('这时发布另一份快照：退出码 3，结局 POOL_NOT_READY，说要先对账；目录里的文件它没有动',
            outcome(blocked) == (3, 'POOL_NOT_READY') and 'reconcile' in str(blocked['report'].get('reason'))
            and blocked['report'].get('replaced') is False and on_disk() == six.text)
    before, traffic = container('agentgateway'), Load()
    done = control_reconcile()
    time.sleep(3)
    result, seen, report = traffic.finish(), observe(), done['report']
    r.note('对账：发布器的输出', report)
    r.note('对账：用了多少秒', done['seconds'])
    r.check('对账：退出码 4，结局 RESTORED；记录的那一份回到了目录里，网关报告加载成功、在跑的是它，没有人确认过的那条路由没有了',
            outcome(done) == (4, 'RESTORED') and report.get('replaced') is True and report.get('restarted') is False
            and report.get('snapshot') == four.sha256 and report.get('previous') == six.sha256
            and on_disk() == four.text and seen['reload'] == LOADED and seen['digest'] == report.get('expected_digest') == kept.get('digest')
            and routes_seen(['f', 'j']) == {'f': 200, 'j': 404})
    r.check('对账没有重启网关；再对一次是 IN_SYNC', same_process(before, container('agentgateway')) and outcome(control_reconcile()) == (0, 'IN_SYNC'))
    no_failures(r, result, '对账期间')

    killed = control_killed(six)
    inode = config_file.stat().st_ino
    completed = control(six)
    r.check('同样被杀掉之后，把同一份快照再发布一次：网关确认它在生效，补记下来就算完成，退出码 0，结局 ACTIVE，文件没有再写',
            killed['killed'] and outcome(completed) == (0, 'ACTIVE') and completed['report'].get('replaced') is False
            and config_file.stat().st_ino == inode and on_disk() == six.text and record().get('snapshot') == six.sha256
            and outcome(control_reconcile()) == (0, 'IN_SYNC') and routes_seen(['j']) == {'j': 200})

    publish(broken)   # 绕过发布器，放一份网关加载不了的文件
    spoiled = wait_for(lambda: (observe()['reload'] or {}).get('synchronized') is False, 10)
    mended = control_reconcile()
    seen = observe()
    r.note('有人放了一份坏文件之后对账：发布器给出的原因', mended['report'].get('reason'))
    r.check('有人绕过发布器放了一份网关加载不了的文件：对账把记录的那一份放回去，退出码 4，RESTORED，原因里有网关自己说的话',
            spoiled is not None and outcome(mended) == (4, 'RESTORED') and 'notAFieldOfARoute' in str(mended['report'].get('reason'))
            and on_disk() == six.text and seen['reload'] == LOADED and seen['digest'] == mended['report'].get('expected_digest'))
    config_file.unlink()   # 有人把配置文件删了
    missing = wait_for(lambda: (observe()['reload'] or {}).get('synchronized') is False, 10)
    r.note('配置文件被删掉之后网关报告的', (observe()['reload'] or {}).get('lastError'))
    found = control_reconcile()
    seen = observe()
    r.check('配置文件被删掉：网关报告读不到文件，继续跑原来那份；对账把记录的那一份放回去，RESTORED；网关一直没有重启',
            missing is not None and outcome(found) == (4, 'RESTORED') and 'no configuration file' in str(found['report'].get('reason'))
            and found['report'].get('previous') == '' and on_disk() == six.text and seen['reload'] == LOADED
            and seen['digest'] == found['report'].get('expected_digest') and same_process(gateway, container('agentgateway')))

    eight = Snapshot(['a', 'b', 'd', 'l'], deadline=46)
    killed = control_killed(eight, during='staging')
    left = leftovers()
    r.note('发布器在离线加载时被强行杀掉之后留下的', left)
    r.check('发布器在离线加载时被强行杀掉：留下了临时容器和候选配置的目录；池没有被碰过，对账是 IN_SYNC',
            killed['killed'] and len(left['离线加载用的容器']) == 1 and left['放候选配置的目录'] == [f'candidate-{SCRATCH}']
            and on_disk() == six.text and outcome(control_reconcile()) == (0, 'IN_SYNC'))
    after = control(eight)
    r.check('下一次发布照常成功，留下的容器和目录被它清掉了；配置文件被删过又放回去之后，网关仍然看得到文件变了',
            outcome(after) == (0, 'ACTIVE') and after['report'].get('replaced') is True and routes_seen(['l']) == {'l': 200}
            and leftovers() == CLEAN)

    publish(broken)
    spoiled = wait_for(lambda: (observe()['reload'] or {}).get('synchronized') is False, 10)
    compose('restart', '--timeout', '60', 'agentgateway')   # 带着那份坏文件重启
    down = wait_for(lambda: container('agentgateway').get('running') is False, 20)
    r.check('有人放了一份坏文件，之后网关重启了：它起不来', spoiled is not None and down is not None and observe()['digest'] is None)
    unknown = control_reconcile('--timeout', '3s')
    r.note('网关没有在跑时对账：发布器给出的原因', unknown['report'].get('reason'))
    r.check('这时对账：记录的那一份放回去了，但读不到网关，确认不了，退出码 5，结局 UNKNOWN；对账不替人把网关起起来',
            outcome(unknown) == (5, 'UNKNOWN') and unknown['report'].get('replaced') is True and on_disk() == eight.text
            and container('agentgateway').get('running') is False)
    inode = config_file.stat().st_ino
    waited = control_reconcile('--timeout', '3s')
    r.note('文件已经是对的、只是读不到网关时对账：发布器给出的原因', waited['report'].get('reason'))
    r.check('再对一次：文件已经是对的，它不再写，只等网关到时限；仍是 UNKNOWN',
            outcome(waited) == (5, 'UNKNOWN') and waited['report'].get('replaced') is False and config_file.stat().st_ino == inode
            and 2.5 <= waited['seconds'] <= 10)
    front_before = container('front')
    started = compose('up', '-d')   # 把网关起起来：用的是部署文件的启动命令
    up = wait_for(lambda: observe()['digest'] is not None, 30)
    r.check('docker compose up -d 把网关起起来之后：它读到的是放回去的那一份，confirm 这一步是 IN_SYNC，front 没有动，请求照常',
            started.returncode == 0 and up is not None and outcome(step('confirm')) == (0, 'IN_SYNC')
            and outcome(control_reconcile()) == (0, 'IN_SYNC') and observe()['reload'] == LOADED
            and same_process(front_before, container('front')) and routes_seen(['a', 'l']) == {'a': 200, 'l': 200})

    r.case('SH-11', '带重启的发布（gateway-control restart）：先换文件，网关加载得了再重启；没有到位就放回上一份再重启一次')
    key = 'terminationMaxDeadline'
    name, front_name, echo_name = (container(service).get('name') for service in ('agentgateway', 'front', 'echo'))
    nine = Snapshot(['a', 'b', 'd', 'm'], deadline=47)
    staged = stage(nine)   # 本脚本自己离线加载一遍，拿它的 config 段和摘要来对
    before, front_before, traffic = container('agentgateway'), container('front'), Load()
    done = control_restart(nine, name)
    time.sleep(3)
    result, seen, report, after = traffic.finish(), observe(), done['report'], container('agentgateway')
    cut = outage(traffic)
    r.note('带重启的发布：发布器的输出', report)
    r.note('带重启的发布：发布器用了多少秒（离线加载，换文件之后等 1 秒，重启，重启之后再等 1 秒）', done['seconds'])
    r.check('一份 config 段与网关启动时不同的快照：退出码 0，结局 ACTIVE；换了文件，也重启了网关，指出了要改的那一项',
            outcome(done) == (0, 'ACTIVE') and report.get('replaced') is True and report.get('restarted') is True
            and report.get('restart') == [key] and report.get('snapshot') == nine.sha256 and report.get('previous') == eight.sha256)
    r.check('网关换了一个进程，还是那个容器；front 没有动',
            bool(after.get('running')) and after.get('id') == before.get('id') and after.get('pid') != before.get('pid')
            and same_process(front_before, container('front')))
    r.check('重启之后 config 段是这份快照的值，摘要等于期望值，新路由生效；记录跟上了，对账是 IN_SYNC',
            seen['config'].get(key) == (staged.get('config') or {}).get(key) == '47s' and seen['reload'] == LOADED
            and seen['digest'] == report.get('expected_digest') == staged.get('digest') and on_disk() == nine.text
            and routes_seen(['a', 'm']) == {'a': 200, 'm': 200}
            and record().get('snapshot') == nine.sha256 and outcome(control_reconcile()) == (0, 'IN_SYNC'))
    r.check('重启时在途的慢请求做完了，没有一个被切断；重启之后请求照常',
            cut['began'] is not None and len(cut['spanning']) >= 1 and not cut['cut']
            and len(cut['last']) == 20 and all(q['outcome'] == '200' for q in cut['last']))
    note_outage(r, '带重启的发布', cut, result)

    # 重启途中在终端里按 Ctrl-C；这时有一个请求还要 13 秒左右才做完。
    ten, held = Snapshot(['a', 'b', 'd', 'n'], deadline=48), {}
    pending = threading.Thread(target=lambda: held.update(long_request(front_name, 'a', 14)), daemon=True)
    before, since = container('agentgateway'), time.time()
    stopped = restart_interrupted(ten, name, 4, pending.start)
    pending.join(90)
    seen, report, after, events = observe(), stopped['report'], container('agentgateway'), docker_events(name, since)
    r.note('重启途中按 Ctrl-C：发布器的退出码、结局、从开始到退出用了多少秒', [stopped['exit'], report.get('outcome'), stopped['seconds']])
    r.note('发信号那一刻，发布器所在的进程组里有谁 / 它不在这个进程组里的子进程', [stopped['group'], stopped['elsewhere']])
    r.note('重启途中按 Ctrl-C：这期间 docker 对网关容器做过的事', events)
    r.note('重启时在途的那个 14 秒的请求', held)
    r.check('docker 的重启命令不在发布器的进程组里：在终端里按 Ctrl-C，信号到不了它',
            stopped['signalled'] and stopped['group'] == ['gateway-control'] and stopped['elsewhere'] == ['docker restart'])
    r.check('重启已经开始之后收到 SIGINT：发布器做完才退出，退出码 0，结局 ACTIVE；网关只重启了一次',
            outcome(stopped) == (0, 'ACTIVE') and report.get('restarted') is True and events.count('restart') == 1
            and seen['config'].get(key) == '48s' and after.get('pid') != before.get('pid') and on_disk() == ten.text
            and record().get('snapshot') == ten.sha256)
    r.check('重启时还要 13 秒左右才做完的那个请求做完了：docker 等的是容器自己设的停止时限（60 秒），不是它默认的 10 秒，没有去强杀',
            held.get('status') == '200' and held.get('seconds', 0) >= 14 and stopped['seconds'] >= 14 and 'kill 9' not in events)

    before = container('agentgateway')
    needless = control_restart(Snapshot(['a', 'b', 'd', 'o'], deadline=48), name)
    r.note('用不着重启的快照：发布器给出的原因', needless['report'].get('reason'))
    r.check('config 段与网关启动时相同的快照：退出码 3，结局 REFUSED，让改用 publish；池没有被碰过',
            outcome(needless) == (3, 'REFUSED') and 'publish it instead' in str(needless['report'].get('reason'))
            and needless['report'].get('replaced') is False and needless['report'].get('restarted') is False and on_disk() == ten.text)
    lacking = control_restart(Snapshot(['a', 'b', 'd', 'p'], deadline=49, root=f'tls/{ONLY_IN_STAGING}'), name)
    seen = observe()
    r.check('要重启、池里的网关却加载不了的快照：重启之前就发现了，上一份放回去，退出码 4，结局 RESTORED',
            outcome(lacking) == (4, 'RESTORED') and lacking['report'].get('replaced') is True and lacking['report'].get('restarted') is False
            and ONLY_IN_STAGING in str(lacking['report'].get('reason')) and on_disk() == ten.text and seen['reload'] == LOADED
            and seen['digest'] == (lacking['report'].get('observed') or {}).get('digest'))
    echo_before = container('echo')
    wrong = control_restart(Snapshot(['a', 'b', 'd', 'q'], deadline=49), echo_name)
    r.note('让它重启别的容器：它说了什么', wrong['stderr'])
    r.check('--container 指的不是这个池的网关（这里指的是 echo）：退出码 1，什么都没做',
            wrong['exit'] == 1 and not wrong['report'] and 'not the gateway of this pool' in wrong['stderr'] and on_disk() == ten.text
            and same_process(echo_before, container('echo')))
    r.check('上面三次网关都没有重启', same_process(before, container('agentgateway')))

    thirteen = Snapshot(['a', 'b', 'd', 'r'], deadline=49)
    killed = restart_killed(thirteen, name)
    settled = wait_for(lambda: observe()['config'].get(key) == '49s', 20)
    r.check('docker 刚把网关重新起来，发布器就被强行杀掉：文件是新的，网关已经带着新设置起来，记录里仍是上一份',
            killed['killed'] and settled is not None and on_disk() == thirteen.text and record().get('snapshot') == ten.sha256)
    half = control_reconcile()
    seen = observe()
    r.note('带重启的发布做到一半之后对账：发布器的输出', half['report'])
    r.check('对账：记录的那一份放回去了，路由回到了那一份；启动设置还差一次重启，退出码 6，结局 RESTART_PENDING，指出了那一项',
            outcome(half) == (6, 'RESTART_PENDING') and half['report'].get('replaced') is True and half['report'].get('restarted') is False
            and half['report'].get('restart') == [key] and on_disk() == ten.text and seen['digest'] == half['report'].get('expected_digest')
            and seen['config'].get(key) == '49s' and routes_seen(['n', 'r']) == {'n': 200, 'r': 404})
    again = control_restart(None, name)
    seen = observe()
    r.check('restart 不给快照：用记录里的那一份重启，文件不用再换；退出码 0，结局 ACTIVE，启动设置回来了，之后对账是 IN_SYNC',
            outcome(again) == (0, 'ACTIVE') and again['report'].get('replaced') is False and again['report'].get('restarted') is True
            and again['report'].get('snapshot') == ten.sha256 and seen['config'].get(key) == '48s' and on_disk() == ten.text
            and outcome(control_reconcile()) == (0, 'IN_SYNC'))

    # 指标端口撞上 front 的端口：离线加载的那个容器里没有 front，加载得了；池里的网关拿它启动却起不来。
    clash = Snapshot(['a', 'b', 'd', 's'], deadline=48, stats=PORT['front'])
    before, stats, since = container('agentgateway'), observe()['config'].get('statsAddr'), time.time()
    rolled = control_restart(clash, name, '--timeout', '5s')
    seen, after, events = observe(), container('agentgateway'), docker_events(name, since)
    r.note('重启之后网关起不来：发布器的输出', rolled['report'])
    r.note('重启之后网关起不来：发布器用了多少秒（等网关的时限设成了 5 秒）', rolled['seconds'])
    r.note('重启之后网关起不来：网关自己说的', gateway_said(name, since))
    r.note('重启之后网关起不来：这期间 docker 对网关容器做过的事', events)
    r.check('一份离线加载得了、池里的网关拿它却起不来的快照：重启之后读不到网关，发布器把上一份放回去再重启一次，退出码 4，结局 RESTORED',
            outcome(rolled) == (4, 'RESTORED') and rolled['report'].get('replaced') is True and rolled['report'].get('restarted') is True
            and rolled['report'].get('restart') == ['statsAddr'] and events.count('restart') == 2)
    r.check('网关回来了：在跑的是上一份，启动设置也是上一份的；对账是 IN_SYNC，请求照常',
            bool(after.get('running')) and after.get('pid') != before.get('pid') and on_disk() == ten.text and seen['reload'] == LOADED
            and seen['digest'] == (rolled['report'].get('observed') or {}).get('digest') and seen['config'].get(key) == '48s'
            and stats is not None and seen['config'].get('statsAddr') == stats
            and routes_seen(['n', 's']) == {'n': 200, 's': 404} and outcome(control_reconcile()) == (0, 'IN_SYNC'))
    left = leftovers()
    r.note('三条命令都用过之后', left)
    r.check('三条命令都用过之后没有留下别的东西', left == CLEAN)

    r.case('SH-12', '断电之后再启动：网关启动之前先把记录的那一份放到位（place），回读对上了（confirm）才开 front')
    kept, record_file = record(), POOL / 'config' / RECORD
    before, inode = {service: container(service) for service in LONG_RUNNING}, config_file.stat().st_ino
    ran = {service: container(service).get('started') for service in ('place', 'confirm')}
    again = compose('up', '-d')
    placed, confirmed = step('place'), step('confirm')
    r.check('池好好的时候再跑一次启动命令（docker compose up -d）：退出码 0；place 和 confirm 各又跑了一遍（IN_PLACE，IN_SYNC），'
            '什么都没有写；三个常驻容器没有动',
            again.returncode == 0 and outcome(placed) == (0, 'IN_PLACE') and placed['report'].get('replaced') is False
            and outcome(confirmed) == (0, 'IN_SYNC') and confirmed['report'].get('replaced') is False
            and all(container(service).get('started') not in (None, ran[service]) for service in ran)
            and config_file.stat().st_ino == inode and all(same_process(before[service], container(service)) for service in LONG_RUNNING))
    r.check('place 说的那一份和期望摘要都是记录里的；它没有去读网关',
            placed['report'].get('snapshot') == ten.sha256 == kept.get('snapshot')
            and placed['report'].get('expected_digest') == kept.get('digest') and placed['report'].get('observed') is None)

    cut = power_cut()
    time.sleep(2)   # docker 要是会自己把谁起起来，这时该看得见了
    r.check('断电（三个常驻容器同时被强行杀掉）：没有哪一个自己起来；业务端口和回读口上都没有人应答',
            cut and not any(container(service).get('running') for service in LONG_RUNNING)
            and get('a.test', '/quick')['status'] is None and observe()['digest'] is None)
    seen = boot(('n',))
    now = observe()
    r.note('断电之后再启动：各件事发生的时刻（相对于启动命令开始的秒数）', timeline(seen))
    r.note('断电之后再启动：这期间发往业务端口的请求各得到什么（None 是没有得到应答）', seen['answers'])
    r.check('断电之后再启动（docker compose up -d，开机时那个单元跑的就是它）：退出码 0；放在那里的就是记录的那一份，'
            'place 什么都没有写（IN_PLACE）；confirm 是 IN_SYNC',
            seen['exit'] == 0 and outcome(seen['place']) == (0, 'IN_PLACE') and seen['place']['report'].get('replaced') is False
            and outcome(seen['confirm']) == (0, 'IN_SYNC') and seen['confirm']['report'].get('replaced') is False)
    r.check('先后是：place 跑完，网关才启动；网关启动了，confirm 才跑；confirm 跑完，front 才启动', in_order(seen))
    r.check('confirm 跑完之前，发往业务端口的请求没有一个得到应答（这期间发了不少于 10 个）；之后请求照常', gated(seen, 'n'))
    r.check('网关在跑的是记录的那一份，启动设置也是那一份的；本机上的发布器来对账是 IN_SYNC',
            now['reload'] == LOADED and now['digest'] == kept.get('digest') and now['config'].get(key) == '48s' and on_disk() == ten.text
            and outcome(control_reconcile()) == (0, 'IN_SYNC') and routes_seen(['a', 'n']) == {'a': 200, 'n': 200})

    unconfirmed = Snapshot(['a', 'b', 'd', 'n', 't'], deadline=48)   # 一份没有毛病的快照，只是没有人确认过

    def left_by_a_killed_publisher() -> bool:
        return control_killed(unconfirmed)['killed'] and wait_for(lambda: routes_seen(['t']) == {'t': 200}, 10) is not None

    def unloadable_file() -> bool:
        publish(broken)
        return wait_for(lambda: (observe()['reload'] or {}).get('synchronized') is False, 10) is not None

    def file_deleted() -> bool:
        config_file.unlink()
        return wait_for(lambda: (observe()['reload'] or {}).get('synchronized') is False, 10) is not None

    for what, spoil, previous, says in (
            ('发布器刚把一份快照换上去就被强行杀掉，网关已经在跑这一份', left_by_a_killed_publisher, unconfirmed.sha256,
             'was not the snapshot last confirmed'),
            ('有人绕过发布器放了一份网关加载不了的文件', unloadable_file, broken.sha256, 'was not the snapshot last confirmed'),
            ('配置文件被删掉了', file_deleted, '', 'there was no configuration file in place')):
        spoiled, cut = spoil(), power_cut()
        seen = boot(('n', 't'))
        now, report = observe(), seen['place']['report']
        r.note(f'{what}，然后断电，再启动：各件事发生的时刻（相对于启动命令开始的秒数）', timeline(seen))
        r.note(f'{what}，然后断电，再启动：place 给出的原因', report.get('reason'))
        r.note(f'{what}，然后断电，再启动：这期间发往业务端口的请求各得到什么', seen['answers'])
        r.check(f'{what}，然后断电。再启动：place 把记录的那一份放回去了（IN_PLACE，写了文件），说了原来放着的是什么',
                spoiled and cut and seen['exit'] == 0 and outcome(seen['place']) == (0, 'IN_PLACE') and report.get('replaced') is True
                and report.get('snapshot') == ten.sha256 and report.get('previous') == previous and says in str(report.get('reason'))
                and on_disk() == ten.text)
        r.check(f'{what}，然后断电。再启动：网关是带着记录的那一份起来的，confirm 是 IN_SYNC，没有再写；先后没有乱，'
                'confirm 跑完之前没有请求得到应答',
                outcome(seen['confirm']) == (0, 'IN_SYNC') and seen['confirm']['report'].get('replaced') is False
                and in_order(seen) and gated(seen, 'n') and now['reload'] == LOADED and now['digest'] == kept.get('digest'))
        r.check(f'{what}，然后断电。再启动：不在记录里的路由 t，启动期间和之后一次都没有应答过 200',
                '200' not in seen['answers']['t'] and seen['answers']['t'].get('404', 0) >= 1
                and routes_seen(['n', 't']) == {'n': 200, 't': 404})

    r.case('SH-13', '启动时对不上：记录坏了，网关就不启动；读不到网关，front 就不开')
    whole = record_file.read_bytes()
    record_file.write_bytes(whole[:len(whole) // 2])   # 记录只剩前一半
    cut = power_cut()
    at = {service: container(service).get('started') for service in SERVICES}
    failed = compose('up', '-d')
    placed = step('place')
    r.note('记录坏了时启动：docker compose up -d 的退出码，和它最后说的', [failed.returncode, (failed.stderr.strip().splitlines() or [''])[-1].strip()])
    r.note('记录坏了时启动：place 说了什么', placed['stderr'])
    r.check('记录读不成样子时启动：place 以退出码 1 结束，说记录坏了，什么都没有写；up 以非零码结束',
            cut and failed.returncode != 0 and placed['exit'] == 1 and not placed['report'] and 'is damaged' in placed['stderr']
            and on_disk() == ten.text and record_file.read_bytes() == whole[:len(whole) // 2])
    r.check('记录读不成样子时启动：网关没有启动，confirm 没有跑，front 没有启动；业务端口和回读口上都没有人应答',
            all(container(service).get('started') == at[service] for service in ('agentgateway', 'confirm', 'front'))
            and not container('agentgateway').get('running') and not container('front').get('running')
            and get('a.test', '/quick')['status'] is None and observe()['digest'] is None)
    record_file.write_bytes(whole)
    seen = boot(('n',))
    r.check('把记录修好之后再跑启动命令：退出码 0，先后没有乱，confirm 跑完之前没有请求得到应答，之后请求照常',
            seen['exit'] == 0 and outcome(seen['place']) == (0, 'IN_PLACE') and outcome(seen['confirm']) == (0, 'IN_SYNC')
            and in_order(seen, holder_was_up=True) and gated(seen, 'n'))

    readback_key = POOL / 'tls' / 'gateway-readback.key'
    key_bytes, key_mode = readback_key.read_bytes(), stat.S_IMODE(readback_key.stat().st_mode)
    cut = power_cut()
    readback_key.unlink()   # 网关回读口的私钥不见了：它读不成自己的配置，起不来
    at, since, began = container('front').get('started'), time.time(), time.monotonic()
    failed = compose('up', '-d')
    took = round(time.monotonic() - began, 1)
    placed, confirmed, gateway = step('place'), step('confirm'), container('agentgateway')
    r.note(f'网关起不来时启动：docker compose up -d 的退出码、它最后说的、用了多少秒（confirm 等网关的时限在这里设成了 {CONFIRM_SECONDS} 秒）',
           [failed.returncode, (failed.stderr.strip().splitlines() or [''])[-1].strip(), took])
    r.note('网关起不来时启动：网关自己说的', gateway_said(gateway.get('name', '-'), since))
    r.note('网关起不来时启动：confirm 给出的原因', confirmed['report'].get('reason'))
    r.check('网关起不来时启动（它回读口的私钥不见了）：place 照常（IN_PLACE）；网关启动了，又退出了',
            cut and outcome(placed) == (0, 'IN_PLACE') and gateway.get('running') is False and gateway.get('exit') not in (0, None)
            and moment(gateway.get('started') or '') >= since)
    r.check('网关起不来时启动：confirm 等到时限也读不到网关，退出码 5，结局 UNKNOWN，什么都没有写；up 以非零码结束，'
            'front 没有启动，业务端口上没有人应答',
            outcome(confirmed) == (5, 'UNKNOWN') and confirmed['report'].get('replaced') is False
            and 'could not be read' in str(confirmed['report'].get('reason')) and failed.returncode != 0 and took >= CONFIRM_SECONDS
            and container('front').get('started') == at and not container('front').get('running')
            and get('a.test', '/quick')['status'] is None)
    readback_key.write_bytes(key_bytes)
    os.chmod(readback_key, key_mode)
    seen = boot(('n',))
    r.check('把私钥放回去之后再跑启动命令：网关起来了，confirm 是 IN_SYNC，front 才启动，请求照常',
            seen['exit'] == 0 and outcome(seen['confirm']) == (0, 'IN_SYNC') and in_order(seen, holder_was_up=True) and gated(seen, 'n'))

    before, ran = {service: container(service) for service in LONG_RUNNING}, container('confirm').get('started')
    with open(POOL / 'config' / '.config.yaml.lock', 'r+b') as held_lock:
        try:
            fcntl.flock(held_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)   # 发布器做一次发布，从头到尾就是这样占着它
            free = True
        except BlockingIOError:   # 上一条启动命令已经回来了，它的 place 或 confirm 却还在跑，占着锁
            free = False
        busy = compose('up', '-d')
    placed = step('place')
    r.note('一次发布正在进行时跑启动命令：place 说了什么', placed['stderr'])
    r.check('上一条启动命令回来的时候，配置目录的锁是空着的：它的 place 和 confirm 都已经跑完了', free)
    r.check('一次发布正在进行（配置目录的锁被占着）时跑启动命令：place 以退出码 1 结束，说有发布正在进行；up 以非零码结束，'
            'confirm 没有跑，三个常驻容器没有动',
            free and busy.returncode != 0 and placed['exit'] == 1 and 'another publication' in placed['stderr']
            and container('confirm').get('started') == ran and on_disk() == ten.text
            and all(same_process(before[service], container(service)) for service in LONG_RUNNING))
    r.check('锁放开之后再跑启动命令：退出码 0，confirm 是 IN_SYNC',
            compose('up', '-d').returncode == 0 and outcome(step('confirm')) == (0, 'IN_SYNC'))

    before = {service: container(service) for service in LONG_RUNNING}
    docker('kill', before['netns'].get('name', '-'))
    time.sleep(1)
    r.check('netns 这个容器单独死了：网关和 front 还在跑，但业务端口和回读口上都没有人应答了',
            {service: bool(container(service).get('running')) for service in LONG_RUNNING} == {'netns': False, 'agentgateway': True, 'front': True}
            and get('a.test', '/quick')['status'] is None and observe()['digest'] is None)
    began = time.monotonic()
    failed = compose('up', '-d')
    took = round(time.monotonic() - began, 1)
    confirmed = step('confirm')
    r.note('netns 单独死了之后跑启动命令：退出码、它最后说的、用了多少秒', [failed.returncode, (failed.stderr.strip().splitlines() or [''])[-1].strip(), took])
    r.note('netns 单独死了之后跑启动命令：confirm 给出的原因', confirmed['report'].get('reason'))
    r.check('这时只跑启动命令修不好：netns 重新起来了，网关和 front 没有被动过，confirm 读不到网关（UNKNOWN），up 以非零码结束；'
            '业务端口和回读口上仍然没有人应答',
            failed.returncode != 0 and bool(container('netns').get('running'))
            and container('netns').get('started') != before['netns'].get('started')
            and all(same_process(before[service], container(service)) for service in ('agentgateway', 'front'))
            and outcome(confirmed) == (5, 'UNKNOWN') and get('a.test', '/quick')['status'] is None and observe()['digest'] is None)
    stopped = compose('stop', *SERVICES)
    seen = boot(('n',))
    r.check('先停（docker compose stop）再跑启动命令：整个池重新起来，先后没有乱，请求照常',
            stopped.returncode == 0 and seen['exit'] == 0 and outcome(seen['confirm']) == (0, 'IN_SYNC') and in_order(seen) and gated(seen, 'n'))

    r.case('SH-14', '部署文件的其余部分：在跑着的池上跑启动命令就是对一次账；单独重启 front；停；头一次安装')
    stray = Snapshot(['a', 'b', 'd', 'n', 'u'], deadline=48)
    killed = control_killed(stray)
    loaded = wait_for(lambda: routes_seen(['u']) == {'u': 200}, 10)
    before = {service: container(service) for service in LONG_RUNNING}
    first = compose('up', '-d')
    placed, confirmed, now = step('place'), step('confirm'), observe()
    r.note('池在跑着、放着的不是记录的那一份时跑启动命令：up 的退出码，place 和 confirm 的退出码、结局',
           [first.returncode, outcome(placed), outcome(confirmed)])
    r.check('池在跑着，发布器刚把一份快照换上去就被强行杀掉，网关在跑那一份。这时跑启动命令：place 把记录的那一份放回去（IN_PLACE，写了文件）',
            killed['killed'] and loaded is not None and outcome(placed) == (0, 'IN_PLACE') and placed['report'].get('replaced') is True
            and placed['report'].get('previous') == stray.sha256 and on_disk() == ten.text)
    # 网关看到文件变了要重新加载，confirm 紧跟着就去读。它读到的多半已经是记录的那一份（IN_SYNC）；要是赶在重新加载之前，
    # 它会自己再放一次、等到网关确认（RESTORED，退出码 4，这一次 up 以非零码结束）。两种都对。
    r.check('...confirm 是 IN_SYNC（退出码 0），或者 RESTORED（退出码 4：它赶在网关重新加载之前读到了旧的，自己又放了一次并等到了确认）；'
            'up 的退出码是零还是非零与它一致',
            outcome(confirmed) in ((0, 'IN_SYNC'), (4, 'RESTORED')) and (first.returncode == 0) == (confirmed['exit'] == 0))
    r.check('...网关在跑的是记录的那一份，没有人确认过的那条路由没有了；三个常驻容器都没有重启；再跑一次启动命令，退出码 0，confirm 是 IN_SYNC',
            now['reload'] == LOADED and now['digest'] == kept.get('digest') and routes_seen(['n', 'u']) == {'n': 200, 'u': 404}
            and all(same_process(before[service], container(service)) for service in LONG_RUNNING)
            and compose('up', '-d').returncode == 0 and outcome(step('confirm')) == (0, 'IN_SYNC'))

    before = {service: container(service) for service in LONG_RUNNING}
    again = compose('restart', 'front')
    back, after = wait_for(lambda: get('a.test', '/quick')['status'] == 200, 10), container('front')
    r.check('单独重启 front（docker compose restart front）：front 换了一个进程，网关和 netns 没有动，请求照常',
            again.returncode == 0 and back is not None and bool(after.get('running')) and after.get('id') == before['front'].get('id')
            and after.get('pid') != before['front'].get('pid')
            and all(same_process(before[service], container(service)) for service in ('netns', 'agentgateway')))

    held = {}

    def in_flight():
        began = time.monotonic()
        held.update(get('a.test', '/sleep/4', 30))
        held['seconds'] = round(time.monotonic() - began, 2)

    pending = threading.Thread(target=in_flight, daemon=True)
    pending.start()
    time.sleep(1)
    since, began = time.time(), time.monotonic()
    stopped = compose('stop', *SERVICES)   # 只点部署文件里的七个：后端 echo 是这套用例自己加的，不跟着停
    took = round(time.monotonic() - began, 2)
    pending.join(40)
    events, after = pool_events(since), {service: container(service) for service in LONG_RUNNING}
    r.note('停的时候 docker 给各容器发的信号和它们的退出，按先后', events)
    r.note('停的时候在途的那个 4 秒的请求', held)
    r.note('docker compose stop 用了多少秒', took)
    r.check('停（docker compose stop）的时候有一个请求在途，还要 3 秒左右才做完：它做完了，得到 200',
            stopped.returncode == 0 and held.get('status') == 200 and held.get('seconds', 0) >= 4)
    r.check('停的先后：front 先收到 SIGQUIT，把在途的请求做完才退出；然后网关收到 SIGTERM，退出；最后是 netns',
            events == ['kill front 3', 'die front', 'kill agentgateway 15', 'die agentgateway', 'kill netns 9', 'die netns'])
    r.check('三个常驻容器都停了，front 和网关是自己退出的（退出码 0）；业务端口上没有人应答',
            not any(c.get('running') for c in after.values()) and after['front'].get('exit') == 0
            and after['agentgateway'].get('exit') == 0 and get('a.test', '/quick')['status'] is None)
    seen = boot(('n',))
    r.check('停了之后再跑启动命令：整个池重新起来，先后没有乱，请求照常',
            seen['exit'] == 0 and outcome(seen['place']) == (0, 'IN_PLACE') and outcome(seen['confirm']) == (0, 'IN_SYNC')
            and in_order(seen) and gated(seen, 'n'))

    # 头一次安装，照 deploy/compose/README.md 的步骤。先把这个池整个拆掉：容器都删了，配置目录是空的。
    fresh = Snapshot(['a', 'v'])
    removed = compose('down', '--timeout', '2')
    shutil.rmtree(POOL / 'config')
    (POOL / 'config').mkdir()
    gone = not any(container(service) for service in (*SERVICES, 'echo'))
    compose('up', '-d', 'echo')   # 后端不属于部署文件，先单独起来
    config_file.write_text(fresh.text, encoding='utf-8')   # 一、把第一份快照放进配置目录
    os.chmod(config_file, 0o644)
    first = compose('up', '-d', 'agentgateway')            # 二、只把网关起起来
    up = wait_for(lambda: observe()['digest'] is not None, 30)
    placed = step('place')
    r.check('一个全新的池（容器都删了，配置目录是空的）。放进第一份快照，docker compose up -d agentgateway：退出码 0；place 没有可放的（NO_RECORD），'
            '网关起来了；confirm 和 front 的容器还没有，业务端口上没有人应答',
            removed.returncode == 0 and gone and first.returncode == 0 and up is not None and outcome(placed) == (0, 'NO_RECORD')
            and container('confirm') == {} and container('front') == {} and get('a.test', '/quick')['status'] is None)
    done = control(fresh)                                  # 三、用发布器把同一份快照发布一次
    installed = record()
    r.check('用发布器把同一份快照发布一次：退出码 0，ACTIVE，文件没有再写；这个池有了第一条记录，记的是这一份，带着启动设置',
            outcome(done) == (0, 'ACTIVE') and done['report'].get('replaced') is False and installed.get('snapshot') == fresh.sha256
            and installed.get('adopted') is False and bool(installed.get('startup')) and on_disk() == fresh.text)
    seen = boot(('a',))                                    # 四、docker compose up -d
    r.check('再跑 docker compose up -d：退出码 0，place 是 IN_PLACE，confirm 是 IN_SYNC；confirm 跑完，front 才启动，请求照常',
            seen['exit'] == 0 and outcome(seen['place']) == (0, 'IN_PLACE') and outcome(seen['confirm']) == (0, 'IN_SYNC')
            and 0 < seen['confirm']['finished'] <= seen['started']['front'] and gated(seen, 'a')
            and routes_seen(['a', 'v', 'n']) == {'a': 200, 'v': 200, 'n': 404})
    left = leftovers()
    r.note('四条命令都用过之后', left)
    r.check('四条命令都用过之后没有留下别的东西', left == CLEAN)

    r.case('SH-15', '后端的名字在网关第一次用到它时还解析不了：那条路由一直答 503，名字解析得了之后也不恢复，重启网关才好')
    compose('stop', 'echo')              # 后端不在了：它的名字在这个 compose 网络里也就解析不了了
    compose('restart', 'agentgateway')   # 一个刚启动的网关：它还没有解析过哪个后端的名字
    up = wait_for(lambda: observe()['digest'] is not None, 30)
    absent = get('a.test', '/quick')
    r.note('后端的名字解析不了时网关的应答', [absent.get('status'), absent.get('body')])
    r.check('后端的名字解析不了时，网关答 503，说名字解析失败',
            up is not None and not backend_reachable() and absent['status'] == 503 and 'dns' in str(absent.get('body')).lower())
    compose('start', 'echo')
    back = wait_for(backend_reachable, 20, every=0.5)
    time.sleep(20)
    still = get('a.test', '/quick')
    r.note('后端起来 20 秒之后网关的应答', [still.get('status'), still.get('body')])
    r.check('后端起来了：从网关所在的网络命名空间里按名字连得上它。20 秒之后，网关对这条路由仍然答 503，说名字解析失败',
            back is not None and backend_reachable() and still['status'] == 503 and 'dns' in str(still.get('body')).lower())
    compose('restart', 'agentgateway')
    healed = wait_for(lambda: get('a.test', '/quick')['status'] == 200, 20)
    r.note('重启网关之后过了多少秒请求得到 200', healed)
    r.check('重启网关之后，请求照常', healed is not None)
    compose('stop', 'echo')
    compose('restart', 'agentgateway')
    up = wait_for(lambda: observe()['digest'] is not None, 30)
    compose('start', 'echo')
    back = wait_for(backend_reachable, 20, every=0.5)
    asked = get('a.test', '/quick')
    r.check('对照：网关启动时后端的名字解析不了，但在第一个请求到来之前它解析得了了。这个请求得到 200：网关是第一次用到这个名字时才去解析的',
            up is not None and back is not None and asked['status'] == 200)

    egress_cases(r)
    keeper_cases(r, fresh)


def egress_cases(r: Results):
    """出口的规则（SH-22）。开始时池好好地在跑，后端也在；结束时也是：三个常驻容器都在，账对得上。
    最后一段让 egress 这一步失败一次，看网关不启动；原因去掉之后池又是完整的，keeper_cases 接着用它。"""
    r.case('SH-22', '出口的规则：从网关所在的网络命名空间往外，只连得上配置里写着的地址；断电之后再启动，规则先于网关装好；egress 这一步失败，网关不启动')
    echo_ip = docker('inspect', '-f', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', container('echo').get('id', '-')).stdout.strip()
    capabilities = {service: docker('inspect', '-f', '{{json .HostConfig.CapAdd}} {{json .HostConfig.CapDrop}} {{.Config.User}}',
                                    container(service).get('id', '-')).stdout.split() for service in EGRESS}
    ran, watcher = container('egress'), container('egress-watch')
    r.note('装规则的两个容器多出来的 capability、去掉的 capability、身份', capabilities)
    r.check('egress 这一步已经以退出码 0 跑完，egress-watch 在跑；两个都是 root，除了 NET_ADMIN 没有别的 capability',
            ran.get('running') is False and ran.get('exit') == 0 and bool(watcher.get('running'))
            and all(found == ['["CAP_NET_ADMIN"]', '["ALL"]', '0:0'] for found in capabilities.values()))   # docker 报告时带 CAP_ 前缀

    backend, callers, admin = f'{echo_ip}:{ECHO_PORT}', f"127.0.0.1:{PORT['callers']}", f"127.0.0.1:{PORT['admin']}"
    refused = [f'{echo_ip}:{ECHO_PORT + 1}', f"127.0.0.1:{PORT['stats']}", '192.0.2.1:443']   # 最后一个是文档用的地址段，没有人在那里
    six = f"[::1]:{PORT['stats']}"
    seen = from_the_pool(CONNECT, backend, callers, admin, *refused, six)
    held = pinned()
    r.note('从池的网络命名空间里 connect 的结果（0 连上了，113 和 13 是被规则拒绝，111 是对方拒绝）', seen)
    r.note('规则里钉着的', held)
    r.check('钉着的是配置里写着的两处：后端的名字（钉在它的地址上）和回读路由转给的管理地址',
            held == {f'echo:{ECHO_PORT}': [echo_ip], admin: ['127.0.0.1']})
    r.check('后端的名字解析得了，后端连得上；回环上，front 转给网关的那个端口和配置里写着的管理地址连得上',
            seen.get('echo') == echo_ip and [seen.get(target) for target in (backend, callers, admin)] == [0, 0, 0])
    r.check('后端那个地址的另一个端口、回环上网关的指标端口（它在听，但配置里没有写它）、一个不相干的地址：都被规则拒绝；IPv6 的回环也是',
            [seen.get(target) for target in refused] == [REFUSED_HERE] * 3 and seen.get(six) == REFUSED_HERE_V6)
    counted = from_the_pool(HAMMER, echo_ip, str(ECHO_PORT + 1), '8')
    r.note('egress-watch 每两秒重写一遍规则的 8 秒里，连后端那个地址的另一个端口，各种结果的次数', counted)
    r.check('这 8 秒里连了不少于 500 次，每一次都被规则拒绝：规则被重写的时候没有空档',
            sum(counted.values()) >= 500 and set(counted) == {str(REFUSED_HERE)})

    forgot = compose('run', '--rm', '--no-deps', 'egress', 'forget')
    r.note('docker compose run --rm --no-deps egress forget 说了什么', forgot.stdout.strip().splitlines())
    r.check('部署说明里写的那条重新解析的命令（docker compose run --rm --no-deps egress forget）：退出码 0，两处都重新钉过，'
            '钉着的没有变，请求照常',
            forgot.returncode == 0 and f'pinned echo:{ECHO_PORT} -> {echo_ip}' in forgot.stdout and pinned() == held
            and get('a.test', '/quick')['status'] == 200)

    cut = power_cut()   # netns 没了，它的网络命名空间连同里面的规则也就没了
    died = wait_for(lambda: not container('egress-watch').get('running'), 5)
    dead, since = container('egress-watch'), time.time()
    up = compose('up', '-d')
    back = wait_for(lambda: get('a.test', '/quick')['status'] == 200, 30)
    ran, watcher, gateway, holder = (container(service) for service in ('egress', 'egress-watch', 'agentgateway', 'netns'))
    r.note('断电之后 egress-watch 过了多少秒停的，它的退出码', [died, dead.get('exit')])
    r.check('断电（三个常驻容器被强行杀掉）：egress-watch 跟着 netns 死了，没有留在已经没用的那个命名空间里；退出码 137，是随 netns 的 PID 命名空间被内核杀掉的，不是脚本自己退出的', cut and died is not None and dead.get('exit') == 137)
    r.check('再跑启动命令：退出码 0；egress 这一步在这次启动里重新跑了，在网关启动之前以 0 跑完；egress-watch 是在新的 netns 之后起来的；请求照常',
            up.returncode == 0 and back is not None and ran.get('exit') == 0
            and since <= moment(ran.get('started') or '') <= moment(ran.get('finished') or '') <= moment(gateway.get('started') or '')
            and bool(watcher.get('running')) and moment(watcher.get('started') or '') >= moment(holder.get('started') or '') >= since)
    seen = from_the_pool(CONNECT, backend, refused[0], refused[1])
    r.note('再启动之后从新的网络命名空间里 connect 的结果', seen)
    r.check('新的网络命名空间里规则在：后端连得上，它的另一个端口和网关的指标端口被拒绝；钉着的还是那两处',
            seen.get(backend) == 0 and [seen.get(target) for target in refused[:2]] == [REFUSED_HERE] * 2
            and pinned() == held and outcome(step('confirm')) == (0, 'IN_SYNC'))

    # egress 这一步失败，网关就不启动：compose.yml 里 agentgateway 等 egress 以退出码 0 跑完（service_completed_successfully）。
    # 让它失败的办法，是运维真会碰到的一种：egress 是 root，除了 NET_ADMIN 没有别的 capability（上面查过），读配置靠的是
    # 文件对所有人可读；配置文件改成 0600（属主是跑这套用例的用户），它就读不了，脚本说 cannot read 然后以 1 退出。
    # place 是以属主的身份跑的，读得了这个文件，而且内容已经是记录的那一份，它不会重写文件，所以每次 up 里 place 都抹不掉这个办法。
    config_file = POOL / 'config' / 'config.yaml'
    written, content = config_file.stat(), config_file.read_text(encoding='utf-8')
    mode = stat.S_IMODE(written.st_mode)
    r.check('egress 读配置靠的是文件对所有人可读：配置文件现在是 0644（发布器写的就是这个）', mode == 0o644)
    cut = power_cut()
    died = wait_for(lambda: not container('egress-watch').get('running'), 5)
    since = time.time()
    os.chmod(config_file, 0o600)
    try:
        failed = compose('up', '-d')
        names = ('netns', 'egress', 'agentgateway', 'confirm', 'front', 'egress-watch')
        stopped = {service: container(service) for service in names}
        said, placed = step('egress'), step('place')
        closed = get('a.test', '/quick')
        left, left_content = config_file.stat(), config_file.read_text(encoding='utf-8')
    finally:
        os.chmod(config_file, mode)   # 不管上面出了什么错，目录里的文件都要回到原样
    r.note('egress 失败时 docker compose up -d 的退出码，和它最后说的', [failed.returncode, (failed.stderr.strip().splitlines() or [''])[-1].strip()])
    r.note('egress 失败时：egress 容器的退出码，和它写到标准错误上的', [said['exit'], said['stderr']])
    r.note('egress 失败时：place 的退出码和结局，配置文件的模式', [outcome(placed), oct(stat.S_IMODE(left.st_mode))])
    r.note('egress 失败时：netns、egress、网关、confirm、front、egress-watch 是不是在跑',
           {service: stopped[service].get('running') for service in names})
    r.check('egress 读不了配置（配置文件是 0600）：docker compose up -d 以非零码结束；egress 容器以非零码退出，在标准错误上说了为什么（cannot read）',
            cut and died is not None and failed.returncode != 0 and said['exit'] not in (None, 0) and 'cannot read' in said['stderr'])
    r.check('网关没有被这次 up 启动：它的启动时刻不晚于命令开始的时刻，它没在跑；confirm、egress-watch 也没有启动；front 没在跑，业务端口上没有人应答',
            all(not stopped[service].get('running') and moment(stopped[service].get('started') or '') <= since
                for service in ('agentgateway', 'confirm', 'front', 'egress-watch'))
            and closed['status'] is None)
    r.check('这个办法是确定的：place 在这次 up 里照常以 0 跑完（IN_PLACE），在 egress 之前；配置文件没有被动过：还是那个文件，'
            '内容、属主、修改时刻都不变，模式还是 0600',
            outcome(placed) == (0, 'IN_PLACE') and since <= placed['started'] <= placed['finished'] <= said['started']
            and stat.S_IMODE(left.st_mode) == 0o600 and left_content == content
            and (left.st_ino, left.st_uid, left.st_mtime_ns) == (written.st_ino, written.st_uid, written.st_mtime_ns))

    # 去掉原因：池又是完整的。
    since = time.time()
    again = compose('up', '-d')
    back = wait_for(lambda: get('a.test', '/quick')['status'] == 200, 30)
    ran, watcher, gateway = (container(service) for service in ('egress', 'egress-watch', 'agentgateway'))
    r.check('配置文件改回 0644 再跑启动命令：退出码 0；egress 在这次启动里重新跑了，以 0 跑完，网关在它之后才启动；confirm 是 IN_SYNC；请求照常',
            stat.S_IMODE(config_file.stat().st_mode) == 0o644 and again.returncode == 0 and back is not None and ran.get('exit') == 0
            and since <= moment(ran.get('started') or '') <= moment(ran.get('finished') or '') <= moment(gateway.get('started') or '')
            and outcome(step('confirm')) == (0, 'IN_SYNC'))
    r.check('池又是完整的：三个常驻容器和后端 echo 都在跑，egress-watch 在跑；钉着的和之前一样',
            all(container(service).get('running') for service in (*LONG_RUNNING, 'echo')) and bool(watcher.get('running'))
            and pinned() == held)


def keeper_cases(r: Results, confirmed: Snapshot):
    """看守的用例（SH-16 到 SH-18）。开始时池好好地在跑：三个常驻容器和后端都在，confirmed 是这个池上最后一次
    得到确认的那份快照，网关在跑的就是它。"""
    config_file, lock_file = POOL / 'config' / 'config.yaml', POOL / 'config' / '.config.yaml.lock'
    routes = confirmed.routes

    def running() -> dict:
        return {service: container(service) for service in LONG_RUNNING}

    def all_up() -> bool:
        return all(container(service).get('running') for service in LONG_RUNNING)

    def answering() -> bool:
        return get('a.test', '/quick')['status'] == 200

    r.case('SH-16', '看守（gateway-control keep）：池里常驻的容器死了，它跑启动命令把它们起回来；一次发布占着池时它不动手')
    kept, before = record(), running()
    ids = {service: container(service).get('id') for service in SERVICES}
    ran = {service: container(service).get('started') for service in ('place', 'confirm')}
    # 不给间隔：5 秒看一眼，一分钟对一次账。环境里带着部署文件的各个变量。两样都与看守的单元里的相同。
    keeper = Keeper(settings=True)
    first = keeper.next(lambda line: True, 15)
    time.sleep(7)
    r.note('看守在一个好好的池上写的那一行（原样）', {name: value for name, value in first.items() if name != 'at'})
    r.check('在一个好好的池上启动看守：它写了一行，说三个常驻容器都在跑（whole），账对得上（IN_SYNC）；它没有动手',
            whole(first) and first.get('action') == '' and first.get('busy') is False and first.get('error') == ''
            and first.get('after') is None and all(member(first, 'pool', service).get('running') is True for service in LONG_RUNNING)
            and reconciled(first).get('outcome') == 'IN_SYNC' and reconciled(first).get('snapshot') == confirmed.sha256
            and reconciled(first).get('replaced') is False)
    r.check('之后 7 秒（它 5 秒看一眼）它没有再出声；三个常驻容器没有动，place 和 confirm 没有再跑',
            len(keeper.lines) == 1 and not keeper.said and all(same_process(before[service], container(service)) for service in LONG_RUNNING)
            and all(container(service).get('started') == ran[service] for service in ran))

    traffic, mark, since = Load(), keeper.mark(), time.time()
    docker('kill', before['agentgateway'].get('name', '-'))
    back = keeper.next(acted, 40, mark)
    healed = wait_for(answering, 20)
    time.sleep(3)
    result = traffic.finish()
    cut, placed, confirming, after, now = outage(traffic), step('place'), step('confirm'), running(), observe()
    refused = cut['refused']
    r.note('网关被杀掉：看守写的那一行', brief(back))
    r.note('网关被杀掉：没有得到 200 的快请求（时刻是相对于流量开始的秒数）',
           f"{len(refused)} 个，发出的时刻从 {refused[0]['at']} 到 {refused[-1]['at']}" if refused else '没有')
    r.note('网关被杀掉：没有得到 200 的请求得到的是什么', cut['answers'])
    r.note('网关被杀掉：快请求 / 慢请求的结果', f"{result['quick']} / {result['slow']}，历时 {result['seconds']} 秒")
    r.check('网关被强行杀掉（docker kill）：看守下一眼看到它没在跑（down），跑了启动命令（start）；之后三个容器都在跑，账对得上',
            back.get('action') == 'start' and back.get('condition') == 'down'
            and back.get('why') == 'the gateway is not running (exited (137))' and back.get('busy') is False
            and back.get('repaired') is True and back.get('start_error') == '' and back.get('retry_in_seconds') == 0 and back.get('error') == ''
            and member(back, 'pool', 'agentgateway').get('running') is False and member(back, 'after', 'agentgateway').get('running') is True
            and reconciled(back).get('outcome') == 'IN_SYNC')
    r.check('网关是经启动命令起来的：place 先跑完（IN_PLACE），网关才启动，然后是 confirm（IN_SYNC）',
            outcome(placed) == (0, 'IN_PLACE') and outcome(confirming) == (0, 'IN_SYNC')
            and since <= placed['started'] <= placed['finished'] <= moment(after['agentgateway'].get('started') or '') <= confirming['started'])
    r.check('网关换了一个进程，还是那个容器；netns 和 front 没有被动过',
            bool(after['agentgateway'].get('running')) and after['agentgateway'].get('id') == before['agentgateway'].get('id')
            and after['agentgateway'].get('pid') != before['agentgateway'].get('pid')
            and all(same_process(before[service], after[service]) for service in ('netns', 'front')))
    r.check('网关在跑的是记录的那一份。请求只在网关死着的那一段得不到 200（不超过 15 秒：看守 5 秒看一眼），之后照常',
            healed is not None and now['reload'] == LOADED and now['digest'] == kept.get('digest') and on_disk() == confirmed.text
            and bool(refused) and refused[-1]['at'] - refused[0]['at'] <= 15
            and len(cut['last']) == 20 and all(q['outcome'] == '200' for q in cut['last']))

    mark, before = keeper.mark(), running()
    docker('kill', before['front'].get('name', '-'))
    back = keeper.next(acted, 40, mark)
    healed, after = wait_for(answering, 20), running()
    r.note('front 被杀掉：看守写的那一行', brief(back))
    r.check('front 被强行杀掉：看守跑启动命令把它起回来；front 换了一个进程，网关和 netns 没有被动过，请求照常',
            back.get('action') == 'start' and back.get('condition') == 'down' and back.get('why') == 'the front proxy is not running (exited (137))'
            and back.get('repaired') is True and back.get('start_error') == '' and reconciled(back).get('outcome') == 'IN_SYNC'
            and bool(after['front'].get('running')) and after['front'].get('id') == before['front'].get('id')
            and after['front'].get('pid') != before['front'].get('pid')
            and all(same_process(before[service], after[service]) for service in ('netns', 'agentgateway')) and healed is not None)
    r.check('看守的环境里带着部署文件的各个变量（它的单元里就是这样），它跑的启动命令没有因此重建哪个容器：七个容器都还是原来那七个',
            ids == {service: container(service).get('id') for service in SERVICES} and len(set(ids.values())) == 7)
    stopped = keeper.stop()
    r.check('叫停看守（SIGTERM）：它以 0 退出，标准错误上什么都没有说', stopped['exit'] == 0 and stopped['seconds'] < 5 and not stopped['stderr'])

    keeper = Keeper('--interval', '1s')   # 以下 1 秒看一眼：省时间
    keeper.next(whole, 15)
    mark, since, before = keeper.mark(), time.time(), running()
    docker('kill', before['netns'].get('name', '-'))
    back = keeper.next(acted, 60, mark)
    healed, after, events = wait_for(answering, 20), running(), pool_events(since)
    r.note('netns 单独被杀掉：看守写的那一行', brief(back))
    r.note('netns 单独被杀掉：这期间 docker 给各容器发的信号和它们的退出，按先后', events)
    r.check('netns 单独被强行杀掉（SH-13：这时只跑启动命令修不好）：看守看出网关和 front 接着的那个命名空间已经不在了（orphaned），'
            '先把这两个停下，再跑启动命令（stop+start）；之后三个容器都在跑，账对得上',
            back.get('action') == 'stop+start' and back.get('condition') == 'orphaned'
            and back.get('why') == '; '.join(f'{what} is running but the container that holds its network namespace is not'
                                             for what in ('the gateway', 'the front proxy'))
            and back.get('repaired') is True and back.get('start_error') == '' and reconciled(back).get('outcome') == 'IN_SYNC')
    r.check('停的是 front 和网关，front 在先，两个都是自己退出的；然后启动命令照它的先后来（place，网关，confirm，front）',
            events == ['kill netns 9', 'die netns', 'kill front 3', 'die front', 'kill agentgateway 15', 'die agentgateway',
                       'die place', 'die confirm']
            and outcome(step('place')) == (0, 'IN_PLACE') and outcome(step('confirm')) == (0, 'IN_SYNC')
            and step('place')['finished'] <= moment(after['agentgateway'].get('started') or '')
            and step('confirm')['finished'] <= moment(after['front'].get('started') or ''))
    r.check('三个常驻容器都换了进程，还是那三个容器；请求照常',
            all(bool(after[service].get('running')) and after[service].get('id') == before[service].get('id')
                and after[service].get('pid') != before[service].get('pid') for service in LONG_RUNNING)
            and healed is not None and routes_seen(routes) == {name: 200 for name in routes})
    stopped = keeper.stop()

    dark = power_cut()
    time.sleep(1)

    def kept_alive() -> tuple:
        """起一个看守，等它把启动命令跑完。"""
        nonlocal keeper
        keeper = Keeper('--interval', '1s')
        line = keeper.next(acted, 60)
        return (0 if line.get('repaired') and not line.get('start_error') else 1), str(line.get('start_error') or '')

    seen = boot(('a',), start=kept_alive)
    back = keeper.next(acted, 1)
    r.note('三个常驻容器都死了时启动看守：它写的那一行', brief(back))
    r.note('三个常驻容器都死了时启动看守：各件事发生的时刻（相对于看守启动的秒数；"命令返回"是看守写出那一行的时刻）', timeline(seen))
    r.note('三个常驻容器都死了时启动看守：这期间发往业务端口的请求各得到什么（None 是没有得到应答）', seen['answers'])
    r.check('三个常驻容器同时被强行杀掉（断电的样子），这时才启动看守：它第一眼看到三个都没在跑，跑了启动命令，都起来了',
            stopped['exit'] == 0 and dark and seen['exit'] == 0 and back.get('action') == 'start' and back.get('condition') == 'down'
            and back.get('why') == '; '.join(f'{what} is not running (exited (137))' for what in (
                'the container that holds the network namespace', 'the gateway', 'the front proxy'))
            and back.get('repaired') is True and reconciled(back).get('outcome') == 'IN_SYNC')
    r.check('看守跑的启动命令与开机时的是同一条：place 跑完网关才启动，confirm 跑完 front 才启动；confirm 跑完之前没有请求得到应答',
            outcome(seen['place']) == (0, 'IN_PLACE') and outcome(seen['confirm']) == (0, 'IN_SYNC') and in_order(seen) and gated(seen, 'a'))

    unconfirmed = Snapshot([*routes, 't'])   # 一份没有毛病的快照，只是没有人确认过
    before, knock = running(), Knock(('a', 't'))
    with open(lock_file, 'r+b') as held_lock:
        fcntl.flock(held_lock, fcntl.LOCK_EX)   # 发布器做一次发布，从头到尾就是这样占着这个池
        mark = keeper.mark()
        docker('kill', before['agentgateway'].get('name', '-'))
        publish(unconfirmed)   # 绕过发布器把它放进目录：一次发布做到一半时，目录里就是这样一份文件
        busy = keeper.next(lambda line: line.get('busy'), 15, mark)
        time.sleep(4)   # 看守又看了四眼
        waiting = list(keeper.lines[mark:])
        left_alone = not container('agentgateway').get('running') and on_disk() == unconfirmed.text
    back = keeper.next(acted, 30, mark)
    healed = wait_for(answering, 20)
    time.sleep(1)
    log = knock.finish()
    placed = step('place')
    answers = {route: dict(collections.Counter(str(q['status']) for q in log if q['route'] == route)) for route in ('a', 't')}
    r.note('池被占着时看守写的', [brief(line) for line in waiting])
    r.note('锁放开之后看守写的那一行', brief(back))
    r.note('池被占着到网关回来，这期间发往业务端口的请求各得到什么', answers)
    r.check('一次发布正占着这个池（配置目录的锁被占着），这时网关死了，目录里放着一份没人确认过的文件。看守说池被占着（busy），不动手：'
            '它又看了四眼，网关还是没在跑，那份文件没有被动过',
            busy.get('busy') is True and busy.get('action') == '' and busy.get('condition') == 'down' and busy.get('reconcile') is None
            and len(waiting) == 1 and left_alone)
    r.check('锁放开之后看守才跑启动命令：place 把记录的那一份放回去（写了文件，说了原来放着的是哪一份），网关带着它起来，账对得上',
            back.get('action') == 'start' and back.get('busy') is False and back.get('repaired') is True
            and outcome(placed) == (0, 'IN_PLACE') and placed['report'].get('replaced') is True
            and placed['report'].get('previous') == unconfirmed.sha256 and on_disk() == confirmed.text
            and reconciled(back).get('outcome') == 'IN_SYNC')
    r.check('没人确认过的那条路由 t 从头到尾一次都没有应答过 200；网关回来之后请求照常',
            '200' not in answers['t'] and answers['t'].get('404', 0) >= 1 and healed is not None
            and routes_seen(['a', 't']) == {'a': 200, 't': 404})
    stopped = keeper.stop()
    r.check('这几次之后叫停看守：以 0 退出', stopped['exit'] == 0 and not stopped['stderr'])

    r.case('SH-17', '看守定时对账：发布器死在半路留下的文件、有人绕过发布器写的文件，它在下一次对账时收回去；正常的发布它不碰，网关它不重启')
    key = 'terminationMaxDeadline'
    keeper = Keeper('--interval', '1s', '--reconcile-interval', '5s')
    keeper.next(whole, 15)
    before = running()
    stray = Snapshot([*routes, 'u'])
    traffic, mark = Load(), keeper.mark()
    for _ in range(3):   # 发布器一开始正好撞上看守在对账时，它什么都没做就退出了：再来
        killed = control_killed(stray)
        if killed['killed']:
            break
    at = time.time()
    back = keeper.next(restored, 20, mark)
    gone = wait_for(lambda: routes_seen(['u']) == {'u': 404}, 10)
    time.sleep(3)
    result, now = traffic.finish(), observe()
    r.note('发布器被杀掉之后过了多少秒，看守写出把文件收回去的那一行（它 5 秒对一次账）', round(back['at'] - at, 2) if back else None)
    r.note('发布器被杀掉之后：看守写的那一行', brief(back))
    r.check('发布器刚把一份没人确认过的快照换上去就被强行杀掉。看守在下一次对账时把记录的那一份放回去（RESTORED），'
            '说了原来放着的是哪一份；它没有动容器',
            killed['killed'] and restored(back) and back.get('action') == '' and whole(back)
            and reconciled(back).get('replaced') is True and reconciled(back).get('restarted') is False
            and reconciled(back).get('snapshot') == confirmed.sha256 and reconciled(back).get('previous') == stray.sha256
            and back.get('at', at + 99) - at <= 15)
    r.check('网关在跑的又是记录的那一份，没人确认过的那条路由没有了；三个常驻容器都没有重启',
            gone is not None and on_disk() == confirmed.text and now['reload'] == LOADED and now['digest'] == kept.get('digest')
            and all(same_process(before[service], container(service)) for service in LONG_RUNNING))
    no_failures(r, result, '从发布器被杀掉到看守收回去')

    broken = Snapshot([*routes, 'c'], unloadable='c')
    mark = keeper.mark()
    publish(broken)   # 绕过发布器，放一份网关加载不了的文件
    back = keeper.next(restored, 20, mark)
    r.note('有人放了一份网关加载不了的文件：看守给出的原因', reconciled(back).get('reason'))
    r.check('有人绕过发布器放了一份网关加载不了的文件：看守在下一次对账时收回去（RESTORED）',
            restored(back) and back.get('action') == '' and reconciled(back).get('previous') == broken.sha256
            and on_disk() == confirmed.text)
    mark = keeper.mark()
    config_file.unlink()   # 有人把配置文件删了
    back = keeper.next(restored, 20, mark)
    now = observe()
    r.check('配置文件被删掉：看守在下一次对账时把记录的那一份放回去（RESTORED），说那里原来没有文件',
            restored(back) and back.get('action') == '' and reconciled(back).get('previous') == ''
            and 'there was no configuration file in place' in str(reconciled(back).get('reason')) and on_disk() == confirmed.text
            and now['reload'] == LOADED and now['digest'] == kept.get('digest'))
    r.check('这两次网关和 front 也都没有重启', all(same_process(before[service], container(service)) for service in LONG_RUNNING))

    newer = Snapshot([*routes, 'w'])
    mark = keeper.mark()
    done = patient(lambda: control(newer))
    time.sleep(12)   # 看守又对了两次账还多
    lines = list(keeper.lines[mark:])
    r.note('看守在跑时正常发布一份新快照：这期间看守写的', [brief(line) for line in lines])
    r.check('看守在跑时用发布器正常发布一份新快照：ACTIVE。过了 12 秒（看守又对了两次账还多），这一份还在生效，看守没有把它收回去',
            outcome(done) == (0, 'ACTIVE') and done['report'].get('replaced') is True and on_disk() == newer.text
            and record().get('snapshot') == newer.sha256 and routes_seen(['w']) == {'w': 200}
            and not any(acted(line) or reconciled(line).get('replaced') for line in lines))

    tuned = Snapshot([*routes, 'w'], deadline=46)   # 与上一份只差 config 段里的一项：要重启网关才生效
    name = before['agentgateway'].get('name', '-')
    mark, since, before = keeper.mark(), time.time(), running()
    done = patient(lambda: control_restart(tuned, name))
    time.sleep(3)
    lines, events, after, now = list(keeper.lines[mark:]), docker_events(name, since), running(), observe()
    r.note('看守在跑时做一次带重启的发布：这期间看守写的', [brief(line) for line in lines])
    r.note('看守在跑时做一次带重启的发布：这期间 docker 对网关容器做过的事', events)
    r.check('看守在跑时做一次带重启的发布（gateway-control restart）：ACTIVE，网关重启了，就这一次；启动设置换成了新的',
            outcome(done) == (0, 'ACTIVE') and done['report'].get('restarted') is True
            and events.count('restart') == 1 and events.count('start') == 1
            and now['config'].get(key) == '46s' and record().get('snapshot') == tuned.sha256
            and after['agentgateway'].get('pid') != before['agentgateway'].get('pid')
            and all(same_process(before[service], after[service]) for service in ('netns', 'front')))
    r.check('看守没有插手：这期间它没有动过容器，也没有往回放过文件',
            not any(acted(line) or reconciled(line).get('replaced') for line in lines)
            and all(line.get('busy') is True for line in lines if line.get('condition') == 'down'))

    # 一份离线加载得了、网关拿它却起不来的快照（指标端口撞上 front 的，见 SH-11）：发布器重启网关之后读不到它，等满时限，
    # 把上一份放回去再重启一次。网关前后停了 5 秒多，这期间池一直被这次发布占着。
    clash = Snapshot([*routes, 'w'], deadline=46, stats=PORT['front'])
    ran = {service: container(service).get('started') for service in ('place', 'confirm')}
    mark, since = keeper.mark(), time.time()
    rolled = patient(lambda: control_restart(clash, name, '--timeout', '5s'))
    time.sleep(3)
    lines, events, now = list(keeper.lines[mark:]), docker_events(name, since), observe()
    down = [line for line in lines if line.get('condition') == 'down']
    r.note('带重启的发布让网关停了 5 秒多：发布器用了多少秒，这期间 docker 对网关容器做过的事', [rolled['seconds'], events])
    r.note('带重启的发布让网关停了 5 秒多：这期间看守写的', [brief(line) for line in lines])
    r.check('一份网关拿它起不来的快照做带重启的发布：网关停了 5 秒多，发布器把上一份放回去再重启一次（RESTORED）。'
            '看守这期间看到网关没在跑，说的是池被占着（busy），没有动手：place 和 confirm 没有跑，网关只有发布器的那两次重启',
            outcome(rolled) == (4, 'RESTORED') and rolled['seconds'] >= 5 and events.count('restart') == 2
            and len(down) >= 1 and all(line.get('busy') is True and line.get('reconcile') is None for line in down)
            and not any(acted(line) or reconciled(line).get('replaced') for line in lines)
            and all(container(service).get('started') == ran[service] for service in ran))
    r.check('发布器做完之后看守看到池又好了，账对得上（IN_SYNC）：在跑的是记录的那一份，启动设置也是它的',
            bool(lines) and whole(lines[-1]) and reconciled(lines[-1]).get('outcome') == 'IN_SYNC'
            and now['config'].get(key) == '46s' and on_disk() == tuned.text and record().get('snapshot') == tuned.sha256)

    # 带重启的发布做到一半，发布器被强行杀掉：docker 已经把网关带着新设置重新起来，记录里仍是上一份（SH-11）。
    # 等网关在回读口上答得上话才杀：刚启动的头几毫秒里它看不到换上去的文件，看守正好在那时把记录的那一份放回去的话，
    # 那一次对账是 UNKNOWN，要下一次才是 RESTART_PENDING。
    half = Snapshot([*routes, 'w', 'z'], deadline=47)
    mark = keeper.mark()
    for _ in range(3):   # 发布器一开始正好撞上看守在对账时，它什么都没做就退出了：再来
        killed = restart_killed(half, name)
        if killed['killed']:
            break
    left_running = running()
    pending = keeper.next(lambda line: reconciled(line).get('outcome') == 'RESTART_PENDING', 20, mark)
    time.sleep(7)   # 看守又对了一次账还多
    lines, now = list(keeper.lines[mark:]), observe()
    r.note('带重启的发布做到一半：网关重新起来之后过了多少秒在回读口上答话，这时才杀发布器', killed.get('answered'))
    r.note('带重启的发布做到一半发布器被杀掉：这期间看守写的', [brief(line) for line in lines])
    r.check('带重启的发布做到一半，发布器被强行杀掉：网关已经带着新设置起来了。看守在下一次对账时把记录的那一份放回去，'
            '报告启动设置还差一次重启（RESTART_PENDING），指出是哪一项',
            killed['killed'] and pending.get('action') == '' and whole(pending) and reconciled(pending).get('replaced') is True
            and reconciled(pending).get('restart') == [key] and reconciled(pending).get('snapshot') == tuned.sha256
            and reconciled(pending).get('previous') == half.sha256 and on_disk() == tuned.text
            and routes_seen(['w', 'z']) == {'w': 200, 'z': 404})
    r.check('它自己不重启网关：又过了 7 秒（它又对了一次账还多），网关还是发布器被杀掉时的那个进程，启动设置还是新的那一套',
            not any(acted(line) for line in lines) and same_process(left_running['agentgateway'], container('agentgateway'))
            and now['config'].get(key) == '47s')
    mark = keeper.mark()
    again = patient(lambda: control_restart(None, name))
    settled = keeper.next(lambda line: reconciled(line).get('outcome') == 'IN_SYNC', 20, mark)
    now = observe()
    r.check('由人来做完：不给快照的 restart 拿记录的那一份再重启一次（ACTIVE）。启动设置回来了，看守下一次对账是 IN_SYNC',
            outcome(again) == (0, 'ACTIVE') and again['report'].get('restarted') is True and now['config'].get(key) == '46s'
            and whole(settled) and settled.get('action') == '' and not any(acted(line) for line in keeper.lines[mark:]))
    stopped = keeper.stop()
    r.check('这些事做下来看守一直在跑；叫停它，以 0 退出', stopped['exit'] == 0 and not stopped['stderr'])
    confirmed = tuned

    r.case('SH-18', '看守修不好时隔得越来越久再试；它在跑时这个池停不住；叫停它、杀掉它；变量文件写得不对它不启动；头一次安装')
    readback_key = POOL / 'tls' / 'gateway-readback.key'
    key_bytes, key_mode = readback_key.read_bytes(), stat.S_IMODE(readback_key.stat().st_mode)
    keeper = Keeper('--interval', '1s')
    keeper.next(whole, 15)
    before, mark = running(), keeper.mark()
    readback_key.unlink()   # 网关回读口的私钥不见了：它再启动时起不来（SH-13）
    docker('kill', before['agentgateway'].get('name', '-'))
    failed = keeper.next(acted, 40, mark)
    meanwhile = get('a.test', '/quick')
    readback_key.write_bytes(key_bytes)
    os.chmod(readback_key, key_mode)
    attempts = keeper.wait(acted, 40, mark, count=2)
    back = attempts[1] if len(attempts) == 2 else {}
    healed = wait_for(answering, 20)
    r.note(f'网关起不来时：看守写的那一行（confirm 等网关的时限在这里设成了 {CONFIRM_SECONDS} 秒）', brief(failed))
    r.note('网关起不来时：往业务端口发请求得到的', [meanwhile.get('status'), meanwhile.get('body')])
    r.note('私钥放回去之后：看守写的那一行', brief(back))
    r.check('网关死了，而且起不来（它回读口的私钥不见了）。看守跑了启动命令，没有修好：它说了启动命令卡在 confirm 这一步，'
            '隔 2 秒再试（它 1 秒看一眼）',
            failed.get('action') == 'start' and failed.get('repaired') is False and failed.get('retry_in_seconds') == 2
            and '"confirm" didn\'t complete successfully: exit 5' in str(failed.get('start_error'))
            and member(failed, 'after', 'agentgateway').get('running') is False and failed.get('reconcile') is None)
    r.check('这期间 front 一直开着，没有被动过：发往业务端口的请求得到 502', meanwhile.get('status') == 502
            and same_process(before['front'], container('front')))
    r.check('把私钥放回去，看守下一次再试就好了：网关起来了，账对得上，请求照常；netns 和 front 没有被动过',
            back.get('action') == 'start' and back.get('repaired') is True and back.get('start_error') == ''
            and reconciled(back).get('outcome') == 'IN_SYNC' and back.get('at', 0) - failed.get('at', 0) >= 2 and healed is not None
            and all(same_process(before[service], container(service)) for service in ('netns', 'front')))

    mark = keeper.mark()
    halted = compose('stop', *SERVICES)
    healed = wait_for(lambda: all_up() and answering(), 90, every=0.5)
    time.sleep(3)
    lines = list(keeper.lines[mark:])
    r.note('看守在跑时停这个池：停止命令的退出码，和这期间看守写的', [halted.returncode, [brief(line) for line in lines]])
    r.check('看守在跑时停这个池（docker compose stop）：停不住。看守把它起回来了：三个容器都在跑，请求照常，账对得上。'
            '要让这个池停着，得先停看守',
            any(acted(line) for line in lines) and healed is not None and all_up() and answering()
            and outcome(patient(control_reconcile)) == (0, 'IN_SYNC'))

    mark, since, before = keeper.mark(), time.time(), running()
    docker('kill', before['agentgateway'].get('name', '-'))
    caught = wait_for(keeper.composing, 15, every=0.02)
    stopped = keeper.stop()   # 它正跑着启动命令
    last, confirming = (keeper.lines[mark:] or [{}])[-1], step('confirm')
    r.note('看守正跑着启动命令时叫停它：从发信号到它退出过了多少秒', stopped['seconds'])
    r.note('看守正跑着启动命令时叫停它：它最后写的那一行', brief(last))
    r.check('看守正跑着启动命令时叫停它（SIGTERM）：它把这条命令跑完才退出，退出码 0；池没有停在半路：三个容器都在跑，'
            'confirm 是 IN_SYNC，请求照常',
            caught is not None and stopped['exit'] == 0 and not stopped['stderr'] and last.get('action') == 'start'
            and last.get('repaired') is True and all_up() and outcome(confirming) == (0, 'IN_SYNC')
            and since < confirming['finished'] <= stopped['at'] and wait_for(answering, 10) is not None)

    keeper = Keeper('--interval', '1s')
    keeper.next(whole, 15)
    before = running()
    killed = keeper.stop(signal.SIGKILL)
    time.sleep(2)
    with open(lock_file, 'r+b') as held_lock:
        try:
            fcntl.flock(held_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            free = True
        except BlockingIOError:
            free = False
    r.check('看守闲着时被强行杀掉（SIGKILL）：池不受影响，三个常驻容器没有动，请求照常；配置目录的锁空着，目录里没有多出东西',
            killed['exit'] == -signal.SIGKILL and free and all(same_process(before[service], container(service)) for service in LONG_RUNNING)
            and answering() and leftovers()['配置目录'] == CLEAN['配置目录'])

    keeper = Keeper('--interval', '1s')
    again = keeper.next(whole, 15)
    stopped = keeper.stop()
    halted = compose('stop', *SERVICES)
    time.sleep(5)
    r.check('再起一个看守，它照常（whole，IN_SYNC）。先叫停它（它闲着，立刻以 0 退出），再停这个池：停住了，过了 5 秒三个容器都还停着',
            reconciled(again).get('outcome') == 'IN_SYNC' and stopped['exit'] == 0 and stopped['seconds'] < 3
            and halted.returncode == 0 and not any(container(service).get('running') for service in LONG_RUNNING))

    # 变量文件：看守把自己的环境交给 docker compose，docker compose 先用环境里的。systemd 读法不同的行、环境里另一个值，
    # 都会让它跑的启动命令拿到另一套设置。池这时停着：看守要是启动了，会把它起起来。
    commented = CONTROL / 'commented.env'
    listen = f"CALLERS_LISTEN=127.0.0.1:{HOST['front']}\n"
    commented.write_text(POOL_ENV.read_text(encoding='utf-8').replace(listen, listen.rstrip() + ' # 只给本机\n'), encoding='utf-8')
    unread = Keeper('--interval', '1s', env_file=commented)
    refused = unread.ended()
    unlike = Keeper('--interval', '1s', more={'CONFIRM_TIMEOUT': '99s'})
    differing_value = unlike.ended()
    r.note('变量文件里有一行的值后面跟着注释：看守说了什么', refused['stderr'])
    r.note('环境里有一个变量与变量文件里的值不同：看守说了什么', differing_value['stderr'])
    r.check('变量文件里有一行的值后面跟着注释（systemd 会把注释也读进值里）：看守不启动，退出码 2，指出是哪个文件的哪一行，'
            '那一行的内容不写出来',
            POOL_ENV.read_text(encoding='utf-8').startswith(listen) and refused['exit'] == 2
            and any(f'env file {commented}, line 1: only NAME=value lines are accepted' in line for line in refused['stderr'])
            and not any('只给本机' in line or '127.0.0.1:' in line for line in refused['stderr']))
    r.check('环境里有一个变量与变量文件里的值不同：看守不启动，退出码 2，指出是哪个变量，两个值都不写出来',
            differing_value['exit'] == 2
            and any('CONFIRM_TIMEOUT has another value in the environment of this command' in line for line in differing_value['stderr'])
            and not any(value in line.replace(str(POOL_ENV), '') for line in differing_value['stderr']
                        for value in ('99s', f'{CONFIRM_SECONDS}s')))
    r.check('这两次它什么都没做：没有写出一行，停着的池没有被起起来',
            not unread.lines and not unlike.lines and not any(container(service).get('running') for service in LONG_RUNNING))

    # 头一次安装时看守已经在跑。先把这个池整个拆掉：容器都删了，配置目录里只有第一份快照。
    opening = Snapshot(['a', 'x'])
    compose('down', '--timeout', '2')
    shutil.rmtree(POOL / 'config')
    (POOL / 'config').mkdir()
    compose('up', '-d', 'echo')
    config_file.write_text(opening.text, encoding='utf-8')
    os.chmod(config_file, 0o644)
    keeper = Keeper('--interval', '1s', '--reconcile-interval', '1s')
    attempts = keeper.wait(acted, 90, count=4)
    front, closed = container('front'), get('a.test', '/quick')
    mark = keeper.mark()
    done = patient(lambda: control(opening))   # 用发布器把这一份发布一次：这个池有了第一条记录
    published = time.time()
    agreed = keeper.next(lambda line: not acted(line) and reconciled(line).get('outcome') == 'IN_SYNC', 30, mark)
    opened = keeper.next(lambda line: acted(line) and line.get('repaired'), 30, mark)
    healed = wait_for(answering, 20)
    r.note('一个全新的池上看守头四次跑启动命令：各次写的', [brief(line) for line in attempts])
    r.note('发布了第一份之后看守写的两行：账对上了的那一行，开了 front 的那一行', [brief(agreed), brief(opened)])
    opened_at = moment(container('front').get('started') or '')
    r.note('从第一份发布做完到 front 启动过了多少秒；这时离原定的下一次再试还有多少秒',
           [round(opened_at - published, 2), round(attempts[-1]['at'] + 16 - opened_at, 2)] if opened and len(attempts) == 4 else None)
    r.check('一个全新的池（容器都没有，配置目录里只有第一份快照，没有记录）上启动看守：它跑启动命令，网关起来了，confirm 没有可对的，'
            'front 不开。它隔 2、4、8、16 秒再试，每次都报告账还没有可对的（UNCONFIRMED）',
            len(attempts) == 4 and [line.get('retry_in_seconds') for line in attempts] == [2, 4, 8, 16]
            and all(line.get('action') == 'start' and line.get('repaired') is False
                    and '"confirm" didn\'t complete successfully: exit 3' in str(line.get('start_error'))
                    and reconciled(line).get('outcome') == 'UNCONFIRMED' and member(line, 'after', 'agentgateway').get('running') is True
                    and member(line, 'after', 'front').get('running') is False for line in attempts)
            and 'the front proxy is not running (there is no such container)' in str(attempts[0].get('why'))
            and front.get('status') == 'created' and closed['status'] is None)
    r.check('用发布器发布第一份（ACTIVE）。看守下一次对账时看到账对上了（IN_SYNC），不再等到原定的时候：下一眼就跑启动命令，'
            'front 开了，请求照常',
            outcome(done) == (0, 'ACTIVE') and agreed.get('condition') == 'down' and agreed.get('retry_in_seconds') == 0
            and opened.get('action') == 'start' and opened.get('start_error') == '' and reconciled(opened).get('outcome') == 'IN_SYNC'
            and 0 < agreed.get('at', 0) <= opened.get('at', 0) and len(attempts) == 4 and opened['at'] < attempts[-1]['at'] + 16
            and healed is not None and routes_seen(['a', 'x']) == {'a': 200, 'x': 200} and record().get('snapshot') == opening.sha256)
    stopped = keeper.stop()
    left = leftovers()
    r.note('五条命令都用过之后', left)
    r.check('叫停看守，以 0 退出。五条命令都用过之后没有留下别的东西', stopped['exit'] == 0 and not stopped['stderr'] and left == CLEAN)

    history_absent_case(r, opening)   # SH-23：要在 SH-19 为看守的单元建出历史目录之前查
    unit_command_case(r, opening)
    alerting_cases(r, opening)
    history_cases(r, opening)


def unit_command_case(r: Results, confirmed: Snapshot):
    """SH-19。开始时这套用例的池在跑（看守已经停了），confirmed 是池的目录里最后一次得到确认的那份快照。
    这一条先把那个池拆掉，再拿同一个池的目录，照两个单元文件里写的命令起一个：命令在安装目录里跑，
    docker compose 的项目和文件都不另给。这个池没有后端，所以不往路由上发请求：front 开没开，看一条没有的路由
    是不是得到网关的 404。"""
    r.case('SH-19', '两个 systemd 单元里写的命令原样跑一遍：在放着 compose.yml 和 .env 的目录里，docker compose 的项目和文件都不另给')
    pool_unit, keep_unit = unit_commands('idp-gateway-pool.service'), unit_commands('idp-gateway-pool-keep.service')
    settings = pool_settings()
    # 两条命令的环境：不带部署文件的变量，也不带 COMPOSE_ 开头的。看守的那一条另加 .env 里的各个变量：
    # 它的单元由 systemd 读了 .env 交给它的就是这样。
    plain = {name: value for name, value in compose_environment().items() if name not in ('TOOLS_IMAGE', 'PROBE')}

    def nowhere() -> bool:
        return get('nowhere.test', '/quick')['status'] == 404

    def run_in_place(words: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(words, cwd=HOSTED, env=plain, capture_output=True, text=True, timeout=300)

    compose('down', '--timeout', '2')   # 这套用例自己的池让出两个端口
    others = sorted(c['name'] for c in hosted().values()) + hosted_networks()
    r.note(f'开始之前，这台机器上叫 {DEPLOYED_PROJECT} 的 compose 项目的容器和网络', others)
    if not r.check(f'这台机器上没有叫 {DEPLOYED_PROJECT} 的 compose 项目（部署文件自己的项目名）。有的话这一条不动它，后面的也就没有跑', not others):
        return
    HOSTED.mkdir()
    HISTORY.mkdir(mode=0o700)   # 看守的单元的命令行里有 --history-dir ${POOL_DIR}/history：目录要先建好（deploy/compose/README.md）
    os.chmod(HISTORY, 0o700)
    for name in ('compose.yml', 'front.nginx.conf', 'pin-egress.sh'):
        shutil.copy2(DEPLOY / name, HOSTED / name)
    shutil.copy2(POOL_ENV, HOSTED / '.env')
    HOSTED_MARK.write_text(DEPLOYED_PROJECT + '\n', encoding='utf-8')

    up = run_in_place(pool_unit.get('ExecStart') or ['false'])
    opened = wait_for(nowhere, 20)
    first, now = hosted(), observe()
    placed, confirming = step_of(first.get('place', {})), step_of(first.get('confirm', {}))
    r.note('池的单元的启动命令和停止命令（原样）', [pool_unit.get('ExecStart'), pool_unit.get('ExecStop')])
    r.note('docker compose 记在容器上的项目目录和它用的 compose 文件', sorted({(c['directory'], c['files']) for c in first.values()}))
    r.check('池的单元的启动命令（ExecStart=，原样）在安装目录里跑：退出码 0。命令里没有给项目和文件，docker compose 自己找到了'
            '那个目录里的 compose.yml 和 .env：项目名是部署文件里写的那个，七个服务各一个容器',
            up.returncode == 0 and pool_unit.get('ExecStart', [''])[0] == '/usr/bin/docker'
            and not any(word.startswith('-') and word != '-d' for word in pool_unit['ExecStart'])
            and sorted(first) == sorted(SERVICES)
            and all(c['name'] == f'{DEPLOYED_PROJECT}-{service}-1' for service, c in first.items())
            and {(c['directory'], c['files']) for c in first.values()} == {(str(HOSTED), str(HOSTED / 'compose.yml'))})
    r.check('这个池照部署文件的先后起来了：place 是 IN_PLACE，confirm 是 IN_SYNC，网关在跑的是记录的那一份，front 开了',
            outcome(placed) == (0, 'IN_PLACE') and outcome(confirming) == (0, 'IN_SYNC') and opened is not None
            and all(first.get(service, {}).get('running') for service in LONG_RUNNING)
            and now['reload'] == LOADED and now['digest'] == record().get('digest') and on_disk() == confirmed.text)

    argv = filled_in(keep_unit.get('ExecStart') or ['false'], settings)
    keeper = Keeper(command=argv, cwd=HOSTED, environment={**plain, **settings})
    began = keeper.next(lambda line: True, 20)
    time.sleep(2)
    r.note('看守的单元的命令行，${…} 换成 .env 里的值之后', argv)
    r.check('看守的单元的命令行（ExecStart=，${…} 换成 .env 里的值）在同一个目录里跑，环境里带着 .env 的各个变量。命令行里没有给它'
            ' docker compose 的项目、文件和变量文件；它看的就是这个池（whole），账对得上（IN_SYNC），没有动手',
            argv[:3] == ['/usr/bin/env', str(CONTROL_BINARY), 'keep'] and not any(word.startswith('--compose') for word in argv)
            and whole(began) and began.get('action') == '' and reconciled(began).get('outcome') == 'IN_SYNC'
            and reconciled(began).get('snapshot') == confirmed.sha256 and len(keeper.lines) == 1 and not keeper.said)
    numbers = scrape(settings['KEEPER_METRICS_LISTEN'])
    r.check('单元的命令行以 --metrics-listen ${KEEPER_METRICS_LISTEN} --history-dir ${POOL_DIR}/history --pool <部署文件的项目名> 结尾：.env 里写的那个地址上读得到这个看守的指标，'
            '它说自己守着的是部署文件里写的那个项目，池是完整的',
            argv[-6:] == ['--metrics-listen', settings['KEEPER_METRICS_LISTEN'], '--history-dir', str(HISTORY), '--pool', DEPLOYED_PROJECT]
            and numbers['status'] == 200
            and numbers['series'].get(f'idp_gateway_keeper_info{{project="{DEPLOYED_PROJECT}"}}') == 1
            and standing(numbers['series'], 'idp_gateway_pool_condition') == ['whole']
            and standing(numbers['series'], 'idp_gateway_pool_reconcile_outcome') == ['IN_SYNC'])

    ran = []

    def composing() -> bool:
        ran.extend(line for line in keeper.children() if line.endswith(' up -d'))
        return bool(ran)

    before, mark, since = hosted(), keeper.mark(), time.time()
    docker('kill', before.get('agentgateway', {}).get('id', '-'))
    caught = wait_for(composing, 30, every=0.02)
    back = keeper.next(acted, 40, mark)
    healed = wait_for(nowhere, 20)
    after, now = hosted(), observe()
    r.note('网关被杀掉之后看守跑的那条命令（它的子进程的命令行）', ran[:1])
    r.note('网关被杀掉：看守写的那一行', brief(back))
    r.check('网关被强行杀掉：看守在那个目录里跑的启动命令是 docker compose -p <部署文件里写的项目名> up -d，没有给文件。'
            '它把网关起回来了（start），账对得上，front 照常',
            caught is not None and ran[:1] == [f'docker compose -p {DEPLOYED_PROJECT} up -d']
            and back.get('action') == 'start' and back.get('condition') == 'down'
            and back.get('why') == 'the gateway is not running (exited (137))' and back.get('repaired') is True
            and back.get('start_error') == '' and reconciled(back).get('outcome') == 'IN_SYNC' and healed is not None
            and now['reload'] == LOADED and now['digest'] == record().get('digest'))
    r.check('这条命令拿到的设置与池的单元的启动命令拿到的相同：没有哪个容器被重建，七个还是原来那七个；netns 和 front 没有被动过，'
            '网关换了一个进程；place 和 confirm 各又跑了一遍（IN_PLACE、IN_SYNC）',
            len(after) == 7 and {service: c['id'] for service, c in after.items()} == {service: c['id'] for service, c in before.items()}
            and all(same_process(before[service], after[service]) for service in ('netns', 'front'))
            and bool(after['agentgateway']['running']) and after['agentgateway']['pid'] != before['agentgateway']['pid']
            and outcome(step_of(after['place'])) == (0, 'IN_PLACE') and outcome(step_of(after['confirm'])) == (0, 'IN_SYNC')
            and all(moment(after[service]['started']) >= since for service in ('place', 'confirm')))

    stopped = keeper.stop()
    halted = run_in_place(pool_unit.get('ExecStop') or ['false'])
    time.sleep(3)
    resting = hosted()
    r.check('停，照 systemctl stop 池的单元时的先后（units.py 的 UN-03）：先叫停看守，它以 0 退出；再跑池的单元的停止命令'
            '（ExecStop=，原样）：退出码 0，三个常驻容器都停了，过了 3 秒还停着',
            stopped['exit'] == 0 and not stopped['stderr'] and halted.returncode == 0 and len(resting) == 7
            and not any(c['running'] for c in resting.values()))
    down = run_in_place(['docker', 'compose', 'down', '--volumes', '--timeout', '2'])
    left = sorted(c['name'] for c in hosted().values()) + hosted_networks()
    r.note('拆掉之后这台机器上这个项目还剩什么', left)
    r.check('在那个目录里 docker compose down 之后，这台机器上没有留下这个项目的容器和网络', down.returncode == 0 and not left)


def alerting_cases(r: Results, confirmed: Snapshot):
    """告警（SH-20、SH-21）。开始时两个池都拆掉了，池的目录里放着 confirmed，记录是它。先用启动命令把这套用例的池
    起起来，再起看守：这一回给了它 --metrics-listen。"""
    lock_file, readback_key = POOL / 'config' / '.config.yaml.lock', POOL / 'tls' / 'gateway-readback.key'
    quiet_zeros = ('idp_gateway_pool_busy', 'idp_gateway_pool_unrepaired_attempts', 'idp_gateway_pool_starts_total',
                   'idp_gateway_pool_snapshots_put_back_total', 'idp_gateway_keeper_last_look_failed')

    def answering() -> bool:
        return get('a.test', '/quick')['status'] == 200

    def running() -> dict:
        return {service: container(service) for service in LONG_RUNNING}

    r.case('SH-20', '看守的指标（--metrics-listen）：它不出声的时候这些数照样在走；池出了事、它动了手、它往回放了文件，数跟着变；它停了就读不到')
    up = compose('up', '-d')
    opened = wait_for(answering, 30)
    nobody = scrape()
    r.check('先用启动命令把这套用例的池起起来：退出码 0，请求照常。看守还没有启动：那个地址上没有人，读不到',
            up.returncode == 0 and opened is not None and nobody['status'] is None)

    keeper = Keeper('--interval', '1s', '--reconcile-interval', '3s', '--metrics-listen', METRICS)
    first = keeper.next(lambda line: True, 15)
    time.sleep(4)
    one = scrape()
    time.sleep(4)
    two, now = scrape(), time.time()
    seen, earlier = two['series'], one['series']
    r.note('一个安稳的池上读到的', seen)
    r.check('读得到：200，Prometheus 的文本格式；每个数都先说了自己是 gauge 还是 counter，以 _total 结尾的是 counter，别的是 gauge',
            two['status'] == 200 and two['content_type'] == 'text/plain; version=0.0.4; charset=utf-8' and len(seen) >= 20
            and all(name.split('{')[0] in two['types'] for name in seen)
            and all((kind == 'counter') == name.endswith('_total') and kind in ('gauge', 'counter') for name, kind in two['types'].items()))
    r.check('一个安稳的池：三个常驻容器都在跑（whole），账对得上（IN_SYNC），没有被占着，没有动过手，没有往回放过文件；'
            '它守着的项目、看一眼和对账的间隔是给它的那些',
            standing(seen, 'idp_gateway_pool_condition') == ['whole'] and standing(seen, 'idp_gateway_pool_reconcile_outcome') == ['IN_SYNC']
            and all(seen.get(name) == 0 for name in quiet_zeros) and seen.get(f'idp_gateway_keeper_info{{project="{PROJECT}"}}') == 1
            and seen.get('idp_gateway_keeper_look_interval_seconds') == 1 and seen.get('idp_gateway_keeper_reconcile_interval_seconds') == 3)
    looks = seen.get('idp_gateway_keeper_looks_total', 0) - earlier.get('idp_gateway_keeper_looks_total', 0)
    ages = [round(now - seen.get(name, 0), 2) for name in ('idp_gateway_keeper_last_look_timestamp_seconds', 'idp_gateway_pool_last_reconcile_timestamp_seconds')]
    r.note('隔 4 秒读了两次：看过的眼数多了几；第二次读到时，上一眼和上一次对账各是几秒之前', [looks, ages])
    r.check('这 8 秒里看守只写了开头那一行，之后没有出声。指标照样在走：隔 4 秒再读，看过的眼数多了 3 到 5，上一眼和上一次对账的时刻'
            '都往前走了；上一眼是 2 秒之内的事，上一次对账是 4.5 秒之内的事（它 1 秒看一眼，3 秒对一次账）',
            len(keeper.lines) == 1 and whole(first) and not keeper.said and 3 <= looks <= 5
            and all(seen.get(name, 0) > earlier.get(name, 0) > seen.get('idp_gateway_keeper_start_time_seconds', now)
                    for name in ('idp_gateway_keeper_last_look_timestamp_seconds', 'idp_gateway_pool_last_reconcile_timestamp_seconds'))
            and 0 <= ages[0] < 2 and 0 <= ages[1] < 4.5)
    elsewhere = {path: scrape(path=path)['status'] for path in ('/', '/metrics/', '/config_dump', '/debug/pprof/')}
    written = {method: scrape(method=method) for method in ('POST', 'PUT', 'DELETE')}
    listening = subprocess.run(['ss', '-ltnH', f"sport = :{HOST['metrics']}"], capture_output=True, text=True).stdout.split()
    r.note('别的路径、别的方法得到的；这个端口在哪个地址上听', [elsewhere, {method: answer['status'] for method, answer in written.items()},
                                                [word for word in listening if word.endswith(f":{HOST['metrics']}")]])
    r.check('那个地址上只有 /metrics，而且只读：别的路径都是 404，POST、PUT、DELETE 是 405。它只在给它的那个回环地址上听',
            set(elsewhere.values()) == {404} and all(answer['status'] == 405 and answer['allow'] == 'GET, HEAD' for answer in written.values())
            and [word for word in listening if word.endswith(f":{HOST['metrics']}")] == [METRICS])

    before = running()
    with open(lock_file, 'r+b') as held_lock:
        fcntl.flock(held_lock, fcntl.LOCK_EX)   # 一次发布正占着这个池
        docker('kill', before['agentgateway'].get('name', '-'))
        down = wait_for(lambda: pool_is('down'), 15, every=0.2)
        time.sleep(3)   # 看守又看了三眼
        held = scrape()['series']
    back = wait_for(lambda: scrape()['series'].get('idp_gateway_pool_starts_total') == 1 and pool_is('whole'), 40, every=0.2)
    healed = wait_for(answering, 20)
    after = scrape()['series']
    r.check('一次发布正占着这个池时网关死了：池不是完整的了（down），被占着（busy 是 1）；又过了 3 秒，启动命令还是没有跑',
            down is not None and standing(held, 'idp_gateway_pool_condition') == ['down'] and held.get('idp_gateway_pool_busy') == 1
            and held.get('idp_gateway_pool_starts_total') == 0 and held.get('idp_gateway_keeper_last_look_failed') == 0)
    r.check('锁放开，看守跑启动命令把网关起回来：启动命令的次数是 1，池又是完整的，没有被占着，接连没修好的次数是 0，账对得上，请求照常',
            back is not None and healed is not None and standing(after, 'idp_gateway_pool_condition') == ['whole']
            and after.get('idp_gateway_pool_starts_total') == 1 and after.get('idp_gateway_pool_busy') == 0
            and after.get('idp_gateway_pool_unrepaired_attempts') == 0 and standing(after, 'idp_gateway_pool_reconcile_outcome') == ['IN_SYNC'])

    key_bytes, key_mode = readback_key.read_bytes(), stat.S_IMODE(readback_key.stat().st_mode)
    readback_key.unlink()   # 网关回读口的私钥不见了：它再启动时起不来（SH-13、SH-18）
    docker('kill', container('agentgateway').get('name', '-'))
    stuck = wait_for(lambda: scrape()['series'].get('idp_gateway_pool_unrepaired_attempts', 0) >= 2, 90, every=0.3)
    failing = scrape()['series']
    readback_key.write_bytes(key_bytes)
    os.chmod(readback_key, key_mode)
    mended = wait_for(lambda: pool_is('whole'), 90, every=0.3)
    healed = wait_for(answering, 20)
    recovered = scrape()['series']
    r.note('网关起不来时读到的：池的样子，接连没修好的次数，启动命令的次数',
           [standing(failing, 'idp_gateway_pool_condition'), failing.get('idp_gateway_pool_unrepaired_attempts'), failing.get('idp_gateway_pool_starts_total')])
    r.check('网关死了而且起不来（它回读口的私钥不见了）：池一直不是完整的（down），接连没修好的次数到了 2，启动命令的次数跟着长到了 3；'
            '这不是池被占着，也不是看守没看成',
            stuck is not None and standing(failing, 'idp_gateway_pool_condition') == ['down']
            and failing.get('idp_gateway_pool_unrepaired_attempts') == 2 and failing.get('idp_gateway_pool_starts_total') == 3
            and failing.get('idp_gateway_pool_busy') == 0 and failing.get('idp_gateway_keeper_last_look_failed') == 0)
    r.check('把私钥放回去，看守下一次再试就好了：池又是完整的，接连没修好的次数回到 0，启动命令的次数是 4，账对得上，请求照常',
            mended is not None and healed is not None and standing(recovered, 'idp_gateway_pool_condition') == ['whole']
            and recovered.get('idp_gateway_pool_unrepaired_attempts') == 0 and recovered.get('idp_gateway_pool_starts_total') == 4
            and standing(recovered, 'idp_gateway_pool_reconcile_outcome') == ['IN_SYNC'])

    before = running()
    stray = Snapshot([*confirmed.routes, 'm'])   # 一份没有毛病的快照，只是没有人确认过
    publish(stray)   # 绕过发布器把它放进目录
    taken_back = wait_for(lambda: account_is('RESTORED'), 20, every=0.1)
    counted = scrape()['series'].get('idp_gateway_pool_snapshots_put_back_total')
    settled = wait_for(lambda: account_is('IN_SYNC'), 20, every=0.1)
    calm = scrape()['series']
    r.check('有人绕过发布器放了一份没人确认过的文件：看守下一次对账把记录的那一份放回去，对账的结局是 RESTORED，往回放的次数是 1；'
            '再下一次对账又是 IN_SYNC，次数还是 1。启动命令没有跑，三个常驻容器没有动',
            taken_back is not None and counted == 1 and settled is not None and calm.get('idp_gateway_pool_snapshots_put_back_total') == 1
            and calm.get('idp_gateway_pool_starts_total') == 4 and on_disk() == confirmed.text
            and all(same_process(before[service], container(service)) for service in LONG_RUNNING))

    stopped = keeper.stop()
    gone = scrape()
    r.check('叫停看守：以 0 退出。那个地址上没有人了，读不到', stopped['exit'] == 0 and not stopped['stderr'] and gone['status'] is None)
    with socket.socket() as squatter:
        squatter.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        squatter.bind(('127.0.0.1', HOST['metrics']))
        squatter.listen(1)
        shut_out = Keeper('--interval', '1s', '--metrics-listen', METRICS)
        refused = shut_out.ended(15)
    r.note('那个地址被别的进程占着时启动看守：它说的', refused['stderr'])
    r.check('那个地址已经被别的进程占着时启动看守：它不启动，退出码 1，说的是这个地址占不了；一行都没有写。'
            '（看守在跑而监控读不到它，和它没有在跑，从外面分不清。）',
            refused['exit'] == 1 and not shut_out.lines
            and any(f'metrics: listen tcp {METRICS}' in line and 'address already in use' in line for line in refused['stderr']))
    unset = Keeper('--interval', '1s', '--metrics-listen', '')
    unfilled = unset.ended(15)
    r.note('--metrics-listen 是空的时启动看守：它说的', unfilled['stderr'])
    r.check('--metrics-listen 给了却是空的（.env 里漏了 KEEPER_METRICS_LISTEN 时，单元交给它的就是这样）：它不当成"不给指标"，不启动，'
            '退出码 2，一行都没有写；池没有被动过',
            unfilled['exit'] == 2 and not unset.lines and any('--metrics-listen must be host:port' in line for line in unfilled['stderr'])
            and all(same_process(before[service], container(service)) for service in LONG_RUNNING))

    r.case('SH-21', '告警规则（deploy/compose 里的那一份）：一个真的 Prometheus 来读真的看守，池出了事、看守没了，该响的那几条响；'
                    '规则的写法和时长由 promtool 查')
    shipped = [rule['alert'] for group in yaml.safe_load(RULES.read_text(encoding='utf-8'))['groups'] for rule in group['rules']]
    summaries = {rule['alert']: rule['annotations']['summary']
                 for group in yaml.safe_load(RULES.read_text(encoding='utf-8'))['groups'] for rule in group['rules']}
    checked, tested = promtool('check', 'rules', RULES), promtool('test', 'rules', RULE_TESTS)
    r.note('promtool check rules 和 promtool test rules 说的', [' '.join((done.stdout + done.stderr).split()) for done in (checked, tested)])
    r.check('promtool check rules：部署目录里的那份规则写法没有毛病，一共 8 条',
            checked.returncode == 0 and f'SUCCESS: {len(shipped)} rules found' in checked.stdout + checked.stderr and len(shipped) == 8)
    r.check('promtool test rules（rules.test.yml，数是造的）：各条在该响的时候响，没到时长、或者事情自己过去了的不响',
            tested.returncode == 0 and 'SUCCESS' in tested.stdout + tested.stderr and 'FAILED' not in tested.stdout + tested.stderr)

    keeper = Keeper('--interval', '1s', '--reconcile-interval', '3s', '--metrics-listen', METRICS)
    keeper.next(whole, 15)
    started = prometheus_up()

    def target() -> dict:
        return (prometheus('/api/v1/targets').get('activeTargets') or [{}])[0]

    reading = wait_for(lambda: target().get('health') == 'up', 40, every=0.3)
    time.sleep(5)
    loaded = [rule for group in prometheus('/api/v1/rules').get('groups') or [] for rule in group.get('rules') or []]
    quiet = alerts()
    r.note('Prometheus 读的是哪里', [target().get('scrapeUrl'), target().get('labels')])
    r.check('Prometheus 起来了（主机网络，只听回环），装上了那 8 条规则，每一条都算得出来；它读得到看守：规则里写的那个抓取任务是 up',
            started.returncode == 0 and reading is not None and [rule.get('name') for rule in loaded] == shipped
            and all(rule.get('health') == 'ok' and rule.get('type') == 'alerting' for rule in loaded)
            and target().get('labels', {}).get('job') == JOB and target().get('scrapeUrl') == f'http://{METRICS}/metrics')
    r.check('一个安稳的池，看守刚启动、什么都没做过：一条都不响，也没有哪一条在等时长', quiet == {})

    publish(Snapshot([*confirmed.routes, 'n']))   # 绕过发布器放一份没人确认过的文件
    put_back = wait_for(lambda: alerts().get('GatewayPoolSnapshotPutBack') == 'firing', 30, every=0.3)
    said = [alert for alert in prometheus('/api/v1/alerts').get('alerts') or [] if alert['labels']['alertname'] == 'GatewayPoolSnapshotPutBack']
    r.note('看守往回放了一次文件之后 Prometheus 的告警', alerts())
    r.check('有人绕过发布器放了一份文件，看守把记录的那一份放回去：GatewayPoolSnapshotPutBack 响了（这一条不等时长），'
            '带着规则里写的严重程度和那句话；别的没有响',
            put_back is not None and alerts() == {'GatewayPoolSnapshotPutBack': 'firing'} and len(said) == 1
            and said[0]['labels'].get('severity') == 'warning' and said[0]['labels'].get('job') == JOB
            and said[0]['annotations'].get('summary') == summaries['GatewayPoolSnapshotPutBack'])

    with open(lock_file, 'r+b') as held_lock:
        fcntl.flock(held_lock, fcntl.LOCK_EX)   # 一次发布正占着这个池，看守不动手：池要一直不完整下去
        docker('kill', container('agentgateway').get('name', '-'))
        waiting = wait_for(lambda: alerts().get('GatewayPoolNotWhole') == 'pending', 30, every=0.3)
        during = alerts()
    brought = wait_for(lambda: alerts().get('GatewayPoolBroughtBack') == 'firing' and 'GatewayPoolNotWhole' not in alerts(), 60, every=0.3)
    healed = wait_for(answering, 20)
    r.note('网关死着、池被占着时 Prometheus 的告警；看守把网关起回来之后的', [during, alerts()])
    r.check('网关死了，池被占着：GatewayPoolNotWhole 的条件成立了，在等它的 2 分钟（pending），还没有响',
            waiting is not None and during.get('GatewayPoolNotWhole') == 'pending' and 'GatewayPoolBroughtBack' not in during)
    r.check('锁放开，看守把网关起回来：GatewayPoolNotWhole 没有等到 2 分钟就撤了，一次都没有响；GatewayPoolBroughtBack 响了，请求照常',
            brought is not None and healed is not None
            and alerts() == {'GatewayPoolSnapshotPutBack': 'firing', 'GatewayPoolBroughtBack': 'firing'})

    stopped = keeper.stop()
    stopped_at = time.monotonic()
    noticed = wait_for(lambda: alerts().get('GatewayKeeperDown') == 'pending', 30, every=0.3)
    unreachable = target().get('health')
    fired = wait_for(lambda: alerts().get('GatewayKeeperDown') == 'firing', 90, every=0.5)
    fired_after = round(time.monotonic() - stopped_at, 1)
    cry = [alert for alert in prometheus('/api/v1/alerts').get('alerts') or [] if alert['labels']['alertname'] == 'GatewayKeeperDown']
    r.note('看守停了之后过了多少秒 GatewayKeeperDown 响（规则里的时长是 1 分钟）', fired_after if fired is not None else None)
    r.note('看守停了之后 Prometheus 的告警', alerts())
    r.check('叫停看守（以 0 退出）：Prometheus 读不到它了，GatewayKeeperDown 的条件成立，先是在等（pending）',
            stopped['exit'] == 0 and noticed is not None and unreachable == 'down')
    r.check('等满规则里写的 1 分钟，GatewayKeeperDown 响了（真的等，不是造的数）：从看守停下算起 60 到 75 秒，'
            '带着规则里写的严重程度和那句话',
            fired is not None and 60 <= fired_after <= 75 and len(cry) == 1 and cry[0]['state'] == 'firing'
            and cry[0]['labels'].get('severity') == 'critical' and cry[0]['annotations'].get('summary') == summaries['GatewayKeeperDown'])

    removed = docker('rm', '-f', PROMETHEUS)
    closed = wait_for(lambda: prometheus('/api/v1/alerts') == {} and scrape()['status'] is None, 15)
    left = leftovers()
    r.check('拆掉 Prometheus。两个端口上都没有人了；池还好好的，请求照常，配置目录里没有多出东西',
            removed.returncode == 0 and closed is not None and answering() and left == CLEAN
            and on_disk() == confirmed.text and all(container(service).get('running') for service in LONG_RUNNING))


def history_absent_case(r: Results, confirmed: Snapshot):
    """SH-23。不给 --history-dir 时什么都不写。开始时是 SH-18 做完的样子：池好好地在跑，confirmed 是记录里的那一份，
    历史的目录还没有人建过（SH-19 要用它，下一条就建）。它排在 SH-19 前面跑，为的就是这一条要在历史目录出现之前查。"""
    r.case('SH-23', '不给 --history-dir 时什么都不写：前面各条用例跑完之后池的目录下没有历史目录，再跑几条不带历史的命令，也没有多出任何东西')

    def entries() -> list[str]:
        return sorted(p.name for p in POOL.iterdir())

    def strays() -> list[str]:
        """运行目录里任何地方的 releases.log，和 snapshots 目录（本脚本自己放要发布的快照文件的那一个除外）。"""
        found = []
        for where, directories, files in os.walk(RUN):
            found += [os.path.join(where, name) for name in files if name == 'releases.log']
            found += [os.path.join(where, name) for name in directories if name == 'snapshots' and os.path.join(where, name) != str(CONTROL / 'snapshots')]
        return found

    before, left = entries(), leftovers()
    r.note('SH-01 到 SH-18、SH-22 都跑完之后，池的目录下有什么', before)
    r.check('前面各条用例（SH-01 到 SH-18、SH-22，用过 publish、restart、reconcile、place、confirm 和看守，一次都没有给 --history-dir）跑完之后：'
            '池的目录下只有 config、gateway.env、tls，没有历史目录；整个运行目录里没有 releases.log，也没有历史的 snapshots 目录；配置目录里没有多出文件',
            before == ['config', 'gateway.env', 'tls'] and not HISTORY.exists() and not strays() and left == CLEAN)
    again, reconciling = control(confirmed), control_reconcile()
    r.note('现在再不带历史发布同一份、对一次账：发布器写到标准输出的两份 JSON 的键', [sorted(again['report']), sorted(reconciling['report'])])
    r.check('再不带历史发布同一份快照、对一次账（都是池已经在的样子，不改池）：ACTIVE、IN_SYNC；输出里没有 release 和 history_settled，标准错误上什么都没有',
            outcome(again) == (0, 'ACTIVE') and outcome(reconciling) == (0, 'IN_SYNC')
            and not ({'release', 'history_settled'} & (set(again['report']) | set(reconciling['report'])))
            and not again['stderr'] and not reconciling['stderr'])
    half = control(confirmed, '--pool', PROJECT)
    r.check('只给 --pool、不给 --history-dir：退出码 2，说它没有地方可记，池没有被碰过（悄悄丢掉它比报错糟）',
            half['exit'] == 2 and not half['report'] and '--pool was given without --history-dir' in half['stderr'] and on_disk() == confirmed.text)
    r.check('这几条命令之后池的目录下还是没有历史目录，运行目录里还是没有 releases.log，配置目录里没有多出文件',
            entries() == before and not HISTORY.exists() and not strays() and leftovers() == CLEAN)


def history_cases(r: Results, confirmed: Snapshot):
    """SH-24 到 SH-30（docs/adr/ADR-0013.md）：发布历史接在真的池上。开始时池好好地在跑，三个常驻容器和后端都在，confirmed 是
    这个池上最后一次得到确认的那份快照，网关在跑的就是它，看守都停了；结束时也是这样（记录是最后一次发布的那一份）。
    历史目录这时现建：本次运行的池的目录下，0700，归跑这些命令的账号（SH-19 为看守的单元建过一个，空的，先删掉）。
    池的名字是 PROJECT。发布的快照都与 confirmed 同一套启动设置（deadline 45），要重启的那几次另说。"""
    routes = confirmed.routes
    name = container('agentgateway').get('name')
    key = 'terminationMaxDeadline'

    def answering() -> bool:
        return get('a.test', '/quick')['status'] == 200

    def quiet(line: dict) -> bool:
        return not line.get('history_notes')

    shutil.rmtree(HISTORY, ignore_errors=True)
    HISTORY.mkdir(mode=0o700)
    os.chmod(HISTORY, 0o700)
    mode = lambda path: stat.S_IMODE(path.stat().st_mode)   # noqa: E731

    # ---- SH-24 -----------------------------------------------------------------------------------------
    r.case('SH-24', '带着历史发布：publish --history-dir --pool --note 得 ACTIVE，日志里依次是 STAGED、APPLYING、OBSERVING、ACTIVE，快照存下来，'
                    'releases 和 release 读得出来；再发布一份，前一条是 SUPERSEDED；带重启的发布多一步"重启网关"')
    note = 'SH-24：第一份，用来看历史'
    first = Snapshot([*routes, 'h1'])
    done = control(first, *history_flags('--note', note))
    report = done['report']
    r.note('带着历史发布：发布器的输出', report)
    r.check('publish --history-dir <池的目录>/history --pool <名字> --note：退出码 0，结局 ACTIVE，换了文件；输出里有这一条的编号（1），标准错误上什么都没有',
            outcome(done) == (0, 'ACTIVE') and report.get('release') == 1 and report.get('replaced') is True and not done['stderr']
            and on_disk() == first.text and report.get('snapshot') == first.sha256)
    steps = release_steps(1)
    rows = history_rows()
    r.note('releases.log 里第 1 条的各行', [{k: row.get(k) for k in ('state', 'step', 'at')} for row in rows if row.get('release') == 1])
    r.check('releases.log：这一条依次是 STAGED、APPLYING（replace-file）、OBSERVING、ACTIVE；每行是一个 JSON，说的都是这个池',
            steps == ['STAGED', 'APPLYING(replace-file)', 'OBSERVING', 'ACTIVE'] and len(rows) == 4 and {row.get('pool') for row in rows} == {PROJECT}
            and HISTORY_LOG.read_text(encoding='utf-8').endswith('\n'))
    stored = HISTORY_SNAPSHOTS / f'{first.sha256}.yaml'
    before_stored = HISTORY_SNAPSHOTS / f'{confirmed.sha256}.yaml'
    r.check('快照存在 snapshots/ 下，名字是内容的 SHA-256，内容与发布的一字不差；动手之前放着的那一份（confirmed）也存下来了，同样一字不差',
            stored.is_file() and stored.read_bytes() == first.text.encode() and before_stored.is_file()
            and before_stored.read_bytes() == confirmed.text.encode()
            and sorted(p.name for p in HISTORY_SNAPSHOTS.iterdir()) == sorted([stored.name, before_stored.name]))
    r.check('权限：历史目录和 snapshots/ 是 0700，releases.log 和快照文件是 0600（历史目录是本脚本建的，其余两样是发布器建的）',
            mode(HISTORY) == 0o700 and mode(HISTORY_SNAPSHOTS) == 0o700 and mode(HISTORY_LOG) == 0o600
            and mode(stored) == 0o600 and mode(before_stored) == 0o600)
    listing = releases()
    row = listed(listing, 1)
    r.note('releases 的输出', listing['report'])
    r.check('releases：退出码 0，LISTED，一条：ACTIVE，命令 publish，快照是这一份（12 位），带备注；与池的记录比，对得上（match）',
            outcome(listing) == (0, 'LISTED') and len(listing['report'].get('releases') or []) == 1 and row.get('state') == 'ACTIVE'
            and row.get('command') == 'publish' and row.get('snapshot') == first.sha256[:12] and row.get('has_note') is True
            and (listing['report'].get('comparison') or {}).get('status') == 'match'
            and (listing['report'].get('pool_record') or {}).get('snapshot') == first.sha256[:12] and not listing['stderr'])
    detail = shown(1)
    r.note('release --id 1 的输出', detail)
    initiator = detail.get('initiator') or {}
    r.check('release --id 1：SHOWN，每一步都在（STAGED、APPLYING、OBSERVING、ACTIVE，各有时刻）；发起人是发布器证书上的身份和操作系统账号，'
            '输出里写明这是进程自己报的、没有人核实；备注原样在，也标着未经核实',
            outcome(release_detail(1)) == (0, 'SHOWN') and [step['state'] for step in detail.get('steps') or []] == ['STAGED', 'APPLYING', 'OBSERVING', 'ACTIVE']
            and all(step.get('at') for step in detail['steps']) and initiator.get('workload_identity') == pki.ID['publisher']
            and f'(uid {os.getuid()})' in str(initiator.get('os_account')) and 'nobody verified it' in str(initiator.get('status'))
            and detail.get('note') == note and 'nobody verified it' in str(detail.get('note_status'))
            and detail.get('snapshot') == first.sha256 and detail.get('previous') == confirmed.sha256
            and detail.get('expected_digest') and detail.get('expected_digest') == detail.get('observed_digest')
            and detail.get('version') == LOCK['version'] and detail.get('revision') == LOCK['git_revision'])

    second = Snapshot([*routes, 'h2'])
    done = control(second, *history_flags())
    listing = releases()
    r.check('再发布一份：ACTIVE，编号 2；前一条（1）读出来是 SUPERSEDED（读的时候按"后来有更晚的 ACTIVE"推出来的，日志里 1 的最后一行仍是 ACTIVE），'
            '它说被第 2 条取代；与池的记录比仍对得上',
            outcome(done) == (0, 'ACTIVE') and done['report'].get('release') == 2 and listed(listing, 1).get('state') == 'SUPERSEDED'
            and listed(listing, 1).get('recorded_state') == 'ACTIVE' and listed(listing, 1).get('superseded_by') == 2
            and listed(listing, 2).get('state') == 'ACTIVE' and release_steps(1)[-1] == 'ACTIVE'
            and (listing['report'].get('comparison') or {}).get('status') == 'match')

    heavier = Snapshot([*routes, 'h2'], deadline=46)   # 与 second 只差启动时才读的那一项：要重启
    before = container('agentgateway')
    done = control_restart(heavier, name, *history_flags())
    seen = observe()
    after = container('agentgateway')
    steps = release_steps(3)
    r.note('带重启的发布：发布器的输出', done['report'])
    r.note('带重启的发布：第 3 条的各步', steps)
    r.check('带重启的发布（restart --history-dir …）：ACTIVE，换了文件也重启了网关，编号 3；日志里比 publish 多一步 APPLYING（restart-gateway）：'
            'STAGED、APPLYING（replace-file）、APPLYING（restart-gateway）、OBSERVING、ACTIVE',
            outcome(done) == (0, 'ACTIVE') and done['report'].get('release') == 3 and done['report'].get('replaced') is True
            and done['report'].get('restarted') is True and steps == ['STAGED', 'APPLYING(replace-file)', 'APPLYING(restart-gateway)', 'OBSERVING', 'ACTIVE']
            and seen['config'].get(key) == '46s' and after.get('pid') != before.get('pid') and shown(3).get('restarted') is True)
    back = control_restart(second, name, *history_flags())
    seen = observe()
    r.check('再用带重启的发布把启动设置改回来（后面各条要用）：ACTIVE，编号 4，历史里也是一次换文件加一次重启；网关在跑的是 second，启动设置是 45 秒',
            outcome(back) == (0, 'ACTIVE') and back['report'].get('release') == 4 and release_steps(4) == [
                'STAGED', 'APPLYING(replace-file)', 'APPLYING(restart-gateway)', 'OBSERVING', 'ACTIVE']
            and seen['config'].get(key) == '45s' and on_disk() == second.text and routes_seen(['h1', 'h2']) == {'h1': 404, 'h2': 200})
    r.check('四次发布之后没有留下别的东西：配置目录里只有配置文件、它的锁文件和记录；池的目录下是 config、gateway.env、history、tls',
            leftovers() == CLEAN and sorted(p.name for p in POOL.iterdir()) == ['config', 'gateway.env', 'history', 'tls'])

    # ---- SH-25 -----------------------------------------------------------------------------------------
    r.case('SH-25', '先写后做：历史写不进去时 publish 什么都不动；改回来之后同一条命令成功')
    third = Snapshot([*routes, 'h3'])
    if os.geteuid() == 0:
        r.check('这一条要一个受文件权限约束的账号：它把历史目录改成不可写', False)
    else:
        pool_before, directories = pool_now(), (HISTORY, HISTORY_SNAPSHOTS)
        refused = None
        try:
            os.chmod(HISTORY_LOG, 0o400)
            for directory in directories:
                os.chmod(directory, 0o500)
            refused = control(third, *history_flags())
            pool_after = pool_now()
        finally:
            for directory in directories:
                os.chmod(directory, 0o700)
            os.chmod(HISTORY_LOG, 0o600)
        r.note('历史目录不可写时 publish：退出码和标准错误', [refused['exit'], refused['stderr']])
        r.check('历史目录不可写（目录 0500，日志 0400）：publish 退出码 1，没有 JSON，标准错误说的是发布历史写不进去、池什么都没有动',
                refused['exit'] == 1 and not refused['report'] and 'release history could not be written' in refused['stderr']
                and 'nothing was done to the pool' in refused['stderr'])
        r.check('池没有被碰：配置文件还是原来那份，池的记录一个字节没变，网关是同一个进程、摘要没变，历史的日志和快照一个字节、一个文件没变；'
                '经网关的请求照常（现有的路由 200，新的 404）；没有留下别的东西',
                pool_after == pool_before and on_disk() == second.text and routes_seen(['h2', 'h3']) == {'h2': 200, 'h3': 404}
                and leftovers() == CLEAN and mode(HISTORY) == mode(HISTORY_SNAPSHOTS) == 0o700 and mode(HISTORY_LOG) == 0o600)
        done = control(third, *history_flags())
        r.check('目录改回来之后，同一条命令：ACTIVE，编号 5（上一次什么都没有开始，不占编号），历史里是完整的四步',
                outcome(done) == (0, 'ACTIVE') and done['report'].get('release') == 5
                and release_steps(5) == ['STAGED', 'APPLYING(replace-file)', 'OBSERVING', 'ACTIVE'] and on_disk() == third.text
                and routes_seen(['h3']) == {'h3': 200})

    # ---- SH-26 -----------------------------------------------------------------------------------------
    r.case('SH-26', '发布器死在半路，看守收拾，历史跟着有了结局：停在 APPLYING，看守下一次对账把放回去的补成 FAILED、更早没有结局的补成 OVERTAKEN；'
                    '带重启的发布做到一半被杀，对账补成什么就是什么')
    first_open, second_open = Snapshot([*routes, 'k1']), Snapshot([*routes, 'k2'])
    top = history_newest()
    killed_first = control_killed(first_open, extra=tuple(history_flags()))
    stuck = release_steps(top + 1)
    r.note('第一次被杀之后，历史里这一条的各步', stuck)
    r.check('发布器带着历史，刚把文件换上去就被强行杀掉：这一条停在 APPLYING（replace-file）之后，没有结局；配置文件是没人确认过的那份',
            killed_first['killed'] and stuck[:2] == ['STAGED', 'APPLYING(replace-file)'] and stuck[-1] in ('APPLYING(replace-file)', 'OBSERVING')
            and on_disk() == first_open.text and record().get('snapshot') == third.sha256
            and listed(releases(), top + 1).get('state') in ('APPLYING', 'OBSERVING'))
    log_before = HISTORY_LOG.read_bytes()
    plain = control_reconcile()
    r.check('不带历史对一次账（看守没有给 --history-dir 时就是这样）：把记录的那一份放回去（RESTORED，退出码 4）；历史的日志一个字节没动，'
            '那一条仍然没有结局',
            outcome(plain) == (4, 'RESTORED') and on_disk() == third.text and HISTORY_LOG.read_bytes() == log_before
            and release_steps(top + 1) == stuck and 'history_settled' not in plain['report'])
    killed_second = control_killed(second_open, extra=tuple(history_flags()))
    r.check('再来一次：又被杀在换上文件之后（这时历史里已经有一条没有结局的了）；这一条也没有结局',
            killed_second['killed'] and release_steps(top + 2)[:2] == ['STAGED', 'APPLYING(replace-file)']
            and release_steps(top + 2)[-1] in ('APPLYING(replace-file)', 'OBSERVING') and on_disk() == second_open.text)
    keeper = Keeper('--interval', '1s', '--reconcile-interval', '5s', *history_flags())
    healed = keeper.next(restored, 30)
    stopped_with = {number: shown(number) for number in (top + 1, top + 2)}
    listing = releases()
    r.note('看守带着历史收拾之后写的那一行', brief(healed))
    r.note('看守的这一行里补上结局的编号', reconciled(healed).get('history_settled'))
    r.check('带着 --history-dir 的看守在第一次对账时把记录的那一份放回去（RESTORED），并把历史补上：这一行的 reconcile 里 history_settled 是 [%d, %d]；'
            '它没有动容器，没有 history_notes' % (top + 1, top + 2),
            restored(healed) and reconciled(healed).get('history_settled') == [top + 1, top + 2] and quiet(healed) and healed.get('action') == ''
            and whole(healed) and on_disk() == third.text and not keeper.said)
    older, newer = stopped_with[top + 1], stopped_with[top + 2]
    r.check('最新的那一条补成 FAILED（记录确认的是别的快照：没有生效），步骤名是 reconcile，原因写了记录确认的是哪一份、它没有生效；'
            '它之前没有结局的那一条补成 OVERTAKEN（后来的发布越过了它，是否生效不知道，不借用 FAILED），原因说了后一条的编号',
            newer.get('state') == 'FAILED' and release_steps(top + 2)[-1] == 'FAILED(reconcile)' and 'did not take effect' in str(newer.get('reason'))
            and third.sha256[:12] in str(newer.get('reason'))
            and older.get('state') == 'OVERTAKEN' and release_steps(top + 1)[-1] == 'OVERTAKEN(reconcile)'
            and f'a later release ({top + 2})' in str(older.get('reason')) and 'not known' in str(older.get('reason')))
    r.check('releases：这两条分别是 FAILED 和 OVERTAKEN；最后一条 ACTIVE 仍是第 5 条，与池的记录对得上',
            listed(listing, top + 1).get('state') == 'OVERTAKEN' and listed(listing, top + 2).get('state') == 'FAILED'
            and (listing['report'].get('comparison') or {}).get('status') == 'match'
            and ((listing['report'].get('comparison') or {}).get('history_last_active') or {}).get('number') == 5)
    stopped = keeper.stop()
    r.check('叫停看守：以 0 退出，标准错误上什么都没有；再对一次账（带历史），没有什么要补的：IN_SYNC，输出里没有 history_settled',
            stopped['exit'] == 0 and not stopped['stderr'] and (lambda d: outcome(d) == (0, 'IN_SYNC') and 'history_settled' not in d['report'])(
                control_reconcile(*history_flags())))

    middle = Snapshot([*routes, 'k3'], deadline=46)
    top = history_newest()
    killed = restart_killed(middle, name, extra=tuple(history_flags()))
    applied = wait_for(lambda: observe()['config'].get(key) == '46s', 20)
    cut = release_steps(top + 1)
    r.note('带重启的发布做到一半被杀：历史里这一条的各步', cut)
    r.check('带重启的发布：docker 刚把网关重新起来、网关在回读口上答得上话，发布器被强行杀掉：文件是新的，网关已经带着新设置起来，记录里仍是上一份；'
            '历史里这一条停在重启之后，没有结局',
            killed['killed'] and applied is not None and on_disk() == middle.text and record().get('snapshot') == third.sha256
            and cut[:3] == ['STAGED', 'APPLYING(replace-file)', 'APPLYING(restart-gateway)'] and cut[-1] in ('APPLYING(restart-gateway)', 'OBSERVING'))
    keeper = Keeper('--interval', '1s', '--reconcile-interval', '5s', *history_flags())
    half = keeper.next(lambda line: reconciled(line).get('outcome') == 'RESTART_PENDING', 30)
    cut_after = shown(top + 1)
    r.note('带重启的发布做到一半之后看守写的那一行', brief(half))
    r.note('...历史里这一条补成了什么', [cut_after.get('state'), cut_after.get('reason'), release_steps(top + 1)])
    r.check('带着 --history-dir 的看守对账：记录的那一份放回去了，启动设置还差一次重启（RESTART_PENDING，指出了那一项），它不重启网关；'
            '历史里这一条补成了 FAILED（步骤 reconcile）：记录确认的是别的快照，这一份没有生效；补它的是这一次对账，history_settled 是它',
            reconciled(half).get('history_settled') == [top + 1] and reconciled(half).get('restart') == [key] and reconciled(half).get('replaced') is True
            and reconciled(half).get('restarted') is False and on_disk() == third.text and cut_after.get('state') == 'FAILED'
            and release_steps(top + 1)[-1] == 'FAILED(reconcile)' and quiet(half) and half.get('action') == '')
    keeper.stop()
    done = control_restart(None, name, *history_flags())
    seen = observe()
    r.check('不给快照的 restart（用记录里的那一份重启，把启动设置带回来）：ACTIVE，不再换文件，历史里这一条是 STAGED、APPLYING（restart-gateway）、OBSERVING、ACTIVE；'
            '之后对账（带历史）是 IN_SYNC，没有什么要补的',
            outcome(done) == (0, 'ACTIVE') and done['report'].get('replaced') is False and done['report'].get('restarted') is True
            and release_steps(done['report'].get('release', 0)) == ['STAGED', 'APPLYING(restart-gateway)', 'OBSERVING', 'ACTIVE']
            and seen['config'].get(key) == '45s' and on_disk() == third.text
            and (lambda d: outcome(d) == (0, 'IN_SYNC') and 'history_settled' not in d['report'])(control_reconcile(*history_flags()))
            and leftovers() == CLEAN)

    # ---- SH-27 -----------------------------------------------------------------------------------------
    r.case('SH-27', '收尾那一行没有写上：看守的下一次对账把它补成 ACTIVE（原因里写明是事后补的）；或者不等看守、再发布一次同一份，它补全那一条，不另开一条。'
                    'ACTIVE_NOT_RECORDED 和退出码 8 本身卡不准那一瞬间，只有单元测试')

    def drop_last_line() -> dict:
        """脚本替发布器"没写上"最后一行：把 releases.log 的最后一行去掉，模拟池已经换了、收尾那一笔没有写进去。"""
        lines = HISTORY_LOG.read_bytes().splitlines(keepends=True)
        HISTORY_LOG.write_bytes(b''.join(lines[:-1]))   # 原地写：文件的权限不变
        return json.loads(lines[-1])

    fourth = Snapshot([*routes, 'h4'])
    done = control(fourth, *history_flags())
    number = done['report'].get('release', 0)
    dropped = drop_last_line()
    listing = releases()
    r.check('发布一份（ACTIVE），再由本脚本把 releases.log 的最后一行（这一条的 ACTIVE）去掉：这一条停在 OBSERVING；releases 指出历史和池的记录对不上'
            '（池的记录是这一份，历史里最后一条 ACTIVE 是更早的），退出码仍是 0，标准错误上说了一句',
            outcome(done) == (0, 'ACTIVE') and dropped.get('state') == 'ACTIVE' and dropped.get('release') == number
            and release_steps(number) == ['STAGED', 'APPLYING(replace-file)', 'OBSERVING'] and outcome(listing) == (0, 'LISTED')
            and (listing['report'].get('comparison') or {}).get('status') == 'mismatch'
            and 'do not agree' in listing['stderr'] and listed(listing, number).get('state') == 'OBSERVING')
    keeper = Keeper('--interval', '1s', '--reconcile-interval', '5s', *history_flags())
    healed = keeper.next(lambda line: reconciled(line).get('outcome') == 'IN_SYNC', 30)
    keeper.stop()
    after, listing = shown(number), releases()
    r.note('看守补上之后这一条的各步', release_steps(number))
    r.check('带着 --history-dir 的看守在第一次对账时（IN_SYNC）把它补成 ACTIVE：这一行的 history_settled 是 [%d]；补上的那一行步骤名是 reconcile，'
            '原因里写明记录确认的是这份、在这一条开始之后，结局是事后补的' % number,
            reconciled(healed).get('history_settled') == [number] and after.get('state') == 'ACTIVE'
            and release_steps(number)[-1] == 'ACTIVE(reconcile)' and 'written afterwards' in str((after.get('steps') or [{}])[-1].get('reason'))
            and 'made after this release started' in str((after.get('steps') or [{}])[-1].get('reason')) and quiet(healed))
    r.check('releases 的比对重新对得上（match）；这一条的编号没有变，也没有多出新的一条',
            (listing['report'].get('comparison') or {}).get('status') == 'match' and history_newest() == number and not listing['stderr'])

    fifth = Snapshot([*routes, 'h5'])
    done = control(fifth, *history_flags())
    number = done['report'].get('release', 0)
    drop_last_line()
    state = pool_now()
    done = control(fifth, *history_flags())
    detail = shown(number)
    r.note('去掉最后一行之后再跑同样的 publish：发布器的输出', done['report'])
    r.check('去掉最后一行，不等看守，直接再跑同样的 publish：ACTIVE，没有再写文件；它给停着的那一条补了结局，不另开一条（编号还是 %d，'
            '输出里 history_settled 是 [%d]），补的那一行步骤名是 publish-again' % (number, number),
            outcome(done) == (0, 'ACTIVE') and done['report'].get('replaced') is False and done['report'].get('release') == number
            and done['report'].get('history_settled') == [number] and history_newest() == number
            and release_steps(number)[-1] == 'ACTIVE(publish-again)' and detail.get('state') == 'ACTIVE'
            and {k: v for k, v in pool_now().items() if k not in ('log', 'snapshots')} == {k: v for k, v in state.items() if k not in ('log', 'snapshots')})
    listing = releases()
    r.check('releases 的比对对得上（match）；池的记录、配置文件、网关一个字没动',
            (listing['report'].get('comparison') or {}).get('status') == 'match' and on_disk() == fifth.text and leftovers() == CLEAN)

    # ---- SH-28 -----------------------------------------------------------------------------------------
    r.case('SH-28', '回滚：rollback --to <早先的编号> 是一次新的发布，记着回到的是哪一条，历史里已有的各行一个字不变；回到现在放着的、回到 FAILED 的是 REFUSED；'
                    '快照被改了一个字节，非零退出，池不动')
    earlier = shown(1)
    log_before = HISTORY_LOG.read_bytes()
    pool_before, gateway_before = pool_now(), container('agentgateway')
    done = rollback(1)
    new = done['report'].get('release', 0)
    seen = observe()
    detail = shown(new)
    log_after = HISTORY_LOG.read_bytes()
    appended = [json.loads(line) for line in log_after[len(log_before):].splitlines() if line.strip()]
    r.note('回滚：发布器的输出', done['report'])
    r.check('rollback --to 1（第 1 条放上去的是 first）：退出码 0，ACTIVE，是新的一条（编号 %d），换了文件；配置文件是 first 的快照，一字不差' % (history_newest()),
            outcome(done) == (0, 'ACTIVE') and new == history_newest() and new > number and done['report'].get('replaced') is True
            and on_disk() == first.text and done['report'].get('snapshot') == first.sha256)
    r.check('新的一条记着它回到的是第 1 条（rolled_back_to），命令是 rollback，取代的是回滚之前最后一条 ACTIVE；它也有完整的四步',
            detail.get('rolled_back_to') == 1 and detail.get('command') == 'rollback' and detail.get('supersedes') == number
            and [step['state'] for step in detail.get('steps') or []] == ['STAGED', 'APPLYING', 'OBSERVING', 'ACTIVE']
            and listed(releases(), 1).get('state') == 'SUPERSEDED')
    r.check('网关在跑的又是那份快照：回读的摘要等于第 1 条当时确认的摘要，也等于这一次的期望值；路由回来了（first 的 h1 是 200，回滚之前的 h5 是 404）；'
            '网关没有重启',
            seen['reload'] == LOADED and seen['digest'] == earlier.get('observed_digest') == done['report'].get('expected_digest')
            and routes_seen(['h1', 'h5']) == {'h1': 200, 'h5': 404} and same_process(gateway_before, container('agentgateway'))
            and record().get('snapshot') == first.sha256)
    r.check('历史里已有的各行一个字没变：回滚之后的日志，前面一整段就是回滚之前的日志；多出来的行都是新的那一条的',
            log_after.startswith(log_before) and appended and {row.get('release') for row in appended} == {new}
            and [row['state'] for row in appended] == ['STAGED', 'APPLYING', 'OBSERVING', 'ACTIVE'])

    pool_before, log_before = pool_now(), HISTORY_LOG.read_bytes()
    same = rollback(1)
    rows = releases()['report']['releases']
    failed_target = rollback(next(row['number'] for row in rows if row['state'] == 'FAILED'))
    overtaken_target = rollback(next(row['number'] for row in rows if row['state'] == 'OVERTAKEN'))
    missing = rollback(999)
    r.note('回滚到现在放着的 / FAILED 的 / OVERTAKEN 的 / 没有的编号：各自的原因', [same['report'].get('reason'), failed_target['report'].get('reason'),
                                                                    overtaken_target['report'].get('reason'), missing['report'].get('reason')])
    r.check('回到现在放着的这一份（第 1 条，池里正是它）：退出码 3，REFUSED，原因说没有什么可回的；什么都没动（配置文件、记录、网关、日志都没变，没有新的一条）',
            outcome(same) == (3, 'REFUSED') and 'nothing to roll back to' in str(same['report'].get('reason')) and pool_now() == pool_before)
    r.check('回到一条 FAILED 的、一条 OVERTAKEN 的（都没有到过 ACTIVE）、一个没有的编号：都是 REFUSED（退出码 3），说的是没有到过 ACTIVE / 没有这一条；什么都没动',
            outcome(failed_target) == (3, 'REFUSED') and 'never reached ACTIVE' in str(failed_target['report'].get('reason'))
            and 'FAILED' in str(failed_target['report'].get('reason'))
            and outcome(overtaken_target) == (3, 'REFUSED') and 'never reached ACTIVE' in str(overtaken_target['report'].get('reason'))
            and outcome(missing) == (3, 'REFUSED') and 'no release 999' in str(missing['report'].get('reason')) and pool_now() == pool_before)

    target = HISTORY_SNAPSHOTS / f'{second.sha256}.yaml'   # 第 2 条放上去的那一份：不是现在放着的
    original = target.read_bytes()
    altered = None
    try:
        target.write_bytes(b'x' + original[1:])   # 改掉一个字节
        altered = rollback(2)
        after = pool_now()
    finally:
        target.write_bytes(original)
    r.note('快照被改了一个字节之后回滚：退出码和标准错误', [altered['exit'], altered['stderr']])
    r.check('把 snapshots/ 里第 2 条的快照改掉一个字节，再 rollback --to 2：退出码 1，没有 JSON，标准错误说那份快照与它的 SHA-256 对不上、池什么都没有动；'
            '池没有被碰（配置文件、记录、网关、日志、快照文件的名单都没变）',
            altered['exit'] == 1 and not altered['report'] and 'SHA-256' in altered['stderr'] and 'nothing was done to the pool' in altered['stderr']
            and after == pool_before and leftovers() == CLEAN)
    r.check('把那个字节改回去之后，历史里那份快照还是一字不差', target.read_bytes() == second.text.encode() and mode(target) == 0o600)

    # ---- SH-29 -----------------------------------------------------------------------------------------
    r.case('SH-29', '有人漏给了 --history-dir：不带历史的发布之后，releases 指出历史和池的记录对不上；之后带着历史再发布一次，又对得上')
    forgot = Snapshot([*routes, 'h6'])
    last_active = [row for row in releases()['report']['releases'] if row['state'] == 'ACTIVE'][-1]['number']
    done = control(forgot)
    listing = releases()
    comparison = listing['report'].get('comparison') or {}
    r.note('漏给参数之后 releases 的比对', comparison)
    r.check('不带 --history-dir 发布一份（ACTIVE，输出里没有 release）：releases 退出码仍是 0，比对是 mismatch：池的记录是这一份，历史里最后一条 ACTIVE 是第 %d 条；'
            '输出里的 detail 和标准错误都这样说' % last_active,
            outcome(done) == (0, 'ACTIVE') and 'release' not in done['report'] and outcome(listing) == (0, 'LISTED') and comparison.get('status') == 'mismatch'
            and (comparison.get('history_last_active') or {}).get('number') == last_active
            and (listing['report'].get('pool_record') or {}).get('snapshot') == forgot.sha256[:12]
            and forgot.sha256[:12] in str(comparison.get('detail')) and 'do not agree' in listing['stderr'])
    noted = Snapshot([*routes, 'h7'])
    done = control(noted, *history_flags())
    listing = releases()
    r.check('之后带着历史再发布一次：ACTIVE，新的一条；比对又对得上（match），历史里最后一条 ACTIVE 就是它',
            outcome(done) == (0, 'ACTIVE') and done['report'].get('release') == history_newest()
            and (listing['report'].get('comparison') or {}).get('status') == 'match' and not listing['stderr']
            and ((listing['report'].get('comparison') or {}).get('history_last_active') or {}).get('number') == done['report'].get('release'))

    # ---- SH-30 -----------------------------------------------------------------------------------------
    r.case('SH-30', '开机不靠历史：历史目录挪走、或日志写坏，断电再 docker compose up -d，池照常起来；带着 --history-dir 的看守照常看容器、对账、起容器，'
                    '只是不补历史，并说出历史的问题；目录放回去之后恢复正常')
    log_original = HISTORY_LOG.read_bytes()
    away = HISTORY.with_name('history.away')
    clean_place = ('IN_PLACE', 'IN_SYNC')

    def one_boot():
        """断电（三个常驻容器同时被杀），再跑部署文件的启动命令；-> 是否断了，启动的结果。"""
        dark = power_cut()
        time.sleep(1)
        return dark, boot(('a',))

    def booted(dark: bool, seen: dict) -> bool:
        return (dark and seen['exit'] == 0 and outcome(seen['place']) == (0, 'IN_PLACE') and outcome(seen['confirm']) == (0, 'IN_SYNC')
                and in_order(seen) and gated(seen, 'a') and not ({'release', 'history_settled'} & (set(seen['place']['report']) | set(seen['confirm']['report'])))
                and answering())

    def works_with_a_bad_history() -> tuple:
        """带着 --history-dir 的看守在历史有毛病时：第一行；杀掉网关之后的那一行；有人绕过发布器放了一份没人确认过的文件之后，
        它下一次对账收回去的那一行；叫停它。"""
        keeper = Keeper('--interval', '1s', '--reconcile-interval', '3s', *history_flags())
        first_line = keeper.next(lambda line: True, 20)
        mark = keeper.mark()
        docker('kill', container('agentgateway').get('name', '-'))
        revived = keeper.next(acted, 40, mark)
        healed = wait_for(answering, 20)
        mark = keeper.mark()
        publish(Snapshot([*routes, 'z']))   # 绕过发布器
        put_back = keeper.next(restored, 20, mark)
        stopped = keeper.stop()
        return first_line, revived, healed, put_back, stopped, list(keeper.said)

    os.rename(HISTORY, away)
    try:
        dark, seen = one_boot()
        r.note('历史目录不在时断电再启动', timeline(seen))
        r.check('历史目录挪走（整个不在了），断电（三个常驻容器同时被强行杀掉），docker compose up -d：退出码 0，place 是 IN_PLACE，confirm 是 IN_SYNC，'
                '先后照部署文件来，confirm 跑完之前没有应答；请求照常；place 和 confirm 的输出里没有历史的东西（它们不挂历史目录）',
                booted(dark, seen))
        keeper_first, revived, healed, put_back, stopped, said = works_with_a_bad_history()
        r.note('历史目录不在时带着 --history-dir 的看守：第一行', brief(keeper_first))
        r.note('...它在标准错误上说的', said)
        r.note('...第一行和杀掉网关之后那一行里的 history_notes', [keeper_first.get('history_notes'), revived.get('history_notes')])
        r.check('历史目录不在时启动带着 --history-dir 的看守：它没有退出，第一行说三个容器都在跑（whole）、账对得上（IN_SYNC），没有动手；标准错误上有一句，'
                '说发布历史打不开、不补历史；这一行的 history_notes 说了补不成（它的原因是历史目录不在）',
                whole(keeper_first) and keeper_first.get('action') == '' and reconciled(keeper_first).get('outcome') == 'IN_SYNC'
                and any('release history could not be opened' in line for line in said)
                and any('history' in note and 'no such file' in note for note in keeper_first.get('history_notes') or []))
        r.check('杀掉网关：看守照常把它起回来（start，修好了），账对得上（IN_SYNC），请求照常；有人绕过发布器放了一份没人确认过的文件，它下一次对账照常收回去'
                '（RESTORED），那一行的 history_notes 说了补不成；叫停它以 0 退出',
                revived.get('action') == 'start' and revived.get('condition') == 'down' and revived.get('repaired') is True
                and reconciled(revived).get('outcome') == 'IN_SYNC' and healed is not None and restored(put_back)
                and reconciled(put_back).get('previous') == Snapshot([*routes, 'z']).sha256 and on_disk() == noted.text
                and bool(put_back.get('history_notes')) and stopped['exit'] == 0)
        reading = releases()
        r.check('releases 对着不在的目录：退出码 1，说历史目录必须已经存在、不自动创建；发布命令带着它也是（池不动）',
                reading['exit'] == 1 and not reading['report'] and 'must exist' in reading['stderr']
                and (lambda d: d['exit'] == 1 and 'history' in d['stderr'] and on_disk() == noted.text)(control(Snapshot([*routes, 'h8']), *history_flags())))
    finally:
        if away.exists():
            os.rename(away, HISTORY)
    r.check('目录放回去之后恢复正常：releases 对得上（match）', (releases()['report'].get('comparison') or {}).get('status') == 'match' and HISTORY_LOG.read_bytes() == log_original)

    try:
        HISTORY_LOG.write_bytes(b'this line is not a release\n' + log_original)   # 中间的一行读不懂：历史坏了，不猜，不跳过
        dark, seen = one_boot()
        r.check('日志写坏（第一行读不懂，后面的还在），断电，docker compose up -d：与历史好好的时候一样：IN_PLACE、IN_SYNC，先后照部署文件来，请求照常',
                booted(dark, seen))
        keeper_first, revived, healed, put_back, stopped, said = works_with_a_bad_history()
        r.note('日志坏了时带着 --history-dir 的看守：第一行', brief(keeper_first))
        r.note('...第一行里的 history_notes', keeper_first.get('history_notes'))
        r.check('日志坏了时带着 --history-dir 的看守：照常启动，第一行 whole、IN_SYNC，没有动手；这一行的 history_notes 说历史坏了、补不成；'
                '杀掉网关它照常起回来（start，修好了，IN_SYNC），请求照常；有人绕过发布器放了文件它照常收回去（RESTORED）；叫停它以 0 退出',
                whole(keeper_first) and keeper_first.get('action') == '' and reconciled(keeper_first).get('outcome') == 'IN_SYNC'
                and any('damaged' in note for note in keeper_first.get('history_notes') or [])
                and revived.get('action') == 'start' and revived.get('repaired') is True and reconciled(revived).get('outcome') == 'IN_SYNC'
                and healed is not None and restored(put_back) and on_disk() == noted.text and stopped['exit'] == 0)
        reading, before = releases(), pool_now()
        refused = control(Snapshot([*routes, 'h9']), *history_flags())
        r.check('日志坏了时：releases 退出码 1，说历史坏了；publish 带着它也是退出码 1，池什么都没有动（先写后做）；对账带着它，结局和退出码照常（IN_SYNC，0）',
                reading['exit'] == 1 and 'damaged' in reading['stderr'] and refused['exit'] == 1 and not refused['report'] and 'damaged' in refused['stderr']
                and pool_now() == before and (lambda d: outcome(d) == (0, 'IN_SYNC') and 'damaged' in d['stderr'])(control_reconcile(*history_flags())))
    finally:
        HISTORY_LOG.write_bytes(log_original)
    again = control(Snapshot([*routes, 'h10']), *history_flags())
    keeper = Keeper('--interval', '1s', '--reconcile-interval', '3s', *history_flags())
    plain_line = keeper.next(lambda line: True, 20)
    stopped = keeper.stop()
    listing = releases()
    r.check('日志改回去之后一切正常：publish 带着历史 ACTIVE，新的一条；带着 --history-dir 的看守第一行没有 history_notes，标准错误上什么都没有；releases 对得上',
            outcome(again) == (0, 'ACTIVE') and again['report'].get('release') == history_newest() and quiet(plain_line) and not stopped['stderr']
            and reconciled(plain_line).get('outcome') == 'IN_SYNC' and (listing['report'].get('comparison') or {}).get('status') == 'match')
    r.check('这一条用例做完之后池是好的：三个常驻容器都在，请求照常，配置目录里没有多出东西；池的目录下是 config、gateway.env、history、tls，'
            '历史目录是 0700',
            all(container(service).get('running') for service in LONG_RUNNING) and answering() and leftovers() == CLEAN
            and sorted(p.name for p in POOL.iterdir()) == ['config', 'gateway.env', 'history', 'tls'] and mode(HISTORY) == 0o700)


if __name__ == '__main__':
    sys.exit(main())
