#!/usr/bin/env python3
"""在本机用 docker compose 验证单机上的一个网关池。跑的就是正式的部署文件（deploy/compose/compose.yml），
只另外套上一个会回话的后端（echo.yml）。网关跑在容器里，配置目录挂载进去；发布就是把目录里的配置文件整份
换掉（写临时文件，再改名盖上去），网关不重启；之后经回读口确认它在跑的是哪一份。

    .venv/bin/python tests/integration/compose/run.py        # 六分钟左右；自己起，跑完自己拆（需要 docker 和 go）

真的部分：docker compose 和部署文件本身、锁定的上游 agentgateway 镜像（按摘要引用）、网关前面的那层 nginx
（与黑盒套件同一个镜像，配置只差端口）、网关自己的回读口（双向 TLS），以及发布器（cmd/gateway-control，
现场用 Go 构建：SH-09 起由本脚本在本机上跑它；部署文件的 place 和 confirm 两步跑的也是这同一个文件）。
配置是一份只有几条路由的小文件，路由的后端是同一个 compose 网络里一个会回话的小服务；没有 JWT、ExtAuthZ
和凭证，那些由黑盒套件覆盖。

一个池在单机上是什么（deploy/compose/compose.yml 里的五个服务，按启动的先后）：
    netns         什么都不做，只占着网络命名空间和本机上的两个端口。front 和网关都接在它里面，相当于
                  Kubernetes 上的同一个 Pod；两个可以各自重启。
    place         跑完就退出。网关启动之前，把记录里确认过的那一份配置放到位（gateway-control place）。
    agentgateway  收业务请求的监听、管理和指标端口只绑回环；另开一个回读口（本机回环 27619），要发布器的
                  客户端证书，只转发 /config_dump 和 /api/runtime 两个 GET。配置目录以只读方式挂进容器。
    confirm       跑完就退出。网关起来之后对一次账（gateway-control reconcile）；对上了，front 才启动。
    front         nginx。对外收业务请求的只有它（本机回环 27620）。
另有 echo（echo.yml）：路由的后端，不属于部署文件。

SH-01 到 SH-08 由本脚本扮演发布器：往挂载的目录里写文件，从本机经回读口读网关在跑什么。这几条看的是
网关和这种发布方式本身。SH-09 到 SH-11 换成真的发布器的三条命令（publish、reconcile、restart），本脚本
在旁边看，并且替它制造麻烦：把它强行杀掉，绕过它往目录里写文件、删文件，带着坏文件重启网关。
SH-12 到 SH-14 看部署文件：断电之后再启动的先后，启动时对不上会怎样，停，头一次安装。断电是把三个常驻
容器同时强行杀掉来模拟的；真的重启一台机器没有做过。SH-15 是网关自己的一个性质，开机的先后与它有关。

占用本机回环上的 27618 到 27620，与黑盒套件、Gatekeeper 联调和 Kubernetes 套件的端口重叠，不能同时跑。
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
STALE = (POOL, PKI, CONTROL, RUN / 'staging', RUN / 'single', RUN / 'expansion')   # 每次运行前后都清掉
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
SCRATCH = f'{PROJECT}-scratch'   # 另起的那个网关容器：发布前的离线加载用它，"只挂单个文件"的对照也用它
HOST = {'front': 27620, 'readback': 27619, 'scratch': 27618}   # 本机回环上的端口
# netns 占着的那个网络命名空间里的端口：front 和网关都接在里面。
PORT = {'front': 8080, 'callers': 8081, 'readback': 8443, 'admin': 15000, 'stats': 15020, 'readiness': 15021}
ECHO_PORT = 8000
GATEWAY_FILES = ('gateway-readback.crt', 'gateway-readback.key', 'gateway.crt', 'gateway.key', 'ca.crt')
RUN_AS = f'{os.getuid()}:{os.getgid()}'
LOADED = {'synchronized': True, 'lastError': None}
SESSION_KEY = secrets.token_hex(32)
SERVICES = ('netns', 'place', 'agentgateway', 'confirm', 'front')   # 部署文件里的五个，按启动的先后
LONG_RUNNING = ('netns', 'agentgateway', 'front')                   # 其中常驻的三个
CONFIRM_SECONDS = 10                                                # confirm 这一步等网关的时限
probe.PORTS = {'front': HOST['front']}   # probe.two_hosts 往哪个端口发


def pool_settings() -> dict:
    """部署文件要的各个变量在这次运行里的值：运维会写进 .env 的那些。"""
    return {
        'CALLERS_LISTEN': f"127.0.0.1:{HOST['front']}", 'READBACK_PORT': str(HOST['readback']), 'READBACK_NAME': pki.READBACK_NAME,
        'POOL_DIR': str(POOL), 'GATEWAY_USER': RUN_AS, 'CONTROL_USER': RUN_AS, 'GATEWAY_ENV_FILE': str(POOL / 'gateway.env'),
        'GATEWAY_CONTROL': str(CONTROL_BINARY),
        'PUBLISHER_CERT': str(PKI / 'publisher.crt'), 'PUBLISHER_KEY': str(PKI / 'publisher.key'), 'READBACK_CA': str(PKI / 'ca.crt'),
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


def control_command(snapshot: Snapshot) -> list[str]:
    return [str(CONTROL_BINARY), 'publish', '--snapshot', snapshot_file(snapshot), *pool_flags(), *staging_flags()]


def restart_command(snapshot: Snapshot | None, target: str, *extra: str) -> list[str]:
    """gateway-control restart 的命令行。target 是要重启的容器；snapshot 为 None 时不给快照，
    用的是这个池上最后一次得到确认的那一份。"""
    chosen = ['--snapshot', snapshot_file(snapshot)] if snapshot else []
    return [str(CONTROL_BINARY), 'restart', '--container', target, *chosen, *pool_flags(), *staging_flags(), *extra]


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


def control(snapshot: Snapshot) -> dict:
    """让真的发布器发布这份快照。"""
    return run_control(control_command(snapshot))


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


def control_killed(snapshot: Snapshot, during: str = 'swap') -> dict:
    """让真的发布器发布这份快照，中途把它强行杀掉（SIGKILL）：它来不及收拾。
    during 是 'swap'：它刚把文件换上去；是 'staging'：它做离线加载用的临时容器刚出现。
    killed 为假表示没等到那一刻。"""
    if during == 'swap':
        def reached() -> bool:
            return on_disk() == snapshot.text
    else:
        def reached() -> bool:
            return bool(scratch_containers())
    running = subprocess.Popen(control_command(snapshot), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    seen = wait_for(lambda: reached() or running.poll() is not None, 60, every=0.01)
    killed = seen is not None and running.poll() is None
    running.kill()
    running.wait(30)
    return {'killed': killed, 'exit': running.returncode}


def restart_killed(snapshot: Snapshot, target: str) -> dict:
    """让真的发布器做一次带重启的发布；docker 刚把网关容器重新起来（发布器还在等它报告），就把发布器强行杀掉。
    killed 为假表示没等到那一刻。"""
    def started() -> str:
        return docker('inspect', '-f', '{{.State.StartedAt}}', target).stdout.strip()
    before = started()
    running = subprocess.Popen(restart_command(snapshot, target), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    seen = wait_for(lambda: started() not in ('', before) or running.poll() is not None, 90, every=0.01)
    killed = seen is not None and running.poll() is None
    running.kill()
    running.wait(30)
    return {'killed': killed, 'exit': running.returncode}


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
    c = container(service)
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
    """docker 自 since（Unix 时间）以来给部署文件里的五个容器发过的信号，和它们的退出，按先后：
    "kill 服务 信号" 和 "die 服务"。"""
    done = docker('events', '--since', f'{since:.3f}', '--until', str(int(time.time()) + 1),
                  '--filter', f'label=com.docker.compose.project={PROJECT}', '--format',
                  '{{.TimeNano}} {{.Action}} {{index .Actor.Attributes "com.docker.compose.service"}} {{index .Actor.Attributes "signal"}}')
    rows = [line.split() for line in done.stdout.splitlines()]
    rows = [row for row in rows if len(row) >= 3 and row[0].isdigit() and row[1] in ('kill', 'die') and row[2] in SERVICES]
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


def boot(routes: tuple = ('a',)) -> dict:
    """跑一次部署文件的启动命令（docker compose up -d，开机时那个单元跑的就是它），这期间一直有人在敲业务端口。
    时刻都是 Unix 时间。
    -> exit、said：命令的退出码和它最后说的那一行；began、seconds：命令开始的时刻和用了多少秒；
       place、confirm：这两步这一次的结果（见 step）；started：五个容器各自最近一次启动的时刻；
       answers：每条路由上各种结果各有多少个；first：第一个应答是什么时候到的（一个都没有时是 None），
       first_sent：得到它的那个请求是什么时候发出的；unanswered：在那之前落空的请求有多少个。"""
    knock, began = Knock(routes), time.time()
    up = compose('up', '-d')
    seconds = round(time.time() - began, 2)
    if up.returncode == 0:
        wait_for(lambda: get(f'{routes[0]}.test', '/quick')['status'] is not None, 10)
    time.sleep(1)   # front 开了之后再敲一秒：每条路由都问到几次
    log = knock.finish()
    answered = min((q for q in log if q['status'] is not None), key=lambda q: q['back'], default=None)
    first = answered['back'] if answered else None
    return {'exit': up.returncode, 'said': (up.stderr.strip().splitlines() or [''])[-1].strip(), 'began': began, 'seconds': seconds,
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
    """容器、网络和本次运行的证书都不留；留下的只有 .run/result.json。"""
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
    for stale in STALE:
        shutil.rmtree(stale, ignore_errors=True)
    POOL_ENV.unlink(missing_ok=True)


def main() -> int:
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
    r.check('五个容器都没有重启策略：docker 自己不会去起其中任何一个',
            all(policy.get('Name') in ('no', '') and not policy.get('MaximumRetryCount') for policy in policies.values()) and len(policies) == 5)
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
    stopped = compose('stop', *SERVICES)   # 只点部署文件里的五个：后端 echo 是这套用例自己加的，不跟着停
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


if __name__ == '__main__':
    sys.exit(main())
