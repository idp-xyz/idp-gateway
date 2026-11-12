#!/usr/bin/env python3
"""在本机用 docker compose 验证单机上的发布方式：网关跑在容器里，配置目录挂载进去；发布就是把目录里的
配置文件整份换掉（写临时文件，再改名盖上去），网关不重启；之后经回读口确认它在跑的是哪一份。

    .venv/bin/python tests/integration/compose/run.py        # 三分半到四分钟；自己起，跑完自己拆（需要 docker 和 go）

真的部分：docker compose、锁定的上游 agentgateway 镜像（按摘要引用）、网关前面的那层 nginx（与黑盒套件
同一个镜像、同一份配置，只换了端口）、网关自己的回读口（双向 TLS），以及最后三条用例里的发布器
（cmd/gateway-control，现场用 Go 构建）。配置是一份只有几条路由的小文件，路由的后端是同一个 compose
网络里一个会回话的小服务；没有 JWT、ExtAuthZ 和凭证，那些由黑盒套件覆盖。

一个池在单机上是什么（compose.yml）：
    front         nginx。对外收业务请求的只有它（本机回环 27620）。
    agentgateway  与 front 共用一个网络命名空间，相当于 Kubernetes 上的同一个 Pod。收业务请求的监听、
                  管理和指标端口只绑回环；另开一个回读口（本机回环 27619），要发布器的客户端证书，
                  只转发 /config_dump 和 /api/runtime 两个 GET。配置目录以只读方式挂进容器。
    echo          路由的后端。
SH-01 到 SH-08 由本脚本扮演发布器：往挂载的目录里写文件，从本机经回读口读网关在跑什么。这几条看的是
网关和这种发布方式本身。SH-09 到 SH-11 换成真的发布器的三条命令（publish、reconcile、restart），本脚本
在旁边看，并且替它制造麻烦：把它强行杀掉，绕过它往目录里写文件、删文件，带着坏文件重启网关。

占用本机回环上的 27618 到 27620，与黑盒套件、Gatekeeper 联调和 Kubernetes 套件的端口重叠，不能同时跑。
"""
from __future__ import annotations
import base64, collections, hashlib, http.client, json, os, secrets, shutil, signal, socket, stat, subprocess, sys, threading, time
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BLACKBOX = ROOT / 'tests/acceptance/blackbox'
KUBERNETES = ROOT / 'tests/integration/kubernetes'
sys.path[:0] = [str(BLACKBOX), str(KUBERNETES)]
import pin  # noqa: E402
import pki  # noqa: E402
import probe  # noqa: E402  Kubernetes 套件的那个：这里用它发"两个 Host 头"的函数，它的 echo 也是这里的后端

RUN = HERE / '.run'
POOL = RUN / 'pool'   # 挂进网关容器的两个目录：config 由发布器写，tls 是网关自己的证书
PKI = RUN / 'pki'     # 本次运行的全套证书。发布器的证书只在这里，不进网关容器
# 真的发布器（SH-09 到 SH-11）用的东西：现场构建的二进制；它做离线加载用的另一套证书（另一个 CA）、挂进临时容器的
# 证书目录、放候选配置的目录；要发布的快照文件。
CONTROL = RUN / 'control'
CONTROL_BINARY = CONTROL / 'bin' / 'gateway-control'
ONLY_IN_STAGING = 'only-in-staging.crt'   # 只有离线加载那边才有的一个文件
RECORD = '.config.yaml.confirmed'         # 发布器留在配置目录里的记录
STALE = (POOL, PKI, CONTROL, RUN / 'front', RUN / 'staging', RUN / 'single', RUN / 'expansion')   # 每次运行前后都清掉
LOCK = pin.lock()
GATEWAY_IMAGE = pin.image_reference(LOCK)   # 上游镜像，按多平台索引的摘要引用
# 与黑盒套件同一个前置 nginx（tests/contracts 里有一条测试检查几套用例一致）。
FRONT_IMAGE = ('public.ecr.aws/nginx/nginx-unprivileged:stable-alpine'
               '@sha256:c3fc8fa482be50ef709c6438eb1bc98d50dbfe5a9b48be90711b8814f4dfd701')
# 回话的后端用它：只是一个带 Python 的镜像。
TOOLS_IMAGE = ('public.ecr.aws/docker/library/python:3.13-alpine'
               '@sha256:1e1f6334529d1fb26a2ef619d7cffb30a7c7d7cc1cc7338ebee283a58d1aeaca')
# 前置 nginx 的配置就是黑盒套件的那一份，只换监听的端口和转给谁。
FRONT_DIFFERENCES = [('listen 127.0.0.1:27620;', 'listen 8080;'), ('proxy_pass http://127.0.0.1:27611;', 'proxy_pass http://127.0.0.1:8081;')]

PROJECT = 'idp-gateway-compose'
SCRATCH = f'{PROJECT}-scratch'   # 另起的那个网关容器：发布前的离线加载用它，"只挂单个文件"的对照也用它
HOST = {'front': 27620, 'readback': 27619, 'scratch': 27618}   # 本机回环上的端口
# front 和网关共用的那个网络命名空间里的端口。
PORT = {'front': 8080, 'callers': 8081, 'readback': 8443, 'admin': 15000, 'stats': 15020, 'readiness': 15021}
ECHO_PORT = 8000
GATEWAY_FILES = ('gateway-readback.crt', 'gateway-readback.key', 'gateway.crt', 'gateway.key', 'ca.crt')
RUN_AS = f'{os.getuid()}:{os.getgid()}'
LOADED = {'synchronized': True, 'lastError': None}
COMPOSE_ENV = {**os.environ, 'FRONT_IMAGE': FRONT_IMAGE, 'GATEWAY_IMAGE': GATEWAY_IMAGE, 'TOOLS_IMAGE': TOOLS_IMAGE,
               'RUN_DIR': str(RUN), 'RUN_AS': RUN_AS, 'PROBE': str(KUBERNETES / 'probe.py'),
               'FRONT_PORT': str(HOST['front']), 'READBACK_PORT': str(HOST['readback']), 'SESSION_KEY': secrets.token_hex(32)}
probe.PORTS = {'front': HOST['front']}   # probe.two_hosts 往哪个端口发


def die(message: str):
    print('run.py:', message, file=sys.stderr)
    raise SystemExit(2)


def docker(*argv: str, timeout: float = 300) -> subprocess.CompletedProcess:
    return subprocess.run(['docker', *argv], capture_output=True, text=True, timeout=timeout)


def compose(*argv: str, timeout: float = 300) -> subprocess.CompletedProcess:
    return subprocess.run(['docker', 'compose', '-p', PROJECT, '-f', str(HERE / 'compose.yml'), *argv],
                          capture_output=True, text=True, timeout=timeout, env=COMPOSE_ENV)


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
        built = subprocess.run([go, 'build', '-o', str(CONTROL_BINARY), './cmd/gateway-control'],
                               cwd=ROOT, capture_output=True, text=True, timeout=600)
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
            'pid': c['State']['Pid'],
            'restarts': c['RestartCount'], 'image': c['Config']['Image'], 'network': c['HostConfig']['NetworkMode'],
            'published': {port: sorted(f"{b['HostIp']}:{b['HostPort']}" for b in bindings)
                          for port, bindings in (c['NetworkSettings'].get('Ports') or {}).items() if bindings},
            'mounts': {m['Destination']: {'type': m['Type'], 'source': m['Source'], 'writable': m['RW']} for m in c.get('Mounts') or []}}


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
    """从同一个 compose 网络上的另一个容器（echo）去连 front 那个网络命名空间里的各端口。
    0 是连上了，111 是被拒绝。"""
    code = ('import json, socket\n'
            'seen = {}\n'
            f'for name, port in {PORT!r}.items():\n'
            '    with socket.socket() as s:\n'
            '        s.settimeout(3)\n'
            "        seen[name] = s.connect_ex(('front', port))\n"
            'print(json.dumps(seen))\n')
    done = docker('exec', container('echo').get('id', '-'), 'python', '-c', code)
    try:
        return json.loads(done.stdout)
    except ValueError:
        return {'error': (done.stderr or done.stdout).strip()[-200:]}


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
        self.cases, self.current = [], None

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
def front_config() -> str:
    text = (BLACKBOX / 'front.nginx.conf').read_text(encoding='utf-8')
    for old, new in FRONT_DIFFERENCES:
        if text.count(old) != 1:
            die(f'黑盒套件的 front.nginx.conf 里找不到恰好一处 {old!r}：FRONT_DIFFERENCES 要跟着改')
        text = text.replace(old, new)
    return text


def prepare():
    """本次运行的目录：证书现做；网关容器只拿到它自己的那几个文件。"""
    RUN.mkdir(exist_ok=True)
    os.chmod(RUN, 0o700)
    for stale in STALE:
        shutil.rmtree(stale, ignore_errors=True)
    pki.issue(PKI)
    (POOL / 'config').mkdir(parents=True)
    (POOL / 'tls').mkdir()
    for name in GATEWAY_FILES:
        shutil.copy2(PKI / name, POOL / 'tls' / name)
    (RUN / 'front').mkdir()
    (RUN / 'front' / 'nginx.conf').write_text(front_config(), encoding='utf-8')


def teardown():
    """容器、网络和本次运行的证书都不留；留下的只有 .run/result.json。"""
    compose('down', '--volumes', '--remove-orphans', '--timeout', '5')
    docker('rm', '-f', SCRATCH)
    for stale in STALE:
        shutil.rmtree(stale, ignore_errors=True)


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
                'compose': compose('version', '--short').stdout.strip()}
    if not versions['docker'] or not versions['compose']:
        die('需要 docker 和 docker compose')
    teardown()   # 上一次没跑完留下的
    prepare()
    build_control()
    one, two, bad = Snapshot(['a']), Snapshot(['a', 'b']), Snapshot(['a', 'b', 'c'], unloadable='c')
    tuned = Snapshot(['a', 'b'], deadline=46)   # 与 two 只差 config 段里的一项
    r = Results()

    r.case('SH-01', '网关在容器里，从挂载进去的目录启动')
    staged = stage(one)
    r.check('发布前，锁定的镜像在另一个容器里加载了这份快照', staged.get('loaded'))
    one.expected = staged.get('digest')
    publish(one)
    up = compose('up', '-d', '--wait', '--wait-timeout', '60')
    if up.returncode != 0:
        die(f'compose 起不来：{up.stderr.strip()[-600:]}')
    if wait_for(lambda: observe()['digest'] is not None, 30) is None:
        die('30 秒内回读口没有给出运行配置：' + compose('logs', '--tail', '20', 'agentgateway').stdout[-600:])
    gateway, front, seen = container('agentgateway'), container('front'), observe()
    r.check('三个容器都在跑', all(container(name).get('running') for name in ('front', 'agentgateway', 'echo')))
    r.note('网关容器的镜像', gateway.get('image'))
    r.check('网关容器跑的是按摘要引用的锁定镜像，它报告的版本和提交与锁定文件一致',
            gateway.get('image') == GATEWAY_IMAGE
            and (seen['build'].get('version'), seen['build'].get('gitRevision')) == (LOCK['version'], LOCK['git_revision']))
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
    r.note('本机上映射出来的端口', {'front': front.get('published'), 'agentgateway': gateway.get('published')})
    r.check('本机上只映射了两个端口，都只在回环上：front 的端口和回读口',
            front.get('published') == {f"{PORT['front']}/tcp": [f"127.0.0.1:{HOST['front']}"],
                                       f"{PORT['readback']}/tcp": [f"127.0.0.1:{HOST['readback']}"]}
            and gateway.get('published') == {} and str(gateway.get('network')).startswith('container:'))
    connect = from_another_container()
    r.note('从同一个网络上的另一个容器连各端口的结果（0 是连上了，111 是被拒绝）', connect)
    r.check('从另一个容器连不上网关收业务请求的监听、管理、指标和就绪端口（都只绑回环）',
            connect.get('callers') == connect.get('admin') == connect.get('stats') == connect.get('readiness') == 111)
    r.check('...连得上的只有 front 的端口和回读口', connect.get('front') == connect.get('readback') == 0)
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
    r.note('会话密钥在不在网关报告的 config 段里', COMPOSE_ENV['SESSION_KEY'] in json.dumps(running))
    r.check('记录里的启动设置每一项只有指纹（64 个十六进制字符）：项目就是网关 config 段里除了随环境变的两项之外的那些，会话密钥不在记录里',
            len(startup) > 20 and set(startup) == set(running) - {'dns', 'numWorkerThreads'}
            and all(isinstance(v, str) and len(v) == 64 and not v.strip('0123456789abcdef') for v in startup.values())
            and COMPOSE_ENV['SESSION_KEY'] not in json.dumps(kept))

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
    compose('start', 'agentgateway')   # 由脚本把网关起起来
    up = wait_for(lambda: observe()['digest'] is not None, 30)
    r.check('把网关起起来之后：它读到的是放回去的那一份，对账是 IN_SYNC，请求照常',
            up is not None and outcome(control_reconcile()) == (0, 'IN_SYNC') and observe()['reload'] == LOADED
            and routes_seen(['a', 'l']) == {'a': 200, 'l': 200})

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

    print(f"\ndocker {versions['docker']}，compose {versions['compose']}，agentgateway {LOCK['version']}（{GATEWAY_IMAGE}）")
    r.report()
    failed = r.failed()
    (RUN / 'result.json').write_text(json.dumps({**versions, 'agentgateway': LOCK['version'], 'image': GATEWAY_IMAGE,
                                                 'front_image': FRONT_IMAGE, 'cases': r.cases}, ensure_ascii=False, indent=1), encoding='utf-8')
    print(f"\n{len(r.cases) - len(failed)}/{len(r.cases)}（详细结果在 {RUN / 'result.json'}）")
    return int(bool(failed))


if __name__ == '__main__':
    sys.exit(main())
