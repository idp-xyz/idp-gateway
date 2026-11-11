#!/usr/bin/env python3
"""在本机的 kind 集群里验证 ADR-0010：standalone 模式的 agentgateway，每份快照一个不可变的 ConfigMap，
发布就是把 Deployment 滚动替换到新的 ConfigMap 上。

先 ./stack.sh up 把集群拉起来，再运行本脚本：

    .venv/bin/python tests/integration/kubernetes/run.py

真的部分：Kubernetes（kind，一个节点）、Deployment 的滚动替换、锁定的上游 agentgateway 镜像（按摘要引用）、
网关前面的那层 nginx（与黑盒套件同一个镜像、同一份配置，只换了端口）、网关自己的回读口（双向 TLS）。
配置是一份只有几条路由的小文件，路由的后端是集群里一个会回话的小服务；没有 JWT、ExtAuthZ 和凭证，
那些由黑盒套件覆盖。

每个网关 Pod 里是什么：
    front         nginx。Pod 上唯一收业务请求的端口（8080），转给本机回环上的网关。
    agentgateway  收业务请求的监听只绑回环（8081）；管理、指标端口只绑回环；另开一个回读口（8443），
                  要发布器的客户端证书，只转发 /config_dump 和 /api/runtime 两个 GET。
读每个副本在跑什么，走的就是这个回读口，从集群里另一个 Pod 发起；不用 kubectl exec 进网关容器
（上游镜像里没有 shell）。

本脚本只用本目录 .run/ 里的 kubeconfig，只动 egress-test 这一个命名空间；发布前的离线加载在本机
起一个容器，占用端口 27619（与黑盒套件的回读口相同，两者不能同时跑）。
"""
from __future__ import annotations
import hashlib, http.client, json, os, secrets, shutil, socket, subprocess, sys, threading, time
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BLACKBOX = ROOT / 'tests/acceptance/blackbox'
sys.path.insert(0, str(BLACKBOX))
import pin  # noqa: E402
import pki  # noqa: E402

RUN = HERE / '.run'
KUBECONFIG = RUN / 'kubeconfig'
LOCK = pin.lock()
GATEWAY_IMAGE = pin.image_reference(LOCK)   # 上游镜像，按多平台索引的摘要引用
# 与黑盒套件同一个前置 nginx（tests/contracts 里有一条测试检查两边一致）。
FRONT_IMAGE = ('public.ecr.aws/nginx/nginx-unprivileged:stable-alpine'
               '@sha256:c3fc8fa482be50ef709c6438eb1bc98d50dbfe5a9b48be90711b8814f4dfd701')
# 集群里的工具 Pod 和回话的后端用它：只是一个带 Python 的镜像，probe.py 只用标准库。
TOOLS_IMAGE = ('public.ecr.aws/docker/library/python:3.13-alpine'
               '@sha256:1e1f6334529d1fb26a2ef619d7cffb30a7c7d7cc1cc7338ebee283a58d1aeaca')
# 前置 nginx 的配置就是黑盒套件的那一份，只换监听的端口和转给谁。
FRONT_DIFFERENCES = [('listen 127.0.0.1:27620;', 'listen 8080;'), ('proxy_pass http://127.0.0.1:27611;', 'proxy_pass http://127.0.0.1:8081;')]

NAMESPACE, APP, REPLICAS = 'egress-test', 'agentgateway', 3
PORT = {'front': 8080, 'callers': 8081, 'readback': 8443, 'admin': 15000, 'stats': 15020, 'readiness': 15021}
ECHO_PORT, STAGING_PORT, STAGING_CONTAINER = 8000, 27619, 'idp-gateway-k8s-staging'
# Pod 被终止时的先后：front 先等 PRESTOP 秒再停止接新连接（端点摘除要时间）；网关收到 SIGTERM 后
# 在 MIN_DEADLINE 秒内照常接 front 转来的请求，之后只把在途的做完，最迟 MAX_DEADLINE 秒。
PRESTOP, MIN_DEADLINE, MAX_DEADLINE, GRACE = 8, 12, 45, 60
KUBECTL = shutil.which('kubectl') or str(Path.home() / '.local/bin/kubectl')


def die(message: str):
    print('run.py:', message, file=sys.stderr)
    raise SystemExit(2)


def kubectl(*argv: str, stdin: str | None = None, check: bool = True, timeout: float = 180) -> subprocess.CompletedProcess:
    done = subprocess.run([KUBECTL, '--kubeconfig', str(KUBECONFIG), *argv], input=stdin, capture_output=True, text=True, timeout=timeout)
    if check and done.returncode != 0:
        die(f"kubectl {' '.join(argv[:5])} 失败：{done.stderr.strip()[-600:]}")
    return done


def apply(*documents: dict):
    kubectl('apply', '-f', '-', stdin=yaml.safe_dump_all(documents, sort_keys=False))


def docker(*argv: str, timeout: float = 300) -> subprocess.CompletedProcess:
    return subprocess.run(['docker', *argv], capture_output=True, text=True, timeout=timeout)


# ---- 一份快照：发布器要下发的全部文件 ---------------------------------------------------------------
def gateway_config(routes: list[str], unloadable: str | None = None) -> str:
    """网关的配置文件。unloadable 指的那条路由带一个不存在的字段：整份文件网关加载不了。"""
    def route(name: str) -> dict:
        r = {'name': f'route-{name}', 'gateways': ['callers'], 'hostnames': [f'{name}.test'],
             'policies': {'timeout': {'requestTimeout': '30s'}},
             'backends': [{'host': f'echo.{NAMESPACE}.svc.cluster.local:{ECHO_PORT}'}]}
        if name == unloadable:
            r['notAFieldOfARoute'] = True
        return r

    # 一条形状与真实的池相同的路由：先经双向 TLS 去问 PDP。这里没有 PDP，这条路由也不会被请求。
    # 有了它，/config_dump 里才有证书正文（backendTLS 的 cert 和 root），期望摘要的算法才有东西可验。
    pdp_shaped = {'name': 'route-pdp-shaped', 'gateways': ['callers'], 'hostnames': ['pdp-shaped.test'],
                  'policies': {'extAuthz': {
                      'host': f'echo.{NAMESPACE}.svc.cluster.local:{ECHO_PORT}', 'failureMode': 'deny',
                      'policies': {'backendTLS': {'cert': 'tls/gateway.crt', 'key': 'tls/gateway.key', 'root': 'tls/ca.crt',
                                                  'hostname': pki.GATEKEEPER_NAME}},
                      'protocol': {'http': {'path': '"/v1/extauthz/check"'}}}},
                  'backends': [{'host': f'echo.{NAMESPACE}.svc.cluster.local:{ECHO_PORT}'}]}

    document = {
        'config': {
            'adminAddr': f"127.0.0.1:{PORT['admin']}", 'statsAddr': f"127.0.0.1:{PORT['stats']}",
            'readinessAddr': f"0.0.0.0:{PORT['readiness']}",   # kubelet 从 Pod 外面探
            'storage': {'mode': 'readOnly'},
            'connectionMinTerminationDeadline': f'{MIN_DEADLINE}s', 'connectionTerminationDeadline': f'{MAX_DEADLINE}s'},
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

    def __init__(self, routes: list[str], unloadable: str | None = None):
        self.routes, self.text = routes, gateway_config(routes, unloadable)
        self.id = hashlib.sha256(self.text.encode()).hexdigest()[:12]
        self.configmap = f'{APP}-snapshot-{self.id}'
        self.expected = None   # 离线加载之后才有：期望的运行配置摘要

    def manifest(self) -> dict:
        return {'apiVersion': 'v1', 'kind': 'ConfigMap', 'immutable': True,
                'metadata': {'name': self.configmap, 'namespace': NAMESPACE, 'labels': {'app': APP, 'snapshot': self.id}},
                'data': {'config.yaml': self.text}}


# ---- 运行配置的摘要 ---------------------------------------------------------------------------------
def without_certificates(node):
    """证书正文换成占位：证书来自各池自己的 Secret，换证书不经过发布。"""
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


# ---- 发布前的离线加载 -------------------------------------------------------------------------------
def stage(snapshot: Snapshot) -> dict:
    """发布器在发布前做的那一步：用锁定的镜像在集群外加载这份快照，经回读口读它报告的运行配置。
    证书是另外现做的一套（另一个 CA），与集群里的无关。加载不了的文件在这里就被拒绝。"""
    work = RUN / 'staging'
    shutil.rmtree(work, ignore_errors=True)
    (work / 'config').mkdir(parents=True)
    (work / 'config' / 'config.yaml').write_text(snapshot.text, encoding='utf-8')
    pki.issue(work / 'tls')
    docker('rm', '-f', STAGING_CONTAINER)
    started = docker('run', '-d', '--name', STAGING_CONTAINER, '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                     '--user', f'{os.getuid()}:{os.getgid()}', '-p', f"127.0.0.1:{STAGING_PORT}:{PORT['readback']}",
                     '-v', f"{work / 'config'}:/work/config:ro", '-v', f"{work / 'tls'}:/work/tls:ro", '-w', '/work',
                     '-e', f'SESSION_KEY={secrets.token_hex(32)}', GATEWAY_IMAGE, '-f', 'config/config.yaml')
    if started.returncode != 0:
        die(f'离线加载用的容器起不来：{started.stderr.strip()[-300:]}')
    try:
        result, deadline = None, time.monotonic() + 20
        while time.monotonic() < deadline and result is None:
            state = docker('inspect', '-f', '{{.State.Running}} {{.State.ExitCode}}', STAGING_CONTAINER).stdout.split()
            if state and state[0] == 'false':
                logs = docker('logs', STAGING_CONTAINER)
                return {'loaded': False, 'exit_code': int(state[1]), 'said': (logs.stdout + logs.stderr).strip().split('\n')[-1][:200]}
            try:
                conn = pki.GatekeeperConnection(STAGING_PORT, pki.client_context(work / 'tls', 'publisher'), 3, pki.READBACK_NAME)
                conn.request('GET', '/config_dump', headers={'Host': pki.READBACK_NAME})
                response = conn.getresponse()
                body = response.read()
                conn.close()
                if response.status == 200:
                    result = json.loads(body)
            except (OSError, ValueError, http.client.HTTPException):
                time.sleep(0.3)
        if result is None:
            return {'loaded': False, 'exit_code': None, 'said': '20 秒内回读口没有给出运行配置'}
        return {'loaded': True, 'digest': published_digest(result), 'digest_with_certificates': published_digest(result, certificates=True),
                'config': result.get('config') or {}}
    finally:
        docker('rm', '-f', STAGING_CONTAINER)
        shutil.rmtree(work, ignore_errors=True)


# ---- 集群里的东西 -----------------------------------------------------------------------------------
def front_config() -> str:
    text = (BLACKBOX / 'front.nginx.conf').read_text(encoding='utf-8')
    for old, new in FRONT_DIFFERENCES:
        if text.count(old) != 1:
            die(f'黑盒套件的 front.nginx.conf 里找不到恰好一处 {old!r}：FRONT_DIFFERENCES 要跟着改')
        text = text.replace(old, new)
    return text


def secret(name: str, files: dict) -> dict:
    return {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': name, 'namespace': NAMESPACE}, 'stringData': files}


def restricted(extra: dict | None = None) -> dict:
    return {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}, **(extra or {})}


def gateway_deployment(snapshot: Snapshot) -> dict:
    """一个池：Pod 模板指着一份快照的 ConfigMap。换快照就是换这个名字，由 Deployment 一批一批替换副本。"""
    gateway = {
        'name': 'agentgateway', 'image': GATEWAY_IMAGE, 'workingDir': '/work', 'args': ['-f', 'config/config.yaml'],
        'env': [{'name': 'SESSION_KEY', 'valueFrom': {'secretKeyRef': {'name': 'agentgateway-session', 'key': 'key'}}}],
        'ports': [{'containerPort': PORT['readback']}],
        'readinessProbe': {'httpGet': {'path': '/healthz/ready', 'port': PORT['readiness']}, 'periodSeconds': 2},
        'securityContext': restricted(),
        'volumeMounts': [{'name': 'snapshot', 'mountPath': '/work/config', 'readOnly': True},
                         {'name': 'tls', 'mountPath': '/work/tls', 'readOnly': True}]}
    front = {
        'name': 'front', 'image': FRONT_IMAGE, 'command': ['nginx', '-c', '/etc/front/nginx.conf', '-g', 'daemon off;'],
        'ports': [{'containerPort': PORT['front']}],
        'readinessProbe': {'tcpSocket': {'port': PORT['front']}, 'periodSeconds': 2},
        'lifecycle': {'preStop': {'sleep': {'seconds': PRESTOP}}},
        'securityContext': restricted(),
        'volumeMounts': [{'name': 'front', 'mountPath': '/etc/front', 'readOnly': True}, {'name': 'tmp', 'mountPath': '/tmp'}]}
    return {
        'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {'name': APP, 'namespace': NAMESPACE},
        'spec': {'replicas': REPLICAS, 'minReadySeconds': 3, 'revisionHistoryLimit': 5,
                 'strategy': {'type': 'RollingUpdate', 'rollingUpdate': {'maxSurge': 1, 'maxUnavailable': 0}},
                 'selector': {'matchLabels': {'app': APP}},
                 'template': {'metadata': {'labels': {'app': APP, 'snapshot': snapshot.id}},
                              'spec': {'automountServiceAccountToken': False, 'terminationGracePeriodSeconds': GRACE,
                                       'securityContext': {'runAsNonRoot': True, 'seccompProfile': {'type': 'RuntimeDefault'}},
                                       'containers': [gateway, front],
                                       'volumes': [{'name': 'snapshot', 'configMap': {'name': snapshot.configmap}},
                                                   {'name': 'tls', 'secret': {'secretName': 'gateway-tls'}},
                                                   {'name': 'front', 'configMap': {'name': 'front-nginx'}},
                                                   {'name': 'tmp', 'emptyDir': {}}]}}}}


def tools_deployment(name: str, command: list[str], certificates: bool) -> dict:
    container = {'name': name, 'image': TOOLS_IMAGE, 'command': command,
                 'env': [{'name': 'READBACK_NAME', 'value': pki.READBACK_NAME}, {'name': 'GATEWAY_PORTS', 'value': json.dumps(PORT)},
                         {'name': 'ECHO_PORT', 'value': str(ECHO_PORT)}, {'name': 'PYTHONUNBUFFERED', 'value': '1'}],
                 'securityContext': restricted({'runAsUser': 65534, 'runAsGroup': 65534}),
                 'volumeMounts': [{'name': 'scripts', 'mountPath': '/scripts', 'readOnly': True}, {'name': 'tmp', 'mountPath': '/tmp'}]
                 + ([{'name': 'certs', 'mountPath': '/certs', 'readOnly': True}] if certificates else [])}
    return {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {'name': name, 'namespace': NAMESPACE},
            'spec': {'replicas': 1, 'selector': {'matchLabels': {'app': name}},
                     'template': {'metadata': {'labels': {'app': name}},
                                  'spec': {'automountServiceAccountToken': False, 'terminationGracePeriodSeconds': 2,
                                           'securityContext': {'runAsNonRoot': True, 'seccompProfile': {'type': 'RuntimeDefault'}},
                                           'containers': [container],
                                           'volumes': [{'name': 'scripts', 'configMap': {'name': 'tools'}}, {'name': 'tmp', 'emptyDir': {}}]
                                           + ([{'name': 'certs', 'secret': {'secretName': 'probe-certs'}}] if certificates else [])}}}}


def service(name: str, port: int) -> dict:
    return {'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': name, 'namespace': NAMESPACE},
            'spec': {'selector': {'app': name}, 'ports': [{'port': port, 'targetPort': port}]}}


def everything_but_the_pool() -> list[dict]:
    """会话密钥、证书、前置 nginx 的配置、工具 Pod 和回话的后端。证书每次运行现做。"""
    tls = RUN / 'tls'
    shutil.rmtree(tls, ignore_errors=True)
    pki.issue(tls)
    read = lambda name: (tls / name).read_text(encoding='utf-8')
    return [
        {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': NAMESPACE}},
        secret('agentgateway-session', {'key': secrets.token_hex(32)}),
        # 网关 Pod 拿到的是：回读口的服务端证书、它去问 PDP 用的客户端证书、CA。发布器的证书不在这里。
        secret('gateway-tls', {name: read(name) for name in ('gateway-readback.crt', 'gateway-readback.key', 'gateway.crt', 'gateway.key', 'ca.crt')}),
        # 工具 Pod 扮演发布器，也扮演不是发布器的调用方。
        secret('probe-certs', {name: read(name) for name in ('ca.crt', 'publisher.crt', 'publisher.key', 'business-app.crt', 'business-app.key',
                                                             'rogue-publisher.crt', 'rogue-publisher.key')}),
        {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'tools', 'namespace': NAMESPACE},
         'data': {'probe.py': (HERE / 'probe.py').read_text(encoding='utf-8')}},
        {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'front-nginx', 'namespace': NAMESPACE}, 'data': {'nginx.conf': front_config()}},
        tools_deployment('echo', ['python', '/scripts/probe.py', 'echo'], certificates=False), service('echo', ECHO_PORT),
        tools_deployment('probe', ['python', '-c', 'import time; time.sleep(10**9)'], certificates=True),
        service(APP, PORT['front']),
    ]


# ---- 观察 -------------------------------------------------------------------------------------------
def pods(include_terminating: bool = False) -> list[dict]:
    items = json.loads(kubectl('get', 'pods', '-n', NAMESPACE, '-l', f'app={APP}', '-o', 'json').stdout)['items']
    found = []
    for item in items:
        terminating = bool(item['metadata'].get('deletionTimestamp'))
        if terminating and not include_terminating:
            continue
        statuses = {s['name']: s for s in item['status'].get('containerStatuses') or []}
        found.append({'name': item['metadata']['name'], 'uid': item['metadata']['uid'], 'ip': item['status'].get('podIP'),
                      'snapshot': item['metadata']['labels'].get('snapshot'), 'terminating': terminating,
                      'ready': len(statuses) == 2 and all(s.get('ready') for s in statuses.values()),
                      'restarts': sum(s.get('restartCount', 0) for s in statuses.values()),
                      'gateway': statuses.get('agentgateway', {})})
    return sorted(found, key=lambda p: p['name'])


def probe(*argv: str, timeout: float = 90) -> dict:
    """在工具 Pod 里跑 probe.py：从集群里另一个工作负载的位置去看。"""
    done = kubectl('exec', '-n', NAMESPACE, 'deploy/probe', '--', 'python', '/scripts/probe.py', *argv, check=False, timeout=timeout)
    try:
        return json.loads(done.stdout)
    except ValueError:
        return {'error': (done.stderr or done.stdout).strip()[-300:]}


def inspect(pod: dict, routes: list[str]) -> dict:
    """从工具 Pod 去看一个副本：经回读口读它在跑什么，再看它的各个端口和路由。看不成的项留空，由检查项去判。"""
    seen = {'admin_only': {}, 'other_callers': {}, 'connect': {}, 'routes': {}, **probe('inspect', pod['ip'], *routes)}
    dump = (seen.get('dump') or {}).get('json')
    runtime = (seen.get('runtime') or {}).get('json') or {}
    seen['digest'] = published_digest(dump) if isinstance(dump, dict) else None
    seen['digest_with_certificates'] = published_digest(dump, certificates=True) if isinstance(dump, dict) else None
    seen['config'] = (dump or {}).get('config') or {}
    seen['reload'] = runtime.get('configReload')
    seen['storage'] = (runtime.get('ui') or {}).get('configStoreMode')
    seen['build'] = runtime.get('build') or {}
    return seen


def deployment_status() -> dict:
    return json.loads(kubectl('get', 'deployment', APP, '-n', NAMESPACE, '-o', 'json').stdout).get('status', {})


class ReadyWatch(threading.Thread):
    """滚动期间每半秒看一次：就绪的副本有几个。"""

    def __init__(self):
        super().__init__(daemon=True)
        self.lowest, self.samples, self._stop_now = None, 0, threading.Event()

    def run(self):
        while not self._stop_now.is_set():
            try:
                ready = deployment_status().get('readyReplicas', 0)
                self.lowest = ready if self.lowest is None else min(self.lowest, ready)
                self.samples += 1
            except SystemExit:
                pass
            self._stop_now.wait(0.5)

    def finish(self) -> int | None:
        self._stop_now.set()
        self.join(10)
        return self.lowest


class Load:
    """工具 Pod 经 Service 发请求：每秒 20 个快请求（每个一条新连接），外加两条线各自接连发 2 秒的慢请求。"""

    def __init__(self, route: str = 'a'):
        self.result, self.thread = None, threading.Thread(target=self._run, args=(route,), daemon=True)
        self.thread.start()
        time.sleep(4)   # 先有几秒不受打扰的流量

    def _run(self, route: str):
        self.result = probe('load', APP, str(PORT['front']), route, timeout=700)

    def finish(self) -> dict:
        kubectl('exec', '-n', NAMESPACE, 'deploy/probe', '--', 'touch', '/tmp/stop', check=False)
        self.thread.join(60)
        return self.result or {'error': '没有拿到结果'}


def publish(snapshot: Snapshot) -> float:
    """发布器要做的那一步：建这份快照的 ConfigMap（已有则不变），把 Pod 模板指过去。返回做完的时刻。"""
    apply(snapshot.manifest(), gateway_deployment(snapshot))
    return time.monotonic()


def rolled_out(timeout: int = 240) -> bool:
    return kubectl('rollout', 'status', f'deployment/{APP}', '-n', NAMESPACE, f'--timeout={timeout}s', check=False, timeout=timeout + 20).returncode == 0


def wait_for(predicate, seconds: float, every: float = 1.0):
    """-> predicate() 第一次成立时过了多少秒；到时还不成立则 None。"""
    started = time.monotonic()
    while time.monotonic() - started < seconds:
        if predicate():
            return round(time.monotonic() - started, 1)
        time.sleep(every)
    return None


def same(values) -> bool:
    values = list(values)
    return bool(values) and None not in values and len(set(values)) == 1


def differing(a: dict, b: dict) -> list[str]:
    return sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))


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
        r.note(f'{what}：没有得到 200 的请求（至多列 40 个）', traffic['failures'])
    r.check(f'{what}：发出去的请求不少于 100 个', sum((traffic.get('quick') or {}).values()) >= 100)
    r.check(f'{what}：没有一个请求失败', traffic.get('not_200') == 0 and bool(traffic.get('quick')) and bool(traffic.get('slow')))


def main() -> int:
    try:
        return run()
    finally:   # 证书和离线加载用的容器不留
        docker('rm', '-f', STAGING_CONTAINER)
        shutil.rmtree(RUN / 'tls', ignore_errors=True)
        shutil.rmtree(RUN / 'staging', ignore_errors=True)


def run() -> int:
    if not KUBECONFIG.exists():
        die('集群还没有拉起来：先运行 tests/integration/kubernetes/stack.sh up')
    with socket.socket() as s:
        s.settimeout(0.3)
        if s.connect_ex(('127.0.0.1', STAGING_PORT)) == 0:
            die(f'端口 {STAGING_PORT} 已被占用（黑盒套件在跑？），离线加载要用它')
    server = json.loads(kubectl('version', '-o', 'json').stdout).get('serverVersion', {}).get('gitVersion')
    one, two, bad = Snapshot(['a']), Snapshot(['a', 'b']), Snapshot(['a', 'b', 'c'], unloadable='c')
    r = Results()

    # 从一个干净的命名空间开始。
    kubectl('delete', 'namespace', NAMESPACE, '--ignore-not-found', '--wait=true', timeout=300)

    r.case('K8-01', f'{REPLICAS} 个副本从同一份快照启动')
    staged = stage(one)
    r.check('发布前，锁定的镜像在集群外加载了这份快照', staged.get('loaded'))
    one.expected = staged.get('digest')
    apply(*everything_but_the_pool())
    apply(one.manifest())
    apply(gateway_deployment(one))
    for name in ('echo', 'probe', APP):
        if kubectl('rollout', 'status', f'deployment/{name}', '-n', NAMESPACE, '--timeout=420s', check=False, timeout=440).returncode != 0:
            die(f'deployment/{name} 没有就绪：' + kubectl('get', 'pods', '-n', NAMESPACE, '-o', 'wide', check=False).stdout[-800:])
    first = pods()
    seen = {p['name']: inspect(p, ['a', 'b']) for p in first}
    r.check(f'{REPLICAS} 个 Pod 都就绪', len(first) == REPLICAS and all(p['ready'] for p in first))
    pinned = {LOCK['image']['index'], *LOCK['image']['manifests'].values()}
    r.note('Pod 里网关容器的镜像', sorted({p['gateway'].get('imageID', '') for p in first}))
    r.check('每个 Pod 里跑的是锁定摘要的上游镜像', all(p['gateway'].get('imageID', '').rpartition('@')[2] in pinned for p in first))
    r.check('它报告的版本和提交与锁定文件一致',
            all((s['build'].get('version'), s['build'].get('gitRevision')) == (LOCK['version'], LOCK['git_revision']) for s in seen.values()))
    r.check('发布器的证书经回读口读到每个副本：配置已加载，存储模式 readOnly',
            all(s['reload'] == {'synchronized': True, 'lastError': None} and s['storage'] == 'readOnly' for s in seen.values()))
    r.check('各副本的摘要相同', same(s['digest'] for s in seen.values()))
    r.check('...并且等于发布前在集群外算出的期望值', one.expected is not None and all(s['digest'] == one.expected for s in seen.values()))
    # 集群外那次加载用的是另一套证书。证书正文在 /config_dump 里，所以算摘要时要先把它换成占位。
    r.check('证书正文计入时，各副本之间仍相同，但与集群外的那次加载不同',
            same(s['digest_with_certificates'] for s in seen.values())
            and all(s['digest_with_certificates'] != staged.get('digest_with_certificates') for s in seen.values()))
    r.note('config 段里，集群里的副本与集群外的那次加载不同的项', differing(next(iter(seen.values()))['config'], staged.get('config') or {}))
    r.check('回读口上，管理地址的其余接口一个都没有（关停、改日志级别、调试、界面）：全是 404',
            all(len(s['admin_only']) == 4 and set(s['admin_only'].values()) == {404} for s in seen.values()))
    r.check('回读口不回答别的调用方：同一个 CA 的其它工作负载、没有证书、别的 CA 的证书',
            all(len(s['other_callers']) == 3 and set(s['other_callers'].values()) == {None} for s in seen.values()))
    connect = {p['name']: seen[p['name']]['connect'] for p in first}
    r.note('从另一个 Pod 连各端口的结果（0 是连上了，111 是被拒绝）', next(iter(connect.values()), None))
    r.check('从另一个 Pod 连不上网关收业务请求的监听、管理端口和指标端口（都只绑回环）',
            all(c.get('callers') == c.get('admin') == c.get('stats') == 111 for c in connect.values()))
    r.check('...连得上的只有 front 的端口、回读口和就绪探测口',
            all(c.get('front') == c.get('readback') == c.get('readiness') == 0 for c in connect.values()))
    r.check('从另一个 Pod 经 front 的端口，路由 a 有、路由 b 没有', all(s['routes'] == {'a': 200, 'b': 404} for s in seen.values()))
    # 网关自己会接受带两个 Host 头的请求（黑盒套件的 P1-SS-04）。Pod 里挡它的是 front。
    r.check('带两个 Host 头的请求在 front 就被拒绝：400，应答的是 nginx',
            all((s.get('two_hosts') or {}).get('status') == 400 and (s.get('two_hosts') or {}).get('server') == 'nginx' for s in seen.values()))
    changed = kubectl('patch', 'configmap', one.configmap, '-n', NAMESPACE, '--type', 'merge', '-p', '{"data":{"config.yaml":"changed"}}', check=False)
    r.check('这份快照的 ConfigMap 改不了（不可变）', changed.returncode != 0 and 'immutable' in changed.stderr.lower())
    shell = kubectl('exec', '-n', NAMESPACE, first[0]['name'], '-c', 'agentgateway', '--', 'sh', '-c', 'true', check=False)
    r.note('网关容器里有没有 shell（kubectl exec ... sh）', '有' if shell.returncode == 0 else '没有')

    r.case('K8-02', '发布：新快照是另一个不可变的 ConfigMap，Deployment 滚动替换副本；期间一直有流量')
    staged = stage(two)
    two.expected = staged.get('digest')
    r.check('新快照在集群外加载成功，期望摘要与上一份不同', staged.get('loaded') and two.expected not in (None, one.expected))
    traffic, watch = Load(), ReadyWatch()
    watch.start()
    began = publish(two)
    finished = rolled_out()
    took = round(time.monotonic() - began, 1)
    gone = wait_for(lambda: not any(p['terminating'] for p in pods(include_terminating=True)), 120)
    time.sleep(3)
    lowest, result = watch.finish(), traffic.finish()
    second = pods()
    seen = {p['name']: inspect(p, ['a', 'b']) for p in second}
    r.note('从发布到滚动完成过了多少秒', took)
    r.note('此后旧 Pod 全部退出又过了多少秒', gone)
    r.check('滚动完成', finished)
    r.check(f'滚动期间就绪的副本始终不少于 {REPLICAS} 个', watch.samples > 5 and lowest is not None and lowest >= REPLICAS)
    no_failures(r, result, '滚动期间')
    r.check('副本全部换成了新的 Pod，都指着新快照', len(second) == REPLICAS and all(p['ready'] and p['snapshot'] == two.id for p in second)
            and not {p['uid'] for p in second} & {p['uid'] for p in first})
    r.check('每个副本的摘要等于新快照在集群外算出的期望值', two.expected is not None and all(s['digest'] == two.expected for s in seen.values()))
    r.check('路由 b 在每个副本上都生效了', all(s['routes'] == {'a': 200, 'b': 200} for s in seen.values()))
    r.check('上一份快照的 ConfigMap 还在（回滚要用）',
            kubectl('get', 'configmap', one.configmap, '-n', NAMESPACE, check=False).returncode == 0)

    r.case('K8-03', '一份网关加载不了的快照：集群外的加载先拒绝；硬发下去，滚动停在第一个新 Pod')
    staged = stage(bad)
    r.note('集群外加载的结果', staged)
    r.check('发布前，集群外的加载就拒绝了这份文件', staged.get('loaded') is False and staged.get('exit_code') not in (0, None))
    before = pods()
    publish(bad)

    def crashed():
        return [p for p in pods() if p['snapshot'] == bad.id and (p['restarts'] > 0 or 'terminated' in p['gateway'].get('state', {})
                                                                 or p['gateway'].get('state', {}).get('waiting', {}).get('reason') == 'CrashLoopBackOff')]
    took = wait_for(lambda: bool(crashed()), 120)
    time.sleep(10)   # 再给它一点时间：如果滚动会接着往下走，这时该看得见了
    traffic = Load()
    time.sleep(12)
    result = traffic.finish()
    now, new = pods(), crashed()
    old = [p for p in now if p['snapshot'] == two.id]
    state = (new[0]['gateway'] if new else {})
    r.note('新 Pod 里网关容器的状态', {'state': list(state.get('state', {})), 'restarts': state.get('restartCount'),
                                   'last_exit_code': (state.get('lastState', {}).get('terminated') or state.get('state', {}).get('terminated') or {}).get('exitCode')})
    r.note('从发布到新 Pod 里的网关第一次退出过了多少秒', took)
    r.check('新快照的 Pod 起来了，里面的网关退出，Pod 没有就绪', took is not None and bool(new) and not any(p['ready'] for p in new))
    r.check('只起了一个新 Pod：滚动没有往下走', len([p for p in now if p['snapshot'] == bad.id]) == 1)
    r.check('原来的副本一个没少，没有重启，仍然就绪', [(p['uid'], p['restarts']) for p in old] == [(p['uid'], p['restarts']) for p in before]
            and len(old) == REPLICAS and all(p['ready'] for p in old) and deployment_status().get('readyReplicas') == REPLICAS)
    no_failures(r, result, '停住期间')
    seen = {p['name']: inspect(p, ['a', 'b', 'c']) for p in old}
    r.check('原来的副本仍是上一份快照：摘要没有变，被拒绝的文件里的路由 c 没有生效',
            all(s['digest'] == two.expected and s['routes'] == {'a': 200, 'b': 200, 'c': 404} for s in seen.values()))
    publish(two)   # 发布器把 Pod 模板指回上一份
    back = rolled_out(120)
    wait_for(lambda: not any(p['snapshot'] == bad.id for p in pods(include_terminating=True)), 90)
    after = pods()
    r.check('把 Pod 模板指回上一份快照之后滚动完成，坏的那个 Pod 没了', back and not any(p['snapshot'] == bad.id for p in after))
    r.check('...原来的副本还是那几个，没有被重建', [(p['uid'], p['restarts']) for p in after] == [(p['uid'], p['restarts']) for p in before])

    r.case('K8-04', '回滚：把 Pod 模板指回更早的那份快照；期间一直有流量')
    before = pods()
    traffic, watch = Load(), ReadyWatch()
    watch.start()
    began = publish(one)
    finished = rolled_out()
    took = round(time.monotonic() - began, 1)
    wait_for(lambda: not any(p['terminating'] for p in pods(include_terminating=True)), 120)
    time.sleep(3)
    lowest, result = watch.finish(), traffic.finish()
    third = pods()
    seen = {p['name']: inspect(p, ['a', 'b']) for p in third}
    r.note('从发布到滚动完成过了多少秒', took)
    r.check('滚动完成', finished)
    r.check(f'滚动期间就绪的副本始终不少于 {REPLICAS} 个', watch.samples > 5 and lowest is not None and lowest >= REPLICAS)
    no_failures(r, result, '滚动期间')
    r.check('副本全部换成了新的 Pod，都指着更早的那份快照', len(third) == REPLICAS and all(p['ready'] and p['snapshot'] == one.id for p in third)
            and not {p['uid'] for p in third} & {p['uid'] for p in before})
    r.check('每个副本的摘要回到那份快照的期望值，路由 b 没有了',
            all(s['digest'] == one.expected and s['routes'] == {'a': 200, 'b': 404} for s in seen.values()))

    print(f'\nKubernetes {server}，agentgateway {LOCK["version"]}（{GATEWAY_IMAGE}），{REPLICAS} 个副本')
    r.report()
    failed = r.failed()
    (RUN / 'result.json').write_text(json.dumps({'kubernetes': server, 'agentgateway': LOCK['version'], 'image': GATEWAY_IMAGE,
                                                 'front_image': FRONT_IMAGE, 'replicas': REPLICAS, 'cases': r.cases}, ensure_ascii=False, indent=1), encoding='utf-8')
    print(f"\n{len(r.cases) - len(failed)}/{len(r.cases)}（详细结果在 {RUN / 'result.json'}）")
    return int(bool(failed))


if __name__ == '__main__':
    sys.exit(main())
