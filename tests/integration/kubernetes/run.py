#!/usr/bin/env python3
"""在本机的 kind 集群里验证 ADR-0010：standalone 模式的 agentgateway，多个副本，配置经 ConfigMap 下发。

先 ./stack.sh up 把集群拉起来，再运行本脚本：

    .venv/bin/python tests/integration/kubernetes/run.py

真的部分：Kubernetes（kind，一个节点）、kubelet 把 ConfigMap 投影成文件的那套机制、锁定的 agentgateway
二进制（在本地打包成镜像）。这里只看"配置怎么到网关、网关怎么报告"：配置是一份只有几条路由的小文件，
路由的后端是一个没有进程监听的端口，没有 JWT、ExtAuthZ 和凭证。那些由黑盒套件覆盖。

回读走 kubectl exec：网关的管理地址在 Pod 里只绑了回环。本脚本只用本目录 .run/ 里的 kubeconfig，
只动 egress-test 这一个命名空间。
"""
from __future__ import annotations
import hashlib, json, re, secrets, shutil, subprocess, sys, time
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
RUN = HERE / '.run'
KUBECONFIG = RUN / 'kubeconfig'
LOCK = json.loads((ROOT / 'deploy/agentgateway/agentgateway.lock.json').read_text(encoding='utf-8'))
IMAGE = f"idp-gateway-k8s/agentgateway:{LOCK['version']}"   # 由 stack.sh 用锁定的二进制打包
NAMESPACE, APP, CONFIGMAP, SECRET = 'egress-test', 'agentgateway', 'agentgateway-config', 'agentgateway-session'
REPLICAS, GATEWAY_PORT, ADMIN_PORT = 3, 8080, 15000
PROPAGATION_WAIT = 240   # 秒。ConfigMap 的变更要等 kubelet 同步到 Pod 里；上游文档说可能要一分钟
SETTLE = 45              # 秒。Pod 就绪后等这么久再做第一次变更，见 K8-02 前面的说明
KUBECTL = shutil.which('kubectl') or str(Path.home() / '.local/bin/kubectl')


def die(message: str):
    print('run.py:', message, file=sys.stderr)
    raise SystemExit(2)


def kubectl(*argv: str, stdin: str | None = None, check: bool = True, timeout: float = 120) -> subprocess.CompletedProcess:
    done = subprocess.run([KUBECTL, '--kubeconfig', str(KUBECONFIG), *argv], input=stdin, capture_output=True, text=True, timeout=timeout)
    if check and done.returncode != 0:
        die(f"kubectl {' '.join(argv[:5])} 失败：{done.stderr.strip()[-600:]}")
    return done


# ---- 要下发的东西 ---------------------------------------------------------------------------
def config(routes: list[str], storage: str = 'readOnly', unloadable: str | None = None) -> str:
    """一份只有路由的小配置。unloadable 指的那条路由带一个不存在的字段：整份文件网关加载不了。"""
    out = ['config:', f'  adminAddr: 127.0.0.1:{ADMIN_PORT}', '  storage:', f'    mode: {storage}', '',
           'gateways:', '  default:', f'    port: {GATEWAY_PORT}', '    protocol: HTTP', '', 'routes:']
    for name in routes:
        out += [f'- name: route-{name}', '  gateways: [default]', f'  hostnames: ["{name}.test"]']
        if name == unloadable:
            out += ['  notAFieldOfARoute: true']
        # 没有进程监听的端口：一条路由在不在，看网关答的是 404 还是别的。
        out += ['  backends:', '  - host: 127.0.0.1:9']
    return '\n'.join(out) + '\n'


def configmap(text: str) -> dict:
    return {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': CONFIGMAP, 'namespace': NAMESPACE},
            'data': {'config.yaml': text}}


def deployment(name: str, replicas: int, cpu_limit: str | None = None) -> dict:
    """一组读同一个 ConfigMap 的网关。ConfigMap 整个目录只读挂载（不用 subPath，subPath 挂载的文件
    不会随 ConfigMap 更新）。"""
    container = {
        'name': APP, 'image': IMAGE, 'imagePullPolicy': 'Never', 'args': ['-f', '/config/config.yaml'],
        'env': [{'name': 'SESSION_KEY', 'valueFrom': {'secretKeyRef': {'name': SECRET, 'key': 'key'}}}],
        'ports': [{'containerPort': GATEWAY_PORT}],
        'readinessProbe': {'tcpSocket': {'port': GATEWAY_PORT}, 'periodSeconds': 2},
        'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}},
        'volumeMounts': [{'name': 'config', 'mountPath': '/config', 'readOnly': True}],
    }
    if cpu_limit:
        container['resources'] = {'requests': {'cpu': cpu_limit}, 'limits': {'cpu': cpu_limit}}
    return {
        'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {'name': name, 'namespace': NAMESPACE},
        'spec': {'replicas': replicas, 'selector': {'matchLabels': {'app': name}},
                 'template': {'metadata': {'labels': {'app': name}},
                              'spec': {'automountServiceAccountToken': False,
                                       'securityContext': {'runAsNonRoot': True, 'runAsUser': 65534, 'runAsGroup': 65534,
                                                           'seccompProfile': {'type': 'RuntimeDefault'}},
                                       'containers': [container],
                                       'volumes': [{'name': 'config', 'configMap': {'name': CONFIGMAP}}]}}},
    }


def manifests(text: str) -> str:
    """一个池的全部：会话密钥、ConfigMap、Deployment。"""
    return yaml.safe_dump_all([
        {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': NAMESPACE}},
        {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': SECRET, 'namespace': NAMESPACE},
         'stringData': {'key': secrets.token_hex(32)}},   # 每次运行现生成，不落盘
        configmap(text), deployment(APP, REPLICAS)], sort_keys=False)


def publish(text: str) -> float:
    """发布器要做的那一步：换掉 ConfigMap。返回换完的时刻。"""
    kubectl('apply', '-f', '-', stdin=yaml.safe_dump(configmap(text), sort_keys=False))
    return time.monotonic()


# ---- 逐个副本去看 -----------------------------------------------------------------------------
def pods(app: str = APP) -> list[dict]:
    items = json.loads(kubectl('get', 'pods', '-n', NAMESPACE, '-l', f'app={app}', '-o', 'json').stdout)['items']
    found = []
    for item in items:
        if item['metadata'].get('deletionTimestamp'):
            continue
        status = (item['status'].get('containerStatuses') or [{}])[0]
        found.append({'name': item['metadata']['name'], 'uid': item['metadata']['uid'],
                      'ready': bool(status.get('ready')), 'restarts': status.get('restartCount', 0)})
    return sorted(found, key=lambda p: p['name'])


def in_pod(pod: str, *command: str) -> subprocess.CompletedProcess:
    return kubectl('exec', '-n', NAMESPACE, pod, '--', *command, check=False, timeout=30)


def admin(pod: str, path: str):
    """网关自己的管理地址，在 Pod 里只绑回环，所以进到 Pod 里去读。"""
    done = in_pod(pod, 'wget', '-q', '-T', '5', '-O', '-', f'http://127.0.0.1:{ADMIN_PORT}{path}')
    try:
        return json.loads(done.stdout)
    except ValueError:
        return None


def digest(pod: str, published_only: bool = False) -> str | None:
    """这个副本报告的运行配置（/config_dump）的摘要，与键的顺序无关。

    /config_dump 的 config 段是启动时定下的设置，里面除了文件里写的，还有随运行环境变的值
    （工作线程数、DNS 搜索域等）。published_only 时去掉这一段，只算路由、策略、后端这些
    随文件重载的部分。"""
    running = admin(pod, '/config_dump')
    if not isinstance(running, dict):
        return None
    if published_only:
        running = {k: v for k, v in running.items() if k != 'config'}
    return hashlib.sha256(json.dumps(running, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def startup_settings(pod: str) -> dict:
    return (admin(pod, '/config_dump') or {}).get('config') or {}


def differing(a: dict, b: dict) -> list[str]:
    return sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))


def reload_state(pod: str) -> dict:
    return (admin(pod, '/api/runtime') or {}).get('configReload') or {}


def storage_mode(pod: str):
    return ((admin(pod, '/api/runtime') or {}).get('ui') or {}).get('configStoreMode')


def route_status(pod: str, name: str) -> int | None:
    done = in_pod(pod, 'wget', '-q', '-S', '-T', '5', '-O', '/dev/null', '--header', f'Host: {name}.test',
                  f'http://127.0.0.1:{GATEWAY_PORT}/x')
    found = re.search(r'HTTP/1\.[01] (\d{3})', done.stderr)
    return int(found[1]) if found else None


def served(pod: str, name: str) -> bool:
    """路由在：网关把请求往后端送了（后端不存在，所以不是 2xx，但也不是"没有这条路由"的 404）。"""
    status = route_status(pod, name)
    return status is not None and status != 404


def wait_each(names: list[str], predicate, since: float, seconds: float = PROPAGATION_WAIT) -> dict:
    """-> 每个副本从 since 起过了多少秒 predicate 才成立；到时还不成立的记 None。"""
    seen: dict = {name: None for name in names}
    while time.monotonic() - since < seconds and None in seen.values():
        for name in names:
            if seen[name] is None and predicate(name):
                seen[name] = round(time.monotonic() - since, 1)
        time.sleep(1.0)
    return seen


def same(values) -> bool:
    values = list(values)
    return bool(values) and None not in values and len(set(values)) == 1


def unchanged(before: list[dict], after: list[dict]) -> bool:
    return [(p['uid'], p['restarts']) for p in before] == [(p['uid'], p['restarts']) for p in after]


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


def main() -> int:
    if not KUBECONFIG.exists():
        die('集群还没有拉起来：先运行 tests/integration/kubernetes/stack.sh up')
    server = json.loads(kubectl('version', '-o', 'json').stdout).get('serverVersion', {}).get('gitVersion')
    one, two = config(['a']), config(['a', 'b'])
    r = Results()

    # 从一个干净的命名空间开始。
    kubectl('delete', 'namespace', NAMESPACE, '--ignore-not-found', '--wait=true', timeout=240)
    kubectl('apply', '-f', '-', stdin=manifests(one))
    kubectl('rollout', 'status', f'deployment/{APP}', '-n', NAMESPACE, '--timeout=180s', timeout=200)

    r.case('K8-01', f'{REPLICAS} 个副本从同一个 ConfigMap 启动')
    started = pods()
    names = [p['name'] for p in started]
    r.check(f'{REPLICAS} 个 Pod 都就绪', len(started) == REPLICAS and all(p['ready'] for p in started))
    r.check('每个副本都报告配置已加载', all(reload_state(n) == {'synchronized': True, 'lastError': None} for n in names))
    r.check('每个副本都报告存储模式为 readOnly', all(storage_mode(n) == 'readOnly' for n in names))
    first = {n: digest(n) for n in names}
    r.check('各副本 /config_dump 的摘要相同', same(first.values()))
    r.check('路由 a 在每个副本上都在，路由 b 都不在', all(served(n, 'a') and route_status(n, 'b') == 404 for n in names))
    r.check('Pod 里的配置文件写不进去', all(in_pod(n, 'sh', '-c', 'echo x >> /config/config.yaml').returncode != 0 for n in names))
    build = (admin(names[0], '/api/runtime') or {}).get('build') or {}
    r.note('Pod 里的网关报告的版本', f"{build.get('version')} {str(build.get('gitRevision'))[:12]}")
    r.check('它就是锁定的那个发布版', (build.get('version'), build.get('gitRevision')) == (LOCK['version'], LOCK['git_revision']))
    one_digest = first[names[0]]

    # Pod 刚就绪就换 ConfigMap，量到过一两秒就到；等一会儿再换，要几十秒。后一种才是常态，所以先等。
    # （多半是 Pod 状态刚变化时 kubelet 会额外同步一次，这一点没有去证实。）
    time.sleep(SETTLE)

    r.case('K8-02', 'ConfigMap 换成多一条路由的版本')
    before = pods()
    took = wait_each(names, lambda n: digest(n) not in (None, one_digest), publish(two))
    second = {n: digest(n) for n in names}
    r.note('各副本从换 ConfigMap 到摘要改变过了多少秒', took)
    if None not in took.values():
        r.note('最先变的副本和最后变的副本之间隔了多少秒', round(max(took.values()) - min(took.values()), 1))
    r.check(f'{PROPAGATION_WAIT} 秒内每个副本的摘要都变了', None not in took.values())
    r.check('变了之后各副本的摘要相同', same(second.values()))
    r.check('每个副本都报告配置已加载', all(reload_state(n) == {'synchronized': True, 'lastError': None} for n in names))
    r.check('路由 b 在每个副本上都生效了', all(served(n, 'b') for n in names))
    r.check('没有 Pod 被重建或重启', unchanged(before, pods()))
    two_digest = second[names[0]]

    r.case('K8-03', 'ConfigMap 换成一份网关加载不了的版本（里面另有一条没有问题的新路由 c）')
    before = pods()
    took = wait_each(names, lambda n: reload_state(n).get('synchronized') is False,
                     publish(config(['a', 'b', 'c', 'd'], unloadable='d')))
    states = {n: reload_state(n) for n in names}
    r.note('各副本从换 ConfigMap 到报告加载失败过了多少秒', took)
    r.note('其中一个副本给的原因', states[names[0]].get('lastError'))
    r.check(f'{PROPAGATION_WAIT} 秒内每个副本都报告加载失败', None not in took.values())
    r.check('...并且都给了原因', all(s.get('lastError') for s in states.values()))
    r.check('各副本的摘要仍是上一份被接受的配置', all(digest(n) == two_digest for n in names))
    r.check('路由 b 仍然生效；被拒绝的文件里没有问题的路由 c 没有生效',
            all(served(n, 'b') and route_status(n, 'c') == 404 for n in names))
    r.check('没有 Pod 被重建或重启', unchanged(before, pods()))
    back = wait_each(names, lambda n: reload_state(n).get('synchronized') is True, publish(two))
    r.note('换回上一份之后，各副本到报告加载成功过了多少秒', back)
    r.check('换回上一份之后每个副本都报告配置已加载', None not in back.values())
    r.check('...摘要没有变', all(digest(n) == two_digest for n in names))

    r.case('K8-04', '只在启动时读取的设置：ConfigMap 里把 storage.mode 改成 file，同时加一条路由 e')
    before = pods()
    took = wait_each(names, lambda n: served(n, 'e'), publish(config(['a', 'b', 'e'], storage='file')))
    r.note('各副本从换 ConfigMap 到路由 e 生效过了多少秒', took)
    r.check('每个副本都重新加载了新文件（路由 e 生效）', None not in took.values())
    r.check('不重启，各副本报告的存储模式仍是启动时的 readOnly', all(storage_mode(n) == 'readOnly' for n in names))
    third = {n: digest(n) for n in names}
    third_published = {n: digest(n, published_only=True) for n in names}
    reloaded_settings = startup_settings(names[0])
    r.check('各副本的摘要相同', same(third.values()))
    r.check('到这里仍然没有 Pod 被重建或重启', unchanged(before, pods()))
    kubectl('rollout', 'restart', f'deployment/{APP}', '-n', NAMESPACE)
    kubectl('rollout', 'status', f'deployment/{APP}', '-n', NAMESPACE, '--timeout=180s', timeout=200)
    restarted = pods()
    fresh = [p['name'] for p in restarted]
    r.check('滚动重启换掉了全部 Pod', len(restarted) == REPLICAS and all(p['ready'] for p in restarted)
            and not {p['uid'] for p in restarted} & {p['uid'] for p in before})
    r.check('重启之后每个副本报告的存储模式是 file', all(storage_mode(n) == 'file' for n in fresh))
    fourth = {n: digest(n) for n in fresh}
    r.check('重启之后各副本的摘要相同', same(fourth.values()))
    r.check('路由 a、b、e 在重启后的每个副本上都在', all(served(n, x) for n in fresh for x in 'abe'))
    # 同一份文件，一批实例是重载进来的，一批是启动时读的。
    r.check('重启前后，随文件重载的那部分（去掉 config 段）摘要相同',
            same(list(third_published.values()) + [digest(n, published_only=True) for n in fresh]))
    r.check('重启前后，整个 /config_dump 的摘要不同：没重启的实例上那项设置还是旧的',
            same(third.values()) and same(fourth.values()) and third[names[0]] != fourth[fresh[0]])
    r.note('重启前后 config 段里不同的项', differing(reloaded_settings, startup_settings(fresh[0])))

    r.case('K8-05', '同一个 ConfigMap，另起一个 CPU 限额为 1 的副本：摘要拿来跨实例比对时要注意什么')
    kubectl('apply', '-f', '-', stdin=yaml.safe_dump(deployment(APP + '-small', 1, cpu_limit='1'), sort_keys=False))
    kubectl('rollout', 'status', f'deployment/{APP}-small', '-n', NAMESPACE, '--timeout=180s', timeout=200)
    small = [p['name'] for p in pods(APP + '-small')]
    r.check('这个副本就绪，并报告配置已加载', len(small) == 1 and reload_state(small[0]) == {'synchronized': True, 'lastError': None})
    if small:
        r.check('随文件重载的那部分（去掉 config 段），它与另外三个副本摘要相同',
                same([digest(small[0], published_only=True)] + [digest(n, published_only=True) for n in fresh]))
        r.note('整个 /config_dump 的摘要，它与另外三个副本是否相同', digest(small[0]) == fourth[fresh[0]])
        r.note('两边 config 段里不同的项', differing(startup_settings(small[0]), startup_settings(fresh[0])))
        r.note('工作线程数：限额为 1 的副本 / 没有限额的副本',
               f"{startup_settings(small[0]).get('numWorkerThreads')} / {startup_settings(fresh[0]).get('numWorkerThreads')}")

    print(f'\nKubernetes {server}，agentgateway {LOCK["version"]}，{REPLICAS} 个副本')
    r.report()
    failed = r.failed()
    (RUN / 'result.json').write_text(json.dumps({'kubernetes': server, 'agentgateway': LOCK['version'], 'image': IMAGE,
                                                 'replicas': REPLICAS, 'cases': r.cases}, ensure_ascii=False, indent=1), encoding='utf-8')
    print(f"\n{len(r.cases) - len(failed)}/{len(r.cases)}（详细结果在 {RUN / 'result.json'}）")
    return int(bool(failed))


if __name__ == '__main__':
    sys.exit(main())
