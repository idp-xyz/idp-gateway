#!/usr/bin/env python3
"""联调：真实的 Gatekeeper（本机实例）→ 真实的 agentgateway → gateway-authz → Gatekeeper 的 PDP。

先用 ./stack.sh up 把本机的 Gatekeeper 拉起来，再运行本脚本：

    .venv/bin/python tests/integration/gatekeeper/run.py [--key-rotation]

真的部分：Gatekeeper（Hydra 签发的 M2M 令牌、JWKS、PDP 与它背后的 OpenFGA）、agentgateway、
gateway-authz（产品构建）。假的部分：Provider（黑盒套件的 mock_provider.py）和工作负载证书
（每次运行现做的 CA）。

网关配置就是黑盒套件的 agentgateway.poc.yaml，只换了三处：签发者、JWKS 的来源，以及
"Token 环境"的来源（见 GATEWAY_DIFFERENCES）。登记表按本地实例里的租户和客户端现生成。

租户、客户端和授权关系只建在本机实例里。已发布的 gk.idp.xyz 是生产环境，本脚本不访问它。
占用黑盒套件的端口 27611-27616，两者不能同时运行。
"""
from __future__ import annotations
import argparse, base64, http.client, json, os, secrets, socket, subprocess, sys, time, urllib.error, urllib.parse, urllib.request
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
RUN = HERE / '.run'
TLS = RUN / 'tls'
BLACKBOX = ROOT / 'tests/acceptance/blackbox'
sys.path.insert(0, str(BLACKBOX))
import pki  # noqa: E402

PROJECT = 'idp-gateway-gk'
ISSUER = 'http://127.0.0.1:27621'
BRIDGE = 'http://127.0.0.1:27622'
AUDIENCE = 'idp-egress-gateway'   # 与黑盒套件相同。本机实例的 TOKEN_AUDIENCE 里加了它，见 compose.local.yml
OTHER_AUDIENCE = 'bip-api'        # Gatekeeper 默认的受众：发给别的服务的令牌
PORTS = {'gateway': 27611, 'provider': 27612, 'authz': 27613, 'admin': 27614, 'stats': 27615, 'readiness': 27616}
BINARIES = {'1.7.0': '/home/tops/.local/opt/agentgateway/1.7.0/agentgateway', '1.6.0': '/usr/local/bin/agentgateway'}
HOST = 'egress-api.idp.test'
TRACKING = '/providers/mockcarrier/v1/tracking/TRK-1'
BINDING = 'gatekeeper:mockcarrier-test'
KEY_ROTATION = False          # --key-rotation
ROTATION_WAIT = 60

# 黑盒套件的网关配置里被替换的文本，以及各自应当出现的次数。
GATEWAY_DIFFERENCES = [
    ('      issuer: https://gatekeeper.idp.test\n', f'      issuer: {ISSUER}\n', 1),
    ('        file: .run/jwks.json\n', f'        url: {ISSUER}/.well-known/jwks.json\n', 1),
    # Gatekeeper 的令牌里没有 env 声明。这里的"Token 环境"是这个网关实例的常量：
    # 它只信一个签发者，签发者属于哪个环境是部署时定下的。
    ("x-idp-verified-env: jwt.env\n", "x-idp-verified-env: '\"TEST\"'\n", 3),
]


# ---- 小工具 ------------------------------------------------------------------------------
def die(message: str):
    print('run.py:', message, file=sys.stderr)
    raise SystemExit(2)


def call(method: str, url: str, body=None, headers: dict | None = None, form: dict | None = None, timeout: float = 10.0):
    """返回 (状态码, 解析后的 JSON 或原文)。连接不上时状态码为 None。"""
    data, headers = None, dict(headers or {})
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
    elif body is not None:
        data, headers['Content-Type'] = json.dumps(body).encode(), 'application/json'
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status, raw = response.status, response.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    except (urllib.error.URLError, OSError) as e:
        return None, f'{type(e).__name__}: {e}'
    try:
        return status, json.loads(raw or b'null')
    except ValueError:
        return status, raw.decode(errors='replace')


def stack_env() -> dict:
    path = RUN / 'stack.env'
    if not path.exists():
        die('本机的 Gatekeeper 还没有拉起来：先运行 tests/integration/gatekeeper/stack.sh up')
    return dict(line.split('=', 1) for line in path.read_text().splitlines() if '=' in line)


ENV = stack_env()


def admin(method: str, path: str, body=None):
    return call(method, BRIDGE + '/admin/api' + path, body, {'X-Admin-Key': ENV['ADMIN_API_KEY']})


def port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex(('127.0.0.1', port)) == 0


def wait_port(port: int, up: bool, timeout: float = 15.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if port_open(port) == up:
            return True
        time.sleep(0.1)
    return False


# ---- 本机 Gatekeeper 里的测试数据 ----------------------------------------------------------
def token_for(client: dict, audience: str | None = AUDIENCE):
    basic = base64.b64encode(f"{client['client_id']}:{client['client_secret']}".encode()).decode()
    form = {'grant_type': 'client_credentials', **({'audience': audience} if audience else {})}
    status, body = call('POST', ISSUER + '/oauth2/token', form=form, headers={'Authorization': 'Basic ' + basic})
    return body.get('access_token') if status == 200 and isinstance(body, dict) else None


def seed() -> dict:
    """两个租户，各一个获授的 M2M 客户端；蓝租户另有一个登记表里有、Gatekeeper 里没有授权的客户端。
    客户端密钥只在创建时返回一次，存在 .run/clients.json（0600）。"""
    path = RUN / 'clients.json'
    state = json.loads(path.read_text()) if path.exists() else {}
    # 文件里记着的租户在这个实例里已经不存在（实例重建过）：全部重来。
    if any(admin('GET', f"/tenants/{entry['tenant_id']}")[0] != 200 for entry in state.values()):
        state = {}
    for key in ('blue', 'green'):
        if key not in state:
            status, tenant = admin('POST', '/tenants', {'slug': f'tenant-{key}-{secrets.token_hex(3)}', 'name': f'Tenant {key}'})
            if status not in (200, 201):
                die(f'建租户失败：{status} {tenant}')
            state[key] = {'tenant_id': tenant['id']}
    state.setdefault('ungranted', {'tenant_id': state['blue']['tenant_id']})
    for key, entry in state.items():
        if entry.get('client') and token_for(entry['client']):
            continue
        status, client = admin('POST', f"/tenants/{entry['tenant_id']}/m2m-clients", {'name': f'parcel-service-{key}'})
        if status not in (200, 201):
            die(f'建 M2M 客户端失败：{status} {client}')
        entry['client'] = client
    path.write_text(json.dumps(state, indent=1))
    os.chmod(path, 0o600)
    return state


def tuples_of(obj: str) -> set:
    status, page = admin('GET', '/authz/tuples?page_size=100&object=' + urllib.parse.quote(obj))
    if status != 200:
        die(f'读授权关系失败：{status} {page}')
    found = set()
    for item in page.get('tuples') or []:
        key = item.get('key', item)
        found.add((key['user'], key['relation'], key['object']))
    return found


def write_tuple(method: str, user: str, relation: str, obj: str):
    status, body = admin(method, '/authz/tuples', {'user': user, 'relation': relation, 'object': obj})
    if status != 200:
        die(f'{method} 授权关系 {user} {relation} {obj} 失败：{status} {body}')


def desired_tuples(state: dict) -> dict:
    wanted = {}
    for key in ('blue', 'green'):
        obj = f'provider_account:account-{key}'
        wanted[obj] = {(f"org:{state[key]['tenant_id']}", 'org', obj),
                       (f"user:{state[key]['client']['client_id']}", 'caller', obj)}
    return wanted


def sync_tuples(state: dict):
    """让两个账户上的授权关系恰好是 desired_tuples()：多的删掉，少的补上。"""
    for obj, wanted in desired_tuples(state).items():
        have = tuples_of(obj)
        for t in have - wanted:
            write_tuple('DELETE', *t)
        for t in wanted - have:
            write_tuple('POST', *t)


# ---- 进程 --------------------------------------------------------------------------------
PROCS: list[tuple[str, subprocess.Popen, int]] = []


def start(name: str, argv: list[str], port: int, env: dict | None = None):
    log = open(RUN / f'{name}.log', 'a')   # 同一轮里重启的进程接着写，判定记录不丢
    PROCS.append((name, subprocess.Popen(argv, cwd=HERE, stdout=log, stderr=subprocess.STDOUT, env=env or os.environ), port))
    if not wait_port(port, up=True):
        tail = (RUN / f'{name}.log').read_text()[-1200:]
        stop_all()
        die(f'{name} 没有在端口 {port} 上起来：\n{tail}')


def stop(name: str):
    for entry in [p for p in PROCS if p[0] == name]:
        _, process, port = entry
        process.terminate()
        try:
            process.wait(5)
        except subprocess.TimeoutExpired:
            process.kill()
        wait_port(port, up=False)
        PROCS.remove(entry)


def stop_all():
    for name in [p[0] for p in reversed(PROCS)]:
        stop(name)


def container(service: str, action: str):
    """停或启本机 Gatekeeper 的一个容器。只动带着本项目标签的容器。"""
    name = f'{PROJECT}-{service}-1'
    label = subprocess.run(['docker', 'inspect', '-f', '{{index .Config.Labels "com.docker.compose.project"}}', name],
                           capture_output=True, text=True).stdout.strip()
    if label != PROJECT:
        die(f'容器 {name} 不属于 compose 项目 {PROJECT}，不动它')
    subprocess.run(['docker', action, name], check=True, capture_output=True)


def start_authz(token_file: Path | None):
    """token_file 为 None 时不接 Gatekeeper：只看登记表。"""
    ask = ['--gatekeeper-url', BRIDGE, '--gatekeeper-token-file', str(token_file)] if token_file else []
    start('gateway-authz', [str(RUN / 'gateway-authz'), '--listen', f"127.0.0.1:{PORTS['authz']}",
                            '--tls-cert', str(TLS / 'gatekeeper.crt'), '--tls-key', str(TLS / 'gatekeeper.key'),
                            '--client-ca', str(TLS / 'ca.crt'), '--policy', str(RUN / 'policy.json'),
                            '--credentials', str(RUN / 'authz-credentials.json'),
                            '--gateway-identity', pki.ID['gateway'], '--broker-identity', pki.ID['broker'], *ask], PORTS['authz'])


def prepare(state: dict) -> dict:
    for name, port in PORTS.items():
        if port_open(port):
            die(f'端口 {port}（{name}）已被占用：黑盒套件在跑，或上一次运行没有收尾')
    pki.issue(TLS)
    provider_tokens = {a: f'mock-{a}-' + secrets.token_urlsafe(24) for a in ('account-blue', 'account-green')}
    admin_secret = secrets.token_urlsafe(24)
    blue, green = state['blue'], state['green']
    operation = {
        'route_id': 'mockcarrier-tracking-get', 'provider_id': 'mockcarrier', 'operation_id': 'tracking.get',
        'environment': 'TEST', 'method': 'GET', 'path_prefix': '/providers/mockcarrier/v1/tracking',
        'upstream_hostname': 'mockcarrier.example', 'port': 443, 'credential_binding_ref': BINDING,
        'allowed_tenants': [blue['tenant_id'], green['tenant_id']],
        'accounts_by_tenant': {blue['tenant_id']: ['account-blue'], green['tenant_id']: ['account-green']},
        # 登记表认这三个客户端；其中 ungranted 在 Gatekeeper 里没有账户授权。
        'allowed_service_ids': [state[k]['client']['client_id'] for k in ('blue', 'green', 'ungranted')],
    }
    files = {
        'policy.json': json.dumps({'version': 'integration-gk', 'default_decision': 'DENY', 'registered_operations': [operation]}),
        'authz-credentials.json': json.dumps({f'{BINDING}/{a}': t for a, t in provider_tokens.items()}),
        'pdp-token': ENV['GK_PDP_AUTH_TOKEN'] + '\n',
        'pdp-token.wrong': 'not-the-pdp-token\n',
        'state.json': json.dumps({'admin_secret': admin_secret, 'ports': {'forbidden': 27617}, 'provider_slow_seconds': 1,
                                  'provider_tokens': {t: a for a, t in provider_tokens.items()}}),
        # 黑盒配置里另外两条路由引用的文件；这里不走那两条路由。
        'broker-local.key': secrets.token_urlsafe(24), 'static-provider.key': secrets.token_urlsafe(24),
    }
    config = (BLACKBOX / 'agentgateway.poc.yaml').read_text(encoding='utf-8')
    for old, new, times in GATEWAY_DIFFERENCES:
        if config.count(old) != times:
            die(f'黑盒套件的网关配置变了：{old.strip()!r} 出现了 {config.count(old)} 次，应为 {times} 次')
        config = config.replace(old, new)
    files['agentgateway.yaml'] = config
    for name, content in files.items():
        (RUN / name).write_text(content, encoding='utf-8')
        os.chmod(RUN / name, 0o600)
    build = subprocess.run(['/usr/local/go/bin/go', 'build', '-trimpath', '-o', str(RUN / 'gateway-authz'), './cmd/gateway-authz'],
                           cwd=ROOT, capture_output=True, text=True)
    if build.returncode != 0:
        die('gateway-authz 构建失败：\n' + build.stderr[-1500:])
    return {'provider_tokens': provider_tokens, 'admin_secret': admin_secret}


def start_all(binary: str):
    for log in RUN.glob('*.log'):
        log.unlink()
    start('provider', [sys.executable, str(BLACKBOX / 'mock_provider.py'), '--port', str(PORTS['provider']),
                       '--name', 'mockcarrier', '--state', str(RUN / 'state.json')], PORTS['provider'])
    start_authz(RUN / 'pdp-token')
    start('gateway', [binary, '-f', '.run/agentgateway.yaml'], PORTS['gateway'],
          env={**os.environ, 'SESSION_KEY': secrets.token_hex(32)})


# ---- 观察 --------------------------------------------------------------------------------
def gw(token: str | None, account: str | None = None) -> dict:
    headers = {'Host': HOST}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    if account:
        headers['X-Provider-Account'] = account
    started = time.perf_counter()
    try:
        conn = http.client.HTTPConnection('127.0.0.1', PORTS['gateway'], timeout=10)
        conn.request('GET', TRACKING, headers=headers)
        response = conn.getresponse()
        raw = response.read()
        conn.close()
    except OSError as e:
        return {'status': None, 'json': {}, 'error': str(e), 'ms': 0.0}
    try:
        parsed = json.loads(raw)
    except ValueError:
        parsed = {}
    return {'status': response.status, 'json': parsed if isinstance(parsed, dict) else {}, 'ms': (time.perf_counter() - started) * 1000}


def provider_hits(secret: str) -> list:
    status, body = call('GET', f"http://127.0.0.1:{PORTS['provider']}/admin/hits", headers={'X-Poc-Admin': secret})
    return body['hits'] if status == 200 else die('读不到 Provider 的记录')


def provider_reset(secret: str):
    call('POST', f"http://127.0.0.1:{PORTS['provider']}/admin/reset", headers={'X-Poc-Admin': secret}, form={})


def decisions() -> list:
    """gateway-authz 自己记下的判定。"""
    lines = []
    for line in (RUN / 'gateway-authz.log').read_text().splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if entry.get('msg') == 'egress authorization':
            lines.append(entry)
    return lines


def authz_times(subject: str, tenant: str, count: int = 300):
    """以网关的工作负载身份，在一条连接上连续问 gateway-authz；返回各次耗时（毫秒），有一次没放行就返回 None。"""
    headers = {'x-idp-verified-subject': subject, 'x-idp-verified-tenant': tenant, 'x-idp-verified-env': 'TEST',
               'x-idp-route-id': 'mockcarrier-tracking-get', 'x-idp-provider-id': 'mockcarrier', 'x-idp-operation-id': 'tracking.get',
               'x-idp-environment': 'TEST', 'x-idp-method': 'GET', 'x-idp-path': TRACKING}
    conn = pki.GatekeeperConnection(PORTS['authz'], pki.client_context(TLS, 'gateway'), 5)
    times = []
    try:
        for _ in range(count):
            started = time.perf_counter()
            conn.request('GET', '/v1/extauthz/check', headers=headers)
            response = conn.getresponse()
            response.read()
            times.append((time.perf_counter() - started) * 1000)
            if response.status != 200:
                return None
    finally:
        conn.close()
    return sorted(times)


def percentiles(times) -> dict | None:
    if not times:
        return None
    at = lambda q: round(times[min(len(times) - 1, int(len(times) * q))], 2)
    return {'p50': at(0.50), 'p90': at(0.90), 'p99': at(0.99), 'max': round(times[-1], 2)}


def forged(real: str) -> str:
    """别的密钥签的令牌，头和声明照抄真的那个。"""
    header = jwt.get_unverified_header(real)
    claims = jwt.decode(real, options={'verify_signature': False})
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return jwt.encode(claims, pem, algorithm='RS256', headers={'kid': header['kid']})


class Results:
    def __init__(self, version: str):
        self.version, self.cases, self.current = version, [], None

    def case(self, cid: str, title: str):
        self.current = {'id': cid, 'title': title, 'checks': [], 'notes': {}}
        self.cases.append(self.current)

    def check(self, what: str, ok: bool):
        self.current['checks'].append({'check': what, 'ok': bool(ok)})

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


# ---- 用例 --------------------------------------------------------------------------------
def run_cases(r: Results, state: dict, made: dict):
    secret, provider_tokens = made['admin_secret'], made['provider_tokens']
    blue, green, ungranted = (state[k]['client'] for k in ('blue', 'green', 'ungranted'))
    tok = {'blue': token_for(blue), 'green': token_for(green), 'ungranted': token_for(ungranted),
           'blue-no-aud': token_for(blue, None), 'blue-other-aud': token_for(blue, OTHER_AUDIENCE)}
    if not all(tok.values()):
        die('从本机的 Hydra 拿不到令牌')

    def fresh():
        provider_reset(secret)
        return len(decisions())

    def last_reason(since: int):
        new = decisions()[since:]
        return new[-1]['reason'] if new else None

    def wait_allowed(token: str, seconds: float = 40.0) -> bool:
        end = time.time() + seconds
        while time.time() < end:
            if gw(token)['status'] == 200:
                return True
            time.sleep(0.5)
        return False

    # 网关启动后要先取到 JWKS。
    if not wait_allowed(tok['blue'], 20):
        r.case('GK-00', '网关取到 JWKS，真实令牌可用')
        r.check('蓝租户的请求在 20 秒内被放行', False)
        r.note('last', gw(tok['blue']))
        return

    for cid, key, account in (('GK-01', 'blue', 'account-blue'), ('GK-02', 'green', 'account-green')):
        r.case(cid, f'{key} 租户的真实 M2M 令牌：Gatekeeper 确认授权，Provider 收到 {account} 的凭证')
        mark = fresh()
        answer = gw(tok[key])
        hits = provider_hits(secret)
        r.check('状态码 200', answer['status'] == 200)
        r.check(f'Provider 以 {account} 应答', answer['json'].get('account') == account)
        r.check('Provider 恰好收到一个请求', len(hits) == 1)
        if hits:
            headers = {k.lower(): v for k, v in hits[0]['headers']}
            r.check('Provider 收到的是该账户的凭证', headers.get('authorization') == 'Bearer ' + provider_tokens[account])
            r.check('调用方的 IDP 令牌没有到达 Provider', tok[key] not in json.dumps(hits[0]))
        r.check('gateway-authz 记为 ACTIVE_ACCOUNT_GRANT', last_reason(mark) == 'ACTIVE_ACCOUNT_GRANT')

    r.case('GK-03', '同一个客户端的令牌，但不是发给出站网关的：不带 audience 参数（aud 为空数组），或发给 ' + OTHER_AUDIENCE)
    for name in ('blue-no-aud', 'blue-other-aud'):
        mark = fresh()
        answer = gw(tok[name])
        r.check(f'{name}：状态码 401', answer['status'] == 401)
        r.check(f'{name}：没有到达 gateway-authz 和 Provider', len(decisions()) == mark and not provider_hits(secret))

    r.case('GK-04', '别的密钥签名、声明照抄真实令牌')
    mark = fresh()
    answer = gw(forged(tok['blue']))
    r.check('状态码 401', answer['status'] == 401)
    r.check('没有到达 gateway-authz 和 Provider', len(decisions()) == mark and not provider_hits(secret))

    r.case('GK-05', '登记表认的客户端，在 Gatekeeper 里没有这个账户的授权')
    mark = fresh()
    answer = gw(tok['ungranted'])
    r.check('状态码 403', answer['status'] == 403)
    r.check('原因是 ACCOUNT_NOT_GRANTED', answer['json'].get('reason_code') == 'ACCOUNT_NOT_GRANTED' and last_reason(mark) == 'ACCOUNT_NOT_GRANTED')
    r.check('Provider 没有收到请求', not provider_hits(secret))

    r.case('GK-06', '蓝租户申请绿租户的账户')
    mark = fresh()
    answer = gw(tok['blue'], 'account-green')
    r.check('状态码 403', answer['status'] == 403)
    r.check('原因是 ACCOUNT_NOT_GRANTED', last_reason(mark) == 'ACCOUNT_NOT_GRANTED')
    r.check('Provider 没有收到请求', not provider_hits(secret))

    r.case('GK-07', '在 Gatekeeper 里收回授权：下一个请求就被拒绝；恢复后又放行；期间没有重启任何进程')
    grant = (f"user:{blue['client_id']}", 'caller', 'provider_account:account-blue')
    write_tuple('DELETE', *grant)
    try:
        mark = fresh()
        answer = gw(tok['blue'])
        r.check('收回后状态码 403', answer['status'] == 403)
        r.check('原因是 ACCOUNT_NOT_GRANTED', last_reason(mark) == 'ACCOUNT_NOT_GRANTED')
        r.check('Provider 没有收到请求', not provider_hits(secret))
        r.check('绿租户不受影响', gw(tok['green'])['status'] == 200)
    finally:
        write_tuple('POST', *grant)
    r.check('恢复后立即放行', gw(tok['blue'])['status'] == 200)

    for cid, service, title in (('GK-08', 'openfga', 'Gatekeeper 背后的授权引擎停了（PDP 仍以 200 应答）'),
                                ('GK-09', 'login-consent', 'Gatekeeper 的 PDP 本身不可达')):
        r.case(cid, title + '：不放行，也不记成策略拒绝；恢复后自动恢复')
        container(service, 'stop')
        try:
            mark = fresh()
            answer = gw(tok['blue'])
            r.note('调用方看到的状态码', answer['status'])
            r.check('不是成功状态码', answer['status'] is not None and answer['status'] >= 400)
            r.check('gateway-authz 记为 GRANT_STATE_UNAVAILABLE', last_reason(mark) == 'GRANT_STATE_UNAVAILABLE')
            r.check('Provider 没有收到请求', not provider_hits(secret))
        finally:
            container(service, 'start')
        r.check('恢复后放行（不重启网关和 gateway-authz）', wait_allowed(tok['blue']))

    r.case('GK-10', 'gateway-authz 拿着错误的 PDP 令牌')
    stop('gateway-authz')
    start_authz(RUN / 'pdp-token.wrong')
    try:
        mark = fresh()
        answer = gw(tok['blue'])
        r.note('调用方看到的状态码', answer['status'])
        r.check('不是成功状态码', answer['status'] is not None and answer['status'] >= 400)
        r.check('gateway-authz 记为 GRANT_STATE_UNAVAILABLE', last_reason(mark) == 'GRANT_STATE_UNAVAILABLE')
        r.check('Provider 没有收到请求', not provider_hits(secret))
    finally:
        stop('gateway-authz')
        start_authz(RUN / 'pdp-token')
    r.check('换回正确的令牌后放行', wait_allowed(tok['blue'], 10))

    r.case('GK-11', 'gateway-authz 一次判定的耗时，问与不问 Gatekeeper（同一条连接上连续 300 次；仅记录，不设门槛）')
    subject, tenant = blue['client_id'], state['blue']['tenant_id']
    asking = authz_times(subject, tenant)
    stop('gateway-authz')
    start_authz(None)
    try:
        alone = authz_times(subject, tenant)
    finally:
        stop('gateway-authz')
        start_authz(RUN / 'pdp-token')
    r.note('每次都问 Gatekeeper（毫秒）', percentiles(asking))
    r.note('只看登记表（毫秒）', percentiles(alone))
    r.check('两种情况下 300 次都放行', bool(asking) and bool(alone))
    if KEY_ROTATION:
        r.case('GK-12', f'本机 Hydra 换了访问令牌的签名密钥：网关不重启，{ROTATION_WAIT} 秒内接受新密钥签的令牌')
        kid = lambda t: jwt.get_unverified_header(t)['kid']
        old = token_for(blue)
        # 往访问令牌的密钥集里加一把新密钥，Hydra 随即用它签发；旧密钥仍在 JWKS 里。
        made_key = subprocess.run(['docker', 'exec', f'{PROJECT}-hydra-1', 'hydra', 'create', 'jwks', 'hydra.jwt.access-token',
                                   '--alg', 'RS256', '--endpoint', 'http://127.0.0.1:4445', '--format', 'json'],
                                  capture_output=True, text=True)
        new, end = None, time.time() + 30
        while made_key.returncode == 0 and time.time() < end:
            new = token_for(blue)
            if new and kid(new) != kid(old):
                break
            new = None
            time.sleep(1)
        r.check('Hydra 开始用新密钥签发', new is not None)
        if new:
            r.check('旧密钥签的令牌仍被接受', gw(old)['status'] == 200)
            r.note('新密钥签的令牌，第一个请求的状态码', gw(new)['status'])
            r.check(f'{ROTATION_WAIT} 秒内被接受', wait_allowed(new, ROTATION_WAIT))

    logs = ''.join((RUN / f'{n}.log').read_text(errors='replace') for n in ('gateway-authz', 'gateway'))
    r.check('PDP 令牌、Provider 凭证和客户端密钥都不在网关与 gateway-authz 的日志里',
            not any(s in logs for s in [ENV['GK_PDP_AUTH_TOKEN'], *provider_tokens.values(), *(state[k]['client']['client_secret'] for k in state)]))


def main() -> int:
    global KEY_ROTATION
    parser = argparse.ArgumentParser(description='gateway-authz 与本机 Gatekeeper 的联调')
    parser.add_argument('--key-rotation', action='store_true',
                        help=f'加跑 GK-12：给本机 Hydra 换访问令牌的签名密钥（每个网关版本多等至多 {ROTATION_WAIT} 秒，并给本机实例留下一把新密钥）')
    KEY_ROTATION = parser.parse_args().key_rotation
    if call('GET', ISSUER + '/health/ready')[0] != 200 or call('GET', BRIDGE + '/admin/me')[0] != 200:
        die('本机的 Gatekeeper 没有就绪：运行 tests/integration/gatekeeper/stack.sh up')
    state = seed()
    sync_tuples(state)
    made = prepare(state)
    summary, exit_code = {}, 0
    for version, binary in BINARIES.items():
        if not Path(binary).exists():
            print(f'agentgateway {version}: 没有找到 {binary}，跳过')
            continue
        results = Results(version)
        try:
            start_all(binary)
            run_cases(results, state, made)
        finally:
            stop_all()
            sync_tuples(state)
        print(f'\nagentgateway {version}')
        results.report()
        failed = results.failed()
        summary[version] = {'cases': results.cases, 'passed': len(results.cases) - len(failed), 'failed': [c['id'] for c in failed]}
        exit_code |= bool(failed)
    gatekeeper_commit = subprocess.run(['git', '-C', os.environ.get('GK_SRC', str(Path.home() / '.local/src/idp-gatekeeper')),
                                        'rev-parse', '--short', 'HEAD'], capture_output=True, text=True).stdout.strip()
    (RUN / 'result.json').write_text(json.dumps({'gatekeeper_commit': gatekeeper_commit, 'gateway_differences': GATEWAY_DIFFERENCES,
                                                 'agentgateway': summary}, ensure_ascii=False, indent=1), encoding='utf-8')
    print('\n' + '；'.join(f"{v}: {s['passed']}/{len(s['cases'])}" for v, s in summary.items()),
          f'（Gatekeeper {gatekeeper_commit}；详细结果在 {RUN / "result.json"}）')
    return int(exit_code)


if __name__ == '__main__':
    sys.exit(main())
