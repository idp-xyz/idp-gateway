#!/usr/bin/env python3
"""WanbExpress on the single-host pool (development plan 3.2, second step): deploy/compose/compose.yml with the overlay
deploy/compose/gateway-authz.yml, the configuration deploy/providers/wanbexpress/agentgateway.yaml published by gateway-control, callers
coming in through front, the egress rules in force, the PDP being the local Gatekeeper stack's pdp-mtls.

    tests/integration/gatekeeper/stack.sh up                                         the local Gatekeeper (left up)
    .venv/bin/python tests/integration/wanbexpress/pool.py                           upstream is the stand-in (a container of the pool's network)
    .venv/bin/python tests/integration/wanbexpress/pool.py --sandbox --sandbox-credentials FILE
    .venv/bin/python tests/integration/wanbexpress/pool.py --control no-egress       the services that install the egress rules do nothing: WB-11 fails
    .venv/bin/python tests/integration/wanbexpress/pool.py --control no-pdp-tls      gateway-authz without its --gatekeeper-tls-* arguments, and a variable missing

The cases are those of run.py (WB-01 to WB-10, imported and used as they are) with these differences: WB-09 is skipped (it swaps gateway-authz for
the acceptance build, which the pool does not run); what the gateway and gateway-authz logged is read from the containers; and WB-11 is
added: the egress rules are in force. The pool is a compose project of its own (PROJECT), on ports 27631-27634; it is taken down with its
volumes, and the temporary directory with everything in it removed, however the run ends. Only this project and the Gatekeeper stack are touched.
"""
from __future__ import annotations
import argparse, atexit, datetime, importlib.util, json, os, re, secrets, shutil, socket, subprocess, sys, tempfile, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
_spec = importlib.util.spec_from_file_location('wb_run', HERE / 'run.py')
wb = importlib.util.module_from_spec(_spec)
sys.modules['wb_run'] = wb
_spec.loader.exec_module(wb)
gk, pki, pin = wb.gk, wb.pki, wb.pin

DEPLOY = ROOT / 'deploy/compose'
PROJECT = 'idp-gateway-wanb-pool'
SCRATCH = f'{PROJECT}-scratch'
PORT = {'front': 27631, 'readback': 27632, 'staging': 27633, 'mock': 27634}
IN_POOL = {'callers': 8081, 'readback': 8443, 'admin': 15000, 'stats': 15020}     # in the namespace of netns
TOOLS_IMAGE = ('public.ecr.aws/docker/library/python:3.13-alpine@sha256:1e1f6334529d1fb26a2ef619d7cffb30a7c7d7cc1cc7338ebee283a58d1aeaca')
PDP_ADDRESS = 'https://pdp-mtls:8443'     # the service name and container port of the PDP's mutual-TLS front in the Gatekeeper stack
GATEWAY_IMAGE = pin.image_reference(pin.lock())
RUN_AS = f'{os.getuid()}:{os.getgid()}'
GO = wb.GO
WORK: Path = None          # the temporary directory of this run
STANDIN = True
CONTROL_NAME = None


def die(message: str):
    print('pool.py:', message, file=sys.stderr)
    raise SystemExit(2)


def docker(*argv: str, timeout: float = 300) -> subprocess.CompletedProcess:
    return subprocess.run(['docker', *argv], capture_output=True, text=True, timeout=timeout)


def settings() -> dict:
    pool, authz = WORK / 'pool', WORK / 'authz'
    return {
        'CALLERS_LISTEN': f"127.0.0.1:{PORT['front']}", 'READBACK_PORT': str(PORT['readback']), 'READBACK_NAME': pki.READBACK_NAME,
        'POOL_DIR': str(pool), 'GATEWAY_USER': RUN_AS, 'CONTROL_USER': RUN_AS, 'GATEWAY_ENV_FILE': str(pool / 'gateway.env'),
        'GATEWAY_CONTROL': str(WORK / 'bin/gateway-control'), 'PUBLISHER_CERT': str(gk.TLS / 'publisher.crt'),
        'PUBLISHER_KEY': str(gk.TLS / 'publisher.key'), 'READBACK_CA': str(gk.TLS / 'ca.crt'), 'CONFIRM_TIMEOUT': '30s',
        # gateway-authz.yml (gateway-authz.env.example)
        'GATEWAY_AUTHZ': str(WORK / 'bin/gateway-authz'), 'GATEWAY_AUTHZ_USER': RUN_AS, 'GATEWAY_AUTHZ_POLICY': str(authz / 'policy.json'),
        'GATEWAY_AUTHZ_CREDENTIALS_DIR': str(authz / 'credentials'), 'GATEWAY_AUTHZ_TLS_CERT': str(gk.TLS / 'gatekeeper.crt'),
        'GATEWAY_AUTHZ_TLS_KEY': str(gk.TLS / 'gatekeeper.key'), 'GATEWAY_AUTHZ_GATEWAY_CA': str(gk.TLS / 'ca.crt'),
        'GATEWAY_AUTHZ_GATEWAY_IDENTITY': pki.ID['gateway'], 'GATEWAY_AUTHZ_PDP_URL': PDP_ADDRESS, 'GATEWAY_AUTHZ_PDP_NAME': gk.PDP_NAME,
        'GATEWAY_AUTHZ_PDP_TOKEN_FILE': str(authz / 'pdp-token'), 'GATEWAY_AUTHZ_PDP_CERT': str(gk.TLS / 'gateway-authz.crt'),
        'GATEWAY_AUTHZ_PDP_KEY': str(gk.TLS / 'gateway-authz.key'), 'GATEWAY_AUTHZ_PDP_CA': str(gk.TLS / 'ca.crt'),
        # the test overlay
        'TOOLS_IMAGE': TOOLS_IMAGE, 'MOCK_HOST_PORT': str(PORT['mock']), 'MOCK_SCRIPT': str(wb.MOCK), 'MOCK_STATE': str(WORK / 'mock-state.json'),
    }


def compose_files(extra: tuple = ()) -> list[str]:
    files = [DEPLOY / 'compose.yml', DEPLOY / 'gateway-authz.yml', HERE / 'pool.yml', *extra]
    return [a for f in files for a in ('-f', str(f))]


def compose(*argv: str, timeout: float = 300, extra: tuple = ()) -> subprocess.CompletedProcess:
    env_file = WORK / 'pool.env'
    names = set(settings())
    env = {k: v for k, v in os.environ.items() if k not in names and not k.startswith('COMPOSE_')}
    if STANDIN:
        env['COMPOSE_PROFILES'] = 'standin'
    return subprocess.run(['docker', 'compose', '-p', PROJECT, '--env-file', str(env_file), *compose_files(extra), *argv],
                          capture_output=True, text=True, timeout=timeout, env=env)


def container(service: str) -> dict:
    found = compose('ps', '-q', '-a', service).stdout.split()
    inspected = json.loads(docker('inspect', found[0]).stdout or '[]') if found else []
    if not inspected:
        return {}
    c = inspected[0]
    return {'id': c['Id'], 'name': c['Name'].lstrip('/'), 'running': c['State']['Running'], 'exit': c['State']['ExitCode'],
            'env': c['Config'].get('Env') or [], 'ip': ((c['NetworkSettings'].get('Networks') or {}).get(f'{PROJECT}_default') or {}).get('IPAddress', '')}


def wait_for(predicate, seconds: float, every: float = 0.3):
    end = time.time() + seconds
    while time.time() < end:
        value = predicate()
        if value:
            return value
        time.sleep(every)
    return None


# ---- the files the pool is given -----------------------------------------------------------------------------------------
def build(package: str, target: str):
    done = subprocess.run([GO, 'build', '-trimpath', '-o', str(WORK / 'bin' / target), package], cwd=ROOT, capture_output=True, text=True,
                          env={**os.environ, 'CGO_ENABLED': '0'})      # static: they run in an image without glibc
    if done.returncode != 0:
        die(f'{package} does not build:\n' + done.stderr[-1500:])


def put(path: Path, content: str | bytes, mode: int = 0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(content if isinstance(content, bytes) else content.encode())
    os.chmod(path, mode)


def prepare(state: dict, made: dict, sandbox: bool, snapshot_text: str):
    pool, authz, control = WORK / 'pool', WORK / 'authz', WORK / 'control'
    for directory in (pool / 'config', pool / 'tls', authz / 'credentials', control / 'work', control / 'tls', control / 'snapshots'):
        directory.mkdir(parents=True, exist_ok=True)
    os.chmod(pool / 'config', 0o755)
    os.chmod(authz / 'credentials', 0o700)
    os.chmod(pool, 0o755)
    jwks = gk.call('GET', gk.ISSUER + '/.well-known/jwks.json')
    if jwks[0] != 200 or not isinstance(jwks[1], dict) or not jwks[1].get('keys'):
        die('no JWKS from the local Hydra')
    # Only the key that signs the tokens now. The gateway's dump lists the keys of a JWKS in an order that changes from one start to the next, and the
    # publisher's digest is sensitive to the order of a list: with two keys in the file the publisher sometimes sees a digest that is not the one it
    # staged (one run in three here). The local Hydra has two (a key rotation was tried on it earlier). Reported, not worked around in the publisher.
    kid = wb.gk.jwt.get_unverified_header(gk.token_for(state['blue']['client']))['kid']
    jwks[1]['keys'] = [k for k in jwks[1]['keys'] if k.get('kid') == kid]
    if len(jwks[1]['keys']) != 1:
        die('the signing key of the tokens is not in the JWKS exactly once')
    # certificates: the rig's, because the PDP's mutual-TLS front trusts this run's CA (publish_pdp_tls)
    for name in ('gateway-readback.crt', 'gateway-readback.key', 'gateway.crt', 'gateway.key', 'ca.crt'):
        shutil.copy2(gk.TLS / name, pool / 'tls' / name)
    for directory in (pool / 'tls', control / 'tls'):
        put(directory / 'jwks.json', json.dumps(jwks[1]), 0o644)
        for name in ('gateway-readback.crt', 'gateway-readback.key', 'gateway.crt', 'gateway.key', 'ca.crt'):
            if directory != pool / 'tls':
                shutil.copy2(gk.TLS / name, directory / name)
    put(pool / 'gateway.env', f'SESSION_KEY={secrets.token_hex(32)}\n')
    put(authz / 'policy.json', wb.policy_for(state, sandbox))
    put(authz / 'pdp-token', gk.ENV['GK_PDP_AUTH_TOKEN'] + '\n')
    table = {f'{wb.BINDING}/{a}': {'account': n, 'token': t} for a, (n, t) in made['accounts'].items()}
    put(authz / 'credentials' / 'developer-tokens.json', json.dumps(table))
    put(WORK / 'mock-state.json', json.dumps({'admin_secret': made['mock_secret'], 'accounts': {f'{n};{t}': n for n, t in made['accounts'].values()}}))
    put(WORK / 'pool.env', ''.join(f'{k}={v}\n' for k, v in settings().items()), 0o600)
    build('./cmd/gateway-control', 'gateway-control')
    build('./cmd/gateway-authz', 'gateway-authz')
    # the first configuration the gateway starts from: only the read-back listener and its route. Published over it is the real one.
    import yaml
    full = yaml.safe_load(snapshot_text)
    first = {k: v for k, v in full.items() if k not in ('gateways', 'routes')}
    first['gateways'] = {'read-back': full['gateways']['read-back']}
    first['routes'] = [r for r in full['routes'] if r['name'] == 'read-back']
    put(pool / 'config' / 'config.yaml', yaml.safe_dump(first, sort_keys=False), 0o644)
    return control


# ---- the publisher ---------------------------------------------------------------------------------------------------------------
def control_flags() -> list[str]:
    return ['--config-dir', str(WORK / 'pool/config'), '--read-back', f"127.0.0.1:{PORT['readback']}", '--read-back-name', pki.READBACK_NAME,
            '--tls-cert', str(gk.TLS / 'publisher.crt'), '--tls-key', str(gk.TLS / 'publisher.key'), '--tls-ca', str(gk.TLS / 'ca.crt')]


def publish(snapshot_text: str) -> dict:
    snapshot = WORK / 'control/snapshots/wanbexpress.yaml'
    put(snapshot, snapshot_text, 0o644)
    argv = [str(WORK / 'bin/gateway-control'), 'publish', '--snapshot', str(snapshot), *control_flags(),
            '--image', GATEWAY_IMAGE, '--staging-name', SCRATCH, '--staging-publish', f"127.0.0.1:{PORT['staging']}",
            '--staging-container-port', str(IN_POOL['readback']), '--staging-tls-dir', str(WORK / 'control/tls'),
            '--staging-work-dir', str(WORK / 'control/work')]
    started = time.monotonic()
    done = subprocess.run(argv, capture_output=True, text=True, timeout=180)
    try:
        report = json.loads(done.stdout) if done.stdout.strip() else {}
    except ValueError:
        report = {'unparsed': done.stdout[:300]}
    return {'exit': done.returncode, 'outcome': report.get('outcome') or report.get('status'), 'report_keys': sorted(report) if isinstance(report, dict) else None,
            'stderr': done.stderr.strip()[-300:], 'detail': {k: v for k, v in report.items() if k in ('reason', 'detail', 'message', 'error', 'loaded', 'last_error')}, 'seconds': round(time.monotonic() - started, 2)}


def read_back(path: str) -> dict:
    try:
        conn = pki.GatekeeperConnection(PORT['readback'], pki.client_context(gk.TLS, 'publisher'), 3, pki.READBACK_NAME)
        conn.request('GET', path, headers={'Host': pki.READBACK_NAME})
        response = conn.getresponse()
        body = response.read()
        conn.close()
        return {'status': response.status, 'json': json.loads(body)}
    except (OSError, ValueError):
        return {'status': None}


# ---- what the cases read from the pool ---------------------------------------------------------------------------------------------
def pool_decisions() -> list:
    out = []
    for line in compose('logs', '--no-color', '--no-log-prefix', 'gateway-authz').stdout.splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and entry.get('msg') == 'egress authorization':
            out.append(entry)
    return out


def pool_peers() -> set:
    """What the gateway holds connections to, read from the namespace it is in (netns: nothing else in there connects outwards but front)."""
    netns = container('netns')
    texts = {name: docker('exec', netns['name'], 'cat', f'/proc/net/{name}').stdout for name in ('tcp', 'tcp6')}
    return wb.peers_from_tables(texts)


def logs_of() -> dict:
    return {f'{service} log': compose('logs', '--no-color', '--no-log-prefix', service).stdout for service in ('agentgateway', 'gateway-authz', 'front')}


CONNECT = r'''
import json, socket, sys
seen = {}
for target in sys.argv[1:]:
    host, port = target.rsplit(":", 1)
    with socket.socket() as s:
        s.settimeout(3)
        seen[target] = s.connect_ex((host, int(port)))
print(json.dumps(seen))
'''
RESOLVE = r'''
import json, socket, sys
seen = {}
for name in sys.argv[1:]:
    try:
        seen[name] = sorted(set(socket.gethostbyname_ex(name)[2]))
    except OSError as e:
        seen[name] = type(e).__name__
print(json.dumps(seen))
'''


def from_the_pool(code: str, *argv: str) -> dict:
    """A throwaway container in the namespace of netns (the gateway's): it prints one JSON. Not part of the project."""
    done = docker('run', '--rm', '--network', f"container:{container('netns')['id']}", TOOLS_IMAGE, 'python', '-c', code, *argv)
    try:
        return json.loads(done.stdout)
    except ValueError:
        return {'error': (done.stderr or done.stdout).strip()[-300:]}


def pinned() -> dict:
    """What the egress rules pin: {"name:port": [addresses]}, read by another throwaway container of the egress service."""
    listed = compose('run', '--rm', '--no-deps', '--entrypoint', 'iptables', 'egress', '-S', 'IDP_EGRESS').stdout
    found = {}
    for line in listed.splitlines():
        words = line.replace('"', '').split()
        if '--comment' in words and '-d' in words and words[words.index('--comment') + 1].startswith('pin:'):
            found.setdefault(words[words.index('--comment') + 1][4:], []).append(words[words.index('-d') + 1].split('/')[0])
    return {key: sorted(addresses) for key, addresses in found.items()}


REFUSED_BY_RULE = 113      # EHOSTUNREACH: the rule rejects with icmp-host-prohibited (as in tests/integration/compose)


def egress_case(r: wb.Results, sandbox: bool, extra: dict):
    STATE = wb.STATE
    STATE['label'] = 'WB-11'
    r.case('WB-11', 'the egress rules are in force: from the gateway\'s namespace the registered upstream is reachable, an address that is not registered is not; the pinned addresses are what the upstream name resolves to')
    held = pinned()
    r.note('pinned by the egress rules', held)
    authz = container('gateway-authz')['ip']
    outsider = container('outsider')['ip']
    if sandbox:
        upstream = 'api-sbx.wanbexpress.com:80'
        resolved = from_the_pool(RESOLVE, 'api-sbx.wanbexpress.com', 'gateway-authz', 'outsider')
        listed = held.get(upstream, [])
        r.note('api-sbx.wanbexpress.com resolved from the namespace of netns to', resolved.get('api-sbx.wanbexpress.com'))
        r.check('the sandbox name is pinned, on port 80, to addresses the namespace\'s resolver (or this host\'s) gives for it',
                bool(listed) and set(listed) <= set(resolved.get('api-sbx.wanbexpress.com') or []) | set(wb_resolve_host()))
        targets = [f'{a}:80' for a in listed]
        refused = [f'{outsider}:8000', f'{authz}:9444']
    else:
        mock = container('wanb-mock')['ip']
        upstream = 'wanb-mock:8000'
        r.check('the stand-in\'s name is pinned, on port 8000, to the address the stand-in has', held.get(upstream) == [mock])
        targets = [f'{mock}:8000']
        refused = [f'{outsider}:8000', f'{mock}:8001', f'{authz}:9444']
    r.check('gateway-authz\'s name is pinned, on port 9443, to the address gateway-authz has', held.get('gateway-authz:9443') == [authz])
    r.check('the gateway\'s own admin address (read-back route) is allowed on loopback', held.get(f"127.0.0.1:{IN_POOL['admin']}") == ['127.0.0.1'])
    seen = from_the_pool(CONNECT, *targets, f'{authz}:9443', f"127.0.0.1:{IN_POOL['callers']}", *refused, f"127.0.0.1:{IN_POOL['stats']}")
    r.note('connect() from the gateway\'s namespace (0 connected, 113 refused by the rule)', seen)
    r.check('the registered upstream (address and port) can be connected to', bool(targets) and all(seen.get(t) == 0 for t in targets))
    r.check('gateway-authz\'s registered address and port, and loopback 8081 (where front hands the callers\' requests), can be connected to',
            seen.get(f'{authz}:9443') == 0 and seen.get(f"127.0.0.1:{IN_POOL['callers']}") == 0)
    r.check('the other container of the network (outsider), another port on the registered addresses, and the gateway\'s stats port on loopback are refused by the rule',
            all(seen.get(t) == REFUSED_BY_RULE for t in [*refused, f"127.0.0.1:{IN_POOL['stats']}"]))
    r.check('the rules are the ones installed by the egress service of the project (the pins can be listed)', bool(held))
    extra['egress'] = {'pinned': held, 'upstream_name': upstream}


def wb_resolve_host() -> list:
    return sorted({a[4][0] for a in socket.getaddrinfo('api-sbx.wanbexpress.com', 80, type=socket.SOCK_STREAM)})


# ---- the controls that need no pool of requests ---------------------------------------------------------------------------------------
def control_no_pdp_tls() -> dict:
    """gateway-authz started without its --gatekeeper-tls-* arguments (the URL is not loopback), and the overlay with a variable missing."""
    base = ['--listen=0.0.0.0:9443', '--tls-cert=/authz/server.crt', '--tls-key=/authz/server.key', '--client-ca=/authz/gateway-ca.crt',
            f"--gateway-identity={pki.ID['gateway']}", '--policy=/authz/policy.json', '--developer-tokens=/authz/credentials/developer-tokens.json',
            f'--gatekeeper-url={PDP_ADDRESS}', '--gatekeeper-token-file=/authz/pdp-token']
    done = compose('run', '--rm', '--no-deps', '-T', 'gateway-authz', *base, timeout=60)
    text = (done.stdout + done.stderr).strip().splitlines()
    names = set(settings())
    env = {k: v for k, v in os.environ.items() if k not in names and not k.startswith('COMPOSE_')}
    lines = [l for l in (WORK / 'pool.env').read_text().splitlines() if not l.startswith('GATEWAY_AUTHZ_PDP_CA=')]
    put(WORK / 'missing.env', '\n'.join(lines) + '\n')
    missing = subprocess.run(['docker', 'compose', '-p', PROJECT, '--env-file', str(WORK / 'missing.env'), *compose_files(), 'config', '-q'],
                             capture_output=True, text=True, env=env)
    return {'without_gatekeeper_tls_arguments': {'exit': done.returncode, 'last_line': text[-1][:240] if text else ''},
            'a_variable_missing': {'exit': missing.returncode, 'said': (missing.stderr.strip().splitlines() or [''])[-1][:240]}}


# ---- the run -------------------------------------------------------------------------------------------------------------------
def teardown():
    if WORK is None or os.environ.get('WB_POOL_KEEP'):
        return
    if (WORK / 'pool.env').exists():
        compose('down', '--volumes', '--remove-orphans', '--timeout', '5', extra=(HERE / 'pool_no_egress.yml',) if CONTROL_NAME == 'no-egress' else ())
    mine = f'label=com.docker.compose.project={PROJECT}'
    left = docker('ps', '-a', '-q', '--filter', mine).stdout.split()
    if left:
        docker('rm', '-f', '-v', *left)
    for network in docker('network', 'ls', '-q', '--filter', mine).stdout.split():
        docker('network', 'rm', network)
    docker('rm', '-f', SCRATCH)
    shutil.rmtree(WORK, ignore_errors=True)


def main() -> int:
    global WORK, STANDIN, CONTROL_NAME
    parser = argparse.ArgumentParser(description='deploy/providers/wanbexpress on the single-host pool')
    parser.add_argument('--sandbox', action='store_true')
    parser.add_argument('--sandbox-credentials')
    parser.add_argument('--control', choices=['no-egress', 'no-pdp-tls'], help='a deliberate break, stand-in only')
    parser.add_argument('--mutate', choices=sorted(wb.MUTATIONS))
    args = parser.parse_args()
    if args.sandbox != bool(args.sandbox_credentials):
        die('--sandbox and --sandbox-credentials go together')
    if args.sandbox and (args.control or args.mutate):
        die('--control and --mutate are for the stand-in only')
    sandbox, STANDIN, CONTROL_NAME = args.sandbox, not args.sandbox, args.control
    for port in PORT.values():
        with socket.socket() as s:
            s.settimeout(0.3)
            if s.connect_ex(('127.0.0.1', port)) == 0:
                die(f'port {port} is in use')
    if gk.call('GET', gk.ISSUER + '/health/ready')[0] != 200 or gk.call('GET', gk.BRIDGE + '/admin/me')[0] != 200:
        die('the local Gatekeeper is not ready: tests/integration/gatekeeper/stack.sh up')
    binary, reported = pin.resolve()
    made: dict = {'mock_secret': secrets.token_urlsafe(24)}
    if sandbox:
        account, token = wb.read_sandbox_credentials(args.sandbox_credentials)
        made['accounts'] = {wb.BLUE_ACCOUNT: (account, token)}
    else:
        made['accounts'] = {a: ('WB' + secrets.token_hex(4).upper(), secrets.token_hex(20)) for a in (wb.BLUE_ACCOUNT, wb.GREEN_ACCOUNT)}
    WORK = Path(tempfile.mkdtemp(prefix='wanb-pool-'))
    if not os.environ.get('WB_POOL_KEEP'):
        atexit.register(shutil.rmtree, WORK, True)
    try:
        return run(args, made, sandbox, reported)
    finally:
        teardown()


def run(args, made: dict, sandbox: bool, reported: dict) -> int:
    state = gk.seed()
    gk.sync_tuples(state)
    pki.issue(gk.TLS)
    gk.publish_pdp_tls()
    snapshot = wb.gateway_config(sandbox, args.mutate, pool=True)
    prepare(state, made, sandbox, snapshot)
    wb.say(f'pool {PROJECT} in {WORK} ({"sandbox" if sandbox else "stand-in"})')
    extra_files = (HERE / 'pool_no_egress.yml',) if args.control == 'no-egress' else ()

    if args.control == 'no-pdp-tls':
        result = control_no_pdp_tls()
        wb.say(json.dumps(result, indent=1))
        (wb.OUT).mkdir(exist_ok=True)
        (wb.OUT / 'result-pool-control-no-pdp-tls.json').write_text(json.dumps(result, indent=1))
        refused_to_start = result['without_gatekeeper_tls_arguments']['exit'] != 0
        return int(not refused_to_start)

    services = ['agentgateway', 'gateway-authz', 'outsider'] + (['wanb-mock'] if STANDIN else [])
    record: dict = {'steps': {}}
    first = compose('up', '-d', *services, extra=extra_files, timeout=600)
    record['steps']['up_first'] = {'exit': first.returncode, 'said': (first.stderr.strip().splitlines() or [''])[-1][:200]}
    if first.returncode != 0:
        wb.say('the pool did not start: ' + first.stderr[-600:])
        return 1
    if not wait_for(lambda: read_back('/api/runtime')['status'] == 200, 40):
        wb.say('the gateway\'s read-back does not answer')
        return 1
    published = publish(snapshot)
    record['steps']['publish'] = published
    wb.say(f"publish: exit {published['exit']}, outcome {published['outcome']}, {published['detail']}")
    full = compose('up', '-d', extra=extra_files, timeout=600)
    record['steps']['up_full'] = {'exit': full.returncode, 'said': (full.stderr.strip().splitlines() or [''])[-1][:200]}
    if published['exit'] != 0 or full.returncode != 0:
        wb.say('publish or the full start failed: ' + published['stderr'] + full.stderr[-400:])
        wb.say('gateway log, last lines:\n' + '\n'.join([l for l in compose('logs', '--no-color', '--no-log-prefix', 'agentgateway').stdout.splitlines() if 'request gateway' not in l][-14:]))
        return 1

    wb.HOOKS.update(second_authorization_reaches_the_gateway=False, gateway_port=PORT['front'], mock_port=PORT['mock'], decisions=pool_decisions, peers=pool_peers,
                    skip_wb09='the pool runs the product build of gateway-authz; WB-09 swaps in the acceptance build')
    wb.MOCK_SECRET = made['mock_secret']
    tok_blue = gk.token_for(state['blue']['client'])
    # ready: past 401 (the JWKS is read from the file at once), and an answer from gateway-authz (403: allowed, refused by the path rule)
    if not wait_for(lambda: wb.req('GET', f'{wb.BASE}/parcels', tok_blue)['status'] == 403, 40):
        wb.say('requests through front do not get as far as the gateway\'s path rule')
        return 1
    wb.CALLS.clear()
    results = wb.Results()
    started_at = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
    try:
        wb.run_cases(results, state, made, sandbox)
        extras: dict = {}
        egress_case(results, sandbox, extras)
    finally:
        leftovers = [c for c, s in wb.CREATED.items() if s != 'deleted']
        for code in leftovers:
            try:
                if wb.data(wb.req('DELETE', f'{wb.BASE}/parcels/{code}', tok_blue)).get('Succeeded') is True:
                    wb.CREATED[code] = 'deleted'
            except Exception:
                pass
    # the environment of the containers: proxy variables
    proxies = {s: sorted(e.split('=', 1)[0] for e in container(s)['env'] if 'proxy' in e.split('=', 1)[0].lower()) for s in ('agentgateway', 'front', 'netns', 'gateway-authz')}
    mode = f"pool, {'sandbox' if sandbox else 'stand-in'}" + (f' (control: {args.control or args.mutate})' if (args.control or args.mutate) else '')
    uncleaned = sorted(c for c, s in wb.CREATED.items() if s != 'deleted')
    record.update({'finished_at': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'), 'started_at': started_at, 'mode': mode,
                   'project': PROJECT, 'agentgateway': reported['version'],
                   'repository_head': subprocess.run(['git', '-C', str(ROOT), 'rev-parse', '--short', 'HEAD'], capture_output=True, text=True).stdout.strip(),
                   'gatekeeper_commit': subprocess.run(['git', '-C', os.environ.get('GK_SRC', str(Path.home() / '.local/src/idp-gatekeeper')), 'rev-parse', '--short', 'HEAD'],
                                                       capture_output=True, text=True).stdout.strip(),
                   'proxy_variables_in_the_containers': proxies, 'egress': extras.get('egress'),
                   'upstream': ({'kind': 'the carrier\'s sandbox', 'name': wb.SANDBOX_HOST, 'port': 80, 'name_resolved_to_by_this_host': wb_resolve_host(),
                                 'addresses_the_pool_held_connections_to': sorted(wb.PEERS)} if sandbox else {'kind': 'stand-in', 'name': 'wanb-mock:8000'}),
                   'calls': wb.CALLS, 'parcels_to_delete_by_hand': uncleaned})
    record['cases'] = results.cases
    failed = results.failed()
    scanned, looked_for = wb.scan(made, state, json.dumps(record, ensure_ascii=False, indent=1), logs_of())
    results.case('WB-10', 'the logs of the gateway, gateway-authz and front (the containers\'), this run\'s output and the result file hold no token and no Authorization of the carrier\'s scheme')
    for where, found in scanned.items():
        results.check(f'{where}: none of the {len(looked_for)} secrets of this run, and no value of the carrier\'s authorization scheme',
                      not found['secret found'] and not found['Authorization value of the carrier\'s scheme found'])
    results.cases.sort(key=lambda c: int(c['id'][3:]))
    failed = results.failed()
    record.update({'cases': results.cases, 'secret_scan': {'looked_for': looked_for, 'outcome': scanned},
                   'passed': [c['id'] for c in results.cases if c not in failed], 'failed': [c['id'] for c in failed]})
    name = wb.OUT / f"result-pool-{'sandbox' if sandbox else 'standin'}{'-' + (args.control or args.mutate) if (args.control or args.mutate) else ''}.json"
    wb.OUT.mkdir(exist_ok=True)
    put(name, json.dumps(record, ensure_ascii=False, indent=1))
    wb.say(f'\nagentgateway {reported["version"]}; {mode}')
    results.report()
    wb.say(f'  proxy variables in the containers: {proxies}')
    if sandbox:
        wb.say(f'  the pool held connections to {sorted(wb.PEERS)}')
    wb.say('  calls to front (case, call, status, ms):')
    for c in wb.CALLS:
        wb.say(f"    {c['case']:6} {c['call']:55} {c['status']}  {c['ms']}")
    if uncleaned:
        wb.say('\n' + '!' * 70 + f'\n!! PARCELS THAT WERE CREATED AND NOT DELETED: {uncleaned}\n!! Delete them by hand at the carrier.\n' + '!' * 70)
    wb.say(f"\n{len(results.cases) - len(failed)}/{len(results.cases)} ({mode}); results in {name}")
    return int(bool(failed) or bool(uncleaned))


if __name__ == '__main__':
    sys.exit(main())
