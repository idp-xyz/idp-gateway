#!/usr/bin/env python3
"""SF International on the single-host pool (ADR-0014 step 3): deploy/compose/compose.yml with the overlays
deploy/compose/gateway-authz.yml and deploy/compose/provider-signer.yml, the configuration
deploy/providers/sfintl/agentgateway.yaml published by gateway-control, callers coming in through front, the egress
rules in force in the gateway's namespace and in the signer's, the PDP being the local Gatekeeper stack's pdp-mtls.

    tests/integration/gatekeeper/stack.sh up                                         the local Gatekeeper (left up)
    .venv/bin/python tests/integration/sfintl/pool.py                                upstream is the stand-in (a container of the pool's network)
    .venv/bin/python tests/integration/sfintl/pool.py --sandbox --sandbox-credentials FILE
    .venv/bin/python tests/integration/sfintl/pool.py --control no-signer-egress    the signer's egress step does nothing: SF-11 fails
    .venv/bin/python tests/integration/sfintl/pool.py --control no-signer-name      the published configuration does not name provider-signer

The cases are those of run.py, imported and used as they are, with these differences: SF-09 is skipped (it swaps
gateway-authz for the acceptance build, which the pool does not run); SF-12 is skipped (gateway-authz.yml does not
pass --revocations, and this overlay only adds the SF OpenAPI arguments); what the gateway, gateway-authz and the
signer logged is read from the containers; SF-15 calls the signer on a loopback port this file publishes (the deploy
overlay does not); and SF-11 is added: the egress rules. The pool is a compose project of its own (PROJECT), on
ports 27641-27645 (27610-27623 are the rig, the black-box suite, Gatekeeper and the compose suite; 27630 is
egressnet; 27631-27634 are the WanbExpress pool). It is taken down with its volumes, and the temporary directory
removed, however the run ends. Only this project and the Gatekeeper stack are touched.

--sandbox is implemented and is not run from here. In that mode the signer's CONFIG names api-ifsp-sit.sf.global:80,
and a probe that must be refused goes only to an address on this machine's docker networks.
"""
from __future__ import annotations
import argparse, atexit, datetime, importlib.util, json, os, secrets, shutil, socket, subprocess, sys, tempfile, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
_spec = importlib.util.spec_from_file_location('sf_run', HERE / 'run.py')
sf = importlib.util.module_from_spec(_spec)
sys.modules['sf_run'] = sf
_spec.loader.exec_module(sf)
gk, pki, pin = sf.gk, sf.pki, sf.pin

DEPLOY = ROOT / 'deploy/compose'
PROJECT = 'idp-gateway-sfintl-pool'
SCRATCH = f'{PROJECT}-scratch'
PROBE = f'{PROJECT}-probe'
# 27610-27623 rig / black-box / Gatekeeper / compose suite; 27630 egressnet; 27631-27634 WanbExpress pool.
PORT = {'front': 27641, 'readback': 27642, 'staging': 27643, 'mock': 27644, 'signer': 27645}
IN_POOL = {'callers': 8081, 'readback': 8443, 'admin': 15000, 'stats': 15020, 'signer': 9444, 'authz': 9443, 'carrier': 8080}
TOOLS_IMAGE = 'public.ecr.aws/docker/library/python:3.13-alpine@sha256:1e1f6334529d1fb26a2ef619d7cffb30a7c7d7cc1cc7338ebee283a58d1aeaca'
EGRESS_IMAGE = 'docker@sha256:b36f28717b43f23f56c7c72e97eeba80aeb24fc3f4dbf9fa409b25b074bf1260'
PDP_ADDRESS = 'https://pdp-mtls:8443'
GATEWAY_IMAGE = pin.image_reference(pin.lock())
RUN_AS = f'{os.getuid()}:{os.getgid()}'
GO = sf.GO
CARRIER_NAME = 'sfintl-standin'
WORK: Path | None = None
STANDIN = True
CONTROL_NAME = None
REFUSED_BY_RULE, REFUSED_BY_RULE_V6 = 113, 13   # EHOSTUNREACH; IPv6 is EACCES. 111 is the other side refusing.


def die(message: str):
    print('pool.py:', message, file=sys.stderr)
    raise SystemExit(2)


def clean_env(base: dict | None = None) -> dict:
    return {k: v for k, v in (base or os.environ).items() if 'proxy' not in k.lower()}


def docker(*argv: str, timeout: float = 300) -> subprocess.CompletedProcess:
    return subprocess.run(['docker', *argv], capture_output=True, text=True, timeout=timeout, env=clean_env())


def settings(sandbox: bool) -> dict:
    pool, authz = WORK / 'pool', WORK / 'authz'
    carrier_host = sf.SANDBOX_HOST if sandbox else CARRIER_NAME
    carrier_port = 80 if sandbox else IN_POOL['carrier']
    carrier_url = f'http://{sf.SANDBOX_HOST}/openapi/api/dispatch' if sandbox else f'http://{CARRIER_NAME}:{carrier_port}/openapi/api/dispatch'
    return {
        'CALLERS_LISTEN': f"127.0.0.1:{PORT['front']}", 'READBACK_PORT': str(PORT['readback']), 'READBACK_NAME': pki.READBACK_NAME,
        'POOL_DIR': str(pool), 'GATEWAY_USER': RUN_AS, 'CONTROL_USER': RUN_AS, 'GATEWAY_ENV_FILE': str(pool / 'gateway.env'),
        'GATEWAY_CONTROL': str(WORK / 'bin/gateway-control'), 'PUBLISHER_CERT': str(gk.TLS / 'publisher.crt'),
        'PUBLISHER_KEY': str(gk.TLS / 'publisher.key'), 'READBACK_CA': str(gk.TLS / 'ca.crt'), 'CONFIRM_TIMEOUT': '30s',
        'GATEWAY_AUTHZ': str(WORK / 'bin/gateway-authz'), 'GATEWAY_AUTHZ_USER': RUN_AS, 'GATEWAY_AUTHZ_POLICY': str(authz / 'policy.json'),
        'GATEWAY_AUTHZ_CREDENTIALS_DIR': str(authz / 'credentials'), 'GATEWAY_AUTHZ_TLS_CERT': str(gk.TLS / 'gatekeeper.crt'),
        'GATEWAY_AUTHZ_TLS_KEY': str(gk.TLS / 'gatekeeper.key'), 'GATEWAY_AUTHZ_GATEWAY_CA': str(gk.TLS / 'ca.crt'),
        'GATEWAY_AUTHZ_GATEWAY_IDENTITY': pki.ID['gateway'], 'GATEWAY_AUTHZ_PDP_URL': PDP_ADDRESS, 'GATEWAY_AUTHZ_PDP_NAME': gk.PDP_NAME,
        'GATEWAY_AUTHZ_PDP_TOKEN_FILE': str(authz / 'pdp-token'), 'GATEWAY_AUTHZ_PDP_CERT': str(gk.TLS / 'gateway-authz.crt'),
        'GATEWAY_AUTHZ_PDP_KEY': str(gk.TLS / 'gateway-authz.key'), 'GATEWAY_AUTHZ_PDP_CA': str(gk.TLS / 'ca.crt'),
        'GATEWAY_AUTHZ_SF_PLAIN_HTTP_HOST': carrier_host,
        'SIGNER': str(WORK / 'bin/provider-signer'), 'SIGNER_USER': RUN_AS, 'SIGNER_TLS_CERT': str(gk.TLS / 'provider-signer.crt'),
        'SIGNER_TLS_KEY': str(gk.TLS / 'provider-signer.key'), 'SIGNER_CLIENT_CA': str(gk.TLS / 'ca.crt'),
        'SIGNER_GATEWAY_IDENTITY': pki.ID['gateway'], 'SIGNER_CARRIER_URL': carrier_url, 'SIGNER_PLAIN_HTTP_HOST': carrier_host,
        'SIGNER_EGRESS_CONFIG': str(WORK / 'signer-hosts.yaml'),
        'TOOLS_IMAGE': TOOLS_IMAGE, 'STANDIN_IMAGE': ensure_standin_image() if not sandbox else TOOLS_IMAGE,
        'MOCK_HOST_PORT': str(PORT['mock']), 'MOCK_SCRIPT': str(sf.MOCK),
        'MOCK_STATE': str(WORK / 'mock-state.json'), 'SIGNER_HOST_PORT': str(PORT['signer']),
    }


def compose_files(extra: tuple = ()) -> list[str]:
    files = [DEPLOY / 'compose.yml', DEPLOY / 'gateway-authz.yml', DEPLOY / 'provider-signer.yml', HERE / 'pool.yml', *extra]
    return [a for f in files for a in ('-f', str(f))]


def compose(*argv: str, timeout: float = 300, extra: tuple = ()) -> subprocess.CompletedProcess:
    names = set(settings(not STANDIN))
    env = {k: v for k, v in clean_env().items() if k not in names and not k.startswith('COMPOSE_')}
    if STANDIN:
        env['COMPOSE_PROFILES'] = 'standin'
    return subprocess.run(['docker', 'compose', '-p', PROJECT, '--env-file', str(WORK / 'pool.env'), *compose_files(extra), *argv],
                          capture_output=True, text=True, timeout=timeout, env=env)


def container(service: str) -> dict:
    found = compose('ps', '-q', '-a', service).stdout.split()
    inspected = json.loads(docker('inspect', found[0]).stdout or '[]') if found else []
    if not inspected:
        return {}
    c = inspected[0]
    return {'id': c['Id'], 'name': c['Name'].lstrip('/'), 'running': c['State']['Running'], 'exit': c['State']['ExitCode'],
            'env': c['Config'].get('Env') or [],
            'ip': ((c['NetworkSettings'].get('Networks') or {}).get(f'{PROJECT}_default') or {}).get('IPAddress', '')}


def wait_for(predicate, seconds: float, every: float = 0.3):
    end = time.time() + seconds
    while time.time() < end:
        value = predicate()
        if value:
            return value
        time.sleep(every)
    return None


def ensure_standin_image() -> str:
    """mock_sfintl.py imports cryptography. The tools image does not have it, so the stand-in image is that image plus the same version the rig runs."""
    import cryptography
    name = f'{PROJECT}-standin:{cryptography.__version__}'
    if docker('image', 'inspect', name).returncode == 0:
        return name
    dockerfile = (f'FROM {TOOLS_IMAGE}\n'
                  f'RUN pip install --no-cache-dir --disable-pip-version-check cryptography=={cryptography.__version__}\n')
    done = subprocess.run(['docker', 'build', '-t', name, '-'], input=dockerfile, capture_output=True, text=True, timeout=600, env=clean_env())
    if done.returncode != 0:
        die('the stand-in image did not build:\n' + (done.stderr or done.stdout)[-1500:])
    return name


def build(package: str, target: str):
    done = subprocess.run([GO, 'build', '-trimpath', '-o', str(WORK / 'bin' / target), package], cwd=ROOT, capture_output=True, text=True,
                          env={**clean_env(), 'CGO_ENABLED': '0', 'PATH': '/usr/local/go/bin:' + os.environ.get('PATH', '')})
    if done.returncode != 0:
        die(f'{package} does not build:\n' + done.stderr[-1500:])


def put(path: Path, content: str | bytes, mode: int = 0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(content if isinstance(content, bytes) else content.encode())
    os.chmod(path, mode)


def apps_document(apps: dict, endpoint: str) -> dict:
    return {f'{sf.BINDING}/{account}': {'token_endpoint': endpoint, 'app_key': app['app_key'], 'app_secret': app['app_secret'],
                                       'encoding_aes_key': app['encoding_aes_key'], 'key_version': '1'}
            for account, app in apps.items()}


def prepare(state: dict, made: dict, sandbox: bool, snapshot_text: str):
    pool, authz = WORK / 'pool', WORK / 'authz'
    for directory in (pool / 'config', pool / 'tls', authz / 'credentials', WORK / 'control/work', WORK / 'control/tls', WORK / 'control/snapshots'):
        directory.mkdir(parents=True, exist_ok=True)
    os.chmod(pool / 'config', 0o755)
    os.chmod(authz / 'credentials', 0o700)
    os.chmod(pool, 0o755)
    os.chmod(WORK, 0o755)
    jwks = gk.call('GET', gk.ISSUER + '/.well-known/jwks.json')
    if jwks[0] != 200 or not isinstance(jwks[1], dict) or not jwks[1].get('keys'):
        die('no JWKS from the local Hydra')
    for name in ('gateway-readback.crt', 'gateway-readback.key', 'gateway.crt', 'gateway.key', 'ca.crt'):
        shutil.copy2(gk.TLS / name, pool / 'tls' / name)
    for directory in (pool / 'tls', WORK / 'control/tls'):
        put(directory / 'jwks.json', json.dumps(jwks[1]), 0o644)
        for name in ('gateway-readback.crt', 'gateway-readback.key', 'gateway.crt', 'gateway.key', 'ca.crt'):
            if directory != pool / 'tls':
                shutil.copy2(gk.TLS / name, directory / name)
    put(pool / 'gateway.env', f'SESSION_KEY={secrets.token_hex(32)}\n', 0o600)
    put(authz / 'policy.json', sf.policy_for(state, sandbox))
    put(authz / 'pdp-token', gk.ENV['GK_PDP_AUTH_TOKEN'] + '\n')
    # The base command still names developer-tokens.json. {} is a valid file; this carrier does not use those handles.
    put(authz / 'credentials' / 'developer-tokens.json', '{}\n')
    endpoint = made['token_endpoint']
    apps_path = authz / 'credentials' / 'sfintl.apps.json'
    put(apps_path, json.dumps(apps_document(made['apps'], endpoint)))
    sf.APPS_FILE = apps_path
    if not sandbox:
        put(WORK / 'mock-state.json', json.dumps({'admin_secret': made['mock_secret'], 'token_lifetime_seconds': 7200,
                                                 'apps': [{'app_key': app['app_key'], 'app_secret': app['app_secret'],
                                                           'encoding_aes_key': app['encoding_aes_key'], 'api_username': app['api_username']}
                                                          for app in made['apps'].values()]}))
    carrier = f'{sf.SANDBOX_HOST}:80' if sandbox else f'{CARRIER_NAME}:{IN_POOL["carrier"]}'
    # 0644: signer-egress is root without CAP_DAC_OVERRIDE, so it can read this only when the mode allows it. No secret in it.
    put(WORK / 'signer-hosts.yaml', f'# the only host the signer\'s namespace may open a new connection to\nhost: {carrier}\n', 0o644)
    put(WORK / 'pool.env', ''.join(f'{k}={v}\n' for k, v in settings(sandbox).items()), 0o600)
    build('./cmd/gateway-control', 'gateway-control')
    build('./cmd/gateway-authz', 'gateway-authz')
    build('./cmd/provider-signer', 'provider-signer')
    import yaml
    full = yaml.safe_load(snapshot_text)
    first = {k: v for k, v in full.items() if k not in ('gateways', 'routes')}
    first['gateways'] = {'read-back': full['gateways']['read-back']}
    first['routes'] = [r for r in full['routes'] if r['name'] == 'read-back']
    put(pool / 'config' / 'config.yaml', yaml.safe_dump(first, sort_keys=False), 0o644)


def control_flags() -> list[str]:
    return ['--config-dir', str(WORK / 'pool/config'), '--read-back', f"127.0.0.1:{PORT['readback']}", '--read-back-name', pki.READBACK_NAME,
            '--tls-cert', str(gk.TLS / 'publisher.crt'), '--tls-key', str(gk.TLS / 'publisher.key'), '--tls-ca', str(gk.TLS / 'ca.crt')]


def publish(snapshot_text: str) -> dict:
    snapshot = WORK / 'control/snapshots/sfintl.yaml'
    put(snapshot, snapshot_text, 0o644)
    argv = [str(WORK / 'bin/gateway-control'), 'publish', '--snapshot', str(snapshot), *control_flags(),
            '--image', GATEWAY_IMAGE, '--staging-name', SCRATCH, '--staging-publish', f"127.0.0.1:{PORT['staging']}",
            '--staging-container-port', str(IN_POOL['readback']), '--staging-tls-dir', str(WORK / 'control/tls'),
            '--staging-work-dir', str(WORK / 'control/work')]
    done = subprocess.run(argv, capture_output=True, text=True, timeout=180, env=clean_env())
    try:
        report = json.loads(done.stdout) if done.stdout.strip() else {}
    except ValueError:
        report = {'unparsed': done.stdout[:300]}
    return {'exit': done.returncode, 'outcome': report.get('outcome') or report.get('status'),
            'stderr': done.stderr.strip()[-300:],
            'detail': {k: v for k, v in report.items() if k in ('reason', 'detail', 'message', 'error', 'loaded', 'last_error')} if isinstance(report, dict) else {}}


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


def pool_authz_log() -> str:
    """The gateway-authz log pool_decisions reads. Decisions keep only the egress-authorization lines."""
    return compose('logs', '--no-color', '--no-log-prefix', 'gateway-authz').stdout


def pool_decisions() -> list:
    out = []
    for line in pool_authz_log().splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and entry.get('msg') == 'egress authorization':
            out.append(entry)
    return out


def pool_signer_calls() -> list:
    found = []
    for line in compose('logs', '--no-color', '--no-log-prefix', 'signer').stdout.splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and entry.get('msg') == 'signer call':
            found.append(entry)
    return found


def pool_gateway_log() -> str:
    return compose('logs', '--no-color', '--no-log-prefix', 'agentgateway').stdout


def pool_authz_identity():
    found = container('gateway-authz')
    return (found.get('id'), found.get('running') is True) if found else (None, False)


def pool_peers() -> set:
    """The signer and gateway-authz are the processes that talk to the carrier. Read from the namespaces they run in."""
    found = set()
    for service in ('provider-signer', 'gateway-authz'):
        holder = container(service)
        if not holder or not holder.get('running'):
            continue
        texts = {}
        for name in ('tcp', 'tcp6'):
            done = docker('exec', holder['name'], 'cat', f'/proc/net/{name}')
            texts[name] = done.stdout if done.returncode == 0 else ''
        found |= sf.peers_from_tables(texts)
    return found


def logs_of() -> dict:
    text_of = lambda service: compose('logs', '--no-color', '--no-log-prefix', service).stdout
    return {'gateway log': text_of('agentgateway'), 'gateway-authz log': text_of('gateway-authz'),
            'provider-signer log': text_of('signer')}


CONNECT = r'''
import json, socket, sys
seen = {}
for target in sys.argv[1:]:
    host, port = target.rsplit(":", 1)
    with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET) as s:
        s.settimeout(3)
        seen[target] = s.connect_ex((host.strip("[]"), int(port)))
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


def from_namespace(service: str, code: str, *argv: str) -> dict:
    """A throwaway container joined to service's namespace. Its name contains the project name. It prints one JSON."""
    holder = container(service)
    if not holder:
        return {'error': f'{service} is not running'}
    docker('rm', '-f', PROBE)
    done = docker('run', '--name', PROBE, '--rm', '--network', f"container:{holder['id']}", TOOLS_IMAGE, 'python', '-c', code, *argv)
    try:
        return json.loads(done.stdout)
    except ValueError:
        return {'error': (done.stderr or done.stdout).strip()[-300:]}


def pinned(service: str) -> dict:
    listed = compose('run', '--rm', '--no-deps', '-T', '--entrypoint', 'iptables', service, '-S', 'IDP_EGRESS')
    found = {}
    for line in listed.stdout.splitlines():
        words = line.replace('"', '').split()
        if '--comment' in words and '-d' in words and words[words.index('--comment') + 1].startswith('pin:'):
            found.setdefault(words[words.index('--comment') + 1][4:], []).append(words[words.index('-d') + 1].split('/')[0])
    return {key: sorted(addresses) for key, addresses in found.items()}


def rule_listing(service: str) -> dict:
    v4 = compose('run', '--rm', '--no-deps', '-T', '--entrypoint', 'iptables', service, '-S', 'IDP_EGRESS')
    v6 = compose('run', '--rm', '--no-deps', '-T', '--entrypoint', 'ip6tables', service, '-S', 'IDP_EGRESS')
    return {'ipv4': v4.stdout.splitlines(), 'ipv6': v6.stdout.splitlines(), 'ipv4_exit': v4.returncode, 'ipv6_exit': v6.returncode}


def chain_names(namespace_service: str) -> str:
    holder = container(namespace_service)
    if not holder:
        return f'{namespace_service} is not running'
    docker('rm', '-f', PROBE)
    done = docker('run', '--name', PROBE, '--rm', '--network', f"container:{holder['id']}",
                  '--user', '0:0', '--cap-add', 'NET_ADMIN', '--entrypoint', 'iptables', EGRESS_IMAGE, '-S')
    return done.stdout if done.returncode == 0 else (done.stderr or '')[-300:]


def egress_case(r: sf.Results, sandbox: bool):
    sf.STATE['label'] = 'SF-11'
    r.case('SF-11', 'the egress rules: the signer\'s namespace can open the carrier and nothing else; the gateway\'s namespace can open the signer and gateway-authz, and cannot open the carrier')
    signer_held = pinned('signer-egress')
    gateway_held = pinned('egress')
    signer_rules, gateway_rules = rule_listing('signer-egress'), rule_listing('egress')
    authz_rules = chain_names('gateway-authz')
    r.note('pinned in the signer\'s namespace', signer_held)
    r.note('pinned in the gateway\'s namespace', gateway_held)
    r.note('signer namespace rules (iptables -S IDP_EGRESS, then ip6tables)', signer_rules)
    r.note('gateway namespace rules (iptables -S IDP_EGRESS, then ip6tables)', gateway_rules)
    r.note('gateway-authz\'s namespace has no egress rules (iptables -S; not a check)', authz_rules)
    authz_ip = container('gateway-authz')['ip']
    signer_ip = container('provider-signer')['ip']
    outsider_ip = container('outsider')['ip']
    if sandbox:
        spec = f'{sf.SANDBOX_HOST}:80'
        resolved = from_namespace('provider-signer', RESOLVE, sf.SANDBOX_HOST)
        listed = signer_held.get(spec, [])
        host_resolved = sorted({item[4][0] for item in socket.getaddrinfo(sf.SANDBOX_HOST, 80, type=socket.SOCK_STREAM)})
        r.note(f'{sf.SANDBOX_HOST} resolved from the signer\'s namespace', resolved.get(sf.SANDBOX_HOST))
        r.check('the sandbox name is pinned, on port 80, to addresses the namespace\'s resolver (or this host\'s) gives for it',
                bool(listed) and set(listed) <= set(resolved.get(sf.SANDBOX_HOST) or []) | set(host_resolved))
        allowed = [f'{address}:80' for address in listed]
        # A probe that must be refused stays on this machine. Another port on the carrier's public address is not used.
        refused = [f'{outsider_ip}:8000', f'{authz_ip}:9444', '[::1]:9']
        refused_v4 = refused[:-1]
    else:
        spec = f'{CARRIER_NAME}:{IN_POOL["carrier"]}'
        carrier_ip = container('sfintl-standin')['ip']
        r.check('the stand-in\'s name is pinned, on its port, to the address the stand-in has', signer_held.get(spec) == [carrier_ip])
        allowed = [f'{carrier_ip}:{IN_POOL["carrier"]}']
        refused = [f'{outsider_ip}:8000', f'{carrier_ip}:8001', f'{authz_ip}:9444', '[::1]:9']
        refused_v4 = refused[:-1]
    seen_signer = from_namespace('provider-signer', CONNECT, *allowed, *refused)
    r.note('connect() from the signer\'s namespace (0 connected, 113 refused by the rule, 13 refused on IPv6)', seen_signer)
    r.check('from the signer\'s namespace the carrier\'s pinned address and port can be connected to',
            bool(allowed) and all(seen_signer.get(t) == 0 for t in allowed))
    r.check('from the signer\'s namespace anything else (another container, another port, IPv6 loopback) is refused by the rule',
            all(seen_signer.get(t) == REFUSED_BY_RULE for t in refused_v4) and seen_signer.get('[::1]:9') == REFUSED_BY_RULE_V6)
    r.check('the signer\'s chain holds the pin for the carrier\'s name:port', spec in signer_held and bool(signer_held.get(spec)))
    r.check('gateway-authz is pinned, on 9443, to the address it has', gateway_held.get('gateway-authz:9443') == [authz_ip])
    r.check('provider-signer is pinned, on 9444, to the address the signer\'s namespace has', gateway_held.get('provider-signer:9444') == [signer_ip])
    r.check('the carrier\'s name:port is not pinned in the gateway\'s namespace (the published configuration does not name it)',
            spec not in gateway_held)
    gateway_targets = [f'{signer_ip}:9444', f'{authz_ip}:9443', f"127.0.0.1:{IN_POOL['callers']}"]
    if sandbox:
        gateway_refused = [f'{outsider_ip}:8000', '[::1]:9']
    else:
        gateway_refused = [f'{carrier_ip}:{IN_POOL["carrier"]}', f'{outsider_ip}:8000', '[::1]:9']
    seen_gateway = from_namespace('netns', CONNECT, *gateway_targets, *gateway_refused)
    r.note('connect() from the gateway\'s namespace (0 connected, 113 refused by the rule, 13 refused on IPv6)', seen_gateway)
    r.check('from the gateway\'s namespace provider-signer:9444, gateway-authz:9443 and loopback 8081 can be connected to',
            all(seen_gateway.get(t) == 0 for t in gateway_targets))
    if sandbox:
        r.check('from the gateway\'s namespace the carrier is not reachable: its name:port is not pinned, and a connection to another container of this machine is refused by the rule',
                spec not in gateway_held and seen_gateway.get(f'{outsider_ip}:8000') == REFUSED_BY_RULE)
    else:
        r.check('from the gateway\'s namespace the carrier\'s address and port are refused by the rule',
                seen_gateway.get(f'{carrier_ip}:{IN_POOL["carrier"]}') == REFUSED_BY_RULE)
    r.check('from the gateway\'s namespace IPv6 loopback is refused by the rule', seen_gateway.get('[::1]:9') == REFUSED_BY_RULE_V6)


def without_signer_name(snapshot: str, other: str) -> str:
    """The published configuration no longer names provider-signer. The backend host becomes another container of this machine, on 9444, where nothing listens."""
    old = '  - host: provider-signer:9444\n'
    found = snapshot.count(old)
    if found != 4:
        die(f'the configuration no longer has provider-signer:9444 exactly 4 times (found {found})')
    return snapshot.replace(old, f'  - host: {other}:9444\n')


def teardown():
    if WORK is None or os.environ.get('SF_POOL_KEEP'):
        return
    extra = (HERE / 'pool_no_signer_egress.yml',) if CONTROL_NAME == 'no-signer-egress' else ()
    try:
        if (WORK / 'pool.env').exists():
            compose('down', '--volumes', '--remove-orphans', '--timeout', '5', extra=extra)
    except Exception:
        pass
    mine = f'label=com.docker.compose.project={PROJECT}'
    left = docker('ps', '-a', '-q', '--filter', mine).stdout.split()
    if left:
        docker('rm', '-f', '-v', *left)
    for network in docker('network', 'ls', '-q', '--filter', mine).stdout.split():
        docker('network', 'rm', network)
    volumes = docker('volume', 'ls', '-q', '--filter', mine).stdout.split()
    if volumes:
        docker('volume', 'rm', '-f', *volumes)
    docker('rm', '-f', PROBE, SCRATCH)
    shutil.rmtree(WORK, ignore_errors=True)


def main() -> int:
    global WORK, STANDIN, CONTROL_NAME
    parser = argparse.ArgumentParser(description='deploy/providers/sfintl on the single-host pool')
    parser.add_argument('--sandbox', action='store_true')
    parser.add_argument('--sandbox-credentials')
    parser.add_argument('--control', choices=['no-signer-egress', 'no-signer-name'], help='a deliberate break, stand-in only')
    parser.add_argument('--evidence', action='store_true', help='write tests/integration/sfintl/evidence/pool-{sandbox,standin}.json (only with this flag)')
    args = parser.parse_args()
    if args.evidence and args.control:
        die('--evidence is for a run of the real configuration, not for a control')
    if args.sandbox != bool(args.sandbox_credentials):
        die('--sandbox and --sandbox-credentials go together')
    if args.sandbox and args.control:
        die('--control is for the stand-in only')
    sandbox, STANDIN, CONTROL_NAME = args.sandbox, not args.sandbox, args.control
    if sandbox:
        sf.open_sandbox_journal()
    for port in PORT.values():
        if sandbox and port == PORT['mock']:
            continue
        with socket.socket() as s:
            s.settimeout(0.3)
            if s.connect_ex(('127.0.0.1', port)) == 0:
                die(f'port {port} is in use')
    if gk.call('GET', gk.ISSUER + '/health/ready')[0] != 200 or gk.call('GET', gk.BRIDGE + '/admin/me')[0] != 200:
        die('the local Gatekeeper is not ready: tests/integration/gatekeeper/stack.sh up')
    _binary, reported = pin.resolve()
    made: dict = {'apps': {}}
    if sandbox:
        app = sf.read_sandbox_credentials(args.sandbox_credentials)
        made['apps'] = {sf.BLUE_ACCOUNT: app}
        made['token_endpoint'] = f'http://{sf.SANDBOX_HOST}/openapi/api/token'
        made['mock_secret'] = ''
    else:
        for account in (sf.BLUE_ACCOUNT, sf.GREEN_ACCOUNT):
            made['apps'][account] = {'app_key': 'app' + secrets.token_hex(8), 'app_secret': secrets.token_hex(24),
                                     'encoding_aes_key': sf.new_aes_key(), 'api_username': 'user' + secrets.token_hex(4)}
        made['token_endpoint'] = f'http://{CARRIER_NAME}:{IN_POOL["carrier"]}/openapi/api/token'
        made['mock_secret'] = secrets.token_urlsafe(24)
    sf.PLAIN_HTTP_HOST[0] = sf.SANDBOX_HOST if sandbox else ''
    sf.CARRIER_URL[0] = settings_carrier(sandbox)
    sf.MOCK_SECRET = made['mock_secret']
    WORK = Path(tempfile.mkdtemp(prefix='sfintl-pool-'))
    if not os.environ.get('SF_POOL_KEEP'):
        atexit.register(teardown)
    try:
        return run(args, made, sandbox, reported)
    finally:
        teardown()


def settings_carrier(sandbox: bool) -> str:
    if sandbox:
        return f'http://{sf.SANDBOX_HOST}/openapi/api/dispatch'
    return f'http://{CARRIER_NAME}:{IN_POOL["carrier"]}/openapi/api/dispatch'


def run(args, made: dict, sandbox: bool, reported: dict) -> int:
    state = gk.seed()
    gk.sync_tuples(state)
    pki.issue(gk.TLS)
    gk.publish_pdp_tls()
    snapshot = sf.CONFIG.read_text(encoding='utf-8')
    prepare(state, made, sandbox, snapshot)
    sf.say(f'pool {PROJECT} in {WORK} ({"sandbox" if sandbox else "stand-in"})')
    extra = (HERE / 'pool_no_signer_egress.yml',) if args.control == 'no-signer-egress' else ()
    if STANDIN:
        stood = compose('up', '-d', 'sfintl-standin', extra=extra, timeout=180)
        if stood.returncode != 0 or not wait_for(lambda: container('sfintl-standin').get('running') and container('sfintl-standin').get('ip'), 30):
            sf.say(f'the stand-in did not start (compose exit {stood.returncode}): ' + stood.stderr[-600:])
            sf.say(compose('logs', '--no-color', '--no-log-prefix', 'sfintl-standin').stdout[-800:])
            return 1
        if not wait_for(lambda: from_namespace('sfintl-standin', RESOLVE, CARRIER_NAME).get(CARRIER_NAME) == [container('sfintl-standin')['ip']], 20):
            sf.say('the stand-in\'s name did not resolve on the pool network')
            return 1
    services = ['agentgateway', 'gateway-authz', 'outsider', 'signer']
    first = compose('up', '-d', *services, extra=extra, timeout=600)
    if first.returncode != 0:
        sf.say('the pool did not start: ' + first.stderr[-800:])
        return 1
    if not wait_for(lambda: read_back('/api/runtime')['status'] == 200, 40):
        sf.say('the gateway\'s read-back does not answer')
        return 1
    if args.control == 'no-signer-name':
        other = container('outsider').get('ip')
        if not other:
            sf.say('outsider has no address')
            return 1
        snapshot = without_signer_name(snapshot, other)
    published = publish(snapshot)
    sf.say(f"publish: exit {published['exit']}, outcome {published['outcome']}, {published['detail']}")
    full = compose('up', '-d', extra=extra, timeout=600)
    if published['exit'] != 0 or full.returncode != 0:
        sf.say('publish or the full start failed: ' + published['stderr'] + full.stderr[-400:])
        return 1

    def dump_has(needle: str) -> bool:
        got = read_back('/config_dump')
        return got.get('status') == 200 and needle in json.dumps(got.get('json'))

    if not wait_for(lambda: dump_has('sfintl-orders-create'), 40):
        sf.say('the gateway did not load the published configuration')
        return 1
    if args.control == 'no-signer-name' and dump_has('provider-signer:9444'):
        sf.say('the published configuration still names provider-signer:9444')
        return 1
    sf.HOOKS.update(second_authorization_reaches_the_gateway=False, gateway_port=PORT['front'], mock_port=PORT['mock'],
                    signer_port=PORT['signer'], decisions=pool_decisions, authz_log=pool_authz_log, signer_calls=pool_signer_calls, gateway_log=pool_gateway_log,
                    peers=pool_peers, authz_identity=pool_authz_identity,
                    oversized_body_stopped_by_front=True,
                    skip_sf09='the pool runs the product build of gateway-authz; SF-09 swaps in the acceptance build',
                    skip_extra={'SF-12': 'the pool starts gateway-authz with gateway-authz.yml\'s command plus --sf-openapi-apps and --sf-openapi-plain-http-host only, so --revocations is not passed and gateway-control has nothing to revoke through'})
    tok = gk.token_for(state['blue']['client'])
    if not wait_for(lambda: sf.req('GET', sf.ORDERS, tok)['status'] in (401, 403, 404), 40):
        sf.say('requests through front do not get an answer')
        return 1
    signer_ip = container('provider-signer').get('ip')

    def signer_errno():
        return from_namespace('netns', CONNECT, f'{signer_ip}:9444').get(f'{signer_ip}:9444')

    if args.control == 'no-signer-name':
        if not wait_for(lambda: signer_errno() == REFUSED_BY_RULE, 20):
            sf.say(f'the control did not take: connect to the signer from the gateway\'s namespace returned {signer_errno()}')
            return 1
    elif not wait_for(lambda: signer_errno() == 0 and container('signer').get('running'), 30):
        sf.say(f'the gateway\'s namespace cannot yet open the signer (connect returned {signer_errno()}); signer running={container("signer").get("running")}')
        sf.say('signer-egress log:\n' + compose('logs', '--no-color', '--no-log-prefix', 'signer-egress').stdout[-800:])
        return 1
    sf.CALLS.clear()
    results = sf.Results()
    started_at = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
    failure: BaseException | None = None
    try:
        sf.run_cases(results, state, made, sandbox)
        egress_case(results, sandbox)
    except BaseException as caught:
        failure = caught
    finally:
        try:
            sf.cancel_outstanding(state)
        except Exception:
            pass
        if STANDIN and sf.MOCK_SECRET:
            try:
                sf.harvest(sf.standin_hits())
            except Exception:
                pass
    proxies = {}
    for service in ('agentgateway', 'front', 'netns', 'gateway-authz', 'provider-signer', 'signer'):
        found = container(service)
        proxies[service] = sorted(e.split('=', 1)[0] for e in found.get('env', []) if 'proxy' in e.split('=', 1)[0].lower()) if found else []
    mode = f"pool, {'sandbox' if sandbox else 'stand-in'}" + (f' (control: {args.control})' if args.control else '')
    uncleaned = sorted(waybill for waybill, status in sf.CREATED.items() if status != 'cancelled')
    record = {'finished_at': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'), 'started_at': started_at,
              'mode': mode, 'project': PROJECT, 'agentgateway': reported['version'],
              'repository_head': subprocess.run(['git', '-C', str(ROOT), 'rev-parse', '--short', 'HEAD'], capture_output=True, text=True).stdout.strip(),
              'gatekeeper_commit': subprocess.run(['git', '-C', os.environ.get('GK_SRC', str(Path.home() / '.local/src/idp-gatekeeper')), 'rev-parse', '--short', 'HEAD'],
                                                  capture_output=True, text=True).stdout.strip(),
              'proxy_variables_in_the_containers': proxies,
              'upstream': ({'kind': 'the carrier\'s sandbox', 'name': sf.SANDBOX_HOST, 'port': 80,
                            'addresses_the_signer_and_gateway_authz_held_connections_to': sorted(sf.PEERS)}
                           if sandbox else {'kind': 'stand-in', 'name': f'{CARRIER_NAME}:{IN_POOL["carrier"]}', 'signer': 'provider-signer:9444'}),
              'calls': sf.CALLS, 'cleanup_cancels': sf.CLEANUP_CANCELS,
              'orders_to_cancel_by_hand': [{'sfWaybillNo': waybill, 'customerOrderNo': sf.ORDER_OF.get(waybill)} for waybill in uncleaned]}
    if failure is not None:
        record['aborted'] = f'{type(failure).__name__}: {failure}'
    scanned, looked_for = sf.scan(made, state, json.dumps(record, ensure_ascii=False, indent=1), sandbox, logs_of())
    results.case('SF-10', 'the logs of the gateway, gateway-authz and provider-signer, this run\'s output and the result file hold none of this run\'s secrets')
    def clean_of(found: dict) -> bool:
        return not found['secret found'] and not found['Sf-OpenApi value found'] and not found.get('access-token shape found')
    for where, found in scanned.items():
        results.check(f'{where}: none of the {len(looked_for)} secrets of this run, and no value of the carrier\'s authorization scheme', clean_of(found))
    results.cases.sort(key=lambda case: int(case['id'][3:]))
    failed = results.failed()
    record.update({'cases': results.cases, 'secret_scan': {'looked_for': looked_for, 'outcome': scanned},
                   'passed': [case['id'] for case in results.cases if case not in failed],
                   'failed': [case['id'] for case in failed]})
    sf.OUT.mkdir(exist_ok=True)
    name = sf.OUT / f"result-pool-{'sandbox' if sandbox else 'standin'}{'-' + args.control if args.control else ''}.json"
    put(name, json.dumps(record, ensure_ascii=False, indent=1))
    sf.say(f'\nagentgateway {reported["version"]}; {mode}')
    results.report()
    if uncleaned:
        sf.warn_uncancelled()
    kept = True
    if args.evidence:
        upstream = record['upstream']
        kept = sf.write_evidence(f"pool-{'sandbox' if sandbox else 'standin'}.json",
                                 sf.evidence_document('pool: deploy/compose with gateway-authz.yml and provider-signer.yml, the configuration published by gateway-control, callers through front, the egress rules in force in the gateway\'s namespace and in the signer\'s; the PDP is the local Gatekeeper stack',
                                                      sandbox, started_at, record['finished_at'], reported, results, upstream,
                                                      {'in_the_containers': proxies, 'present_in_the_containers': any(proxies.values())}, GATEWAY_IMAGE),
                                 made, state, sandbox)
    sf.say(f"\n{len(results.cases) - len(failed)}/{len(results.cases)} ({mode}); results in {name}")
    if failure is not None:
        if sf.warn_uncancelled() and isinstance(failure, SystemExit) and failure.code in (0, None):
            return 1
        if isinstance(failure, SystemExit):
            return int(failure.code) if isinstance(failure.code, int) else 1
        raise failure
    gk.sync_tuples(state)
    return int(bool(failed) or bool(uncleaned) or not kept)


if __name__ == '__main__':
    sys.exit(main())
