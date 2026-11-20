#!/usr/bin/env python3
"""SF International: deploy/providers/sfintl/agentgateway.yaml on the Gatekeeper integration rig.

Real: the local Gatekeeper (stack.sh up, not touched here), the pinned agentgateway, gateway-authz (product build, asking the
PDP over mutual TLS on 27623), provider-signer (built from ./cmd/provider-signer), the configuration file of the repository
as it is. Stand-in: the carrier (mock_sfintl.py). The signer is the gateway's backend; the carrier is the signer's.

    .venv/bin/python tests/integration/sfintl/run.py                         upstream is the stand-in
    .venv/bin/python tests/integration/sfintl/run.py --mutate NAME           one deliberate break (see MUTATIONS, OTHER_CONTROLS)
    .venv/bin/python tests/integration/sfintl/run.py --sandbox --sandbox-credentials FILE
                                                                             upstream is the carrier's sandbox (plain HTTP)

The rig, its processes, its Gatekeeper seed and its tokens are those of tests/integration/gatekeeper/run.py, which is
imported and used as it is (it is not changed). Ports are the same set plus 27618 for the signer, so this suite, the
WanbExpress suites, the rig suite and the black-box suite do not run at once.
Files the processes need are written to tests/integration/gatekeeper/.run/ (ignored) with names starting sfintl.;
results go to tests/integration/sfintl/.run/. SF-11 is reserved for the pool and is not a case here. There is no pool.py yet;
HOOKS is the seam a later one would use, the way tests/integration/wanbexpress/pool.py uses the WanbExpress suite.
"""
from __future__ import annotations
import argparse, atexit, base64, datetime, email.utils, hashlib, shutil, tempfile, http.client, importlib.util, ipaddress, json, os, re, secrets, socket, ssl, stat, subprocess, sys, time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
OUT = HERE / '.run'

# The rig, as it is. Importing it reads the stack's environment and adds the certificate names the rig uses.
_spec = importlib.util.spec_from_file_location('gk_rig', ROOT / 'tests/integration/gatekeeper/run.py')
gk = importlib.util.module_from_spec(_spec)
sys.modules['gk_rig'] = gk
_spec.loader.exec_module(gk)
pki, pin = gk.pki, gk.pin

# The signer needs a server certificate for its own name. Added here, the way the rig adds its own, without changing pki.py.
pki.ID['provider-signer'] = 'spiffe://idp.test/egress/provider-signer'
pki.LEAVES['provider-signer'] = ('ca', 'provider-signer', 'provider-signer.idp.test')

CONFIG = ROOT / 'deploy/providers/sfintl/agentgateway.yaml'
POLICY_EXAMPLE = ROOT / 'deploy/providers/sfintl/policy.example.json'
MOCK = HERE / 'mock_sfintl.py'
RUN = gk.RUN
HOST = gk.HOST
BASE = '/providers/sfintl/v1'
ORDERS, CANCELS, QUERIES = f'{BASE}/orders', f'{BASE}/order-cancellations', f'{BASE}/agent-number-queries'
BINDING = 'gatekeeper:sfintl-test'
SANDBOX_HOST = 'api-ifsp-sit.sf.global'
BLUE_ACCOUNT, GREEN_ACCOUNT = 'account-blue', 'account-green'
SIGNER_PORT = 27618          # free on this rig; the black-box suite uses it for something else, and the suites never run together
GO = '/usr/local/go/bin/go'
SIGNER_NAME = 'provider-signer.idp.test'

# The signer's own refusals, the ones it answers before it calls the carrier (application/failures.go).
BEFORE_CARRIER = {'caller_not_allowed', 'unknown_operation', 'query_not_allowed', 'unsupported_media_type',
                  'credential_malformed', 'request_too_large', 'body_not_json_object', 'internal'}
SIGNER_DETAIL = {
    'caller_not_allowed': (403, 'The caller is not the configured gateway.'),
    'unknown_operation': (404, 'No operation is registered for this method and path.'),
    'query_not_allowed': (400, 'The request must not carry a query string.'),
    'unsupported_media_type': (415, 'The request body must be application/json.'),
    'credential_malformed': (403, 'The Authorization header does not carry a usable credential.'),
    'request_too_large': (413, 'The request body is larger than the limit.'),
    'body_not_json_object': (400, 'The request body must be exactly one JSON object.'),
    'internal': (500, 'The request could not be prepared.'),
    'carrier_timeout': (504, 'The carrier did not answer in time.'),
    'carrier_unreachable': (502, 'The carrier could not be reached.'),
    'carrier_status': (502, 'The carrier answered with an unexpected HTTP status.'),
    'carrier_answer_unreadable': (502, "The carrier's answer could not be read."),
}

# Deliberate breaks. no-backend-tls matches the backendTLS blocks after RIG_VALUES has rewritten tls/ to .run/tls/.
BACKEND_RULE = ("      authorization:\n        rules:\n        - allow: 'request.headers[\"authorization\"].startsWith(\"Sf-OpenApi \")'\n")
BACKEND_TLS = ("      backendTLS:\n        cert: .run/tls/gateway.crt\n        key: .run/tls/gateway.key\n        root: .run/tls/ca.crt\n        hostname: provider-signer.idp.test\n")
MUTATIONS = {
    'bearer-prefix': ('startsWith("Sf-OpenApi ")', 'startsWith("Bearer ")', 3),
    'no-backend-rule': (BACKEND_RULE, '', 3),
    'no-backend-tls': (BACKEND_TLS, '', 3),
    'wrong-signer-name': ('        hostname: provider-signer.idp.test\n', '        hostname: wrong.idp.test\n', 3),
    'create-retry': ("    # No retry policy on purpose. A create that times out has an unknown result; the carrier answers a repeated customerOrderNo with the existing order (measured 2026-11-20 for an identical body).\n"
                     "    timeout:\n      requestTimeout: 9s\n",
                     "    retry:\n      attempts: 2\n      codes: [502, 503, 504]\n    timeout:\n      requestTimeout: 9s\n", 1),
}
# Controls that do not change the configuration file.
OTHER_CONTROLS = ('no-revocations', 'signer-other-identity', 'signer-long-timeout')
REVOCATIONS = RUN / 'sfintl.revocations.json'
NOTHING_REVOKED = '{"epoch": 0, "revoked_accounts": {}}\n'
USE_REVOCATIONS = [True]
SIGNER_IDENTITY = ['']          # filled in main with the gateway's identity, unless a control says otherwise
SIGNER_TIMEOUT = ['']           # empty: the signer's default (8s)
EVIDENCE = HERE / 'evidence'
PLANTED = 'Sf-OpenApi PLANTED-BY-CALLER;planted;' + ('A' * 43)

OUTPUT: list[str] = []
ISSUED: set[str] = set()        # access tokens seen in the stand-in's dispatch records; never printed


def say(text: str = ''):
    OUTPUT.append(text)
    print(text, flush=True)


def die(message: str):
    # main cancels outstanding orders while the gateway is still up, then stops the processes.
    # Stopping here would take the gateway down before that cancel.
    print('run.py:', message, file=sys.stderr)
    raise SystemExit(2)


class Results:
    def __init__(self):
        self.cases, self.current = [], None

    def case(self, cid: str, title: str):
        self.current = {'id': cid, 'title': title, 'checks': [], 'notes': {}}
        self.cases.append(self.current)

    def check(self, what: str, ok: bool):
        self.current['checks'].append({'check': what, 'ok': bool(ok)})

    def skip(self, what: str, why: str):
        self.current['checks'].append({'check': what, 'ok': None, 'skipped': why})

    def note(self, key: str, value):
        self.current['notes'][key] = value

    def failed(self) -> list:
        return [c for c in self.cases if any(k['ok'] is False for k in c['checks'])]

    def report(self):
        for c in self.cases:
            bad = [k['check'] for k in c['checks'] if k['ok'] is False]
            skipped = [k for k in c['checks'] if k['ok'] is None]
            say(f"  {'FAIL' if bad else 'PASS'}  {c['id']}  {c['title']}  ({sum(1 for k in c['checks'] if k['ok'])} checks, {len(skipped)} skipped)")
            for what in bad:
                say(f'          x {what}')
            for k in skipped:
                say(f"          - SKIPPED: {k['check']} ({k['skipped']})")
            for key, value in c['notes'].items():
                say(f'          {key}: {value}')


def read_sandbox_credentials(path_text: str) -> dict:
    """{"app_key", "app_secret", "encoding_aes_key", "api_username"}, outside the repository, 0600."""
    path = Path(path_text).expanduser()
    if not path.is_file():
        die('--sandbox-credentials: no such file')
    resolved = path.resolve()
    if resolved == ROOT or ROOT in resolved.parents:
        die('--sandbox-credentials: the file is inside the repository; credentials stay out of it. Put it somewhere else')
    if stat.S_IMODE(resolved.stat().st_mode) & 0o077:
        die('--sandbox-credentials: the file must be 0600 or stricter')
    try:
        entry = json.loads(resolved.read_text())
    except ValueError:
        die('--sandbox-credentials: not JSON')
    needed = {'app_key', 'app_secret', 'encoding_aes_key', 'api_username'}
    if not (isinstance(entry, dict) and set(entry) == needed and all(isinstance(v, str) and v for v in entry.values())):
        die('--sandbox-credentials: the file must be {"app_key", "app_secret", "encoding_aes_key", "api_username"}')
    try:
        raw = base64.b64decode(entry['encoding_aes_key'] + '=', validate=True)
    except ValueError:
        raw = b''
    if len(entry['encoding_aes_key']) != 43 or len(raw) != 32:
        die('--sandbox-credentials: encoding_aes_key must be 43 base64 characters decoding to 32 bytes')
    return entry


def wrapped_apps(app: dict, endpoint: str) -> Path:
    """gateway-authz's apps file for this run, in a temporary directory (0700) removed when the process ends."""
    directory = Path(tempfile.mkdtemp(prefix='sfintl-'))
    os.chmod(directory, 0o700)
    atexit.register(shutil.rmtree, directory, True)
    path = directory / 'sfintl.apps.json'
    document = {f'{BINDING}/{BLUE_ACCOUNT}': {'token_endpoint': endpoint, 'app_key': app['app_key'], 'app_secret': app['app_secret'],
                                              'encoding_aes_key': app['encoding_aes_key'], 'key_version': '1'}}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(document, f)
    return path


def write(name: str, content: str) -> Path:
    path = RUN / name
    path.write_text(content, encoding='utf-8')
    os.chmod(path, 0o600)
    return path


def build(tags: list[str], target: str, package: str = './cmd/gateway-authz'):
    done = subprocess.run([GO, 'build', '-trimpath', *tags, '-o', str(RUN / target), package], cwd=ROOT, capture_output=True, text=True)
    if done.returncode != 0:
        die(f'{package} build failed:\n' + done.stderr[-1500:])


def policy_for(state: dict, sandbox: bool) -> str:
    """The example register with its placeholders filled in from the rig's tenants and clients (structurally, whole strings)."""
    names = {'TENANT-ID-BLUE': state['blue']['tenant_id'], 'TENANT-ID-GREEN': state['green']['tenant_id'],
             'CLIENT-ID-BLUE': state['blue']['client']['client_id'], 'CLIENT-ID-GREEN': state['green']['client']['client_id']}
    ungranted = state['ungranted']['client']['client_id']
    document = json.loads(POLICY_EXAMPLE.read_text())
    used = set()

    def fill(value):
        if isinstance(value, dict):
            return {fill(k): fill(v) for k, v in value.items()}
        if isinstance(value, list):
            return [fill(v) for v in value]
        if isinstance(value, str) and value in names:
            used.add(value)
            return names[value]
        return value
    rows = fill(document['registered_operations'])
    if used != set(names):
        die(f'policy.example.json no longer holds every placeholder: missing {sorted(set(names) - used)}')
    for row in rows:
        row['allowed_service_ids'].append(ungranted)
        if sandbox:
            del row['accounts_by_tenant'][state['green']['tenant_id']]
    document['registered_operations'] = rows
    if any(('TENANT-ID-' in json.dumps(r) or 'CLIENT-ID-' in json.dumps(r)) for r in rows):
        die('a placeholder is left in the register')
    return json.dumps(document)


# The deployment file is written with the values of the single-host pool. On the rig these are put back, each with the
# number of times it occurs (the suite stops when the file no longer says what it expects). The signer's backend is
# replaced in both modes: the gateway always talks to the local signer, and the carrier's address is the signer's flag.
RIG_VALUES = [
    ('  adminAddr: 127.0.0.1:15000\n', '  adminAddr: 127.0.0.1:27614\n', 1),
    ('  statsAddr: 127.0.0.1:15020\n', '  statsAddr: 127.0.0.1:27615\n', 1),
    ('  readinessAddr: 127.0.0.1:15021\n', '  readinessAddr: 127.0.0.1:27616\n', 1),
    ("destination.port == 8081'", "destination.port == 27611'", 1),
    ('destination.port == 8443 &&', 'destination.port == 27619 &&', 1),
    ('    port: 8443\n', '    port: 27619\n', 1),
    ('    port: 8081\n', '    port: 27611\n', 1),
    ('      host: gateway-authz:9443\n', '      host: 127.0.0.1:27613\n', 3),
    ('cert: tls/', 'cert: .run/tls/', 7),
    ('key: tls/', 'key: .run/tls/', 7),
    ('root: tls/', 'root: .run/tls/', 7),
    ('        file: tls/jwks.json\n', '        url: http://127.0.0.1:27621/.well-known/jwks.json\n', 1),
    ('  - host: 127.0.0.1:15000\n', '  - host: 127.0.0.1:27614\n', 1),
    ('  - host: provider-signer:9444\n', f'  - host: 127.0.0.1:{SIGNER_PORT}\n', 3),
]


def gateway_config(mutation: str | None) -> str:
    text = CONFIG.read_text(encoding='utf-8')
    changes = list(RIG_VALUES)
    if mutation in MUTATIONS:
        changes.append(MUTATIONS[mutation])
    for old, new, times in changes:
        found = text.count(old)
        if found != times:
            die(f'the configuration changed: {old.strip()[:70]!r} occurs {found} times, expected {times}')
        text = text.replace(old, new)
    return text


def start_authz(binary: str, extra_env: dict | None = None):
    argv = [str(RUN / binary), '--listen', f"127.0.0.1:{gk.PORTS['authz']}",
            '--tls-cert', str(gk.TLS / 'gatekeeper.crt'), '--tls-key', str(gk.TLS / 'gatekeeper.key'), '--client-ca', str(gk.TLS / 'ca.crt'),
            '--policy', str(RUN / 'sfintl.policy.json'), '--sf-openapi-apps', str(APPS_FILE),
            '--gateway-identity', pki.ID['gateway'],
            '--gatekeeper-url', gk.PDP_URL, '--gatekeeper-token-file', str(RUN / 'sfintl.pdp-token'),
            '--gatekeeper-tls-cert', str(gk.TLS / 'gateway-authz.crt'), '--gatekeeper-tls-key', str(gk.TLS / 'gateway-authz.key'),
            '--gatekeeper-tls-ca', str(gk.TLS / 'ca.crt'), '--gatekeeper-name', gk.PDP_NAME]
    if PLAIN_HTTP_HOST[0]:
        argv += ['--sf-openapi-plain-http-host', PLAIN_HTTP_HOST[0]]
    if USE_REVOCATIONS[0]:
        argv += ['--revocations', str(REVOCATIONS), '--revoker-identity', pki.ID['revoker']]
    gk.start('gateway-authz', argv, gk.PORTS['authz'], env={**os.environ, **(extra_env or {})})


def start_signer():
    argv = [str(RUN / 'provider-signer'), '--listen', f'127.0.0.1:{SIGNER_PORT}',
            '--tls-cert', str(gk.TLS / 'provider-signer.crt'), '--tls-key', str(gk.TLS / 'provider-signer.key'),
            '--client-ca', str(gk.TLS / 'ca.crt'), '--gateway-identity', SIGNER_IDENTITY[0], '--carrier-url', CARRIER_URL[0]]
    if PLAIN_HTTP_HOST[0]:
        argv += ['--carrier-plain-http-host', PLAIN_HTTP_HOST[0]]
    if SIGNER_TIMEOUT[0]:
        argv += ['--carrier-timeout', SIGNER_TIMEOUT[0]]
    gk.start('provider-signer', argv, SIGNER_PORT)


def clean_proxy_env() -> tuple[dict, list]:
    env = {k: v for k, v in os.environ.items() if 'proxy' not in k.lower()}
    return env, sorted(k for k in os.environ if 'proxy' in k.lower())


CALLS: list[dict] = []
PEERS: set = set()
STATE = {'label': ''}
APPS_FILE = RUN / 'sfintl.apps.json'
CARRIER_URL = ['']
PLAIN_HTTP_HOST = ['']          # empty on the stand-in (the carrier is a loopback literal); the sandbox host otherwise
CLOCK: dict = {}


def process_peers(name: str) -> set:
    entry = next((p for p in gk.PROCS if p[0] == name), None)
    if entry is None:
        return set()
    inodes = set()
    try:
        for fd in os.listdir(f'/proc/{entry[1].pid}/fd'):
            try:
                link = os.readlink(f'/proc/{entry[1].pid}/fd/{fd}')
            except OSError:
                continue
            if link.startswith('socket:['):
                inodes.add(link[8:-1])
    except OSError:
        return set()
    texts = {}
    for family in ('tcp', 'tcp6'):
        try:
            texts[family] = Path(f'/proc/net/{family}').read_text()
        except OSError:
            pass
    return peers_from_tables(texts, inodes)


def peers_from_tables(texts: dict, inodes: set | None = None) -> set:
    """Non-loopback addresses (address:port) of established TCP connections. inodes limits the sockets to one process."""
    found = set()
    for name, text in texts.items():
        for line in text.splitlines()[1:]:
            fields = line.split()
            if (inodes is not None and fields[9] not in inodes) or fields[3] != '01':
                continue
            host, port = fields[2].split(':')
            raw = bytes.fromhex(host)
            address = (ipaddress.IPv4Address(raw[::-1]) if name == 'tcp'
                       else ipaddress.IPv6Address(b''.join(raw[i:i + 4][::-1] for i in range(0, 16, 4))))
            if getattr(address, 'ipv4_mapped', None):
                address = address.ipv4_mapped
            if not address.is_loopback:
                found.add(f'{address}:{int(port, 16)}')
    return found


def carrier_peers() -> set:
    """The signer and gateway-authz are the processes that talk to the carrier. The gateway talks to the signer."""
    return process_peers('provider-signer') | process_peers('gateway-authz')


def req(method: str, path: str, token: str | None = None, body=None, headers=(), raw: bytes | None = None,
        content_type: str | None = None, sample_peers: bool = False, timeout: float = 40) -> dict:
    """One request to the gateway. A header may be given twice. raw is sent as the body bytes, exactly."""
    pairs = [('Host', HOST)] + ([('Authorization', 'Bearer ' + token)] if token else []) + list(headers)
    started = time.perf_counter()
    answer = {'status': None, 'json': None, 'headers': [], 'ms': 0.0}
    try:
        conn = http.client.HTTPConnection('127.0.0.1', HOOKS['gateway_port'], timeout=timeout)
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        for name, value in pairs:
            conn.putheader(name, value)
        data = raw
        if data is None and body is not None:
            data = json.dumps(body, ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode()
        if data is not None:
            conn.putheader('Content-Type', content_type or 'application/json')
            conn.putheader('Content-Length', str(len(data)))
        conn.endheaders(data)
        response = conn.getresponse()
        answer.update(status=response.status, headers=[(k.lower(), v) for k, v in response.getheaders()], received_at=time.time())
        try:
            blob = response.read()
        except http.client.IncompleteRead as e:
            answer['error'] = 'IncompleteRead'
            blob = e.partial
        try:
            answer['json'] = json.loads(blob) if blob else None
        except ValueError:
            answer['json'] = None
        if sample_peers:
            PEERS.update((HOOKS['peers'] or carrier_peers)())
        conn.close()
    except (OSError, http.client.HTTPException) as e:
        answer['error'] = type(e).__name__
    answer['ms'] = round((time.perf_counter() - started) * 1000, 1)
    shown = path if len(path) < 90 else '(long path)'
    CALLS.append({'case': STATE['label'], 'call': f'{method} {shown}', 'status': answer['status'], 'ms': answer['ms']})
    return answer


def envelope(answer: dict) -> dict:
    value = answer.get('json')
    return value if isinstance(value, dict) else {}


def business(answer: dict) -> dict:
    value = envelope(answer).get('apiResultData')
    return value if isinstance(value, dict) else {}


def waybill_of(answer: dict):
    data = business(answer).get('data')
    number = data.get('sfWaybillNo') if isinstance(data, dict) else None
    return number if isinstance(number, str) and number else None


def is_signer(answer: dict, code: str, carrier_status: int | None = None) -> bool:
    status, detail = SIGNER_DETAIL[code]
    expected = {'error': code, 'detail': detail}
    if carrier_status is not None:
        expected['carrier_status'] = carrier_status
    return answer['status'] == status and answer.get('json') == expected


def header_names(answer: dict) -> set:
    return {k for k, _ in answer['headers']}


def no_carrier_headers(answer: dict) -> bool:
    names = header_names(answer)
    return 'set-cookie' not in names and 'x-mock-provider' not in names


def line_fields(line: str) -> dict:
    """key=value pairs of a gateway line; a quoted value is kept as written (escapes not undone)."""
    return {m[2]: m[3][1:-1] if m[3].startswith('"') else m[3]
            for m in re.finditer(r'(^|\s)([A-Za-z0-9_.]+)=("(?:[^"\\]|\\.)*"|\S+)', line)}


def pull_fields(line: str) -> dict:
    fields = line_fields(line)
    if line.lstrip().startswith('{'):
        try:
            parsed = json.loads(line)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            fields.update({k: v for k, v in parsed.items() if isinstance(v, (str, int, float))})
    kept = {}
    for key, value in fields.items():
        if key.startswith('provider_') or key in ('route', 'http.status', 'method', 'path', 'status', 'response_code'):
            kept[key] = value[:80] if isinstance(value, str) else value
    return kept


def gateway_log_text() -> str:
    reader = HOOKS.get('gateway_log')
    if reader:
        return reader()
    path = RUN / 'gateway.log'
    return path.read_text(encoding='utf-8', errors='replace') if path.exists() else ''


def signer_calls(wait: bool = False) -> list:
    if wait:
        time.sleep(0.05)       # the signer writes the line after it has written the response
    reader = HOOKS.get('signer_calls')
    if reader:
        return reader()
    path = RUN / 'provider-signer.log'
    if not path.exists():
        return []
    found = []
    for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if entry.get('msg') == 'signer call':
            found.append(entry)
    return found


def json_log(path: Path, msg: str) -> list:
    if not path.exists():
        return []
    found = []
    for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if entry.get('msg') == msg:
            found.append(entry)
    return found


# ---- the stand-in -------------------------------------------------------------------------------------------------------
def _admin(method: str, path: str):
    return gk.call(method, f"http://127.0.0.1:{HOOKS['mock_port']}{path}", headers={'X-Poc-Admin': MOCK_SECRET}, form={} if method == 'POST' else None)


def harvest(hits: list):
    """Access tokens are only in dispatch records (the token response itself is not recorded). Collected across resets."""
    for hit in hits:
        if hit.get('kind') != 'dispatch':
            continue
        for key, value in hit.get('headers') or []:
            if key.lower() == 'token' and isinstance(value, str) and value:
                ISSUED.add(value)


def standin_hits() -> list:
    status, body = _admin('GET', '/admin/hits')
    hits = body['hits'] if status == 200 and isinstance(body, dict) else die('cannot read the stand-in\'s records')
    harvest(hits)
    return hits


def standin_reset():
    status, body = _admin('GET', '/admin/hits')
    if status == 200 and isinstance(body, dict):
        harvest(body.get('hits') or [])
    _admin('POST', '/admin/reset')


def standin_fault(kind: str, seconds: float = 0, code: int = 0):
    gk.call('POST', f"http://127.0.0.1:{HOOKS['mock_port']}/admin/fault?kind={kind}&seconds={seconds}&code={code}",
            headers={'X-Poc-Admin': MOCK_SECRET}, form={})


def standin_orders() -> list:
    status, body = _admin('GET', '/admin/orders')
    return body['orders'] if status == 200 and isinstance(body, dict) else die('cannot read the stand-in\'s orders')


def header_values(hit: dict, name: str) -> list:
    return [v for k, v in hit['headers'] if k.lower() == name.lower()]


def token_app_key(hit: dict):
    got = parse_qs(urlsplit(hit.get('raw_target') or '').query).get('appKey') or []
    return got[0] if len(got) == 1 else None


# ---- gateway-control, orders ---------------------------------------------------------------------------------------------
CONTROL_BINARY = RUN / 'gateway-control'
CREATED: dict[str, str] = {}          # sfWaybillNo -> 'created' | 'cancelled'
ORDER_OF: dict[str, str] = {}         # sfWaybillNo -> customerOrderNo


def control(*args: str) -> dict:
    """gateway-control, against this run's gateway-authz, under the revoker's certificate. What it prints is not kept."""
    argv = [str(CONTROL_BINARY), *args, '--authz', f"127.0.0.1:{gk.PORTS['authz']}", '--authz-name', pki.GATEKEEPER_NAME,
            '--tls-cert', str(gk.TLS / 'revoker.crt'), '--tls-key', str(gk.TLS / 'revoker.key'), '--tls-ca', str(gk.TLS / 'ca.crt'), '--timeout', '5s']
    done = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=60)
    parsed = None
    if done.stdout.count('\n') == 1:
        try:
            parsed = json.loads(done.stdout)
        except ValueError:
            pass
    return {'code': done.returncode, 'json': parsed if isinstance(parsed, dict) else None,
            'said': done.stderr.strip().splitlines()[-1][:160] if done.stderr.strip() else ''}


def outcome(result: dict, name: str, **fields) -> bool:
    body = result['json'] or {}
    return result['code'] == 0 and body.get('outcome') == name and all(body.get(k) == v for k, v in fields.items())


def new_order_no() -> str:
    return f"IDPGW-{datetime.datetime.now(datetime.timezone.utc):%Y%m%d}-{secrets.token_hex(6)}"


def new_aes_key() -> str:
    """43 base64 characters: 32 bytes, standard encoding, the trailing '=' removed."""
    return base64.b64encode(secrets.token_bytes(32)).decode('ascii')[:-1]


def order_body(order_no: str, api_username: str) -> dict:
    """The create body the sandbox accepted on 2026-11-20 (the order map in the flow program), with this order's user name and number."""
    return {
        'apiUsername': api_username, 'customerOrderNo': order_no, 'platformOrderId': order_no, 'platformCode': 'IDPGW',
        'erpCode': '0000', 'erpName': '0000', 'interProductCode': 'INT0255', 'parcelQuantity': 1, 'parcelTotalWeight': 0.31,
        'declaredValue': 1.1, 'declaredCurrency': 'USD', 'isBat': 0, 'createOrderType': '1', 'customsInfo': {},
        'parcelInfoList': [{'amount': 1.1, 'cName': '孕妇上衣', 'currency': 'USD', 'goodsUrl': 'baidu.com', 'hsCode': '620432',
                            'name': 'Maternity Shirt', 'quantity': 1, 'unit': 'piece', 'weight': 0.31}],
        'receiverInfo': {'address': '928 MADISON ST', 'company': 'Kacey Russell', 'contact': 'Kacey Russell', 'country': 'US',
                         'email': 'idpgw-test@example.com', 'phoneNo': '3463079643', 'postCode': '53188-3543', 'regionFirst': 'WI',
                         'regionSecond': 'WAUKESHA', 'regionThird': '', 'telNo': '3463079643'},
        'senderInfo': {'address': 'Zhengxin Industrial 3rd floor,Huating Road 7#,DaLang Street', 'company': '1',
                       'contact': 'tianmeng', 'country': 'CN', 'phoneNo': '17608455622', 'postCode': '518009', 'regionFirst': 'GuangDong',
                       'regionSecond': 'ShenZhen', 'regionThird': 'baoan', 'telNo': '17608455622'},
    }


def query_body(order_no: str, waybill: str) -> dict:
    return {'service': 'WaybillService', 'waybillList': [{'orderNo': order_no, 'sfWaybillNo': waybill}]}


def cancel_body(order_no: str, waybill: str) -> dict:
    return {'cancelReason': 'IDPGW test order', 'customerOrderNo': order_no, 'sfWaybillNo': waybill}


def remember(order_no: str, waybill: str | None):
    if isinstance(waybill, str) and waybill:
        ORDER_OF.setdefault(waybill, order_no)
        CREATED.setdefault(waybill, 'created')


# What differs when the gateway runs in the pool: where requests go, where records, decisions and logs are read.
HOOKS = {'gateway_port': gk.PORTS['gateway'], 'mock_port': gk.PORTS['provider'], 'signer_port': SIGNER_PORT,
         'decisions': gk.decisions, 'signer_calls': None, 'gateway_log': None, 'skip_sf09': None, 'peers': None, 'logs': None,
         'second_authorization_reaches_the_gateway': True, 'skip_extra': None}
MOCK_SECRET = ''


def run_cases(r: Results, state: dict, made: dict, sandbox: bool):
    apps = made['apps']
    blue, green, ungranted = (state[k]['client'] for k in ('blue', 'green', 'ungranted'))
    tok = {'blue': gk.token_for(blue), 'green': gk.token_for(green), 'ungranted': gk.token_for(ungranted),
           'blue-other-aud': gk.token_for(blue, gk.OTHER_AUDIENCE)}
    if not all(tok.values()):
        die('no token from the local Hydra')
    made['tokens'] = list(tok.values())
    seen_token = {}          # app key -> token the stand-in accepted, compared and never printed

    def caller(token='blue'):
        return tok[token]

    def marks(reset: bool = False):
        if reset and not sandbox:
            standin_reset()
        return len(HOOKS['decisions']()), len(signer_calls())

    def new_decisions(mark: int) -> list:
        return HOOKS['decisions']()[mark:]

    def reason_since(mark: int):
        new = new_decisions(mark)
        return new[-1].get('reason') if new else None

    def asked_since(mark: int) -> int:
        return len(new_decisions(mark))

    def signer_stopped(what: str, mark: int, own_refusal_counts: bool):
        """Judged by the signer's log: no new `signer call`, or (when own_refusal_counts) only a refusal from before the carrier call."""
        new = signer_calls(wait=True)[mark:]
        outcomes = [str(entry.get('outcome')) for entry in new]
        if not new:
            ok, how = True, 'no new signer call'
        elif own_refusal_counts and all(item in BEFORE_CARRIER for item in outcomes):
            ok, how = True, 'refused before the carrier (' + ', '.join(outcomes) + ')'
        else:
            ok, how = False, 'signer call outcomes ' + ', '.join(outcomes)
        r.check(f'{what} (judged by the signer\'s log: {how})', ok)

    def standin_quiet(what: str, no_token: bool = False):
        """Judged by the stand-in's records: no dispatch, and no token request when no_token."""
        detail = 'no dispatch' + (' and no token request' if no_token else '')
        label = f'{what} (judged by the stand-in\'s records: {detail})'
        if sandbox:
            r.skip(label, 'only the stand-in records what arrived; nothing was sent that should reach the carrier')
            return
        kinds = {hit['kind'] for hit in standin_hits()}
        r.check(label, 'dispatch' not in kinds and (not no_token or 'token' not in kinds))

    def quiet(what: str, dmark: int, smark: int, no_token: bool = False, signer_may_refuse: bool = False):
        signer_stopped(what, smark, signer_may_refuse)
        standin_quiet(what, no_token)

    def skipped_here(cid: str) -> bool:
        reason = (HOOKS.get('skip_extra') or {}).get(cid)
        if reason:
            r.skip('every check of this case', reason)
        return bool(reason)

    def note_answer(key: str, answer: dict):
        biz = business(answer)
        r.note(key, {'status': answer['status'], 'error': answer.get('error'), 'apiResultCode': envelope(answer).get('apiResultCode'),
                     'signer_error': envelope(answer).get('error'), 'success': biz.get('success'), 'code': biz.get('code')})

    def post(path: str, body, token: str = 'blue', headers=(), raw: bytes | None = None, content_type: str | None = None) -> dict:
        return req('POST', path, caller(token), body, headers=headers, raw=raw, content_type=content_type, sample_peers=sandbox)

    def remember_answer(order_no: str, answer: dict):
        remember(order_no, waybill_of(answer))

    def cancel_order(order_no: str, waybill: str, token: str = 'blue') -> tuple[dict, int]:
        """Repeat a cancel that answers success false, up to 6 times. The 3 second gap is the one measured at the sandbox; the stand-in does not need it."""
        last = {'status': None, 'json': None, 'headers': []}
        for attempt in range(1, 7):
            last = post(CANCELS, cancel_body(order_no, waybill), token)
            if business(last).get('success') is True:
                CREATED[waybill] = 'cancelled'
                return last, attempt
            if attempt < 6 and sandbox:
                time.sleep(3)
        return last, 6

    def replace_apps(document: dict):
        """The way gateway-authz asks for: a new file next to the old one, then renamed over it."""
        staged = APPS_FILE.with_name(APPS_FILE.name + '.next')
        staged.write_text(json.dumps(document), encoding='utf-8')
        os.chmod(staged, 0o600)
        os.replace(staged, APPS_FILE)

    def apps_document(blue_version: str = '1', green_version: str = '1', extra: dict | None = None) -> dict:
        document = {}
        for account, app in apps.items():
            entry = {'token_endpoint': made['token_endpoint'], 'app_key': app['app_key'], 'app_secret': app['app_secret'],
                     'encoding_aes_key': app['encoding_aes_key'],
                     'key_version': blue_version if account == BLUE_ACCOUNT else green_version}
            if account == BLUE_ACCOUNT and extra:
                entry.update(extra)
            document[f'{BINDING}/{account}'] = entry
        return document

    def authz_process():
        entry = next((p for p in gk.PROCS if p[0] == 'gateway-authz'), None)
        return (entry[1].pid, entry[1].poll() is None) if entry else (None, False)

    def order_active(order_no: str) -> bool:
        return any(item.get('customer_order_no') == order_no and item.get('state') == 'active' for item in standin_orders())

    def order_waybill(order_no: str):
        found = [item.get('sf_waybill_no') for item in standin_orders() if item.get('customer_order_no') == order_no]
        return found[-1] if found else None

    def create_dispatches(order_no: str) -> list:
        return [hit for hit in standin_hits() if hit.get('kind') == 'dispatch' and hit.get('msg_type') == 'IECS_CREATE_ORDER'
                and hit.get('customer_order_no') == order_no]

    # Wait until the gateway has fetched the JWKS. GET has no route, so the answer is 404 once the token is accepted and 401 until then.
    STATE['label'] = 'ready'
    end = time.time() + 20
    ready = None
    while time.time() < end:
        ready = req('GET', ORDERS, tok['blue'])['status']
        if ready == 404:
            break
        time.sleep(0.3)
    if ready != 404:
        die(f'the gateway did not become ready (GET {ORDERS} is {ready}, expected 404 once the JWKS is loaded)')

    # SF-01
    STATE['label'] = 'SF-01'
    r.case('SF-01', 'query, create, query, cancel, query: the blue tenant\'s real Gatekeeper token, through the gateway')
    order_no = new_order_no()
    username = apps[BLUE_ACCOUNT]['api_username']
    if not sandbox:
        standin_reset()
    dmark, smark = marks()
    queried = post(QUERIES, query_body(order_no, 'SF000000000000'))
    date = dict(queried['headers']).get('date')
    if date and queried.get('received_at'):
        try:
            CLOCK.update(carrier_response_date=date,
                         offset_seconds=round(email.utils.parsedate_to_datetime(date).timestamp() - queried['received_at'], 1),
                         resolution_seconds=1, taken_from='the Date header of the first query (SF-01), as it reached the caller')
        except (TypeError, ValueError, KeyError):
            pass
    wrong = (business(queried).get('wrongData') or [{}])[0]
    r.check('query of an order number that does not exist: HTTP 200, apiResultCode 0, wrongData status 4001',
            queried['status'] == 200 and envelope(queried).get('apiResultCode') == 0 and isinstance(wrong, dict) and wrong.get('status') == '4001')
    last = new_decisions(dmark)[-1] if asked_since(dmark) else {}
    r.check('query: gateway-authz decided ACTIVE_ACCOUNT_GRANT for agent-numbers.query',
            last.get('reason') == 'ACTIVE_ACCOUNT_GRANT' and last.get('operation_id') == 'agent-numbers.query')
    if not (queried['status'] == 200 and envelope(queried).get('apiResultCode') == 0):
        note_answer('first query', queried)

    dmark, _ = marks()
    created = post(ORDERS, order_body(order_no, username))
    waybill = waybill_of(created)
    remember(order_no, waybill)
    biz = business(created)
    data = biz.get('data') if isinstance(biz.get('data'), dict) else {}
    r.check('create: HTTP 200, apiResultCode 0, success true',
            created['status'] == 200 and envelope(created).get('apiResultCode') == 0 and biz.get('success') is True)
    r.check('create: the envelope has exactly apiResultCode, apiResultData, apiTimestamp',
            set(envelope(created)) == {'apiResultCode', 'apiResultData', 'apiTimestamp'})
    r.check('create: a sfWaybillNo and our customerOrderNo, and no business code',
            bool(waybill) and data.get('customerOrderNo') == order_no and 'code' not in biz)
    if not waybill:
        note_answer('create', created)
    created_decision = new_decisions(dmark)[-1] if asked_since(dmark) else {}
    r.check('create: gateway-authz decided ACTIVE_ACCOUNT_GRANT for orders.create',
            created_decision.get('reason') == 'ACTIVE_ACCOUNT_GRANT' and created_decision.get('operation_id') == 'orders.create')
    if sandbox:
        r.skip('no Set-Cookie and no X-Mock-Provider from the carrier reach the caller', 'the stand-in sets both; the sandbox was not asked to')
    else:
        r.check('no Set-Cookie and no X-Mock-Provider from the carrier reach the caller (the stand-in sets both)', no_carrier_headers(created))
    time.sleep(0.5)
    log_lines = gateway_log_text().splitlines()
    with_number = [line for line in log_lines if order_no in line]
    with_field = [line for line in with_number if 'provider_reference_id' in line]
    shown = [pull_fields(line) for line in (with_field or with_number)[:3]]
    r.note('access log', {'lines_with_the_order_number': len(with_number), 'lines_with_provider_reference_id': len(with_field), 'fields': shown})
    fields = pull_fields(with_field[0]) if len(with_field) == 1 else {}
    r.check('the create\'s access-log line carries provider_reference_id = our customerOrderNo',
            len(with_field) == 1 and fields.get('provider_reference_id') == order_no)
    r.check('the create\'s access-log line carries provider_request_id = the sfWaybillNo',
            len(with_field) == 1 and bool(waybill) and fields.get('provider_request_id') == waybill)

    if waybill:
        again = post(QUERIES, query_body(order_no, waybill))
        status = ((business(again).get('wrongData') or [{}])[0] or {}).get('status') if isinstance((business(again).get('wrongData') or [None])[0], dict) else None
        r.check('query of the new order: HTTP 200, apiResultCode 0, wrongData status 4002',
                again['status'] == 200 and envelope(again).get('apiResultCode') == 0 and status == '4002')
        query_decisions = [item for item in HOOKS['decisions']() if item.get('operation_id') == 'agent-numbers.query']
        r.check('the second query: gateway-authz decided ACTIVE_ACCOUNT_GRANT for agent-numbers.query',
                len(query_decisions) >= 2 and query_decisions[-1].get('reason') == 'ACTIVE_ACCOUNT_GRANT')
        cancelled, attempts = cancel_order(order_no, waybill)
        r.note('cancel attempts', attempts)
        r.check('cancel: HTTP 200, apiResultCode 0, success true, code 200',
                cancelled['status'] == 200 and envelope(cancelled).get('apiResultCode') == 0 and business(cancelled).get('success') is True
                and business(cancelled).get('code') == '200')
        cancel_decisions = [item for item in HOOKS['decisions']() if item.get('operation_id') == 'orders.cancel']
        r.check('cancel: gateway-authz decided ACTIVE_ACCOUNT_GRANT for orders.cancel',
                bool(cancel_decisions) and cancel_decisions[-1].get('reason') == 'ACTIVE_ACCOUNT_GRANT')
        if business(cancelled).get('success') is not True:
            note_answer('cancel', cancelled)
        after = post(QUERIES, query_body(order_no, waybill))
        after_status = ((business(after).get('wrongData') or [{}])[0] or {}).get('status') if isinstance((business(after).get('wrongData') or [None])[0], dict) else None
        r.check('query after the cancel: HTTP 200, apiResultCode 0, wrongData status 4001',
                after['status'] == 200 and envelope(after).get('apiResultCode') == 0 and after_status == '4001')
    if sandbox:
        r.skip('exactly one token request was made for the blue app up to here', 'the sandbox does not show its token requests to us')
    else:
        hits = standin_hits()
        blue_tokens = [hit for hit in hits if hit['kind'] == 'token' and token_app_key(hit) == apps[BLUE_ACCOUNT]['app_key']]
        r.check('exactly one token request was made for the blue app up to here (the rest were served from the cache)', len(blue_tokens) == 1)
        creates = [hit for hit in hits if hit.get('msg_type') == 'IECS_CREATE_ORDER' and hit.get('refused') is None]
        if creates:
            got = header_values(creates[-1], 'token')
            if len(got) == 1:
                seen_token[apps[BLUE_ACCOUNT]['app_key']] = got[0]

    # SF-02
    STATE['label'] = 'SF-02'
    r.case('SF-02', 'the same create again while the order exists: success, code 123052, the same waybill; a cancel that is too early fails and the next one works')
    order_no = new_order_no()
    body = order_body(order_no, username)
    first = post(ORDERS, body)
    waybill = waybill_of(first)
    remember(order_no, waybill)
    r.check('the first create succeeded and answered a waybill', first['status'] == 200 and business(first).get('success') is True and bool(waybill))
    same = post(ORDERS, body)
    same_bill = waybill_of(same)
    if same_bill and same_bill != waybill:
        remember(order_no, same_bill)
    r.check('the same create again: HTTP 200, apiResultCode 0, success true, code 123052',
            same['status'] == 200 and envelope(same).get('apiResultCode') == 0 and business(same).get('success') is True and business(same).get('code') == '123052')
    r.check('the same create again: the waybill number is the first one', bool(waybill) and same_bill == waybill)
    if business(same).get('code') != '123052':
        note_answer('repeat create', same)
    if sandbox:
        r.skip('fault cancel-not-yet: the caller gets the carrier\'s code 500 and the order still exists', 'the fault is the stand-in\'s; the sandbox is not asked to misbehave')
        r.skip('the cancel after that fault succeeds', 'the fault is the stand-in\'s')
    elif waybill:
        if not sandbox:
            standin_reset()
        standin_fault('cancel-not-yet')
        early = post(CANCELS, cancel_body(order_no, waybill))
        r.check('fault cancel-not-yet: HTTP 200, code 500, success false, unchanged (a business answer, not a signer error)',
                early['status'] == 200 and envelope(early).get('apiResultCode') == 0 and business(early).get('success') is False and business(early).get('code') == '500'
                and 'error' not in envelope(early))
        r.check('fault cancel-not-yet: the order still exists', order_active(order_no))
        if business(early).get('code') != '500':
            note_answer('cancel-not-yet', early)
        late, _ = cancel_order(order_no, waybill)
        r.check('the cancel again succeeds: success true, code 200', business(late).get('success') is True and business(late).get('code') == '200')
    if waybill and CREATED.get(waybill) != 'cancelled':
        done, _ = cancel_order(order_no, waybill)
        r.check('the order made for this case is cancelled', business(done).get('success') is True)

    # SF-03
    STATE['label'] = 'SF-03'
    r.case('SF-03', 'what the carrier receives (stand-in only): the caller\'s bytes unchanged, the blue app\'s own credential, none of the caller\'s headers')
    if sandbox or skipped_here('SF-03'):
        if sandbox:
            r.skip('every check of this case', 'only the stand-in can say what it received, and a planted credential is not sent to the sandbox')
    else:
        standin_reset()
        orders = []
        raws = []
        answers = []
        for _ in range(3):
            number = new_order_no()
            unusual = order_body(number, username)
            unusual['senderInfo'] = dict(unusual['senderInfo'], company='A<B&C 公司')
            raw = json.dumps(unusual, ensure_ascii=False, indent=2).encode()
            sent = [('Cookie', 'session=caller-session'), ('X-Forwarded-For', '10.1.2.3'), ('X-Forwarded-Host', 'internal.idp.test'),
                    ('X-Forwarded-Proto', 'https'), ('Forwarded', 'for=10.1.2.3;host=internal.idp.test'), ('X-Evil-Probe', 'caller'),
                    ('X-Provider-Account', BLUE_ACCOUNT)]
            if HOOKS['second_authorization_reaches_the_gateway']:
                sent.append(('Authorization', PLANTED))
            answer = post(ORDERS, None, headers=sent, raw=raw)
            orders.append(number)
            raws.append(raw)
            answers.append(answer)
            remember(number, waybill_of(answer))
        hits = [hit for hit in standin_hits() if hit.get('kind') == 'dispatch']
        r.check('three creates answered 200 and the carrier received three dispatches', [a['status'] for a in answers] == [200] * 3 and len(hits) == 3)
        r.check('each dispatch was accepted (refused is null) and msgType is IECS_CREATE_ORDER',
                len(hits) == 3 and all(hit.get('refused') is None and hit.get('msg_type') == 'IECS_CREATE_ORDER' for hit in hits))
        r.check('each target is exactly /openapi/api/dispatch', len(hits) == 3 and all(hit.get('raw_target') == '/openapi/api/dispatch' for hit in hits))
        r.check('plaintext_sha256 equals the SHA-256 of the exact bytes the caller sent',
                len(hits) == 3 and all(hit.get('plaintext_sha256') == hashlib.sha256(raw).hexdigest() for hit, raw in zip(hits, raws)))
        blue_key = apps[BLUE_ACCOUNT]['app_key']
        keys = [header_values(hit, 'appKey') for hit in hits]
        tokens = [header_values(hit, 'token') for hit in hits]
        expected = seen_token.get(blue_key)
        r.check('appKey is the blue app\'s, compared and not printed', all(item == [blue_key] for item in keys))
        r.check('token is the token the stand-in issued to the blue app (the one SF-01\'s create carried), compared and not printed',
                expected is not None and all(item == [expected] for item in tokens))
        nonces = [header_values(hit, 'nonce') for hit in hits]
        r.check('three different nonces', all(len(item) == 1 for item in nonces) and len({item[0] for item in nonces}) == 3)
        names = {key.lower() for hit in hits for key, _ in hit['headers']}
        r.note('header names the carrier saw', sorted(names))
        r.check('none of the caller\'s headers arrived (cookie, forwarding headers, x-evil-probe, x-provider-account)',
                not names & {'cookie', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto', 'forwarded', 'x-evil-probe', 'x-provider-account'})
        r.check('no x-idp-* header and no authorization header at all', not [name for name in names if name.startswith('x-idp-')] and 'authorization' not in names)
        flat = json.dumps(hits)
        r.check('the caller\'s Gatekeeper token and the planted credential are nowhere in the records', tok['blue'] not in flat and 'PLANTED' not in flat)
        token_hits = [hit for hit in standin_hits() if hit['kind'] == 'token']
        r.check('no new token request (the token is cached)', len(token_hits) == 0)
        r.check('no Set-Cookie and no X-Mock-Provider reach the caller', all(no_carrier_headers(answer) for answer in answers))
        for number in orders:
            bill = waybill_of(next(answer for answer, n in zip(answers, orders) if n == number)) or order_waybill(number)
            if bill:
                remember(number, bill)
                cancel_order(number, bill)

    # SF-04
    STATE['label'] = 'SF-04'
    r.case('SF-04', 'no token, a token for another audience, a forged signature, on each of the three paths: 401, and nothing is asked downstream')
    for label, token in (('no token', None), ('another audience', tok['blue-other-aud']), ('forged signature', gk.forged(tok['blue']))):
        for path in (ORDERS, CANCELS, QUERIES):
            dmark, smark = marks(reset=True)
            answer = req('POST', path, token, {'x': 1})
            short = path.removeprefix(BASE)
            r.check(f'{label} {short}: 401', answer['status'] == 401)
            r.check(f'{label} {short}: gateway-authz was not asked', asked_since(dmark) == 0)
            quiet(f'{label} {short}: the signer was not called and the carrier got nothing', dmark, smark, no_token=True)

    # SF-05
    STATE['label'] = 'SF-05'
    r.case('SF-05', 'tenants: green gets the green app; green cannot cancel blue\'s order (the stand-in\'s assumption); blue asking for green\'s account is refused'
           + ('' if not sandbox else ' (sandbox: green has no account)'))
    if sandbox:
        dmark, _ = marks()
        answer = post(QUERIES, query_body(new_order_no(), 'SF000000000000'), 'green')
        r.check('green (no account in this run): 403', answer['status'] == 403)
        r.note('green: gateway-authz\'s reason', reason_since(dmark))
        r.skip('green gets the green app, and green cannot cancel an order of the blue app', 'there is one sandbox account; order ownership per app is the stand-in\'s assumption and is not sent to the sandbox')
    else:
        owned = new_order_no()
        made_it = post(ORDERS, order_body(owned, username))
        owned_bill = waybill_of(made_it)
        remember(owned, owned_bill)
        r.check('a blue order exists to try against', bool(owned_bill))
        dmark, _ = marks(reset=True)
        answer = post(QUERIES, query_body(new_order_no(), 'SF000000000000'), 'green')
        hits = [hit for hit in standin_hits() if hit.get('kind') == 'dispatch']
        green_key = apps[GREEN_ACCOUNT]['app_key']
        got_key = header_values(hits[0], 'appKey') if len(hits) == 1 else []
        got_token = header_values(hits[0], 'token') if len(hits) == 1 else []
        accepted = len(hits) == 1 and hits[0].get('refused') is None and len(got_token) == 1
        if accepted:
            seen_token[green_key] = got_token[0]
        r.check('green: HTTP 200 and the dispatch carries the green app\'s key', answer['status'] == 200 and got_key == [green_key])
        r.check('green: the dispatch carries the token the stand-in issued to the green app (accepted, and not the blue app\'s), compared and not printed',
                accepted and got_token[0] != seen_token.get(apps[BLUE_ACCOUNT]['app_key']))
        if owned_bill:
            denied = post(CANCELS, cancel_body(owned, owned_bill), 'green')
            r.check('green cannot cancel blue\'s order: business success is false (order ownership per app is the stand-in\'s assumption)',
                    denied['status'] == 200 and business(denied).get('success') is False)
            r.check('blue\'s order still exists after green\'s cancel', order_active(owned))
            done, _ = cancel_order(owned, owned_bill)
            r.check('blue then cancels that order', business(done).get('success') is True)
    dmark, smark = marks(reset=not sandbox)
    answer = post(QUERIES, query_body(new_order_no(), 'SF000000000000'), headers=[('X-Provider-Account', GREEN_ACCOUNT)])
    r.check('blue asking for the green account: 403', answer['status'] == 403)
    r.check('the reason is ACCOUNT_NOT_GRANTED', reason_since(dmark) == 'ACCOUNT_NOT_GRANTED')
    quiet('blue asking for the green account: the signer was not called and the carrier got nothing', dmark, smark)

    # SF-06
    STATE['label'] = 'SF-06'
    r.case('SF-06', 'a client the register knows but Gatekeeper has no grant for: 403, the signer is not called')
    dmark, smark = marks(reset=not sandbox)
    answer = post(QUERIES, query_body(new_order_no(), 'SF000000000000'), 'ungranted')
    r.check('403', answer['status'] == 403)
    r.check('the reason is ACCOUNT_NOT_GRANTED', reason_since(dmark) == 'ACCOUNT_NOT_GRANTED')
    signer_stopped('the signer was not called', smark, False)
    standin_quiet('the carrier got nothing', no_token=False)

    # SF-07
    STATE['label'] = 'SF-07'
    r.case('SF-07', 'a method or a path that is not registered does not get to the signer or the carrier')
    for method in ('GET', 'PUT', 'DELETE', 'PATCH'):
        for path in (ORDERS, CANCELS, QUERIES):
            dmark, smark = marks(reset=not sandbox)
            answer = req(method, path, tok['blue'], raw=b'[]', content_type='application/json') if method in ('PUT', 'PATCH') else req(method, path, tok['blue'])
            short = f'{method} {path.removeprefix(BASE)}'
            r.check(f'{short}: 404 from the gateway', answer['status'] == 404)
            r.check(f'{short}: gateway-authz was not asked', asked_since(dmark) == 0)
            quiet(f'{short}: the signer was not called and the carrier got nothing', dmark, smark)
    near = [f'{ORDERS}/', f'{ORDERS}/X', f'{BASE}/orders-extra', f'{BASE}/order-cancellations/1', f'{BASE}/agent-number-queries/x',
            f'{ORDERS}/../orders', f'{ORDERS}/%2e%2e', f'{ORDERS}%2fX', f'{BASE}/%252e', f'{ORDERS};x=1', f'{ORDERS}%00',
            f'{BASE}//orders', f'{BASE}/ORDERS', '/sfintl/v1/orders', '/providers/wanbexpress/v1/parcels', '/providers/sfintl/v2/orders']
    for path in near:
        dmark, smark = marks(reset=not sandbox)
        # A JSON array: if a path were forwarded anyway, the signer would still refuse it before the carrier. The check requires that it was not called.
        answer = req('POST', path, tok['blue'], raw=b'[]', content_type='application/json')
        short = path.removeprefix(BASE) if path.startswith(BASE) else path
        r.check(f'{short}: refused ({answer["status"]})', answer['status'] is not None and answer['status'] >= 400)
        signer_stopped(f'{short}: the signer was not called', smark, False)
        standin_quiet(f'{short}: the carrier got nothing')
    dmark, smark = marks(reset=not sandbox)
    answer = req('POST', ORDERS + '?x=1', tok['blue'], raw=b'[]', content_type='application/json')
    r.check(f'query string on an allowed path: refused ({answer["status"]})', answer['status'] is not None and answer['status'] >= 400)
    seen = signer_calls(wait=True)[smark:]
    outcomes = [entry.get('outcome') for entry in seen]
    if not seen:
        who = f'the gateway ({answer["status"]}); the signer was not called'
    elif outcomes == ['query_not_allowed']:
        who = f'the signer, 400 query_not_allowed (HTTP {answer["status"]} to the caller)'
    else:
        who = f'signer outcomes {outcomes}, HTTP {answer["status"]} to the caller'
    r.note('who refused the query string', who)
    standin_quiet('query string: the carrier got nothing')
    signer_stopped('query string: nothing reached the carrier', smark, True)

    # SF-08
    STATE['label'] = 'SF-08'
    r.case('SF-08', 'the signer\'s own refusals, through the gateway: the caller gets the signer\'s JSON, and the carrier is not asked')
    refusals = [('Content-Type text/plain', b'hello', 'text/plain', 'unsupported_media_type'),
                ('a JSON array', b'[]', 'application/json', 'body_not_json_object'),
                ('two JSON objects', b'{}{}', 'application/json', 'body_not_json_object'),
                ('an empty body', b'', 'application/json', 'body_not_json_object'),
                ('a body that is not JSON', b'not-json', 'application/json', 'body_not_json_object')]
    for label, raw, content_type, code in refusals:
        dmark, smark = marks(reset=not sandbox)
        answer = post(ORDERS, None, raw=raw, content_type=content_type)
        r.check(f'{label}: the signer\'s {SIGNER_DETAIL[code][0]} {code}, as written', is_signer(answer, code))
        if not is_signer(answer, code):
            note_answer(label, answer)
        signer_stopped(f'{label}: nothing reached the carrier', smark, True)
        standin_quiet(f'{label}: the carrier got no dispatch')
    dmark, smark = marks(reset=not sandbox)
    huge = b'{' + b'"pad":"' + (b'a' * (1 << 20)) + b'"}'
    answer = post(ORDERS, None, raw=huge)
    who = 'provider-signer' if is_signer(answer, 'request_too_large') else 'not the signer\'s JSON'
    r.note('body over 1 MiB', {'status': answer['status'], 'who': who, 'signer_error': envelope(answer).get('error')})
    r.check(f'body over 1 MiB: refused ({answer["status"]})', answer['status'] is not None and answer['status'] >= 400)
    r.check('body over 1 MiB: the signer\'s 413 request_too_large, as written', is_signer(answer, 'request_too_large'))
    signer_stopped('body over 1 MiB: nothing reached the carrier', smark, True)
    standin_quiet('body over 1 MiB: the carrier got no dispatch')

    def extra_cases():
        # SF-12
        STATE['label'] = 'SF-12'
        r.case('SF-12', 'revocation through gateway-control: a read-only query is refused, the signer is not called, green is not touched; restored, blue is served again')
        if not skipped_here('SF-12'):
            pid = authz_process()
            if sandbox:
                r.skip('before: blue is served', 'the confirming query is the one after the restore')
            else:
                standin_reset()
                before = post(QUERIES, query_body(new_order_no(), 'SF000000000000'))
                r.check('before: blue is served (query HTTP 200, apiResultCode 0)', before['status'] == 200 and envelope(before).get('apiResultCode') == 0)
            revoked = {'code': None, 'json': None, 'said': ''}
            try:
                revoked = control('revoke', '--account', BLUE_ACCOUNT, '--reason', 'sfintl rig: SF-12')
                r.note('gateway-control revoke', {'exit': revoked['code'], 'outcome': (revoked['json'] or {}).get('outcome'), 'said': revoked['said']})
                r.check('gateway-control revoke: exit 0, REVOKED, the account is revoked and it changed',
                        outcome(revoked, 'REVOKED', command='revoke', account=BLUE_ACCOUNT, revoked=True, changed=True))
                dmark, smark = marks(reset=not sandbox)
                answer = post(QUERIES, query_body(new_order_no(), 'SF000000000000'))
                r.note('blue\'s next request', {'status': answer['status'], 'reason_code': envelope(answer).get('reason_code'), 'gateway-authz decided': reason_since(dmark)})
                r.check('blue\'s next request: 403', answer['status'] == 403)
                r.check('the reason is ACCOUNT_REVOKED, in the answer and in gateway-authz\'s decision',
                        envelope(answer).get('reason_code') == 'ACCOUNT_REVOKED' and reason_since(dmark) == 'ACCOUNT_REVOKED')
                signer_stopped('blue\'s request after the revocation: the signer was not called', smark, False)
                standin_quiet('blue\'s request after the revocation: the carrier got nothing')
                if sandbox:
                    r.skip('green is not affected by blue\'s revocation', 'there is one sandbox account')
                else:
                    green_answer = post(QUERIES, query_body(new_order_no(), 'SF000000000000'), 'green')
                    green_hits = [hit for hit in standin_hits() if hit.get('kind') == 'dispatch']
                    r.check('green is not affected: query HTTP 200, apiResultCode 0, and the dispatch carries the green app\'s key',
                            green_answer['status'] == 200 and envelope(green_answer).get('apiResultCode') == 0 and len(green_hits) == 1
                            and header_values(green_hits[0], 'appKey') == [apps[GREEN_ACCOUNT]['app_key']])
                listed = control('revocations')
                rows = (listed['json'] or {}).get('revoked_accounts') or []
                r.check('gateway-control revocations: LISTED, blue\'s account is in the table and no other',
                        outcome(listed, 'LISTED') and [item.get('account_id') for item in rows] == [BLUE_ACCOUNT])
            finally:
                lifted = control('restore', '--account', BLUE_ACCOUNT) if revoked['json'] else {'code': None, 'json': None, 'said': ''}
            r.check('gateway-control restore: exit 0, LIFTED, the account is not revoked and it changed',
                    outcome(lifted, 'LIFTED', command='restore', account=BLUE_ACCOUNT, revoked=False, changed=True))
            if not sandbox:
                standin_reset()
            again = post(QUERIES, query_body(new_order_no(), 'SF000000000000'))
            r.check('after the restore blue is served again: query HTTP 200, apiResultCode 0', again['status'] == 200 and envelope(again).get('apiResultCode') == 0)
            if not sandbox:
                r.check('and the carrier received that one request', len([hit for hit in standin_hits() if hit.get('kind') == 'dispatch']) == 1)
            r.check('gateway-authz is the same process throughout (same pid, still running)', authz_process() == pid and pid[0] is not None)

        # SF-13
        STATE['label'] = 'SF-13'
        r.case('SF-13', 'the token and the apps file (stand-in only): a voided token keeps failing until key_version changes; a token is replaced before it is used expired; a file that does not load changes nothing')
        if sandbox:
            r.skip('every check of this case', 'the sandbox token is not voided or shortened from here, and the apps file is not rewritten against the real carrier')
        elif not skipped_here('SF-13'):
            pid = authz_process()
            blue_key = apps[BLUE_ACCOUNT]['app_key']
            green_key = apps[GREEN_ACCOUNT]['app_key']

            def one_query(reset: bool = True) -> dict:
                if reset:
                    standin_reset()
                return post(QUERIES, query_body(new_order_no(), 'SF000000000000'))

            def token_hits():
                return [hit for hit in standin_hits() if hit['kind'] == 'token']

            try:
                _admin('POST', '/admin/tokens/void')
                standin_reset()
                voided = one_query(reset=False)
                r.check('after the token is voided: HTTP 200 and the carrier\'s apiResultCode 500 is passed through (apiErrorMsg kept, apiResultData null)',
                        voided['status'] == 200 and envelope(voided).get('apiResultCode') == 500 and 'apiErrorMsg' in envelope(voided)
                        and envelope(voided).get('apiResultData') is None and 'error' not in envelope(voided))
                if envelope(voided).get('apiResultCode') != 500:
                    note_answer('voided token', voided)
                further = []
                for _ in range(3):
                    follow = one_query(reset=False)
                    further.append(envelope(follow).get('apiResultCode'))
                r.note('further requests after the voided token, apiResultCode', further)
                standin_reset()
                replace_apps(apps_document(blue_version='2'))
                served = one_query(reset=False)
                hits = token_hits()
                r.check('key_version changed: the next request is served (HTTP 200, apiResultCode 0)',
                        served['status'] == 200 and envelope(served).get('apiResultCode') == 0)
                r.check('the stand-in saw exactly one new token request, and it is the blue app\'s',
                        len(hits) == 1 and token_app_key(hits[0]) == blue_key)
                r.check('the green app\'s token was not fetched again', all(token_app_key(hit) != green_key for hit in hits))
                r.check('gateway-authz is the same process after the file is replaced', authz_process() == pid and pid[0] is not None)
                dispatches = [hit for hit in standin_hits() if hit.get('kind') == 'dispatch' and hit.get('refused') is None]
                if dispatches:
                    got = header_values(dispatches[-1], 'token')
                    if len(got) == 1:
                        seen_token[blue_key] = got[0]

                _admin('POST', '/admin/token-lifetime?seconds=5')
                replace_apps(apps_document(blue_version='3'))
                standin_reset()
                short = one_query(reset=False)
                first_hits = [hit for hit in standin_hits() if hit.get('kind') == 'dispatch' and hit.get('refused') is None]
                first_token = header_values(first_hits[0], 'token') if len(first_hits) == 1 else []
                r.check('a 5-second token is fetched and the request is served',
                        short['status'] == 200 and envelope(short).get('apiResultCode') == 0 and len(token_hits()) == 1 and len(first_token) == 1)
                time.sleep(6)       # past the 5 second life; the refresh lead for a 5 second token is half a second
                standin_reset()
                renewed = one_query(reset=False)
                renewed_hits = [hit for hit in standin_hits() if hit.get('kind') == 'dispatch']
                renewed_token = header_values(renewed_hits[0], 'token') if len(renewed_hits) == 1 else []
                r.check('after the token is past its life: the request is served and the dispatch was not refused',
                        renewed['status'] == 200 and envelope(renewed).get('apiResultCode') == 0 and len(renewed_hits) == 1 and renewed_hits[0].get('refused') is None)
                r.check('that dispatch carries a new token (one more token request; compared, not printed)',
                        len(token_hits()) == 1 and len(renewed_token) == 1 and len(first_token) == 1 and renewed_token[0] != first_token[0])
                if len(renewed_token) == 1:
                    seen_token[blue_key] = renewed_token[0]
            finally:
                _admin('POST', '/admin/token-lifetime?seconds=7200')
                replace_apps(apps_document())
            standin_reset()
            restored = one_query(reset=False)
            r.check('the lifetime is back to 7200 and key_version is back, and a request is served',
                    restored['status'] == 200 and envelope(restored).get('apiResultCode') == 0)
            r.check('gateway-authz is the same process throughout', authz_process() == pid and pid[0] is not None)

            try:
                replace_apps(apps_document(extra={'unexpected': 'no'}))
                standin_reset()
                kept = one_query(reset=False)
                kept_hits = [hit for hit in standin_hits() if hit.get('kind') == 'dispatch']
                r.check('a file that does not load: the next request is still served with the last file that loaded',
                        kept['status'] == 200 and envelope(kept).get('apiResultCode') == 0 and len(kept_hits) == 1 and kept_hits[0].get('refused') is None
                        and header_values(kept_hits[0], 'appKey') == [blue_key])
            finally:
                replace_apps(apps_document())
            standin_reset()
            back = one_query(reset=False)
            r.check('the first file is put back and a request is served', back['status'] == 200 and envelope(back).get('apiResultCode') == 0)

        # SF-14
        STATE['label'] = 'SF-14'
        r.case('SF-14', 'a create whose result is unknown, and a carrier that misbehaves (stand-in only): one dispatch, no replay, the signer\'s own error')
        if sandbox:
            r.skip('every check of this case', 'the sandbox cannot be made slow, cut off, or given a bad answer; faults are the stand-in\'s')
        elif not skipped_here('SF-14'):
            def slow_or_cut(label: str, kind: str, hold: float):
                number = new_order_no()
                body = order_body(number, username)
                standin_reset()
                standin_fault(kind, hold)
                started = time.perf_counter()
                answer = post(ORDERS, body)
                took = time.perf_counter() - started
                if kind == 'slow':
                    time.sleep(max(0.0, hold + 1.5 - took))
                else:
                    time.sleep(1.5)
                code = envelope(answer).get('error')
                r.note(f'{label}: what the caller got', {'status': answer['status'], 'error': code or answer.get('error'), 'seconds': round(took, 3)})
                if kind == 'slow':
                    r.check(f'{label}: the caller gets the signer\'s own 504 carrier_timeout after about the signer\'s 8s (not the gateway\'s 9s)',
                            is_signer(answer, 'carrier_timeout') and 7.0 <= took <= 8.8)
                else:
                    which = envelope(answer).get('error')
                    carrier_status = envelope(answer).get('carrier_status')
                    matches = (which == 'carrier_status' and is_signer(answer, 'carrier_status', carrier_status)) or (
                        which in ('carrier_unreachable', 'carrier_answer_unreadable') and is_signer(answer, which))
                    r.check(f'{label}: the caller gets a 502 from the signer', answer['status'] == 502 and matches)
                r.check(f'{label}: the caller\'s answer has no Set-Cookie and no X-Mock-Provider', no_carrier_headers(answer))
                r.check(f'{label}: the carrier received exactly one create dispatch (no replay)', len(create_dispatches(number)) == 1)
                bill = order_waybill(number)
                r.check(f'{label}: the order exists', order_active(number) and bool(bill))
                if bill:
                    remember(number, bill)
                repeat = post(ORDERS, body)
                repeat_bill = waybill_of(repeat)
                if repeat_bill:
                    remember(number, repeat_bill)
                r.check(f'{label}: the same create again answers 123052 with that order\'s waybill',
                        repeat['status'] == 200 and business(repeat).get('success') is True and business(repeat).get('code') == '123052'
                        and bool(bill) and repeat_bill == bill)
                r.check(f'{label}: two create dispatches in all', len(create_dispatches(number)) == 2)
                if bill:
                    done, _ = cancel_order(number, bill)
                    r.check(f'{label}: the order is cancelled', business(done).get('success') is True)
                elif repeat_bill:
                    done, _ = cancel_order(number, repeat_bill)
                    r.check(f'{label}: the order is cancelled', business(done).get('success') is True)

            slow_or_cut('slow', 'slow', 11)
            slow_or_cut('cut', 'cut', 0)

            number = new_order_no()
            standin_reset()
            standin_fault('status', code=503)
            answer = post(ORDERS, order_body(number, username))
            r.note('status 503: what the caller got', {'status': answer['status'], 'error': envelope(answer).get('error'), 'carrier_status': envelope(answer).get('carrier_status')})
            r.check('status 503: 502 carrier_status with carrier_status 503', is_signer(answer, 'carrier_status', 503))
            r.check('status 503: no Set-Cookie and no X-Mock-Provider', no_carrier_headers(answer))
            r.check('status 503: the order was not created', not order_active(number))
            # A retry can turn the signer's 502 into a later success. The check above still fails; the waybill is cancelled anyway.
            bill = waybill_of(answer) or order_waybill(number)
            if bill:
                remember(number, bill)
                cancel_order(number, bill)

            number = new_order_no()
            standin_reset()
            standin_fault('garbage')
            answer = post(ORDERS, order_body(number, username))
            r.check('garbage: 502 carrier_answer_unreadable', is_signer(answer, 'carrier_answer_unreadable'))
            r.check('garbage: no Set-Cookie and no X-Mock-Provider', no_carrier_headers(answer))
            r.check('garbage: the order was not created', not order_active(number))
            bill = waybill_of(answer) or order_waybill(number)
            if bill:
                remember(number, bill)
                cancel_order(number, bill)

            number = new_order_no()
            standin_reset()
            standin_fault('undecryptable')
            answer = post(ORDERS, order_body(number, username))
            r.check('undecryptable: 502 carrier_answer_unreadable', is_signer(answer, 'carrier_answer_unreadable'))
            r.check('undecryptable: no Set-Cookie and no X-Mock-Provider', no_carrier_headers(answer))
            bill = order_waybill(number)
            r.check('undecryptable: the order exists', order_active(number) and bool(bill))
            if bill:
                remember(number, bill)
                done, _ = cancel_order(number, bill)
                r.check('undecryptable: the order is cancelled', business(done).get('success') is True)

        # SF-15
        STATE['label'] = 'SF-15'
        r.case('SF-15', 'the hop to the signer, called directly: only the gateway\'s certificate is served, and a credential is required')
        if not skipped_here('SF-15'):
            def direct(cert: str | None, headers: list[tuple[str, str]] | None = None) -> dict:
                context = pki.client_context(gk.TLS, cert)
                answer = {'status': None, 'json': None, 'headers': [], 'error': None}
                conn = None
                try:
                    conn = pki.GatekeeperConnection(HOOKS['signer_port'], context, 5, SIGNER_NAME)
                    conn.request('POST', '/sfintl/v1/orders', body=b'{}', headers={'Host': SIGNER_NAME, 'Content-Type': 'application/json', **dict(headers or [])})
                    response = conn.getresponse()
                    blob = response.read()
                    answer['status'] = response.status
                    answer['headers'] = [(k.lower(), v) for k, v in response.getheaders()]
                    try:
                        answer['json'] = json.loads(blob)
                    except ValueError:
                        answer['json'] = None
                except (ssl.SSLError, OSError, http.client.HTTPException) as e:
                    answer['error'] = type(e).__name__
                finally:
                    if conn is not None:
                        conn.close()
                return answer

            probes = [('no client certificate', None, 'handshake'), ('the rogue-gateway certificate (another CA)', 'rogue-gateway', 'handshake'),
                      ('the business-app certificate (right CA, another identity)', 'business-app', 'caller_not_allowed'),
                      ('the gateway certificate and no Authorization', 'gateway', 'credential_malformed')]
            for label, cert, kind in probes:
                smark = len(signer_calls())
                if not sandbox:
                    standin_reset()
                answer = direct(cert)
                if kind == 'handshake':
                    r.check(f'{label}: the handshake or the request fails', answer['status'] is None)
                else:
                    r.check(f'{label}: 403 {kind}, as written', is_signer(answer, kind))
                    if not is_signer(answer, kind):
                        note_answer(label, answer)
                signer_stopped(f'{label}: nothing reached the carrier', smark, True)
                standin_quiet(f'{label}: the carrier got no dispatch')

    # SF-09
    STATE['label'] = 'SF-09'
    r.case('SF-09', 'gateway-authz allows and releases no credential: the gateway\'s backend rule refuses, so the signer is not called; a caller\'s own Authorization does not take its place')
    if HOOKS['skip_sf09']:
        r.skip('every check of this case', HOOKS['skip_sf09'])
        extra_cases()
        return
    secret = secrets.token_urlsafe(24)
    gk.stop('gateway-authz')
    start_authz('gateway-authz-acceptance', {'GATEWAY_AUTHZ_ACCEPTANCE_ADMIN_SECRET': secret,
                                             'GATEWAY_AUTHZ_ACCEPTANCE_OPERATOR_IDENTITY': pki.ID['operator'],
                                             'GATEWAY_AUTHZ_ACCEPTANCE_SLOW_SECONDS': '1'})
    try:
        def operator(path: str):
            conn = pki.GatekeeperConnection(gk.PORTS['authz'], pki.client_context(gk.TLS, 'operator'), 5)
            try:
                conn.request('POST', path, body=b'', headers={'Host': pki.GATEKEEPER_NAME, 'X-Poc-Admin': secret})
                response = conn.getresponse()
                response.read()
                return response.status
            finally:
                conn.close()
        try:
            switched = operator('/admin/mode?value=allow_without_credential')
        except (OSError, http.client.HTTPException):
            switched = None
        r.check('the PDP is set to allow without a credential', switched == 200)
        probe = query_body(new_order_no(), 'SF000000000000')
        for label, headers in (('the caller sends nothing of its own', []), ('the caller\'s own Authorization after its token', [('Authorization', PLANTED)])):
            dmark, smark = marks(reset=not sandbox)
            answer = post(QUERIES, probe, headers=headers)
            r.check(f'{label}: the caller does not get a success ({answer["status"]})', answer['status'] is not None and answer['status'] >= 400)
            r.check(f'{label}: the PDP did allow it (so it is the gateway that refused)', reason_since(dmark) == 'ACTIVE_ACCOUNT_GRANT')
            r.check(f'{label}: the answer is not the carrier\'s', no_carrier_headers(answer))
            signer_stopped(f'{label}: the signer was not called', smark, False)
            standin_quiet(f'{label}: the carrier got nothing')
        dmark, smark = marks(reset=not sandbox)
        answer = req('POST', QUERIES, None, probe, headers=[('Authorization', PLANTED), ('Authorization', 'Bearer ' + tok['blue'])])
        r.check(f'the caller\'s own Authorization before its token: refused ({answer["status"]})', answer['status'] is not None and answer['status'] >= 400)
        signer_stopped('the caller\'s own Authorization before its token: the signer was not called', smark, False)
        standin_quiet('the caller\'s own Authorization before its token: the carrier got nothing')
        try:
            restored = operator('/admin/mode?value=normal')
        except (OSError, http.client.HTTPException):
            restored = None
        r.check('the PDP is set back to normal', restored == 200)
        if sandbox:
            r.skip('control: with a credential released, the same request is served and the carrier saw the blue app\'s key, not the planted one',
                   'what the carrier received is stand-in only; not repeated at the sandbox')
        else:
            standin_reset()
            answer = post(QUERIES, probe, headers=[('Authorization', PLANTED)])
            hits = [hit for hit in standin_hits() if hit.get('kind') == 'dispatch']
            r.check('control: with a credential released, the same request is served (HTTP 200, apiResultCode 0)',
                    answer['status'] == 200 and envelope(answer).get('apiResultCode') == 0)
            flat = json.dumps(hits)
            r.check('control: the carrier saw the blue app\'s key and not the planted one',
                    len(hits) == 1 and header_values(hits[0], 'appKey') == [apps[BLUE_ACCOUNT]['app_key']] and 'PLANTED' not in flat)
    finally:
        gk.stop('gateway-authz')
        start_authz('gateway-authz')
    back = post(QUERIES, query_body(new_order_no(), 'SF000000000000'))
    r.check('the product build of gateway-authz is back and allows again', back['status'] == 200 and envelope(back).get('apiResultCode') == 0)
    extra_cases()


def cancel_outstanding(state: dict):
    """Every order this run learned a waybill for, and any the stand-in still calls active, is cancelled. A sandbox cancel that fails is retried."""
    if not gk.port_open(gk.PORTS['gateway']):
        return
    if gk.port_open(gk.PORTS['provider']) and MOCK_SECRET:
        try:
            for item in standin_orders():
                if item.get('state') != 'cancelled':
                    remember(item.get('customer_order_no'), item.get('sf_waybill_no'))
                    CREATED[item['sf_waybill_no']] = 'created'
        except SystemExit:
            raise
        except Exception:
            pass
    pending = [waybill for waybill, status in CREATED.items() if status != 'cancelled']
    if not pending:
        return
    token = gk.token_for(state['blue']['client'])
    if not token:
        return
    STATE['label'] = 'cleanup'
    for waybill in pending:
        order_no = ORDER_OF.get(waybill)
        if not order_no:
            continue
        last = None
        for attempt in range(1, 7):
            last = req('POST', CANCELS, token, cancel_body(order_no, waybill), sample_peers=bool(PLAIN_HTTP_HOST[0]))
            if business(last).get('success') is True:
                CREATED[waybill] = 'cancelled'
                break
            if attempt < 6 and PLAIN_HTTP_HOST[0]:
                time.sleep(3)


def warn_uncancelled() -> list[str]:
    """Print the orders still in CREATED, between rows of exclamation marks. Returns their waybill numbers."""
    left = sorted(waybill for waybill, status in CREATED.items() if status != 'cancelled')
    if left:
        shown = [f"{waybill} ({ORDER_OF.get(waybill)})" for waybill in left]
        say('\n' + '!' * 70 + f'\n!! ORDERS THAT WERE CREATED AND NOT CANCELLED: {shown}\n!! Cancel them by hand at the carrier.\n' + '!' * 70)
    return left


def secret_list(made: dict, state: dict, sandbox: bool) -> list:
    """Every secret of this run: [(what it is, the value)]. The values are never written anywhere."""
    found = []
    for account, app in made.get('apps', {}).items():
        found.append((f'app key of {account}', app.get('app_key')))
        found.append((f'app secret of {account}', app.get('app_secret')))
        found.append((f'encoding key of {account}', app.get('encoding_aes_key')))
    if not sandbox:
        found += [(f'access token {i}', value) for i, value in enumerate(sorted(ISSUED))]
    found.append(('PDP token', gk.ENV.get('GK_PDP_AUTH_TOKEN', '')))
    found += [(f'client secret of {key}', state[key]['client']['client_secret']) for key in state]
    found += [(f'Gatekeeper token {i}', value) for i, value in enumerate(made.get('tokens', []))]
    return [(what, value) for what, value in found if isinstance(value, str) and value]


def scan(made: dict, state: dict, result_text: str, sandbox: bool, logs: dict | None = None) -> tuple[dict, list]:
    """Logs of the gateway, gateway-authz and the signer, this run's output, and the result file."""
    secrets_found = secret_list(made, state, sandbox)
    texts = logs or {'gateway log': (RUN / 'gateway.log').read_text(encoding='utf-8', errors='replace') if (RUN / 'gateway.log').exists() else '',
                     'gateway-authz log': (RUN / 'gateway-authz.log').read_text(encoding='utf-8', errors='replace') if (RUN / 'gateway-authz.log').exists() else '',
                     'provider-signer log': (RUN / 'provider-signer.log').read_text(encoding='utf-8', errors='replace') if (RUN / 'provider-signer.log').exists() else ''}
    if HOOKS.get('logs'):
        texts = dict(HOOKS['logs'])
    texts = {**texts, 'standard output': '\n'.join(OUTPUT), 'result file': result_text}
    scheme = re.compile(r'Sf-OpenApi [^;\s"\']+;')
    token_shape = re.compile(r'auth_[A-Za-z0-9_-]{8,}')
    outcome_map = {}
    for where, text in texts.items():
        found = {'secret found': [what for what, value in secrets_found if value and value in text],
                 'Sf-OpenApi value found': bool(scheme.search(text))}
        if sandbox:
            found['access-token shape found'] = bool(token_shape.search(text))
        outcome_map[where] = found
    return outcome_map, [what for what, _ in secrets_found]


NO_ROLES = ('Not recorded. The repository owner decided on 2026-11-19 (development plan 1.6) that this technical software has no operator and '
            'approver kept apart: this file records what was run, on which commits and images, and what was seen. It is a record of verification, '
            'not a gate decision.')
EVIDENCE_FIELDS = ('kind', 'upstream_kind', 'operator_and_approver', 'agentgateway', 'gatekeeper_commit', 'repository', 'registry_sha256',
                   'gateway_configuration_sha256', 'environment', 'started_at_utc', 'finished_at_utc', 'clock', 'dataset', 'upstream',
                   'gateway_proxy_variables', 'cases', 'summary')
SECRET_SHAPES = (re.compile(r'Sf-OpenApi [^;\s"\']+;'), re.compile(r'auth_[A-Za-z0-9_-]{8,}'), re.compile(r'Bearer [A-Za-z0-9._~+/=-]{16,}'))


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_out(*argv: str, where: Path | None = None) -> str:
    return subprocess.run(['git', '-C', str(where or ROOT), *argv], capture_output=True, text=True).stdout.strip()


def evidence_document(kind: str, sandbox: bool, started_at: str, finished_at: str, reported: dict, results: 'Results', upstream: dict,
                      proxy_variables, image: str, binary: str | None = None) -> dict:
    checks = [item for case in results.cases for item in case['checks']]
    cases = [{'id': case['id'], 'title': case['title'],
              'result': 'fail' if any(item['ok'] is False for item in case['checks']) else
              ('skipped' if case['checks'] and all(item['ok'] is None for item in case['checks']) else 'pass'),
              'checks': [{'check': item['check'], 'result': 'pass' if item['ok'] else ('fail' if item['ok'] is False else 'skipped'),
                          **({'reason': item['skipped']} if item['ok'] is None else {})} for item in case['checks']],
              'notes': case['notes']} for case in results.cases]
    kept = sorted(waybill for waybill, status in CREATED.items() if status == 'cancelled')
    left = sorted(waybill for waybill, status in CREATED.items() if status != 'cancelled')
    return {
        'kind': kind, 'upstream_kind': 'the carrier\'s sandbox' if sandbox else 'stand-in', 'operator_and_approver': NO_ROLES,
        'agentgateway': {'version': reported['version'], 'image': image, **({'local_binary_sha256': sha256_of(Path(binary))} if binary else {})},
        'gatekeeper_commit': git_out('rev-parse', '--short', 'HEAD', where=Path(os.environ.get('GK_SRC', str(Path.home() / '.local/src/idp-gatekeeper')))),
        'repository': {'commit': git_out('rev-parse', '--short', 'HEAD'),
                       'uncommitted_files': len([line for line in git_out('status', '--porcelain', '--', '.', ':!tests/integration/sfintl/evidence').splitlines() if line.strip()])},
        'registry_sha256': sha256_of(POLICY_EXAMPLE),
        'registry_note': 'the example register; each run fills its placeholders with that run\'s tenant and client ids, so the filled copy differs from run to run',
        'gateway_configuration_sha256': sha256_of(CONFIG),
        'environment': sorted({row['environment'] for row in json.loads(POLICY_EXAMPLE.read_text())['registered_operations']}),
        'started_at_utc': started_at, 'finished_at_utc': finished_at,
        'clock': CLOCK or {'carrier_response_date': None, 'note': 'no Date header on the answer to the first query'},
        'dataset': {'reference_prefix': f"IDPGW-{datetime.datetime.now(datetime.timezone.utc):%Y%m%d}-",
                    'orders_created_and_cancelled': kept, 'orders_left_uncancelled': left},
        'upstream': upstream, 'gateway_proxy_variables': proxy_variables, 'cases': cases,
        'summary': {'cases': len(cases), 'cases_failed': sum(1 for case in cases if case['result'] == 'fail'),
                    'cases_skipped': sum(1 for case in cases if case['result'] == 'skipped'),
                    'checks': len(checks), 'checks_passed': sum(1 for item in checks if item['ok']),
                    'checks_failed': sum(1 for item in checks if item['ok'] is False),
                    'checks_skipped': sum(1 for item in checks if item['ok'] is None)},
    }


def write_evidence(name: str, document: dict, made: dict, state: dict, sandbox: bool) -> bool:
    """Write the evidence file, then read it back. A secret, or a secret shape, deletes the file."""
    EVIDENCE.mkdir(exist_ok=True)
    path = EVIDENCE / name
    path.write_text(json.dumps(document, ensure_ascii=False, indent=1) + '\n', encoding='utf-8')
    text = path.read_text(encoding='utf-8')
    found = [what for what, value in secret_list(made, state, sandbox) if value and value in text]
    found += [f'a value of shape {shape.pattern}' for shape in SECRET_SHAPES if shape.search(text)]
    if found:
        path.unlink()
        say(f'EVIDENCE NOT KEPT: the file held {found} (what it was, not the value); it was deleted')
        return False
    say(f'evidence written: {path.relative_to(ROOT)}')
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description='deploy/providers/sfintl on the Gatekeeper integration rig')
    parser.add_argument('--sandbox', action='store_true', help='upstream is the carrier\'s real sandbox (plain HTTP); needs --sandbox-credentials')
    parser.add_argument('--sandbox-credentials', help='with --sandbox: {"app_key", "app_secret", "encoding_aes_key", "api_username"} (0600, outside the repository)')
    parser.add_argument('--mutate', choices=sorted(MUTATIONS) + list(OTHER_CONTROLS), help='deliberately break one thing (stand-in only)')
    parser.add_argument('--evidence', action='store_true', help='write tests/integration/sfintl/evidence/rig-{sandbox,standin}.json (only with this flag)')
    args = parser.parse_args()
    if args.evidence and args.mutate:
        die('--evidence is for a run of the real configuration, not for a control')
    if args.sandbox != bool(args.sandbox_credentials):
        die('--sandbox and --sandbox-credentials go together')
    if args.sandbox and args.mutate:
        die('--mutate is for the stand-in only')
    global MOCK_SECRET
    OUT.mkdir(exist_ok=True)
    try:
        binary, reported = pin.resolve()
    except pin.PinError as e:
        die(str(e))
    if gk.call('GET', gk.ISSUER + '/health/ready')[0] != 200 or gk.call('GET', gk.BRIDGE + '/admin/me')[0] != 200:
        die('the local Gatekeeper is not ready: tests/integration/gatekeeper/stack.sh up')
    for name, port in gk.PORTS.items():
        if gk.port_open(port):
            die(f'port {port} ({name}) is in use: another suite is running, or the last run did not finish')
    if gk.port_open(SIGNER_PORT):
        die(f'port {SIGNER_PORT} (signer) is in use: another suite is running, or the last run did not finish')
    state = gk.seed()
    gk.sync_tuples(state)
    pki.issue(gk.TLS)
    gk.publish_pdp_tls()

    made: dict = {'apps': {}}
    endpoint = f"http://127.0.0.1:{gk.PORTS['provider']}/openapi/api/token"
    if args.sandbox:
        app = read_sandbox_credentials(args.sandbox_credentials)
        endpoint = f'http://{SANDBOX_HOST}/openapi/api/token'
        APPS_PATH = wrapped_apps(app, endpoint)
        global APPS_FILE
        APPS_FILE = APPS_PATH
        made['apps'] = {BLUE_ACCOUNT: app}
        CARRIER_URL[0] = f'http://{SANDBOX_HOST}/openapi/api/dispatch'
        PLAIN_HTTP_HOST[0] = SANDBOX_HOST
    else:
        for account in (BLUE_ACCOUNT, GREEN_ACCOUNT):
            made['apps'][account] = {'app_key': 'app' + secrets.token_hex(8), 'app_secret': secrets.token_hex(24),
                                     'encoding_aes_key': new_aes_key(), 'api_username': 'user' + secrets.token_hex(4)}
        CARRIER_URL[0] = f"http://127.0.0.1:{gk.PORTS['provider']}/openapi/api/dispatch"
        PLAIN_HTTP_HOST[0] = ''
        write('sfintl.apps.json', json.dumps(apps_document_initial(made['apps'], endpoint)))
    made['token_endpoint'] = endpoint
    MOCK_SECRET = '' if args.sandbox else secrets.token_urlsafe(24)
    if not args.sandbox:
        write('sfintl.mock-state.json', json.dumps({'admin_secret': MOCK_SECRET, 'token_lifetime_seconds': 7200,
                                                   'apps': [{'app_key': app['app_key'], 'app_secret': app['app_secret'],
                                                             'encoding_aes_key': app['encoding_aes_key'], 'api_username': app['api_username']}
                                                            for app in made['apps'].values()]}))
    USE_REVOCATIONS[0] = args.mutate != 'no-revocations'
    SIGNER_IDENTITY[0] = pki.ID['business-app'] if args.mutate == 'signer-other-identity' else pki.ID['gateway']
    SIGNER_TIMEOUT[0] = '20s' if args.mutate == 'signer-long-timeout' else ''
    write('sfintl.revocations.json', NOTHING_REVOKED)
    write('sfintl.policy.json', policy_for(state, args.sandbox))
    write('sfintl.pdp-token', gk.ENV['GK_PDP_AUTH_TOKEN'] + '\n')
    write('sfintl.agentgateway.yaml', gateway_config(args.mutate))
    build([], 'gateway-authz')
    build(['-tags', 'acceptance'], 'gateway-authz-acceptance')
    build([], 'gateway-control', './cmd/gateway-control')
    build([], 'provider-signer', './cmd/provider-signer')

    env, proxy_names = clean_proxy_env()
    env['SESSION_KEY'] = secrets.token_hex(32)
    valid = subprocess.run([binary, '--validate-only', '-f', '.run/sfintl.agentgateway.yaml'], cwd=gk.HERE, capture_output=True, text=True, env=env)
    if valid.returncode != 0:
        die('the gateway does not accept the configuration: ' + ' '.join((valid.stdout + valid.stderr).split())[:400])

    results = Results()
    resolved = sorted({item[4][0] for item in socket.getaddrinfo(SANDBOX_HOST, 80, type=socket.SOCK_STREAM)}) if args.sandbox else None
    started_at = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
    started = time.perf_counter()
    # After the first process is up: cancel while the gateway is still up, stop, and if the run
    # dies with an order left, say so before the exception leaves.
    failure: BaseException | None = None
    running = False
    try:
        for log in RUN.glob('*.log'):
            log.unlink()
        running = True
        if not args.sandbox:
            gk.start('provider', [sys.executable, str(MOCK), '--port', str(gk.PORTS['provider']), '--state', str(RUN / 'sfintl.mock-state.json')], gk.PORTS['provider'])
        start_authz('gateway-authz')
        start_signer()
        gk.start('gateway', [binary, '-f', '.run/sfintl.agentgateway.yaml'], gk.PORTS['gateway'], env=env)
        try:
            run_cases(results, state, made, args.sandbox)
        finally:
            try:
                cancel_outstanding(state)
            except Exception:
                pass
            if not args.sandbox and gk.port_open(gk.PORTS['provider']) and MOCK_SECRET:
                try:
                    harvest(standin_hits())
                except SystemExit:
                    raise
                except Exception:
                    pass
    except BaseException as caught:
        failure = caught
    finally:
        if running:
            gk.stop_all()
            gk.sync_tuples(state)
    if failure is not None:
        if warn_uncancelled() and isinstance(failure, SystemExit) and failure.code in (0, None):
            raise SystemExit(1)
        raise failure

    mode = 'sandbox' if args.sandbox else 'stand-in' + (f' (control: {args.mutate})' if args.mutate else '')
    uncleaned = sorted(waybill for waybill, status in CREATED.items() if status != 'cancelled')
    failed = results.failed()
    record = {'finished_at': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'), 'started_at': started_at,
              'duration_seconds': round(time.perf_counter() - started, 1), 'mode': mode,
              'agentgateway': reported['version'],
              'repository_head': subprocess.run(['git', '-C', str(ROOT), 'rev-parse', '--short', 'HEAD'], capture_output=True, text=True).stdout.strip(),
              'gatekeeper_commit': subprocess.run(['git', '-C', os.environ.get('GK_SRC', str(Path.home() / '.local/src/idp-gatekeeper')), 'rev-parse', '--short', 'HEAD'],
                                                  capture_output=True, text=True).stdout.strip(),
              'gateway_environment': {'proxy_variables_removed_from_the_gateway_process': proxy_names},
              'upstream': ({'kind': 'the carrier\'s sandbox', 'name': SANDBOX_HOST, 'name_resolved_to_at_the_start': resolved,
                            'addresses_the_signer_and_gateway_authz_held_connections_to': sorted(PEERS)}
                           if args.sandbox else {'kind': 'stand-in', 'address': f"127.0.0.1:{gk.PORTS['provider']}", 'signer': f'127.0.0.1:{SIGNER_PORT}'}),
              'calls': CALLS, 'orders_to_cancel_by_hand': [{'sfWaybillNo': waybill, 'customerOrderNo': ORDER_OF.get(waybill)} for waybill in uncleaned],
              'cases': results.cases, 'passed': [case['id'] for case in results.cases if case not in failed], 'failed': [case['id'] for case in failed]}
    scanned, looked_for = scan(made, state, json.dumps(record, ensure_ascii=False, indent=1), args.sandbox)
    def clean_of(found: dict) -> bool:
        return not found['secret found'] and not found['Sf-OpenApi value found'] and not found.get('access-token shape found')
    clean = all(clean_of(found) for found in scanned.values())
    record['secret_scan'] = {'looked_for': looked_for, 'outcome': scanned}
    results.case('SF-10', 'the logs of the gateway, gateway-authz and provider-signer, this run\'s output and the result file hold none of this run\'s secrets')
    for where, found in scanned.items():
        results.check(f'{where}: none of the {len(looked_for)} secrets of this run, and no value of the carrier\'s authorization scheme',
                      clean_of(found))
    results.cases.sort(key=lambda case: int(case['id'][3:]))
    record['cases'], failed = results.cases, results.failed()
    record['passed'], record['failed'] = [case['id'] for case in results.cases if case not in failed], [case['id'] for case in failed]
    final = json.dumps(record, ensure_ascii=False, indent=1)
    name = OUT / f"result-{'sandbox' if args.sandbox else 'standin'}{'-' + args.mutate if args.mutate else ''}.json"
    name.write_text(final, encoding='utf-8')
    os.chmod(name, 0o600)

    say(f'\nagentgateway {reported["version"]}; upstream: {mode}; {record["duration_seconds"]}s')
    results.report()
    if args.sandbox:
        say(f'  proxy variables removed from the gateway process: {proxy_names}')
        say(f'  {SANDBOX_HOST} resolved to {resolved}; the signer and gateway-authz held connections to {sorted(PEERS)}')
        say('  calls (case, call, status, ms):')
        for call in CALLS:
            say(f"    {call['case']:6} {call['call']:55} {call['status']}  {call['ms']}")
    kept = True
    if args.evidence:
        upstream = record['upstream']
        kept = write_evidence(f"rig-{'sandbox' if args.sandbox else 'standin'}.json",
                              evidence_document('rig: the real local Gatekeeper, agentgateway 1.7.0 as a local binary, gateway-authz and provider-signer as local processes',
                                                args.sandbox, started_at, record['finished_at'], reported, results, upstream,
                                                {'proxy_variables_removed_from_the_gateway_process': proxy_names, 'present_in_the_gateway_process': False},
                                                pin.image_reference(pin.lock()), binary), made, state, args.sandbox)
    if uncleaned:
        warn_uncancelled()
    say(f"\n{len(results.cases) - len(failed)}/{len(results.cases)} ({mode}); results in {name}")
    return int(bool(failed) or bool(uncleaned) or not clean or not kept)


def apps_document_initial(apps: dict, endpoint: str) -> dict:
    return {f'{BINDING}/{account}': {'token_endpoint': endpoint, 'app_key': app['app_key'], 'app_secret': app['app_secret'],
                                    'encoding_aes_key': app['encoding_aes_key'], 'key_version': '1'}
            for account, app in apps.items()}


if __name__ == '__main__':
    sys.exit(main())
