#!/usr/bin/env python3
"""WanbExpress: deploy/providers/wanbexpress/agentgateway.yaml on the Gatekeeper integration rig (development plan 3.2, first step).

Real: the local Gatekeeper (stack.sh up, not touched here), the pinned agentgateway, gateway-authz (product build, asking the
PDP over mutual TLS on 27623), the configuration file of the repository as it is. Stand-in: the carrier (mock_wanbexpress.py).

    .venv/bin/python tests/integration/wanbexpress/run.py                         upstream is the stand-in
    .venv/bin/python tests/integration/wanbexpress/run.py --mutate NAME           one deliberate break of the configuration (see MUTATIONS)
    .venv/bin/python tests/integration/wanbexpress/run.py --sandbox --sandbox-credentials FILE
                                                                                  upstream is the carrier's sandbox (plain HTTP, port 80)

The rig, its processes, its Gatekeeper seed and its tokens are those of tests/integration/gatekeeper/run.py, which is
imported and used as it is (it is not changed). Ports are the same set, so this and that suite, and the black-box suite, do not run at once.
Files the processes need are written to tests/integration/gatekeeper/.run/ (ignored); results go to tests/integration/wanbexpress/.run/.
"""
from __future__ import annotations
import argparse, atexit, datetime, email.utils, hashlib, shutil, tempfile, http.client, importlib.util, ipaddress, json, os, re, secrets, socket, stat, subprocess, sys, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
OUT = HERE / '.run'

# The rig, as it is. Importing it reads the stack's environment and adds the certificate names the rig uses.
_spec = importlib.util.spec_from_file_location('gk_rig', ROOT / 'tests/integration/gatekeeper/run.py')
gk = importlib.util.module_from_spec(_spec)
sys.modules['gk_rig'] = gk
_spec.loader.exec_module(gk)
pki, pin = gk.pki, gk.pin

CONFIG = ROOT / 'deploy/providers/wanbexpress/agentgateway.yaml'
POLICY_EXAMPLE = ROOT / 'deploy/providers/wanbexpress/policy.example.json'
MOCK = HERE / 'mock_wanbexpress.py'
RUN = gk.RUN
HOST = gk.HOST                                  # the name callers use
BASE = '/providers/wanbexpress/v1'
BINDING = 'gatekeeper:wanbexpress-test'
SANDBOX_HOST = 'api-sbx.wanbexpress.com'
BLUE_ACCOUNT, GREEN_ACCOUNT = 'account-blue', 'account-green'
GO = '/usr/local/go/bin/go'

# What the stand-in is started with in place of the sandbox: the backend of each route, written in the file as the sandbox.
UPSTREAM = '  - host: api-sbx.wanbexpress.com:80\n'
STANDIN = f"  - host: 127.0.0.1:{gk.PORTS['provider']}\n"

# Deliberate breaks, for the controls: (old text, new text, times it occurs in the file).
BACKEND_RULE = ("      authorization:\n        rules:\n        - allow: 'request.headers[\"authorization\"].startsWith(\"Hc-OweDeveloper \")'\n")
HEADER_FILTER = ("      transformations:\n        request:\n          replace: 'request.headers.filterKeys(k, k in "
                 "[\"accept\", \"authorization\", \"content-type\", \"idempotency-key\", \"traceparent\", \"x-client-trace\"])'\n")
MUTATIONS = {
    'bearer-prefix': ('startsWith("Hc-OweDeveloper ")', 'startsWith("Bearer ")', 4),
    'no-backend-rule': (BACKEND_RULE, '', 4),
    'no-accept': ("        set:\n          accept: application/json\n", '', 4),
    'no-header-filter': (HEADER_FILTER, '', 4),
    'delete-any-method': ("    method: DELETE\n", '', 1),
    # The create route with a retry policy (agentgateway 1.7.0 has `retry`): WB-14 has to fail, the carrier receives more than one POST.
    'create-retry': ("    # No retry policy on purpose. A create that times out has an unknown result; the same ReferenceId answers 0x100005 if it did go through.\n"
                     "    timeout:\n      requestTimeout: 9s\n",
                     "    retry:\n      attempts: 2\n      codes: [502, 503, 504]\n    timeout:\n      requestTimeout: 9s\n      backendRequestTimeout: 4s\n", 1),
}
# Controls that do not change the configuration file: gateway-authz is started without --revocations (WB-12 has to fail).
OTHER_CONTROLS = ('no-revocations',)
REVOCATIONS = RUN / 'wanbexpress.revocations.json'      # gateway-authz's own table of revoked accounts (ADR-0012)
NOTHING_REVOKED = '{"epoch": 0, "revoked_accounts": {}}\n'
USE_REVOCATIONS = [True]
EVIDENCE = HERE / 'evidence'

OUTPUT: list[str] = []


def say(text: str = ''):
    OUTPUT.append(text)
    print(text, flush=True)


def die(message: str):
    gk.stop_all()
    print('run.py:', message, file=sys.stderr)
    raise SystemExit(2)


# ---- results: a check is True, False or skipped (None, with the reason) ---------------------------------------------
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


# ---- the carrier's sandbox: where the credentials file is allowed to be ----------------------------------------------
def read_sandbox_credentials(path_text: str) -> tuple[str, str]:
    """{"account": ..., "token": ...}, outside the repository, 0600. Returns (account, token)."""
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
    if not (isinstance(entry, dict) and set(entry) == {'account', 'token'} and all(isinstance(v, str) and v for v in entry.values())):
        die('--sandbox-credentials: the file must be {"account": ..., "token": ...}')
    return entry['account'], entry['token']


def wrapped_credentials(account: str, token: str) -> Path:
    """gateway-authz's file for this run, in a temporary directory (0700) that is removed when the process ends, however it ends."""
    directory = Path(tempfile.mkdtemp(prefix='wanbexpress-'))
    atexit.register(shutil.rmtree, directory, True)
    path = directory / 'developer-tokens.json'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump({f'{BINDING}/{BLUE_ACCOUNT}': {'account': account, 'token': token}}, f)
    return path


# ---- files and processes -------------------------------------------------------------------------------------------------
def write(name: str, content: str) -> Path:
    path = RUN / name
    path.write_text(content, encoding='utf-8')
    os.chmod(path, 0o600)
    return path


def build(tags: list[str], target: str, package: str = './cmd/gateway-authz'):
    done = subprocess.run([GO, 'build', '-trimpath', *tags, '-o', str(RUN / target), package], cwd=ROOT, capture_output=True, text=True)
    if done.returncode != 0:
        die('gateway-authz build failed:\n' + done.stderr[-1500:])


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
        row['allowed_service_ids'].append(ungranted)    # a client the register knows and Gatekeeper has no grant for
        if sandbox:
            del row['accounts_by_tenant'][state['green']['tenant_id']]   # one sandbox account: the green tenant has none
    document['registered_operations'] = rows
    if any(('TENANT-ID-' in json.dumps(r) or 'CLIENT-ID-' in json.dumps(r)) for r in rows):
        die('a placeholder is left in the register')
    return json.dumps(document)


# The deployment file is written with the values of the single-host pool. On the Gatekeeper rig these are put back to the
# rig's: exact text replacements, each with the number of times it occurs (the suite stops when the file no longer says
# what it expects).
RIG_VALUES = [
    ('  adminAddr: 127.0.0.1:15000\n', '  adminAddr: 127.0.0.1:27614\n', 1),
    ('  statsAddr: 127.0.0.1:15020\n', '  statsAddr: 127.0.0.1:27615\n', 1),
    ('  readinessAddr: 127.0.0.1:15021\n', '  readinessAddr: 127.0.0.1:27616\n', 1),
    ("destination.port == 8081'", "destination.port == 27611'", 1),
    ('destination.port == 8443 &&', 'destination.port == 27619 &&', 1),
    ('    port: 8443\n', '    port: 27619\n', 1),
    ('    port: 8081\n', '    port: 27611\n', 1),
    ('      host: gateway-authz:9443\n', '      host: 127.0.0.1:27613\n', 4),
    ('cert: tls/', 'cert: .run/tls/', 5),
    ('key: tls/', 'key: .run/tls/', 5),
    ('root: tls/', 'root: .run/tls/', 5),
    ('        file: tls/jwks.json\n', '        url: http://127.0.0.1:27621/.well-known/jwks.json\n', 1),
    ('  - host: 127.0.0.1:15000\n', '  - host: 127.0.0.1:27614\n', 1),
]
POOL_STANDIN = '  - host: wanb-mock:8000\n'


def gateway_config(sandbox: bool, mutation: str | None, pool: bool = False) -> str:
    text = CONFIG.read_text(encoding='utf-8')
    changes = [] if pool else list(RIG_VALUES)
    if not sandbox:
        changes.append((UPSTREAM, POOL_STANDIN if pool else STANDIN, 4))
    if mutation in MUTATIONS:
        changes.append(MUTATIONS[mutation])
    for old, new, times in changes:
        if text.count(old) != times:
            die(f'the configuration changed: {old.strip()[:60]!r} occurs {text.count(old)} times, expected {times}')
        text = text.replace(old, new)
    return text


def start_authz(binary: str, extra_env: dict | None = None):
    argv = [str(RUN / binary), '--listen', f"127.0.0.1:{gk.PORTS['authz']}",
            '--tls-cert', str(gk.TLS / 'gatekeeper.crt'), '--tls-key', str(gk.TLS / 'gatekeeper.key'), '--client-ca', str(gk.TLS / 'ca.crt'),
            '--policy', str(RUN / 'wanbexpress.policy.json'), '--developer-tokens', str(TOKENS_FILE),
            '--gateway-identity', pki.ID['gateway'],
            '--gatekeeper-url', gk.PDP_URL, '--gatekeeper-token-file', str(RUN / 'pdp-token'),
            '--gatekeeper-tls-cert', str(gk.TLS / 'gateway-authz.crt'), '--gatekeeper-tls-key', str(gk.TLS / 'gateway-authz.key'),
            '--gatekeeper-tls-ca', str(gk.TLS / 'ca.crt'), '--gatekeeper-name', gk.PDP_NAME]
    if USE_REVOCATIONS[0]:
        argv += ['--revocations', str(REVOCATIONS), '--revoker-identity', pki.ID['revoker']]
    gk.start('gateway-authz', argv, gk.PORTS['authz'], env={**os.environ, **(extra_env or {})})


def clean_proxy_env() -> tuple[dict, list]:
    env = {k: v for k, v in os.environ.items() if 'proxy' not in k.lower()}
    return env, sorted(k for k in os.environ if 'proxy' in k.lower())


# ---- what the gateway does, as the caller sees it -------------------------------------------------------------------------
CALLS: list[dict] = []          # every call to the gateway: what it was, the status and the time it took
PEERS: set = set()              # non-loopback addresses the gateway process held a connection to, sampled after each call
STATE = {'label': ''}


def gateway_peers() -> set:
    entry = next((p for p in gk.PROCS if p[0] == 'gateway'), None)
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
    for name in ('tcp', 'tcp6'):
        try:
            texts[name] = Path(f'/proc/net/{name}').read_text()
        except OSError:
            pass
    return peers_from_tables(texts, inodes)


def peers_from_tables(texts: dict, inodes: set | None = None) -> set:
    """Non-loopback addresses (address:port) of established TCP connections in /proc/net/tcp and tcp6 texts; only the sockets
    with these inodes when given (the pool reads the whole namespace of the gateway's network)."""
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


def req(method: str, path: str, token: str | None = None, body=None, headers=(), sample_peers: bool = False) -> dict:
    """One request to the gateway's listener, with the headers written exactly as given (a header may be given twice)."""
    pairs = [('Host', HOST)] + ([('Authorization', 'Bearer ' + token)] if token else []) + list(headers)
    started = time.perf_counter()
    answer = {'status': None, 'json': None, 'headers': [], 'ms': 0.0}
    try:
        conn = http.client.HTTPConnection('127.0.0.1', HOOKS['gateway_port'], timeout=30)
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        for name, value in pairs:
            conn.putheader(name, value)
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            conn.putheader('Content-Type', 'application/json')
            conn.putheader('Content-Length', str(len(data)))
        conn.endheaders(data)
        response = conn.getresponse()
        answer.update(status=response.status, headers=[(k.lower(), v) for k, v in response.getheaders()], received_at=time.time())
        raw = response.read()
        try:
            answer['json'] = json.loads(raw)
        except ValueError:
            answer['json'] = None
        if sample_peers:
            PEERS.update((HOOKS['peers'] or gateway_peers)())
        conn.close()
    except (OSError, http.client.HTTPException) as e:      # a connection cut off, or an answer that ends before its Content-Length
        answer['error'] = type(e).__name__
    answer['ms'] = round((time.perf_counter() - started) * 1000, 1)
    shown = re.sub(r'/parcels/[^/?]+', '/parcels/{processCode}', path.split('?')[0]) if len(path) < 80 else '(long path)'
    CALLS.append({'case': STATE['label'], 'call': f'{method} {shown}', 'status': answer['status'], 'ms': answer['ms']})
    return answer


def data(answer: dict):
    value = answer['json']
    return value if isinstance(value, dict) else {}


# ---- the stand-in's records ----------------------------------------------------------------------------------------------
def standin_hits() -> list:
    status, body = gk.call('GET', f"http://127.0.0.1:{HOOKS['mock_port']}/admin/hits", headers={'X-Poc-Admin': MOCK_SECRET})
    return body['hits'] if status == 200 else die('cannot read the stand-in\'s records')


def standin_reset():
    gk.call('POST', f"http://127.0.0.1:{HOOKS['mock_port']}/admin/reset", headers={'X-Poc-Admin': MOCK_SECRET}, form={})


def standin_fault(kind: str, seconds: float = 0):
    """The stand-in's fault for the next create only: 'slow' (hold the answer back) or 'cut' (cut it off half way)."""
    gk.call('POST', f"http://127.0.0.1:{HOOKS['mock_port']}/admin/fault?kind={kind}&seconds={seconds}", headers={'X-Poc-Admin': MOCK_SECRET}, form={})


def standin_parcels() -> list:
    status, body = gk.call('GET', f"http://127.0.0.1:{HOOKS['mock_port']}/admin/parcels", headers={'X-Poc-Admin': MOCK_SECRET})
    return body['parcels'] if status == 200 else die('cannot read the stand-in\'s parcels')


CONTROL_BINARY = RUN / 'gateway-control'
CLOCK: dict = {}          # the carrier's Date header of one answer and how far it is from this machine's clock


def control(*args: str) -> dict:
    """gateway-control, the product's own command, against this run's gateway-authz, under the revoker's certificate.
    -> {'code', 'json'}; json is None unless standard output is exactly one line of JSON. What it prints is not kept."""
    argv = [str(CONTROL_BINARY), *args, '--authz', f"127.0.0.1:{gk.PORTS['authz']}", '--authz-name', pki.GATEKEEPER_NAME,
            '--tls-cert', str(gk.TLS / 'revoker.crt'), '--tls-key', str(gk.TLS / 'revoker.key'), '--tls-ca', str(gk.TLS / 'ca.crt'), '--timeout', '5s']
    done = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=60)
    parsed = None
    if done.stdout.count('\n') == 1:
        try:
            parsed = json.loads(done.stdout)
        except ValueError:
            pass
    return {'code': done.returncode, 'json': parsed if isinstance(parsed, dict) else None, 'said': done.stderr.strip().splitlines()[-1][:160] if done.stderr.strip() else ''}


def outcome(result: dict, name: str, **fields) -> bool:
    j = result['json'] or {}
    return result['code'] == 0 and j.get('outcome') == name and all(j.get(k) == v for k, v in fields.items())


def header_values(hit: dict, name: str) -> list:
    return [v for k, v in hit['headers'] if k.lower() == name]


def parcel_body(reference: str) -> dict:
    """The example request of Create-Parcel in the carrier's documentation, with our ReferenceId. No AutoConfirm."""
    return {
        'ReferenceId': reference, 'SellingPlatformOrder': None,
        'ShippingAddress': {'Company': 'Company', 'Street1': 'Street1', 'Street2': 'Street1', 'Street3': None, 'City': 'City', 'Province': '',
                            'Country': '', 'CountryCode': 'GB', 'Postcode': 'NW1 6XE', 'Contacter': 'Jon Snow', 'Tel': '134567890', 'Email': '', 'TaxId': ''},
        'WeightInKg': 1.2,
        'ItemDetails': [{'GoodsId': 'GoodsId', 'GoodsTitle': 'GoodsTitle', 'DeclaredNameEn': 'Test', 'DeclaredNameCn': '品名测试',
                         'DeclaredValue': {'Code': 'USD', 'Value': 5.0}, 'ExportDeclaredValue': {'Code': 'USD', 'Value': 10.0},
                         'WeightInKg': 0.6, 'Quantity': 2, 'HSCode': '', 'CaseCode': '',
                         'SalesUrl': 'http://www.amazon.co.uk/gp/product/B00FEDIPQ4', 'IsSensitive': False, 'Brand': '', 'Model': '',
                         'MaterialCn': '', 'MaterialEn': '', 'UsageCn': '', 'UsageEn': '', 'Manufacturer': None, 'ASIN': '',
                         'CertifierId': '', 'ProductId': '', 'VersionId': ''}],
        'TotalValue': {'Code': 'USD', 'Value': 10.0}, 'TotalVolume': {'Length': 1.0, 'Width': 1.0, 'Height': 1.0, 'Unit': 'CM'},
        'WithBatteryType': 'NOBattery', 'Notes': 'Test', 'BatchNo': '', 'WarehouseCode': 'SZ', 'ShippingMethod': '3HPA', 'ItemType': 'SPX',
        'TradeType': 'B2C', 'TrackingNumber': '', 'ImportLabelUrl': '', 'IsMPS': False, 'MPSType': None, 'Cases': [],
        'AllowRemoteArea': True, 'AutoConfirm': False, 'ShipperInfo': None,
        'ProductionOrSalesCompany': {'Name': 'PDD', 'USCC': '91310106575864243X'}}


def new_reference() -> str:
    return f"IDPGW-{datetime.datetime.now(datetime.timezone.utc):%Y%m%d}-{secrets.token_hex(6)}"


# ---- the cases ---------------------------------------------------------------------------------------------------------------
# What differs when the gateway runs in the pool (pool.py): where the caller's requests go, where the stand-in's records are read,
# where gateway-authz's decisions are read, what WB-09 does, how the gateway's connections are sampled, which logs are scanned.
HOOKS = {'gateway_port': gk.PORTS['gateway'], 'mock_port': gk.PORTS['provider'], 'decisions': gk.decisions, 'skip_wb09': None,
         'peers': None, 'logs': None, 'second_authorization_reaches_the_gateway': True, 'skip_extra': None}
CREATED: dict[str, str] = {}      # process code -> 'created' | 'deleted' : parcels this run made at the carrier
MOCK_SECRET = ''
TOKENS_FILE = RUN / 'wanbexpress.developer-tokens.json'


def run_cases(r: Results, state: dict, made: dict, sandbox: bool):
    accounts = made['accounts']          # 'account-blue' -> (AccountNo, token)
    blue, green, ungranted = (state[k]['client'] for k in ('blue', 'green', 'ungranted'))
    tok = {'blue': gk.token_for(blue), 'green': gk.token_for(green), 'ungranted': gk.token_for(ungranted),
           'blue-other-aud': gk.token_for(blue, gk.OTHER_AUDIENCE)}
    if not all(tok.values()):
        die('no token from the local Hydra')
    made['tokens'] = list(tok.values())

    def fresh() -> int:
        if not sandbox:
            standin_reset()
        return len(HOOKS['decisions']())

    def reason_since(mark: int):
        new = HOOKS['decisions']()[mark:]
        return new[-1]['reason'] if new else None

    def asked_since(mark: int) -> int:
        return len(HOOKS['decisions']()) - mark

    def nothing_at_the_carrier(what: str):
        if sandbox:
            r.skip(what, 'cannot be seen at the real sandbox')
        else:
            r.check(what, len(standin_hits()) == 0)

    def delete_parcel(code: str) -> dict:
        answer = req('DELETE', f'{BASE}/parcels/{code}', tok['blue'], sample_peers=sandbox)
        if data(answer).get('Succeeded') is True:
            CREATED[code] = 'deleted'
        return answer

    # Wait until the gateway has fetched the JWKS: a path of the wrong shape is answered 401 until then and 403 after, and it never goes to
    # the carrier (the real sandbox is not asked while we wait).
    STATE['label'] = 'ready'
    end = time.time() + 20
    while time.time() < end and req('GET', f'{BASE}/parcels', tok['blue'])['status'] == 401:
        time.sleep(0.5)
    fresh()

    # WB-01
    STATE['label'] = 'WB-01'
    r.case('WB-01', 'whoami: the blue tenant\'s real Gatekeeper token, through the gateway, answers with that account')
    mark = fresh()
    answer = req('GET', f'{BASE}/whoami', tok['blue'], sample_peers=True)
    date = dict(answer['headers']).get('date')
    if date and answer.get('received_at'):
        try:
            CLOCK.update(carrier_response_date=date, offset_seconds=round(email.utils.parsedate_to_datetime(date).timestamp() - answer['received_at'], 1),
                         resolution_seconds=1, taken_from='the answer to the first whoami (WB-01), as it reached the caller')
        except (TypeError, ValueError):
            pass
    r.check('status 200', answer['status'] == 200)
    r.check('Succeeded is true', data(answer).get('Succeeded') is True)
    r.check('Data is the account number of the blue tenant\'s account (value not recorded)', data(answer).get('Data') == accounts[BLUE_ACCOUNT][0])
    last = HOOKS['decisions']()[-1] if len(HOOKS['decisions']()) > mark else {}
    r.check('gateway-authz decided ACTIVE_ACCOUNT_GRANT for whoami.get', last.get('reason') == 'ACTIVE_ACCOUNT_GRANT' and last.get('operation_id') == 'whoami.get')
    if sandbox:
        r.skip('no Set-Cookie from the carrier reaches the caller', 'the real sandbox sets none to be removed; the stand-in does')
    else:
        r.check('no Set-Cookie from the carrier reaches the caller (the stand-in sets one)', 'set-cookie' not in dict(answer['headers']))

    if sandbox and not (answer['status'] == 200 and data(answer).get('Succeeded') is True):
        r.note('stopped after WB-01', 'the sandbox did not accept whoami with this account; nothing more is sent to it (only the cases that never reach it follow)')
        r.note('whoami answered', {'status': answer['status'], 'Error.Code': (data(answer).get('Error') or {}).get('Code') if isinstance(data(answer).get('Error'), dict) else None})
        return

    # WB-02
    STATE['label'] = 'WB-02'
    r.case('WB-02', 'create, get by process code, delete: one whole chain')
    reference = new_reference()
    created = req('POST', f'{BASE}/parcels', tok['blue'], parcel_body(reference), sample_peers=sandbox)
    body = data(created)
    code = (body.get('Data') or {}).get('ProcessCode') if isinstance(body.get('Data'), dict) else None
    if body.get('Succeeded') is not True:
        error = body.get('Error') or {}
        r.note('create refused by the carrier: Code', error.get('Code') if isinstance(error, dict) else None)
        r.note('create refused by the carrier: Message', error.get('Message') if isinstance(error, dict) else None)
    if code:
        CREATED[code] = 'created'      # whatever the checks say, a ProcessCode is a parcel to delete
    r.check('create: status 200 and Succeeded true', created['status'] == 200 and body.get('Succeeded') is True)
    r.check('create: the answer carries a ProcessCode and our ReferenceId', bool(code) and body.get('Data', {}).get('ReferenceId') == reference)
    r.check('create: Status is Original (AutoConfirm was not set)', (body.get('Data') or {}).get('Status') == 'Original')
    if code:
        CREATED[code] = 'created'
        got = req('GET', f'{BASE}/parcels/{code}', tok['blue'], sample_peers=sandbox)
        r.check('get: status 200, Succeeded true', got['status'] == 200 and data(got).get('Succeeded') is True)
        r.check('get: ReferenceId and ProcessCode are the ones created', (data(got).get('Data') or {}).get('ReferenceId') == reference
                and (data(got).get('Data') or {}).get('ProcessCode') == code)
        deleted = delete_parcel(code)
        r.check('delete: status 200, Succeeded true', deleted['status'] == 200 and data(deleted).get('Succeeded') is True)
        after = req('GET', f'{BASE}/parcels/{code}', tok['blue'], sample_peers=sandbox)
        r.check('get after delete: HTTP 404, as the carrier answered it, passed on by the gateway unchanged', after['status'] == 404)

    # WB-03
    STATE['label'] = 'WB-03'
    r.case('WB-03', 'the same ReferenceId again: identical body gets the existing parcel back; a changed body gets 0x100005 (HTTP 200, Succeeded false), unchanged to the caller')
    reference = new_reference()
    body_one = parcel_body(reference)
    first = req('POST', f'{BASE}/parcels', tok['blue'], body_one, sample_peers=sandbox)
    first_code = (data(first).get('Data') or {}).get('ProcessCode') if isinstance(data(first).get('Data'), dict) else None
    if first_code:
        CREATED[first_code] = 'created'
    r.check('the first create succeeded', data(first).get('Succeeded') is True and bool(first_code))

    def created_code(answer: dict):
        d = data(answer).get('Data')
        code = d.get('ProcessCode') if isinstance(d, dict) else None
        if code and code != first_code:
            CREATED[code] = 'created'        # a parcel that was not expected: still one to delete (the checks fail)
        return code
    same = req('POST', f'{BASE}/parcels', tok['blue'], parcel_body(reference), sample_peers=sandbox)
    same_code = created_code(same)
    r.check('identical body: HTTP 200, Succeeded true', same['status'] == 200 and data(same).get('Succeeded') is True)
    r.check('identical body: the ProcessCode is the first one (nothing new was made)', bool(first_code) and same_code == first_code)
    changed_body = parcel_body(reference)
    changed_body['WeightInKg'] = 1.3
    changed = req('POST', f'{BASE}/parcels', tok['blue'], changed_body, sample_peers=sandbox)
    created_code(changed)
    error = data(changed).get('Error')
    r.check('changed body: HTTP status 200', changed['status'] == 200)
    r.check('changed body: Succeeded false', data(changed).get('Succeeded') is False)
    r.check('changed body: Error.Code is 0x100005', isinstance(error, dict) and error.get('Code') == '0x100005')
    if not (isinstance(error, dict) and error.get('Code') == '0x100005'):
        r.note('the changed-body answer: Error', error)
    if first_code:
        r.check('the parcel made for this case is deleted', data(delete_parcel(first_code)).get('Succeeded') is True)

    # WB-04
    STATE['label'] = 'WB-04'
    r.case('WB-04', 'what the carrier receives (stand-in only): one Authorization of the documented form, a new nonce each time, Accept written by the gateway, nothing of the caller')
    if sandbox:
        r.skip('every check of this case', 'only the stand-in can say what it received')
    else:
        standin_reset()
        planted = 'Hc-OweDeveloper PLANTED-BY-CALLER;planted-by-caller;' + '0' * 32
        sent = [('Accept', 'text/html'), ('X-Provider-Account', BLUE_ACCOUNT), ('Cookie', 'session=caller-session'), ('X-Forwarded-For', '10.1.2.3'),
                ('X-Forwarded-Host', 'internal.idp.test'), ('X-Forwarded-Proto', 'https'), ('Forwarded', 'for=10.1.2.3;host=internal.idp.test'),
                ('X-Evil-Probe', 'caller')]
        if HOOKS['second_authorization_reaches_the_gateway']:
            sent.append(('Authorization', planted))
        answers = [req('GET', f'{BASE}/whoami', tok['blue'], headers=sent) for _ in range(3)]
        hits = standin_hits()
        r.check('all three answered 200 and the carrier received three requests', [a['status'] for a in answers] == [200] * 3 and len(hits) == 3)
        account, token = accounts[BLUE_ACCOUNT]
        shape = re.compile(r'Hc-OweDeveloper ' + re.escape(account) + ';' + re.escape(token) + ';([A-Za-z0-9_-]+)')
        seen = [header_values(h, 'authorization') for h in hits]
        r.check('exactly one Authorization header on each', all(len(v) == 1 for v in seen))
        matches = [shape.fullmatch(v[0]) for v in seen if len(v) == 1]
        r.check('it is of the documented form (scheme, account, token, nonce) with the blue account\'s own account and token', len(matches) == 3 and all(matches))
        nonces = [m.group(1) for m in matches if m]
        r.check('the nonce is different in each request', len(set(nonces)) == 3)
        r.check('Accept is exactly application/json, once, though the caller sent text/html', all(header_values(h, 'accept') == ['application/json'] for h in hits))
        r.check('Host is the carrier\'s name', all(header_values(h, 'host') == [SANDBOX_HOST] for h in hits))
        names = {k.lower() for h in hits for k, _ in h['headers']}
        r.check('x-provider-account, cookie and the forwarding headers did not arrive', not names & {'x-provider-account', 'cookie', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto', 'forwarded'})
        r.check('a header the caller invented (x-evil-probe) did not arrive; nor any x-idp-* header', 'x-evil-probe' not in names and not [n for n in names if n.startswith('x-idp-')])
        flat = json.dumps(hits)
        r.check('the caller\'s Gatekeeper token and the Authorization the caller planted are nowhere in what arrived', tok['blue'] not in flat and 'PLANTED-BY-CALLER' not in flat)
        r.note('header names the carrier saw', sorted(names))
        if not HOOKS['second_authorization_reaches_the_gateway']:
            # Behind front (nginx) a request with two Authorization headers does not get as far as the gateway.
            standin_reset()
            twice = req('GET', f'{BASE}/whoami', tok['blue'], headers=[('Authorization', planted)])
            r.check(f'a second Authorization header from the caller is refused by front ({twice["status"]}) and the carrier receives nothing',
                    twice['status'] is not None and twice['status'] >= 400 and len(standin_hits()) == 0)
        r.check('no Set-Cookie from the carrier reaches the caller', all('set-cookie' not in dict(a['headers']) for a in answers))

    # WB-05
    STATE['label'] = 'WB-05'
    r.case('WB-05', 'no token, a token for another audience, a forged signature: refused with 401, the carrier gets nothing, gateway-authz is not asked')
    for label, token in (('no token', None), ('another audience', tok['blue-other-aud']), ('forged signature', gk.forged(tok['blue']))):
        mark = fresh()
        answer = req('GET', f'{BASE}/whoami', token)
        r.check(f'{label}: 401', answer['status'] == 401)
        r.check(f'{label}: gateway-authz was not asked', asked_since(mark) == 0)
        nothing_at_the_carrier(f'{label}: the carrier received nothing')

    # WB-06
    STATE['label'] = 'WB-06'
    r.case('WB-06', 'tenants: each gets its own account; blue asking for green\'s account is refused' + ('' if not sandbox else ' (sandbox: green has no account)'))
    if sandbox:
        mark = fresh()
        answer = req('GET', f'{BASE}/whoami', tok['green'])
        r.check('green (no account in this run): 403', answer['status'] == 403)
        r.note('green: gateway-authz\'s reason', reason_since(mark))
        r.skip('green gets the green account\'s Data; the two accounts do not mix', 'there is one sandbox account')
    else:
        mark = fresh()
        answer = req('GET', f'{BASE}/whoami', tok['green'])
        r.check('green: 200 and Data is the green account number', answer['status'] == 200 and data(answer).get('Data') == accounts[GREEN_ACCOUNT][0])
        r.check('green: the carrier saw the green account\'s credential and no other', [header_values(h, 'authorization')[0].split(';')[0] for h in standin_hits()]
                == ['Hc-OweDeveloper ' + accounts[GREEN_ACCOUNT][0]])
    mark = fresh()
    answer = req('GET', f'{BASE}/whoami', tok['blue'], headers=[('X-Provider-Account', GREEN_ACCOUNT)])
    r.check('blue asking for the green account: 403', answer['status'] == 403)
    r.check('the reason is ACCOUNT_NOT_GRANTED', reason_since(mark) == 'ACCOUNT_NOT_GRANTED')
    nothing_at_the_carrier('blue asking for the green account: the carrier received nothing')

    # WB-07
    STATE['label'] = 'WB-07'
    r.case('WB-07', 'a client the register knows but Gatekeeper has no grant for: 403, the carrier gets nothing')
    mark = fresh()
    answer = req('GET', f'{BASE}/whoami', tok['ungranted'])
    r.check('403', answer['status'] == 403)
    r.check('the reason is ACCOUNT_NOT_GRANTED', reason_since(mark) == 'ACCOUNT_NOT_GRANTED')
    nothing_at_the_carrier('the carrier received nothing')

    # WB-08
    STATE['label'] = 'WB-08'
    r.case('WB-08', 'a method or a path that is not registered does not get to the carrier')
    # A method with no route at all on the path: the gateway answers 404 itself and gateway-authz is not asked.
    other_method = [('PUT', f'{BASE}/parcels/ABC123'), ('PATCH', f'{BASE}/parcels/ABC123'), ('PUT', f'{BASE}/parcels'),
                    ('POST', f'{BASE}/whoami'), ('DELETE', f'{BASE}/whoami')]
    for method, path in other_method:
        mark = fresh()
        answer = req(method, path, tok['blue'], body={'x': 1} if method in ('POST', 'PUT', 'PATCH') else None)
        r.check(f'{method} {path.removeprefix(BASE)}: 404 from the gateway, gateway-authz not asked', answer['status'] == 404 and asked_since(mark) == 0)
        nothing_at_the_carrier(f'{method} {path.removeprefix(BASE)}: the carrier received nothing')
    # A registered method on a path of the wrong shape: the route is found, and the gateway's own rule refuses it.
    paths = [('GET', f'{BASE}/bags'), ('GET', f'{BASE}/parcels'), ('GET', f'{BASE}/parcels?referenceId=IDPGW-1'), ('GET', f'{BASE}/parcels/'),
             ('GET', f'{BASE}/parcels/ABC/def'), ('GET', f'{BASE}/parcels/../whoami'), ('GET', f'{BASE}/parcels/%2e%2e/whoami'),
             ('GET', f'{BASE}/parcels/a%2fb'), ('DELETE', f'{BASE}/parcels/a%2Fb'), ('GET', f'{BASE}/parcels/ABC;x=1'), ('GET', f'{BASE}/parcels/%00'),
             ('GET', f'{BASE}/whoami/extra'), ('GET', f'{BASE}/parcels/%252e%252e'), ('GET', '/api/whoami'), ('GET', '/providers/mockcarrier/v1/tracking/T-1'),
             ('GET', f'{BASE}//whoami'), ('POST', f'{BASE}/parcels/'), ('POST', f'{BASE}/parcels/ABC123'), ('DELETE', f'{BASE}/parcels')]
    for method, path in paths:
        mark = fresh()
        answer = req(method, path, tok['blue'], body={'x': 1} if method == 'POST' else None)
        r.check(f'{method} {path.removeprefix(BASE)}: refused ({answer["status"]})', answer['status'] is not None and answer['status'] >= 400)
        nothing_at_the_carrier(f'{method} {path.removeprefix(BASE)}: the carrier received nothing')
    if not sandbox:
        # What is allowed and carries a query string: where does the query go? Recorded, not judged (the config does not forbid it).
        standin_reset()
        req('GET', f'{BASE}/parcels/ABC123?note=q', tok['blue'])
        hits = standin_hits()
        r.note('GET /parcels/{processCode}?note=q reaches the carrier as', [h['raw_target'] for h in hits])

    def skipped_here(cid: str) -> bool:
        reason = (HOOKS['skip_extra'] or {}).get(cid)
        if reason:
            r.skip('every check of this case', reason)
        return bool(reason)

    def blue_whoami_at_the_carrier(label_token: str = 'blue'):
        """One whoami as blue on the stand-in -> (the answer, the token the carrier received as a (number, token) pair or None)."""
        standin_reset()
        answer = req('GET', f'{BASE}/whoami', tok[label_token])
        hits = standin_hits()
        given = header_values(hits[0], 'authorization') if len(hits) == 1 else []
        match = re.fullmatch(r'Hc-OweDeveloper ([^; ]+);([^; ]+);[A-Za-z0-9_-]+', given[0]) if len(given) == 1 else None
        return answer, (match.group(1), match.group(2)) if match else None

    def authz_process():
        entry = next((p for p in gk.PROCS if p[0] == 'gateway-authz'), None)
        return (entry[1].pid, entry[1].poll() is None) if entry else (None, False)

    def extra_cases():
        # WB-12
        STATE['label'] = 'WB-12'
        r.case('WB-12', 'revocation through gateway-control: blue is refused on its next request, gateway-authz is not replaced, green is not touched; restored, blue is served again')
        if not skipped_here('WB-12'):
            pid = authz_process()
            if sandbox:
                r.skip('before: blue is served (one whoami to the carrier)', 'the sandbox is not asked for more than it has to be: the confirming whoami comes after the restore')
            else:
                standin_reset()
                r.check('before: blue is served (whoami 200)', req('GET', f'{BASE}/whoami', tok['blue'])['status'] == 200)
            revoked = {'code': None, 'json': None, 'said': ''}
            try:
                revoked = control('revoke', '--account', BLUE_ACCOUNT, '--reason', 'wanbexpress rig: WB-12')
                r.note('gateway-control revoke', {'exit': revoked['code'], 'outcome': (revoked['json'] or {}).get('outcome'), 'said': revoked['said']})
                r.check('gateway-control revoke: exit 0, REVOKED, the account is revoked and it changed',
                        outcome(revoked, 'REVOKED', command='revoke', account=BLUE_ACCOUNT, revoked=True, changed=True))
                if not sandbox:
                    standin_reset()
                mark = len(HOOKS['decisions']())
                answer = req('GET', f'{BASE}/whoami', tok['blue'])
                r.note('blue\'s next request', {'status': answer['status'], 'reason_code': data(answer).get('reason_code'), 'gateway-authz decided': reason_since(mark)})
                r.check('blue\'s next request: 403', answer['status'] == 403)
                r.check('the reason is ACCOUNT_REVOKED, in the answer and in gateway-authz\'s decision', data(answer).get('reason_code') == 'ACCOUNT_REVOKED' and reason_since(mark) == 'ACCOUNT_REVOKED')
                nothing_at_the_carrier('blue\'s request after the revocation: the carrier received nothing')
                if sandbox:
                    r.skip('green is not affected by blue\'s revocation', 'there is one sandbox account')
                else:
                    green_answer = req('GET', f'{BASE}/whoami', tok['green'])
                    r.check('green is not affected: whoami 200 and Data is the green account number',
                            green_answer['status'] == 200 and data(green_answer).get('Data') == accounts[GREEN_ACCOUNT][0])
                listed = control('revocations')
                rows = (listed['json'] or {}).get('revoked_accounts') or []
                r.check('gateway-control revocations: LISTED, blue\'s account is in the table and no other',
                        outcome(listed, 'LISTED') and [x.get('account_id') for x in rows] == [BLUE_ACCOUNT])
            finally:
                lifted = control('restore', '--account', BLUE_ACCOUNT) if revoked['json'] else {'code': None, 'json': None, 'said': ''}
            r.check('gateway-control restore: exit 0, LIFTED, the account is not revoked and it changed',
                    outcome(lifted, 'LIFTED', command='restore', account=BLUE_ACCOUNT, revoked=False, changed=True))
            if not sandbox:
                standin_reset()
            again = req('GET', f'{BASE}/whoami', tok['blue'], sample_peers=sandbox)
            r.check('after the restore blue is served again: whoami 200, Succeeded true', again['status'] == 200 and data(again).get('Succeeded') is True)
            if not sandbox:
                r.check('...and the carrier received that one request', len(standin_hits()) == 1)
            r.check('gateway-authz is the same process throughout (same pid, still running)', authz_process() == pid and pid[0] is not None)

        # WB-13
        STATE['label'] = 'WB-13'
        r.case('WB-13', 'credential rotation (stand-in only): the credentials file is replaced the way gateway-authz asks; the next request leaves with the new token; a file that does not load changes nothing')
        if sandbox:
            r.skip('every check of this case', 'the sandbox has one valid token; sending a real carrier an invalid credential is not a normal request')
        elif not skipped_here('WB-13'):
            pid = authz_process()
            account, old = accounts[BLUE_ACCOUNT]
            new = made['rotated_token']

            def replace_file(blue_token: str):
                """The way gateway-authz asks for: a new file next to the old one, then renamed over it."""
                table = {f'{BINDING}/{a}': {'account': n, 'token': blue_token if a == BLUE_ACCOUNT else t} for a, (n, t) in accounts.items()}
                staged = TOKENS_FILE.with_name(TOKENS_FILE.name + '.next')
                staged.write_text(json.dumps(table), encoding='utf-8')
                os.chmod(staged, 0o600)
                os.replace(staged, TOKENS_FILE)
            try:
                answer, seen = blue_whoami_at_the_carrier()
                r.check('before: the carrier receives the old token', answer['status'] == 200 and seen == (account, old))
                replace_file(new)
                answer, seen = blue_whoami_at_the_carrier()
                r.check('the file is replaced: the very next request leaves with the new token', answer['status'] == 200 and seen == (account, new))
                green_answer, green_seen = blue_whoami_at_the_carrier('green')
                r.check('green, whose entry did not change, is served as before', green_answer['status'] == 200 and green_seen == accounts[GREEN_ACCOUNT])
                replace_file('not a token; it has spaces and a semicolon')
                answer, seen = blue_whoami_at_the_carrier()
                r.check('replaced by a file that does not load: the next request leaves with the last token that loaded (as P1-DT-04 saw it)',
                        answer['status'] == 200 and seen == (account, new))
            finally:
                replace_file(old)
            answer, seen = blue_whoami_at_the_carrier()
            r.check('the first file is put back: the next request leaves with the first token again', answer['status'] == 200 and seen == (account, old))
            r.check('gateway-authz is the same process throughout (same pid, still running)', authz_process() == pid and pid[0] is not None)

        # WB-14
        STATE['label'] = 'WB-14'
        r.case('WB-14', 'a create whose result is unknown (stand-in only): after a timeout and after an answer cut off half way the carrier received one POST, none is replayed; the same ReferenceId and body again gives the parcel that exists')
        if sandbox:
            r.skip('every check of this case', 'the sandbox cannot be made to be slow or to cut an answer; faults are the stand-in\'s')
        elif not skipped_here('WB-14'):
            def create_posts() -> list:
                return [h for h in standin_hits() if h['method'] == 'POST' and h['raw_target'] == '/api/parcels']
            for label, kind, seconds in (('timeout', 'slow', 11), ('cut-off answer', 'cut', 0)):
                reference = new_reference()
                standin_reset()
                standin_fault(kind, seconds)
                started = time.time()
                answer = req('POST', f'{BASE}/parcels', tok['blue'], parcel_body(reference))
                took = time.time() - started
                if kind == 'slow':
                    time.sleep(max(0.0, seconds + 1.5 - took))      # the stand-in has answered by then, and any replay has had its time
                else:
                    time.sleep(1.5)
                r.note(f'{label}: what the caller got', {'status': answer['status'], 'error': answer.get('error'), 'seconds': round(took, 1),
                                                        'reason': (data(answer).get('Error') or {}).get('Code') if isinstance(data(answer).get('Error'), dict) else None})
                from_gateway = 'x-mock-provider' not in dict(answer['headers'])
                if kind == 'slow':
                    r.check(f'{label}: the caller gets the gateway\'s own timeout answer (5xx, not the carrier\'s) after about the route\'s 9 seconds',
                            answer['status'] is not None and 500 <= answer['status'] <= 599 and from_gateway and 8.5 <= took <= 9.8)
                else:
                    # What the gateway does with an answer that is cut off after its headers went out is not known beforehand: the status is recorded
                    # in the note. The check is that the caller does not get a whole answer: a 5xx, or a body that ends before its Content-Length.
                    r.check(f'{label}: the caller does not get a complete answer (a 5xx, or a body that ends before its Content-Length: the status is in the note)',
                            answer['status'] is not None and (500 <= answer['status'] <= 599 or answer.get('error') == 'IncompleteRead') and data(answer).get('Succeeded') is not True)
                r.check(f'{label}: the carrier received exactly one POST (no replay)', len(create_posts()) == 1)
                exists = [p for p in standin_parcels() if p['reference_id'] == reference]
                r.check(f'{label}: the carrier did make the parcel (that is why the result is unknown)', len(exists) == 1)
                for p in exists:
                    CREATED[p['process_code']] = 'created'
                repeat = req('POST', f'{BASE}/parcels', tok['blue'], parcel_body(reference))
                code = (data(repeat).get('Data') or {}).get('ProcessCode') if isinstance(data(repeat).get('Data'), dict) else None
                if code:
                    CREATED[code] = 'created'
                r.check(f'{label}: the same ReferenceId and body again: HTTP 200, Succeeded true, the parcel that exists (nothing new)',
                        repeat['status'] == 200 and data(repeat).get('Succeeded') is True and len(exists) == 1 and code == exists[0]['process_code'])
                r.check(f'{label}: the carrier now has one parcel for that ReferenceId and received two POSTs in all', len([p for p in standin_parcels() if p['reference_id'] == reference]) == 1
                        and len(create_posts()) == 2)
                for p in exists:
                    r.check(f'{label}: the parcel is deleted', data(delete_parcel(p['process_code'])).get('Succeeded') is True)

    # WB-09
    STATE['label'] = 'WB-09'
    r.case('WB-09', 'gateway-authz allows and releases no credential: the gateway itself refuses; a caller\'s own Authorization does not take its place')
    if HOOKS['skip_wb09']:
        r.skip('every check of this case', HOOKS['skip_wb09'])
        extra_cases()
        return
    stop_authz = lambda: gk.stop('gateway-authz')
    secret = secrets.token_urlsafe(24)
    stop_authz()
    start_authz('gateway-authz-acceptance', {'GATEWAY_AUTHZ_ACCEPTANCE_ADMIN_SECRET': secret, 'GATEWAY_AUTHZ_ACCEPTANCE_OPERATOR_IDENTITY': pki.ID['operator'],
                                             'GATEWAY_AUTHZ_ACCEPTANCE_SLOW_SECONDS': '1'})
    try:
        def operator(path: str) -> int | None:
            conn = pki.GatekeeperConnection(gk.PORTS['authz'], pki.client_context(gk.TLS, 'operator'), 5)
            try:
                conn.request('POST', path, body=b'', headers={'Host': pki.GATEKEEPER_NAME, 'X-Poc-Admin': secret})
                response = conn.getresponse()
                response.read()
                return response.status
            finally:
                conn.close()
        r.check('the PDP is set to allow without a credential', operator('/admin/mode?value=allow_without_credential') == 200)
        planted = 'Hc-OweDeveloper PLANTED-BY-CALLER;planted-by-caller;' + '0' * 32
        for label, headers, order_first in (('the caller sends nothing of its own', [], False), ('the caller\'s own Authorization after its token', [('Authorization', planted)], False)):
            mark = fresh()
            answer = req('GET', f'{BASE}/whoami', tok['blue'], headers=headers)
            r.check(f'{label}: the caller does not get a success ({answer["status"]})', answer['status'] is not None and answer['status'] >= 400)
            r.check(f'{label}: the PDP did allow it (so it is the gateway that refused)', reason_since(mark) == 'ACTIVE_ACCOUNT_GRANT')
            r.check(f'{label}: the answer is not the carrier\'s', 'x-mock-provider' not in dict(answer['headers']) and 'set-cookie' not in dict(answer['headers']))
            nothing_at_the_carrier(f'{label}: the carrier received nothing')
        mark = fresh()
        answer = req('GET', f'{BASE}/whoami', None, headers=[('Authorization', planted), ('Authorization', 'Bearer ' + tok['blue'])])
        r.check(f'the caller\'s own Authorization before its token: refused ({answer["status"]})', answer['status'] is not None and answer['status'] >= 400)
        nothing_at_the_carrier('the caller\'s own Authorization before its token: the carrier received nothing')
        r.check('the PDP is set back to normal', operator('/admin/mode?value=normal') == 200)
        if sandbox:
            r.skip('control: with a credential released, the same request goes through with the PDP\'s credential and not the caller\'s', 'WB-04 is stand-in only; not repeated at the sandbox')
        else:
            fresh()
            answer = req('GET', f'{BASE}/whoami', tok['blue'], headers=[('Authorization', planted)])
            hits = standin_hits()
            r.check('control: with a credential released, the same request is answered 200', answer['status'] == 200)
            r.check('control: the carrier got the PDP\'s credential and not the planted one',
                    len(hits) == 1 and header_values(hits[0], 'authorization')[0].startswith('Hc-OweDeveloper ' + accounts[BLUE_ACCOUNT][0] + ';')
                    and 'PLANTED' not in json.dumps(hits))
    finally:
        stop_authz()
        start_authz('gateway-authz')
    r.check('the product build of gateway-authz is back and allows again', req('GET', f'{BASE}/whoami', tok['blue'], sample_peers=sandbox)['status'] == 200)
    extra_cases()


def secret_list(made: dict, state: dict) -> list:
    """Every secret of this run: [(what it is, the value)]. The values are never written anywhere."""
    found = []
    for account, token in made['accounts'].values():
        found += [(f'token of {account}', token), (f'credential of {account}', f'{account};{token}')]
    if made.get('rotated_token'):
        found.append(('rotated token of the blue account', made['rotated_token']))
    found += [('PDP token', gk.ENV['GK_PDP_AUTH_TOKEN'])] + [(f'client secret of {k}', state[k]['client']['client_secret']) for k in state]
    return found + [(f'Gatekeeper token {i}', t) for i, t in enumerate(made.get('tokens', []))]


def scan(made: dict, state: dict, result_text: str, logs: dict | None = None) -> tuple[dict, list]:
    """Where could a secret be: the logs of the two processes, this run's own output, and the result file. -> {where: found?}, [what was looked for, no values]"""
    secrets_found = secret_list(made, state)
    texts = {**(logs or {'gateway log': (RUN / 'gateway.log').read_text(errors='replace'), 'gateway-authz log': (RUN / 'gateway-authz.log').read_text(errors='replace')}),
             'standard output': '\n'.join(OUTPUT), 'result file': result_text}
    outcome = {}
    for where, text in texts.items():
        outcome[where] = {'secret found': [what for what, value in secrets_found if value and value in text],
                          'Authorization value of the carrier\'s scheme found': bool(re.search(r'Hc-OweDeveloper [^;\s"\']+;', text))}
    return outcome, [what for what, _ in secrets_found]


# ---- the evidence files (--evidence), written by this suite and by pool.py --------------------------------------------------
NO_ROLES = ('Not recorded. The repository owner decided on 2026-11-19 (development plan 1.6) that this technical software has no operator and '
            'approver kept apart: this file records what was run, on which commits and images, and what was seen. It is a record of verification, '
            'not a gate decision.')
EVIDENCE_FIELDS = ('kind', 'upstream_kind', 'operator_and_approver', 'agentgateway', 'gatekeeper_commit', 'repository', 'registry_sha256',
                   'gateway_configuration_sha256', 'environment', 'started_at_utc', 'finished_at_utc', 'clock', 'dataset', 'upstream',
                   'gateway_proxy_variables', 'cases', 'summary')
SECRET_SHAPES = (re.compile(r'Hc-OweDeveloper [^;\s"\']+;'), re.compile(r'Bearer [A-Za-z0-9._~+/=-]{16,}'))


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_out(*argv: str, where: Path | None = None) -> str:
    return subprocess.run(['git', '-C', str(where or ROOT), *argv], capture_output=True, text=True).stdout.strip()


def evidence_document(kind: str, sandbox: bool, started_at: str, finished_at: str, reported: dict, results: 'Results', upstream: dict,
                      proxy_variables, image: str, binary: str | None = None) -> dict:
    """What the file says. No token, no Authorization value, no client secret, no account number: write_evidence looks again before it keeps the file."""
    checks = [k for c in results.cases for k in c['checks']]
    cases = [{'id': c['id'], 'title': c['title'], 'result': 'fail' if any(k['ok'] is False for k in c['checks']) else
              ('skipped' if c['checks'] and all(k['ok'] is None for k in c['checks']) else 'pass'),
              'checks': [{'check': k['check'], 'result': 'pass' if k['ok'] else ('fail' if k['ok'] is False else 'skipped'), **({'reason': k['skipped']} if k['ok'] is None else {})}
                         for k in c['checks']], 'notes': c['notes']} for c in results.cases]
    kept = [code for code, state in CREATED.items() if state == 'deleted']
    return {
        'kind': kind, 'upstream_kind': 'the carrier\'s sandbox' if sandbox else 'stand-in', 'operator_and_approver': NO_ROLES,
        'agentgateway': {'version': reported['version'], 'image': image, **({'local_binary_sha256': sha256_of(Path(binary))} if binary else {})},
        'gatekeeper_commit': git_out('rev-parse', '--short', 'HEAD', where=Path(os.environ.get('GK_SRC', str(Path.home() / '.local/src/idp-gatekeeper')))),
        'repository': {'commit': git_out('rev-parse', '--short', 'HEAD'),
                       'uncommitted_files': len([l for l in git_out('status', '--porcelain', '--', '.', ':!tests/integration/wanbexpress/evidence').splitlines() if l.strip()])},
        'registry_sha256': sha256_of(POLICY_EXAMPLE),
        'registry_note': 'the example register; each run fills its placeholders with that run\'s tenant and client ids, so the filled copy differs from run to run',
        'gateway_configuration_sha256': sha256_of(CONFIG),
        'environment': sorted({row['environment'] for row in json.loads(POLICY_EXAMPLE.read_text())['registered_operations']}),
        'started_at_utc': started_at, 'finished_at_utc': finished_at,
        'clock': CLOCK or {'carrier_response_date': None, 'note': 'no Date header on the answer to the first whoami'},
        'dataset': {'reference_prefix': f"IDPGW-{datetime.datetime.now(datetime.timezone.utc):%Y%m%d}-", 'data': 'the example request of the carrier\'s documentation' + ('' if sandbox else ', synthetic accounts'),
                    'parcels_created_and_deleted': sorted(kept), 'parcels_left_undeleted': sorted(c for c, s in CREATED.items() if s != 'deleted')},
        'upstream': upstream, 'gateway_proxy_variables': proxy_variables, 'cases': cases,
        'summary': {'cases': len(cases), 'cases_failed': sum(1 for c in cases if c['result'] == 'fail'), 'cases_skipped': sum(1 for c in cases if c['result'] == 'skipped'),
                    'checks': len(checks), 'checks_passed': sum(1 for k in checks if k['ok']), 'checks_failed': sum(1 for k in checks if k['ok'] is False),
                    'checks_skipped': sum(1 for k in checks if k['ok'] is None)},
    }


def write_evidence(name: str, document: dict, made: dict, state: dict) -> bool:
    """Write tests/integration/wanbexpress/evidence/<name>, then read it back and look for what must not be in it (a token, the carrier's
    Authorization, a client secret, a Gatekeeper token, an account number). Found: the file is deleted. -> True when the file is kept.
    An account number is looked for as a whole JSON string value (not in the field `environment`), not as a substring: it can be a short
    ordinary word that the file legitimately holds elsewhere (the environment name TEST); where it appears together with a token is caught by the shape check."""
    EVIDENCE.mkdir(exist_ok=True)
    path = EVIDENCE / name
    path.write_text(json.dumps(document, ensure_ascii=False, indent=1) + '\n', encoding='utf-8')
    text = path.read_text(encoding='utf-8')
    looked_for = secret_list(made, state)
    values = set()

    def strings(node):
        if isinstance(node, str):
            values.add(node)
        elif isinstance(node, dict):
            for v in node.values():
                strings(v)
        elif isinstance(node, list):
            for v in node:
                strings(v)
    strings({k: v for k, v in json.loads(text).items() if k != 'environment'})
    found = [what for what, value in looked_for if value and value in text] + [f'account number of {a} (a whole string value)' for a, (n, _t) in made['accounts'].items() if n in values] + [f'a value of shape {shape.pattern}' for shape in SECRET_SHAPES if shape.search(text)]
    if found:
        path.unlink()
        say(f'EVIDENCE NOT KEPT: the file held {found} (what it was, not the value); it was deleted')
        return False
    say(f'evidence written: {path.relative_to(ROOT)}')
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description='deploy/providers/wanbexpress on the Gatekeeper integration rig')
    parser.add_argument('--sandbox', action='store_true', help='upstream is the carrier\'s real sandbox (plain HTTP, port 80); needs --sandbox-credentials')
    parser.add_argument('--sandbox-credentials', help='with --sandbox: a file {"account": ..., "token": ...} (0600, outside the repository)')
    parser.add_argument('--mutate', choices=sorted(MUTATIONS) + list(OTHER_CONTROLS), help='deliberately break one thing (stand-in only)')
    parser.add_argument('--evidence', action='store_true', help='write tests/integration/wanbexpress/evidence/rig-{sandbox,standin}.json (only with this flag)')
    args = parser.parse_args()
    if args.evidence and args.mutate:
        die('--evidence is for a run of the real configuration, not for a control')
    if args.sandbox != bool(args.sandbox_credentials):
        die('--sandbox and --sandbox-credentials go together')
    if args.sandbox and args.mutate:
        die('--mutate is for the stand-in only')
    global TOKENS_FILE, MOCK_SECRET
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
    state = gk.seed()
    gk.sync_tuples(state)
    pki.issue(gk.TLS)
    gk.publish_pdp_tls()

    made: dict = {}
    if args.sandbox:
        account, token = read_sandbox_credentials(args.sandbox_credentials)
        TOKENS_FILE = wrapped_credentials(account, token)
        made['accounts'] = {BLUE_ACCOUNT: (account, token)}
    else:
        made['accounts'] = {a: ('WB' + secrets.token_hex(4).upper(), secrets.token_hex(20)) for a in (BLUE_ACCOUNT, GREEN_ACCOUNT)}
        made['rotated_token'] = secrets.token_hex(20)      # the stand-in accepts it for the blue account as well: WB-13 rotates to it
        TOKENS_FILE = write('wanbexpress.developer-tokens.json', json.dumps({f'{BINDING}/{a}': {'account': n, 'token': t} for a, (n, t) in made['accounts'].items()}))
    MOCK_SECRET = secrets.token_urlsafe(24)
    mock_accounts = {f'{n};{t}': n for n, t in made['accounts'].values()}
    if made.get('rotated_token'):
        mock_accounts[f"{made['accounts'][BLUE_ACCOUNT][0]};{made['rotated_token']}"] = made['accounts'][BLUE_ACCOUNT][0]
    write('wanbexpress.mock-state.json', json.dumps({'admin_secret': MOCK_SECRET, 'accounts': mock_accounts}))
    USE_REVOCATIONS[0] = args.mutate != 'no-revocations'
    write('wanbexpress.revocations.json', NOTHING_REVOKED)
    write('wanbexpress.policy.json', policy_for(state, args.sandbox))
    write('pdp-token', gk.ENV['GK_PDP_AUTH_TOKEN'] + '\n')
    config = gateway_config(args.sandbox, args.mutate)
    write('wanbexpress.agentgateway.yaml', config)
    build([], 'gateway-authz')
    build(['-tags', 'acceptance'], 'gateway-authz-acceptance')
    build([], 'gateway-control', './cmd/gateway-control')

    env, proxy_names = clean_proxy_env()
    env['SESSION_KEY'] = secrets.token_hex(32)
    valid = subprocess.run([binary, '--validate-only', '-f', '.run/wanbexpress.agentgateway.yaml'], cwd=gk.HERE, capture_output=True, text=True, env=env)
    if valid.returncode != 0:
        die('the gateway does not accept the configuration: ' + ' '.join((valid.stdout + valid.stderr).split())[:400])

    results = Results()
    resolved = sorted({a[4][0] for a in socket.getaddrinfo(SANDBOX_HOST, 80, type=socket.SOCK_STREAM)}) if args.sandbox else None
    started_at = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
    try:
        for log in RUN.glob('*.log'):
            log.unlink()
        if not args.sandbox:
            gk.start('provider', [sys.executable, str(MOCK), '--port', str(gk.PORTS['provider']), '--state', str(RUN / 'wanbexpress.mock-state.json')], gk.PORTS['provider'])
        start_authz('gateway-authz')
        gk.start('gateway', [binary, '-f', '.run/wanbexpress.agentgateway.yaml'], gk.PORTS['gateway'], env=env)
        try:
            run_cases(results, state, made, args.sandbox)
        finally:
            leftovers = [c for c, s in CREATED.items() if s != 'deleted']
            if leftovers and gk.port_open(gk.PORTS['gateway']):
                try:
                    blue_token = gk.token_for(state['blue']['client'])
                    for code in leftovers:
                        answer = req('DELETE', f'{BASE}/parcels/{code}', blue_token)
                        if data(answer).get('Succeeded') is True:
                            CREATED[code] = 'deleted'
                except Exception:
                    pass
    finally:
        gk.stop_all()
        gk.sync_tuples(state)

    mode = 'sandbox' if args.sandbox else 'stand-in' + (f' (control: {args.mutate})' if args.mutate else '')
    uncleaned = sorted(c for c, s in CREATED.items() if s != 'deleted')
    failed = results.failed()
    record = {'finished_at': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'), 'started_at': started_at, 'mode': mode,
              'agentgateway': reported['version'], 'repository_head': subprocess.run(['git', '-C', str(ROOT), 'rev-parse', '--short', 'HEAD'], capture_output=True, text=True).stdout.strip(),
              'gatekeeper_commit': subprocess.run(['git', '-C', os.environ.get('GK_SRC', str(Path.home() / '.local/src/idp-gatekeeper')), 'rev-parse', '--short', 'HEAD'],
                                                  capture_output=True, text=True).stdout.strip(),
              'gateway_environment': {'proxy_variables_removed_from_the_gateway_process': proxy_names},
              'upstream': ({'kind': 'the carrier\'s sandbox', 'name': SANDBOX_HOST, 'port': 80, 'name_resolved_to_at_the_start': resolved,
                            'addresses_the_gateway_process_held_connections_to': sorted(PEERS)}
                           if args.sandbox else {'kind': 'stand-in', 'address': f"127.0.0.1:{gk.PORTS['provider']}"}),
              'calls': CALLS, 'parcels_to_delete_by_hand': uncleaned,
              'cases': results.cases, 'passed': [c['id'] for c in results.cases if c not in failed], 'failed': [c['id'] for c in failed]}
    scanned, looked_for = scan(made, state, json.dumps(record, ensure_ascii=False, indent=1))
    clean = all(not v['secret found'] and not v['Authorization value of the carrier\'s scheme found'] for v in scanned.values())
    record['secret_scan'] = {'looked_for': looked_for, 'outcome': scanned}
    results.case('WB-10', 'the logs of the gateway and gateway-authz, this run\'s output and the result file hold no token and no Authorization of the carrier\'s scheme')
    for where, found in scanned.items():
        results.check(f'{where}: none of the {len(looked_for)} secrets of this run, and no value of the carrier\'s authorization scheme',
                      not found['secret found'] and not found['Authorization value of the carrier\'s scheme found'])
    results.cases.sort(key=lambda c: int(c['id'][3:]))
    record['cases'], failed = results.cases, results.failed()
    record['passed'], record['failed'] = [c['id'] for c in results.cases if c not in failed], [c['id'] for c in failed]
    final = json.dumps(record, ensure_ascii=False, indent=1)
    name = OUT / f"result-{'sandbox' if args.sandbox else 'standin'}{'-' + args.mutate if args.mutate else ''}.json"
    name.write_text(final, encoding='utf-8')
    os.chmod(name, 0o600)

    say(f'\nagentgateway {reported["version"]}; upstream: {mode}')
    results.report()
    if args.sandbox:
        say(f'  proxy variables removed from the gateway process: {proxy_names}')
        say(f'  {SANDBOX_HOST} resolved to {resolved}; the gateway held connections to {sorted(PEERS)}')
        say('  calls to the gateway (case, call, status, ms):')
        for c in CALLS:
            say(f"    {c['case']:6} {c['call']:55} {c['status']}  {c['ms']}")
    kept = True
    if args.evidence:
        upstream = record['upstream'] | ({'name_resolved_to_at_the_start': resolved} if args.sandbox else {})
        kept = write_evidence(f"rig-{'sandbox' if args.sandbox else 'standin'}.json",
                              evidence_document('rig: the real local Gatekeeper, agentgateway 1.7.0 as a local binary, gateway-authz as a local process', args.sandbox, started_at,
                                                record['finished_at'], reported, results, upstream, {'proxy_variables_removed_from_the_gateway_process': proxy_names,
                                                                                                     'present_in_the_gateway_process': False},
                                                pin.image_reference(pin.lock()), binary), made, state)
    if uncleaned:
        say('\n' + '!' * 70 + f'\n!! PARCELS THAT WERE CREATED AND NOT DELETED: {uncleaned}\n!! Delete them by hand at the carrier.\n' + '!' * 70)
    say(f"\n{len(results.cases) - len(failed)}/{len(results.cases)} ({mode}); results in {name}")
    return int(bool(failed) or bool(uncleaned) or not clean or not kept)


if __name__ == '__main__':
    sys.exit(main())
