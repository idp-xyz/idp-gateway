#!/usr/bin/env python3
"""Black-box runner: a real agentgateway between this repository's gateway-authz and a mock provider.

Builds cmd/gateway-authz, starts the processes (gateway, gateway-authz, mock local broker,
mock provider and a target no route may reach), drives requests through the gateway, checks
what the PDP, the broker and the provider actually received, and writes one evidence file.
Expectations are taken from G01/G03/G04 and are fixed in this file before the run; a case
that does not meet its expectation is reported as FAIL, not adjusted.

The gateway is the one build pinned in deploy/agentgateway/agentgateway.lock.json: the binary of
the pinned container image, taken out of the image and started on this host. A binary that is
not that build (version, git revision and SHA-256; see pin.py) is not started.

Before the cases the binary is started four more times, briefly: twice from the reviewed
configuration with its mitigations taken out, once with no session key and once to see what
it then lets through (observe_unmitigated); once from the reviewed configuration itself with
no session key; and once from the reviewed configuration with the header allow list replaced
by an expression it cannot evaluate (observe_unevaluable_allow_list). What these starts show
is written to the evidence as observations about the binary. They are not checks.

The PDP on the "gatekeeper" port is gateway-authz built with the `acceptance` tag: the same
code as the product build plus the controls this runner needs (see what it received, make it
answer 500, slow, or without a credential, revoke an account). Case titles, port names and
certificate names still say "Gatekeeper" and "PDP" from the time a Python mock stood there.

Usage (from the repository root):
    .venv/bin/python tests/acceptance/blackbox/run.py                              the pinned agentgateway, from ~/.local/opt/agentgateway/<version>/ or else PATH
    .venv/bin/python tests/acceptance/blackbox/run.py --agentgateway /path/to/bin  the pinned agentgateway, kept somewhere else
    .venv/bin/python tests/acceptance/blackbox/run.py --check-evidence             is the evidence file about the current tree?
The evidence file is tests/acceptance/blackbox/evidence/p1-run-agentgateway-<version>.json.
"""
from __future__ import annotations
import argparse, base64, copy, datetime, errno, hashlib, hmac, http.client, json, os, platform, re, secrets, shutil, socket, subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import jwt
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jsonschema import Draft202012Validator

import pin
import pki

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
RUN = HERE / '.run'
TLS = RUN / 'tls'
CONFIG = HERE / 'agentgateway.poc.yaml'
# The gateway is started from a per-run copy: a gateway that writes to its own config file
# (it does when it has no session key, see P1-CF-01) must not be able to alter the reviewed
# file in the repository.
RUN_CONFIG = RUN / 'agentgateway.yaml'
PORTS = {'gateway': 27611, 'provider': 27612, 'gatekeeper': 27613, 'admin': 27614,
         'stats': 27615, 'readiness': 27616, 'forbidden': 27617, 'broker': 27618, 'readback': 27619, 'front': 27620}
# Front proxy: official nginx, unprivileged variant, from nginx's own public registry. Pinned
# by digest; the tag is there for the reader. Docker Hub was not reachable from this host.
FRONT_IMAGE = ('public.ecr.aws/nginx/nginx-unprivileged:stable-alpine'
               '@sha256:c3fc8fa482be50ef709c6438eb1bc98d50dbfe5a9b48be90711b8814f4dfd701')
FRONT_CONF = HERE / 'front.nginx.conf'
FRONT_CONTAINER = 'idp-gateway-p1-front'
ISSUER, AUDIENCE, LOGICAL_HOST, KID = 'https://gatekeeper.idp.test', 'idp-egress-gateway', 'egress-api.idp.test', 'poc-key-1'
PROVIDER_SLOW_SECONDS, PDP_SLOW_SECONDS = 3.5, 2.5   # both longer than the gateway's 2s / 1s timeouts
TRACKING = '/providers/mockcarrier/v1/tracking'
LABELS = '/providers/mockcarrier/v1/labels'
RATES = '/providers/mockcarrier/v1/rates'
MANIFESTS = '/providers/mockcarrier/v1/manifests'   # Mode B route
PICKUPS = '/providers/mockcarrier/v1/pickups'       # backendAuth.key.expression route
PARCELS = '/providers/mockcarrier/v1/parcels'       # developer-token route: the credential is not a Bearer token (ADR-0011)
PARCELS_ROUTE = 'mockcarrier-parcels-get-developer-token'
DEVELOPER_TOKENS = RUN / 'authz-developer-tokens.json'
REVOCATIONS = RUN / 'authz-revocations.json'          # gateway-authz's own table of revoked accounts (ADR-0012)
NOTHING_REVOKED = '{"epoch": 0, "revoked_accounts": {}}\n'

# Headers the reviewed configuration registers for every provider backend (G03 §5). Same names,
# lower case, as the transformations.request.replace expression on each backend; tests/contracts
# compares the two. Host and the framing headers are the gateway's own and are not listed there.
HEADER_ALLOW = ("accept", "authorization", "content-type", "idempotency-key", "traceparent", "x-client-trace")
# Caller headers that no removal names and that are not on the allow list. Without the allow list
# they reach the provider (unmitigated_defaults); with it they must not (P1-HD-02).
UNREGISTERED = [("X-Evil-Probe", "must-not-reach"), ("X-Custom-Stuff", "also-not"),
                ("X-Internal-Hint", "drop-me")]

# --------------------------------------------------------------------------------------
# keys, tokens
# --------------------------------------------------------------------------------------
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()
fp = lambda s: hashlib.sha256(s.encode() if isinstance(s, str) else s).hexdigest()[:12]


def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def private_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def public_pem(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def jwk(key, kid: str) -> dict:
    n = key.public_key().public_numbers()
    as_bytes = lambda i: i.to_bytes((i.bit_length() + 7) // 8, 'big')
    return {'kty': 'RSA', 'use': 'sig', 'alg': 'RS256', 'kid': kid, 'n': b64u(as_bytes(n.n)), 'e': b64u(as_bytes(n.e))}


def claims(**over) -> dict:
    now = int(time.time())
    c = {'iss': ISSUER, 'aud': AUDIENCE, 'sub': 'parcel-service', 'tenant_id': 'tenant-blue', 'env': 'TEST',
         'iat': now, 'nbf': now - 5, 'exp': now + 300}
    c.update(over)
    return {k: v for k, v in c.items() if v is not None}


def mint(key, kid: str = KID, **over) -> str:
    return jwt.encode(claims(**over), private_pem(key), algorithm='RS256', headers={'kid': kid})


def forge(header: dict, body: dict, sign=None) -> str:
    signing_input = b64u(json.dumps(header).encode()) + '.' + b64u(json.dumps(body).encode())
    return signing_input + '.' + (b64u(sign(signing_input.encode())) if sign else '')


# --------------------------------------------------------------------------------------
# http
# --------------------------------------------------------------------------------------
def send(port: int, method: str, target: str, headers=(), body: bytes | None = None, timeout: float = 10.0,
         tls: tuple | None = None) -> dict:
    """Raw-ish client: the request target and headers go on the wire exactly as given.
    tls=(certificate name or None, CA name) speaks TLS instead, to the Gatekeeper port; a third
    element names the server the certificate must be for, when that is not Gatekeeper."""
    started = time.monotonic()
    try:
        conn = (pki.GatekeeperConnection(port, pki.client_context(TLS, *tls[:2]), timeout, *tls[2:]) if tls
                else http.client.HTTPConnection('127.0.0.1', port, timeout=timeout))
    except Exception as e:
        return {'status': None, 'headers': [], 'body': b'', 'error': f'{type(e).__name__}: {e}', 'seconds': 0.0}
    try:
        conn.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
        for k, v in headers:
            conn.putheader(k, v)
        if body is not None:
            conn.putheader('Content-Length', str(len(body)))
        conn.endheaders(body)
        resp = conn.getresponse()
        data = resp.read()
        return {'status': resp.status, 'headers': resp.getheaders(), 'body': data, 'seconds': round(time.monotonic() - started, 3)}
    except Exception as e:  # connection-level outcome is an observation too
        return {'status': None, 'headers': [], 'body': b'', 'error': f'{type(e).__name__}: {e}',
                'seconds': round(time.monotonic() - started, 3)}
    finally:
        conn.close()


def gw(method: str, target: str, token: str | None = None, headers=(), body: bytes | None = None, host: str = LOGICAL_HOST,
       port: int | None = None, **kw) -> dict:
    hs = [('Host', host)]
    if token is not None:
        hs.append(('Authorization', 'Bearer ' + token))
    return send(port or PORTS['gateway'], method, target, hs + list(headers), body, **kw)


def front(*args, **kw) -> dict:
    """The same request as gw(), sent to the front proxy instead of the gateway listener."""
    return gw(*args, port=PORTS['front'], **kw)


def header(resp_or_pairs, name: str) -> list[str]:
    pairs = resp_or_pairs['headers'] if isinstance(resp_or_pairs, dict) else resp_or_pairs
    return [v for k, v in pairs if k.lower() == name.lower()]


def body_json(resp: dict) -> dict:
    try:
        return json.loads(resp['body'] or b'{}')
    except ValueError:
        return {}


# --------------------------------------------------------------------------------------
# processes
# --------------------------------------------------------------------------------------
PROCS: dict[str, subprocess.Popen] = {}


def port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex(('127.0.0.1', port)) == 0


def wait_port(port: int, up: bool, timeout: float = 15.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if port_open(port) == up:
            return
        time.sleep(0.1)
    raise RuntimeError(f"port {port} did not become {'open' if up else 'closed'} within {timeout}s")


def start(name: str, argv: list[str], port: int, cwd: Path = HERE, env: dict | None = None):
    log = open(RUN / f'{name}.log', 'ab')
    PROCS[name] = subprocess.Popen(argv, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, env=env)
    wait_port(port, up=True)


def stop(name: str, port: int | None = None):
    p = PROCS.pop(name, None)
    if p is None:
        return
    p.terminate()
    try:
        p.wait(timeout=8)
    except subprocess.TimeoutExpired:
        p.kill(); p.wait(timeout=5)
    if port:
        wait_port(port, up=False)


AUTHZ_BINARY = RUN / 'gateway-authz'
AUTHZ_BUILD = ['build', '-trimpath', '-tags', 'acceptance', '-o', 'tests/acceptance/blackbox/.run/gateway-authz', './cmd/gateway-authz']
MOCKS = ('mock_broker.py', 'mock_provider.py', 'pki.py', 'pin.py')   # the modules beside this file; not all of them are mocks


def find_go() -> str | None:
    return shutil.which('go') or next((p for p in ('/usr/local/go/bin/go',) if Path(p).exists()), None)


def authz_source_sha256() -> str:
    """One digest over what gateway-authz is built from: go.mod and every non-test Go file under cmd/ and internal/."""
    files = [ROOT / 'go.mod'] + [p for top in ('cmd', 'internal') for p in (ROOT / top).rglob('*.go') if not p.name.endswith('_test.go')]
    lines = sorted(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(ROOT).as_posix()}\n' for p in files)
    return hashlib.sha256(''.join(lines).encode()).hexdigest()


def build_authz(go: str) -> str:
    """Build the acceptance flavour of gateway-authz into .run/. -> what the toolchain said, '' on success."""
    AUTHZ_BINARY.unlink(missing_ok=True)   # never run a binary left over from another tree
    built = subprocess.run([go, *AUTHZ_BUILD], cwd=ROOT, capture_output=True, text=True, timeout=600)
    if built.returncode != 0 or not AUTHZ_BINARY.exists():
        return (built.stdout + built.stderr).strip() or 'no binary produced'
    os.chmod(AUTHZ_BINARY, 0o700)
    return ''


def gatekeeper_command() -> tuple[list[str], dict]:
    """How gateway-authz is started here: its arguments, and the environment the acceptance build asks for."""
    env = {**os.environ, 'GATEWAY_AUTHZ_ACCEPTANCE_ADMIN_SECRET': S.admin,
           'GATEWAY_AUTHZ_ACCEPTANCE_OPERATOR_IDENTITY': pki.ID['operator'],
           'GATEWAY_AUTHZ_ACCEPTANCE_SLOW_SECONDS': str(PDP_SLOW_SECONDS)}
    argv = [str(AUTHZ_BINARY), '--listen', f"127.0.0.1:{PORTS['gatekeeper']}",
            '--tls-cert', str(TLS / 'gatekeeper.crt'), '--tls-key', str(TLS / 'gatekeeper.key'),
            '--client-ca', str(TLS / 'ca.crt'), '--policy', str(HERE / 'policy.poc.json'),
            '--credentials', str(RUN / 'authz-credentials.json'),
            '--developer-tokens', str(DEVELOPER_TOKENS),
            '--revocations', str(REVOCATIONS), '--revoker-identity', pki.ID['revoker'],
            '--gateway-identity', pki.ID['gateway'], '--broker-identity', pki.ID['broker']]
    return argv, env


def start_gatekeeper():
    """The PDP on the gatekeeper port: this repository's gateway-authz, acceptance build."""
    argv, env = gatekeeper_command()
    start('gateway-authz', argv, PORTS['gatekeeper'], env=env)


def gatekeeper_refuses_to_start() -> dict:
    """Run the same command while nothing listens on the port, and see whether it gives up.
    -> {'exited': its exit code, or None if it was still running after 10 seconds and was killed, 'said': its last line}"""
    argv, env = gatekeeper_command()
    try:
        done = subprocess.run(argv, cwd=HERE, env=env, capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        return {'exited': None, 'said': ''}
    lines = (done.stdout + done.stderr).strip().splitlines()
    # The message names the file by its full path; the evidence should not depend on where the repository is.
    return {'exited': done.returncode, 'said': lines[-1].replace(str(RUN), '.run') if lines else ''}


def start_broker():
    start('broker', [sys.executable, str(HERE / 'mock_broker.py'), '--port', str(PORTS['broker']),
                     '--state', str(RUN / 'state.json'), '--store', str(RUN / 'broker-store.json'),
                     '--local-key', str(RUN / 'broker-local.key')], PORTS['broker'])


def docker(*argv: str, timeout: float = 180) -> subprocess.CompletedProcess:
    return subprocess.run(['docker', *argv], capture_output=True, text=True, timeout=timeout)


def front_image_available() -> bool:
    """The pinned image, pulled once if this host does not have it yet."""
    try:
        return docker('image', 'inspect', FRONT_IMAGE).returncode == 0 or docker('pull', '-q', FRONT_IMAGE).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def start_front():
    docker('rm', '-f', FRONT_CONTAINER)   # a leftover of an interrupted run, by this name only
    run = docker('run', '-d', '--name', FRONT_CONTAINER, '--network', 'host', '--read-only', '--tmpfs', '/tmp',
                 '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                 '-v', f'{FRONT_CONF}:/etc/nginx/nginx.conf:ro', '--entrypoint', 'nginx', FRONT_IMAGE,
                 '-c', '/etc/nginx/nginx.conf', '-g', 'daemon off;')
    if run.returncode != 0:
        raise RuntimeError(f'front proxy did not start: {run.stderr.strip()[:300]}')
    wait_port(PORTS['front'], up=True)


def stop_front():
    logs = docker('logs', FRONT_CONTAINER)
    if logs.returncode == 0:
        (RUN / 'front.log').write_text(logs.stdout + logs.stderr, encoding='utf-8')
    docker('rm', '-f', FRONT_CONTAINER)
    wait_port(PORTS['front'], up=False)


class Impostor:
    """A server on the Gatekeeper port that is not Gatekeeper: its certificate carries the
    right names but comes from a CA the gateway was not told to trust. It asks for no client
    certificate and would allow everything, with a credential of its own."""

    def __init__(self):
        self.requests, impostor = [], self
        ctx = pki.server_context(TLS, 'rogue-gatekeeper', client_ca=None)

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *a):
                pass

            def setup(self):
                self.request = ctx.wrap_socket(self.request, server_side=True)
                super().setup()

            def _handle(self):
                impostor.requests.append(self.path)
                self.send_response(200)
                self.send_header('Content-Length', '2')
                self.send_header('Authorization', 'Bearer ' + S.impostor_token)
                self.end_headers()
                self.wfile.write(b'{}')

            do_GET = do_POST = _handle

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def handle_error(self, request, client_address):
                pass

        self.server = Server(('127.0.0.1', PORTS['gatekeeper']), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        wait_port(PORTS['gatekeeper'], up=False)


def gateway_env(session_key: str | None) -> dict:
    env = {k: v for k, v in os.environ.items() if k != 'SESSION_KEY'}
    if session_key:
        env['SESSION_KEY'] = session_key
    return env


def start_without_session_key_rewrites(binary: str, configuration: bytes) -> bool:
    """Start the gateway once from this configuration with no session key in its environment,
    and report whether it altered the file it was given."""
    probe = RUN / 'default-start.yaml'
    probe.write_bytes(configuration)
    os.chmod(probe, 0o600)
    start('agentgateway-default-start', [binary, '-f', f'.run/{probe.name}'], PORTS['gateway'], env=gateway_env(None))
    time.sleep(0.5)
    stop('agentgateway-default-start', PORTS['gateway'])
    rewritten = probe.read_bytes() != configuration
    probe.unlink()   # it may now hold a generated key
    return rewritten


def admin_api(method: str, path: str, body: dict | None = None) -> dict:
    """The gateway's own admin address (loopback): the API its UI uses."""
    headers = [('Host', f"127.0.0.1:{PORTS['admin']}")] + ([('Content-Type', 'application/json')] if body is not None else [])
    return send(PORTS['admin'], method, path, headers, json.dumps(body).encode() if body is not None else None)


# A change to the configuration as the UI would send it: one more resource, of a kind the
# reviewed file does not use, pointing at the target no route may reach.
ADMIN_WRITE = ('/api/config/resources/mcp.target',
               {'resources': [{'value': {'name': 'written-through-the-admin-api',
                                         'mcp': {'host': f"http://127.0.0.1:{PORTS['forbidden']}/mcp"}}}]})


def config_dump_digest() -> str | None:
    """A digest of what the gateway says it is running (/config_dump), independent of key order."""
    try:
        running = json.loads(admin_api('GET', '/config_dump')['body'])
    except ValueError:
        return None
    return hashlib.sha256(json.dumps(running, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def readback(method: str, target: str, cert: str | None = 'publisher', ca: str = 'ca', host: str = pki.READBACK_NAME, headers=()) -> dict:
    """The gateway's read-back listener, presenting the named certificate (None: no certificate)."""
    return send(PORTS['readback'], method, target, [('Host', host)] + list(headers), None if method == 'GET' else b'',
                tls=(cert, ca, pki.READBACK_NAME))


def listening() -> dict:
    """port -> the local addresses this host listens on for it, for the ports of this run."""
    found: dict = {}
    for line in sh(['ss', '-ltnH']).splitlines():
        fields = line.split()
        if len(fields) > 3 and ':' in fields[3]:
            address, _, port = fields[3].rpartition(':')
            if port.isdigit() and int(port) in PORTS.values():
                found.setdefault(int(port), set()).add(address.strip('[]'))
    return {port: sorted(addresses) for port, addresses in found.items()}


def another_address_of_this_host() -> str | None:
    """An address of this machine that is not loopback: the one it would send from. No packet is sent."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('192.0.2.1', 9))
            address = s.getsockname()[0]
    except OSError:
        return None
    return None if address.startswith('127.') or address == '0.0.0.0' else address


def connect_errno(address: str, port: int) -> int:
    """0 when a TCP connection to address:port is accepted, otherwise the error number."""
    with socket.socket() as s:
        s.settimeout(2)
        return s.connect_ex((address, port))


def sh(argv: list[str]) -> str:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=20, cwd=ROOT).stdout.strip()
    except Exception as e:
        return f'<unavailable: {type(e).__name__}>'


# --------------------------------------------------------------------------------------
# case harness
# --------------------------------------------------------------------------------------
class S:  # per-run secrets; never written to the evidence file
    signing = attacker = None
    admin = broker_key = static_token = session_key = impostor_token = ''
    token = {}  # account -> provider token
    developer = {}       # account -> (the carrier's account number, developer token): what gateway-authz starts with
    developer_next = {}  # the same accounts with another token each: what P1-DT-04 rotates to
    # not secrets: what the runner observed about the binary before the cases
    default_start_rewrites = None    # start_without_session_key_rewrites(), default storage mode
    read_only_start_rewrites = None  # the same, from the reviewed configuration
    config_bytes = b''               # what the gateway is started from
    pdp_protocols: set = set()       # HTTP versions the gateway spoke to the PDP


CASES: list[tuple] = []


def case(cid: str, title: str, expectation: str, maps_to: tuple = ()):
    def deco(fn):
        CASES.append((cid, title, expectation, maps_to, fn))
        return fn
    return deco


class Ctx:
    def __init__(self):
        self.checks, self.observed = [], {}

    def check(self, label: str, ok) -> bool:
        self.checks.append({'check': label, 'ok': bool(ok)})
        return bool(ok)

    def note(self, key: str, value):
        self.observed[key] = value


ADMIN = lambda: [('X-Poc-Admin', S.admin)]
provider_hits = lambda: body_json(send(PORTS['provider'], 'GET', '/admin/hits', ADMIN())).get('hits', [])
forbidden_hits = lambda: body_json(send(PORTS['forbidden'], 'GET', '/admin/hits', ADMIN())).get('hits', [])
broker_log = lambda: body_json(send(PORTS['broker'], 'GET', '/admin/log', ADMIN())).get('log', [])


def pdp(method: str, target: str, headers=(), body: bytes | None = None, cert: str | None = 'operator', ca: str = 'ca') -> dict:
    """A direct call to the Gatekeeper port, presenting the named certificate (None: no certificate).
    send() writes no Host header of its own, and gateway-authz answers 400 to an HTTP/1.1 request without one."""
    return send(PORTS['gatekeeper'], method, target, [('Host', pki.GATEKEEPER_NAME)] + list(headers), body, tls=(cert, ca))


pdp_state = lambda: body_json(pdp('GET', '/admin/log', ADMIN()))
pdp_log = lambda: pdp_state().get('log', [])
pdp_admin = lambda path: body_json(pdp('POST', path, ADMIN(), b''))


def reset_all():
    send(PORTS['provider'], 'POST', '/admin/reset', ADMIN(), b'')
    send(PORTS['forbidden'], 'POST', '/admin/reset', ADMIN(), b'')
    send(PORTS['broker'], 'POST', '/admin/reset', ADMIN(), b'')
    pdp('POST', '/admin/reset', ADMIN(), b'')


def nothing_forwarded(c: Ctx, also_pdp: bool = True):
    c.check('provider received nothing', len(provider_hits()) == 0)
    c.check('forbidden target received nothing', len(forbidden_hits()) == 0)
    if also_pdp:
        c.check('PDP was not consulted', len(pdp_log()) == 0)


def blue(**over) -> str:
    return mint(S.signing, **over)


def green(**over) -> str:
    return mint(S.signing, tenant_id='tenant-green', **over)


# ---- caller authentication -------------------------------------------------------------
def jwt_reject_case(cid, title, make_token, extra_maps=()):
    @case(cid, title, 'gateway answers 401; neither the PDP nor the provider sees the request',
          ('GW-AT-003', 'GW-FR-003') + tuple(extra_maps))
    def _(c: Ctx):
        r = gw('GET', TRACKING + '/TRK-1', make_token())
        c.note('status', r['status'])
        c.check('status is 401', r['status'] == 401)
        nothing_forwarded(c)


jwt_reject_case('P1-JWT-02', 'no token', lambda: None)
jwt_reject_case('P1-JWT-03', 'signed by a different key under the trusted kid', lambda: mint(S.attacker))
jwt_reject_case('P1-JWT-04', 'wrong issuer', lambda: blue(iss='https://evil.idp.test'))
jwt_reject_case('P1-JWT-05', 'wrong audience', lambda: blue(aud='some-other-service'))
jwt_reject_case('P1-JWT-06', 'expired', lambda: blue(exp=int(time.time()) - 120))
jwt_reject_case('P1-JWT-07', 'alg=none, no signature', lambda: forge({'alg': 'none', 'typ': 'JWT', 'kid': KID}, claims()))
jwt_reject_case('P1-JWT-08', 'HS256 signed with the RSA public key (algorithm confusion)',
                lambda: forge({'alg': 'HS256', 'typ': 'JWT', 'kid': KID}, claims(),
                              lambda m: hmac.new(public_pem(S.signing), m, hashlib.sha256).digest()))
jwt_reject_case('P1-JWT-09', 'nbf ten minutes in the future', lambda: blue(nbf=int(time.time()) + 600))
jwt_reject_case('P1-JWT-10', 'no exp claim', lambda: blue(exp=None))
jwt_reject_case('P1-JWT-11', 'unknown kid, attacker key', lambda: mint(S.attacker, kid='attacker-key'))
jwt_reject_case('P1-JWT-12', 'no audience claim', lambda: blue(aud=None))


# ---- authorization and account selection -------------------------------------------------
def expect_account(c: Ctx, r: dict, account: str, upstream_target: str):
    hits = provider_hits()
    c.note('status', r['status'])
    c.note('provider_saw_target', [h['raw_target'] for h in hits])
    c.check('status is 200', r['status'] == 200)
    c.check(f'provider answered as {account}', body_json(r).get('account') == account)
    c.check('provider received exactly one request', len(hits) == 1)
    if hits:
        auth = header(hits[0]['headers'], 'authorization')
        c.check(f"provider received exactly the {account} credential", auth == ['Bearer ' + S.token[account]])
        c.check('logical path rewritten to provider path', hits[0]['raw_target'] == upstream_target)


@case('P1-AZ-01', 'tenant-blue, no account requested', 'provider is called once, with account-blue\'s credential',
      ('GW-AT-006', 'GW-AT-002', 'GW-FR-006', 'GW-FR-033'))
def _(c):
    r = gw('GET', TRACKING + '/TRK-1', blue())
    expect_account(c, r, 'account-blue', '/v1/tracking/TRK-1')
    log = pdp_log()
    c.check('PDP consulted exactly once', len(log) == 1)
    if log:
        c.check('PDP saw tenant-blue from the validated token', header(log[0]['headers'], 'x-idp-verified-tenant') == ['tenant-blue'])
        c.note('pdp_saw_path', header(log[0]['headers'], 'x-idp-path'))


@case('P1-AZ-02', 'tenant-green, no account requested', 'provider is called once, with account-green\'s credential',
      ('GW-AT-006', 'GW-NAT-001', 'GW-FR-006'))
def _(c):
    expect_account(c, gw('GET', TRACKING + '/TRK-2', green()), 'account-green', '/v1/tracking/TRK-2')


@case('P1-AZ-03', 'tenant-blue asks for account-green', '403 from the PDP; provider not called',
      ('GW-AT-004', 'GW-ST-002', 'GW-NAT-001', 'GW-FR-004'))
def _(c):
    r = gw('GET', TRACKING + '/TRK-1', blue(), [('X-Provider-Account', 'account-green')])
    c.note('status', r['status']); c.note('reason_code', body_json(r).get('reason_code'))
    c.check('status is 403', r['status'] == 403)
    log = pdp_log()
    c.check('PDP saw the requested account', bool(log) and header(log[0]['headers'], 'x-provider-account') == ['account-green'])
    nothing_forwarded(c, also_pdp=False)


@case('P1-AZ-04', 'tenant-blue asks for its own account-blue', 'allowed, account-blue credential', ('GW-AT-029', 'GW-FR-029'))
def _(c):
    expect_account(c, gw('GET', TRACKING + '/TRK-1', blue(), [('X-Provider-Account', 'account-blue')]),
                   'account-blue', '/v1/tracking/TRK-1')


@case('P1-AZ-05', 'tenant-blue token plus forged trusted-context headers',
      'forged x-idp-* values never reach the PDP; the request is served as tenant-blue',
      ('GW-AT-022', 'GW-ST-020', 'GW-AT-032', 'GW-FR-022', 'GW-FR-032'))
def _(c):
    forged = [('X-Idp-Verified-Tenant', 'tenant-green'), ('X-Idp-Verified-Subject', 'cargo-service'),
              ('X-Idp-Verified-Env', 'PROD'), ('X-Idp-Operation-Id', 'labels.create'),
              ('X-Idp-Environment', 'PROD'), ('X-Idp-Provider-Id', 'othercarrier'), ('X-Tenant-ID', 'tenant-green')]
    r = gw('GET', TRACKING + '/TRK-1', blue(), forged)
    expect_account(c, r, 'account-blue', '/v1/tracking/TRK-1')
    log = pdp_log()
    if c.check('PDP consulted exactly once', len(log) == 1):
        hs = log[0]['headers']
        c.check('PDP saw exactly one verified tenant, tenant-blue', header(hs, 'x-idp-verified-tenant') == ['tenant-blue'])
        c.check('PDP saw exactly one verified subject, parcel-service', header(hs, 'x-idp-verified-subject') == ['parcel-service'])
        c.check('PDP saw the route\'s operation, not the forged one', header(hs, 'x-idp-operation-id') == ['tracking.get'])
        c.check('PDP saw the route\'s environment, not the forged one', header(hs, 'x-idp-environment') == ['TEST'])
        c.check('PDP saw the route\'s provider, not the forged one', header(hs, 'x-idp-provider-id') == ['mockcarrier'])
        c.check('X-Tenant-ID was not passed to the PDP', header(hs, 'x-tenant-id') == [])


def denied_by_pdp(cid, title, make_token, method='GET', target=TRACKING + '/TRK-1', maps=()):
    @case(cid, title, '403 from the PDP; provider not called', maps)
    def _(c):
        r = gw(method, target, make_token(), body=b'{}' if method == 'POST' else None)
        c.note('status', r['status']); c.note('reason_code', body_json(r).get('reason_code'))
        c.check('status is 403', r['status'] == 403)
        nothing_forwarded(c, also_pdp=False)


denied_by_pdp('P1-AZ-06', 'service identity with no grant', lambda: blue(sub='unknown-service'), maps=('GW-AT-004', 'GW-FR-004'))
denied_by_pdp('P1-AZ-07', 'token issued for PROD used on the TEST pool', lambda: blue(env='PROD'), maps=('GW-AT-028', 'GW-FR-028'))
denied_by_pdp('P1-AZ-08', 'valid token without a tenant claim', lambda: blue(tenant_id=None), maps=('GW-AT-032', 'GW-FR-032'))
denied_by_pdp('P1-AZ-09', 'service granted tracking.get but not labels.create', lambda: blue(sub='cargo-service'),
              method='POST', target=LABELS, maps=('GW-AT-029', 'GW-FR-029'))
denied_by_pdp('P1-AZ-10', 'tenant with no grant at all', lambda: blue(tenant_id='tenant-red'), maps=('GW-AT-004', 'GW-NAT-001'))


def trusted_context(route: str, operation: str, path: str) -> list:
    """The headers a gateway would send, written by something that is not the gateway."""
    return [('X-Idp-Verified-Subject', 'parcel-service'), ('X-Idp-Verified-Tenant', 'tenant-blue'), ('X-Idp-Verified-Env', 'TEST'),
            ('X-Idp-Route-Id', route), ('X-Idp-Provider-Id', 'mockcarrier'), ('X-Idp-Operation-Id', operation),
            ('X-Idp-Environment', 'TEST'), ('X-Idp-Method', 'GET'), ('X-Idp-Path', path)]


def carries_credential(r: dict) -> bool:
    return any(t in (r['body'].decode(errors='replace') + json.dumps(r['headers'])) for t in S.token.values())


@case('P1-AZ-11', 'something other than the gateway calls the PDP/Broker directly',
      'without a certificate from the workload CA there is no TLS session; with one, 401 and no provider credential '
      'unless the certificate is the gateway\'s', ('GW-ST-018', 'GW-AT-021', 'GW-FR-021'))
def _(c):
    ctx = trusted_context('mockcarrier-tracking-get', 'tracking.get', TRACKING + '/TRK-1')
    jwt_too = ctx + [('Authorization', 'Bearer ' + blue())]
    for label, cert in [('no client certificate', None),
                        ('a certificate with the gateway\'s identity from another CA', 'rogue-gateway')]:
        r = pdp('GET', '/v1/extauthz/check', jwt_too, cert=cert)
        c.check(f'{label}: no HTTP response', r['status'] is None)
        c.check(f'{label}: no provider credential returned', not carries_credential(r))
    state = pdp_state()
    c.note('tls_handshakes_refused_by_the_pdp', state.get('tls_handshakes_refused'))
    c.check('the PDP refused both TLS handshakes', len(state.get('tls_handshakes_refused', [])) == 2)
    c.check('...and handled no request from either', len(state.get('log', [])) == 0)
    # Workloads of the same trust domain that are not the gateway.
    for label, cert in [('a business app\'s own workload certificate, with a valid caller JWT', 'business-app'),
                        ('the local broker\'s certificate', 'broker')]:
        r = pdp('GET', '/v1/extauthz/check', jwt_too, cert=cert)
        c.check(f'{label}: 401', r['status'] == 401)
        c.check(f'{label}: no provider credential returned', not carries_credential(r))
    # Control: the refusals above are about who is calling, not about the request.
    r = pdp('GET', '/v1/extauthz/check', ctx, cert='gateway')
    c.check('control: the same request under the gateway\'s certificate is allowed', r['status'] == 200 and carries_credential(r))


@case('P1-AZ-12', 'paths and methods with no registered route', '404 from the gateway; nothing consulted or forwarded',
      ('GW-AT-001', 'GW-AT-005', 'GW-FR-001', 'GW-FR-005'))
def _(c):
    probes = [('GET', '/providers/othercarrier/v1/tracking/1'), ('DELETE', TRACKING + '/TRK-1'), ('GET', '/'),
              ('GET', LABELS), ('PUT', LABELS), ('GET', '/admin/hits'), ('GET', '/v1/tracking/TRK-1')]
    statuses = {f'{m} {t}': gw(m, t, blue())['status'] for m, t in probes}
    c.note('statuses', statuses)
    c.check('every probe answered 404', all(s == 404 for s in statuses.values()))
    nothing_forwarded(c)


# ---- credential hygiene -------------------------------------------------------------------
@case('P1-CR-01', 'what the provider receives', 'no IDP JWT, no trusted-context or account-request headers, no cookie; ordinary headers intact',
      ('GW-AT-008', 'GW-ST-001', 'GW-FR-008', 'GW-FR-022'))
def _(c):
    tok = blue()
    r = gw('GET', TRACKING + '/TRK-1', tok, [('Cookie', 'session=caller-session'), ('X-Provider-Account', 'account-blue'),
                                            ('X-Client-Trace', 'keep-me'), ('Accept', 'application/json'),
                                            ('X-Forwarded-Host', 'internal.idp.test'), ('X-Forwarded-For', '10.1.2.3'),
                                            ('Forwarded', 'for=10.1.2.3;host=internal.idp.test')])
    hits = provider_hits()
    if not c.check('request reached the provider once', r['status'] == 200 and len(hits) == 1):
        return
    hs = hits[0]['headers']
    names = sorted({k.lower() for k, _ in hs})
    c.note('provider_saw_header_names', names)
    c.note('provider_saw_host', header(hs, 'host'))
    c.check('IDP JWT appears in no header value', all(tok not in v for _, v in hs))
    c.check('no x-idp-* header', not any(n.startswith('x-idp-') for n in names))
    c.check('no x-provider-account header', 'x-provider-account' not in names)
    c.check('no cookie header', 'cookie' not in names)
    c.check('caller\'s ordinary header preserved', header(hs, 'x-client-trace') == ['keep-me'])
    c.check('Host is the registered upstream authority, not the logical egress name',
            header(hs, 'host') == [f"127.0.0.1:{PORTS['provider']}"])
    c.check('caller-supplied X-Forwarded-* / Forwarded not passed on',
            not any(n in names for n in ('x-forwarded-host', 'x-forwarded-for', 'forwarded')))


# ---- the provider receives the headers registered for it, and no other (G03 §5) ------------------------
# P1-CR-01 above is from before the allow list: what it calls the caller's "ordinary header",
# X-Client-Trace, is a registered header now, and that is why it is still passed on.
def outside_the_allow_list(hit: dict) -> list:
    """Names of the headers the provider recorded that are neither registered nor the gateway's own."""
    return sorted({k.lower() for k, _ in hit['headers']} - set(HEADER_ALLOW) - {'host', 'content-length'})


@case('P1-HD-01', 'registered request headers reach the provider',
      'every header on the allow list that the caller sent is present; the provider credential is still Authorization',
      ('GW-AT-008', 'GW-FR-008'))
def _(c):
    trace_id = '0af7651916cd43dd8537bf50925c1ba0'
    r = gw('GET', TRACKING + '/TRK-1', blue(),
           [('Accept', 'application/json'), ('X-Client-Trace', 'keep-me'),
            ('Idempotency-Key', 'idem-1'), ('Traceparent', f'00-{trace_id}-b7ad6b7169203331-01')])
    hits = provider_hits()
    if not c.check('request reached the provider once', r['status'] == 200 and len(hits) == 1):
        return
    hs = hits[0]['headers']
    c.note('provider_saw_header_names', sorted({k.lower() for k, _ in hs}))
    c.check('Accept preserved', header(hs, 'accept') == ['application/json'])
    c.check('X-Client-Trace preserved', header(hs, 'x-client-trace') == ['keep-me'])
    c.check('Idempotency-Key preserved', header(hs, 'idempotency-key') == ['idem-1'])
    # The name is on the allow list, so a Traceparent reaches the provider. The gateway may
    # rewrite the value for its own span; that is still correlation, not a dropped header.
    c.note('traceparent_the_provider_received', header(hs, 'traceparent'))
    c.check('Traceparent reaches the provider', bool(header(hs, 'traceparent')))
    c.check('...and it still carries the caller\'s trace id', [v.split('-')[1:2] for v in header(hs, 'traceparent')] == [[trace_id]])
    c.check('provider credential is present as Authorization',
            bool(header(hs, 'authorization')) and header(hs, 'authorization')[0].startswith('Bearer '))
    c.check('the provider received no header outside the registered set', outside_the_allow_list(hits[0]) == [])


@case('P1-HD-02', 'headers not on the allow list do not reach the provider',
      'caller-supplied headers outside the registered set are dropped; removals still drop Cookie and X-Forwarded-*',
      ('GW-AT-008', 'GW-FR-008'))
def _(c):
    r = gw('GET', TRACKING + '/TRK-1', blue(),
           list(UNREGISTERED) + [('Cookie', 'session=caller-session'), ('X-Forwarded-For', '10.1.2.3'),
                                 ('X-Client-Trace', 'keep-me')])
    hits = provider_hits()
    if not c.check('request reached the provider once', r['status'] == 200 and len(hits) == 1):
        return
    hs = hits[0]['headers']
    names = {k.lower() for k, _ in hs}
    c.note('provider_saw_header_names', sorted(names))
    c.check('no unregistered caller header reached the provider',
            not any(k.lower() in names for k, _ in UNREGISTERED))
    c.check('Cookie still removed', 'cookie' not in names)
    c.check('X-Forwarded-For still removed', 'x-forwarded-for' not in names)
    c.check('registered X-Client-Trace still present', header(hs, 'x-client-trace') == ['keep-me'])
    c.check('the provider received no header outside the registered set', outside_the_allow_list(hits[0]) == [])


@case('P1-HD-03', 'the allow list on every provider route',
      'on each of the six routes the provider receives one request whose headers are registered ones or the gateway\'s own, '
      'with exactly one credential; headers a client commonly sends without being asked are not among them',
      ('GW-AT-008', 'GW-FR-008'))
def _(c):
    sent = list(UNREGISTERED) + [('X-Client-Trace', 'keep-me'), ('User-Agent', 'blackbox/1'), ('Accept-Encoding', 'gzip'),
                                 ('Accept-Language', 'en'), ('Baggage', 'k=v')]
    routes = [('Mode A', 'GET', TRACKING + '/TRK-1', None), ('Mode A, a write', 'POST', LABELS, LABEL_BODY),
              ('Mode B', 'GET', MANIFESTS + '/MAN-1', None), ('Mode C', 'GET', RATES, None),
              ('Mode A with key.expression', 'GET', PICKUPS + '/PCK-1', None),
              ('Mode A with a developer token', 'GET', PARCELS + '/PRC-1', None)]
    seen = {}
    for label, method, target, body in routes:
        send(PORTS['provider'], 'POST', '/admin/reset', ADMIN(), b'')
        r = gw(method, target, blue(), sent + (JSON_CT if body else []), body)
        hits = provider_hits()
        seen[label] = sorted({k.lower() for k, _ in hits[0]['headers']}) if len(hits) == 1 else {'status': r['status'], 'provider_hits': len(hits)}
        if not c.check(f'{label}: served, and the provider received one request', r['status'] in (200, 201) and len(hits) == 1):
            continue
        hs = hits[0]['headers']
        c.check(f'{label}: no header outside the registered set', outside_the_allow_list(hits[0]) == [])
        c.check(f'{label}: the registered header the caller sent, and exactly one credential',
                header(hs, 'x-client-trace') == ['keep-me'] and len(header(hs, 'authorization')) == 1)
    c.note('provider_saw_header_names', seen)


@case('P1-HD-04', 'requests made to get a header past the allow list',
      'none does: with a value that is not UTF-8, a name in another letter case, a header named in Connection, a registered header '
      'sent twice or a second Authorization, the provider is left with registered headers only and the one credential',
      ('GW-AT-008', 'GW-ST-001', 'GW-FR-008'))
def _(c):
    planted = ('X-Evil-Probe', 'must-not-reach')
    attempts = [
        ('an unregistered header whose value is not UTF-8', [('X-Bin', '\xff\xfe'), planted]),
        ('a registered header whose value is not UTF-8', [('X-Client-Trace', 'caf\xe9'), planted]),
        ('names in other letter cases', [('X-EVIL-PROBE', 'must-not-reach'), ('x-CLIENT-trace', 'keep-me')]),
        ('the header named in Connection', [('Connection', 'keep-alive, X-Evil-Probe'), planted]),
        ('a registered header sent twice', [('X-Client-Trace', 'one'), ('X-Client-Trace', 'two'), planted]),
        ('a second Authorization after the caller\'s token', [('Authorization', 'Basic Y2FsbGVyOnBsYW50ZWQ='), planted]),
    ]
    seen = {}
    for label, headers in attempts:
        send(PORTS['provider'], 'POST', '/admin/reset', ADMIN(), b'')
        r = gw('GET', TRACKING + '/TRK-1', blue(), headers)
        hits = provider_hits()
        if not c.check(f'{label}: served, and the provider received one request', r['status'] == 200 and len(hits) == 1):
            seen[label] = {'status': r['status'], 'provider_hits': len(hits)}
            continue
        hs = hits[0]['headers']
        # What became of the registered header in each attempt is an observation, not a check.
        seen[label] = {'names': sorted({k.lower() for k, _ in hs}), 'x-client-trace': header(hs, 'x-client-trace')}
        c.check(f'{label}: no header outside the registered set', outside_the_allow_list(hits[0]) == [])
        c.check(f'{label}: exactly one Authorization, account-blue\'s credential',
                header(hs, 'authorization') == ['Bearer ' + S.token['account-blue']])
    c.note('provider_saw', seen)


@case('P1-CR-02', 'what the caller receives', 'the provider credential appears nowhere in the response', ('GW-AT-007', 'GW-FR-007'))
def _(c):
    r = gw('GET', TRACKING + '/TRK-1', blue())
    blob = r['body'].decode(errors='replace') + json.dumps(r['headers'])
    c.note('response_header_names', sorted({k.lower() for k, _ in r['headers']}))
    c.check('status is 200', r['status'] == 200)
    c.check('no provider credential in response headers or body', not any(t in blob for t in S.token.values()))
    c.check('no broker key in response', S.broker_key not in blob)


@case('P1-CR-03', 'what the PDP receives',
      'the gateway\'s workload identity, from its client certificate; not the caller\'s JWT, and no bearer credential of any kind',
      ('GW-AT-021', 'GW-FR-021'))
def _(c):
    tok = blue()
    gw('GET', TRACKING + '/TRK-1', tok)
    log = pdp_log()
    if not c.check('PDP consulted exactly once', len(log) == 1):
        return
    hs = log[0]['headers']
    c.note('pdp_saw_header_names', sorted({k.lower() for k, _ in hs}))
    c.note('pdp_saw_peer', {'identity': log[0].get('peer_identity'), 'tls_version': log[0].get('tls_version')})
    c.check('caller JWT appears in no header value', all(tok not in v for _, v in hs))
    c.check('no Authorization header at all', header(hs, 'authorization') == [])
    c.check('the caller is the gateway workload, by its verified client certificate', log[0].get('peer_identity') == pki.ID['gateway'])
    c.check('the session is TLS 1.2 or later', log[0].get('tls_version') in ('TLSv1.2', 'TLSv1.3'))


# ---- revocation -------------------------------------------------------------------------------
@case('P1-RV-01', 'revoke account-blue while both tenants are active',
      'the next blue request is denied and not forwarded; green is unaffected; restore re-enables blue',
      ('GW-AT-026', 'GW-ST-026', 'GW-AT-047', 'GW-FR-026', 'GW-FR-047'))
def _(c):
    c.check('before: blue allowed', gw('GET', TRACKING + '/TRK-1', blue())['status'] == 200)
    pdp_admin('/admin/revoke?account=account-blue')
    send(PORTS['provider'], 'POST', '/admin/reset', ADMIN(), b'')
    r = gw('GET', TRACKING + '/TRK-1', blue())
    c.note('first_request_after_revoke', {'status': r['status'], 'reason_code': body_json(r).get('reason_code')})
    c.check('first blue request after revocation: 403', r['status'] == 403)
    c.check('...and the provider did not receive it', len(provider_hits()) == 0)
    g = gw('GET', TRACKING + '/TRK-2', green())
    c.check('green still allowed with its own account', g['status'] == 200 and body_json(g).get('account') == 'account-green')
    pdp_admin('/admin/restore?account=account-blue')
    c.check('after restore: blue allowed again', gw('GET', TRACKING + '/TRK-1', blue())['status'] == 200)


# ---- dependency failure -----------------------------------------------------------------------
def pdp_failure(cid, title, mode):
    @case(cid, title, 'request is rejected and never reaches the provider (fail closed)',
          ('GW-ST-008', 'GW-NAT-006', 'GW-AT-047', 'GW-FR-047'))
    def _(c):
        pdp_admin('/admin/mode?value=' + mode)
        r = gw('GET', TRACKING + '/TRK-1', blue())
        c.note('status', r['status']); c.note('seconds', r['seconds'])
        c.check('not a success status', r['status'] is not None and r['status'] >= 400)
        c.check('provider received nothing', len(provider_hits()) == 0)


pdp_failure('P1-FC-01', 'PDP answers 500', 'error500')
pdp_failure('P1-FC-02', 'PDP slower than the gateway\'s 1s authorization timeout', 'slow')


@case('P1-FC-03', 'PDP process is down', 'request is rejected and never reaches the provider; service resumes when the PDP is back',
      ('GW-ST-008', 'GW-NAT-006', 'GW-FR-047'))
def _(c):
    stop('gateway-authz', PORTS['gatekeeper'])
    try:
        r = gw('GET', TRACKING + '/TRK-1', blue())
        c.note('status_while_down', r['status'])
        c.check('not a success status', r['status'] is not None and r['status'] >= 400)
        c.check('provider received nothing', len(provider_hits()) == 0)
    finally:
        start_gatekeeper()
    c.check('after restart: allowed again', gw('GET', TRACKING + '/TRK-1', blue())['status'] == 200)


@case('P1-TL-01', 'a server on the PDP port that is not Gatekeeper',
      'the gateway does not accept its certificate: it is sent no request, nothing reaches the provider, and service resumes with the real PDP',
      ('GW-ST-018', 'GW-ST-008', 'GW-FR-021', 'GW-FR-047'))
def _(c):
    stop('gateway-authz', PORTS['gatekeeper'])
    impostor = Impostor()
    try:
        r = gw('GET', TRACKING + '/TRK-1', blue())
        w = gw('POST', LABELS, blue(), JSON_CT, LABEL_BODY)
        c.note('statuses_while_impersonated', [r['status'], w['status']])
        c.check('neither request succeeds', all(x['status'] is not None and x['status'] >= 400 for x in (r, w)))
        c.check('the impostor was sent no request by the gateway', impostor.requests == [])
        c.check('provider received nothing', len(provider_hits()) == 0)
        # Control: a client that does trust the other CA is answered, with a credential.
        told = pdp('GET', '/v1/extauthz/check', cert=None, ca='rogue-ca')
        c.check('control: the impostor allows whoever accepts its certificate',
                told['status'] == 200 and header(told, 'authorization') == ['Bearer ' + S.impostor_token])
    finally:
        impostor.close()
        start_gatekeeper()
    c.check('after the real PDP is back: allowed again', gw('GET', TRACKING + '/TRK-1', blue())['status'] == 200)


@case('P1-FC-04', 'PDP allows but the Broker returns no credential',
      'the gateway itself refuses to forward an uncredentialed request; in no case does the caller\'s JWT reach the provider',
      ('GW-ST-009', 'GW-AT-043', 'GW-FR-006', 'GW-FR-043'))
def _(c):
    pdp_admin('/admin/mode?value=allow_without_credential')
    tok = blue()
    r = gw('GET', TRACKING + '/TRK-1', tok)
    hits = provider_hits()
    c.note('status', r['status']); c.note('provider_hits', len(hits))
    c.note('rejected_by', 'provider' if header(r, 'x-mock-provider') else 'gateway')
    c.check('caller does not get a success', r['status'] is not None and r['status'] >= 400)
    c.check('caller JWT did not reach the provider', all(tok not in v for h in hits for _, v in h['headers']))
    c.check('no Authorization header reached the provider', all(header(h['headers'], 'authorization') == [] for h in hits))
    c.check('provider received nothing (rejected at the gateway)', len(hits) == 0)


# ---- where a refusal comes from: the PDP refused, or the PDP could not be asked ---------------------
# With failureMode `deny` the gateway answered 403 in both cases. The reviewed configuration says
# `denyWithStatus: 503`. P1-FC-01 to 03 and P1-TL-01 above keep the expectation they had before that
# (the request is rejected and nothing is forwarded); which status the caller gets is pinned here.
def answered_by_the_gateway(r: dict) -> bool:
    """A refusal the gateway made itself: not relayed from the PDP (no decision in the body), not from the provider."""
    body = body_json(r)
    return r['status'] is not None and not header(r, 'x-mock-provider') and 'result' not in body and 'reason_code' not in body


def gateway_log_size() -> int:
    return (RUN / 'agentgateway.log').stat().st_size


def gateway_logged(since: int) -> dict:
    """Level, status, reason and error of the last request line the gateway wrote after byte `since` of its log."""
    time.sleep(0.4)
    with open(RUN / 'agentgateway.log', 'rb') as f:
        f.seek(since)
        lines = [l for l in f.read().decode(errors='replace').splitlines() if '\trequest ' in l]
    if not lines:
        return {}

    def field(key: str) -> str | None:
        found = re.search(rf' {re.escape(key)}=("[^"]*"|\S+)', lines[-1])
        return found[1].strip('"') if found else None

    return {'level': lines[-1].split('\t')[1], 'http.status': field('http.status'), 'reason': field('reason'), 'error': field('error')}


@case('P1-FO-01', 'the PDP refuses, and the PDP cannot be asked',
      'the caller can tell them apart: a policy denial is 403 with the PDP\'s reason; when the PDP cannot be asked the gateway '
      'answers 503 itself, on every route, and forwards nothing; an answer the PDP did give keeps the PDP\'s status',
      ('GW-AT-043', 'GW-ST-008', 'GW-FR-043', 'GW-FR-047'))
def _(c):
    track = lambda: gw('GET', TRACKING + '/TRK-1', blue())

    denied = gw('GET', TRACKING + '/TRK-1', blue(), [('X-Provider-Account', 'account-green')])
    c.note('policy_denial', {'status': denied['status'], 'reason_code': body_json(denied).get('reason_code')})
    c.check('a policy denial: 403, with the PDP\'s reason', denied['status'] == 403 and body_json(denied).get('reason_code') == 'ACCOUNT_NOT_GRANTED')

    pdp_admin('/admin/mode?value=error500')
    answered = track()
    c.note('pdp_answered_500', {'status': answered['status']})
    c.check('an error the PDP answered with keeps its status: 500', answered['status'] == 500)

    pdp_admin('/admin/mode?value=slow')
    slow = track()
    c.note('pdp_slower_than_the_timeout', {'status': slow['status'], 'seconds': slow['seconds']})
    c.check('the PDP does not answer within the gateway\'s 1s timeout: 503, from the gateway itself',
            slow['status'] == 503 and answered_by_the_gateway(slow))
    pdp_admin('/admin/mode?value=normal')

    stop('gateway-authz', PORTS['gatekeeper'])
    try:
        mark = gateway_log_size()
        down = track()
        # Observation, not a check: with denyWithStatus the gateway's own log line for this request is
        # no longer an error line with reason=ExtAuth; it reads like an answer relayed from the PDP.
        c.note('gateway_log_line_when_the_pdp_cannot_be_asked', gateway_logged(mark))
        c.check('the PDP is down: 503, from the gateway itself', down['status'] == 503 and answered_by_the_gateway(down))
        others = {'labels, a write': gw('POST', LABELS, blue(), JSON_CT, LABEL_BODY),
                  'pickups, key.expression': gw('GET', PICKUPS + '/PCK-1', blue()),
                  'parcels, developer token': gw('GET', PARCELS + '/PRC-1', blue())}
        c.note('other_routes_while_the_pdp_is_down', {name: r['status'] for name, r in others.items()})
        c.check('the same on the other routes that ask the PDP: 503, from the gateway itself',
                all(r['status'] == 503 and answered_by_the_gateway(r) for r in others.values()))
        impostor = Impostor()
        try:
            fake = track()
            c.check('a server on the PDP port whose certificate the gateway does not accept: 503 from the gateway, which sent it nothing',
                    fake['status'] == 503 and answered_by_the_gateway(fake) and impostor.requests == [])
        finally:
            impostor.close()
    finally:
        start_gatekeeper()
    stop('broker', PORTS['broker'])
    try:
        b = gw('GET', MANIFESTS + '/MAN-1', blue())
        c.note('mode_b_while_the_broker_is_down', b['status'])
        c.check('the Mode B route while the local broker is down: 503, from the gateway itself',
                b['status'] == 503 and answered_by_the_gateway(b))
    finally:
        start_broker()
    c.check('the provider received none of these requests', len(provider_hits()) == 0)
    c.check('after the PDP and the broker are back: allowed again',
            track()['status'] == 200 and gw('GET', MANIFESTS + '/MAN-1', blue())['status'] == 200)


# ---- writes -----------------------------------------------------------------------------------
LABEL_BODY = json.dumps({'shipmentReference': 'DEMO-SHP-1024', 'weight': {'value': 1.2, 'unit': 'KG'}}).encode()
JSON_CT = [('Content-Type', 'application/json')]


@case('P1-WR-01', 'POST a label', '201; provider receives the body byte-for-byte, once', ('GW-AT-009', 'GW-FR-009'))
def _(c):
    r = gw('POST', LABELS, blue(), JSON_CT, LABEL_BODY)
    hits = provider_hits()
    c.note('status', r['status'])
    c.check('status is 201', r['status'] == 201)
    c.check('provider received exactly one request', len(hits) == 1)
    if hits:
        c.check('body hash identical', hits[0]['body_sha256'] == hashlib.sha256(LABEL_BODY).hexdigest())
        c.check('content-type preserved', header(hits[0]['headers'], 'content-type') == ['application/json'])
        c.check('rewritten to /v1/labels', hits[0]['raw_target'] == '/v1/labels')


@case('P1-WR-02', 'POST a label; provider answers after the gateway\'s 2s timeout',
      'caller gets 504; the provider received the write exactly once (no replay)',
      ('GW-AT-012', 'GW-ST-011', 'GW-AT-043', 'GW-FR-012', 'GW-FR-043'))
def _(c):
    r = gw('POST', LABELS + '?fault=slow', blue(), JSON_CT, LABEL_BODY)
    c.note('status', r['status']); c.note('seconds', r['seconds'])
    time.sleep(PROVIDER_SLOW_SECONDS + 1.5)  # long enough for any replay to have arrived
    hits = provider_hits()
    c.note('provider_hits', len(hits))
    c.check('status is 504', r['status'] == 504)
    c.check('gateway gave up at about its 2s budget', 1.5 <= r['seconds'] <= 3.0)
    c.check('provider received the write exactly once', len(hits) == 1)


@case('P1-WR-03', 'POST a label; provider drops the connection after reading it',
      'caller gets a 5xx; the provider received the write exactly once, also on a reused connection',
      ('GW-AT-012', 'GW-ST-011', 'GW-FR-012'))
def _(c):
    c.check('warm-up write succeeds', gw('POST', LABELS, blue(), JSON_CT, LABEL_BODY)['status'] == 201)
    statuses = []
    for _ in range(3):
        statuses.append(gw('POST', LABELS + '?fault=reset', blue(), JSON_CT, LABEL_BODY)['status'])
    time.sleep(2.0)
    faulted = [h for h in provider_hits() if 'fault=reset' in h['raw_target']]
    c.note('statuses', statuses); c.note('provider_hits_for_faulted_writes', len(faulted))
    c.check('every faulted write answered 5xx', all(s is not None and 500 <= s <= 599 for s in statuses))
    c.check('three faulted writes sent, three received', len(faulted) == 3)


# ---- passthrough ------------------------------------------------------------------------------
@case('P1-L7-01', 'query string and provider status codes', 'query reaches the provider unchanged; provider 404/429 reach the caller unchanged',
      ('GW-AT-009', 'GW-AT-043', 'GW-FR-009'))
def _(c):
    r = gw('GET', TRACKING + '/TRK-9?a=1&a=2&b=%20x&c=', blue())
    hits = provider_hits()
    c.note('provider_saw_target', [h['raw_target'] for h in hits])
    c.note('pdp_saw_path', [v for e in pdp_log() for v in header(e['headers'], 'x-idp-path')])
    c.check('query unchanged', r['status'] == 200 and len(hits) == 1 and hits[0]['raw_target'] == '/v1/tracking/TRK-9?a=1&a=2&b=%20x&c=')
    nf = gw('GET', TRACKING + '/not-found', blue())
    c.check('provider 404 passed through', nf['status'] == 404 and header(nf, 'x-mock-provider') == ['mockcarrier'])
    rl = gw('GET', TRACKING + '/rate-limited', blue())
    c.check('provider 429 passed through with Retry-After', rl['status'] == 429 and header(rl, 'retry-after') == ['7'])
    gw404 = gw('GET', '/providers/othercarrier/x', blue())
    c.check('a gateway-generated 404 is distinguishable (no provider marker)', gw404['status'] == 404 and header(gw404, 'x-mock-provider') == [])


# ---- egress target control ----------------------------------------------------------------------
@case('P1-SS-01', 'caller tries to choose the upstream', 'the forbidden target receives nothing, whatever the gateway answers',
      ('GW-AT-005', 'GW-ST-003', 'GW-ST-017', 'GW-AT-034', 'GW-FR-005', 'GW-FR-034'))
def _(c):
    f = f"127.0.0.1:{PORTS['forbidden']}"
    attempts = {
        'absolute-form request target': gw('GET', f'http://{f}/v1/stolen', blue()),
        'absolute-form target, logical path': gw('GET', f'http://{f}{TRACKING}/TRK-1', blue()),
        'Host header names the forbidden target': gw('GET', TRACKING + '/TRK-1', blue(), host=f),
        'X-Forwarded-Host': gw('GET', TRACKING + '/TRK-1', blue(), [('X-Forwarded-Host', f)]),
        'second Host header': gw('GET', TRACKING + '/TRK-1', blue(), [('Host', f)]),
    }
    c.note('statuses', {k: v['status'] for k, v in attempts.items()})
    c.note('provider_saw_host', sorted({v for h in provider_hits() for v in header(h['headers'], 'host')}))
    c.check('forbidden target received nothing', len(forbidden_hits()) == 0)
    c.check('provider never saw the forbidden authority in any header',
            all(f not in v for h in provider_hits() for _, v in h['headers']))


@case('P1-SS-02', 'provider answers 302 to an unregistered host',
      'the gateway does not follow it, and does not hand the redirect target or provider cookies to the caller',
      ('GW-ST-004', 'GW-AT-034', 'GW-FR-034'))
def _(c):
    r = gw('GET', TRACKING + '/redirect-me', blue())
    c.note('status', r['status']); c.note('location_passed_to_caller', header(r, 'location'))
    c.check('forbidden target received nothing', len(forbidden_hits()) == 0)
    c.check('provider called once (no follow-up request)', len(provider_hits()) == 1)
    c.check('Location not passed to the caller', header(r, 'location') == [])
    c.check('Set-Cookie not passed to the caller', header(r, 'set-cookie') == [])


@case('P1-SS-04', 'request carrying two Host headers', '400, as RFC 9112 §3.2 requires; nothing consulted or forwarded',
      ('GW-ST-017', 'GW-FR-034'))
def _(c):
    r = gw('GET', TRACKING + '/TRK-1', blue(), [('Host', f"127.0.0.1:{PORTS['forbidden']}")])
    c.note('status', r['status'])
    c.note('provider_saw_host', [header(h['headers'], 'host') for h in provider_hits()])
    c.check('status is 400', r['status'] == 400)
    nothing_forwarded(c)


@case('P1-SS-03', 'path tricks against the registered prefix',
      'none of them is forwarded: a path the PDP cannot read as canonical must not reach the provider',
      ('GW-ST-017', 'GW-AT-034', 'GW-AT-048', 'GW-FR-005', 'GW-FR-034'))
def _(c):
    variants = [TRACKING + '/../../admin/hits', TRACKING + '/%2e%2e/%2e%2e/admin/hits', TRACKING + '/..%2fadmin',
                TRACKING + '/%252e%252e/admin', TRACKING + '/%252e%252e%252fadmin', TRACKING + '//admin',
                TRACKING + '-admin', TRACKING + '/TRK-1%00', TRACKING + '/TRK-1;x=1', '/providers/mockcarrier/v1/./tracking/TRK-1',
                '/providers/mockcarrier/v1/labels/../tracking/TRK-1', TRACKING + '/./TRK-1',
                # the Mode C route has no PDP behind it: whatever stops these must be in the gateway
                RATES + '/../../admin/hits', RATES + '/%2e%2e/%2e%2e/admin/hits', RATES + '/%252e%252e/admin', RATES + '//x']
    seen = {}
    for v in variants:
        reset_all()
        r = gw('GET', v, blue())
        seen[v] = {'status': r['status'], 'provider_saw': [h['raw_target'] for h in provider_hits()],
                   'stopped_by': 'pdp' if pdp_log() else 'gateway'}
    c.note('variants', seen)
    c.check('no variant reached the provider', all(not s['provider_saw'] for s in seen.values()))
    c.check('no variant answered 2xx', all(s['status'] is None or s['status'] >= 400 for s in seen.values()))
    c.check('forbidden target received nothing', len(forbidden_hits()) == 0)


# ---- front proxy ------------------------------------------------------------------------------------
# P1-SS-04 stays as it is: it records what the gateway does on its own listener. These cases
# send requests to the nginx in front of it.
def gateway_log_lines() -> int:
    return len((RUN / 'agentgateway.log').read_text(encoding='utf-8', errors='replace').splitlines())


def answered_by_nginx(r: dict) -> bool:
    """nginx's own error page. (Its Server header is on every response it relays, so that says nothing.)"""
    return b'<center>nginx</center>' in r['body']


@case('P1-FP-01', 'request carrying two Host headers, sent through the front proxy',
      '400 from the front proxy, as RFC 9112 §3.2 requires; the gateway, the PDP and the provider see nothing',
      ('GW-ST-017', 'GW-FR-034'))
def _(c):
    f = f"127.0.0.1:{PORTS['forbidden']}"
    tok = blue()
    before = gateway_log_lines()
    attempts = {
        'logical host first, forbidden target second': front('GET', TRACKING + '/TRK-1', tok, [('Host', f)]),
        'forbidden target first, logical host second': front('GET', TRACKING + '/TRK-1', tok, [('Host', LOGICAL_HOST)], host=f),
        'the same Host header twice': front('GET', TRACKING + '/TRK-1', tok, [('Host', LOGICAL_HOST)]),
        'two Host headers on a write': front('POST', LABELS, tok, JSON_CT + [('Host', f)], LABEL_BODY),
        'no Host header at all': send(PORTS['front'], 'GET', TRACKING + '/TRK-1', [('Authorization', 'Bearer ' + tok)]),
    }
    c.note('statuses', {k: v['status'] for k, v in attempts.items()})
    c.check('every attempt answered 400', all(v['status'] == 400 for v in attempts.values()))
    c.check('...by the front proxy itself (its own error page)', all(answered_by_nginx(v) for v in attempts.values()))
    time.sleep(0.5)
    c.check('the gateway logged no request', gateway_log_lines() == before)
    nothing_forwarded(c)
    # Control: the refusals are about the Host headers, not about the route or the token.
    ok = front('GET', TRACKING + '/TRK-1', tok)
    c.check('control: the same request with one Host header is served', ok['status'] == 200 and body_json(ok).get('account') == 'account-blue')
    time.sleep(0.5)
    c.check('control: ...and that one the gateway did log', gateway_log_lines() > before)
    # Observation, not a check: the gateway's own answer to a request without a Host header.
    c.note('gateway_listener_without_host_header', send(PORTS['gateway'], 'GET', TRACKING + '/TRK-1', [('Authorization', 'Bearer ' + tok)])['status'])


@case('P1-FP-02', 'ordinary traffic through the front proxy',
      'what holds at the gateway listener holds behind the front proxy: caller authentication, account isolation, what the provider receives, the request body',
      ('GW-AT-006', 'GW-AT-008', 'GW-AT-009', 'GW-NAT-001', 'GW-FR-006', 'GW-FR-008', 'GW-FR-009'))
def _(c):
    tok = blue()
    r = front('GET', TRACKING + '/TRK-9?a=1&a=2&b=%20x&c=', tok, [('Cookie', 'session=caller-session'), ('X-Client-Trace', 'keep-me')])
    expect_account(c, r, 'account-blue', '/v1/tracking/TRK-9?a=1&a=2&b=%20x&c=')
    for h in provider_hits():
        names = sorted({k.lower() for k, _ in h['headers']})
        c.note('provider_saw_header_names', names)
        c.check('IDP JWT appears in no header value', all(tok not in v for _, v in h['headers']))
        c.check('nothing the front proxy or the caller added about itself reaches the provider',
                not any(n.startswith(('x-idp-', 'x-forwarded-')) or n in ('x-provider-account', 'cookie', 'forwarded', 'x-real-ip') for n in names))
        c.check('Host is the registered upstream authority', header(h['headers'], 'host') == [f"127.0.0.1:{PORTS['provider']}"])
        c.check('caller\'s ordinary header preserved', header(h['headers'], 'x-client-trace') == ['keep-me'])
    log = pdp_log()
    c.check('PDP saw tenant-blue and the path as the caller sent it',
            len(log) == 1 and header(log[0]['headers'], 'x-idp-verified-tenant') == ['tenant-blue']
            and header(log[0]['headers'], 'x-idp-path') == [TRACKING + '/TRK-9'])
    send(PORTS['provider'], 'POST', '/admin/reset', ADMIN(), b'')
    expect_account(c, front('GET', TRACKING + '/TRK-2', green()), 'account-green', '/v1/tracking/TRK-2')
    send(PORTS['provider'], 'POST', '/admin/reset', ADMIN(), b'')
    c.check('no token: 401', front('GET', TRACKING + '/TRK-1')['status'] == 401)
    c.check('tenant-blue asking for account-green: 403', front('GET', TRACKING + '/TRK-1', tok, [('X-Provider-Account', 'account-green')])['status'] == 403)
    c.check('unregistered path: 404', front('GET', '/providers/othercarrier/v1/tracking/1', tok)['status'] == 404)
    c.check('...and none of those three reached the provider', len(provider_hits()) == 0)
    w = front('POST', LABELS, tok, JSON_CT, LABEL_BODY)
    hits = provider_hits()
    c.check('POST a label: 201, received once, body byte-for-byte',
            w['status'] == 201 and len(hits) == 1 and hits[0]['body_sha256'] == hashlib.sha256(LABEL_BODY).hexdigest())


@case('P1-FP-03', 'writes through the front proxy when the provider fails',
      'the caller gets the gateway\'s 504 or 5xx and the provider received each write exactly once: the front proxy replays nothing',
      ('GW-AT-012', 'GW-ST-011', 'GW-FR-012'))
def _(c):
    slow = front('POST', LABELS + '?fault=slow', blue(), JSON_CT, LABEL_BODY)
    dropped = [front('POST', LABELS + '?fault=reset', blue(), JSON_CT, LABEL_BODY)['status'] for _ in range(2)]
    time.sleep(PROVIDER_SLOW_SECONDS + 1.5)  # long enough for any replay to have arrived
    hits = provider_hits()
    c.note('statuses', {'slow': slow['status'], 'dropped': dropped}); c.note('seconds_slow', slow['seconds'])
    c.note('provider_hits', len(hits))
    c.check('provider slower than the gateway\'s budget: 504 at about 2s', slow['status'] == 504 and 1.5 <= slow['seconds'] <= 3.0)
    c.check('provider drops the connection: 5xx each time', all(s is not None and 500 <= s <= 599 for s in dropped))
    c.check('three writes sent, three received', len(hits) == 3)


@case('P1-FP-04', 'caller tries to choose the upstream or bend the path, through the front proxy',
      'the forbidden target receives nothing and no bent path reaches the provider, whichever of the two hops stops it',
      ('GW-AT-005', 'GW-ST-003', 'GW-ST-017', 'GW-AT-034', 'GW-FR-005', 'GW-FR-034'))
def _(c):
    f = f"127.0.0.1:{PORTS['forbidden']}"
    attempts = {
        'absolute-form request target': front('GET', f'http://{f}/v1/stolen', blue()),
        'absolute-form target, logical path': front('GET', f'http://{f}{TRACKING}/TRK-1', blue()),
        'Host header names the forbidden target': front('GET', TRACKING + '/TRK-1', blue(), host=f),
        'X-Forwarded-Host': front('GET', TRACKING + '/TRK-1', blue(), [('X-Forwarded-Host', f)]),
    }
    c.note('statuses', {k: v['status'] for k, v in attempts.items()})
    c.check('forbidden target received nothing', len(forbidden_hits()) == 0)
    c.check('provider never saw the forbidden authority in any header',
            all(f not in v for h in provider_hits() for _, v in h['headers']))
    variants = [TRACKING + '/../../admin/hits', TRACKING + '/%2e%2e/%2e%2e/admin/hits', TRACKING + '/..%2fadmin',
                TRACKING + '/%252e%252e/admin', TRACKING + '//admin', TRACKING + '/TRK-1%00', TRACKING + '/TRK-1;x=1',
                TRACKING + '/./TRK-1', RATES + '/../../admin/hits', RATES + '/%252e%252e/admin', RATES + '//x']
    seen = {}
    for v in variants:
        reset_all()
        r = front('GET', v, blue())
        seen[v] = {'status': r['status'], 'provider_saw': [h['raw_target'] for h in provider_hits()],
                   'stopped_by': 'front proxy' if answered_by_nginx(r) else ('pdp' if pdp_log() else 'gateway')}
    c.note('variants', seen)
    c.check('no variant reached the provider', all(not s['provider_saw'] for s in seen.values()))
    c.check('no variant answered 2xx', all(s['status'] is None or s['status'] >= 400 for s in seen.values()))
    c.check('forbidden target received nothing after the path variants', len(forbidden_hits()) == 0)


# ---- Mode C ---------------------------------------------------------------------------------------
@case('P1-MC-01', 'static gateway-attached credential (Mode C)',
      'works without a PDP call, but both tenants reach the provider as the same account', ('GW-AT-033', 'GW-FR-033'))
def _(c):
    b, g = gw('GET', RATES, blue()), gw('GET', RATES, green())
    hits = provider_hits()
    c.note('accounts', [body_json(b).get('account'), body_json(g).get('account')])
    c.check('both allowed', b['status'] == 200 and g['status'] == 200)
    c.check('both served as account-shared', body_json(b).get('account') == body_json(g).get('account') == 'account-shared')
    c.check('provider received the same static credential twice',
            [header(h['headers'], 'authorization') for h in hits] == [['Bearer ' + S.static_token]] * 2)
    c.check('PDP was not consulted', len(pdp_log()) == 0)
    c.check('caller JWT still required', gw('GET', RATES)['status'] == 401)
    c.check('caller JWT still not forwarded', all('eyJ' not in v for h in hits for _, v in h['headers']))


# ---- Mode B -----------------------------------------------------------------------------------------
def all_provider_credentials() -> list:
    return list(S.token.values()) + [S.static_token]


@case('P1-MB-01', 'local broker (Mode B): each tenant leaves with its own account',
      'the same isolation as Mode A, while Gatekeeper is asked for a decision only and nothing it sends contains a provider credential',
      ('GW-AT-006', 'GW-NAT-001', 'GW-AT-033', 'GW-FR-006', 'GW-FR-033'))
def _(c):
    expect_account(c, gw('GET', MANIFESTS + '/MAN-1', blue()), 'account-blue', '/v1/manifests/MAN-1')
    send(PORTS['provider'], 'POST', '/admin/reset', ADMIN(), b'')
    expect_account(c, gw('GET', MANIFESTS + '/MAN-2', green()), 'account-green', '/v1/manifests/MAN-2')
    log = pdp_log()
    answers = [e['gatekeeper'] for e in broker_log() if e.get('gatekeeper')]
    c.note('gatekeeper_was_asked', [{'target': e['raw_target'], 'by': e.get('peer_identity')} for e in log])
    c.check('Gatekeeper was asked once per request, on the decision endpoint only',
            [e['raw_target'] for e in log] == ['/v1/egress/authorizations/decision'] * 2)
    c.check('...by the broker workload, not the gateway', all(e.get('peer_identity') == pki.ID['broker'] for e in log))
    c.check('the broker recorded both answers', len(answers) == 2)
    c.check('no provider credential in the headers or body of anything Gatekeeper sent',
            not any(t in json.dumps(answers) for t in all_provider_credentials()))
    decisions = [body_json({'body': a.get('body', '')}) for a in answers]
    schema = json.loads((ROOT / 'contracts/gatekeeper/authz-decision.schema.json').read_text(encoding='utf-8'))
    c.check('both answers are valid DecisionResponse documents (contracts/gatekeeper/authz-decision.schema.json)',
            bool(decisions) and all(not list(Draft202012Validator(schema).iter_errors(d)) for d in decisions))
    c.note('credential_handles', [d.get('credential_handle') for d in decisions])


@case('P1-MB-02', 'Mode B: denial and revocation are still Gatekeeper\'s',
      'another tenant\'s account, a token for another environment and a revoked account are each refused on that request; nothing is forwarded',
      ('GW-AT-004', 'GW-AT-026', 'GW-AT-028', 'GW-ST-026', 'GW-FR-004', 'GW-FR-026', 'GW-FR-028'))
def _(c):
    def refused(label, r, reason):
        c.note(label, {'status': r['status'], 'reason_code': body_json(r).get('reason_code')})
        c.check(f'{label}: 403 {reason}', r['status'] == 403 and body_json(r).get('reason_code') == reason)
        c.check(f'{label}: provider received nothing', len(provider_hits()) == 0)

    refused('tenant-blue asks for account-green',
            gw('GET', MANIFESTS + '/MAN-1', blue(), [('X-Provider-Account', 'account-green')]), 'ACCOUNT_NOT_GRANTED')
    refused('token issued for PROD on the TEST pool', gw('GET', MANIFESTS + '/MAN-1', blue(env='PROD')), 'ENVIRONMENT_MISMATCH')
    pdp_admin('/admin/revoke?account=account-blue')
    refused('first blue request after account-blue is revoked', gw('GET', MANIFESTS + '/MAN-1', blue()), 'ACCOUNT_REVOKED')
    g = gw('GET', MANIFESTS + '/MAN-2', green())
    c.check('green still allowed with its own account', g['status'] == 200 and body_json(g).get('account') == 'account-green')
    pdp_admin('/admin/restore?account=account-blue')
    c.check('after restore: blue allowed again', gw('GET', MANIFESTS + '/MAN-1', blue())['status'] == 200)


@case('P1-MB-03', 'Mode B: Gatekeeper or the broker unavailable',
      'every such request is rejected and never reaches the provider (fail closed); service resumes when both are back',
      ('GW-ST-008', 'GW-NAT-006', 'GW-AT-047', 'GW-FR-047'))
def _(c):
    def refused(label):
        r = gw('GET', MANIFESTS + '/MAN-1', blue())
        c.note(label, {'status': r['status'], 'seconds': r['seconds']})
        c.check(f'{label}: not a success status', r['status'] is not None and r['status'] >= 400)
        c.check(f'{label}: provider received nothing', len(provider_hits()) == 0)

    pdp_admin('/admin/mode?value=error500')
    refused('Gatekeeper answers 500')
    pdp_admin('/admin/mode?value=slow')
    refused('Gatekeeper slower than the broker waits')
    stop('gateway-authz', PORTS['gatekeeper'])
    try:
        refused('Gatekeeper down')
    finally:
        start_gatekeeper()
    stop('broker', PORTS['broker'])
    try:
        refused('broker down')
    finally:
        start_broker()
    c.check('after both are back: allowed again', gw('GET', MANIFESTS + '/MAN-1', blue())['status'] == 200)


@case('P1-MB-04', 'another local process calls the broker directly',
      'without the gateway\'s local key: 401, no provider credential, and Gatekeeper is not even asked',
      ('GW-ST-018', 'GW-AT-021', 'GW-FR-021'))
def _(c):
    ctx = trusted_context('mockcarrier-manifests-get-broker', 'manifests.get', MANIFESTS + '/MAN-1')
    for label, auth in [('no key', []), ('wrong key', [('Authorization', 'Bearer not-the-gateway')]),
                        ('a valid caller JWT instead of the key', [('Authorization', 'Bearer ' + blue())])]:
        r = send(PORTS['broker'], 'GET', '/v1/extauthz/check', ctx + auth)
        c.check(f'{label}: 401', r['status'] == 401)
        c.check(f'{label}: no provider credential returned', not carries_credential(r))
    c.check('Gatekeeper was not asked', len(pdp_log()) == 0)
    # Control, and the limit of this stand-in: the key file is the only thing in the way.
    r = send(PORTS['broker'], 'GET', '/v1/extauthz/check', ctx + [('Authorization', 'Bearer ' + S.broker_key)])
    c.check('control: whoever presents the content of the key file is given a credential',
            r['status'] == 200 and carries_credential(r))


# ---- backendAuth.key.expression ------------------------------------------------------------------------
@case('P1-KX-01', 'credential placed by backendAuth.key.expression instead of header copying',
      'the same result as on the Mode A routes: each tenant leaves with exactly its own account\'s credential',
      ('GW-AT-006', 'GW-NAT-001', 'GW-AT-008', 'GW-FR-006', 'GW-FR-008'))
def _(c):
    tok = blue()
    r = gw('GET', PICKUPS + '/PCK-1', tok, [('Cookie', 'session=caller-session'), ('X-Provider-Account', 'account-blue')])
    expect_account(c, r, 'account-blue', '/v1/pickups/PCK-1')
    for h in provider_hits():
        names = sorted({k.lower() for k, _ in h['headers']})
        c.note('provider_saw_header_names', names)
        c.check('IDP JWT appears in no header value', all(tok not in v for _, v in h['headers']))
        c.check('no x-idp-*, x-provider-account or cookie header',
                not any(n.startswith('x-idp-') or n in ('x-provider-account', 'cookie') for n in names))
    c.check('no provider credential in what the caller received',
            not any(t in r['body'].decode(errors='replace') + json.dumps(r['headers']) for t in all_provider_credentials()))
    send(PORTS['provider'], 'POST', '/admin/reset', ADMIN(), b'')
    expect_account(c, gw('GET', PICKUPS + '/PCK-2', green()), 'account-green', '/v1/pickups/PCK-2')
    log = pdp_log()
    c.check('PDP consulted once per request, by the gateway workload',
            len(log) == 2 and all(e.get('peer_identity') == pki.ID['gateway'] for e in log))


@case('P1-KX-02', 'key.expression route: PDP allows but releases no credential',
      'the gateway itself refuses to forward; no Authorization header of any kind reaches the provider',
      ('GW-ST-009', 'GW-AT-043', 'GW-FR-006', 'GW-FR-043'))
def _(c):
    pdp_admin('/admin/mode?value=allow_without_credential')
    tok = blue()
    r = gw('GET', PICKUPS + '/PCK-1', tok)
    hits = provider_hits()
    c.note('status', r['status']); c.note('provider_hits', len(hits))
    c.note('rejected_by', 'provider' if header(r, 'x-mock-provider') else 'gateway')
    c.check('caller does not get a success', r['status'] is not None and r['status'] >= 400)
    c.check('caller JWT did not reach the provider', all(tok not in v for h in hits for _, v in h['headers']))
    c.check('no Authorization header reached the provider', all(header(h['headers'], 'authorization') == [] for h in hits))
    c.check('provider received nothing (rejected at the gateway)', len(hits) == 0)


@case('P1-KX-03', 'key.expression route: denial and revocation',
      'another tenant\'s account and a revoked account are each refused on that request; nothing is forwarded',
      ('GW-AT-004', 'GW-AT-026', 'GW-FR-004', 'GW-FR-026'))
def _(c):
    r = gw('GET', PICKUPS + '/PCK-1', blue(), [('X-Provider-Account', 'account-green')])
    c.check('tenant-blue asks for account-green: 403', r['status'] == 403)
    pdp_admin('/admin/revoke?account=account-blue')
    r = gw('GET', PICKUPS + '/PCK-1', blue())
    c.note('first_request_after_revoke', {'status': r['status'], 'reason_code': body_json(r).get('reason_code')})
    c.check('first blue request after revocation: 403', r['status'] == 403)
    c.check('provider received nothing in either case', len(provider_hits()) == 0)
    pdp_admin('/admin/restore?account=account-blue')
    c.check('after restore: blue allowed again', gw('GET', PICKUPS + '/PCK-1', blue())['status'] == 200)


# ---- a credential that is not a Bearer token: a developer token with a nonce (ADR-0011) -----------------
# gateway-authz builds `Hc-OweDeveloper account;token;nonce` from a second credentials file and a nonce it
# makes for each request. The gateway copies it as on the Mode A routes. These cases look at what the
# provider then receives. The mock provider refuses a nonce it has accepted before.
DEVELOPER_HEADER = re.compile(r'Hc-OweDeveloper ([^; ]+);([^; ]+);([0-9a-f]{32})')


def policy_binding(route_id: str) -> str:
    operations = json.loads((HERE / 'policy.poc.json').read_text(encoding='utf-8'))['registered_operations']
    return next(o['credential_binding_ref'] for o in operations if o['route_id'] == route_id)


def write_developer_tokens(pairs: dict, also: dict | None = None):
    """Replace gateway-authz's developer-token file the way it asks for: a new file, renamed over the old one."""
    binding = policy_binding(PARCELS_ROUTE)
    document = {f'{binding}/{account}': {'account': number, 'token': token} for account, (number, token) in pairs.items()}
    document.update(also or {})
    staged = DEVELOPER_TOKENS.with_name(DEVELOPER_TOKENS.name + '.next')
    staged.write_text(json.dumps(document), encoding='utf-8')
    os.chmod(staged, 0o600)
    os.replace(staged, DEVELOPER_TOKENS)


def developer_seen(hit: dict) -> tuple | None:
    """(account number, token, nonce) from the Authorization header of a request the provider recorded.
    None unless there is exactly one such header and it has that form."""
    given = header(hit['headers'], 'authorization')
    match = DEVELOPER_HEADER.fullmatch(given[0]) if len(given) == 1 else None
    return match.groups() if match else None


def developer_secrets() -> list:
    return [part for table in (S.developer, S.developer_next) for pair in table.values() for part in pair]


def developer_in(text: str) -> bool:
    """Any of this run's developer account numbers or tokens, or any Authorization value of that scheme."""
    return any(secret in text for secret in developer_secrets()) or re.search(r'Hc-OweDeveloper [^;\s"\']+;', text) is not None


@case('P1-DT-01', 'developer token with a nonce: each tenant leaves with its own account',
      'the provider receives "Hc-OweDeveloper account;token;nonce" for the tenant\'s own account, with a nonce not used before on every request; '
      'nothing of the caller\'s token reaches the provider and nothing of the credential reaches the caller',
      ('GW-AT-006', 'GW-NAT-001', 'GW-AT-008', 'GW-AT-033', 'GW-FR-006', 'GW-FR-008', 'GW-FR-033'))
def _(c):
    tok = blue()
    answers = [gw('GET', f'{PARCELS}/PRC-{n}', tok, [('Cookie', 'session=caller-session'), ('X-Provider-Account', 'account-blue')])
               for n in range(1, 6)]
    hits = provider_hits()
    seen = [developer_seen(h) for h in hits]
    names = sorted({k.lower() for h in hits for k, _ in h['headers']})
    c.note('statuses', [r['status'] for r in answers])
    c.note('provider_saw_target', [h['raw_target'] for h in hits])
    c.note('provider_saw_header_names', names)
    c.check('five requests, each answered 200 by the provider as account-blue',
            [(r['status'], body_json(r).get('account')) for r in answers] == [(200, 'account-blue')] * 5)
    c.check('provider received exactly those five, the logical path rewritten to the provider path',
            [h['raw_target'] for h in hits] == [f'/v1/parcels/PRC-{n}' for n in range(1, 6)])
    c.check('each carries exactly one Authorization header, "Hc-OweDeveloper account;token;nonce", the nonce 32 hexadecimal characters',
            len(seen) == 5 and all(seen))
    c.check('the account number and the token are account-blue\'s', all(s is not None and s[:2] == S.developer['account-blue'] for s in seen))
    c.check('the five nonces are all different', len({s[2] for s in seen if s}) == 5)
    c.check('IDP JWT appears in no header value', all(tok not in v for h in hits for _, v in h['headers']))
    c.check('no x-idp-*, x-provider-account or cookie header',
            not any(n.startswith('x-idp-') or n in ('x-provider-account', 'cookie') for n in names))
    c.check('nothing of the credential in what the caller received',
            not any(developer_in(r['body'].decode(errors='replace') + json.dumps(r['headers'])) for r in answers))
    send(PORTS['provider'], 'POST', '/admin/reset', ADMIN(), b'')
    g = gw('GET', PARCELS + '/PRC-9', green())
    hits = provider_hits()
    c.check('tenant-green: 200 as account-green, and the provider received account-green\'s account number and token',
            g['status'] == 200 and body_json(g).get('account') == 'account-green' and len(hits) == 1
            and (developer_seen(hits[0]) or ())[:2] == S.developer['account-green'])
    log = pdp_log()
    c.check('PDP consulted once per request, by the gateway workload',
            len(log) == 6 and all(e.get('peer_identity') == pki.ID['gateway'] for e in log))


@case('P1-DT-02', 'developer-token route: PDP allows but releases no credential, and the caller sends one of its own',
      'the gateway itself refuses to forward an uncredentialed request; an Authorization header the caller put beside its token '
      'is never what the provider receives',
      ('GW-ST-009', 'GW-AT-043', 'GW-ST-001', 'GW-FR-006', 'GW-FR-008', 'GW-FR-043'))
def _(c):
    tok = blue()
    planted = 'Hc-OweDeveloper PLANTED-BY-CALLER;planted-by-caller;' + '0' * 32
    orders = {'after its token': [('Authorization', 'Bearer ' + tok), ('Authorization', planted)],
              'before its token': [('Authorization', planted), ('Authorization', 'Bearer ' + tok)]}

    def with_planted(order: str) -> dict:   # not gw(): which of the two headers comes first is the point
        return send(PORTS['gateway'], 'GET', PARCELS + '/PRC-1', [('Host', LOGICAL_HOST)] + orders[order])

    pdp_admin('/admin/mode?value=allow_without_credential')
    r = gw('GET', PARCELS + '/PRC-1', tok)
    hits = provider_hits()
    c.note('status', r['status']); c.note('provider_hits', len(hits))
    c.note('rejected_by', 'provider' if header(r, 'x-mock-provider') else 'gateway')
    c.check('caller does not get a success', r['status'] is not None and r['status'] >= 400)
    c.check('provider received nothing (rejected at the gateway)', len(hits) == 0)
    for order in orders:
        r = with_planted(order)
        hits = provider_hits()
        c.note(f'no credential released, caller\'s own header {order}', {'status': r['status'], 'provider_hits': len(hits)})
        c.check(f'no credential released, caller\'s own header {order}: caller does not get a success',
                r['status'] is not None and r['status'] >= 400)
        c.check(f'no credential released, caller\'s own header {order}: provider received nothing', len(hits) == 0)
    pdp_admin('/admin/mode?value=normal')
    for order in orders:
        send(PORTS['provider'], 'POST', '/admin/reset', ADMIN(), b'')
        r = with_planted(order)
        hits = provider_hits()
        c.note(f'credential released, caller\'s own header {order}', {'status': r['status'], 'provider_hits': len(hits)})
        c.check(f'credential released, caller\'s own header {order}: what the caller put there reached the provider in no header',
                all('planted' not in v.lower() for h in hits for _, v in h['headers']))
        c.check(f'credential released, caller\'s own header {order}: a request that reached the provider carried account-blue\'s credential and no other',
                all((developer_seen(h) or ())[:2] == S.developer['account-blue'] for h in hits))
        c.check(f'credential released, caller\'s own header {order}: the caller token did not reach the provider',
                all(tok not in v for h in hits for _, v in h['headers']))


@case('P1-DT-03', 'developer-token route: denial and revocation',
      'another tenant\'s account and a revoked account are each refused on that request; nothing is forwarded',
      ('GW-AT-004', 'GW-AT-026', 'GW-FR-004', 'GW-FR-026'))
def _(c):
    r = gw('GET', PARCELS + '/PRC-1', blue(), [('X-Provider-Account', 'account-green')])
    c.check('tenant-blue asks for account-green: 403', r['status'] == 403)
    pdp_admin('/admin/revoke?account=account-blue')
    r = gw('GET', PARCELS + '/PRC-1', blue())
    c.note('first_request_after_revoke', {'status': r['status'], 'reason_code': body_json(r).get('reason_code')})
    c.check('first blue request after revocation: 403', r['status'] == 403)
    c.check('provider received nothing in either case', len(provider_hits()) == 0)
    g = gw('GET', PARCELS + '/PRC-2', green())
    c.check('green still allowed with its own account', g['status'] == 200 and body_json(g).get('account') == 'account-green')
    pdp_admin('/admin/restore?account=account-blue')
    c.check('after restore: blue allowed again', gw('GET', PARCELS + '/PRC-1', blue())['status'] == 200)


@case('P1-DT-04', 'developer-token route: the token file is replaced while gateway-authz runs',
      'the next request leaves with the new token, without a restart; a replacement that does not load, or that claims a handle '
      'the Bearer file already holds, changes nothing on either kind of route',
      ('GW-AT-018', 'GW-FR-018', 'GW-FR-006'))
def _(c):
    def at_provider(target: str) -> tuple:
        """One blue request -> (status, the account the provider answered as, the token it received)."""
        send(PORTS['provider'], 'POST', '/admin/reset', ADMIN(), b'')
        r = gw('GET', target, blue())
        hits = provider_hits()
        seen = developer_seen(hits[0]) if len(hits) == 1 else None
        return r['status'], body_json(r).get('account'), seen[1] if seen else None

    (number, first), rotated = S.developer['account-blue'], S.developer_next['account-blue'][1]
    process = PROCS['gateway-authz'].pid
    try:
        c.check('before: the provider receives the token gateway-authz started with', at_provider(PARCELS + '/PRC-1') == (200, 'account-blue', first))
        write_developer_tokens({**S.developer, 'account-blue': (number, rotated)})
        c.check('the file is replaced: the very next request leaves with the new token', at_provider(PARCELS + '/PRC-2') == (200, 'account-blue', rotated))
        g = gw('GET', PARCELS + '/PRC-3', green())
        c.check('green, whose entry did not change, is served as before', g['status'] == 200 and body_json(g).get('account') == 'account-green')

        write_developer_tokens({**S.developer, 'account-blue': (number, 'not a token; it has spaces and a semicolon')})
        c.check('replaced by a file that does not load: the next request leaves with the last token that loaded',
                at_provider(PARCELS + '/PRC-4') == (200, 'account-blue', rotated))
        held_as_bearer = policy_binding('mockcarrier-tracking-get') + '/account-blue'
        write_developer_tokens({**S.developer, 'account-blue': (number, first)}, also={held_as_bearer: {'account': number, 'token': first}})
        c.check('replaced by a file that also claims a handle the Bearer file holds: nothing changes on this route',
                at_provider(PARCELS + '/PRC-5') == (200, 'account-blue', rotated))
        send(PORTS['provider'], 'POST', '/admin/reset', ADMIN(), b'')
        r = gw('GET', TRACKING + '/TRK-1', blue())
        c.check('...nor on the Bearer route, which still leaves with account-blue\'s Bearer token',
                r['status'] == 200 and [header(h['headers'], 'authorization') for h in provider_hits()] == [['Bearer ' + S.token['account-blue']]])
    finally:
        write_developer_tokens(S.developer)
    c.check('the first file is put back: the next request leaves with the first token again', at_provider(PARCELS + '/PRC-6') == (200, 'account-blue', first))
    c.check('gateway-authz is the same process throughout', PROCS['gateway-authz'].pid == process and PROCS['gateway-authz'].poll() is None)
    said = (RUN / 'gateway-authz.log').read_text(encoding='utf-8', errors='replace')
    counts = {'loaded again': said.count('"msg":"developer tokens file loaded again"'),
              'did not load': said.count('"msg":"developer tokens file did not load')}
    c.note('gateway_authz_said', counts)
    c.check('gateway-authz said so each time: two files loaded, two did not', counts == {'loaded again': 2, 'did not load': 2})


@case('P1-DT-05', 'developer-token route: what the gateway and gateway-authz have written to their logs',
      'no developer account number or token and no Authorization value of that scheme in any line of either, including the lines '
      'for a credential the PDP did not release and for a token file that did not load',
      ('GW-AT-007', 'GW-FR-007', 'GW-NFR-05'))
def _(c):
    tok = blue()
    ok = gw('GET', PARCELS + '/PRC-1', tok)['status']
    pdp_admin('/admin/mode?value=allow_without_credential')   # makes the gateway log its own credential-handling failure on this route
    refused = gw('GET', PARCELS + '/PRC-1', tok)['status']
    time.sleep(0.5)
    logs = {name: (RUN / f'{name}.log').read_text(encoding='utf-8', errors='replace') for name in ('agentgateway', 'gateway-authz')}
    c.note('log_lines', {name: len(text.splitlines()) for name, text in logs.items()})
    c.check('the route answered 200, then a refusal, just before the logs were read', ok == 200 and refused is not None and refused >= 400)
    c.check('the gateway\'s log has lines for this route, served and refused',
            any(PARCELS_ROUTE in line and 'http.status=200' in line for line in logs['agentgateway'].splitlines())
            and any(PARCELS_ROUTE in line and 'http.status=200' not in line for line in logs['agentgateway'].splitlines()))
    c.check('gateway-authz\'s log has the lines for the token file that loaded and the one that did not',
            'developer tokens file loaded again' in logs['gateway-authz'] and 'developer tokens file did not load' in logs['gateway-authz'])
    for name, text in logs.items():
        c.check(f'{name}: no developer account number, no developer token, no Authorization value of that scheme', not developer_in(text))


# The third kind of refusal beside P1-FO-01's two: the PDP was asked and answered that it cannot decide.
# It comes after the developer-token cases because it replaces their token file, and P1-DT-04 counts
# every time gateway-authz has read that file.
@case('P1-FO-02', 'the PDP answers that it cannot decide',
      'holding no credential for an account its policy grants, gateway-authz answers 503 INDETERMINATE itself: the caller gets '
      'that answer and its reason, not a 403; nothing is forwarded; the other account is served',
      ('GW-AT-043', 'GW-ST-009', 'GW-FR-043', 'GW-FR-006'))
def _(c):
    try:
        write_developer_tokens({'account-green': S.developer['account-green']})
        mark = gateway_log_size()
        r = gw('GET', PARCELS + '/PRC-1', blue())
        answer = body_json(r)
        c.note('answer', {'status': r['status'], 'result': answer.get('result'), 'reason_code': answer.get('reason_code')})
        # Observation: next to the one P1-FO-01 records, the gateway's log line has the same shape.
        c.note('gateway_log_line_when_the_pdp_cannot_decide', gateway_logged(mark))
        c.check('503, and the answer is the PDP\'s own: INDETERMINATE, CREDENTIAL_UNAVAILABLE',
                r['status'] == 503 and answer.get('result') == 'INDETERMINATE' and answer.get('reason_code') == 'CREDENTIAL_UNAVAILABLE')
        c.check('the answer carries no credential', not carries_credential(r) and not developer_in(r['body'].decode(errors='replace') + json.dumps(r['headers'])))
        c.check('the provider received nothing', len(provider_hits()) == 0)
        g = gw('GET', PARCELS + '/PRC-2', green())
        c.check('green, whose credential it holds, is served', g['status'] == 200 and body_json(g).get('account') == 'account-green')
    finally:
        write_developer_tokens(S.developer)
    c.check('with the credential back: blue is served again', gw('GET', PARCELS + '/PRC-1', blue())['status'] == 200)


# ---- revocation through the product's own interface (ADR-0012) --------------------------------------------
# The cases above revoke through the controls that only the acceptance build has. These go the way a
# deployment would: a POST to gateway-authz from the one workload identity it was told may change its
# revocations. The table is a file of gateway-authz's own, so it has to outlive a restart, and
# gateway-authz must not start without it.
REVOCATIONS_PATH = '/v1/egress/revocations'
REVOKE_BLUE = {'account_id': 'account-blue', 'revoked': True, 'reason': 'black-box: credential reported leaked'}
RESTORE_BLUE = {'account_id': 'account-blue', 'revoked': False}


def revocations(method: str, change: dict | None = None, cert: str | None = 'revoker', headers=(), ca: str = 'ca') -> dict:
    """A call to gateway-authz's revocation interface under the named certificate. -> the response, as send() gives it."""
    body = json.dumps(change).encode() if change is not None else None
    return pdp(method, REVOCATIONS_PATH, JSON_CT + list(headers) if body else list(headers), body, cert=cert, ca=ca)


def revocation_table() -> tuple:
    """-> (revocation epoch, [account ids]) as the revoker reads them."""
    state = body_json(revocations('GET'))
    return state.get('revocation_epoch'), [a.get('account_id') for a in state.get('revoked_accounts') or []]


def refused_as_revoked(r: dict) -> bool:
    return r['status'] == 403 and body_json(r).get('reason_code') == 'ACCOUNT_REVOKED'


@case('P1-RV-02', 'an account is revoked through gateway-authz\'s own interface',
      'the next request for that account is refused on every route and not forwarded; the other account is unaffected; '
      'a mistyped account is an error, not a silent success; lifting the revocation lets the account through again',
      ('GW-AT-026', 'GW-ST-026', 'GW-AT-047', 'GW-FR-026', 'GW-FR-047'))
def _(c):
    epoch, accounts = revocation_table()
    c.note('epoch_before', epoch)
    c.check('before: nothing is revoked and blue is allowed', accounts == [] and gw('GET', TRACKING + '/TRK-1', blue())['status'] == 200)
    send(PORTS['provider'], 'POST', '/admin/reset', ADMIN(), b'')
    try:
        r = revocations('POST', REVOKE_BLUE)
        c.note('revoke', {'status': r['status'], 'body': body_json(r)})
        c.check('the revoker revokes account-blue: 200, the account is revoked, the epoch is one higher',
                r['status'] == 200 and body_json(r) == {'account_id': 'account-blue', 'revoked': True, 'changed': True, 'revocation_epoch': epoch + 1})
        for label, target in (('the Bearer route', TRACKING + '/TRK-1'), ('the developer-token route', PARCELS + '/PRC-1'),
                              ('the key.expression route', PICKUPS + '/PCK-1'), ('the Mode B route', MANIFESTS + '/MAN-1')):
            c.check(f'the very next blue request on {label}: 403 ACCOUNT_REVOKED', refused_as_revoked(gw('GET', target, blue())))
        c.check('...and the provider received none of them', len(provider_hits()) == 0)
        g = gw('GET', TRACKING + '/TRK-2', green())
        c.check('green still allowed with its own account', g['status'] == 200 and body_json(g).get('account') == 'account-green')

        r = revocations('POST', REVOKE_BLUE)
        c.check('revoking it again changes nothing: 200, not changed, the same epoch',
                r['status'] == 200 and body_json(r) == {'account_id': 'account-blue', 'revoked': True, 'changed': False, 'revocation_epoch': epoch + 1})
        state = body_json(revocations('GET'))
        c.note('table', state)
        row = (state.get('revoked_accounts') or [{}])[0]
        c.check('the table has that one account, with the identity that revoked it and the reason given',
                len(state.get('revoked_accounts') or []) == 1 and row.get('account_id') == 'account-blue'
                and row.get('revoked_by') == pki.ID['revoker'] and row.get('reason') == REVOKE_BLUE['reason'])
        r = revocations('POST', {'account_id': 'account-bleu', 'revoked': True, 'reason': 'black-box: a mistyped account'})
        c.note('mistyped', {'status': r['status'], 'body': body_json(r)})
        c.check('an account the policy does not name: 422 unknown_account, and nothing changes',
                r['status'] == 422 and body_json(r).get('error') == 'unknown_account' and revocation_table() == (epoch + 1, ['account-blue']))
        c.check('none of these answers carries a provider credential',
                not any(carries_credential(x) or developer_in(x['body'].decode(errors='replace')) for x in (r, revocations('GET'))))
    finally:
        lifted = revocations('POST', RESTORE_BLUE)
    c.check('the revocation is lifted: 200, the account is not revoked, the epoch is one higher again',
            lifted['status'] == 200 and body_json(lifted) == {'account_id': 'account-blue', 'revoked': False, 'changed': True, 'revocation_epoch': epoch + 2})
    c.check('blue is allowed again', gw('GET', TRACKING + '/TRK-1', blue())['status'] == 200)
    on_disk = json.loads(REVOCATIONS.read_text(encoding='utf-8'))
    c.check('the file gateway-authz keeps says the same: nothing revoked, at that epoch', on_disk == {'epoch': epoch + 2, 'revoked_accounts': {}})
    said = (RUN / 'gateway-authz.log').read_text(encoding='utf-8', errors='replace')
    c.check('gateway-authz logged the revocation with who made it and why',
            any('"msg":"egress revocation"' in line and '"action":"revoke"' in line and pki.ID['revoker'] in line
                and REVOKE_BLUE['reason'] in line for line in said.splitlines()))


@case('P1-RV-03', 'who may change the revocations',
      'only the revoker\'s workload certificate: every other workload of the trust domain is answered 401 and is told nothing, '
      'without a certificate of the workload CA there is no TLS session, and nothing changes',
      ('GW-ST-018', 'GW-AT-021', 'GW-FR-021', 'GW-FR-047'))
def _(c):
    c.check('the revoker revokes account-blue', revocations('POST', REVOKE_BLUE)['status'] == 200)
    before = revocation_table()
    try:
        revoke_green = {'account_id': 'account-green', 'revoked': True, 'reason': 'black-box: not this workload\'s to revoke'}
        attempts = (('read the table', 'GET', None), ('lift the revocation', 'POST', RESTORE_BLUE), ('revoke another account', 'POST', revoke_green))
        for label, cert, extra in [('the gateway, which is given credentials', 'gateway', []), ('the local broker', 'broker', []),
                                   ('a business app', 'business-app', []), ('the publisher', 'publisher', []),
                                   ('this suite\'s operator, with the secret of the acceptance controls', 'operator', ADMIN())]:
            answers = [revocations(method, change, cert=cert, headers=extra) for _, method, change in attempts]
            c.note(label, [r['status'] for r in answers])
            c.check(f'{label}: 401 to each of {", ".join(what for what, _, _ in attempts)}', all(r['status'] == 401 for r in answers))
            c.check(f'{label}: told nothing of the table', not any(b'account-blue' in r['body'] for r in answers))
        for label, cert, ca in [('no client certificate', None, 'ca'),
                                ('a certificate with the revoker\'s identity from another CA', 'rogue-revoker', 'ca')]:
            r = revocations('POST', RESTORE_BLUE, cert=cert, ca=ca)
            c.check(f'{label}: no HTTP response', r['status'] is None)
        c.check('after all of that the table and the epoch are as they were', revocation_table() == before)
        c.check('...blue is still refused, green still served',
                refused_as_revoked(gw('GET', TRACKING + '/TRK-1', blue())) and gw('GET', TRACKING + '/TRK-2', green())['status'] == 200)
        # The other way round: the revoker's certificate is good for this and for nothing else.
        asked = pdp('GET', '/v1/extauthz/check', trusted_context('mockcarrier-tracking-get', 'tracking.get', TRACKING + '/TRK-2'), cert='revoker')
        c.check('the revoker is given no decision and no credential', asked['status'] == 401 and not carries_credential(asked))
    finally:
        revocations('POST', RESTORE_BLUE)
    c.check('the revoker lifts the revocation: blue allowed again', gw('GET', TRACKING + '/TRK-1', blue())['status'] == 200)


@case('P1-RV-04', 'a revocation outlives a restart of gateway-authz',
      'after the restart the account is still refused, the epoch has not started again, and the table still says who revoked it and why',
      ('GW-AT-026', 'GW-AT-047', 'GW-FR-026', 'GW-FR-047'))
def _(c):
    r = revocations('POST', REVOKE_BLUE)
    epoch = body_json(r).get('revocation_epoch')
    c.note('epoch_at_revocation', epoch)
    c.check('the revoker revokes account-blue', r['status'] == 200 and isinstance(epoch, int) and epoch > 0)
    try:
        process = PROCS['gateway-authz'].pid
        stop('gateway-authz', PORTS['gatekeeper'])
        start_gatekeeper()
        c.check('gateway-authz is another process now', PROCS['gateway-authz'].pid != process)
        r = gw('GET', TRACKING + '/TRK-1', blue())
        c.note('first_request_after_restart', {'status': r['status'], 'reason_code': body_json(r).get('reason_code'),
                                               'revocation_epoch': body_json(r).get('revocation_epoch')})
        c.check('first blue request after the restart: 403 ACCOUNT_REVOKED', refused_as_revoked(r))
        c.check('...and the provider did not receive it', len(provider_hits()) == 0)
        c.check('the epoch is the one from before the restart, not 0', body_json(r).get('revocation_epoch') == epoch)
        state = body_json(revocations('GET'))
        row = (state.get('revoked_accounts') or [{}])[0]
        c.check('the table read after the restart still has the account, who revoked it and why',
                state.get('revocation_epoch') == epoch and len(state.get('revoked_accounts') or []) == 1 and row.get('account_id') == 'account-blue'
                and row.get('revoked_by') == pki.ID['revoker'] and row.get('reason') == REVOKE_BLUE['reason'])
        g = gw('GET', TRACKING + '/TRK-2', green())
        c.check('green is served after the restart', g['status'] == 200 and body_json(g).get('account') == 'account-green')
    finally:
        if 'gateway-authz' not in PROCS:
            start_gatekeeper()
        revocations('POST', RESTORE_BLUE)
    c.check('the revocation is lifted: blue allowed again', gw('GET', TRACKING + '/TRK-1', blue())['status'] == 200)


@case('P1-RV-05', 'gateway-authz without a revocation file it can read',
      'it does not start, so every request is rejected at the gateway; a missing file is not read as "nothing revoked"; '
      'with the file back it starts and the earlier revocation is still in force',
      ('GW-ST-008', 'GW-NAT-006', 'GW-AT-047', 'GW-FR-026', 'GW-FR-047'))
def _(c):
    c.check('the revoker revokes account-blue', revocations('POST', REVOKE_BLUE)['status'] == 200)
    kept = REVOCATIONS.with_name(REVOCATIONS.name + '.kept')
    stop('gateway-authz', PORTS['gatekeeper'])
    os.replace(REVOCATIONS, kept)
    try:
        def put(content: bytes, mode: int):
            REVOCATIONS.write_bytes(content)
            os.chmod(REVOCATIONS, mode)

        for label, arrange in (('the file is missing', lambda: None),
                               ('the file is cut short', lambda: put(kept.read_bytes()[:40], 0o600)),
                               ('the file says nothing of the table', lambda: put(b'{"epoch": 0}\n', 0o600)),
                               ('the file is readable by others', lambda: put(kept.read_bytes(), 0o644))):
            REVOCATIONS.unlink(missing_ok=True)
            arrange()
            tried = gatekeeper_refuses_to_start()
            c.note(label, tried)
            c.check(f'{label}: gateway-authz gives up instead of listening',
                    tried['exited'] not in (None, 0) and 'revocations' in tried['said'] and not port_open(PORTS['gatekeeper']))
        tok = green()
        r = gw('GET', TRACKING + '/TRK-2', tok)
        c.note('status_while_it_is_not_running', r['status'])
        c.check('while it is not running a request for an account that was never revoked is rejected too',
                r['status'] is not None and r['status'] >= 400)
        c.check('...and the provider received nothing', len(provider_hits()) == 0)
    finally:
        REVOCATIONS.unlink(missing_ok=True)
        os.replace(kept, REVOCATIONS)
        os.chmod(REVOCATIONS, 0o600)
        start_gatekeeper()
    try:
        c.check('with the file back gateway-authz starts, and blue is still refused as revoked',
                refused_as_revoked(gw('GET', TRACKING + '/TRK-1', blue())))
        g = gw('GET', TRACKING + '/TRK-2', green())
        c.check('green is served again', g['status'] == 200 and body_json(g).get('account') == 'account-green')
    finally:
        revocations('POST', RESTORE_BLUE)
    c.check('the revocation is lifted: blue allowed again', gw('GET', TRACKING + '/TRK-1', blue())['status'] == 200)


# ---- reading back what a publisher has published -----------------------------------------------------
# A publisher replaces the file the gateway runs from and has to learn, per instance, whether
# the new file is what is now in effect (G03 §3-4). These cases replace the file under the
# gateway that all the cases run against, and put the reviewed one back before they return.
ZONES = '/providers/mockcarrier/v1/zones'   # served only while P1-RB-01 has it published


def config_with_one_more_route(broken: bool = False) -> bytes:
    """The reviewed configuration plus a copy of the Mode C route under another path. With
    broken, a second copy follows that carries a field no route has: a file the gateway cannot load."""
    doc = yaml.safe_load(CONFIG.read_bytes())
    static = next(r for r in doc['routes'] if r['name'] == 'mockcarrier-rates-get-static')
    for name, segment, unknown in [('readback', 'zones', False)] + ([('unloadable', 'depots', True)] if broken else []):
        extra = copy.deepcopy(static)
        extra['name'] = f'mockcarrier-{segment}-get-{name}'
        extra['matches'][0]['path']['pathPrefix'] = f'/providers/mockcarrier/v1/{segment}'
        extra['policies']['urlRewrite']['path']['prefix'] = f'/v1/{segment}'
        if unknown:
            extra['notAFieldOfARoute'] = True
        doc['routes'].append(extra)
    return yaml.safe_dump(doc, sort_keys=False).encode()


def publish(configuration: bytes):
    """Replace the file the gateway under test was started from, as a publisher would."""
    RUN_CONFIG.write_bytes(configuration)


def reload_state() -> dict:
    """What the gateway says about its last attempt to load its file."""
    return body_json(admin_api('GET', '/api/runtime')).get('configReload') or {}


def wait_until(predicate, seconds: float = 6.0) -> float | None:
    """-> how long it took for predicate() to hold, None if it did not within the time given."""
    started = time.monotonic()
    while time.monotonic() - started < seconds:
        if predicate():
            return round(time.monotonic() - started, 2)
        time.sleep(0.1)
    return None


def zones_reaches_the_provider(tok: str) -> bool:
    return header(gw('GET', ZONES + '/Z-1', tok), 'x-mock-provider') == ['mockcarrier']


@case('P1-RB-01', 'the published file is replaced by one with one more route',
      'the new route is served without a restart; the gateway reports the reload as applied, and what it reports '
      'running changes with the file and returns when the file does',
      ('GW-AT-014', 'GW-FR-014', 'GW-AT-041', 'GW-FR-041', 'GW-NAT-004', 'GW-NFR-04'))
def _(c):
    tok = blue()
    published = config_dump_digest()
    r = gw('GET', ZONES + '/Z-1', tok)
    c.check('before: the extra path has no route', r['status'] == 404 and header(r, 'x-mock-provider') == [] and not provider_hits())
    try:
        publish(config_with_one_more_route())
        took = wait_until(lambda: zones_reaches_the_provider(tok))
        c.note('seconds_until_the_new_route_was_served', took)
        c.check('the new route is served, with no restart', took is not None)
        c.check('the provider received the request under the rewritten path',
                any(h['raw_target'] == '/v1/zones/Z-1' for h in provider_hits()))
        c.check('the gateway reports the reload as applied', reload_state() == {'synchronized': True, 'lastError': None})
        c.check('what the gateway reports running has changed', config_dump_digest() not in (None, published))
        c.check('a route that was there before still works', gw('GET', TRACKING + '/TRK-1', tok)['status'] == 200)
    finally:
        publish(S.config_bytes)
        gone = wait_until(lambda: gw('GET', ZONES + '/Z-1', tok)['status'] == 404 and not zones_reaches_the_provider(tok))
    c.note('seconds_until_the_route_was_gone_again', gone)
    c.check('with the reviewed file back, the extra route is gone', gone is not None)
    c.check('what the gateway reports running is again what it was', published is not None and config_dump_digest() == published)
    c.check('the file is byte-identical to the reviewed configuration', RUN_CONFIG.read_bytes() == S.config_bytes == CONFIG.read_bytes())


@case('P1-RB-02', 'the published file is replaced by one the gateway cannot load',
      'the gateway says so, with a reason; it keeps serving the last configuration it accepted, serves nothing from '
      'the rejected file, and still reports the accepted one as running',
      ('GW-AT-014', 'GW-FR-014', 'GW-ST-016', 'GW-AT-039', 'GW-FR-039', 'GW-AT-041', 'GW-FR-041'))
def _(c):
    tok = blue()
    published = config_dump_digest()
    try:
        publish(config_with_one_more_route(broken=True))
        took = wait_until(lambda: reload_state().get('synchronized') is False)
        state = reload_state()
        c.note('seconds_until_the_failure_was_reported', took)
        c.note('configReload', state)
        c.check('the gateway reports that the reload failed', took is not None)
        c.check('...with a reason', bool(state.get('lastError')))
        c.check('routes of the last accepted configuration still work',
                gw('GET', TRACKING + '/TRK-1', tok)['status'] == 200 and gw('GET', RATES, tok)['status'] == 200)
        # The rejected file also holds a route there is nothing wrong with. Nothing of the file may be in effect.
        r = gw('GET', ZONES + '/Z-1', tok)
        c.check('the loadable route in the rejected file is not served either', r['status'] == 404 and header(r, 'x-mock-provider') == [])
        c.check('what the gateway reports running is still the accepted configuration', published is not None and config_dump_digest() == published)
        # Observation, not a check: this endpoint shows the file, not what is in effect.
        c.note('api_config_effective_shows_the_rejected_file', b'notAFieldOfARoute' in admin_api('GET', '/api/config/effective')['body'])
    finally:
        publish(S.config_bytes)
        back = wait_until(lambda: reload_state().get('synchronized') is True)
    c.note('seconds_until_the_reload_was_reported_applied_again', back)
    c.check('with the reviewed file back, the gateway reports the reload as applied', back is not None)
    c.check('...and reports the same configuration as running', published is not None and config_dump_digest() == published)
    c.check('the file is byte-identical to the reviewed configuration', RUN_CONFIG.read_bytes() == S.config_bytes == CONFIG.read_bytes())


# What the admin address offers besides the two documents a publisher needs. The first three
# are the ones that do something: stop the gateway, change its log level, change its
# configuration. None of it may be reachable through the read-back listener, whoever asks.
ADMIN_ONLY = [('POST', '/quitquitquit'), ('POST', '/logging?level=debug'), ('PUT', ADMIN_WRITE[0]),
              ('GET', '/quitquitquit'), ('GET', '/debug/trace'), ('GET', '/debug/tasks'), ('GET', '/memory'), ('GET', '/debug/pprof/heap'),
              ('GET', '/debug/pprof/profile?seconds=1'), ('GET', '/ui'), ('GET', '/api/config/effective'), ('POST', '/config_dump'),
              ('GET', '/config_dump/'), ('GET', '/config_dump/../quitquitquit'), ('GET', '/api/runtime/'), ('GET', '/api')]


@case('P1-RB-03', 'the read-back listener: what a publisher can read from this instance, and nothing else',
      'with the publisher\'s certificate: the running configuration and the state of the last load, as the admin address gives them; '
      'no other path or method of the admin address; no answer to any other caller, with or without a certificate',
      ('GW-AT-041', 'GW-FR-041', 'GW-AT-014', 'GW-FR-014', 'GW-NAT-004', 'GW-NFR-04', 'GW-AT-046', 'GW-FR-046'))
def _(c):
    local = admin_api('GET', '/config_dump')
    r = readback('GET', '/config_dump')
    c.note('status', r['status'])
    c.check('the publisher reads /config_dump: 200', r['status'] == 200)
    c.check('...and it is the document the admin address gives', bool(body_json(r)) and body_json(r) == body_json(local))
    runtime = readback('GET', '/api/runtime')
    c.check('the publisher reads /api/runtime: the last load is reported as applied',
            runtime['status'] == 200 and body_json(runtime).get('configReload') == {'synchronized': True, 'lastError': None})
    both = r['body'].decode(errors='replace') + runtime['body'].decode(errors='replace')
    c.check('neither document holds a credential, a key or a secret of this run',
            'PRIVATE KEY' not in both and not any(s in both for s in all_provider_credentials() + [S.broker_key, S.session_key, S.admin]))

    elsewhere = {f'{method} {path}': readback(method, path)['status'] for method, path in ADMIN_ONLY}
    c.note('the_rest_of_the_admin_address', elsewhere)
    c.check('every other path or method of the admin address: 404, with the publisher\'s certificate too', set(elsewhere.values()) == {404})
    egress = readback('GET', TRACKING + '/TRK-1', host=LOGICAL_HOST, headers=[('Authorization', 'Bearer ' + blue())])
    c.check('the egress routes are not served on this listener', egress['status'] == 404 and not provider_hits())
    here = gw('GET', '/config_dump', blue())
    c.check('the read-back route is not served on the callers\' listener', here['status'] == 404 and b'"binds"' not in here['body'])

    others = {who: readback('GET', '/config_dump', cert=who) for who in ('operator', 'business-app', 'gateway', 'broker')}
    c.note('other_workloads_of_the_same_ca', {who: got['status'] if got['status'] is not None else got.get('error', '')[:70] for who, got in others.items()})
    c.check('another workload of the same CA gets no answer', all(got['status'] is None for got in others.values()))
    without, rogue = readback('GET', '/config_dump', cert=None), readback('GET', '/config_dump', cert='rogue-publisher')
    c.note('no_certificate', without.get('error', '')[:70]); c.note('certificate_of_another_ca', rogue.get('error', '')[:70])
    c.check('no client certificate: no answer', without['status'] is None)
    c.check('the publisher\'s name on a certificate of another CA: no answer', rogue['status'] is None)
    c.check('after all of that the gateway is running and serving', gw('GET', TRACKING + '/TRK-1', blue())['status'] == 200)


# ---- where the gateway listens --------------------------------------------------------------------------
@case('P1-NL-01', 'which addresses the gateway listens on',
      'the callers\' port, admin, stats and readiness are on loopback only, so the front proxy beside the gateway is the only way in; '
      'the one port other machines can reach is the read-back listener',
      ('GW-ST-017', 'GW-FR-005', 'GW-AT-046', 'GW-FR-046'))
def _(c):
    bound = listening()
    c.note('listening', {name: bound.get(PORTS[name]) for name in ('gateway', 'admin', 'stats', 'readiness', 'readback')})
    for name in ('gateway', 'admin', 'stats', 'readiness'):
        c.check(f'the {name} port is bound to loopback and to nothing else', bound.get(PORTS[name]) == ['127.0.0.1'])
    other = another_address_of_this_host()   # the address itself is not recorded
    c.note('this_host_has_an_address_that_is_not_loopback', other is not None)
    if other:
        c.check('a connection to the callers\' port on that address is refused', connect_errno(other, PORTS['gateway']) == errno.ECONNREFUSED)
        c.check('...and so is one to the admin port', connect_errno(other, PORTS['admin']) == errno.ECONNREFUSED)
        c.check('the read-back port accepts a connection there', connect_errno(other, PORTS['readback']) == 0)
    c.check('through the front proxy the route is served', front('GET', TRACKING + '/TRK-1', blue())['status'] == 200)


# ---- the gateway's own log ----------------------------------------------------------------------------
@case('P1-CR-04', 'what the gateway has written to its log during this run',
      'no provider credential, caller JWT, broker key or session key in any line, including the lines for failed credential handling',
      ('GW-AT-007', 'GW-FR-007', 'GW-NFR-05'))
def _(c):
    tok = blue()
    routes = [TRACKING + '/TRK-1', MANIFESTS + '/MAN-1', RATES, PICKUPS + '/PCK-1']
    ok = [gw('GET', t, tok)['status'] for t in routes]
    pdp_admin('/admin/mode?value=allow_without_credential')   # makes the gateway log its own credential-handling failures
    for t in routes:
        gw('GET', t, tok)
    time.sleep(0.5)
    log = (RUN / 'agentgateway.log').read_text(encoding='utf-8', errors='replace')
    c.note('log_lines', len(log.splitlines())); c.note('routes_exercised', len(routes))
    c.check('every route answered 200 just before the log was read', ok == [200] * len(routes))
    c.check('the log covers the run (more lines than there are cases)', len(log.splitlines()) > len(CASES))
    c.check('no provider credential', not any(t in log for t in all_provider_credentials()))
    c.check('no caller JWT', tok not in log and 'eyJ' not in log)
    c.check('no broker key and no session key', S.broker_key not in log and S.session_key not in log)


# ---- configuration integrity --------------------------------------------------------------------------
@case('P1-CF-02', 'a write to the configuration through the gateway\'s own admin API',
      'refused: what the gateway is running and the file it was started from stay as published; '
      'nor does the gateway write a generated session key into that file',
      ('GW-AT-046', 'GW-FR-046', 'GW-AT-044', 'GW-FR-044', 'GW-NAT-004', 'GW-NFR-04'))
def _(c):
    before = config_dump_digest()
    c.check('the gateway reports what it is running (/config_dump), the same on two reads',
            before is not None and config_dump_digest() == before)
    r = admin_api('PUT', *ADMIN_WRITE)
    c.note('status', r['status'])
    c.note('storage_mode_the_gateway_reports', (body_json(admin_api('GET', '/api/runtime')).get('ui') or {}).get('configStoreMode'))
    c.check('the write is refused', r['status'] is not None and 400 <= r['status'] <= 499)
    time.sleep(0.5)
    c.check('what the gateway is running is unchanged', config_dump_digest() == before)
    c.check('the resource was not stored',
            ADMIN_WRITE[1]['resources'][0]['value']['name'] not in admin_api('GET', ADMIN_WRITE[0])['body'].decode(errors='replace'))
    c.check('the file the gateway was started from is unchanged', RUN_CONFIG.read_bytes() == S.config_bytes == CONFIG.read_bytes())
    c.check('started with no session key, the gateway did not write one into its file either', S.read_only_start_rewrites is False)
    c.check('the gateway is serving', gw('GET', TRACKING + '/TRK-1', blue())['status'] == 200)


@case('P1-CF-01', 'the gateway and its own configuration file',
      'given its session key through the environment, the gateway leaves the file it was started from byte-identical to the reviewed configuration',
      ('GW-NAT-004', 'GW-AT-014', 'GW-NFR-04', 'GW-FR-014'))
def _(c):
    # Observation, not a check: what the same binary does when nobody supplies a session key.
    c.note('start_without_session_key_rewrites_config_file', S.default_start_rewrites)
    c.note('reviewed_configuration', 'tests/acceptance/blackbox/agentgateway.poc.yaml')
    c.check('the file the gateway is running from is byte-identical to the reviewed configuration',
            RUN_CONFIG.read_bytes() == S.config_bytes == CONFIG.read_bytes())
    c.check('the gateway is serving while this is checked', gw('GET', TRACKING + '/TRK-1', blue())['status'] == 200)


# ---- one call, matched at both ends ------------------------------------------------------------------
# Development plan 3.3. From the reference number in a create call's body, the logs alone lead to the gateway's
# line for that call, gateway-authz's decision for it, and the provider's process number. The access log fields
# (frontendPolicies.accessLog.add in the configuration) are the means; what they leave out is pinned here too.
def gateway_request_lines(since: int = 0) -> list[str]:
    time.sleep(0.5)
    with open(RUN / 'agentgateway.log', 'rb') as f:
        f.seek(since)
        return [l for l in f.read().decode(errors='replace').splitlines() if '\trequest ' in l]


def gateway_all_lines(since: int = 0) -> list[str]:
    time.sleep(0.5)
    with open(RUN / 'agentgateway.log', 'rb') as f:
        f.seek(since)
        return f.read().decode(errors='replace').splitlines()


def line_fields(line: str) -> dict:
    """key=value pairs of a gateway line; a quoted value is kept as written (escapes not undone)."""
    return {m[2]: m[3][1:-1] if m[3].startswith('"') else m[3]
            for m in re.finditer(r'(^|\s)([A-Za-z0-9_.]+)=("(?:[^"\\]|\\.)*"|\S+)', line)}


def authz_log_size() -> int:
    return (RUN / 'gateway-authz.log').stat().st_size


def authz_decisions(since: int = 0) -> list[dict]:
    """The "egress authorization" lines gateway-authz wrote after byte `since`."""
    time.sleep(0.3)
    with open(RUN / 'gateway-authz.log', 'rb') as f:
        f.seek(since)
        lines = f.read().decode(errors='replace').splitlines()
    found = []
    for l in lines:
        try:
            d = json.loads(l)
        except ValueError:
            continue
        if d.get('msg') == 'egress authorization':
            found.append(d)
    return found


def new_reference() -> str:
    return 'CO-' + secrets.token_hex(5)


def create_body(reference=None, **more) -> bytes:
    doc = {'shipmentReference': 'DEMO-SHP-1024', 'weight': {'value': 1.2, 'unit': 'KG'}}
    if reference is not None:
        doc['ReferenceId'] = reference
    doc.update(more)
    return json.dumps(doc).encode()


def lines_with(text: str, lines: list[str]) -> list[str]:
    return [l for l in lines if text in l]


@case('P1-CO-01', 'a create call, found from its reference number alone',
      'exactly one gateway line carries the reference number; it names the gateway-authz decision, the tenant and the provider\'s '
      'process number, and the decision is the one line gateway-authz wrote for this call',
      ('GW-FR-017',))
def _(c):
    ref = new_reference()
    body = create_body(ref)
    mark_gw, mark_az = gateway_log_size(), authz_log_size()
    r = gw('POST', LABELS, blue(), JSON_CT, body)
    answer = body_json(r)
    process = (answer.get('Data') or {}).get('ProcessCode')
    c.check('201, with a process number and the reference number in the answer',
            r['status'] == 201 and isinstance(process, str) and process != '' and (answer.get('Data') or {}).get('ReferenceId') == ref)
    lines = gateway_all_lines()
    mine = lines_with(ref, lines)
    c.note('gateway_lines_with_the_reference_number', len(mine))
    c.check('the gateway log has exactly one line with the reference number', len(mine) == 1)
    f = line_fields(mine[0]) if mine else {}
    c.note('gateway_line_fields', {k: f.get(k) for k in ('route', 'http.status', 'authz_decision_id', 'tenant_ref',
                                                           'provider_reference_id', 'provider_request_id')})
    decision = f.get('authz_decision_id')
    c.check('that line has the decision id', bool(decision))
    c.check('...the tenant from the caller\'s token', f.get('tenant_ref') == 'tenant-blue')
    c.check('...the provider\'s process number, the one the caller received', process is not None and f.get('provider_request_id') == process)
    c.check('...the reference number as a field', f.get('provider_reference_id') == ref)
    c.check('...and the route is the create route', f.get('route') == 'default/mockcarrier-labels-create')
    ours = [d for d in authz_decisions() if d.get('decision_id') == decision] if decision else []
    c.note('gateway_authz_lines_with_the_decision', len(ours))
    c.check('gateway-authz has exactly one "egress authorization" line with that decision id', len(ours) == 1)
    if ours:
        d = ours[0]
        c.check('...it is an ALLOW', d.get('result') == 'ALLOW')
        c.check('...for this route, tenant and operation',
                (d.get('route_id'), d.get('tenant'), d.get('operation_id')) == ('mockcarrier-labels-create', 'tenant-blue', 'labels.create'))
    c.check('the provider received the request', len(provider_hits()) == 1 and
            hashlib.sha256(body).hexdigest() == provider_hits()[0]['body_sha256'])


@case('P1-CO-02', 'two tenants create one call each',
      'each reference number leads to its own decision and process number; nothing is crossed',
      ('GW-FR-017', 'GW-NAT-001'))
def _(c):
    refs = {'tenant-blue': new_reference(), 'tenant-green': new_reference()}
    tokens = {'tenant-blue': blue(), 'tenant-green': green()}
    answers = {t: gw('POST', LABELS, tokens[t], JSON_CT, create_body(refs[t])) for t in refs}
    c.check('both answered 201', all(a['status'] == 201 for a in answers.values()))
    lines = gateway_all_lines()
    seen = {}
    for tenant, ref in refs.items():
        mine = lines_with(ref, lines)
        c.check(f'{tenant}: exactly one gateway line with its reference number', len(mine) == 1)
        f = line_fields(mine[0]) if mine else {}
        seen[tenant] = f
        process = (body_json(answers[tenant]).get('Data') or {}).get('ProcessCode')
        c.check(f'{tenant}: the line has its tenant and the process number its caller received',
                f.get('tenant_ref') == tenant and process is not None and f.get('provider_request_id') == process)
        d = [x for x in authz_decisions() if x.get('decision_id') == f.get('authz_decision_id')]
        c.check(f'{tenant}: the decision id is one line at gateway-authz, for that tenant, with that tenant\'s account',
                len(d) == 1 and d[0].get('tenant') == tenant and d[0].get('account') == body_json(answers[tenant]).get('account'))
    c.check('the two lines have different decision ids and different process numbers',
            seen['tenant-blue'].get('authz_decision_id') != seen['tenant-green'].get('authz_decision_id')
            and seen['tenant-blue'].get('provider_request_id') != seen['tenant-green'].get('provider_request_id'))


@case('P1-CO-03', 'the Mode B route and the other GET routes that ask the PDP',
      'the line has the decision id and the tenant, and that decision is found at gateway-authz; there is no reference number '
      'or process number on a call that has none',
      ('GW-FR-017',))
def _(c):
    tok = blue()
    calls = {'tracking (Mode A)': (TRACKING, 'mockcarrier-tracking-get'), 'manifests (Mode B, local broker)': (MANIFESTS, 'mockcarrier-manifests-get-broker'),
             'pickups (key.expression)': (PICKUPS, 'mockcarrier-pickups-get-expression'),
             'parcels (developer token)': (PARCELS, 'mockcarrier-parcels-get-developer-token')}
    for name, (prefix, route) in calls.items():
        unique = 'CO3' + secrets.token_hex(4).upper()
        r = gw('GET', f'{prefix}/{unique}', tok)
        mine = lines_with(f'/{unique} ', gateway_request_lines())
        f = line_fields(mine[0]) if len(mine) == 1 else {}
        c.check(f'{name}: 200 and exactly one line', r['status'] == 200 and len(mine) == 1)
        decision = f.get('authz_decision_id')
        c.check(f'{name}: the line has the decision id, the tenant and the route',
                bool(decision) and f.get('tenant_ref') == 'tenant-blue' and f.get('route') == 'default/' + route)
        c.check(f'{name}: no reference number and no process number', 'provider_reference_id' not in f and 'provider_request_id' not in f)
        d = [x for x in authz_decisions() if x.get('decision_id') == decision] if decision else []
        c.check(f'{name}: exactly one gateway-authz line with that decision id, an ALLOW for this route', len(d) == 1 and
                d[0].get('result') == 'ALLOW' and d[0].get('route_id') == route)
        if d:
            c.note(f'{name}: the gateway-authz line', {'endpoint': d[0].get('endpoint'), 'caller': d[0].get('caller')})


@case('P1-CO-04', 'a reference number that is not of the accepted form',
      'one line for each call; the log has (malformed) or no such field, and none of what the caller put there; the provider '
      'receives the body byte for byte; the caller gets its answer',
      ('GW-FR-017', 'GW-NFR-05'))
def _(c):
    quote = 'x"y\nz\tCO-forged-line level=ERROR'
    variants = {'a string with a quote and a newline': quote, 'a string of 5000 characters': 'A' * 5000,
                'a number': 123456789, 'an object': {'a': 1}, 'an empty string': ''}
    for name, value in variants.items():
        body = create_body(value)
        mark = gateway_log_size()
        r = gw('POST', LABELS, blue(), JSON_CT, body)
        lines = gateway_all_lines(mark)
        reqs = [l for l in lines if '\trequest ' in l]
        f = line_fields(reqs[-1]) if reqs else {}
        c.note(f'{name}: the logged value', f.get('provider_reference_id', '(no such field)'))
        c.check(f'{name}: 201 for the caller', r['status'] == 201)
        c.check(f'{name}: the gateway log grew by exactly one line', len(lines) == 1 and len(reqs) == 1)
        c.check(f'{name}: it says (malformed) or has no such field', f.get('provider_reference_id') in ('(malformed)', None))
        c.check(f'{name}: nothing of what the caller put there is in the line',
                'forged-line' not in lines[0] and 'AAAAA' not in lines[0] and '123456789' not in lines[0] if lines else False)
        c.check(f'{name}: the provider received the body byte for byte, and said so',
                body_json(r).get('body_sha256') == hashlib.sha256(body).hexdigest() == provider_hits()[-1]['body_sha256'])


@case('P1-CO-05', 'the provider answers with a process number that is not of the accepted form',
      'one line for the call; the log has (malformed) for the process number; the caller gets the provider\'s answer unchanged',
      ('GW-FR-017', 'GW-NFR-05'))
def _(c):
    ref = new_reference()
    mark = gateway_log_size()
    r = gw('POST', LABELS + '?fault=bad-process-code', blue(), JSON_CT, create_body(ref))
    lines = gateway_all_lines(mark)
    c.check('the gateway log grew by exactly one line', len(lines) == 1 and '\trequest ' in lines[0])
    f = line_fields(lines[0]) if lines else {}
    c.note('process_number_as_logged', f.get('provider_request_id'))
    c.check('the process number is written as (malformed)', f.get('provider_request_id') == '(malformed)')
    c.check('the reference number, which was fine, is written', f.get('provider_reference_id') == ref)
    c.check('nothing of the provider\'s process number is in the line', lines != [] and 'forged-line' not in lines[0] and 'AAAAA' not in lines[0])
    data = body_json(r).get('Data') or {}
    c.check('the caller got 201 and the provider\'s answer as it was: the long process number with its quote and newline',
            r['status'] == 201 and data.get('ProcessCode', '').startswith('PC-"x"\nforged-line ') and len(data.get('ProcessCode', '')) > 5000
            and data.get('ReferenceId') == ref)


@case('P1-CO-06', 'calls the PDP refuses',
      'the gateway line for a refused call has no decision id and no reference number, and the 403 body has none either (the limit '
      'as it is today); gateway-authz has one DENY line for the refusal, with a decision id of its own',
      ('GW-FR-017',))
def _(c):
    def refused(name, token_fn, before=None, after=None):
        ref = new_reference()
        if before:
            before()
        try:
            mark_gw, mark_az = gateway_log_size(), authz_log_size()
            r = gw('POST', LABELS, token_fn(), JSON_CT, create_body(ref))
            reqs = gateway_request_lines(mark_gw)
            decisions = authz_decisions(mark_az)
        finally:
            if after:
                after()
        body = body_json(r)
        f = line_fields(reqs[-1]) if reqs else {}
        c.note(f'{name}: the gateway line', {k: f.get(k) for k in ('http.status', 'reason', 'authz_decision_id', 'tenant_ref', 'provider_reference_id')})
        c.note(f'{name}: the 403 body', {k: v for k, v in body.items()})
        c.check(f'{name}: 403 with the PDP\'s reason, nothing forwarded', r['status'] == 403 and 'reason_code' in body and len(provider_hits()) == 0)
        c.check(f'{name}: one gateway line', len(reqs) == 1)
        c.check(f'{name}: the line has no decision id and no reference number',
                'authz_decision_id' not in f and 'provider_reference_id' not in f and ref not in (reqs[-1] if reqs else ref))
        c.check(f'{name}: gateway-authz wrote one line for it, a DENY', len(decisions) == 1 and decisions[0].get('result') == 'DENY')
        # The limit, recorded and not wished away: the PDP's 403 body has no decision id (denialBody in
        # internal/egressauthz/adapters/httpapi), and the gateway line has none either. gateway-authz did
        # give the refusal an id and logged it; a caller or an operator can match the two only by route,
        # tenant and time.
        c.note(f'{name}: decision id in the gateway-authz line', decisions[0].get('decision_id') if decisions else None)
        c.check(f'{name}: the 403 body carries no decision id (the limit as it is), while gateway-authz logged one for the refusal',
                'decision_id' not in body and bool(decisions) and bool(decisions[0].get('decision_id')))
        reset_all()
    refused('a tenant with no grant', lambda: blue(tenant_id='tenant-red'))
    refused('a revoked account', blue, before=lambda: pdp_admin('/admin/revoke?account=account-blue'),
            after=lambda: pdp_admin('/admin/restore?account=account-blue'))


@case('P1-CO-07', 'what the logs hold of a call that carries token-like strings, a JWT and credentials',
      'no planted token-like string from the body, no caller JWT and no provider credential in the gateway line or in gateway-authz\'s lines',
      ('GW-AT-007', 'GW-FR-007', 'GW-NFR-05'))
def _(c):
    ref = new_reference()
    planted = ['eyJ' + secrets.token_urlsafe(30), 'Bearer ' + secrets.token_urlsafe(24), 'sk_live_' + secrets.token_hex(12)]
    tok = blue()
    mark_gw, mark_az = gateway_log_size(), authz_log_size()
    r = gw('POST', LABELS, tok, JSON_CT, create_body(ref, note=planted[0], memo={'auth': planted[1]}, key=planted[2]))
    gw('GET', TRACKING + '/TRK-1', tok)
    c.check('the create call was answered 201', r['status'] == 201)
    gateway_text = '\n'.join(gateway_all_lines(mark_gw))
    authz_text = (RUN / 'gateway-authz.log').read_bytes()[mark_az:].decode(errors='replace')
    c.check('the gateway line for the call exists (so the search below is not empty)', ref in gateway_text and 'authz_decision_id=' in gateway_text)
    c.check('gateway-authz lines for these calls exist', authz_text.count('"msg":"egress authorization"') == 2)
    for name, text in (('the gateway', gateway_text), ('gateway-authz', authz_text)):
        c.check(f'{name}: none of the planted strings', not any(p in text or p.split(' ')[-1] in text for p in planted))
        c.check(f'{name}: no caller JWT', tok not in text and 'eyJ' not in text)
        c.check(f'{name}: no provider credential', not any(t in text for t in all_provider_credentials()) and not developer_in(text))
        c.check(f'{name}: no broker key and no session key', S.broker_key not in text and S.session_key not in text)


@case('P1-CO-08', 'a route that does not ask the PDP, with a provider answer that names a decision',
      'the gateway line has no decision id: it comes from the PDP\'s answer header only, not from anything a provider says',
      ('GW-FR-017',))
def _(c):
    mark = gateway_log_size()
    r = gw('GET', RATES + '?fault=forge-decision', blue())
    reqs = gateway_request_lines(mark)
    body = body_json(r)
    f = line_fields(reqs[-1]) if reqs else {}
    c.note('gateway_line_fields', {k: f.get(k) for k in ('route', 'authz_decision_id', 'tenant_ref', 'provider_reference_id', 'provider_request_id')})
    c.check('200, and the answer the caller got does name a decision (so there was something to copy)',
            r['status'] == 200 and body.get('decision_id') == 'forged-by-provider')
    c.check('one gateway line, on the static-credential route', len(reqs) == 1 and f.get('route') == 'default/mockcarrier-rates-get-static')
    c.check('the line has no decision id', 'authz_decision_id' not in f)
    c.check('nothing of the forged id is in the line', 'forged-by-provider' not in (reqs[-1] if reqs else 'forged-by-provider'))
    c.check('the tenant is on the line all the same', f.get('tenant_ref') == 'tenant-blue')
    c.check('gateway-authz was not asked', len(pdp_log()) == 0)


# --------------------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------------------
SCOPE_LIMITS = [
    'The PDP is this repository\'s gateway-authz, built with the `acceptance` tag: the product code plus the test controls '
    'this runner uses (request log, fault modes, revoke/restore). The product build, which has none of them, is not what ran. '
    'Where a case says "Gatekeeper" or "PDP" it means this process.',
    'gateway-authz reads its policy and its credentials from files written for the run and keeps its revocations in a file '
    'made for the run; the certificate of the one workload that may change them is made for the run as well. '
    'No identity provider, grants store, Secret Manager or provider token endpoint is involved, and the deployed Gatekeeper '
    'is not called: the caller tokens are signed by a key made for the run.',
    'The provider is a loopback mock; no carrier sandbox was called. That includes the developer-token route (P1-DT-*): the '
    'scheme is one carrier\'s, taken from its public integration guide, and what answers here is a mock that checks the form '
    'of the header, knows the run\'s account numbers and tokens, and refuses a nonce twice. The carrier was not called.',
    'Mutual TLS is real on the gateway-to-PDP and broker-to-PDP hops only, with a CA and certificates made for the run: '
    'no SPIFFE Workload API, no rotation, no certificate revocation. Caller-to-gateway and gateway-to-provider are plain HTTP.',
    'The local broker (Mode B) is a mock with a JSON file as its store. The gateway reaches it over loopback HTTP and proves '
    'itself with a key file, standing in for a Unix socket or pod-local restriction; that restriction itself is untested.',
    'The front proxy is one nginx build with a minimal configuration, there to show that a component in front can refuse '
    'what the gateway accepts (P1-SS-04). Four cases go through it; the others address the gateway listener directly, '
    'on loopback, which is the only place it listens (P1-NL-01). Whether the eventual entry component behaves like this '
    'nginx has to be tested on that component.',
    'Single gateway process: nothing here speaks to multi-replica behaviour, config rollout, quotas or load.',
    'The read-back listener is exercised on this one instance with a publisher certificate made for the run; there is no '
    'publisher. Reading back from several replicas is tried in tests/integration/kubernetes.',
    'The result holds for the agentgateway build named in this file only: the binary of the container image pinned in '
    'deploy/agentgateway/agentgateway.lock.json at the time of the run, taken out of the image and run on this host, not '
    'in a container. No other version or build is tested.',
    'HTTP ExtAuthZ only. gRPC ExtAuthZ, decision caching, CONNECT, gRPC upstreams, HMAC signing and mTLS towards providers are untested.',
    'DNS rebinding and network-layer egress ACLs are untested: the upstream is a fixed loopback address.',
    'This is PoC evidence. It does not change any NOT_RUN acceptance case or STD-CP gate.',
]


def prepare():
    RUN.mkdir(exist_ok=True)
    for f in RUN.glob('*.log'):
        f.unlink()
    S.signing, S.attacker = new_key(), new_key()
    S.admin, S.broker_key = secrets.token_urlsafe(24), 'broker-local-' + secrets.token_urlsafe(24)
    S.token = {a: f'mock-{a}-' + secrets.token_urlsafe(24) for a in ('account-blue', 'account-green')}
    S.static_token = 'mock-account-shared-' + secrets.token_urlsafe(24)
    S.developer = {a: ('MOCK' + secrets.token_hex(4).upper(), 'developer-' + secrets.token_urlsafe(24)) for a in S.token}
    S.developer_next = {a: (number, 'developer-next-' + secrets.token_urlsafe(24)) for a, (number, _) in S.developer.items()}
    S.impostor_token = 'impostor-' + secrets.token_urlsafe(24)
    S.session_key = secrets.token_hex(32)
    pki.issue(TLS)
    os.chmod(TLS, 0o700)
    (RUN / 'jwks.json').write_text(json.dumps({'keys': [jwk(S.signing, KID)]}), encoding='utf-8')
    (RUN / 'broker-local.key').write_text(S.broker_key, encoding='utf-8')
    (RUN / 'static-provider.key').write_text(S.static_token, encoding='utf-8')
    # The broker's own store: handle (credential binding / account) -> provider token.
    binding = json.loads((HERE / 'policy.poc.json').read_text(encoding='utf-8'))['registered_operations'][0]['credential_binding_ref']
    (RUN / 'broker-store.json').write_text(json.dumps({f'{binding}/{a}': t for a, t in S.token.items()}), encoding='utf-8')
    # gateway-authz's credential file has the same shape: handle -> bearer token.
    (RUN / 'authz-credentials.json').write_text(json.dumps({f'{binding}/{a}': t for a, t in S.token.items()}), encoding='utf-8')
    # Its second credentials file, for the route whose credential is not a Bearer token:
    # handle -> the carrier's account number and a developer token. No nonce is stored.
    write_developer_tokens(S.developer)
    # Its table of revoked accounts. "Nothing revoked" is a file that says so: without the file it does not start.
    REVOCATIONS.write_text(NOTHING_REVOKED, encoding='utf-8')
    for f in RUN.iterdir():
        if f.is_file():
            os.chmod(f, 0o600)


def stage_config(binary: str) -> tuple[bool, str]:
    """Copy the reviewed configuration to where the gateway is started from, have the binary's
    own validator read that copy, and tell the mocks. -> (accepted, what the validator said)"""
    S.config_bytes = CONFIG.read_bytes()
    RUN_CONFIG.write_bytes(S.config_bytes)
    v = subprocess.run([binary, '--validate-only', '-f', str(RUN_CONFIG.relative_to(HERE))], cwd=HERE, capture_output=True, text=True)
    RUN_CONFIG.write_bytes(S.config_bytes)   # start from the reviewed bytes even if validating wrote to the copy
    state = {'admin_secret': S.admin, 'ports': PORTS, 'tls_dir': str(TLS),
             'config_digest': 'sha256:' + hashlib.sha256(S.config_bytes).hexdigest(),
             'provider_slow_seconds': PROVIDER_SLOW_SECONDS, 'pdp_slow_seconds': PDP_SLOW_SECONDS,
             'provider_tokens': {**{t: a for a, t in S.token.items()}, S.static_token: 'account-shared'},
             # "account number;token" -> account, for the tokens gateway-authz starts with and the ones P1-DT-04 rotates to
             'provider_developer_tokens': {f'{number};{token}': a for table in (S.developer, S.developer_next)
                                           for a, (number, token) in table.items()}}
    (RUN / 'state.json').write_text(json.dumps(state), encoding='utf-8')
    for f in (RUN_CONFIG, RUN / 'state.json'):
        os.chmod(f, 0o600)
    return v.returncode == 0, (v.stdout + v.stderr).strip()


# What the reviewed configuration sets because the binary, left to itself, does something unsafe.
LEFT_OUT = ['urlRewrite.authority', 'the canonical-path authorization rule on each route',
            'the credential-present authorization rule on each backend', 'responseHeaderModifier', 'requestHeaderModifier',
            'the header allow list on each backend (transformations)', 'config.storage.mode', 'bindAddress on the callers\' listener']


def unmitigated_config() -> bytes:
    """The reviewed configuration with LEFT_OUT taken out and nothing else changed."""
    doc = yaml.safe_load(CONFIG.read_bytes())
    doc['config'].pop('storage', None)
    for gateway in doc['gateways'].values():
        gateway.pop('bindAddress', None)
    for route in doc['routes']:
        policies = route.get('policies', {})
        for key in ('authorization', 'responseHeaderModifier'):
            policies.pop(key, None)
        policies.get('urlRewrite', {}).pop('authority', None)
        for backend in route['backends']:
            for key in ('authorization', 'requestHeaderModifier', 'transformations'):
                backend.get('policies', {}).pop(key, None)
            if backend.get('policies') == {}:
                del backend['policies']
    return yaml.safe_dump(doc, sort_keys=False).encode()


def observe_unmitigated(binary: str) -> dict:
    """Start the binary once from unmitigated_config() and record what it then lets through.

    Observations, not checks. They are the reason those settings are in the reviewed
    configuration, and they belong to the binary: a new release may answer differently.
    No case runs against this configuration; the gateway under test is started afterwards."""
    probe = RUN / 'unmitigated.yaml'
    seen: dict = {'configuration': 'the reviewed configuration without: ' + '; '.join(LEFT_OUT)}
    try:
        probe.write_bytes(unmitigated_config())
        os.chmod(probe, 0o600)
        v = subprocess.run([binary, '--validate-only', '-f', f'.run/{probe.name}'], cwd=HERE, capture_output=True, text=True)
        if v.returncode != 0:
            seen['not_observed'] = 'the binary does not accept that configuration: ' + ' '.join((v.stdout + v.stderr).split())[:300]
            return seen
        start('agentgateway-unmitigated', [binary, '-f', f'.run/{probe.name}'], PORTS['gateway'], env=gateway_env(S.session_key))
        tok = blue()

        # Without bindAddress: where the callers' port is open.
        seen['callers_listener_bound_to'] = listening().get(PORTS['gateway'])

        # Without urlRewrite.authority and requestHeaderModifier: what of the caller's request reaches the provider.
        reset_all()
        sent = [('Cookie', 'session=caller-session'), ('X-Forwarded-Host', 'internal.idp.test'), ('X-Forwarded-For', '10.1.2.3'),
                ('X-Forwarded-Proto', 'https'), ('Forwarded', 'for=10.1.2.3;host=internal.idp.test')]
        gw('GET', TRACKING + '/TRK-1', tok, sent)
        hits = provider_hits()
        names = {k.lower() for h in hits for k, _ in h['headers']}
        seen['host_header_the_provider_received'] = sorted({v for h in hits for v in header(h['headers'], 'host')})
        seen['caller_headers_the_provider_received'] = sorted(k.lower() for k, _ in sent if k.lower() in names)

        # Without the allow list: headers that no removal names either.
        reset_all()
        gw('GET', TRACKING + '/TRK-1', tok, UNREGISTERED)
        names = {k.lower() for h in provider_hits() for k, _ in h['headers']}
        seen['unregistered_caller_headers_the_provider_received'] = sorted(k.lower() for k, _ in UNREGISTERED if k.lower() in names)

        # Without the canonical-path rule, on the route that has no PDP behind it.
        targets = {}
        for variant in (RATES + '/%252e%252e/admin', RATES + '/x%00', RATES + '/x;x=1'):
            reset_all()
            r = gw('GET', variant, tok)
            targets[variant] = {'status': r['status'], 'provider_received': [h['raw_target'] for h in provider_hits()]}
        seen['request_targets_on_the_route_without_a_pdp'] = targets

        # Without the credential-present rule: the PDP allows and releases no credential.
        reset_all()
        pdp_admin('/admin/mode?value=allow_without_credential')
        r = gw('GET', TRACKING + '/TRK-1', tok)
        hits = provider_hits()
        seen['pdp_allows_without_a_credential'] = {
            'status': r['status'], 'answered_by': 'provider' if header(r, 'x-mock-provider') else 'gateway',
            'requests_the_provider_received': len(hits),
            'authorization_headers_among_them': sum(len(header(h['headers'], 'authorization')) for h in hits)}

        # Without responseHeaderModifier: the provider answers 302 to another host and sets a cookie.
        reset_all()
        r = gw('GET', TRACKING + '/redirect-me', tok)
        seen['provider_answers_302_with_a_cookie'] = {
            'status': r['status'], 'location_given_to_the_caller': header(r, 'location'),
            'set_cookie_given_to_the_caller': bool(header(r, 'set-cookie')),
            'requests_the_redirect_target_received': len(forbidden_hits())}

        # Without config.storage.mode: a write through the gateway's own admin API. Last, because
        # where it is accepted it changes what this instance runs.
        before, running = probe.read_bytes(), config_dump_digest()
        r = admin_api('PUT', *ADMIN_WRITE)
        time.sleep(0.5)
        seen['write_through_the_admin_api'] = {
            'status': r['status'], 'storage_mode_the_gateway_reports': (body_json(admin_api('GET', '/api/runtime')).get('ui') or {}).get('configStoreMode'),
            'what_the_gateway_runs_changed': config_dump_digest() != running,
            'configuration_file_rewritten_by_the_gateway': probe.read_bytes() != before}
    except Exception as e:
        seen['not_observed'] = f'{type(e).__name__}: {e}'
    finally:
        stop('agentgateway-unmitigated', PORTS['gateway'])
        probe.unlink(missing_ok=True)
    return seen


def observe_unevaluable_allow_list(binary: str) -> dict:
    """Start the binary once from the reviewed configuration with the allow-list expression on every
    backend replaced by one it cannot evaluate, and record what the provider then receives.

    An observation, not a check, like observe_unmitigated(). It is why the removals by name stay beside
    the allow list and why P1-HD-03 sends a request through every route: on the build under test such an
    expression passes validation and stops nothing. A new release may refuse it, or refuse the request;
    then what is recorded here changes. No case runs against this configuration."""
    probe = RUN / 'unevaluable.yaml'
    broken = 'request.headers.noSuchFunction(k, true)'
    seen: dict = {'configuration': 'the reviewed configuration with every allow-list expression replaced by: ' + broken}
    try:
        doc = yaml.safe_load(CONFIG.read_bytes())
        replaced = 0
        for route in doc['routes']:
            for backend in route['backends']:
                request = backend.get('policies', {}).get('transformations', {}).get('request', {})
                if 'replace' in request:
                    request['replace'], replaced = broken, replaced + 1
        seen['expressions_replaced'] = replaced
        probe.write_bytes(yaml.safe_dump(doc, sort_keys=False).encode())
        os.chmod(probe, 0o600)
        v = subprocess.run([binary, '--validate-only', '-f', f'.run/{probe.name}'], cwd=HERE, capture_output=True, text=True)
        seen['accepted_by_the_validator'] = v.returncode == 0
        if v.returncode != 0:
            seen['the_validator_said'] = ' '.join((v.stdout + v.stderr).split())[:300]
            return seen
        start('agentgateway-unevaluable', [binary, '-f', f'.run/{probe.name}'], PORTS['gateway'], env=gateway_env(S.session_key))
        reset_all()
        removed_by_name = [('Cookie', 'session=caller-session'), ('X-Forwarded-For', '10.1.2.3'), ('X-Provider-Account', 'account-blue')]
        log = RUN / 'agentgateway-unevaluable.log'
        before = log.stat().st_size
        r = gw('GET', TRACKING + '/TRK-1', blue(), UNREGISTERED + removed_by_name)
        time.sleep(0.4)
        names = {k.lower() for h in provider_hits() for k, _ in h['headers']}
        written = log.read_bytes()[before:].decode(errors='replace').splitlines()
        seen.update({
            'status': r['status'],
            'unregistered_caller_headers_the_provider_received': sorted(k.lower() for k, _ in UNREGISTERED if k.lower() in names),
            'headers_removed_by_name_the_provider_received': sorted(k.lower() for k, _ in removed_by_name if k.lower() in names),
            'lines_the_gateway_logged_beside_the_request_line': len([l for l in written if '\trequest ' not in l]),
        })
    except Exception as e:
        seen['not_observed'] = f'{type(e).__name__}: {e}'
    finally:
        stop('agentgateway-unevaluable', PORTS['gateway'])
        probe.unlink(missing_ok=True)
    return seen


def ephemeral_range() -> tuple[int, int] | None:
    """Range the kernel draws source ports for outgoing connections from (Linux only)."""
    try:
        lo, hi = Path('/proc/sys/net/ipv4/ip_local_port_range').read_text().split()
        return int(lo), int(hi)
    except (OSError, ValueError):
        return None


def input_digests() -> dict:
    """What a run depends on, as recorded in every evidence file. The agentgateway binary is
    covered through the lock: a run starts only the binary the lock names."""
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    return {('agentgateway', 'lock_sha256'): sha(pin.LOCK), ('agentgateway', 'config_sha256'): sha(CONFIG),
            ('policy_sha256',): sha(HERE / 'policy.poc.json'), ('runner_sha256',): sha(Path(__file__).resolve()),
            ('front_proxy', 'config_sha256'): sha(FRONT_CONF), ('gateway_authz', 'source_sha256'): authz_source_sha256(),
            **{('mocks_sha256', f): sha(HERE / f) for f in MOCKS}}


def check_evidence() -> int:
    """Compare the digests recorded in each evidence file with the files as they are now."""
    now, stale = input_digests(), 0
    for f in sorted((HERE / 'evidence').glob('*.json')):
        recorded = json.loads(f.read_text(encoding='utf-8'))
        differs = []
        for keys, value in now.items():
            node = recorded
            for key in keys:
                node = node.get(key) if isinstance(node, dict) else None
            if node != value:
                differs.append('.'.join(keys))
        s = recorded.get('summary', {})
        print(f"{'STALE' if differs else 'OK   '}  {f.name}  ({s.get('pass')}/{s.get('cases')} passed, commit {str(recorded.get('repository_commit'))[:7]})")
        for key in differs:
            print(f'        differs from that run: {key}')
        stale += bool(differs)
    return 1 if stale else 0


def main() -> int:
    ap = argparse.ArgumentParser(description='black-box runner')
    ap.add_argument('--agentgateway', metavar='BINARY',
                    help='where the pinned agentgateway binary is (default: ~/.local/opt/agentgateway/<version>/agentgateway, '
                         'else the one on PATH); a binary that is not the pinned build is refused')
    ap.add_argument('--check-evidence', action='store_true',
                    help='run nothing; report whether each evidence file was produced from the files as they are now')
    args = ap.parse_args()
    if args.check_evidence:
        return check_evidence()
    go = find_go()
    if not go:
        print('go toolchain not found (needed to build cmd/gateway-authz)'); return 2
    try:
        binary, version = pin.resolve(args.agentgateway)
    except pin.PinError as e:
        print(e); return 2
    evidence_file = HERE / 'evidence' / f"p1-run-agentgateway-{version['version']}.json"
    print(f"agentgateway {version['version']} ({version.get('build_target')}) at {binary}, the build pinned in {pin.LOCK.relative_to(ROOT).as_posix()}")

    busy = [f'{n}:{p}' for n, p in PORTS.items() if port_open(p)]
    if busy:
        print('ports already in use, refusing to start:', ', '.join(busy)); return 2
    # A listener port inside the ephemeral range can be taken, for a moment, by any outgoing
    # connection on the machine, and the listener then fails to bind. This happened once
    # with the first port block (47611-47617) on a host whose range is 44620-48715.
    eph = ephemeral_range()
    if eph and any(eph[0] <= p <= eph[1] for p in PORTS.values()):
        print(f'port block overlaps the ephemeral range {eph[0]}-{eph[1]} of this host, refusing to start'); return 2
    if not front_image_available():
        print(f'front proxy image not available and could not be pulled (is docker running?): {FRONT_IMAGE}'); return 2
    front_version = docker('run', '--rm', '--entrypoint', 'nginx', FRONT_IMAGE, '-v')
    front_version = (front_version.stdout + front_version.stderr).strip()
    print('front proxy:', front_version)
    prepare()
    build_said = build_authz(go)
    if build_said:
        print('gateway-authz did not build:', build_said); return 2
    go_version = sh([go, 'version'])
    print('gateway-authz (acceptance build):', go_version)
    config_ok, config_said = stage_config(binary)
    print('native config validation:', config_said)
    if not config_ok:
        return 2

    started = datetime.datetime.now(datetime.timezone.utc)
    results, listeners, unmitigated, unevaluable = [], '', {}, {}
    try:
        mock = lambda name, port: start(name, [sys.executable, str(HERE / 'mock_provider.py'), '--port', str(port),
                                                '--name', name, '--state', str(RUN / 'state.json')], port)
        S.default_start_rewrites = start_without_session_key_rewrites(binary, unmitigated_config())
        S.read_only_start_rewrites = start_without_session_key_rewrites(binary, S.config_bytes)
        mock('mockcarrier', PORTS['provider'])
        mock('forbidden', PORTS['forbidden'])
        start_gatekeeper()
        start_broker()
        unmitigated = observe_unmitigated(binary)
        unevaluable = observe_unevaluable_allow_list(binary)
        start('agentgateway', [binary, '-f', str(RUN_CONFIG.relative_to(HERE))], PORTS['gateway'], env=gateway_env(S.session_key))
        start_front()
        listeners = sh(['ss', '-ltnH'])
        listeners = sorted(l.split()[3] for l in listeners.splitlines() if any(f':{p}' in l for p in PORTS.values()))

        for cid, title, expectation, maps_to, fn in CASES:
            record = {'id': cid, 'title': title, 'expectation': expectation}
            reset_all()
            c = Ctx()
            try:
                fn(c)
            except Exception as e:
                c.check(f'case raised {type(e).__name__}: {e}', False)
            # Observation, not a check: over which HTTP version the gateway asked. P1-AZ-11 is left
            # out: there the runner itself calls the PDP with the gateway's certificate.
            if cid != 'P1-AZ-11':
                S.pdp_protocols.update(e.get('proto') for e in pdp_log() if e.get('peer_identity') == pki.ID['gateway'] and e.get('proto'))
            ok = bool(c.checks) and all(x['ok'] for x in c.checks)
            results.append({**record, 'result': 'PASS' if ok else 'FAIL',
                            'checks': c.checks, 'observed': c.observed, 'indicative_for': list(maps_to)})
            print(f"{'PASS' if ok else 'FAIL'}  {cid}  {title}")
            for x in c.checks:
                if not x['ok']:
                    print(f"        x {x['check']}")
    finally:
        try:
            stop_front()
        except Exception as e:
            print(f'front proxy did not stop cleanly: {type(e).__name__}: {e}')
        for name in list(PROCS):
            stop(name)
        time.sleep(0.3)
        still_open = [p for p in PORTS.values() if port_open(p)]

    passed = sum(r['result'] == 'PASS' for r in results)
    evidence = {
        'title': 'IDP Gateway black-box suite: real agentgateway, gateway-authz (acceptance build), mock provider',
        'started_at_utc': started.isoformat(), 'finished_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'operator': sh(['git', 'config', 'user.name']), 'host': platform.platform(), 'python': sys.version.split()[0],
        'command': ' '.join(['.venv/bin/python', 'tests/acceptance/blackbox/run.py'] + sys.argv[1:]),
        'repository_commit': sh(['git', 'rev-parse', 'HEAD']),
        # Evidence files are this runner's output, not its input: a rerun must not count the
        # evidence of the run before it, not yet committed, as a modified repository.
        # (A porcelain line is "XY path"; X may be a blank that sh() has stripped off the first line.)
        'repository_dirty_files': len([l for l in sh(['git', 'status', '--porcelain', '--untracked-files=all']).splitlines()
                                       if l.strip() and not l.split(None, 1)[-1].strip('"').startswith('tests/acceptance/blackbox/evidence/')]),
        'repository_dirty_files_ignores': 'tests/acceptance/blackbox/evidence/',
        'agentgateway': {'version': version,
                         'binary_sha256': hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                         'image': pin.image_reference(pin.lock()),
                         'binary_is': f"{pin.lock()['image']['binary']} of that image, taken out of it and run on this host",
                         'pinned_by': pin.LOCK.relative_to(ROOT).as_posix(),
                         'lock_sha256': hashlib.sha256(pin.LOCK.read_bytes()).hexdigest(),
                         'config_file': 'tests/acceptance/blackbox/agentgateway.poc.yaml',
                         'config_sha256': hashlib.sha256(CONFIG.read_bytes()).hexdigest(),
                         'native_validation': config_said,
                         'session_key_supplied_by': 'SESSION_KEY environment variable, generated per run, not recorded',
                         'start_without_session_key_rewrites_config_file': S.default_start_rewrites,
                         'start_without_session_key_rewrites_config_file_with_storage_read_only': S.read_only_start_rewrites,
                         'unmitigated_defaults': unmitigated,
                         'allow_list_expression_that_cannot_be_evaluated': unevaluable},
        'policy_sha256': hashlib.sha256((HERE / 'policy.poc.json').read_bytes()).hexdigest(),
        'runner_sha256': hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest(),
        'gateway_authz': {'what_ran': 'cmd/gateway-authz built with the acceptance tag; not the product build',
                          'build_command': 'go ' + ' '.join(AUTHZ_BUILD), 'go': go_version,
                          'source_sha256': authz_source_sha256(),
                          'source_sha256_covers': 'go.mod and every non-test .go file under cmd/ and internal/',
                          'binary_sha256': hashlib.sha256(AUTHZ_BINARY.read_bytes()).hexdigest(),
                          'policy_from': 'tests/acceptance/blackbox/policy.poc.json',
                          'credentials_from': 'two files written for the run, not recorded: Bearer tokens (--credentials), and '
                                              'account numbers with developer tokens (--developer-tokens)',
                          'revocations': 'a file written for the run (--revocations), empty at the start; changed through the '
                                         'acceptance controls and, in P1-RV-02 to 05, through the product interface',
                          'http_versions_seen_from_the_gateway': sorted(S.pdp_protocols)},
        'mocks_sha256': {f: hashlib.sha256((HERE / f).read_bytes()).hexdigest() for f in MOCKS},
        'front_proxy': {'image': FRONT_IMAGE, 'version': front_version, 'config_file': 'tests/acceptance/blackbox/front.nginx.conf',
                        'config_sha256': hashlib.sha256(FRONT_CONF.read_bytes()).hexdigest(),
                        'runs_as': 'container on the host network, unprivileged user, read-only root, no capabilities'},
        'workload_identities': pki.ID,
        'ports': PORTS, 'host_ephemeral_port_range': ephemeral_range(),
        'listen_addresses_observed': listeners, 'ports_left_open_after_run': still_open,
        'summary': {'cases': len(results), 'pass': passed, 'fail': len(results) - passed},
        'scope_limits': SCOPE_LIMITS,
        'formal_acceptance': 'NOT_RUN (unchanged by this PoC)',
        'cases': results,
    }
    evidence_file.parent.mkdir(exist_ok=True)
    evidence_file.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f"\n{passed}/{len(results)} cases passed; evidence: {evidence_file.relative_to(ROOT)}; "
          f"ports left open: {still_open or 'none'}")
    return 0 if passed == len(results) else 1


if __name__ == '__main__':
    sys.exit(main())
