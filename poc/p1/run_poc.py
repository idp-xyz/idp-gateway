#!/usr/bin/env python3
"""P1 PoC runner: a real agentgateway between a mock Gatekeeper and a mock provider.

Starts the four processes, drives requests through the gateway, checks what the PDP and
the provider actually received, and writes poc/p1/evidence/p1-run.json. Expectations are
taken from G01/G03/G04 and are fixed in this file before the run; a case that does not
meet its expectation is reported as FAIL, not adjusted.

Usage (from the repository root):  .venv/bin/python poc/p1/run_poc.py
"""
from __future__ import annotations
import base64, datetime, hashlib, hmac, http.client, json, os, platform, secrets, socket, subprocess, sys, time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RUN = HERE / '.run'
EVIDENCE = HERE / 'evidence' / 'p1-run.json'
CONFIG = HERE / 'agentgateway.poc.yaml'
PORTS = {'gateway': 27611, 'provider': 27612, 'gatekeeper': 27613, 'admin': 27614,
         'stats': 27615, 'readiness': 27616, 'forbidden': 27617}
ISSUER, AUDIENCE, LOGICAL_HOST, KID = 'https://gatekeeper.idp.test', 'idp-egress-gateway', 'egress-api.idp.test', 'poc-key-1'
PROVIDER_SLOW_SECONDS, PDP_SLOW_SECONDS = 3.5, 2.5   # both longer than the gateway's 2s / 1s timeouts
TRACKING = '/providers/mockcarrier/v1/tracking'
LABELS = '/providers/mockcarrier/v1/labels'
RATES = '/providers/mockcarrier/v1/rates'

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
def send(port: int, method: str, target: str, headers=(), body: bytes | None = None, timeout: float = 10.0) -> dict:
    """Raw-ish client: the request target and headers go on the wire exactly as given."""
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=timeout)
    started = time.monotonic()
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


def gw(method: str, target: str, token: str | None = None, headers=(), body: bytes | None = None, host: str = LOGICAL_HOST, **kw) -> dict:
    hs = [('Host', host)]
    if token is not None:
        hs.append(('Authorization', 'Bearer ' + token))
    return send(PORTS['gateway'], method, target, hs + list(headers), body, **kw)


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


def start(name: str, argv: list[str], port: int, cwd: Path = HERE):
    log = open(RUN / f'{name}.log', 'ab')
    PROCS[name] = subprocess.Popen(argv, cwd=cwd, stdout=log, stderr=subprocess.STDOUT)
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


def start_gatekeeper():
    start('gatekeeper', [sys.executable, str(HERE / 'mock_gatekeeper.py'), '--port', str(PORTS['gatekeeper']),
                         '--policy', str(HERE / 'policy.poc.json'), '--state', str(RUN / 'state.json')], PORTS['gatekeeper'])


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
    admin = workload = static_token = ''
    token = {}  # account -> provider token


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
pdp_log = lambda: body_json(send(PORTS['gatekeeper'], 'GET', '/admin/log', ADMIN())).get('log', [])
pdp_admin = lambda path: body_json(send(PORTS['gatekeeper'], 'POST', path, ADMIN(), b''))


def reset_all():
    send(PORTS['provider'], 'POST', '/admin/reset', ADMIN(), b'')
    send(PORTS['forbidden'], 'POST', '/admin/reset', ADMIN(), b'')
    send(PORTS['gatekeeper'], 'POST', '/admin/reset', ADMIN(), b'')


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


@case('P1-AZ-11', 'business app calls the PDP/Broker directly, without the gateway',
      '401 and no provider credential in the answer', ('GW-ST-018', 'GW-AT-021', 'GW-FR-021'))
def _(c):
    ctx = [('X-Idp-Verified-Subject', 'parcel-service'), ('X-Idp-Verified-Tenant', 'tenant-blue'), ('X-Idp-Verified-Env', 'TEST'),
           ('X-Idp-Provider-Id', 'mockcarrier'), ('X-Idp-Operation-Id', 'tracking.get'), ('X-Idp-Environment', 'TEST'),
           ('X-Idp-Method', 'GET'), ('X-Idp-Path', TRACKING + '/TRK-1')]
    for label, auth in [('no credential', []), ('wrong credential', [('Authorization', 'Bearer not-the-gateway')]),
                        ('a valid caller JWT instead of the workload key', [('Authorization', 'Bearer ' + blue())])]:
        r = send(PORTS['gatekeeper'], 'GET', '/v1/extauthz/check', ctx + auth)
        leaked = any(t in (r['body'].decode(errors='replace') + json.dumps(r['headers'])) for t in S.token.values())
        c.check(f'{label}: 401', r['status'] == 401)
        c.check(f'{label}: no provider credential returned', not leaked)


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


@case('P1-CR-02', 'what the caller receives', 'the provider credential appears nowhere in the response', ('GW-AT-007', 'GW-FR-007'))
def _(c):
    r = gw('GET', TRACKING + '/TRK-1', blue())
    blob = r['body'].decode(errors='replace') + json.dumps(r['headers'])
    c.note('response_header_names', sorted({k.lower() for k, _ in r['headers']}))
    c.check('status is 200', r['status'] == 200)
    c.check('no provider credential in response headers or body', not any(t in blob for t in S.token.values()))
    c.check('no workload key in response', S.workload not in blob)


@case('P1-CR-03', 'what the PDP receives', 'the gateway workload key, not the caller\'s JWT', ('GW-AT-021', 'GW-FR-021'))
def _(c):
    tok = blue()
    gw('GET', TRACKING + '/TRK-1', tok)
    log = pdp_log()
    if not c.check('PDP consulted exactly once', len(log) == 1):
        return
    hs = log[0]['headers']
    c.note('pdp_saw_header_names', sorted({k.lower() for k, _ in hs}))
    c.check('caller JWT appears in no header value', all(tok not in v for _, v in hs))
    c.check('Authorization is the gateway workload key', header(hs, 'authorization') == ['Bearer ' + S.workload])


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
    stop('gatekeeper', PORTS['gatekeeper'])
    try:
        r = gw('GET', TRACKING + '/TRK-1', blue())
        c.note('status_while_down', r['status'])
        c.check('not a success status', r['status'] is not None and r['status'] >= 400)
        c.check('provider received nothing', len(provider_hits()) == 0)
    finally:
        start_gatekeeper()
    c.check('after restart: allowed again', gw('GET', TRACKING + '/TRK-1', blue())['status'] == 200)


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


# --------------------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------------------
SCOPE_LIMITS = [
    'Gatekeeper is a mock: no real identity provider, grants store, Secret Manager or provider token endpoint.',
    'The provider is a loopback mock; no carrier sandbox was called.',
    'No TLS or mTLS on any hop. The gateway-to-PDP channel is authenticated by a shared key standing in for workload mTLS.',
    'Single gateway process: nothing here speaks to multi-replica behaviour, config rollout, quotas or load.',
    'agentgateway 1.6.0 was used because it is the binary installed on this machine; the design names 1.7.x.',
    'HTTP ExtAuthZ only. gRPC ExtAuthZ, decision caching, CONNECT, gRPC upstreams, HMAC signing and mTLS client identities are untested.',
    'DNS rebinding and network-layer egress ACLs are untested: the upstream is a fixed loopback address.',
    'This is PoC evidence. It does not change any NOT_RUN acceptance case or STD-CP gate.',
]


def prepare():
    RUN.mkdir(exist_ok=True)
    for f in RUN.glob('*.log'):
        f.unlink()
    S.signing, S.attacker = new_key(), new_key()
    S.admin, S.workload = secrets.token_urlsafe(24), 'gw-workload-' + secrets.token_urlsafe(24)
    S.token = {a: f'mock-{a}-' + secrets.token_urlsafe(24) for a in ('account-blue', 'account-green')}
    S.static_token = 'mock-account-shared-' + secrets.token_urlsafe(24)
    (RUN / 'jwks.json').write_text(json.dumps({'keys': [jwk(S.signing, KID)]}), encoding='utf-8')
    (RUN / 'gateway-workload.key').write_text(S.workload, encoding='utf-8')
    (RUN / 'static-provider.key').write_text(S.static_token, encoding='utf-8')
    state = {'admin_secret': S.admin, 'workload_key': S.workload, 'ports': PORTS,
             'provider_slow_seconds': PROVIDER_SLOW_SECONDS, 'pdp_slow_seconds': PDP_SLOW_SECONDS,
             'provider_tokens': {**{t: a for a, t in S.token.items()}, S.static_token: 'account-shared'}}
    (RUN / 'state.json').write_text(json.dumps(state), encoding='utf-8')
    for f in RUN.iterdir():
        os.chmod(f, 0o600)


def ephemeral_range() -> tuple[int, int] | None:
    """Range the kernel draws source ports for outgoing connections from (Linux only)."""
    try:
        lo, hi = Path('/proc/sys/net/ipv4/ip_local_port_range').read_text().split()
        return int(lo), int(hi)
    except (OSError, ValueError):
        return None


def main() -> int:
    busy = [f'{n}:{p}' for n, p in PORTS.items() if port_open(p)]
    if busy:
        print('ports already in use, refusing to start:', ', '.join(busy)); return 2
    # A listener port inside the ephemeral range can be taken, for a moment, by any outgoing
    # connection on the machine, and the listener then fails to bind. This happened once
    # with the first port block (47611-47617) on a host whose range is 44620-48715.
    eph = ephemeral_range()
    if eph and any(eph[0] <= p <= eph[1] for p in PORTS.values()):
        print(f'port block overlaps the ephemeral range {eph[0]}-{eph[1]} of this host, refusing to start'); return 2
    prepare()
    validate = subprocess.run(['agentgateway', '--validate-only', '-f', CONFIG.name], cwd=HERE, capture_output=True, text=True)
    print('native config validation:', (validate.stdout + validate.stderr).strip())
    if validate.returncode != 0:
        return 2

    started = datetime.datetime.now(datetime.timezone.utc)
    results, listeners = [], ''
    try:
        mock = lambda name, port: start(name, [sys.executable, str(HERE / 'mock_provider.py'), '--port', str(port),
                                                '--name', name, '--state', str(RUN / 'state.json')], port)
        mock('mockcarrier', PORTS['provider'])
        mock('forbidden', PORTS['forbidden'])
        start_gatekeeper()
        start('agentgateway', ['agentgateway', '-f', CONFIG.name], PORTS['gateway'])
        listeners = sh(['ss', '-ltnH'])
        listeners = sorted(l.split()[3] for l in listeners.splitlines() if any(f':{p}' in l for p in PORTS.values()))

        for cid, title, expectation, maps_to, fn in CASES:
            reset_all()
            c = Ctx()
            try:
                fn(c)
            except Exception as e:
                c.check(f'case raised {type(e).__name__}: {e}', False)
            ok = bool(c.checks) and all(x['ok'] for x in c.checks)
            results.append({'id': cid, 'title': title, 'expectation': expectation, 'result': 'PASS' if ok else 'FAIL',
                            'checks': c.checks, 'observed': c.observed, 'indicative_for': list(maps_to)})
            print(f"{'PASS' if ok else 'FAIL'}  {cid}  {title}")
            for x in c.checks:
                if not x['ok']:
                    print(f"        x {x['check']}")
    finally:
        for name in list(PROCS):
            stop(name)
        time.sleep(0.3)
        still_open = [p for p in PORTS.values() if port_open(p)]

    passed = sum(r['result'] == 'PASS' for r in results)
    evidence = {
        'title': 'IDP Gateway P1 PoC: real agentgateway, mock Gatekeeper, mock provider',
        'started_at_utc': started.isoformat(), 'finished_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'operator': sh(['git', 'config', 'user.name']), 'host': platform.platform(), 'python': sys.version.split()[0],
        'command': '.venv/bin/python poc/p1/run_poc.py',
        'repository_commit': sh(['git', 'rev-parse', 'HEAD']),
        'repository_dirty_files': len([l for l in sh(['git', 'status', '--porcelain']).splitlines() if l.strip()]),
        'agentgateway': {'version': json.loads(sh(['agentgateway', '--version']) or '{}'),
                         'binary_sha256': hashlib.sha256(Path(sh(['which', 'agentgateway'])).read_bytes()).hexdigest(),
                         'config_file': 'poc/p1/agentgateway.poc.yaml',
                         'config_sha256': hashlib.sha256(CONFIG.read_bytes()).hexdigest(),
                         'native_validation': (validate.stdout + validate.stderr).strip()},
        'policy_sha256': hashlib.sha256((HERE / 'policy.poc.json').read_bytes()).hexdigest(),
        'policy_reference_sha256': hashlib.sha256((ROOT / 'scripts' / 'policy_reference.py').read_bytes()).hexdigest(),
        'ports': PORTS, 'host_ephemeral_port_range': ephemeral_range(),
        'listen_addresses_observed': listeners, 'ports_left_open_after_run': still_open,
        'summary': {'cases': len(results), 'pass': passed, 'fail': len(results) - passed},
        'scope_limits': SCOPE_LIMITS,
        'formal_acceptance': 'NOT_RUN (unchanged by this PoC)',
        'cases': results,
    }
    EVIDENCE.parent.mkdir(exist_ok=True)
    EVIDENCE.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f"\n{passed}/{len(results)} cases passed; evidence: {EVIDENCE.relative_to(ROOT)}; ports left open: {still_open or 'none'}")
    return 0 if passed == len(results) else 1


if __name__ == '__main__':
    sys.exit(main())
