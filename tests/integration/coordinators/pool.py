#!/usr/bin/env python3
"""Two gateway-authz replicas on the single-host pool, with deploy/compose/coordinators.yml: sf-token-coordinator (ADR-0022)
and authz-state (ADR-0023). Not an acceptance pass: the three ADRs are Proposed and no formal gate is run here.

    tests/integration/gatekeeper/stack.sh up                                  the local Gatekeeper (this file does not start it)
    .venv/bin/python tests/integration/coordinators/pool.py                   coordinators.yml, gateway-authz x2
    .venv/bin/python tests/integration/coordinators/pool.py --control no-coordinators
                                                                              the same two replicas without coordinators.yml
    tests/integration/gatekeeper/stack.sh down

The machinery is tests/integration/sfintl/pool.py, imported and used as it is (with its run.py, the rig, the stand-in image and
its pool.yml), under a compose project of its own (PROJECT) on ports 27881-27895. The files laid over the pool are
compose.yml, gateway-authz.yml, provider-signer.yml, coordinators.yml (not in the control), sfintl/pool.yml and this
directory's pool.yml (two replicas). The project is taken down with its volumes and the temporary directory removed however
the run ends. Only this project and the local Gatekeeper stack are touched.

Which replica answered a request through the gateway is read from the replicas' own logs: every request carries a traceparent
of its own, the gateway keeps its trace id (with a span id of its own) in the traceparent it sends to gateway-authz, and the
decision line records that. A replica is also called directly over mutual TLS from a throwaway container on the project's
network: the gateway's certificate for a decision, the revoker's for gateway-control. Nothing printed holds a credential: a
token is compared by a hash prefix.
"""
from __future__ import annotations
import argparse, atexit, collections, datetime, importlib.util, json, os, secrets, shutil, socket, subprocess, sys, tempfile, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SFINTL = ROOT / 'tests/integration/sfintl'
_spec = importlib.util.spec_from_file_location('sfintl_pool', SFINTL / 'pool.py')
sp = importlib.util.module_from_spec(_spec)
sys.modules['sfintl_pool'] = sp
_spec.loader.exec_module(sp)
sf, gk, pki = sp.sf, sp.gk, sp.pki

DEPLOY = ROOT / 'deploy/compose'
SF_PROJECT = sp.PROJECT
PROJECT = 'idp-gateway-coord-pool'
NETWORK = f'{PROJECT}_default'
CALLER = f'{PROJECT}-caller'
# 27611-27623 rig, black-box, Gatekeeper, compose suite; 27630-27645 egressnet and the WanbExpress and sfintl pools;
# 27651-27679, 27701-27709, 27721-27735 other suites; 27841-27875 the loopback suites ha/ and authzstate/.
PORTS = tuple(range(27881, 27896))
PORT = {'front': 27881, 'readback': 27882, 'staging': 27883, 'mock': 27884, 'signer': 27885}
FRONT_IMAGE = 'public.ecr.aws/nginx/nginx-unprivileged:stable-alpine@sha256:c3fc8fa482be50ef709c6438eb1bc98d50dbfe5a9b48be90711b8814f4dfd701'
AUTHZ_PORT = 9443
LEASE_LEAF = ('sf-token-coordinator', 'sf-token-coordinator.idp.test', 'spiffe://idp.test/egress/sf-token-coordinator')
STATE_LEAF = ('authz-state', 'authz-state.idp.test', 'spiffe://idp.test/egress/authz-state')
OPERATIONS = {'agent-numbers.query': ('sfintl-agent-numbers-query', sf.QUERIES), 'labels.print': ('sfintl-labels-print', sf.PRINTS)}
# One bucket, on one operation only: blue's queries are never limited; green's label prints are, one per hour per account.
RATE_LIMITS = {'version': 'coordinators-pool', 'buckets': [{'id': 'labels-print-per-account', 'provider_id': 'sfintl',
                                                            'operation_id': 'labels.print', 'key_dimensions': ['provider_account'],
                                                            'max_requests': 1, 'window_seconds': 3600}]}

sp.PROJECT, sp.SCRATCH, sp.PROBE, sp.PORT = PROJECT, f'{PROJECT}-scratch', f'{PROJECT}-probe', PORT
for _name, _served, _identity in (LEASE_LEAF, STATE_LEAF):
    pki.ID[_name] = _identity
    pki.LEAVES[_name] = ('ca', _name, _served)

COORDINATED = True
STANDIN_IMAGE = ''
TOKEN_HITS: list = []        # token requests the stand-in recorded before each reset; a hit holds no token
FORGETS: list = []
RESTARTS: list = []          # every replica start after the first: address before and after
_sf_settings = sp.settings
_sf_standin = sp.ensure_standin_image


def standin_image() -> str:
    """The stand-in image of the sfintl pool, under that pool's name. Built only when it is missing."""
    sp.PROJECT = SF_PROJECT
    try:
        return _sf_standin()
    finally:
        sp.PROJECT = PROJECT


def settings(sandbox: bool = False) -> dict:
    values = _sf_settings(False)
    work = sp.WORK
    values.update({
        'SF_TOKEN_COORDINATOR': str(work / 'bin/sf-token-coordinator'), 'AUTHZ_STATE': str(work / 'bin/authz-state'),
        'SF_TOKEN_COORDINATOR_USER': sp.RUN_AS, 'AUTHZ_STATE_USER': sp.RUN_AS,
        'SF_TOKEN_COORDINATOR_TLS_CERT': str(gk.TLS / 'sf-token-coordinator.crt'),
        'SF_TOKEN_COORDINATOR_TLS_KEY': str(gk.TLS / 'sf-token-coordinator.key'), 'SF_TOKEN_COORDINATOR_NAME': LEASE_LEAF[1],
        'AUTHZ_STATE_TLS_CERT': str(gk.TLS / 'authz-state.crt'), 'AUTHZ_STATE_TLS_KEY': str(gk.TLS / 'authz-state.key'),
        'AUTHZ_STATE_NAME': STATE_LEAF[1], 'COORDINATORS_CA': str(gk.TLS / 'ca.crt'), 'COORDINATORS_CLIENT_CA': str(gk.TLS / 'ca.crt'),
        'COORDINATORS_AUTHZ_IDENTITY': pki.ID['gateway-authz'],
        'SF_TOKEN_COORDINATOR_STATE_DIR': str(work / 'coordinators/sf-token-coordinator'),
        'AUTHZ_STATE_STATE_DIR': str(work / 'coordinators/authz-state'),
        'GATEWAY_AUTHZ_REVOKER_IDENTITY': pki.ID['revoker'], 'GATEWAY_AUTHZ_RATE_LIMITS': str(work / 'authz/rate-limits.json'),
    })
    return values


def compose_files(extra: tuple = ()) -> list[str]:
    files = [DEPLOY / 'compose.yml', DEPLOY / 'gateway-authz.yml', DEPLOY / 'provider-signer.yml']
    if COORDINATED:
        files.append(DEPLOY / 'coordinators.yml')
    files += [SFINTL / 'pool.yml', HERE / 'pool.yml', *extra]
    return [a for f in files for a in ('-f', str(f))]


sp.settings, sp.compose_files = settings, compose_files
sp.ensure_standin_image = lambda: STANDIN_IMAGE
compose, docker, wait_for = sp.compose, sp.docker, sp.wait_for


def say(text: str = ''):
    sf.say(text)


def die(message: str):
    print('pool.py:', message, file=sys.stderr)
    raise SystemExit(2)


# ---- what runs --------------------------------------------------------------------------------------------------------------
def inspect(ref: str) -> dict:
    found = json.loads(docker('inspect', ref).stdout or '[]')
    if not found:
        return {}
    c = found[0]
    net = (c['NetworkSettings'].get('Networks') or {}).get(NETWORK) or {}
    return {'id': c['Id'], 'name': c['Name'].lstrip('/'), 'running': c['State']['Running'], 'exit': c['State']['ExitCode'],
            'started_at': c['State']['StartedAt'], 'health': (c['State'].get('Health') or {}).get('Status'), 'ip': net.get('IPAddress', ''),
            'number': int(c['Config']['Labels'].get('com.docker.compose.container-number') or 0),
            'tmpfs': sorted((c['HostConfig'].get('Tmpfs') or {}).keys()),
            'binds': sorted(m.get('Destination') for m in c.get('Mounts', []) if m.get('Type') in ('bind', 'volume')),
            'entrypoint': c['Config'].get('Entrypoint') or []}


def service(name: str) -> dict:
    found = compose('ps', '-q', '-a', name).stdout.split()
    return inspect(found[0]) if found else {}


def replicas() -> list[dict]:
    found = [inspect(cid) for cid in compose('ps', '-q', '-a', 'gateway-authz').stdout.split()]
    return sorted((r for r in found if r), key=lambda r: r['number'])


def log_of(ref: str) -> str:
    done = docker('logs', ref)
    return done.stdout + done.stderr


def json_lines(text: str, msg: str | None = None) -> list:
    found = []
    for line in text.splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and (msg is None or entry.get('msg') == msg):
            found.append(entry)
    return found


def listening(r: dict) -> int:
    return len(json_lines(log_of(r['id']), 'gateway-authz listening'))


def startup(r: dict) -> dict:
    lines = json_lines(log_of(r['id']), 'gateway-authz listening')
    keep = ('sf_openapi_lease', 'authz_state', 'authz_state_quota', 'revocations', 'revocation_epoch', 'rate_limits', 'sf_openapi_apps')
    return {k: lines[-1].get(k) for k in keep} if lines else {}


def restart(r: dict, timeout: int = 5) -> dict:
    """docker restart of one replica, then wait for a new `gateway-authz listening` line. Returns the replica as it is now."""
    before = listening(r)
    docker('restart', '-t', str(timeout), r['id'], timeout=60)
    wait_for(lambda: listening(r) > before or not inspect(r['id']).get('running'), 40)
    now = inspect(r['id'])
    RESTARTS.append({'replica': r['name'], 'address before': r['ip'], 'address after': now.get('ip'), 'case': sf.STATE['label']})
    return now


def coordinator_listening(name: str) -> int:
    return len(json_lines(compose('logs', '--no-color', '--no-log-prefix', name).stdout, f'{name} listening'))


def start_coordinator(name: str, seconds: float = 60) -> bool:
    """compose start of a stopped coordinator; true once it has logged a new `listening` line and its check says healthy."""
    before = coordinator_listening(name)
    compose('start', name, timeout=60)
    return bool(wait_for(lambda: coordinator_listening(name) > before and service(name).get('health') == 'healthy', seconds, 0.5))


def follow_addresses(r: sf.Results, why: str) -> bool:
    """After a replica restarted. Docker may give it another address. pin-egress.sh resolves a name once, so the gateway's
    namespace keeps allowing only the old one until `egress forget`; and the gateway keeps the old address it resolved, so
    some of its extAuthz calls still go there (refused by the rule: 503 from the gateway, no replica decides). Measured,
    then the two steps deploy/compose/README.md documents are taken: egress forget, then docker compose restart agentgateway."""
    ips = sorted(x['ip'] for x in replicas() if x['running'] and x['ip'])
    pins = sp.pinned('egress').get('gateway-authz:9443') or []
    if set(ips) <= set(pins):
        return False
    forgot = compose('run', '--rm', '--no-deps', '-T', 'egress', 'forget', timeout=120)
    after = sp.pinned('egress').get('gateway-authz:9443') or []
    sample = [through(sf.QUERIES, query()) for _ in range(6)]
    lost = [a['status'] for a, w in zip(sample, deciders(sample, 3)) if not w]
    bounced = compose('restart', '--timeout', '5', 'agentgateway', timeout=120)
    ready = wait_for(lambda: sf.req('GET', sf.ORDERS, TOKENS['blue'])['status'] == 404, 40)
    again = [through(sf.QUERIES, query()) for _ in range(6)]
    reached = deciders(again)
    FORGETS.append({'why': why, 'pinned before': pins, 'addresses now': ips, 'forget exit': forgot.returncode, 'pinned after': after,
                    'after forget, of 6 through front, decided by no replica (HTTP status)': lost,
                    'gateway restart exit': bounced.returncode,
                    'after the gateway restart, of 6 through front, decided by a replica': sum(1 for w in reached if len(w) == 1),
                    'after the gateway restart, decisions per replica': per_replica(reached)})
    r.note(f'a replica came back on another address ({why})', FORGETS[-1])
    r.check(f'egress forget pinned the addresses the replicas have now ({why})', forgot.returncode == 0 and set(ips) <= set(after))
    r.check(f'after docker compose restart agentgateway every request through front was decided by a replica ({why})',
            bounced.returncode == 0 and bool(ready) and all(len(w) == 1 for w in reached))
    return True


# ---- requests ---------------------------------------------------------------------------------------------------------------
TOKENS: dict = {}
STATE_GK: dict = {}


def traceparent() -> str:
    return f'00-{secrets.token_hex(16)}-{secrets.token_hex(8)}-01'


def trace_id(value) -> str:
    parts = value.split('-') if isinstance(value, str) else []
    return parts[1] if len(parts) == 4 else ''


def through(path: str, body, who: str = 'blue') -> dict:
    tag = traceparent()
    answer = sf.req('POST', path, TOKENS[who], body, headers=[('traceparent', tag)])
    answer['trace_id'] = trace_id(tag)
    return answer


def deciders(answers: list, seconds: float = 6) -> list:
    """For each answer: the decisions logged with its trace id, [{replica, reason, status}]. The gateway keeps the caller's
    trace id and puts its own span id in the traceparent it sends, so the trace id is what is matched. A replica may log after
    the gateway has answered (the gateway gives up on extAuthz after 1s), so this waits up to `seconds` for every answer."""
    def read() -> list:
        seen: dict = {}
        for r in replicas():
            for entry in json_lines(log_of(r['id']), 'egress authorization'):
                tag = trace_id(entry.get('traceparent'))
                if tag:
                    seen.setdefault(tag, []).append({'replica': r['name'], 'reason': entry.get('reason'), 'status': entry.get('status')})
        return [seen.get(a.get('trace_id'), []) for a in answers]

    time.sleep(0.3)
    return wait_for(lambda: (lambda found: found if all(found) else None)(read()), seconds, 0.5) or read()


def per_replica(found: list) -> dict:
    return dict(collections.Counter(item[0]['replica'] for item in found if len(item) == 1))


def shown(answers: list, found: list) -> list:
    return [{'status': a['status'], 'reason_code': sf.envelope(a).get('reason_code'), 'apiResultCode': sf.envelope(a).get('apiResultCode'),
             'decided by': [f"{d['replica']} {d['reason']}" for d in w]} for a, w in zip(answers, found)]


CALL = r'''
import hashlib, http.client, json, socket, ssl, sys
out = []
for call in json.loads(sys.argv[1]):
    got = {"target": call["target"]}
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations("/tls/ca.crt")
        ctx.load_cert_chain("/tls/%s.crt" % call["cert"], "/tls/%s.key" % call["cert"])
        host, port = call["target"].rsplit(":", 1)
        conn = http.client.HTTPSConnection(call["name"], int(port), timeout=8, context=ctx)
        conn.sock = ctx.wrap_socket(socket.create_connection((host, int(port)), 8), server_hostname=call["name"])
        conn.request("POST", call["path"], body=b"", headers=call["headers"])
        response = conn.getresponse()
        raw = response.read()
        conn.close()
        auth = response.getheader("Authorization") or ""
        parts = auth[len("Sf-OpenApi "):].split(";") if auth.startswith("Sf-OpenApi ") else []
        try:
            body = json.loads(raw) if raw else {}
        except ValueError:
            body = {}
        got.update(status=response.status, scheme=auth.split(" ", 1)[0] if auth else "",
                   token_sha256=hashlib.sha256(parts[1].encode()).hexdigest()[:16] if len(parts) == 3 and parts[1] else "",
                   retry_after=response.getheader("Retry-After"),
                   body={k: body.get(k) for k in ("result", "reason_code", "revocation_epoch") if isinstance(body, dict) and k in body})
    except Exception as e:
        got["error"] = "%s: %s" % (type(e).__name__, str(e)[:200])
    out.append(got)
print(json.dumps(out))
'''


def check(r: dict, who: str, operation: str = 'agent-numbers.query') -> dict:
    """A decision asked of one replica directly, as the gateway asks it (the gateway's certificate, the headers of the route)."""
    route, path = OPERATIONS[operation]
    entry = STATE_GK[who]
    return {'target': f"{r['ip']}:{AUTHZ_PORT}", 'name': pki.GATEKEEPER_NAME, 'cert': 'gateway', 'path': '/v1/extauthz/check',
            'headers': {'x-idp-verified-subject': entry['client']['client_id'], 'x-idp-verified-tenant': entry['tenant_id'],
                        'x-idp-verified-env': 'TEST', 'x-idp-route-id': route, 'x-idp-provider-id': 'sfintl',
                        'x-idp-operation-id': operation, 'x-idp-environment': 'TEST', 'x-idp-method': 'POST', 'x-idp-path': path,
                        'traceparent': traceparent()}}


def direct(calls: list) -> list:
    """The calls, in order, from one throwaway container on the project network. It prints status, scheme and a hash prefix only."""
    docker('rm', '-f', CALLER)
    done = docker('run', '--rm', '--name', CALLER, '--network', NETWORK, '--user', sp.RUN_AS, '--read-only', '--cap-drop', 'ALL',
                  '--security-opt', 'no-new-privileges:true', '-v', f'{gk.TLS}:/tls:ro', sp.TOOLS_IMAGE,
                  'python', '-c', CALL, json.dumps(calls), timeout=120)
    try:
        found = json.loads(done.stdout)
    except ValueError:
        found = [{'error': (done.stderr or done.stdout).strip()[-300:]}] * len(calls)
    for call, got in zip(calls, found):
        got['replica'] = next((r['name'] for r in replicas() if f"{r['ip']}:{AUTHZ_PORT}" == call['target']), call['target'])
    return found


def control_at(r: dict, *args: str) -> dict:
    """gateway-control against one replica, under the revoker's certificate, from a throwaway container on the project network."""
    docker('rm', '-f', CALLER)
    done = docker('run', '--rm', '--name', CALLER, '--network', NETWORK, '--user', sp.RUN_AS, '--read-only', '--cap-drop', 'ALL',
                  '--security-opt', 'no-new-privileges:true', '-v', f"{sp.WORK / 'bin/gateway-control'}:/usr/local/bin/gateway-control:ro",
                  '-v', f'{gk.TLS}:/tls:ro', '--entrypoint', '/usr/local/bin/gateway-control', FRONT_IMAGE, *args,
                  '--authz', f"{r['ip']}:{AUTHZ_PORT}", '--authz-name', pki.GATEKEEPER_NAME, '--tls-cert', '/tls/revoker.crt',
                  '--tls-key', '/tls/revoker.key', '--tls-ca', '/tls/ca.crt', '--timeout', '5s', timeout=60)
    lines = [line for line in done.stdout.splitlines() if line.strip()]
    parsed = None
    if len(lines) == 1:
        try:
            parsed = json.loads(lines[0])
        except ValueError:
            pass
    said = done.stderr.strip().splitlines()[-1][:160] if done.stderr.strip() else ''
    return {'code': done.returncode, 'json': parsed if isinstance(parsed, dict) else None, 'said': said, 'replica': r['name']}


def control_note(result: dict) -> dict:
    body = result['json'] or {}
    return {'replica': result['replica'], 'exit': result['code'], 'outcome': body.get('outcome'), 'changed': body.get('changed'), 'said': result['said']}


def denied(got: dict, status: int, result: str, reason: str) -> bool:
    return got.get('status') == status and got.get('scheme') == '' and (got.get('body') or {}).get('result') == result \
        and (got.get('body') or {}).get('reason_code') == reason


def allowed(got: dict) -> bool:
    return got.get('status') == 200 and got.get('scheme') == 'Sf-OpenApi' and bool(got.get('token_sha256'))


def mirror_of(r: dict) -> dict:
    """The replica's own revocation file (account ids and reasons, no secret). {} when it cannot be read."""
    done = docker('exec', r['id'], 'cat', '/authz/mirror/revocations.json')
    try:
        document = json.loads(done.stdout)
    except ValueError:
        return {}
    return {'epoch': document.get('epoch'), 'revoked_accounts': sorted(document.get('revoked_accounts') or {})}


# ---- the stand-in -----------------------------------------------------------------------------------------------------------
def standin_reset():
    TOKEN_HITS.extend(hit for hit in sf.standin_hits() if hit.get('kind') == 'token')
    sf.standin_reset()


def token_requests(app_key: str) -> list:
    hits = TOKEN_HITS + [hit for hit in sf.standin_hits() if hit.get('kind') == 'token']
    return [hit for hit in hits if sf.token_app_key(hit) == app_key]


def dispatches() -> list:
    return [hit for hit in sf.standin_hits() if hit.get('kind') == 'dispatch']


def fetched_lines() -> list:
    """`sf openapi token fetched` per replica. With the lease coordinator the line says the replica's cache was filled, from the
    coordinator (VALID) or from the carrier (FETCH); it does not say which."""
    return [(r['name'], len(json_lines(log_of(r['id']), 'sf openapi token fetched'))) for r in replicas()]


def lease_answers() -> dict:
    """What sf-token-coordinator answered to acquire, counted from its log: {"FETCH": n, "VALID": n, ...}, and commits."""
    lines = json_lines(compose('logs', '--no-color', '--no-log-prefix', 'sf-token-coordinator').stdout, 'sf lease')
    counted = collections.Counter(entry.get('state') or '' for entry in lines if entry.get('path') == '/v1/sf-leases/acquire')
    counted['commits'] = sum(1 for entry in lines if entry.get('path') == '/v1/sf-leases/commit' and entry.get('status') == 200)
    return dict(counted)


# ---- cases ------------------------------------------------------------------------------------------------------------------
def query():
    return sf.query_body(sf.new_order_no(), 'SF000000000000')


def served(answer: dict) -> bool:
    return answer['status'] == 200 and sf.envelope(answer).get('apiResultCode') == 0


def two_replicas(r: sf.Results, coordinated: bool) -> tuple[dict, dict, bool]:
    reps = replicas()
    ips = sorted(x['ip'] for x in reps if x.get('ip'))
    r.note('replicas', [{'name': x['name'], 'ip': x['ip']} for x in reps])
    r.check('two gateway-authz containers of one service, both running', len(reps) == 2 and all(x['running'] for x in reps))
    r.check('two different addresses on the project network', len(set(ips)) == 2)
    resolved = sp.from_namespace('netns', sp.RESOLVE, 'gateway-authz').get('gateway-authz')
    r.note('gateway-authz resolved from the gateway\'s namespace', resolved)
    r.check('from the gateway\'s namespace the name gateway-authz resolves to both addresses', resolved == ips)
    pins = sp.pinned('egress').get('gateway-authz:9443')
    r.note('the gateway\'s egress pins for gateway-authz:9443', pins)
    r.check('the gateway\'s egress rules pin gateway-authz:9443 to both addresses', pins == ips)
    opened = sp.from_namespace('netns', sp.CONNECT, *[f'{ip}:{AUTHZ_PORT}' for ip in ips])
    r.check('from the gateway\'s namespace both addresses open on 9443', bool(ips) and all(opened.get(f'{ip}:{AUTHZ_PORT}') == 0 for ip in ips))
    lines = [startup(x) for x in reps]
    r.note('startup line of each replica (selected fields)', lines)
    if coordinated:
        r.check('each replica started with the lease coordinator, authz-state for revocations and for quota',
                len(lines) == 2 and all(s.get('sf_openapi_lease') is True and s.get('authz_state') is True and s.get('authz_state_quota') is True
                                        and s.get('revocations') == 'authz-state' and s.get('rate_limits') == 'enabled' for s in lines))
        r.check('each replica has a tmpfs of its own at /authz/mirror and no bind mount or volume there (two revocation files, not one)',
                len(reps) == 2 and all('/authz/mirror' in x['tmpfs'] and '/authz/mirror' not in x['binds'] for x in reps))
        r.check('the entrypoint is the image\'s shell, which execs gateway-authz with its arguments ("$@", not "$$@")',
                all(x['entrypoint'][:2] == ['/bin/sh', '-ec'] and 'exec /usr/local/bin/gateway-authz "$@"' in x['entrypoint'][2] for x in reps))
    else:
        r.check('each replica started without coordinators: no lease, no authz-state, revocations in memory',
                len(lines) == 2 and all(s.get('sf_openapi_lease') is False and s.get('authz_state') is False and s.get('revocations') == 'memory' for s in lines))
    answers = [through(sf.QUERIES, query()) for _ in range(20)]
    found = deciders(answers)
    counts = per_replica(found)
    r.note('20 blue queries through front: decisions per replica', counts)
    r.check('each of the 20 was decided by exactly one replica (its traceparent is in that replica\'s log, once)', all(len(w) == 1 for w in found))
    spread = len(reps) == 2 and all(counts.get(x['name'], 0) > 0 for x in reps)
    r.note('agentgateway sent extAuthz to both replicas', 'yes' if spread else 'no: every decision came from one replica; the other is called directly below')
    a, b = (reps + [{}, {}])[:2]
    return a, b, answers


def default_cases(r: sf.Results, made: dict):
    blue_key = made['apps'][sf.BLUE_ACCOUNT]['app_key']
    green_user = made['apps'][sf.GREEN_ACCOUNT]['api_username']
    standin_reset()

    sf.STATE['label'] = 'CO-01'
    r.case('CO-01', 'two replicas: two containers, two addresses, gateway-authz resolves to both; which replica decided each request')
    a, b, answers = two_replicas(r, True)
    r.check('the 20 queries: HTTP 200, apiResultCode 0', all(served(x) for x in answers))

    sf.STATE['label'] = 'CO-02'
    r.case('CO-02', 'one SF International token for both replicas: the token endpoint is called once, and still once after one replica restarts')
    got = direct([check(a, 'blue'), check(b, 'blue')])
    r.note('direct checks', got)
    r.check('a direct check on each replica: 200 and an Sf-OpenApi credential', len(got) == 2 and all(allowed(x) for x in got))
    r.check('both replicas hand out the same access token (compared by a hash prefix)',
            len({x.get('token_sha256') for x in got}) == 1 and bool(got[0].get('token_sha256')))
    r.check('the stand-in\'s token endpoint was called exactly once for the blue app', len(token_requests(blue_key)) == 1)
    seen = dispatches()
    carried = {tuple(sf.header_values(hit, 'token')) for hit in seen}
    r.check('the 20 dispatches the carrier received all carried one and the same token, and none was refused at the token check',
            len(seen) == 20 and len(carried) == 1 and all(hit.get('refused_at') != 'token' for hit in seen))
    r.note('"sf openapi token fetched" lines per replica (a cache filled, from the coordinator or the carrier; the line does not say which)', fetched_lines())
    leases = lease_answers()
    r.note('sf-token-coordinator\'s answers to acquire, and commits', leases)
    r.check('sf-token-coordinator answered FETCH once and took one commit; every other acquire was VALID',
            leases.get('FETCH') == 1 and leases.get('commits') == 1 and set(leases) <= {'FETCH', 'VALID', 'commits'})
    target = a
    standin_reset()
    after = restart(target)
    r.note('restarted', {'name': target['name'], 'address before': target['ip'], 'address after': after.get('ip')})
    r.check('it came back: running, a new "gateway-authz listening" line', after.get('running') is True)
    follow_addresses(r, f"{target['name']} restarted")
    again = direct([check(after, 'blue')])
    r.note('direct check on the restarted replica', again)
    r.check('the restarted replica, empty cache: direct check 200, Sf-OpenApi, the same token as before',
            allowed(again[0]) and again[0].get('token_sha256') == got[0].get('token_sha256'))
    answers = [through(sf.QUERIES, query()) for _ in range(10)]
    found = deciders(answers)
    r.note('10 more queries through front: decisions per replica', per_replica(found))
    r.check('10 more queries through front: all HTTP 200, apiResultCode 0', all(served(x) for x in answers))
    r.check('still exactly one token request for the blue app in this run', len(token_requests(blue_key)) == 1)
    leases = lease_answers()
    r.note('sf-token-coordinator\'s answers after the restart', leases)
    r.check('sf-token-coordinator still answered FETCH only once: the restarted replica was answered VALID', leases.get('FETCH') == 1)
    reps = replicas()
    a, b = reps[0], reps[1]

    sf.STATE['label'] = 'CO-03'
    r.case('CO-03', 'revoke through one replica: denied 403 ACCOUNT_REVOKED whichever replica decides, and on the other one asked directly; restore through the other')
    standin_reset()
    revoked = control_at(a, 'revoke', '--account', sf.BLUE_ACCOUNT, '--reason', 'coordinators pool: CO-03')
    r.note('gateway-control revoke', control_note(revoked))
    r.check(f"gateway-control revoke through {a['name']}: exit 0, REVOKED, changed",
            sf.outcome(revoked, 'REVOKED', command='revoke', account=sf.BLUE_ACCOUNT, revoked=True, changed=True))
    answers = [through(sf.QUERIES, query()) for _ in range(6)]
    found = deciders(answers)
    r.note('6 blue queries through front', shown(answers, found))
    r.check('6 blue queries through front: all 403 with reason_code ACCOUNT_REVOKED',
            all(x['status'] == 403 and sf.envelope(x).get('reason_code') == 'ACCOUNT_REVOKED' for x in answers))
    r.check('each was decided ACCOUNT_REVOKED by one replica', all(len(w) == 1 and w[0]['reason'] == 'ACCOUNT_REVOKED' for w in found))
    asked = direct([check(b, 'blue'), check(a, 'blue')])
    r.note('direct checks', asked)
    r.check(f"{b['name']}, which did not take the revoke, asked directly: 403 DENY ACCOUNT_REVOKED, no credential",
            denied(asked[0], 403, 'DENY', 'ACCOUNT_REVOKED'))
    r.check(f"{a['name']} asked directly: 403 DENY ACCOUNT_REVOKED, no credential", denied(asked[1], 403, 'DENY', 'ACCOUNT_REVOKED'))
    files = {x['name']: mirror_of(x) for x in (a, b)}
    r.note('each replica\'s own revocation file', files)
    r.check(f"{b['name']}'s own revocation file does not list blue: its refusal came from authz-state, not from a file",
            files[b['name']].get('revoked_accounts') == [] and bool(files[b['name']]))
    r.check(f"{a['name']}'s own file lists blue (it wrote the coordinator's snapshot after its change)",
            files[a['name']].get('revoked_accounts') == [sf.BLUE_ACCOUNT])
    kinds = {hit.get('kind') for hit in sf.standin_hits()}
    r.check('the carrier got nothing for those requests (no dispatch, no token request)', not kinds & {'dispatch', 'token'})
    green = through(sf.QUERIES, query(), 'green')
    r.check('green is not affected: query HTTP 200, apiResultCode 0', served(green))
    lifted = control_at(b, 'restore', '--account', sf.BLUE_ACCOUNT)
    r.note('gateway-control restore', control_note(lifted))
    r.check(f"gateway-control restore through {b['name']}: exit 0, LIFTED, changed",
            sf.outcome(lifted, 'LIFTED', command='restore', account=sf.BLUE_ACCOUNT, revoked=False, changed=True))
    answers = [through(sf.QUERIES, query()) for _ in range(4)]
    r.check('blue through front again: 4 queries, all HTTP 200, apiResultCode 0', all(served(x) for x in answers))
    asked = direct([check(a, 'blue'), check(b, 'blue')])
    r.check('and directly on both replicas: 200 with a credential', all(allowed(x) for x in asked))

    sf.STATE['label'] = 'CO-04'
    r.case('CO-04', 'a shared quota: green may print one label an hour; the second, through the gateway or on the other replica, is 429 RATE_LIMITED')
    standin_reset()
    first = through(sf.PRINTS, sf.print_body('SF000000000000', green_user), 'green')
    one = deciders([first])[0]
    r.note('first print', shown([first], [one]))
    r.check('the first green print through front: HTTP 200 (the carrier\'s business answer is not judged)', first['status'] == 200)
    printed = len(dispatches())
    second = through(sf.PRINTS, sf.print_body('SF000000000000', green_user), 'green')
    two = deciders([second])[0]
    r.note('second print', shown([second], [two]))
    r.check('the second green print through front: 429 with reason_code RATE_LIMITED', second['status'] == 429 and sf.envelope(second).get('reason_code') == 'RATE_LIMITED')
    r.check('it was decided RATE_LIMITED by one replica', len(two) == 1 and two[0]['reason'] == 'RATE_LIMITED')
    r.check('the 429 carries no Authorization header, and the carrier got no second dispatch',
            'authorization' not in sf.header_names(second) and len(dispatches()) == printed == 1)
    first_by = one[0]['replica'] if len(one) == 1 else a['name']
    other = b if first_by == a['name'] else a
    asked = direct([check(other, 'green', 'labels.print')])
    r.note('direct, on the replica that did not decide the first print', asked)
    r.check(f"{other['name']} asked directly: 429 DENY RATE_LIMITED, no credential, a Retry-After",
            denied(asked[0], 429, 'DENY', 'RATE_LIMITED') and bool(asked[0].get('retry_after')))
    r.check('blue\'s queries are not limited: HTTP 200', served(through(sf.QUERIES, query())))

    sf.STATE['label'] = 'CO-05'
    r.case('CO-05', 'authz-state stopped: 503 REVOCATION_STATE_UNAVAILABLE, the carrier gets nothing; a replica restarted meanwhile refuses to start')
    green_revoked = control_at(a, 'revoke', '--account', sf.GREEN_ACCOUNT, '--reason', 'coordinators pool: CO-06')
    r.check('before: green revoked through one replica (REVOKED), for CO-06', sf.outcome(green_revoked, 'REVOKED', account=sf.GREEN_ACCOUNT, changed=True))
    standin_reset()
    stopped = compose('stop', '--timeout', '5', 'authz-state')
    r.check('authz-state is stopped', stopped.returncode == 0 and service('authz-state').get('running') is False)
    started = {x['name']: x['started_at'] for x in replicas()}
    answers = [through(sf.QUERIES, query()) for _ in range(4)]
    found = deciders(answers)
    r.note('4 blue queries through front', shown(answers, found))
    r.check('4 blue queries through front: all 503', all(x['status'] == 503 for x in answers))
    r.check('each was decided REVOCATION_STATE_UNAVAILABLE by one replica', all(len(w) == 1 and w[0]['reason'] == 'REVOCATION_STATE_UNAVAILABLE' for w in found))
    asked = direct([check(a, 'blue'), check(b, 'blue')])
    r.note('direct checks', asked)
    r.check('directly on each replica: 503 INDETERMINATE REVOCATION_STATE_UNAVAILABLE, no credential',
            all(denied(x, 503, 'INDETERMINATE', 'REVOCATION_STATE_UNAVAILABLE') for x in asked))
    kinds = {hit.get('kind') for hit in sf.standin_hits()}
    r.check('the carrier got nothing (no dispatch, no token request)', not kinds & {'dispatch', 'token'})
    r.check('both replicas kept running (same start times)', {x['name']: x['started_at'] for x in replicas()} == started)
    before = listening(b)
    docker('restart', '-t', '5', b['id'], timeout=60)
    gone = wait_for(lambda: (lambda x: x if x and not x['running'] else None)(inspect(b['id'])), 30)
    tail = [line for line in log_of(b['id']).splitlines() if line.startswith('gateway-authz:')][-1:]
    r.note(f"{b['name']} restarted while authz-state is down", {'exit': (gone or {}).get('exit'), 'last error line': tail})
    r.check(f"{b['name']}, restarted while authz-state is down, exits 1 without listening (the initial snapshot is required)",
            bool(gone) and gone['exit'] == 1 and listening(b) == before and bool(tail) and 'authz state' in tail[0])

    sf.STATE['label'] = 'CO-06'
    r.case('CO-06', 'authz-state started again: the revocation table is still there (its state file); the quota bucket is full again (memory only)')
    r.check('authz-state listens again and its check says healthy', start_coordinator('authz-state'))
    before = listening(b)
    docker('start', b['id'], timeout=60)
    wait_for(lambda: listening(b) > before or not inspect(b['id']).get('running'), 40)
    RESTARTS.append({'replica': b['name'], 'address before': b['ip'], 'address after': inspect(b['id']).get('ip'), 'case': 'CO-06'})
    r.check(f"{b['name']} started now that authz-state answers", inspect(b['id']).get('running') is True and listening(b) > before)
    follow_addresses(r, f"{b['name']} started again")
    reps = replicas()
    a, b = reps[0], reps[1]
    asked = direct([check(b, 'green'), check(a, 'green')])
    r.note('green, directly', asked)
    r.check('green is still revoked on both replicas: 403 DENY ACCOUNT_REVOKED', all(denied(x, 403, 'DENY', 'ACCOUNT_REVOKED') for x in asked))
    try:
        kept = json.loads((sp.WORK / 'coordinators/authz-state/state.json').read_text())
    except (OSError, ValueError):
        kept = {}
    r.note('authz-state\'s state file (account ids only)', {'epoch': kept.get('epoch'), 'revoked_accounts': sorted(kept.get('revoked_accounts') or {})})
    r.check('authz-state\'s state file lists green', sf.GREEN_ACCOUNT in (kept.get('revoked_accounts') or {}))
    lifted = control_at(b, 'restore', '--account', sf.GREEN_ACCOUNT)
    r.check('green restored through the other replica: LIFTED', sf.outcome(lifted, 'LIFTED', account=sf.GREEN_ACCOUNT, changed=True))
    asked = direct([check(a, 'green', 'labels.print')])
    r.note('green labels.print, directly', asked)
    r.check('green labels.print: 200 with a credential; the bucket CO-04 emptied is full again (quota buckets are memory only, ADR-0023)', allowed(asked[0]))

    sf.STATE['label'] = 'CO-07'
    r.case('CO-07', 'sf-token-coordinator stopped, both replicas restarted with empty caches: 503, lease_unavailable in their logs, the token endpoint not called')
    stopped = compose('stop', '--timeout', '5', 'sf-token-coordinator')
    r.check('sf-token-coordinator is stopped; authz-state is running', stopped.returncode == 0 and service('sf-token-coordinator').get('running') is False
            and service('authz-state').get('running') is True)
    marks = {x['name']: log_of(x['id']).count('lease_unavailable') for x in replicas()}
    back = [restart(x) for x in replicas()]
    r.check('both replicas restarted and listen again (authz-state answered their first snapshot)', len(back) == 2 and all(x.get('running') for x in back))
    follow_addresses(r, 'both replicas restarted')
    reps = replicas()
    a, b = reps[0], reps[1]
    standin_reset()
    answers = [through(sf.QUERIES, query()) for _ in range(3)]
    found = deciders(answers)
    r.note('3 blue queries through front', shown(answers, found))
    r.check('3 blue queries through front: all 503', all(x['status'] == 503 for x in answers))
    r.check('each was decided CREDENTIAL_UNAVAILABLE by one replica', all(len(w) == 1 and w[0]['reason'] == 'CREDENTIAL_UNAVAILABLE' for w in found))
    asked = direct([check(a, 'blue'), check(b, 'blue')])
    r.note('direct checks', asked)
    r.check('directly on each replica: 503 INDETERMINATE CREDENTIAL_UNAVAILABLE, no credential',
            all(denied(x, 503, 'INDETERMINATE', 'CREDENTIAL_UNAVAILABLE') for x in asked))
    now = {x['name']: log_of(x['id']).count('lease_unavailable') for x in replicas()}
    r.note('lease_unavailable in each replica\'s log, before and after', {name: [marks.get(name), now.get(name)] for name in now})
    r.check('both replicas\' logs have new lease_unavailable lines', len(now) == 2 and all(now[name] > marks.get(name, 0) for name in now))
    kinds = {hit.get('kind') for hit in sf.standin_hits()}
    r.check('the carrier\'s token endpoint was not called, and nothing was dispatched', not kinds & {'dispatch', 'token'})
    r.check('in the whole run, one token request for the blue app', len(token_requests(blue_key)) == 1)


def control_cases(r: sf.Results, made: dict):
    blue_key = made['apps'][sf.BLUE_ACCOUNT]['app_key']
    standin_reset()
    sf.STATE['label'] = 'CTL-01'
    r.case('CTL-01', 'control: the same two replicas without coordinators.yml')
    a, b, answers = two_replicas(r, False)
    r.note('the 20 queries through front: HTTP status and apiResultCode',
           dict(collections.Counter(f"{x['status']}/{sf.envelope(x).get('apiResultCode')}" for x in answers)))
    sf.STATE['label'] = 'CTL-02'
    r.case('CTL-02', 'control: each replica takes its own token from the carrier, and the second voids the first (what ADR-0022 is for)')
    got = direct([check(a, 'blue'), check(b, 'blue'), check(a, 'blue')])
    r.note('direct checks, in this order', got)
    fetchers = fetched_lines()
    r.note('"sf openapi token fetched" lines per replica', fetchers)
    hits = token_requests(blue_key)
    r.note('token requests for the blue app in this run', len(hits))
    r.check('the stand-in\'s token endpoint was called at least twice for the blue app (expected without the coordinator)', len(hits) >= 2)
    r.check('the two replicas hold different tokens (compared by a hash prefix)', len({x.get('token_sha256') for x in got if x.get('token_sha256')}) >= 2)
    standin_reset()
    answers = [through(sf.QUERIES, query()) for _ in range(10)]
    found = deciders(answers)
    voided = [hit for hit in dispatches() if hit.get('refused_at') == 'token']
    counts = per_replica(found)
    r.note('10 queries through front: decisions per replica', counts)
    r.note('of the dispatches, refused by the carrier at the token check', {'refused': len(voided), 'dispatches': len(dispatches())})
    if len(counts) == 2:
        r.check('both replicas decided some of the 10, and the carrier refused some dispatches at the token check: one replica\'s token was voided by the other\'s',
                len(voided) >= 1)
    sf.STATE['label'] = 'CTL-03'
    r.case('CTL-03', 'control: without coordinators.yml gateway-authz has no --revocations, so a revoke is refused (nothing to share)')
    refused = control_at(a, 'revoke', '--account', sf.BLUE_ACCOUNT, '--reason', 'coordinators pool: control')
    r.note('gateway-control revoke', control_note(refused))
    r.check('gateway-control revoke: exit 3, NO_REVOKER_CONFIGURED', refused['code'] == 3 and (refused['json'] or {}).get('outcome') == 'NO_REVOKER_CONFIGURED')


# ---- the run ----------------------------------------------------------------------------------------------------------------
def my_containers() -> list:
    return docker('ps', '-a', '-q', '--filter', f'label=com.docker.compose.project={PROJECT}').stdout.split()


def teardown():
    if sp.WORK is None or os.environ.get('COORD_POOL_KEEP'):
        return
    try:
        if (sp.WORK / 'pool.env').exists():
            compose('down', '--volumes', '--remove-orphans', '--timeout', '5')
    except Exception:
        pass
    mine = f'label=com.docker.compose.project={PROJECT}'
    left = my_containers()
    if left:
        docker('rm', '-f', '-v', *left)
    for network in docker('network', 'ls', '-q', '--filter', mine).stdout.split():
        docker('network', 'rm', network)
    volumes = docker('volume', 'ls', '-q', '--filter', mine).stdout.split()
    if volumes:
        docker('volume', 'rm', '-f', *volumes)
    docker('rm', '-f', sp.PROBE, sp.SCRATCH, CALLER)
    shutil.rmtree(sp.WORK, ignore_errors=True)
    sp.WORK = None


def logs_of() -> dict:
    text = lambda name: compose('logs', '--no-color', '--no-log-prefix', name).stdout
    found = {'gateway log': text('agentgateway'), 'provider-signer log': text('signer')}
    for x in replicas():
        found[f"{x['name']} log"] = log_of(x['id'])
    if COORDINATED:
        found['sf-token-coordinator log'] = text('sf-token-coordinator')
        found['authz-state log'] = text('authz-state')
    return found


def ports_in_use() -> list:
    used = []
    for port in PORTS:
        with socket.socket() as s:
            s.settimeout(0.3)
            if s.connect_ex(('127.0.0.1', port)) == 0:
                used.append(port)
    return used


def main() -> int:
    global COORDINATED, STANDIN_IMAGE
    parser = argparse.ArgumentParser(description='two gateway-authz replicas with the Phase 2 coordinators, on the single-host pool; not an acceptance pass')
    parser.add_argument('--control', choices=['no-coordinators'], help='the same two replicas without coordinators.yml')
    args = parser.parse_args()
    COORDINATED = args.control is None
    if ports_in_use():
        die(f'ports in use: {ports_in_use()} (this suite needs 27881-27895)')
    if my_containers():
        die(f'containers of {PROJECT} are left from an earlier run; take them down first')
    if gk.call('GET', gk.ISSUER + '/health/ready')[0] != 200 or gk.call('GET', gk.BRIDGE + '/admin/me')[0] != 200:
        die('the local Gatekeeper is not ready: tests/integration/gatekeeper/stack.sh up')
    _binary, reported = sp.pin.resolve()
    STANDIN_IMAGE = standin_image()
    made: dict = {'apps': {}}
    for account in (sf.BLUE_ACCOUNT, sf.GREEN_ACCOUNT):
        made['apps'][account] = {'app_key': 'app' + secrets.token_hex(8), 'app_secret': secrets.token_hex(24),
                                 'encoding_aes_key': sf.new_aes_key(), 'api_username': 'user' + secrets.token_hex(4)}
    made['token_endpoint'] = f'http://{sp.CARRIER_NAME}:{sp.IN_POOL["carrier"]}/openapi/api/token'
    made['mock_secret'] = secrets.token_urlsafe(24)
    sf.PLAIN_HTTP_HOST[0] = ''
    sf.CARRIER_URL[0] = sp.settings_carrier(False)
    sf.MOCK_SECRET = made['mock_secret']
    sp.WORK = Path(tempfile.mkdtemp(prefix='coord-pool-'))
    if not os.environ.get('COORD_POOL_KEEP'):
        atexit.register(teardown)
    try:
        return run(args, made, reported)
    finally:
        teardown()


def run(args, made: dict, reported: dict) -> int:
    state = gk.seed()
    gk.sync_tuples(state)
    STATE_GK.update(state)
    pki.issue(gk.TLS)
    gk.publish_pdp_tls()
    snapshot = sf.CONFIG.read_text(encoding='utf-8')
    sp.prepare(state, made, False, snapshot)
    for directory in ('coordinators', 'coordinators/sf-token-coordinator', 'coordinators/authz-state'):
        (sp.WORK / directory).mkdir(exist_ok=True)
        os.chmod(sp.WORK / directory, 0o700)
    sp.put(sp.WORK / 'authz/rate-limits.json', json.dumps(RATE_LIMITS), 0o600)
    sp.build('./cmd/sf-token-coordinator', 'sf-token-coordinator')
    sp.build('./cmd/authz-state', 'authz-state')
    mode = 'control: no-coordinators' if args.control else 'coordinators.yml'
    say(f'pool {PROJECT} in {sp.WORK} ({mode}); not an acceptance pass')
    stood = compose('up', '-d', 'sfintl-standin', timeout=180)
    if stood.returncode != 0 or not wait_for(lambda: sp.container('sfintl-standin').get('running') and sp.container('sfintl-standin').get('ip'), 30):
        say(f'the stand-in did not start (compose exit {stood.returncode}): ' + stood.stderr[-600:])
        return 1
    first = compose('up', '-d', 'agentgateway', 'gateway-authz', 'outsider', 'signer', timeout=600)
    if first.returncode != 0:
        say('the pool did not start: ' + first.stderr[-1200:])
        for x in replicas():
            say(f"{x['name']}: " + log_of(x['id'])[-600:])
        return 1
    if not wait_for(lambda: len(replicas()) == 2 and all(listening(x) > 0 for x in replicas()), 60):
        say('the two replicas do not both listen: ' + json.dumps([(x['name'], x['running'], x['exit']) for x in replicas()]))
        return 1
    if not wait_for(lambda: sp.read_back('/api/runtime')['status'] == 200, 40):
        say('the gateway\'s read-back does not answer')
        return 1
    published = sp.publish(snapshot)
    say(f"publish: exit {published['exit']}, outcome {published['outcome']}, {published['detail']}")
    full = compose('up', '-d', timeout=600)
    if published['exit'] != 0 or full.returncode != 0:
        say('publish or the full start failed: ' + published['stderr'] + full.stderr[-400:])
        return 1

    def dump_has(needle: str) -> bool:
        got = sp.read_back('/config_dump')
        return got.get('status') == 200 and needle in json.dumps(got.get('json'))

    if not wait_for(lambda: dump_has('sfintl-orders-create'), 40):
        say('the gateway did not load the published configuration')
        return 1
    sf.HOOKS.update(gateway_port=PORT['front'], mock_port=PORT['mock'], signer_port=PORT['signer'])
    TOKENS.update(blue=gk.token_for(state['blue']['client']), green=gk.token_for(state['green']['client']))
    made['tokens'] = list(TOKENS.values())
    if not all(TOKENS.values()):
        say('no token from the local Hydra')
        return 1
    if not wait_for(lambda: sf.req('GET', sf.ORDERS, TOKENS['blue'])['status'] == 404, 40):
        say('requests through front do not get the gateway\'s 404 for an unrouted GET (JWKS not loaded?)')
        return 1
    ips = lambda: sorted(x['ip'] for x in replicas())
    if not wait_for(lambda: (sp.pinned('egress').get('gateway-authz:9443') or []) == ips(), 30):
        say(f"the gateway's rules do not pin both replicas: {sp.pinned('egress')}, replicas at {ips()}")
        return 1
    sf.CALLS.clear()
    results = sf.Results()
    started_at = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
    failure: BaseException | None = None
    try:
        (control_cases if args.control else default_cases)(results, made)
    except BaseException as caught:
        failure = caught
    finally:
        try:
            sf.harvest(sf.standin_hits())
        except BaseException:
            pass
    health_lines = {}
    if COORDINATED:
        for name in ('sf-token-coordinator', 'authz-state'):
            health_lines[name] = compose('logs', '--no-color', '--no-log-prefix', name).stdout.count('TLS handshake error')
    record = {'started_at': started_at, 'finished_at': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
              'mode': mode, 'project': PROJECT, 'agentgateway': reported['version'],
              'repository_head': subprocess.run(['git', '-C', str(ROOT), 'rev-parse', '--short', 'HEAD'], capture_output=True, text=True).stdout.strip(),
              'gatekeeper_commit': subprocess.run(['git', '-C', os.environ.get('GK_SRC', str(Path.home() / '.local/src/idp-gatekeeper')), 'rev-parse', '--short', 'HEAD'],
                                                  capture_output=True, text=True).stdout.strip(),
              'replica_restarts': RESTARTS, 'egress_forget': FORGETS, 'coordinator_health_check_lines': health_lines,
              'calls': len(sf.CALLS), 'cases': results.cases}
    if failure is not None:
        record['aborted'] = f'{type(failure).__name__}: {failure}'
    scanned, looked_for = sf.scan(made, state, json.dumps(record, ensure_ascii=False), False, logs_of())
    results.case('CO-08' if not args.control else 'CTL-04', 'the logs (gateway, both replicas, signer, coordinators), this run\'s output and the record hold none of this run\'s secrets')
    for where, found in scanned.items():
        results.check(f'{where}: none of the {len(looked_for)} secrets of this run, and no value of the carrier\'s authorization scheme',
                      not found['secret found'] and not found['Sf-OpenApi value found'])
    teardown()
    results.case('cleanup', 'the project is gone: no container, network or volume left, the ports are free, the temporary directory is removed')
    mine = f'label=com.docker.compose.project={PROJECT}'
    results.check('no container of the project', not my_containers())
    results.check('no network or volume of the project', not docker('network', 'ls', '-q', '--filter', mine).stdout.split()
                  and not docker('volume', 'ls', '-q', '--filter', mine).stdout.split())
    results.check('ports 27881-27895 are free', not ports_in_use())
    results.check('no probe, caller or staging container left', all(docker('inspect', name).returncode != 0 for name in (sp.PROBE, sp.SCRATCH, CALLER)))
    say(f'\nagentgateway {reported["version"]}; {mode}; repository {record["repository_head"]}; Gatekeeper {record["gatekeeper_commit"]}')
    say(f'started {started_at}, finished {record["finished_at"]}; coordinator health-check lines: {health_lines}')
    say('replica restarts (address before -> after): ' + '; '.join(f"{x['case']} {x['replica'][-15:]} {x['address before']} -> {x['address after']}" for x in RESTARTS))
    say(f'egress forget + gateway restart needed: {len(FORGETS)}')
    results.report()
    failed = results.failed()
    checks = sum(1 for case in results.cases for item in case['checks'] if item['ok'])
    total = sum(1 for case in results.cases for item in case['checks'] if item['ok'] is not None)
    say(f"\n{len(results.cases) - len(failed)}/{len(results.cases)} cases, {checks}/{total} checks ({mode}); not an acceptance pass")
    if failure is not None:
        say(f"aborted: {record['aborted']}")
        if isinstance(failure, SystemExit):
            return int(failure.code) if isinstance(failure.code, int) and failure.code else 1
        raise failure
    gk.sync_tuples(state)
    return int(bool(failed))


if __name__ == '__main__':
    sys.exit(main())
