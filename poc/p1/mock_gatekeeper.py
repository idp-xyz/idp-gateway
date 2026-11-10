#!/usr/bin/env python3
"""MOCK Gatekeeper PDP + Credential Broker for the P1 PoC. Loopback only.

Two endpoints of contracts/gatekeeper/openapi.yaml, both behind mutual TLS:

  /v1/extauthz/check                  agentgateway's HTTP ExtAuthZ protocol. 2xx allows, anything
                                      else denies; on allow the `authorization` response header
                                      carries the provider credential (Mode A in G04 §4).
                                      Gateway identity only.
  /v1/egress/authorizations/decision  The neutral decision API. Answers with a decision and a
                                      credential handle, never with a credential (Mode B: the
                                      local broker redeems the handle from its own store).
                                      Gateway or broker identity.

What is real here: the TLS handshake and the caller identity taken from the verified client
certificate; the decision rule, scripts/policy_reference.py, the same reference logic the
unit tests cover. What is not: the CA (made per run by pki.py), storage, a real Secret
Manager, a real provider token endpoint. The tenant and service are still what the gateway
says its validated token contained: this mock never sees the caller's token.
"""
from __future__ import annotations
import argparse, datetime, json, ssl, sys, threading, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from policy_reference import EgressRequest, TrustedPrincipal, evaluate  # noqa: E402
import pki  # noqa: E402

LOCK = threading.Lock()
LOG: list[dict] = []
REFUSED: list[str] = []   # TLS handshakes this server refused
STATE = {'mode': 'normal', 'revoked': set(), 'revocation_epoch': 0}
CFG: dict = {}

# Context the gateway derives from the validated token and from route constants.
TRUSTED = ('x-idp-verified-subject', 'x-idp-verified-tenant', 'x-idp-verified-env', 'x-idp-route-id',
           'x-idp-provider-id', 'x-idp-operation-id', 'x-idp-environment', 'x-idp-method', 'x-idp-path')
DECISION_REQUIRED = ('request_id', 'route_id', 'operation_id', 'provider_id', 'requested_account_id',
                     'environment', 'method', 'path', 'config_digest')
DECISION_OPTIONAL = ('service_id', 'tenant_id', 'token_environment', 'delegated_subject')
MAY_CALL = {'/v1/extauthz/check': ('gateway',), '/v1/egress/authorizations/decision': ('gateway', 'broker')}


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'mock-gatekeeper'
    peer = ''

    def log_message(self, *a):
        pass

    def setup(self):
        # The handshake happens here, in the connection's own thread. Without a certificate
        # from the workload CA there is no HTTP exchange at all.
        self.request.settimeout(10)
        try:
            self.request = CFG['tls'].wrap_socket(self.request, server_side=True)
        except (ssl.SSLError, OSError) as e:
            with LOCK:
                REFUSED.append(getattr(e, 'reason', None) or type(e).__name__)
            raise
        self.request.settimeout(None)
        self.peer = pki.peer_identity(self.request)
        super().setup()

    def _send(self, status: int, payload: dict, headers: dict | None = None):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _handle(self):
        length = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(length) if length else b''
        parts = urlsplit(self.path)
        if parts.path == '/healthz':
            return self._send(200, {'ok': True})
        if parts.path.startswith('/admin/'):
            if self.peer != pki.ID['operator'] or self.headers.get('X-Poc-Admin') != CFG['admin_secret']:
                return self._send(404, {'error': 'not_found'})
            return self._admin(parts.path, parse_qs(parts.query))
        if parts.path not in MAY_CALL:
            return self._send(404, {'error': 'not_found'})

        with LOCK:
            LOG.append({'seq': len(LOG) + 1, 'received_at': time.time(), 'method': self.command, 'raw_target': self.path,
                        'peer_identity': self.peer, 'tls_version': self.connection.version(),
                        'headers': [[k, v] for k, v in self.headers.items()], 'body_len': len(body)})
            mode = STATE['mode']

        # 1. Who is calling? The identity is the one in the verified client certificate. A
        #    business app must not be able to ask for a credential, and neither may the broker.
        if self.peer not in [pki.ID[name] for name in MAY_CALL[parts.path]]:
            return self._deny(401, 'GATEWAY_WORKLOAD_UNAUTHENTICATED')

        if mode == 'error500':
            return self._send(500, {'error': 'injected_pdp_failure'})
        if mode == 'slow':
            time.sleep(float(CFG['pdp_slow_seconds']))
        return self._check(mode) if parts.path == '/v1/extauthz/check' else self._decision(body)

    # ---- decision -------------------------------------------------------------------
    def _deny(self, status: int, reason: str):
        return self._send(status, {'result': 'DENY', 'reason_code': reason,
                                   'policy_version': CFG['policy']['version'],
                                   'revocation_epoch': STATE['revocation_epoch']})

    def _decide(self, ctx: dict, requested: str):
        """-> (reason for denial or '', granted account, credential binding, revocation epoch)"""
        principal = None
        if ctx['subject'] and ctx['tenant'] and ctx['token_env']:
            principal = TrustedPrincipal(service_id=ctx['subject'], tenant_id=ctx['tenant'], verified=True,
                                         environment=ctx['token_env'])

        # The account is a request, not a fact. With no request, a tenant that has exactly
        # one granted account for this operation gets that one.
        if not requested and principal is not None:
            for row in CFG['policy']['registered_operations']:
                if row['operation_id'] == ctx['operation'] and row['provider_id'] == ctx['provider']:
                    granted = row.get('accounts_by_tenant', {}).get(principal.tenant_id, [])
                    if len(granted) == 1:
                        requested = granted[0]

        decision = evaluate(CFG['policy'], principal, EgressRequest(
            provider_id=ctx['provider'], operation_id=ctx['operation'], method=ctx['method'],
            path=ctx['path'], account_id=requested, environment=ctx['environment']))
        # Revocation is checked on every decision and is independent of route publication.
        with LOCK:
            revoked = requested in STATE['revoked']
            epoch = STATE['revocation_epoch']
        if decision.result != 'ALLOW':
            return decision.reason, requested, None, epoch
        if revoked:
            return 'ACCOUNT_REVOKED', requested, None, epoch
        return '', requested, decision.credential_binding_ref, epoch

    def _check(self, mode: str):
        # Trusted context must be present exactly once; a second copy means something
        # other than the gateway managed to add one.
        h = {}
        for name in TRUSTED:
            values = self.headers.get_all(name) or []
            if len(values) > 1:
                return self._deny(403, 'AMBIGUOUS_TRUSTED_CONTEXT')
            h[name] = values[0] if values else ''
        denied, account, _, epoch = self._decide(
            {'subject': h['x-idp-verified-subject'], 'tenant': h['x-idp-verified-tenant'], 'token_env': h['x-idp-verified-env'],
             'provider': h['x-idp-provider-id'], 'operation': h['x-idp-operation-id'], 'environment': h['x-idp-environment'],
             'method': h['x-idp-method'], 'path': h['x-idp-path']}, self.headers.get('X-Provider-Account', ''))
        if denied:
            return self._deny(403, denied)
        body = {'decision_id': 'dec-' + uuid.uuid4().hex[:12], 'result': 'ALLOW', 'reason_code': 'ACTIVE_ACCOUNT_GRANT',
                'policy_version': CFG['policy']['version'], 'revocation_epoch': epoch}
        if mode == 'allow_without_credential':  # Broker could not produce a credential
            return self._send(200, body)
        return self._send(200, body, {'Authorization': 'Bearer ' + CFG['token_by_account'][account],
                                      'X-Idp-Decision-Id': body['decision_id']})

    def _decision(self, raw: bytes):
        """DecisionRequest -> DecisionResponse (contracts/gatekeeper/authz-decision.schema.json).
        The answer names a credential binding. It never contains the credential."""
        try:
            req = json.loads(raw or b'null')
        except ValueError:
            req = None
        if (not isinstance(req, dict) or any(not isinstance(req.get(k), str) for k in DECISION_REQUIRED)
                or set(req) - set(DECISION_REQUIRED) - set(DECISION_OPTIONAL)):
            return self._send(400, {'error': 'invalid_decision_request'})
        denied, account, binding, epoch = self._decide(
            {'subject': req.get('service_id', ''), 'tenant': req.get('tenant_id', ''), 'token_env': req.get('token_environment', ''),
             'provider': req['provider_id'], 'operation': req['operation_id'], 'environment': req['environment'],
             'method': req['method'], 'path': req['path']}, req['requested_account_id'])
        expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=30)
        answer = {'decision_id': 'dec-' + uuid.uuid4().hex[:12], 'result': 'DENY' if denied else 'ALLOW',
                  'reason_code': denied or 'ACTIVE_ACCOUNT_GRANT', 'policy_version': CFG['policy']['version'],
                  'revocation_epoch': epoch, 'request_id': req['request_id'], 'expires_at': expires.isoformat()}
        if not denied:
            answer['credential_handle'] = f'{binding}/{account}'
        return self._send(200, answer)

    # ---- PoC-only controls ------------------------------------------------------------
    def _admin(self, path: str, query: dict):
        arg = lambda k: (query.get(k) or [''])[0]
        with LOCK:
            if path == '/admin/log':
                return self._send(200, {'log': list(LOG), 'tls_handshakes_refused': list(REFUSED)})
            if path == '/admin/reset':
                LOG.clear(); REFUSED.clear(); STATE['mode'] = 'normal'; STATE['revoked'].clear()
                return self._send(200, {'reset': True})
            if path == '/admin/mode':
                STATE['mode'] = arg('value')
                return self._send(200, {'mode': STATE['mode']})
            if path in ('/admin/revoke', '/admin/restore'):
                (STATE['revoked'].add if path.endswith('revoke') else STATE['revoked'].discard)(arg('account'))
                STATE['revocation_epoch'] += 1
                return self._send(200, {'revoked': sorted(STATE['revoked']), 'revocation_epoch': STATE['revocation_epoch']})
        return self._send(404, {'error': 'unknown_admin_operation'})

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _handle


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):   # refused handshakes are counted, not printed
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', type=int, required=True)
    ap.add_argument('--policy', required=True)
    ap.add_argument('--state', required=True, help='JSON written by run_poc.py')
    a = ap.parse_args()
    state = json.loads(open(a.state, encoding='utf-8').read())
    CFG.update(admin_secret=state['admin_secret'], pdp_slow_seconds=state['pdp_slow_seconds'],
               token_by_account={acct: tok for tok, acct in state['provider_tokens'].items()},
               policy=json.loads(open(a.policy, encoding='utf-8').read()),
               tls=pki.server_context(Path(state['tls_dir'])))
    Server(('127.0.0.1', a.port), Handler).serve_forever()


if __name__ == '__main__':
    main()
