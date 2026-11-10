#!/usr/bin/env python3
"""MOCK Gatekeeper PDP + Credential Broker for the P1 PoC. Loopback only.

Speaks agentgateway's HTTP ExtAuthZ protocol: 2xx allows the request, anything else
denies it, and on allow the `authorization` response header carries the provider
credential that the gateway copies onto the upstream request (Mode A in G04 §4).

What is real here: the decision rule is scripts/policy_reference.py, the same reference
logic the unit tests cover. What is not: identity (the gateway's validated-token claims
are trusted because the call presents the gateway workload key; production needs
workload mTLS), storage, a real Secret Manager, a real provider token endpoint.
"""
from __future__ import annotations
import argparse, hmac, json, sys, threading, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from policy_reference import EgressRequest, TrustedPrincipal, evaluate  # noqa: E402

LOCK = threading.Lock()
LOG: list[dict] = []
STATE = {'mode': 'normal', 'revoked': set(), 'revocation_epoch': 0}
CFG: dict = {}

# Context the gateway derives from the validated token and from route constants.
TRUSTED = ('x-idp-verified-subject', 'x-idp-verified-tenant', 'x-idp-verified-env', 'x-idp-route-id',
           'x-idp-provider-id', 'x-idp-operation-id', 'x-idp-environment', 'x-idp-method', 'x-idp-path')


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'mock-gatekeeper'

    def log_message(self, *a):
        pass

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
        if length:
            self.rfile.read(length)
        parts = urlsplit(self.path)
        if parts.path == '/healthz':
            return self._send(200, {'ok': True})
        if parts.path.startswith('/admin/'):
            if self.headers.get('X-Poc-Admin') != CFG['admin_secret']:
                return self._send(404, {'error': 'not_found'})
            return self._admin(parts.path, parse_qs(parts.query))
        if parts.path == '/v1/extauthz/check':
            return self._check()
        return self._send(404, {'error': 'not_found'})

    # ---- decision -------------------------------------------------------------------
    def _deny(self, status: int, reason: str):
        return self._send(status, {'result': 'DENY', 'reason_code': reason,
                                   'policy_version': CFG['policy']['version'],
                                   'revocation_epoch': STATE['revocation_epoch']})

    def _check(self):
        with LOCK:
            LOG.append({'seq': len(LOG) + 1, 'received_at': time.time(), 'method': self.command,
                        'raw_target': self.path, 'headers': [[k, v] for k, v in self.headers.items()]})
            mode = STATE['mode']

        # 1. Is this the gateway? A business app must not be able to ask the Broker for a credential.
        presented = self.headers.get('Authorization', '')
        if not hmac.compare_digest(presented.encode(), ('Bearer ' + CFG['workload_key']).encode()):
            return self._deny(401, 'GATEWAY_WORKLOAD_UNAUTHENTICATED')

        if mode == 'error500':
            return self._send(500, {'error': 'injected_pdp_failure'})
        if mode == 'slow':
            time.sleep(float(CFG['pdp_slow_seconds']))

        # 2. Trusted context must be present exactly once; a second copy means something
        #    other than the gateway managed to add one.
        ctx = {}
        for name in TRUSTED:
            values = self.headers.get_all(name) or []
            if len(values) > 1:
                return self._deny(403, 'AMBIGUOUS_TRUSTED_CONTEXT')
            ctx[name] = values[0] if values else ''

        principal = None
        if ctx['x-idp-verified-subject'] and ctx['x-idp-verified-tenant'] and ctx['x-idp-verified-env']:
            principal = TrustedPrincipal(service_id=ctx['x-idp-verified-subject'], tenant_id=ctx['x-idp-verified-tenant'],
                                         verified=True, environment=ctx['x-idp-verified-env'])

        # 3. The account is a request, not a fact. With no request, a tenant that has exactly
        #    one granted account for this operation gets that one.
        requested = self.headers.get('X-Provider-Account', '')
        if not requested and principal is not None:
            for row in CFG['policy']['registered_operations']:
                if row['operation_id'] == ctx['x-idp-operation-id'] and row['provider_id'] == ctx['x-idp-provider-id']:
                    granted = row.get('accounts_by_tenant', {}).get(principal.tenant_id, [])
                    if len(granted) == 1:
                        requested = granted[0]

        decision = evaluate(CFG['policy'], principal, EgressRequest(
            provider_id=ctx['x-idp-provider-id'], operation_id=ctx['x-idp-operation-id'], method=ctx['x-idp-method'],
            path=ctx['x-idp-path'], account_id=requested, environment=ctx['x-idp-environment']))
        if decision.result != 'ALLOW':
            return self._deny(403, decision.reason)

        # 4. Revocation is checked on every decision and is independent of route publication.
        with LOCK:
            revoked = requested in STATE['revoked']
            epoch = STATE['revocation_epoch']
        if revoked:
            return self._deny(403, 'ACCOUNT_REVOKED')

        body = {'decision_id': 'dec-' + uuid.uuid4().hex[:12], 'result': 'ALLOW', 'reason_code': decision.reason,
                'policy_version': CFG['policy']['version'], 'revocation_epoch': epoch}
        if mode == 'allow_without_credential':  # Broker could not produce a credential
            return self._send(200, body)
        return self._send(200, body, {'Authorization': 'Bearer ' + CFG['token_by_account'][requested],
                                      'X-Idp-Decision-Id': body['decision_id']})

    # ---- PoC-only controls ------------------------------------------------------------
    def _admin(self, path: str, query: dict):
        arg = lambda k: (query.get(k) or [''])[0]
        with LOCK:
            if path == '/admin/log':
                return self._send(200, {'log': list(LOG)})
            if path == '/admin/reset':
                LOG.clear(); STATE['mode'] = 'normal'; STATE['revoked'].clear()
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', type=int, required=True)
    ap.add_argument('--policy', required=True)
    ap.add_argument('--state', required=True, help='JSON written by run_poc.py')
    a = ap.parse_args()
    state = json.loads(open(a.state, encoding='utf-8').read())
    CFG.update(admin_secret=state['admin_secret'], workload_key=state['workload_key'],
               pdp_slow_seconds=state['pdp_slow_seconds'],
               token_by_account={acct: tok for tok, acct in state['provider_tokens'].items()},
               policy=json.loads(open(a.policy, encoding='utf-8').read()))
    ThreadingHTTPServer(('127.0.0.1', a.port), Handler).serve_forever()


if __name__ == '__main__':
    main()
