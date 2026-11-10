#!/usr/bin/env python3
"""MOCK local credential broker for the P1 PoC (Mode B in G04 §4). Loopback only.

Sits next to the gateway and is the ExtAuthZ target of a Mode B route. For each request it
  1. asks Gatekeeper for a decision over mutual TLS, as the broker workload
     (/v1/egress/authorizations/decision: a decision and a credential handle, no credential);
  2. on ALLOW, redeems the handle from its own local store and answers the gateway with the
     provider credential in the `authorization` header, exactly as Gatekeeper does in Mode A.
So the provider credential never crosses the network between Gatekeeper and the gateway;
it exists in this process and on the loopback hop to the gateway.

Not real: the local store is a JSON file written by the runner. The gateway proves itself
with a key file, standing in for whatever restricts a sidecar to its own gateway in a real
deployment (a Unix socket, a pod network namespace). Any local process that can read that
key can ask for credentials.
"""
from __future__ import annotations
import argparse, hmac, json, threading, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pki

LOCK = threading.Lock()
LOG: list[dict] = []
CFG: dict = {}
TRUSTED = ('x-idp-verified-subject', 'x-idp-verified-tenant', 'x-idp-verified-env', 'x-idp-route-id',
           'x-idp-provider-id', 'x-idp-operation-id', 'x-idp-environment', 'x-idp-method', 'x-idp-path')
GATEKEEPER_TIMEOUT = 0.7   # shorter than the gateway's 1s authorization budget


def ask_gatekeeper(request: dict) -> dict:
    """One decision request. The result records what came back, for the runner to inspect."""
    conn = pki.GatekeeperConnection(CFG['gatekeeper_port'], CFG['tls'], GATEKEEPER_TIMEOUT)
    try:
        conn.request('POST', '/v1/egress/authorizations/decision', json.dumps(request).encode(),
                     {'Content-Type': 'application/json'})
        resp = conn.getresponse()
        raw = resp.read()
        return {'status': resp.status, 'headers': resp.getheaders(), 'body': raw.decode(errors='replace')}
    except Exception as e:
        return {'status': None, 'headers': [], 'body': '', 'error': type(e).__name__}
    finally:
        conn.close()


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'mock-broker'

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

    def _deny(self, status: int, reason: str, result: str = 'DENY', answer: dict | None = None):
        answer = answer or {}
        return self._send(status, {'result': result, 'reason_code': reason,
                                   'policy_version': answer.get('policy_version', 'unknown'),
                                   'revocation_epoch': answer.get('revocation_epoch', 0)})

    def _handle(self):
        length = int(self.headers.get('Content-Length') or 0)
        if length:
            self.rfile.read(length)
        path = urlsplit(self.path).path
        if path.startswith('/admin/'):
            if self.headers.get('X-Poc-Admin') != CFG['admin_secret']:
                return self._send(404, {'error': 'not_found'})
            with LOCK:
                if path == '/admin/log':
                    return self._send(200, {'log': list(LOG)})
                if path == '/admin/reset':
                    LOG.clear()
                    return self._send(200, {'reset': True})
            return self._send(404, {'error': 'unknown_admin_operation'})
        if path != '/v1/extauthz/check':
            return self._send(404, {'error': 'not_found'})

        entry = {'received_at': time.time(), 'method': self.command, 'gatekeeper': None}
        with LOCK:
            LOG.append(entry)
            entry['seq'] = len(LOG)

        # 1. Only the gateway this broker sits next to may ask.
        presented = self.headers.get('Authorization', '')
        if not hmac.compare_digest(presented.encode(), ('Bearer ' + CFG['local_key']).encode()):
            return self._deny(401, 'LOCAL_GATEWAY_UNAUTHENTICATED')

        ctx = {}
        for name in TRUSTED:
            values = self.headers.get_all(name) or []
            if len(values) > 1:
                return self._deny(403, 'AMBIGUOUS_TRUSTED_CONTEXT')
            ctx[name] = values[0] if values else ''

        # 2. The decision is Gatekeeper's. Nothing is decided, cached or defaulted here.
        request = {'request_id': 'req-' + uuid.uuid4().hex[:12], 'route_id': ctx['x-idp-route-id'],
                   'operation_id': ctx['x-idp-operation-id'], 'provider_id': ctx['x-idp-provider-id'],
                   'requested_account_id': self.headers.get('X-Provider-Account', ''),
                   'environment': ctx['x-idp-environment'], 'method': ctx['x-idp-method'], 'path': ctx['x-idp-path'],
                   'config_digest': CFG['config_digest'], 'service_id': ctx['x-idp-verified-subject'],
                   'tenant_id': ctx['x-idp-verified-tenant'], 'token_environment': ctx['x-idp-verified-env']}
        got = ask_gatekeeper(request)
        entry['gatekeeper'] = got
        try:
            answer = json.loads(got['body']) if got['status'] == 200 else None
        except ValueError:
            answer = None
        if not isinstance(answer, dict) or answer.get('request_id') != request['request_id']:
            return self._deny(503, 'GATEKEEPER_UNAVAILABLE', 'INDETERMINATE')
        if answer.get('result') != 'ALLOW':
            return self._deny(403, str(answer.get('reason_code') or 'DENIED'), answer=answer)

        # 3. Redeem the handle locally. A handle this store does not hold is a denial.
        token = CFG['store'].get(answer.get('credential_handle'))
        if not token:
            return self._deny(503, 'CREDENTIAL_NOT_HELD_LOCALLY', 'INDETERMINATE', answer)
        return self._send(200, {'decision_id': answer['decision_id'], 'result': 'ALLOW', 'reason_code': answer['reason_code'],
                                'policy_version': answer['policy_version'], 'revocation_epoch': answer['revocation_epoch']},
                          {'Authorization': 'Bearer ' + token, 'X-Idp-Decision-Id': answer['decision_id']})

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _handle


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', type=int, required=True)
    ap.add_argument('--state', required=True, help='JSON written by run_poc.py')
    ap.add_argument('--store', required=True, help='JSON: credential handle -> provider token')
    ap.add_argument('--local-key', required=True, help='file holding the key the gateway presents')
    a = ap.parse_args()
    state = json.loads(open(a.state, encoding='utf-8').read())
    CFG.update(admin_secret=state['admin_secret'], gatekeeper_port=state['ports']['gatekeeper'],
               config_digest=state['config_digest'], store=json.loads(open(a.store, encoding='utf-8').read()),
               local_key=open(a.local_key, encoding='utf-8').read().strip(),
               tls=pki.client_context(Path(state['tls_dir']), 'broker'))
    ThreadingHTTPServer(('127.0.0.1', a.port), Handler).serve_forever()


if __name__ == '__main__':
    main()
