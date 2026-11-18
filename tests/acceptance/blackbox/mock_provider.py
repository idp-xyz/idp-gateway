#!/usr/bin/env python3
"""MOCK provider ("mockcarrier") for the P1 PoC. Loopback only, synthetic data only.

It authenticates callers by provider bearer token and records everything it receives,
so the runner can check out of band what actually left the gateway. Responses never
echo the credential back: what the caller of the gateway sees and what the provider
saw are two separate observations.

/v1/parcels/ is authenticated the other way (docs/adr/ADR-0011.md): a fixed developer
token with a nonce, `Authorization: Hc-OweDeveloper AccountNo;Token;Nonce`. A header that
is missing or not of that form is answered 403, an unknown account or token 401. A nonce
is accepted once: the carrier this scheme is taken from says it will come to refuse a
repeated one, and a stand-in that already does shows a resent header for what it is.
"""
from __future__ import annotations
import argparse, hashlib, json, re, socket, threading, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

HITS: list[dict] = []
NONCES: set[str] = set()   # every nonce accepted since the process started; /admin/reset leaves it alone
LOCK = threading.Lock()
CFG: dict = {}
# Nonce: letters, digits, hyphen and underscore, not empty; no semicolon after it.
DEVELOPER = re.compile(r'Hc-OweDeveloper ([^; ]+);([^; ]+);([A-Za-z0-9_-]+)')


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'mock-provider'

    def log_message(self, *a):  # request bodies and tokens stay out of stderr
        pass

    def _send(self, status: int, payload: dict | None = None, headers: dict | None = None):
        body = json.dumps(payload or {}).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('X-Mock-Provider', CFG['name'])
        self.send_header('X-Provider-Request-Id', 'prq-' + uuid.uuid4().hex[:12])
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def _handle(self):
        length = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(length) if length else b''
        parts = urlsplit(self.path)
        is_admin = parts.path.startswith('/admin/') and self.headers.get('X-Poc-Admin') == CFG['admin_secret']
        if is_admin:
            return self._admin(parts.path)

        # Everything that is not an authenticated admin call is a provider-side observation,
        # including requests for /admin/* that arrive without the admin secret.
        with LOCK:
            HITS.append({
                'seq': len(HITS) + 1,
                'received_at': time.time(),
                'method': self.command,
                'raw_target': self.path,
                'headers': [[k, v] for k, v in self.headers.items()],
                'body_sha256': hashlib.sha256(body).hexdigest(),
                'body_len': len(body),
            })

        if parts.path.startswith('/v1/parcels/'):
            return self._parcels(parts.path)

        auth = self.headers.get('Authorization', '')
        token = auth[7:] if auth.startswith('Bearer ') else ''
        account = CFG['tokens'].get(token)
        if account is None:
            return self._send(401, {'error': 'provider_unauthorized'})

        query = parse_qs(parts.query)
        fault = (query.get('fault') or [''])[0]
        if self.command == 'GET' and parts.path.startswith('/v1/tracking/'):
            tid = parts.path[len('/v1/tracking/'):]
            if tid == 'redirect-me':
                return self._send(302, {'moved': True}, {'Location': f"http://127.0.0.1:{CFG['redirect_port']}/v1/stolen",
                                                         'Set-Cookie': 'provider_session=mock; Path=/'})
            if tid == 'rate-limited':
                return self._send(429, {'error': 'provider_rate_limited'}, {'Retry-After': '7'})
            if tid == 'not-found':
                return self._send(404, {'error': 'tracking_not_found'})
            return self._send(200, {'tracking_id': tid, 'status': 'IN_TRANSIT', 'account': account})
        if self.command == 'POST' and parts.path == '/v1/labels':
            if fault == 'slow':
                time.sleep(float(CFG['slow_seconds']))
            if fault == 'reset':
                # The write was received (and recorded above); the caller never learns the outcome.
                self.close_connection = True
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                return
            return self._send(201, {'label_id': 'lbl-' + uuid.uuid4().hex[:10], 'account': account,
                                    'body_sha256': hashlib.sha256(body).hexdigest()})
        if self.command == 'GET' and parts.path == '/v1/rates':
            return self._send(200, {'rate': '12.34', 'currency': 'USD', 'account': account})
        for resource in ('manifests', 'pickups'):
            if self.command == 'GET' and parts.path.startswith(f'/v1/{resource}/'):
                return self._send(200, {'resource': resource, 'id': parts.path[len(f'/v1/{resource}/'):], 'account': account})
        return self._send(404, {'error': 'unknown_provider_operation'})

    def _parcels(self, path: str):
        """The developer-token operations. Exactly one Authorization header, of the documented form."""
        given = self.headers.get_all('Authorization') or []
        match = DEVELOPER.fullmatch(given[0]) if len(given) == 1 else None
        if match is None:
            return self._send(403, {'error': 'provider_forbidden'})
        account = CFG['developer_tokens'].get(f'{match.group(1)};{match.group(2)}')
        if account is None:
            return self._send(401, {'error': 'provider_unauthorized'})
        with LOCK:
            repeated = match.group(3) in NONCES
            NONCES.add(match.group(3))
        if repeated:
            return self._send(403, {'error': 'provider_nonce_repeated'})
        if self.command == 'GET':
            return self._send(200, {'resource': 'parcels', 'id': path[len('/v1/parcels/'):], 'account': account})
        return self._send(404, {'error': 'unknown_provider_operation'})

    def _admin(self, path: str):
        if path == '/admin/hits':
            with LOCK:
                return self._send(200, {'hits': list(HITS)})
        if path == '/admin/reset':
            with LOCK:
                HITS.clear()
            return self._send(200, {'reset': True})
        return self._send(404, {'error': 'unknown_admin_operation'})

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _handle


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', type=int, required=True)
    ap.add_argument('--name', required=True)
    ap.add_argument('--state', required=True, help='JSON written by run.py')
    a = ap.parse_args()
    state = json.loads(open(a.state, encoding='utf-8').read())
    CFG.update(name=a.name, admin_secret=state['admin_secret'], redirect_port=state['ports']['forbidden'],
               slow_seconds=state['provider_slow_seconds'],
               tokens=state['provider_tokens'] if a.name == 'mockcarrier' else {},
               # The Gatekeeper integration suite starts this mock too, with a state file that has no such entry.
               developer_tokens=state.get('provider_developer_tokens', {}) if a.name == 'mockcarrier' else {})
    ThreadingHTTPServer(('127.0.0.1', a.port), Handler).serve_forever()


if __name__ == '__main__':
    main()
