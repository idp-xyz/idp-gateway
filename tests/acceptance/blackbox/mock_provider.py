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

POST /oauth/token is a token endpoint (docs/adr/ADR-0011.md, step two): OAuth2 client credentials with
client_secret_basic. Each client gets tokens of its own, and the Bearer operations know which account an
issued token belongs to (the answer says so) and refuse one past its lifetime. A test controls what it
answers (lifetime, delay, a fault) through /admin/oauth/config, and reads how often each client was asked,
with which of its secrets, through /admin/oauth. A request to the token endpoint is not a provider-side
observation of a business request: it is kept out of /admin/hits.
"""
from __future__ import annotations
import argparse, hashlib, json, re, socket, threading, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs, unquote_plus
import base64

HITS: list[dict] = []
NONCES: set[str] = set()   # every nonce accepted since the process started; /admin/reset leaves it alone
LOCK = threading.Lock()
CFG: dict = {}
# Token endpoint. OAUTH is what a test controls and reads; ISSUED is every token ever issued (token -> who and until when),
# and survives /admin/reset and /admin/oauth/reset: a token that gateway-authz still holds has to stay known.
OAUTH: dict = {}
ISSUED: dict = {}
OAUTH_FAULTS = ('ok', 'status500', 'status401', 'redirect', 'bad_token_type', 'no_token_type', 'no_expires', 'zero_expires',
                'string_expires', 'empty_token', 'not_json', 'json_array', 'drop')
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
            return self._admin(parts.path, parts.query, body)
        if parts.path == '/oauth/token' and CFG['oauth']:
            return self._token(body)

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
            # A token from the token endpoint: the account it was issued for, for as long as it lives.
            with LOCK:
                issued = ISSUED.get(token)
            if issued is not None and time.time() < issued['expires']:
                account = issued['account']
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
            forged = {'X-Idp-Decision-Id': 'forged-by-provider'} if fault == 'forge-decision-header' else None
            return self._send(200, {'tracking_id': tid, 'status': 'IN_TRANSIT', 'account': account}, forged)
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
            answer = {'label_id': 'lbl-' + uuid.uuid4().hex[:10], 'account': account,
                      'body_sha256': hashlib.sha256(body).hexdigest()}
            # Like the carrier, a create answer that carries the reference number it was given
            # and a process number of the carrier's own. Only when the request has a string
            # ReferenceId: a body without one is answered as it always was.
            try:
                reference = json.loads(body).get('ReferenceId')
            except (ValueError, AttributeError):
                reference = None
            if isinstance(reference, str):
                process_code = 'PC-' + uuid.uuid4().hex[:12]
                if fault == 'bad-process-code':
                    # A process number that is not of the format the gateway's log accepts: quotes,
                    # a newline and a length no real number has.
                    process_code = 'PC-"x"\nforged-line ' + 'A' * 5000
                answer.update({'Succeeded': True, 'Data': {'ProcessCode': process_code, 'ReferenceId': reference}})
            return self._send(201, answer)
        if self.command == 'GET' and parts.path == '/v1/rates':
            answer = {'rate': '12.34', 'currency': 'USD', 'account': account}
            if fault == 'forge-decision':
                # A provider that tries to write a decision id into the gateway's log through its body.
                answer.update({'decision_id': 'forged-by-provider', 'authz_decision_id': 'forged-by-provider'})
            # ... or through a response header, the one the PDP's own answers carry.
            forged = {'X-Idp-Decision-Id': 'forged-by-provider'} if fault == 'forge-decision-header' else None
            return self._send(200, answer, forged)
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

    def _token(self, body: bytes):
        """POST /oauth/token. Basic client credentials (RFC 6749 2.3.1: both parts form-urlencoded), grant_type=client_credentials."""
        auth = self.headers.get('Authorization', '')
        client = secret = None
        if auth.startswith('Basic '):
            try:
                user, _, password = base64.b64decode(auth[6:], validate=True).decode().partition(':')
                client, secret = unquote_plus(user), unquote_plus(password)
            except ValueError:
                pass
        form = parse_qs(body.decode(errors='replace'), keep_blank_values=True)
        with LOCK:
            known = OAUTH.get(client)
            generation = known['secrets'].get(secret) if known else None
            if (self.command != 'POST' or generation is None or generation not in known['valid']
                    or self.headers.get('Content-Type') != 'application/x-www-form-urlencoded'
                    or form.get('grant_type') != ['client_credentials']):
                if known is not None:
                    known['refused'] += 1
                return self._send(401, {'error': 'invalid_client'})
            mode, life, delay = known['mode'], known['life'], known['delay']
            known['fetches'].append({'secret_generation': generation, 'mode': mode, 'at': time.time(), 'scope': (form.get('scope') or [None])[0],
                                     'audience': (form.get('audience') or [None])[0], 'grant_type': form['grant_type'][0]})
        if delay:
            time.sleep(delay)
        if mode == 'drop':
            self.close_connection = True
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            return
        if mode == 'status500':
            return self._send(500, {'error': 'server_error', 'client_secret': 'a body that must not be echoed'})
        if mode == 'status401':
            return self._send(401, {'error': 'invalid_client'})
        if mode == 'redirect':
            return self._send(302, {'moved': True}, {'Location': f"http://127.0.0.1:{CFG['redirect_port']}/oauth/stolen"})
        if mode == 'not_json':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            payload = b'<html>token endpoint says hello</html>'
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if mode == 'json_array':
            return self._send(200, ['not', 'an', 'object'])
        token = f"oauth-{known['account']}-{uuid.uuid4().hex}"
        answer = {'access_token': token, 'token_type': 'Bearer', 'expires_in': life}
        if mode == 'bad_token_type':
            answer['token_type'] = 'mac'
        elif mode == 'no_token_type':
            del answer['token_type']
        elif mode == 'no_expires':
            del answer['expires_in']
        elif mode == 'zero_expires':
            answer['expires_in'] = 0
        elif mode == 'string_expires':
            answer['expires_in'] = str(life)
        elif mode == 'empty_token':
            answer['access_token'] = ''
        with LOCK:
            ISSUED[token] = {'account': known['account'], 'client_id': client, 'expires': time.time() + life}
            known['issued'].append(token)
        return self._send(200, answer)

    def _oauth_report(self):
        with LOCK:
            clients = {cid: {'account': c['account'], 'fetches': list(c['fetches']), 'refused': c['refused'], 'issued': list(c['issued']),
                             'mode': c['mode'], 'life': c['life'], 'delay': c['delay'], 'valid': sorted(c['valid'])}
                       for cid, c in OAUTH.items()}
            return {'clients': clients, 'issued_ever': list(ISSUED)}

    def _admin(self, path: str, query: str = '', body: bytes = b''):
        if path == '/admin/hits':
            with LOCK:
                return self._send(200, {'hits': list(HITS)})
        if path == '/admin/reset':
            with LOCK:
                HITS.clear()
            return self._send(200, {'reset': True})
        if path == '/admin/oauth/reset':
            # Counters and controls back to their start; the tokens already issued stay known.
            with LOCK:
                for c in OAUTH.values():
                    c.update(mode='ok', life=3600, delay=0.0, refused=0, fetches=[], issued=[], valid={'g1'})
            return self._send(200, {'reset': True})
        if path == '/admin/oauth/config':
            # {client_id: {mode, life, delay, valid}}; a key left out stays as it was.
            try:
                change = json.loads(body or b'{}')
                with LOCK:
                    for cid, c in change.items():
                        target = OAUTH[cid]
                        if c.get('mode', 'ok') not in OAUTH_FAULTS:
                            raise ValueError('mode')
                        target.update({k: (set(v) if k == 'valid' else v) for k, v in c.items() if k in ('mode', 'life', 'delay', 'valid')})
            except (ValueError, KeyError, AttributeError):
                return self._send(400, {'error': 'bad_oauth_config'})
            return self._send(200, self._oauth_report())
        if path == '/admin/oauth':
            return self._send(200, self._oauth_report())
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
               developer_tokens=state.get('provider_developer_tokens', {}) if a.name == 'mockcarrier' else {},
               oauth=a.name == 'mockcarrier' and bool(state.get('provider_oauth')))
    # client_id -> its account and the secrets it may present, each named by a generation (g1, g2): what a report says a fetch used.
    for cid, c in (state.get('provider_oauth') or {}).items():
        OAUTH[cid] = {'account': c['account'], 'secrets': c['secrets'], 'valid': {'g1'}, 'mode': 'ok', 'life': 3600, 'delay': 0.0,
                      'refused': 0, 'fetches': [], 'issued': []}
    ThreadingHTTPServer(('127.0.0.1', a.port), Handler).serve_forever()


if __name__ == '__main__':
    main()
