#!/usr/bin/env python3
"""A stand-in for the WanbExpress API, only as far as http://apidoc.wanbexpress.com/ describes it. Loopback, synthetic data.

From the documentation (How-To-Start, whoami, parcels/Create-Parcel, Get-Parcel, Delete-Parcel):
  - `Authorization: Hc-OweDeveloper AccountNo;Token;Nonce`, exactly one header. Missing or not of that form: 403.
    AccountNo and Token not known: 401. The nonce is letters, digits, '-' or '_', not empty.
  - `Accept` has to be application/json.
  - GET /api/whoami -> {"Data": <account>, "Succeeded": true, "Error": null}.
  - POST /api/parcels: ReferenceId is unique across all accounts; a repeat is HTTP 200, Succeeded false,
    Error.Code 0x100005. Success carries Data.ProcessCode, ReferenceId, Status ("Confirmed" when AutoConfirm is true, else "Original").
  - GET /api/parcels/{processCode}, DELETE /api/parcels/{processCode} (only before the parcel is confirmed).
  - A business error is HTTP 200 with Succeeded false and Error.Code / Error.Message.

Measured at the real sandbox on 2026-11-19 (the documentation does not say; the stand-in follows the measurements):
  - the same ReferenceId with an identical body: HTTP 200, Succeeded true, the same ProcessCode (nothing new is made);
  - the same ReferenceId with a different body: HTTP 200, Succeeded false, Error.Code 0x100005, a Message that names the ReferenceId and the
    existing process code, SystemError null, no Data;
  - after a delete the ReferenceId can be used again; deleting what is already gone: HTTP 200, Succeeded true;
  - a process code that does not exist or was deleted: HTTP 404, empty body, no Content-Type.
Stricter than the sandbox, following the documentation: a nonce seen before is refused with 403 (the sandbox accepts it);
an Accept that is not application/json is refused with 406 (the sandbox answers 200 JSON). The 406 is our own choice of status.
Other assumptions of ours:
  - a DELETE of a confirmed parcel is HTTP 200, Succeeded false, Error.Code 0x100002;
  - the body of a create is checked for ReferenceId (a string), ShippingAddress (an object) and a non-empty ItemDetails only.
Every request is recorded as the mock received it (method, raw target, every header in order, body length and hash,
ReferenceId), for the suite to read at /admin/hits with the admin secret. The recorded headers hold the credential;
the mock writes nothing to stderr, and the suite keeps the records out of its own output.
"""
from __future__ import annotations
import argparse, hashlib, json, re, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

DEVELOPER = re.compile(r'Hc-OweDeveloper ([^; ]+);([^; ]+);([A-Za-z0-9_-]+)')
HITS: list[dict] = []
NONCES: set[str] = set()
PARCELS: dict[str, dict] = {}      # process code -> {account, reference, status}
REFERENCES: dict[str, str] = {}    # reference id -> process code: unique across accounts
LOCK = threading.Lock()
CFG: dict = {}
SERIAL = [38000]


def failure(code: str, message: str) -> dict:
    return {'Succeeded': False, 'Error': {'Code': code, 'Message': message}, 'SystemError': None}


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'mock-wanbexpress'

    def log_message(self, *a):
        pass

    def _send(self, status: int, payload: dict | None):
        body = b'' if payload is None else json.dumps(payload).encode()
        self.send_response(status)
        if payload is not None:
            self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('X-Mock-Provider', 'wanbexpress')
        # What a provider must not be able to do to the caller (tests the gateway's response header removal).
        self.send_header('Set-Cookie', 'carrier_session=mock; Path=/')
        self.end_headers()
        self.wfile.write(body)

    def _handle(self):
        length = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(length) if length else b''
        parts = urlsplit(self.path)
        if parts.path.startswith('/admin/') and self.headers.get('X-Poc-Admin') == CFG['admin_secret']:
            if parts.path == '/admin/hits':
                with LOCK:
                    return self._send(200, {'hits': list(HITS)})
            if parts.path == '/admin/reset':
                with LOCK:
                    HITS.clear()
                return self._send(200, {'ok': True})
            return self._send(404, {})
        reference = None
        try:
            parsed = json.loads(body) if body else None
            reference = parsed.get('ReferenceId') if isinstance(parsed, dict) else None
        except ValueError:
            parsed = None
        with LOCK:
            HITS.append({'seq': len(HITS) + 1, 'method': self.command, 'raw_target': self.path,
                         'headers': [[k, v] for k, v in self.headers.items()], 'body_len': len(body),
                         'body_sha256': hashlib.sha256(body).hexdigest(),
                         'reference_id': reference if isinstance(reference, str) else None})

        given = self.headers.get_all('Authorization') or []
        match = DEVELOPER.fullmatch(given[0]) if len(given) == 1 else None
        if match is None:
            return self._send(403, failure('0x000403', 'Forbidden'))
        account = CFG['accounts'].get(f'{match.group(1)};{match.group(2)}')
        if account is None:
            return self._send(401, failure('0x000401', 'Unauthorized'))
        with LOCK:
            repeated = match.group(3) in NONCES
            NONCES.add(match.group(3))
        if repeated:
            return self._send(403, failure('0x000403', 'Nonce repeated'))
        if self.headers.get('Accept') != 'application/json':
            return self._send(406, failure('0x000406', 'Not Acceptable'))

        path = parts.path
        if self.command == 'GET' and path == '/api/whoami':
            return self._send(200, {'Data': account, 'Succeeded': True, 'Error': None})
        if self.command == 'POST' and path == '/api/parcels':
            return self._create(account, parsed)
        found = re.fullmatch(r'/api/parcels/([A-Za-z0-9][A-Za-z0-9._-]*)', path)
        if found and self.command in ('GET', 'DELETE'):
            return self._one(account, found.group(1))
        return self._send(404, failure('0x000404', 'Not Found'))

    def _create(self, account: str, parsed):
        if (not isinstance(parsed, dict) or not isinstance(parsed.get('ReferenceId'), str) or not parsed['ReferenceId']
                or not isinstance(parsed.get('ShippingAddress'), dict) or not parsed.get('ItemDetails')):
            return self._send(200, failure('0x100000', 'Invalid parcel'))
        reference = parsed['ReferenceId']
        with LOCK:
            if reference in REFERENCES:
                known = PARCELS[REFERENCES[reference]]
                if known['body'] == parsed:    # measured at the sandbox: the same body is answered with the parcel that exists
                    return self._send(200, {'Data': {'ProcessCode': REFERENCES[reference], 'ReferenceId': reference, 'Status': known['status']},
                                            'Succeeded': True, 'Error': None})
                answer = failure('0x100005', f'ReferenceId {reference} already exists, process code {REFERENCES[reference]}')
                return self._send(200, answer)
            SERIAL[0] += 1
            code = f'SBXPAA{SERIAL[0]:010d}YQ'
            status = 'Confirmed' if parsed.get('AutoConfirm') is True else 'Original'
            REFERENCES[reference] = code
            PARCELS[code] = {'account': account, 'reference': reference, 'status': status, 'body': parsed}
        return self._send(200, {'Data': {'ProcessCode': code, 'IndexNumber': f'9001{SERIAL[0]:010d}', 'ReferenceId': reference,
                                         'TrackingNumber': '', 'IsVirtualTrackingNumber': False, 'SortCode': '',
                                         'IsRemoteArea': False, 'Status': status}, 'Succeeded': True, 'Error': None})

    def _one(self, account: str, code: str):
        with LOCK:
            parcel = PARCELS.get(code)
            if parcel is None or parcel['account'] != account:
                if self.command == 'DELETE':      # measured at the sandbox: deleting what is gone succeeds
                    return self._send(200, {'Succeeded': True, 'Error': None})
                return self._send(404, None)      # measured: HTTP 404, empty body, no Content-Type
            if self.command == 'GET':
                return self._send(200, {'Data': {'AccountNo': account, 'ReferenceId': parcel['reference'], 'ProcessCode': code,
                                                 'Status': parcel['status']}, 'Succeeded': True, 'Error': None})
            if parcel['status'] != 'Original':
                return self._send(200, failure('0x100002', 'Parcel already confirmed'))
            del PARCELS[code]
            del REFERENCES[parcel['reference']]
        return self._send(200, {'Succeeded': True, 'Error': None})

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _handle


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--state', required=True, help='JSON: {"admin_secret": ..., "accounts": {"AccountNo;Token": "AccountNo"}}')
    args = parser.parse_args()
    CFG.update(json.load(open(args.state)))
    ThreadingHTTPServer(('127.0.0.1', args.port), Handler).serve_forever()


if __name__ == '__main__':
    main()
