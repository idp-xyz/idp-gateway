#!/usr/bin/env python3
"""TLS stand-in for the ingress pool.

Speaks HTTPS, requires a client certificate, and appends one JSON object per
completed HTTP request. A handshake that fails does not append anything: the
application never saw a request. No request line is written to stderr.
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BODY = b'stand-in-ok\n'
LOCK = threading.Lock()
RECORDS = ''
LOCATION = 'https://stand-in.ingress.example/moved'
COOKIE = 'standin=1; Path=/'


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt, *args):
        return

    def _record(self):
        cert = self.connection.getpeercert() or {}
        subject = [f'{key}={value}' for rdn in cert.get('subject', ()) for key, value in rdn]
        sans = [{'kind': kind, 'value': value} for kind, value in cert.get('subjectAltName', ())]
        headers = {key.lower(): value for key, value in self.headers.items()}
        row = {
            'method': self.command,
            'path': self.path,
            'headers': headers,
            'client_subject': subject,
            'client_sans': sans,
            'sent_headers': ['location', 'set-cookie'],
        }
        line = json.dumps(row, ensure_ascii=False, separators=(',', ':')) + '\n'
        with LOCK:
            with open(RECORDS, 'a', encoding='utf-8') as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())

    def _serve(self):
        length = int(self.headers.get('Content-Length', '0') or '0')
        if length:
            self.rfile.read(min(length, 1 << 20))
        self._record()
        payload = b'' if self.command == 'HEAD' else BODY
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(BODY)))
        self.send_header('Location', LOCATION)
        self.send_header('Set-Cookie', COOKIE)
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def do_GET(self):
        self._serve()

    def do_HEAD(self):
        self._serve()

    def do_POST(self):
        self._serve()

    def do_PUT(self):
        self._serve()

    def do_PATCH(self):
        self._serve()

    def do_DELETE(self):
        self._serve()

    def do_OPTIONS(self):
        self._serve()


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        # A probe that is not TLS, or a client that rejects this certificate,
        # ends in the handshake. That is not an application request.
        return


def main() -> None:
    global RECORDS, LOCATION
    parser = argparse.ArgumentParser()
    parser.add_argument('--cert', required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('--client-ca', required=True)
    parser.add_argument('--bind', default='0.0.0.0')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--records', required=True)
    parser.add_argument('--location', default=LOCATION)
    args = parser.parse_args()
    RECORDS = args.records
    LOCATION = args.location
    with open(RECORDS, 'a', encoding='utf-8'):
        pass
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)
    context.load_verify_locations(args.client_ca)
    context.verify_mode = ssl.CERT_REQUIRED
    server = Server((args.bind, args.port), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
