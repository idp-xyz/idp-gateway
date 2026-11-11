#!/usr/bin/env python3
"""Runs inside the cluster, in the tools Pod of the Kubernetes suite (run.py puts this file there).

    probe.py inspect <pod ip> <route> ...   what another workload can and cannot reach on a gateway Pod
    probe.py load <host> <port> <route>     requests through the Service until /tmp/stop appears
    probe.py echo                           the backend the gateway routes forward to

Everything is printed as one JSON document. Standard library only: the image is a plain Python image.
"""
from __future__ import annotations
import collections, http.client, json, os, socket, ssl, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CERTS = '/certs'
READBACK_NAME = os.environ.get('READBACK_NAME', '')
PORTS = json.loads(os.environ.get('GATEWAY_PORTS', '{}'))   # name -> port, as run.py deploys them


class ReadBack(http.client.HTTPSConnection):
    """TLS to <ip>:<port>, verifying the certificate for READBACK_NAME and presenting <cert> (None: nothing)."""

    def __init__(self, ip: str, port: int, cert: str | None):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(f'{CERTS}/ca.crt')
        if cert:
            context.load_cert_chain(f'{CERTS}/{cert}.crt', f'{CERTS}/{cert}.key')
        super().__init__(READBACK_NAME, port, timeout=8, context=context)
        self._ip, self._context = ip, context

    def connect(self):
        raw = socket.create_connection((self._ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=READBACK_NAME)
        except BaseException:
            raw.close()
            raise


def read_back(ip: str, cert: str | None, method: str, path: str) -> dict:
    try:
        conn = ReadBack(ip, PORTS['readback'], cert)
        conn.request(method, path, body=None if method == 'GET' else b'', headers={'Host': READBACK_NAME})
        response = conn.getresponse()
        body = response.read()
        conn.close()
    except Exception as e:
        return {'status': None, 'error': f'{type(e).__name__}: {str(e)[:80]}'}
    try:
        return {'status': response.status, 'json': json.loads(body)}
    except ValueError:
        return {'status': response.status, 'text': body[:120].decode('latin1')}


def connect_errno(ip: str, port: int) -> int:
    with socket.socket() as s:
        s.settimeout(3)
        return s.connect_ex((ip, port))


def get(host: str, port: int, virtual_host: str, path: str, timeout: float = 8) -> dict:
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request('GET', path, headers={'Host': virtual_host, 'Connection': 'close'})
        response = conn.getresponse()
        body = response.read()
        conn.close()
        return {'status': response.status, 'body': body[:80].decode('latin1')}
    except Exception as e:
        return {'status': None, 'error': f'{type(e).__name__}: {str(e)[:80]}'}


def two_hosts(ip: str, route: str) -> dict:
    """A request with two Host header lines, written to the socket by hand: clients do not send this.
    -> the status line and the Server header of whatever answered."""
    request = f'GET /quick HTTP/1.1\r\nHost: {route}.test\r\nHost: other.test\r\nConnection: close\r\n\r\n'
    try:
        with socket.create_connection((ip, PORTS['front']), 5) as s:
            s.sendall(request.encode())
            data = b''
            while len(data) < 65536:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
    except OSError as e:
        return {'status': None, 'error': f'{type(e).__name__}: {str(e)[:80]}'}
    head = data.split(b'\r\n\r\n', 1)[0].decode('latin1').split('\r\n')
    fields = dict(line.split(': ', 1) for line in head[1:] if ': ' in line)
    return {'status': int(head[0].split()[1]) if len(head[0].split()) > 1 and head[0].split()[1].isdigit() else None,
            'server': fields.get('Server')}


def inspect(ip: str, routes: list[str]) -> dict:
    return {
        'two_hosts': two_hosts(ip, routes[0]),
        'dump': read_back(ip, 'publisher', 'GET', '/config_dump'),
        'runtime': read_back(ip, 'publisher', 'GET', '/api/runtime'),
        # What else the admin address offers; asked with the publisher's certificate.
        'admin_only': {f'{method} {path}': read_back(ip, 'publisher', method, path)['status']
                       for method, path in (('POST', '/quitquitquit'), ('POST', '/logging?level=debug'), ('GET', '/debug/tasks'), ('GET', '/ui'))},
        'other_callers': {who: read_back(ip, cert, 'GET', '/config_dump')['status']
                          for who, cert in (('another workload of the same CA', 'business-app'), ('no certificate', None),
                                            ('the publisher\'s name on a certificate of another CA', 'rogue-publisher'))},
        'connect': {name: connect_errno(ip, port) for name, port in PORTS.items()},
        'routes': {name: get(ip, PORTS['front'], f'{name}.test', '/quick')['status'] for name in routes},
    }


def load(host: str, port: int, route: str, rate: float = 20.0, slow_workers: int = 2, slow_seconds: float = 2.0, longest: float = 600.0) -> dict:
    """Quick requests at a fixed rate, each on a connection of its own, and a few slow ones one after another,
    until /tmp/stop exists. Every request that does not come back 200 is listed."""
    try:
        os.unlink('/tmp/stop')
    except FileNotFoundError:
        pass
    started = time.monotonic()
    counts = {'quick': collections.Counter(), 'slow': collections.Counter()}
    failures, guard, threads = [], threading.Lock(), []
    done = lambda: os.path.exists('/tmp/stop') or time.monotonic() - started > longest

    def one(kind: str, path: str, timeout: float):
        at = round(time.monotonic() - started, 1)
        got = get(host, port, f'{route}.test', path, timeout)
        outcome = str(got['status']) if got['status'] is not None else got['error'].split(':')[0]
        with guard:
            counts[kind][outcome] += 1
            if got['status'] != 200:
                failures.append({'at': at, 'kind': kind, 'outcome': outcome, 'detail': (got.get('error') or got.get('body') or '')[:80]})

    def slow():
        while not done():
            one('slow', f'/sleep/{slow_seconds}', slow_seconds + 20)

    for _ in range(slow_workers):
        threads.append(threading.Thread(target=slow))
        threads[-1].start()
    tick = 0
    while not done():
        thread = threading.Thread(target=one, args=('quick', '/quick', 8))
        thread.start()
        threads.append(thread)
        tick += 1
        time.sleep(max(0.0, started + tick / rate - time.monotonic()))
    for thread in threads:
        thread.join(40)
    return {'seconds': round(time.monotonic() - started, 1), 'quick': dict(counts['quick']), 'slow': dict(counts['slow']),
            'not_200': len(failures), 'failures': failures[:40]}


class Echo(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        if self.path.startswith('/sleep/'):
            time.sleep(float(self.path.rsplit('/', 1)[1]))
        body = json.dumps({'backend': socket.gethostname(), 'path': self.path}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def main() -> int:
    command, argv = sys.argv[1], sys.argv[2:]
    if command == 'echo':
        server = ThreadingHTTPServer(('0.0.0.0', int(os.environ.get('ECHO_PORT', '8000'))), Echo)
        server.daemon_threads = True
        server.serve_forever()
    elif command == 'inspect':
        print(json.dumps(inspect(argv[0], argv[1:])))
    elif command == 'load':
        print(json.dumps(load(argv[0], int(argv[1]), argv[2])))
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
