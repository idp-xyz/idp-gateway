#!/usr/bin/env python3
"""Ingress on the single-host pool.

Compiles an ingress spec with gateway-control, publishes it with gateway-control
publish onto deploy/compose/compose.yml (unchanged) plus pool.yml, and sends
callers through front. The stand-in is the only backend. There is no gateway-authz,
no ExtAuthZ, and no provider credential.

    .venv/bin/python tests/integration/ingress/pool.py
    .venv/bin/python tests/integration/ingress/pool.py --evidence     # writes evidence/pool-standin.json
    .venv/bin/python tests/integration/ingress/pool.py --control no-readback-route
    .venv/bin/python tests/integration/ingress/pool.py --control no-path-rule
    .venv/bin/python tests/integration/ingress/pool.py --control backend-untrusted-ca

Host ports are 27651 (front), 27652 (read-back) and 27653 (the publisher's scratch
gateway). 27654 is left unused. The project is idp-gateway-ingress-test. Containers,
networks and the temporary directory are removed however the run ends.
"""
from __future__ import annotations

import argparse
import atexit
import base64
import datetime
import hashlib
import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path

import jwt
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
DEPLOY = ROOT / 'deploy/compose'
LOCK = ROOT / 'deploy/agentgateway/agentgateway.lock.json'
EVIDENCE = HERE / 'evidence/pool-standin.json'
GO = '/usr/local/go/bin/go'
PROJECT = 'idp-gateway-ingress-test'
SCRATCH = f'{PROJECT}-scratch'
PORT = {'front': 27651, 'readback': 27652, 'staging': 27653}
RESERVED = (27651, 27652, 27653, 27654)
IN_POOL = {'callers': 8081, 'readback': 8443, 'admin': 15000, 'stats': 15020, 'readiness': 15021}
TOOLS_IMAGE = ('public.ecr.aws/docker/library/python:3.13-alpine@'
               'sha256:1e1f6334529d1fb26a2ef619d7cffb30a7c7d7cc1cc7338ebee283a58d1aeaca')
FRONT_IMAGE = ('public.ecr.aws/nginx/nginx-unprivileged:stable-alpine@'
               'sha256:c3fc8fa482be50ef709c6438eb1bc98d50dbfe5a9b48be90711b8814f4dfd701')
EGRESS_IMAGE = 'docker@sha256:b36f28717b43f23f56c7c72e97eeba80aeb24fc3f4dbf9fa409b25b074bf1260'
UPSTREAM_HOST = 'stand-in.ingress.example'
UPSTREAM_PORT = 9443
PUBLIC_HOST = 'api.ingress.example'
READBACK_NAME = 'ingress-readback.test'
ISSUER = 'https://issuer.example/ingress-pool'
AUDIENCE = 'ingress-pool.example'
PUBLISHER_ID = 'spiffe://idp.test/ingress-pool/publisher'
GATEWAY_ID = 'spiffe://idp.test/ingress-pool/gateway'
PATH_OK = '/v1/shipments'
BODY = b'stand-in-ok\n'
TRACE = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
REFUSED_BY_RULE = 113
PEM_MARKERS = ('BEGIN PRIVATE KEY', 'BEGIN RSA PRIVATE KEY', 'BEGIN EC PRIVATE KEY')
ALLOWED_HEADERS = {'host', 'accept', 'content-type', 'traceparent'}
FORBIDDEN_HEADERS = {'authorization', 'cookie', 'x-forwarded-for', 'x-not-registered'}

WORK: Path | None = None
TORN = False
SECRETS: list[tuple[str, str]] = []
GOOD = ''
TOKENS: dict[str, str] = {}


def say(text: str = '') -> None:
    print(text, flush=True)


def die(message: str) -> None:
    say('pool.py: ' + message)
    raise SystemExit(2)


def without_compose(env: dict) -> dict:
    return {key: value for key, value in env.items() if not key.startswith('COMPOSE_')}


def docker(*argv: str, timeout: float = 180, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(['docker', *argv], capture_output=True, text=True, timeout=timeout, env=without_compose(env or os.environ))


def settings(standin_cert: Path, standin_key: Path) -> dict:
    pool = WORK / 'pool'
    return {
        'CALLERS_LISTEN': f"127.0.0.1:{PORT['front']}",
        'READBACK_PORT': str(PORT['readback']),
        'READBACK_NAME': READBACK_NAME,
        'POOL_DIR': str(pool),
        'GATEWAY_USER': f'{os.getuid()}:{os.getgid()}',
        'CONTROL_USER': f'{os.getuid()}:{os.getgid()}',
        'GATEWAY_ENV_FILE': str(pool / 'gateway.env'),
        'GATEWAY_CONTROL': str(WORK / 'bin/gateway-control'),
        'PUBLISHER_CERT': str(WORK / 'certs/publisher.crt'),
        'PUBLISHER_KEY': str(WORK / 'certs/publisher.key'),
        'READBACK_CA': str(WORK / 'certs/ca.crt'),
        'CONFIRM_TIMEOUT': '30s',
        'GATEWAY_IMAGE': gateway_image(),
        'TOOLS_IMAGE': TOOLS_IMAGE,
        'STANDIN_SCRIPT': str(HERE / 'standin.py'),
        'STANDIN_CERT': str(standin_cert),
        'STANDIN_KEY': str(standin_key),
        'STANDIN_CLIENT_CA': str(WORK / 'certs/ca.crt'),
        'STANDIN_STATE': str(WORK / 'state'),
    }


def compose_files() -> list[str]:
    return ['-f', str(DEPLOY / 'compose.yml'), '-f', str(HERE / 'pool.yml')]


def compose(*argv: str, timeout: float = 300) -> subprocess.CompletedProcess:
    if WORK is None or not (WORK / 'pool.env').exists():
        return subprocess.CompletedProcess(argv, 1, '', 'pool.env is not written')
    command = list(argv)
    if command and command[0] == 'up':
        command = ['up', '--pull', 'never', *command[1:]]
    return subprocess.run(
        ['docker', 'compose', '-p', PROJECT, '--env-file', str(WORK / 'pool.env'), *compose_files(), *command],
        capture_output=True, text=True, timeout=timeout, env=without_compose(os.environ))


def container(service: str) -> dict:
    found = compose('ps', '-q', '-a', service).stdout.split()
    if not found:
        return {}
    inspected = json.loads(docker('inspect', found[0]).stdout or '[]')
    if not inspected:
        return {}
    raw = inspected[0]
    networks = raw['NetworkSettings'].get('Networks') or {}
    preferred = networks.get(f'{PROJECT}_default') or {}
    ip = preferred.get('IPAddress') or ''
    if not ip:
        for net in networks.values():
            if net.get('IPAddress'):
                ip = net['IPAddress']
                break
    return {
        'id': raw['Id'], 'name': raw['Name'].lstrip('/'), 'running': raw['State']['Running'],
        'exit': raw['State']['ExitCode'], 'started': raw['State'].get('StartedAt') or '',
        'env': raw['Config'].get('Env') or [], 'ip': ip,
    }


def wait_for(predicate, seconds: float, every: float = 0.4):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        value = predicate()
        if value:
            return value
        time.sleep(every)
    return None


def put(path: Path, content: str | bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = content if isinstance(content, bytes) else content.encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
    os.chmod(path, mode)


def gateway_image() -> str:
    image = json.loads(LOCK.read_text(encoding='utf-8'))['image']
    return f"{image['repository']}@{image['index']}"


def pinned_binary() -> tuple[Path, dict]:
    lock = json.loads(LOCK.read_text(encoding='utf-8'))
    binary = Path.home() / '.local/opt/agentgateway' / lock['version'] / 'agentgateway'
    if not binary.is_file():
        die(f'missing locked binary {binary}')
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    want = lock['sha256']['/app/agentgateway in the linux/amd64 image']
    if digest != want:
        die(f'{binary} SHA-256 is {digest}, lock file says {want}')
    reported = json.loads(subprocess.run([str(binary), '--version'], capture_output=True, text=True, timeout=20).stdout)
    return binary, reported


def port_open(port: int) -> bool:
    with socket.socket() as sock:
        sock.settimeout(0.3)
        return sock.connect_ex(('127.0.0.1', port)) == 0


def sweep_project() -> None:
    listed = docker('ps', '-aq', '--filter', f'label=com.docker.compose.project={PROJECT}').stdout.split()
    if listed:
        docker('rm', '-f', '-v', *listed, timeout=60)
    for network in docker('network', 'ls', '-q', '--filter', f'label=com.docker.compose.project={PROJECT}').stdout.split():
        docker('network', 'rm', network, timeout=30)
    docker('rm', '-f', SCRATCH, timeout=30)


def leftovers() -> str:
    names = docker('ps', '-a', '--filter', f'label=com.docker.compose.project={PROJECT}', '--format', '{{.Names}}').stdout.split()
    networks = docker('network', 'ls', '--filter', f'label=com.docker.compose.project={PROJECT}', '--format', '{{.Name}}').stdout.split()
    scratch = docker('ps', '-a', '--filter', f'name=^{SCRATCH}$', '--format', '{{.Names}}').stdout.split()
    busy = [str(port) for port in RESERVED if port_open(port)]
    parts = []
    if names:
        parts.append('containers ' + ','.join(names))
    if networks:
        parts.append('networks ' + ','.join(networks))
    if scratch:
        parts.append('scratch ' + ','.join(scratch))
    if busy:
        parts.append('ports ' + ','.join(busy))
    return '; '.join(parts)


def teardown() -> None:
    global TORN
    if TORN:
        return
    TORN = True
    if WORK is not None and (WORK / 'pool.env').exists():
        compose('down', '--volumes', '--remove-orphans', '--timeout', '10', timeout=120)
    sweep_project()
    if WORK is not None:
        shutil.rmtree(WORK, ignore_errors=True)


def pem_key(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def pem_cert(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def key_line(blob: bytes) -> str:
    lines = [line for line in blob.decode().splitlines() if line and not line.startswith('-----')]
    return lines[0] if lines else ''


def new_ca(common_name: str):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=6))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def leaf(ca_key, ca_cert, common_name: str, uris: list[str], dns_names: list[str], server: bool):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    sans = [x509.UniformResourceIdentifier(item) for item in uris] + [x509.DNSName(item) for item in dns_names]
    usage = ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=6))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return pem_cert(cert), pem_key(key)


def b64url_int(number: int) -> str:
    length = max(1, (number.bit_length() + 7) // 8)
    return base64.urlsafe_b64encode(number.to_bytes(length, 'big')).rstrip(b'=').decode()


def write_jwks_and_tokens() -> None:
    global GOOD
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = pem_key(key)
    other_private = pem_key(other)
    put(WORK / 'certs/jwt.key', private)
    put(WORK / 'certs/other.key', other_private)
    SECRETS.append(('jwt signing key', key_line(private)))
    SECRETS.append(('other signing key', key_line(other_private)))
    numbers = key.public_key().public_numbers()
    kid = 'ingress-pool-test'
    document = {'keys': [{
        'kty': 'RSA', 'use': 'sig', 'alg': 'RS256', 'kid': kid,
        'n': b64url_int(numbers.n), 'e': b64url_int(numbers.e),
    }]}
    text = json.dumps(document)
    put(WORK / 'pool/tls/jwks.json', text, 0o644)
    put(WORK / 'control/tls/jwks.json', text, 0o644)
    now = int(time.time())

    def mint(claims: dict, signing=private, key_id=kid) -> str:
        body = {
            'iss': ISSUER, 'aud': AUDIENCE, 'sub': 'caller.ingress.example',
            'iat': now - 30, 'nbf': now - 30, 'exp': now + 600,
        }
        body.update(claims)
        token = jwt.encode(body, signing, algorithm='RS256', headers={'kid': key_id})
        return token if isinstance(token, str) else token.decode()

    GOOD = mint({})
    TOKENS['valid'] = GOOD
    TOKENS['wrong audience'] = mint({'aud': 'other-audience.example'})
    TOKENS['wrong issuer'] = mint({'iss': 'https://other.example/not-the-issuer'})
    TOKENS['expired'] = mint({'iat': now - 600, 'nbf': now - 600, 'exp': now - 120})
    TOKENS['other key'] = mint({}, signing=other_private, key_id='other-key.example')
    for name, token in TOKENS.items():
        SECRETS.append((name + ' jwt', token))
    jwt.decode(GOOD, key.public_key(), algorithms=['RS256'], audience=AUDIENCE, issuer=ISSUER)


def remember_key(name: str, blob: bytes) -> None:
    line = key_line(blob)
    if line:
        SECRETS.append((name, line))


def issue_material(control: str | None) -> tuple[Path, Path]:
    ca_key, ca_cert = new_ca('ingress pool test CA')
    ca_pem = pem_cert(ca_cert)
    put(WORK / 'certs/ca.crt', ca_pem, 0o644)
    put(WORK / 'pool/tls/ca.crt', ca_pem, 0o644)
    put(WORK / 'control/tls/ca.crt', ca_pem, 0o644)
    pairs = {
        'gateway-readback': leaf(ca_key, ca_cert, 'gateway-readback', [GATEWAY_ID], [READBACK_NAME], True),
        'gateway': leaf(ca_key, ca_cert, 'gateway', [GATEWAY_ID], [], False),
        'publisher': leaf(ca_key, ca_cert, 'publisher', [PUBLISHER_ID], [], False),
        'standin': leaf(ca_key, ca_cert, UPSTREAM_HOST, [], [UPSTREAM_HOST], True),
    }
    for name, (cert, key) in pairs.items():
        cert_mode = 0o644
        if name == 'publisher':
            put(WORK / 'certs/publisher.crt', cert, cert_mode)
            put(WORK / 'certs/publisher.key', key)
            remember_key('publisher key', key)
            continue
        if name == 'standin':
            put(WORK / 'certs/standin.crt', cert, cert_mode)
            put(WORK / 'certs/standin.key', key)
            remember_key('stand-in key', key)
            continue
        for directory in (WORK / 'pool/tls', WORK / 'control/tls'):
            put(directory / f'{name}.crt', cert, cert_mode)
            put(directory / f'{name}.key', key)
        if name == 'gateway':
            remember_key('gateway key', key)
        else:
            remember_key('read-back key', key)
    standin_cert, standin_key = WORK / 'certs/standin.crt', WORK / 'certs/standin.key'
    if control == 'backend-untrusted-ca':
        rogue_key, rogue_cert = new_ca('a CA outside the ingress pool test')
        cert, key = leaf(rogue_key, rogue_cert, UPSTREAM_HOST, [], [UPSTREAM_HOST], True)
        standin_cert, standin_key = WORK / 'certs/rogue-standin.crt', WORK / 'certs/rogue-standin.key'
        put(standin_cert, cert, 0o644)
        put(standin_key, key)
        remember_key('untrusted stand-in key', key)
    return standin_cert, standin_key


def spec_document() -> dict:
    return {
        'traffic_class': 'INGRESS',
        'pool': {
            'name': 'ingress-test',
            'environment': 'TEST',
            'public_hostname': PUBLIC_HOST,
            'listen_port': IN_POOL['callers'],
            'bind_address': '127.0.0.1',
            'admin_addr': f"127.0.0.1:{IN_POOL['admin']}",
            'stats_addr': f"127.0.0.1:{IN_POOL['stats']}",
            'readiness_addr': f"127.0.0.1:{IN_POOL['readiness']}",
            'readback_port': IN_POOL['readback'],
            'publisher_identity': PUBLISHER_ID,
            'tls_dir': 'tls',
            'jwt_issuer': ISSUER,
            'jwt_audiences': [AUDIENCE],
            'jwks_file': 'tls/jwks.json',
            'notes': 'Test spec for tests/integration/ingress. Host names, the issuer and the audience are not product constants.',
        },
        'backend': {
            'backend_service_ref': 'service:ingress.example/stand-in',
            'upstream_host': UPSTREAM_HOST,
            'upstream_port': UPSTREAM_PORT,
            'upstream_tls': 'VERIFY_REQUIRED',
            'upstream_sni': UPSTREAM_HOST,
            'route_timeout': '5s',
        },
        'routes': [{
            'intent_id': 'gwi-ingress-pool-001',
            'route_id': 'ingress-shipments',
            'logical_path': PATH_OK,
            'allowed_methods': ['GET', 'HEAD'],
            'api_asset_ref': 'apiasset:ingress.example/shipments',
            'authz_profile': 'caller-jwt-v1',
            'approval_ref': 'APPROVAL-TEST-INGRESS',
            'expected_generation': 0,
            'transport': 'HTTP',
            'policy_bundle_ref': 'policy:ingress-pool-v1',
        }],
    }


def dump_yaml(document: dict) -> str:
    text = yaml.safe_dump(document, sort_keys=False, width=4096, default_flow_style=False)
    return text if text.endswith('\n') else text + '\n'


def compile_spec(binary: Path) -> bytes:
    spec_path = WORK / 'spec.json'
    put(spec_path, json.dumps(spec_document(), indent=2) + '\n', 0o644)
    gateway_out = WORK / 'compiled.yaml'
    policy_out = WORK / 'policy.json'
    done = subprocess.run([
        str(WORK / 'bin/gateway-control'), 'compile',
        '--spec', str(spec_path),
        '--output-gateway', str(gateway_out),
        '--output-policy', str(policy_out),
        '--agentgateway', str(binary),
        '--lock-file', str(LOCK),
    ], capture_output=True, text=True, timeout=60)
    if done.returncode != 0:
        die(f'compile failed ({done.returncode}): {done.stdout[-400:]} {done.stderr[-600:]}')
    try:
        line = json.loads(done.stdout)
    except ValueError:
        die(f'compile did not write JSON: {done.stdout[:300]}')
    if line.get('outcome') != 'COMPILED' or line.get('routes') != 2 or line.get('native_validated') is not True:
        die(f'compile line {line}')
    text = gateway_out.read_text(encoding='utf-8')
    if "name: 'read-back'" not in text or f"host: '{UPSTREAM_HOST}:{UPSTREAM_PORT}'" not in text:
        die('compiled gateway file is missing the read-back route or the stand-in host')
    return text.encode()


def mutate(original: bytes, control: str | None) -> bytes:
    if control not in ('no-readback-route', 'no-path-rule'):
        return original
    document = yaml.safe_load(original)
    if control == 'no-readback-route':
        document['routes'] = [route for route in document['routes'] if route.get('name') != 'read-back']
    else:
        for route in document['routes']:
            if route.get('name') == 'read-back':
                continue
            route.get('policies', {}).pop('authorization', None)
    rendered = dump_yaml(document).encode()
    check = yaml.safe_load(rendered)
    names = [route.get('name') for route in check['routes']]
    if control == 'no-readback-route':
        if 'read-back' in names or 'read-back' not in check['gateways']:
            die('no-readback-route did not leave the listener without its route')
    else:
        business = [route for route in check['routes'] if route.get('name') != 'read-back']
        if not business or any('authorization' in (route.get('policies') or {}) for route in business):
            die('no-path-rule did not remove the exact-path rule')
        if 'read-back' not in names:
            die('no-path-rule removed the read-back route')
    return rendered


def bootstrap(original: bytes) -> str:
    document = yaml.safe_load(original)
    first = {key: value for key, value in document.items() if key not in ('gateways', 'routes')}
    first['gateways'] = {'read-back': document['gateways']['read-back']}
    first['routes'] = [route for route in document['routes'] if route.get('name') == 'read-back']
    if len(first['routes']) != 1:
        die('bootstrap has no read-back route')
    return dump_yaml(first)


def build_control() -> None:
    (WORK / 'bin').mkdir(parents=True, exist_ok=True)
    done = subprocess.run(
        [GO, 'build', '-trimpath', '-o', str(WORK / 'bin/gateway-control'), './cmd/gateway-control'],
        cwd=ROOT, capture_output=True, text=True, timeout=180,
        env={**os.environ, 'CGO_ENABLED': '0'})
    if done.returncode != 0:
        die('gateway-control did not build:\n' + done.stderr[-1500:])


def prepare(control: str | None, binary: Path) -> bytes:
    for directory in (WORK / 'pool/config', WORK / 'pool/tls', WORK / 'control/tls', WORK / 'control/work',
                      WORK / 'control/snapshots', WORK / 'certs', WORK / 'state', WORK / 'bin'):
        directory.mkdir(parents=True, exist_ok=True)
    os.chmod(WORK / 'pool', 0o755)
    os.chmod(WORK / 'pool/config', 0o755)
    os.chmod(WORK / 'pool/tls', 0o755)
    os.chmod(WORK / 'state', 0o755)
    standin_cert, standin_key = issue_material(control)
    write_jwks_and_tokens()
    put(WORK / 'pool/gateway.env', 'SESSION_KEY=' + os.urandom(32).hex() + '\n')
    original = compile_spec(binary)
    put(WORK / 'pool/config/config.yaml', bootstrap(original), 0o644)
    snapshot = mutate(original, control)
    put(WORK / 'control/snapshots/ingress.yaml', snapshot, 0o644)
    put(WORK / 'pool.env', ''.join(f'{key}={value}\n' for key, value in settings(standin_cert, standin_key).items()), 0o600)
    return snapshot


def publish(snapshot: bytes) -> dict:
    path = WORK / 'control/snapshots/ingress.yaml'
    put(path, snapshot, 0o644)
    argv = [
        str(WORK / 'bin/gateway-control'), 'publish', '--snapshot', str(path),
        '--config-dir', str(WORK / 'pool/config'),
        '--read-back', f"127.0.0.1:{PORT['readback']}", '--read-back-name', READBACK_NAME,
        '--tls-cert', str(WORK / 'certs/publisher.crt'), '--tls-key', str(WORK / 'certs/publisher.key'),
        '--tls-ca', str(WORK / 'certs/ca.crt'),
        '--image', gateway_image(), '--staging-name', SCRATCH,
        '--staging-publish', f"127.0.0.1:{PORT['staging']}",
        '--staging-container-port', str(IN_POOL['readback']),
        '--staging-tls-dir', str(WORK / 'control/tls'),
        '--staging-work-dir', str(WORK / 'control/work'),
    ]
    started = time.monotonic()
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=150)
        code, stdout, stderr = done.returncode, done.stdout, done.stderr
    except subprocess.TimeoutExpired as exc:
        code, stdout, stderr = None, exc.stdout or '', (exc.stderr or '') + '\ntimeout'
        if isinstance(stdout, bytes):
            stdout = stdout.decode()
        if isinstance(stderr, bytes):
            stderr = stderr.decode()
    try:
        report = json.loads(stdout) if stdout.strip() else {}
    except ValueError:
        report = {}
    return {
        'exit': code, 'outcome': report.get('outcome'), 'stdout': stdout.strip(),
        'stderr': stderr.strip()[-800:], 'report': report if isinstance(report, dict) else {},
        'seconds': round(time.monotonic() - started, 2),
    }


class ReadBack(http.client.HTTPSConnection):
    def __init__(self, context: ssl.SSLContext):
        super().__init__(READBACK_NAME, PORT['readback'], timeout=5, context=context)
        self._context = context

    def connect(self):
        sock = socket.create_connection(('127.0.0.1', self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=READBACK_NAME)
        except BaseException:
            sock.close()
            raise


def read_back(path: str) -> dict:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(WORK / 'certs/ca.crt')
    context.load_cert_chain(WORK / 'certs/publisher.crt', WORK / 'certs/publisher.key')
    try:
        conn = ReadBack(context)
        conn.request('GET', path, headers={'Host': READBACK_NAME})
        response = conn.getresponse()
        body = response.read(4096)
        conn.close()
        return {'status': response.status, 'body': body[:120].decode('latin1', 'replace')}
    except (OSError, ssl.SSLError) as exc:
        return {'status': None, 'error': f'{type(exc).__name__}: {exc}'[:200]}


def read_records() -> list:
    path = WORK / 'state/records.jsonl'
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding='utf-8').splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def public_view(record: dict) -> dict:
    headers = record.get('headers') or {}
    shown = {}
    for key, value in headers.items():
        if key in ALLOWED_HEADERS:
            shown[key] = value
        else:
            shown[key] = f'<present, {len(value)} bytes>'
    return {
        'method': record.get('method'), 'path': record.get('path'), 'headers': shown,
        'client_subject': record.get('client_subject'), 'client_sans': record.get('client_sans'),
        'sent_headers': record.get('sent_headers'),
    }


def call(method: str, path: str, token: str | None = None, host: str | None = None,
         extra: dict | None = None, body: bytes | None = None) -> dict:
    headers = {'Host': host or PUBLIC_HOST, 'Connection': 'close'}
    if token is not None:
        headers['Authorization'] = 'Bearer ' + token
    if extra:
        headers.update(extra)
    started = time.monotonic()
    try:
        conn = http.client.HTTPConnection('127.0.0.1', PORT['front'], timeout=12)
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        payload = response.read(65536)
        names = [key.lower() for key, _value in response.getheaders()]
        conn.close()
        return {'status': response.status, 'body': payload, 'header_names': names,
                'ms': round((time.monotonic() - started) * 1000, 1), 'error': None}
    except OSError as exc:
        return {'status': None, 'body': b'', 'header_names': [],
                'ms': round((time.monotonic() - started) * 1000, 1),
                'error': f'{type(exc).__name__}: {exc}'[:200]}


def exchange(method: str, path: str, token: str | None = None, host: str | None = None,
             extra: dict | None = None, body: bytes | None = None) -> tuple[dict, list]:
    before = len(read_records())
    answer = call(method, path, token, host, extra, body)
    return answer, read_records()[before:]


def two_hosts() -> dict:
    raw = (
        f'GET {PATH_OK} HTTP/1.1\r\nHost: {PUBLIC_HOST}\r\nHost: other.ingress.example\r\nConnection: close\r\n\r\n'
    ).encode()
    try:
        with socket.create_connection(('127.0.0.1', PORT['front']), 5) as sock:
            sock.sendall(raw)
            data = b''
            while len(data) < 65536:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
    except OSError as exc:
        return {'status': None, 'body': b'', 'status_line': '', 'error': f'{type(exc).__name__}: {exc}'[:200]}
    head, _, _body = data.partition(b'\r\n\r\n')
    lines = head.decode('latin1').split('\r\n')
    parts = lines[0].split() if lines else []
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
    return {'status': status, 'body': data.split(b'\r\n\r\n', 1)[-1], 'status_line': lines[0] if lines else ''}


def check_success(results: 'Results', answer: dict, seen: list, label: str = '') -> None:
    prefix = f'{label}: ' if label else ''
    results.note(prefix + 'status', answer['status'])
    results.note(prefix + 'body', answer['body'][:160].decode('latin1', 'replace'))
    results.note(prefix + 'backend count', len(seen))
    results.check(prefix + 'status 200', answer['status'] == 200)
    results.check(prefix + 'body is the stand-in body', answer['body'] == BODY)
    results.check(prefix + 'the backend application received one request', len(seen) == 1)
    if not seen:
        results.note(prefix + 'backend', [])
        results.check(prefix + 'the backend saw the gateway client certificate', False)
        results.check(prefix + 'Host is the spec authority', False)
        return
    record = seen[0]
    results.note(prefix + 'backend', public_view(record))
    uris = [item['value'] for item in record.get('client_sans') or [] if item.get('kind') == 'URI']
    host = (record.get('headers') or {}).get('host')
    results.check(prefix + 'the backend saw the gateway client certificate', GATEWAY_ID in uris)
    results.check(prefix + 'Host is the spec authority', host == UPSTREAM_HOST)


class Results:
    def __init__(self):
        self.cases = []
        self.current = None

    def case(self, case_id: str, title: str) -> None:
        self.current = {'id': case_id, 'title': title, 'checks': [], 'notes': []}
        self.cases.append(self.current)

    def check(self, text: str, ok: bool) -> None:
        self.current['checks'].append({'check': text, 'ok': bool(ok)})

    def note(self, text: str, value) -> None:
        self.current['notes'].append({'note': text, 'value': value})

    def failed(self) -> list:
        return [case for case in self.cases if any(item['ok'] is False for item in case['checks'])]

    def report(self) -> None:
        for case in self.cases:
            bad = [item['check'] for item in case['checks'] if not item['ok']]
            state = 'FAIL' if bad else 'pass'
            say(f"{case['id']} {state}  {sum(item['ok'] for item in case['checks'])}/{len(case['checks'])}")
            for item in case['notes']:
                say(f"    {item['note']}: {json.dumps(item['value'], ensure_ascii=False)[:500]}")
            for item in bad:
                say(f"    not met: {item}")


CONNECT = r'''
import json, socket, sys
seen = {}
for target in sys.argv[1:]:
    host, port = target.rsplit(":", 1)
    with socket.socket() as s:
        s.settimeout(3)
        seen[target] = s.connect_ex((host, int(port)))
print(json.dumps(seen))
'''


def from_the_pool(code: str, *argv: str) -> dict:
    netns = container('netns')
    if not netns.get('id'):
        return {'error': 'netns is not running'}
    done = docker('run', '--rm', '--network', f"container:{netns['id']}", TOOLS_IMAGE, 'python', '-c', code, *argv, timeout=60)
    try:
        return json.loads(done.stdout)
    except ValueError:
        return {'error': (done.stderr or done.stdout).strip()[-300:]}


def pinned() -> dict:
    listed = compose('run', '--rm', '--no-deps', '--entrypoint', 'iptables', 'egress', '-S', 'IDP_EGRESS', timeout=60).stdout
    found = {}
    for line in listed.splitlines():
        words = line.replace('"', '').split()
        if '--comment' in words and '-d' in words and words[words.index('--comment') + 1].startswith('pin:'):
            found.setdefault(words[words.index('--comment') + 1][4:], []).append(words[words.index('-d') + 1].split('/')[0])
    return {key: sorted(set(addresses)) for key, addresses in found.items()}


def ensure_images() -> None:
    for image in (gateway_image(), TOOLS_IMAGE, FRONT_IMAGE, EGRESS_IMAGE):
        have = docker('image', 'inspect', image, timeout=30)
        if have.returncode == 0:
            continue
        say('pulling an image that is not local yet')
        done = docker('pull', image, timeout=300)
        if done.returncode != 0:
            die('could not pull a required image\n' + (done.stderr or done.stdout)[-500:])


def strip_proxy() -> list[str]:
    names = sorted(key for key in os.environ if 'proxy' in key.lower())
    for name in names:
        os.environ.pop(name, None)
    return names


def proxy_in_containers() -> dict:
    found = {}
    for service in ('agentgateway', 'front', 'netns', 'standin', 'outsider'):
        info = container(service)
        found[service] = sorted(item.split('=', 1)[0] for item in info.get('env') or [] if 'proxy' in item.split('=', 1)[0].lower())
    return found


def log_text(service: str) -> str:
    return compose('logs', '--no-color', '--no-log-prefix', service, timeout=60).stdout


def run_cases(results: Results, published: dict) -> None:
    results.case('IN-01', 'gateway-control publish of the compiled file reports the confirmed outcome')
    results.note('exit', published['exit'])
    results.note('outcome', published['outcome'])
    results.note('outcome line', published['stdout'][:1500])
    results.note('stderr', published['stderr'])
    results.note('seconds', published['seconds'])
    results.check('publish exits 0', published['exit'] == 0)
    results.check('publish outcome is ACTIVE', published['outcome'] == 'ACTIVE')

    results.case('IN-02', 'no token is 401 and the backend receives nothing')
    answer, seen = exchange('GET', PATH_OK)
    results.note('status', answer['status'])
    results.note('error', answer['error'])
    results.note('backend count', len(seen))
    results.check('status 401', answer['status'] == 401)
    results.check('the backend received nothing', seen == [])

    results.case('IN-03', 'a valid token GET of the registered path reaches the stand-in')
    answer, seen = exchange('GET', PATH_OK, GOOD, extra={'Accept': 'application/json'})
    check_success(results, answer, seen)

    results.case('IN-04', 'the caller JWT is not forwarded; only the allowlisted headers are')
    answer, seen = exchange('GET', PATH_OK, GOOD, extra={
        'Accept': 'application/json', 'Content-Type': 'application/json', 'traceparent': TRACE,
        'Cookie': 'session=not-a-secret', 'X-Forwarded-For': '203.0.113.5', 'X-Not-Registered': 'probe',
    })
    results.note('status', answer['status'])
    names = set()
    if seen:
        names = set(seen[0].get('headers') or {})
        results.note('backend', public_view(seen[0]))
    else:
        results.note('backend', [])
    results.note('header names', sorted(names))
    outside = sorted(names - ALLOWED_HEADERS)
    if outside:
        results.note('headers outside host and the allowlist', outside)
    results.check('status 200', answer['status'] == 200)
    results.check('the backend received the request', len(seen) == 1)
    results.check('Authorization was not forwarded', 'authorization' not in names)
    results.check('Cookie, X-Forwarded-For and X-Not-Registered were not forwarded', FORBIDDEN_HEADERS.isdisjoint(names))
    results.check('no header outside host, accept, content-type and traceparent', not outside)

    results.case('IN-05', 'HEAD on the registered path')
    answer, seen = exchange('HEAD', PATH_OK, GOOD, extra={'Accept': 'application/json'})
    results.note('status', answer['status'])
    results.note('caller body length', len(answer['body']))
    results.note('backend', [public_view(item) for item in seen])
    results.check('status 200', answer['status'] == 200)
    results.check('the backend saw HEAD on the registered path',
                  len(seen) == 1 and seen[0].get('method') == 'HEAD' and seen[0].get('path') == PATH_OK)

    results.case('IN-06', 'POST is not a registered method')
    answer, seen = exchange('POST', PATH_OK, GOOD, extra={'Content-Type': 'application/json'}, body=b'{}')
    results.note('status', answer['status'])
    results.note('backend count', len(seen))
    results.check('the backend received nothing', seen == [])
    results.check('the caller got 403, 404 or 405', answer['status'] in (403, 404, 405))

    results.case('IN-07', 'a deeper path and a path that only shares the prefix do not reach the backend')
    for label, path in (('deeper path', PATH_OK + '/123'), ('prefix string', '/v1/shipmentsX')):
        answer, seen = exchange('GET', path, GOOD)
        results.note(label + ' status', answer['status'])
        results.note(label + ' backend count', len(seen))
        if seen:
            results.note(label + ' backend', public_view(seen[0]))
        results.check(label + ' is 403 or 404', answer['status'] in (403, 404))
        results.check(label + ' backend received nothing', seen == [])

    results.case('IN-08', 'wrong audience, wrong issuer, expired token, and a token signed by another key are 401')
    for name in ('wrong audience', 'wrong issuer', 'expired', 'other key'):
        answer, seen = exchange('GET', PATH_OK, TOKENS[name])
        results.note(name + ' status', answer['status'])
        results.note(name + ' backend count', len(seen))
        results.check(name + ' is 401', answer['status'] == 401)
        results.check(name + ' backend received nothing', seen == [])

    results.case('IN-09', 'another Host header')
    answer, seen = exchange('GET', PATH_OK, GOOD, host='other.ingress.example')
    results.note('status', answer['status'])
    results.note('backend count', len(seen))
    results.check('the backend received nothing', seen == [])
    results.check('the caller got 403 or 404', answer['status'] in (403, 404))

    results.case('IN-10', 'Location and Set-Cookie from the backend do not reach the caller')
    answer, seen = exchange('GET', PATH_OK, GOOD)
    names = answer['header_names']
    results.note('status', answer['status'])
    results.note('caller header names', names)
    results.note('backend sent_headers', seen[0].get('sent_headers') if seen else None)
    results.check('the backend answered', answer['status'] == 200 and len(seen) == 1)
    results.check('Location did not reach the caller', 'location' not in names)
    results.check('Set-Cookie did not reach the caller', 'set-cookie' not in names)

    results.case('IN-11', 'two Host headers through front are refused by nginx')
    before = len(read_records())
    raw = two_hosts()
    seen = read_records()[before:]
    results.note('status', raw['status'])
    results.note('status line', raw['status_line'])
    results.note('nginx error page', b'<center>nginx</center>' in raw['body'])
    results.check('status 400', raw['status'] == 400)
    results.check('the body is nginx\'s own error page', b'<center>nginx</center>' in raw['body'])
    results.check('the backend received nothing', seen == [])

    results.case('IN-12', 'stop then up -d comes back through place and confirm, and the registered GET still works')
    previous_confirm = container('confirm').get('started')
    stopped = compose('stop', timeout=120)
    started = compose('up', '-d', timeout=180)

    def confirm_settled():
        info = container('confirm')
        if info and not info.get('running') and info.get('started') and info.get('started') != previous_confirm:
            return info
        return None

    confirm = wait_for(confirm_settled, 25) or container('confirm')
    place = container('place')
    results.note('stop exit', stopped.returncode)
    results.note('up exit', started.returncode)
    results.note('up stderr', (started.stderr or '').strip()[-400:])
    results.note('confirm exit', confirm.get('exit') if confirm else None)
    results.note('place exit', place.get('exit') if place else None)
    results.check('place exits 0', bool(place) and place.get('exit') == 0 and not place.get('running'))
    results.check('confirm exits 0', started.returncode == 0 and bool(confirm) and confirm.get('exit') == 0 and not confirm.get('running'))
    came_back = wait_for(lambda: call('GET', PATH_OK, GOOD)['status'] == 200, 40)
    results.note('a GET returned 200 after restart', bool(came_back))
    answer, seen = exchange('GET', PATH_OK, GOOD, extra={'Accept': 'application/json'})
    check_success(results, answer, seen, 'after restart')

    results.case('IN-13', 'from the gateway namespace an address the published file does not name is refused, and the backend is reachable')
    held = pinned()
    standin = container('standin').get('ip', '')
    outsider = container('outsider').get('ip', '')
    upstream = f'{UPSTREAM_HOST}:{UPSTREAM_PORT}'
    results.note('pinned', held)
    results.note('stand-in address', standin)
    results.note('outsider address', outsider)
    targets = []
    if standin:
        targets.append(f'{standin}:{UPSTREAM_PORT}')
    if outsider:
        targets.append(f'{outsider}:8000')
    if standin:
        targets.append(f'{standin}:8000')
    targets.extend([f"127.0.0.1:{IN_POOL['callers']}", f"127.0.0.1:{IN_POOL['admin']}", f"127.0.0.1:{IN_POOL['stats']}"])
    seen = from_the_pool(CONNECT, *targets) if targets else {'error': 'no addresses'}
    results.note('connect', seen)
    results.check('the stand-in name is pinned to the stand-in address', bool(standin) and held.get(upstream) == [standin])
    results.check('the backend address can be connected to', bool(standin) and seen.get(f'{standin}:{UPSTREAM_PORT}') == 0)
    results.check('the outsider address is refused by the rule', bool(outsider) and seen.get(f'{outsider}:8000') == REFUSED_BY_RULE)
    results.check('another port on the stand-in and the stats port are refused by the rule',
                  bool(standin) and seen.get(f'{standin}:8000') == REFUSED_BY_RULE and seen.get(f"127.0.0.1:{IN_POOL['stats']}") == REFUSED_BY_RULE)
    results.check('the read-back route host is pinned on loopback', held.get(f"127.0.0.1:{IN_POOL['admin']}") == ['127.0.0.1'])
    results.check('loopback 8081 and the admin address named by the read-back route can be connected to',
                  seen.get(f"127.0.0.1:{IN_POOL['callers']}") == 0 and seen.get(f"127.0.0.1:{IN_POOL['admin']}") == 0)

    results.case('IN-14', 'the gateway log and the backend records contain no JWT and no private key material')
    texts = {
        'agentgateway log': log_text('agentgateway'),
        'front log': log_text('front'),
        'stand-in log': log_text('standin'),
        'backend records': (WORK / 'state/records.jsonl').read_text(encoding='utf-8') if (WORK / 'state/records.jsonl').exists() else '',
    }
    found = {}
    for where, text in texts.items():
        hits = [name for name, value in SECRETS if value and value in text]
        if any(marker in text for marker in PEM_MARKERS):
            hits.append('private-key header')
        found[where] = hits
    results.note('found', found)
    results.check('no JWT and no private key material in the gateway log, front log, stand-in log, or backend records',
                  all(not hits for hits in found.values()))


def evidence_document(args, reported: dict, binary: Path, published: dict, snapshot: bytes,
                      results: Results, started: str, finished: str, proxies: dict, removed_proxy: list[str]) -> dict:
    checks = [item for case in results.cases for item in case['checks']]
    cases = []
    for case in results.cases:
        if any(item['ok'] is False for item in case['checks']):
            state = 'fail'
        else:
            state = 'pass'
        cases.append({
            'id': case['id'], 'title': case['title'], 'result': state,
            'checks': [{'check': item['check'], 'result': 'pass' if item['ok'] else 'fail'} for item in case['checks']],
            'notes': case['notes'],
        })
    porcelain = subprocess.run(['git', '-C', str(ROOT), 'status', '--porcelain=v1'], capture_output=True, text=True).stdout
    return {
        'kind': 'ingress pool: deploy/compose/compose.yml unchanged, tests/integration/ingress/pool.yml adds the stand-in, gateway-control compile then publish, callers through front',
        'not_an_acceptance_pass': True,
        'operator_and_approver': 'Not recorded. This file records what was run and what was seen. It is not an acceptance pass and it is not a gate decision.',
        'control': args.control,
        'agentgateway': {
            'version': reported.get('version'), 'git_revision': reported.get('git_revision'),
            'image': gateway_image(), 'local_binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
        },
        'repository': {
            'commit': subprocess.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip(),
            'uncommitted_files': len([line for line in porcelain.splitlines() if line.strip()]),
        },
        'gateway_configuration_sha256': hashlib.sha256(snapshot).hexdigest(),
        'environment': ['TEST'],
        'started_at_utc': started, 'finished_at_utc': finished,
        'wall_seconds': round(time.monotonic() - results.started, 2),
        'upstream': {'kind': 'stand-in', 'host': UPSTREAM_HOST, 'port': UPSTREAM_PORT, 'authority': UPSTREAM_HOST},
        'publish': {'exit': published['exit'], 'outcome': published['outcome'], 'outcome_line': published['stdout'][:1500], 'seconds': published['seconds']},
        'proxy_variables_removed_from_this_process': removed_proxy,
        'gateway_proxy_variables': {'in_the_containers': proxies, 'present_in_the_containers': any(proxies.values())},
        'cases': cases,
        'summary': {
            'cases': len(cases),
            'cases_failed': sum(1 for case in cases if case['result'] == 'fail'),
            'checks': len(checks),
            'checks_passed': sum(1 for item in checks if item['ok']),
            'checks_failed': sum(1 for item in checks if not item['ok']),
        },
    }


def write_evidence(path: Path, document: dict) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, ensure_ascii=False, indent=1) + '\n', encoding='utf-8')
    text = path.read_text(encoding='utf-8')
    found = [name for name, value in SECRETS if value and value in text]
    if any(marker in text for marker in PEM_MARKERS):
        found.append('private-key header')
    if found:
        path.unlink()
        say('EVIDENCE NOT KEPT: the file held ' + ', '.join(found))
        return False
    say(f'evidence written: {path}')
    return True


def run(args, binary: Path, reported: dict, wall_start: float) -> int:
    overlay = (HERE / 'pool.yml').read_text(encoding='utf-8')
    if UPSTREAM_HOST not in overlay or '"9443"' not in overlay:
        die('pool.yml does not name the stand-in host and port the suite compiles')
    started = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
    ensure_images()
    build_control()
    removed_proxy = strip_proxy()
    snapshot = prepare(args.control, binary)
    say(f'pool {PROJECT} in {WORK}' + (f' control {args.control}' if args.control else ''))
    first = compose('up', '-d', 'agentgateway', 'standin', 'outsider', timeout=180)
    if first.returncode != 0:
        say('the pool did not start: ' + (first.stderr or '')[-800:])
    if not wait_for(lambda: read_back('/api/runtime').get('status') == 200, 40):
        say('read-back did not answer before publish')
        say('\n'.join(log_text('agentgateway').splitlines()[-12:]))
    published = publish(snapshot)
    say(f"publish: exit {published['exit']}, outcome {published['outcome']}, {published['seconds']}s")
    if published['stdout']:
        say(published['stdout'][:500])
    if published['stderr']:
        say(published['stderr'][-500:])
    full = compose('up', '-d', timeout=180)
    if full.returncode != 0:
        say('full up exit ' + str(full.returncode) + ' ' + (full.stderr or '')[-500:])
    if published['exit'] == 0:
        want_status = None if args.control == 'backend-untrusted-ca' else 200

        def front_ready():
            status = call('GET', PATH_OK, GOOD)['status']
            if want_status is None:
                return status is not None
            return status == want_status

        if not wait_for(front_ready, 40):
            say('front did not answer as expected before the cases')
    results = Results()
    results.started = wall_start
    run_cases(results, published)
    proxies = proxy_in_containers()
    results.report()
    failed = results.failed()
    say(f"proxy variables in containers: {proxies}")
    finished = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
    kept = True
    if args.evidence:
        document = evidence_document(args, reported, binary, published, snapshot, results, started, finished, proxies, removed_proxy)
        kept = write_evidence(EVIDENCE, document)
    checks = [item for case in results.cases for item in case['checks']]
    passed_checks = sum(item['ok'] for item in checks)
    say(f"{len(results.cases) - len(failed)}/{len(results.cases)} cases, {passed_checks}/{len(checks)} checks, wall {round(time.monotonic() - wall_start, 1)}s")
    return 0 if not failed and kept else 1


def main() -> int:
    global WORK, TORN
    parser = argparse.ArgumentParser(description='compiled ingress configuration on the single-host pool')
    parser.add_argument('--control', choices=['no-readback-route', 'no-path-rule', 'backend-untrusted-ca'])
    parser.add_argument('--evidence', action='store_true',
                        help='write tests/integration/ingress/evidence/pool-standin.json (only with this flag)')
    args = parser.parse_args()
    if args.evidence and args.control:
        die('--evidence is for a run of the compiled configuration, not for a control')
    for port in RESERVED:
        if port_open(port):
            die(f'port {port} is in use')
    sweep_project()
    for port in RESERVED:
        if port_open(port):
            die(f'port {port} is still in use after sweeping {PROJECT}')
    binary, reported = pinned_binary()
    WORK = Path(tempfile.mkdtemp(prefix='ingress-pool-'))
    TORN = False
    atexit.register(teardown)
    wall_start = time.monotonic()
    try:
        try:
            code = run(args, binary, reported, wall_start)
        except Exception:
            traceback.print_exc()
            code = 1
    finally:
        teardown()
    left = leftovers()
    if left:
        say('LEFTOVERS ' + left)
        return 1
    say('left nothing of ' + PROJECT)
    return code


if __name__ == '__main__':
    sys.exit(main())
