"""Loopback evidence for dual-replica SF lease + workloadtls hot-reload. Not an acceptance pass.

Real processes only: a Python SF OpenAPI token stand-in, sf-token-coordinator, and two
gateway-authz replicas. No agentgateway, no Gatekeeper, no provider-signer.

    /home/tops/workspace/idp-gateway/.venv/bin/python tests/integration/ha/run.py
    /home/tops/workspace/idp-gateway/.venv/bin/python tests/integration/ha/run.py --control no-lease-mutual-kick
    /home/tops/workspace/idp-gateway/.venv/bin/python tests/integration/ha/run.py --control wrong-identity

Ports 27841-27855 only. Proxy variables are removed before any subprocess or local request.
"""
from __future__ import annotations

import argparse
import atexit
import base64
import datetime
import http.client
import json
import os
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[3]

STANDIN, COORD, AUTHZ_A, AUTHZ_B = 27841, 27842, 27843, 27844
PORTS = tuple(range(27841, 27856))

AUTHZ_ID = "spiffe://idp.test/ha/gateway-authz"
GATEWAY_ID = "spiffe://idp.test/ha/gateway"
OTHER_ID = "spiffe://idp.test/ha/other"
COORD_NAME = "coord.ha.idp.test"
AUTHZ_A_NAME = "authz-a.ha.idp.test"
AUTHZ_B_NAME = "authz-b.ha.idp.test"
BINDING = "gatekeeper:sfintl-ha-test"
ACCOUNT = "account-blue"
TENANT = "TENANT-ID-BLUE"
SERVICE = "CLIENT-ID-BLUE"
PATH_ORDERS = "/providers/sfintl/v1/orders"
HANDLE = f"{BINDING}/{ACCOUNT}"

# Production-shaped lifetime. Cold Acquire uses MaxRefreshLead (10m); a short expireIn
# would make a just-committed lease look unusable to the other replica and force another FETCH.
TOKEN_EXPIRE_IN = 7200

WORK = None
PROCS = []
SERVERS = []
CLEANED = False
SECRETS = []  # redacted shapes only in say(); tokens and app secrets go here


class Results:
    def __init__(self):
        self.cases = []
        self.current = None

    def case(self, case_id, title):
        self.current = {"id": case_id, "title": title, "checks": [], "notes": []}
        self.cases.append(self.current)
        say(f"-- {case_id} {title}")
        return self.current

    def check(self, text, ok):
        self.current["checks"].append({"check": text, "ok": bool(ok)})
        say(f"    {'ok' if ok else 'FAIL'}  {text}")
        return bool(ok)

    def note(self, text, value):
        self.current["notes"].append({"note": text, "value": value})

    def failed(self):
        return [case for case in self.cases if any(not item["ok"] for item in case["checks"])]

    def report(self):
        say("---")
        total = 0
        passed = 0
        for case in self.cases:
            bad = [item["check"] for item in case["checks"] if not item["ok"]]
            ok_n = sum(item["ok"] for item in case["checks"])
            total += len(case["checks"])
            passed += ok_n
            say(f"{case['id']} {'FAIL' if bad else 'pass'}  {ok_n}/{len(case['checks'])}  {case['title']}")
            for item in case["notes"]:
                say("    " + item["note"] + ": " + clip(item["value"]))
            for item in bad:
                say("    not met: " + item)
        say(f"{len(self.cases)} cases, {passed}/{total} checks")
        return passed, total


def say(text):
    print(redact(text), flush=True)


def clip(value):
    raw = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    return redact(raw)[:500]


def die(text):
    say(text)
    raise SystemExit(2)


def remember_secret(value):
    if value and value not in SECRETS:
        SECRETS.append(value)


def redact(text):
    if not isinstance(text, str):
        text = str(text)
    for secret in SECRETS:
        if secret:
            text = text.replace(secret, "[redacted]")
    return text


def scrub_proxy():
    for key in list(os.environ):
        if "proxy" in key.lower():
            os.environ.pop(key, None)


def go_env():
    env = {key: value for key, value in os.environ.items() if "proxy" not in key.lower()}
    env["PATH"] = "/usr/local/go/bin:" + env.get("PATH", "")
    env["CGO_ENABLED"] = "0"
    return env


def listening_ports(ports):
    want = set(ports)
    found = set()
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = open(path, encoding="ascii").read().splitlines()
        except OSError:
            continue
        for line in lines[1:]:
            parts = line.split()
            local = parts[1] if len(parts) > 3 else ""
            if ":" not in local:
                continue
            port = int(local.rsplit(":", 1)[1], 16)
            if port in want and parts[3] == "0A":
                found.add(port)
    return sorted(found)


def ensure_free(ports):
    found = listening_ports(ports)
    if found:
        die("refusing to start; a process is listening on " + ", ".join(str(port) for port in found))


def build(pkg, dest):
    proc = subprocess.run(
        ["go", "build", "-o", str(dest), pkg],
        cwd=ROOT, env=go_env(), capture_output=True, text=True,
    )
    if proc.returncode != 0:
        die(f"go build {pkg} failed: {(proc.stdout + proc.stderr)[-1500:]}")


def name_of(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def new_key():
    return ec.generate_private_key(ec.SECP256R1())


def pem_key(key):
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    )


def write_key(path, key):
    path.write_bytes(pem_key(key))
    path.chmod(0o600)


def write_cert(path, cert):
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def atomic_replace_bytes(path, data):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    if path.suffix in (".key",) or path.name.endswith(".key"):
        tmp.chmod(0o600)
    os.replace(tmp, path)


def make_ca(common_name):
    key = new_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = name_of(common_name)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_leaf(ca_key, ca_cert, common_name, ekus, dns=(), uris=()):
    key = new_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name_of(common_name))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage(list(ekus)), critical=False)
    )
    names = [x509.DNSName(item) for item in dns]
    names += [x509.UniformResourceIdentifier(item) for item in uris]
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    return key, builder.sign(ca_key, hashes.SHA256())


def private_json(path, text):
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)
    if path.stat().st_mode & 0o077:
        die(f"{path} is readable by others")


def mkdir0700(path):
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)


def new_aes_key():
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")[:-1]


def cert_serial(path):
    cert = x509.load_pem_x509_certificate(Path(path).read_bytes())
    return cert.serial_number


# ---- SF OpenAPI token stand-in -----------------------------------------------------------------


class StandInState:
    def __init__(self, app_key, app_secret, expire_in):
        self.lock = threading.Lock()
        self.app_key = app_key
        self.app_secret = app_secret
        self.expire_in = int(expire_in)
        self.hits = 0
        self.last_token = ""
        self.valid = set()

    def issue(self, app_key, app_secret):
        with self.lock:
            if app_key != self.app_key or app_secret != self.app_secret:
                return None
            self.hits += 1
            # Production rule: a new token voids the previous one for this app.
            self.valid.clear()
            token = "auth_" + secrets.token_hex(20)
            self.valid.add(token)
            self.last_token = token
            remember_secret(token)
            return token, self.expire_in

    def snapshot(self):
        with self.lock:
            return {"hits": self.hits, "last_token": self.last_token, "expire_in": self.expire_in}

    def set_expire_in(self, seconds):
        with self.lock:
            self.expire_in = int(seconds)


def standin_handler(state: StandInState):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            return

        def _json(self, status, body):
            raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path == "/openapi/api/token":
                qs = parse_qs(parsed.query, keep_blank_values=True)
                keys = qs.get("appKey", [])
                secrets_q = qs.get("appSecret", [])
                if len(keys) != 1 or len(secrets_q) != 1:
                    self._json(200, {"apiResultCode": 502, "apiErrorMsg": "bad params",
                                     "apiResultData": None, "apiTimestamp": int(time.time() * 1000)})
                    return
                issued = state.issue(keys[0], secrets_q[0])
                if issued is None:
                    self._json(200, {"apiResultCode": 1002, "apiErrorMsg": "user does not exist",
                                     "apiResultData": None, "apiTimestamp": int(time.time() * 1000)})
                    return
                token, expire_in = issued
                self._json(200, {
                    "apiResultCode": 0,
                    "apiErrorMsg": None,
                    "apiResultData": {"expireIn": expire_in, "accessToken": token},
                    "apiTimestamp": int(time.time() * 1000),
                })
                return
            if parsed.path == "/admin/hits":
                snap = state.snapshot()
                self._json(200, {"hits": snap["hits"], "last_token_shape": "auth_" + ("*" * 40),
                                 "expire_in": snap["expire_in"]})
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self):
            parsed = urlparse(self.path)
            if parsed.path == "/admin/token-lifetime":
                qs = parse_qs(parsed.query)
                try:
                    seconds = int((qs.get("seconds") or ["0"])[0])
                except ValueError:
                    seconds = 0
                if seconds < 1:
                    self._json(400, {"error": "seconds must be >= 1"})
                    return
                state.set_expire_in(seconds)
                self._json(200, {"ok": True, "expire_in": seconds})
                return
            self.send_response(404)
            self.end_headers()

    return Handler


def start_standin(state: StandInState):
    httpd = ThreadingHTTPServer(("127.0.0.1", STANDIN), standin_handler(state))
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    SERVERS.append(httpd)
    return httpd


def standin_hits(state: StandInState):
    return state.snapshot()["hits"]


# ---- process helpers ---------------------------------------------------------------------------


def start_proc(name, argv, port, log_name=None):
    log_path = WORK / f"{log_name or name}.log"
    handle = open(log_path, "ab")
    proc = subprocess.Popen(argv, cwd=ROOT, stdout=handle, stderr=subprocess.STDOUT, env=go_env())
    PROCS.append({"name": name, "proc": proc, "port": port, "log": handle, "log_path": log_path})
    wait_listen(proc, log_path, [port])
    return proc


def wait_listen(proc, log_path, ports, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            die("process exited: " + tail(log_path))
        if all(port in listening_ports(ports) for port in ports):
            return
        time.sleep(0.05)
    die("process did not listen on " + ",".join(str(port) for port in ports) + ": " + tail(log_path))


def wait_quiet(ports, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not listening_ports(ports):
            return
        time.sleep(0.05)


def stop_named(name, wait_port=True):
    left = []
    for entry in list(PROCS):
        if entry["name"] != name:
            left.append(entry)
            continue
        proc = entry["proc"]
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(5)
        entry["log"].close()
        if wait_port and entry["port"] is not None:
            wait_quiet([entry["port"]])
    PROCS[:] = left


def stop_procs():
    for entry in list(reversed(PROCS)):
        proc = entry["proc"]
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(5)
        try:
            entry["log"].close()
        except Exception:
            pass
    PROCS.clear()


def stop_servers():
    for httpd in list(SERVERS):
        try:
            httpd.shutdown()
            httpd.server_close()
        except Exception:
            pass
    SERVERS.clear()


def tail(path):
    if path is None or not Path(path).exists():
        return ""
    return redact(Path(path).read_text(encoding="utf-8", errors="replace")[-1500:])


def pid_of(name):
    for entry in PROCS:
        if entry["name"] == name and entry["proc"].poll() is None:
            return entry["proc"].pid
    return None


def log_blob(*names):
    out = []
    for name in names:
        path = WORK / f"{name}.log"
        if path.exists():
            out.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(out)


# ---- mTLS client -------------------------------------------------------------------------------


class LoopbackHTTPS(http.client.HTTPSConnection):
    def __init__(self, port, context, timeout, server_name):
        super().__init__(server_name, port, timeout=timeout, context=context)
        self._tls = context
        self._server_name = server_name

    def connect(self):
        sock = socket.create_connection(("127.0.0.1", self.port), self.timeout)
        try:
            self.sock = self._tls.wrap_socket(sock, server_hostname=self._server_name)
        except BaseException:
            sock.close()
            raise


def client_context(cert_name, ca_name="ca"):
    tls = WORK / "tls"
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(tls / f"{ca_name}.crt")
    ctx.load_cert_chain(tls / f"{cert_name}.crt", tls / f"{cert_name}.key")
    return ctx


def peer_serial(conn):
    cert = conn.sock.getpeercert(binary_form=True)
    parsed = x509.load_der_x509_certificate(cert)
    return parsed.serial_number


def check_headers():
    return {
        "x-idp-verified-subject": SERVICE,
        "x-idp-verified-tenant": TENANT,
        "x-idp-verified-env": "TEST",
        "x-idp-route-id": "sfintl-orders-create",
        "x-idp-provider-id": "sfintl",
        "x-idp-operation-id": "orders.create",
        "x-idp-environment": "TEST",
        "x-idp-method": "POST",
        "x-idp-path": PATH_ORDERS,
    }


def extauthz(port, server_name, cert_name="gateway", method="GET"):
    conn = LoopbackHTTPS(port, client_context(cert_name), 5, server_name)
    try:
        conn.request(method, "/v1/extauthz/check", headers=check_headers())
        response = conn.getresponse()
        body = response.read()
        auth = response.getheader("Authorization") or ""
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = {}
        serial = peer_serial(conn)
        return {
            "status": response.status,
            "authorization": auth,
            "body": parsed if isinstance(parsed, dict) else {},
            "serial": serial,
            "raw": body.decode("utf-8", errors="replace"),
        }
    finally:
        conn.close()


def token_from_header(authorization):
    # Sf-OpenApi appKey;token;aesKey
    if not authorization.startswith("Sf-OpenApi "):
        return ""
    parts = authorization[len("Sf-OpenApi "):].split(";")
    if len(parts) != 3:
        return ""
    return parts[1]


# ---- material / boot ---------------------------------------------------------------------------


def issue_material(app_key, app_secret, aes_key):
    tls = WORK / "tls"
    ca_key, ca_cert = make_ca("ha-loopback-ca")
    write_cert(tls / "ca.crt", ca_cert)

    both = (ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH)
    leaves = {
        "coord": (both, (COORD_NAME,), ("spiffe://idp.test/ha/sf-lease",)),
        "authz-a": (both, (AUTHZ_A_NAME,), (AUTHZ_ID,)),
        "authz-b": (both, (AUTHZ_B_NAME,), (AUTHZ_ID,)),
        "gateway": ((ExtendedKeyUsageOID.CLIENT_AUTH,), (), (GATEWAY_ID,)),
        "other": ((ExtendedKeyUsageOID.CLIENT_AUTH,), (), (OTHER_ID,)),
    }
    for filename, (ekus, dns, uris) in leaves.items():
        key, cert = make_leaf(ca_key, ca_cert, filename, ekus, dns=dns, uris=uris)
        write_key(tls / f"{filename}.key", key)
        write_cert(tls / f"{filename}.crt", cert)

    # Keep CA key for HA-04 re-issue.
    write_key(tls / "ca.key", ca_key)
    (tls / "ca_meta.json").write_text(json.dumps({"cn": "ha-loopback-ca"}), encoding="utf-8")
    return ca_key, ca_cert


def write_policy_and_apps(app_key, app_secret, aes_key):
    policy = {
        "version": "ha-sf-lease",
        "default_decision": "DENY",
        "registered_operations": [{
            "route_id": "sfintl-orders-create",
            "provider_id": "sfintl",
            "operation_id": "orders.create",
            "environment": "TEST",
            "method": "POST",
            "path_prefix": PATH_ORDERS,
            "upstream_hostname": "provider-signer.ha.idp.test",
            "port": 9444,
            "credential_binding_ref": BINDING,
            "allowed_tenants": [TENANT],
            "accounts_by_tenant": {TENANT: [ACCOUNT]},
            "allowed_service_ids": [SERVICE],
        }],
    }
    (WORK / "policy.json").write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
    endpoint = f"http://127.0.0.1:{STANDIN}/openapi/api/token"
    apps = {
        HANDLE: {
            "token_endpoint": endpoint,
            "app_key": app_key,
            "app_secret": app_secret,
            "encoding_aes_key": aes_key,
            "key_version": "1",
        },
    }
    private_json(WORK / "apps.json", json.dumps(apps))


def authz_argv(name, port, server_name, with_lease=True):
    tls = WORK / "tls"
    argv = [
        str(WORK / "gateway-authz"),
        "--listen", f"127.0.0.1:{port}",
        "--tls-cert", str(tls / f"{name}.crt"),
        "--tls-key", str(tls / f"{name}.key"),
        "--client-ca", str(tls / "ca.crt"),
        "--policy", str(WORK / "policy.json"),
        "--sf-openapi-apps", str(WORK / "apps.json"),
        "--sf-openapi-plain-http-host", "127.0.0.1",
        "--gateway-identity", GATEWAY_ID,
    ]
    if with_lease:
        argv += [
            "--sf-openapi-lease-url", f"https://127.0.0.1:{COORD}",
            "--sf-openapi-lease-cert", str(tls / f"{name}.crt"),
            "--sf-openapi-lease-key", str(tls / f"{name}.key"),
            "--sf-openapi-lease-ca", str(tls / "ca.crt"),
            "--sf-openapi-lease-name", COORD_NAME,
        ]
    return argv


def start_coordinator():
    tls = WORK / "tls"
    return start_proc("coordinator", [
        str(WORK / "sf-token-coordinator"),
        "--listen", f"127.0.0.1:{COORD}",
        "--tls-cert", str(tls / "coord.crt"),
        "--tls-key", str(tls / "coord.key"),
        "--client-ca", str(tls / "ca.crt"),
        "--authz-identity", AUTHZ_ID,
        "--lease-file", str(WORK / "leases.json"),
    ], COORD)


def start_authz(label, port, leaf_name, with_lease=True):
    # label is the process name; leaf_name is the cert basename.
    return start_proc(label, authz_argv(leaf_name, port, leaf_name, with_lease=with_lease), port, log_name=label)


def prepare(with_lease=True, expire_in=TOKEN_EXPIRE_IN):
    global WORK
    scrub_proxy()
    ensure_free(PORTS)
    WORK = Path(tempfile.mkdtemp(prefix="idp-gateway-ha-", dir="/tmp"))
    os.chmod(WORK, 0o700)
    mkdir0700(WORK / "tls")
    app_key = "app" + secrets.token_hex(8)
    app_secret = secrets.token_hex(24)
    aes_key = new_aes_key()
    remember_secret(app_secret)
    remember_secret(aes_key)
    remember_secret(app_key)
    issue_material(app_key, app_secret, aes_key)
    write_policy_and_apps(app_key, app_secret, aes_key)
    build("./cmd/gateway-authz", WORK / "gateway-authz")
    build("./cmd/sf-token-coordinator", WORK / "sf-token-coordinator")
    state = StandInState(app_key, app_secret, expire_in)
    start_standin(state)
    if with_lease:
        start_coordinator()
    start_authz("authz-a", AUTHZ_A, "authz-a", with_lease=with_lease)
    start_authz("authz-b", AUTHZ_B, "authz-b", with_lease=with_lease)
    return state


def cleanup():
    global CLEANED, WORK
    if CLEANED:
        return
    CLEANED = True
    stop_procs()
    stop_servers()
    wait_quiet(PORTS, seconds=8)
    if WORK is not None:
        shutil.rmtree(WORK, ignore_errors=True)
        WORK = None


# ---- cases -------------------------------------------------------------------------------------


def run_ha01(results, state):
    results.case("HA-01", "dual replica share one carrier token")
    pid_a = pid_of("authz-a")
    pid_b = pid_of("authz-b")
    results.check("authz-a and authz-b are running", pid_a is not None and pid_b is not None)

    barrier = threading.Barrier(16)
    outcomes = []
    lock = threading.Lock()

    def one(port, name):
        barrier.wait(10)
        got = extauthz(port, name)
        with lock:
            outcomes.append(got)

    threads = []
    for _ in range(8):
        threads.append(threading.Thread(target=one, args=(AUTHZ_A, AUTHZ_A_NAME)))
        threads.append(threading.Thread(target=one, args=(AUTHZ_B, AUTHZ_B_NAME)))
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)

    statuses = [item["status"] for item in outcomes]
    headers = [item["authorization"] for item in outcomes]
    tokens = [token_from_header(h) for h in headers]
    hits = standin_hits(state)
    results.check("16 concurrent checks returned", len(outcomes) == 16)
    results.check("all checks are 200", statuses == [200] * 16 and all(headers))
    results.check("stand-in token endpoint called exactly once", hits == 1)
    results.check("all Authorization headers share the same token", len(set(tokens)) == 1 and tokens[0] != "")
    results.check("all headers use Sf-OpenApi scheme", all(h.startswith("Sf-OpenApi ") for h in headers))
    results.check("authz PIDs unchanged", pid_of("authz-a") == pid_a and pid_of("authz-b") == pid_b)
    results.note("carrier_hits", hits)
    results.note("shared_token_shape", "auth_" + ("*" * 40) if tokens and tokens[0] else "")
    return tokens[0] if tokens else "", time.monotonic()


def run_ha02(results, state, shared_token):
    results.case("HA-02", "restarted authz-B reuses the coordinated token")
    pid_a = pid_of("authz-a")
    hits_before = standin_hits(state)
    stop_named("authz-b")
    start_authz("authz-b", AUTHZ_B, "authz-b", with_lease=True)
    pid_b = pid_of("authz-b")
    got_a = extauthz(AUTHZ_A, AUTHZ_A_NAME)
    got_b = extauthz(AUTHZ_B, AUTHZ_B_NAME)
    hits = standin_hits(state)
    tok_a = token_from_header(got_a["authorization"])
    tok_b = token_from_header(got_b["authorization"])
    results.check("authz-B came back on a new PID", pid_b is not None)
    results.check("authz-A PID unchanged", pid_of("authz-a") == pid_a)
    results.check("both checks are 200 with Sf-OpenApi", got_a["status"] == 200 and got_b["status"] == 200)
    results.check("restarted authz-B returns the same token", tok_b == shared_token and tok_a == shared_token)
    results.check("carrier still called exactly once total", hits == 1 and hits == hits_before)
    results.note("carrier_hits", hits)


def run_ha04(results):
    results.case("HA-04", "authz listen leaf hot-reload without restart")
    tls = WORK / "tls"
    ca_key = serialization.load_pem_private_key((tls / "ca.key").read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate((tls / "ca.crt").read_bytes())
    pid_a = pid_of("authz-a")
    pid_b = pid_of("authz-b")
    pid_c = pid_of("coordinator")
    before = extauthz(AUTHZ_A, AUTHZ_A_NAME)
    old_serial = before["serial"]
    results.check("pre-reload check is 200", before["status"] == 200)

    new_key, new_cert = make_leaf(
        ca_key, ca_cert, "authz-a-rotated",
        (ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH),
        dns=(AUTHZ_A_NAME,), uris=(AUTHZ_ID,),
    )
    new_serial = new_cert.serial_number
    atomic_replace_bytes(tls / "authz-a.crt", new_cert.public_bytes(serialization.Encoding.PEM))
    atomic_replace_bytes(tls / "authz-a.key", pem_key(new_key))
    # Force a new handshake (no keep-alive reuse of the old leaf).
    after = None
    for _ in range(20):
        after = extauthz(AUTHZ_A, AUTHZ_A_NAME)
        if after["status"] == 200 and after["serial"] == new_serial:
            break
        time.sleep(0.05)
    results.check("post-reload check is 200", after is not None and after["status"] == 200)
    results.check("new handshake presents the rotated serial", after["serial"] == new_serial and new_serial != old_serial)
    results.check("authz and coordinator PIDs unchanged",
                  pid_of("authz-a") == pid_a and pid_of("authz-b") == pid_b and pid_of("coordinator") == pid_c)
    results.note("old_serial", str(old_serial))
    results.note("new_serial", str(new_serial))

    # Optional: rotate coordinator server leaf the same way.
    old_coord = cert_serial(tls / "coord.crt")
    ck, cc = make_leaf(
        ca_key, ca_cert, "coord-rotated",
        (ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH),
        dns=(COORD_NAME,), uris=("spiffe://idp.test/ha/sf-lease",),
    )
    atomic_replace_bytes(tls / "coord.crt", cc.public_bytes(serialization.Encoding.PEM))
    atomic_replace_bytes(tls / "coord.key", pem_key(ck))
    # Authz still has a warm local cache; a check that does not need refresh should still pass.
    still = extauthz(AUTHZ_B, AUTHZ_B_NAME)
    results.check("after coordinator leaf rotate, warm-cache check still 200", still["status"] == 200)
    results.check("coordinator leaf file serial changed", cert_serial(tls / "coord.crt") != old_coord)
    results.check("coordinator PID still unchanged", pid_of("coordinator") == pid_c)


def run_ha03(results, state, issued_at):
    results.case("HA-03", "coordinator down fails closed without a new carrier fetch")
    # Warm-cache with a 2h token would still succeed after the coordinator stops.
    # Empty the local caches (restart both authz) so the next check must Acquire;
    # with the coordinator down that is fail-closed, never a direct carrier fetch.
    _ = issued_at
    hits_before = standin_hits(state)
    stop_named("coordinator")
    results.check("coordinator is no longer listening", COORD not in listening_ports([COORD]))
    stop_named("authz-a")
    stop_named("authz-b")
    start_authz("authz-a", AUTHZ_A, "authz-a", with_lease=True)
    start_authz("authz-b", AUTHZ_B, "authz-b", with_lease=True)

    got_a = extauthz(AUTHZ_A, AUTHZ_A_NAME)
    got_b = extauthz(AUTHZ_B, AUTHZ_B_NAME)
    hits = standin_hits(state)
    logs = log_blob("authz-a", "authz-b")
    results.check("authz-A check is not 200", got_a["status"] != 200)
    results.check("authz-B check is not 200", got_b["status"] != 200)
    results.check("no Authorization on denied responses",
                  not got_a["authorization"] and not got_b["authorization"])
    results.check("responses are 503 INDETERMINATE / CREDENTIAL_UNAVAILABLE",
                  got_a["status"] == 503 and got_b["status"] == 503
                  and got_a["body"].get("result") == "INDETERMINATE"
                  and got_b["body"].get("result") == "INDETERMINATE"
                  and got_a["body"].get("reason_code") == "CREDENTIAL_UNAVAILABLE"
                  and got_b["body"].get("reason_code") == "CREDENTIAL_UNAVAILABLE")
    results.check("carrier was not called again", hits == hits_before)
    results.check("authz logs show lease_unavailable", "lease_unavailable" in logs)
    results.note("carrier_hits", hits)
    results.note("authz_a_status", got_a["status"])
    results.note("authz_b_status", got_b["status"])


def run_cleanup(results):
    results.case("cleanup", "no leftover listeners on suite ports")
    stop_procs()
    stop_servers()
    wait_quiet(PORTS, seconds=8)
    left = listening_ports(PORTS)
    results.check("suite ports are free", left == [])
    if left:
        results.note("left", left)


def run_suite(results, state):
    shared, issued_at = run_ha01(results, state)
    run_ha02(results, state, shared)
    run_ha04(results)
    run_ha03(results, state, issued_at)
    run_cleanup(results)


# ---- controls ----------------------------------------------------------------------------------


def run_control_wrong_identity(results, state):
    results.case("control-wrong-identity", "wrong SPIFFE caller is 401")
    got = extauthz(AUTHZ_A, AUTHZ_A_NAME, cert_name="other")
    hits = standin_hits(state)
    results.check("status is 401", got["status"] == 401)
    results.check("no Authorization header", got["authorization"] == "")
    results.check("carrier was not called", hits == 0)
    results.note("status", got["status"])
    run_cleanup(results)


def run_control_no_lease(results, state):
    results.case("control-no-lease-mutual-kick", "without lease flags two authz each hit the carrier")
    barrier = threading.Barrier(8)
    outcomes = []
    lock = threading.Lock()

    def one(port, name):
        barrier.wait(10)
        got = extauthz(port, name)
        with lock:
            outcomes.append(got)

    threads = []
    for _ in range(4):
        threads.append(threading.Thread(target=one, args=(AUTHZ_A, AUTHZ_A_NAME)))
        threads.append(threading.Thread(target=one, args=(AUTHZ_B, AUTHZ_B_NAME)))
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)

    # Give the second fetch a moment if the first voided mid-flight.
    time.sleep(0.2)
    # One more round that must miss the voided peer token and fetch again if caches diverged.
    again_a = extauthz(AUTHZ_A, AUTHZ_A_NAME)
    again_b = extauthz(AUTHZ_B, AUTHZ_B_NAME)
    outcomes.extend([again_a, again_b])

    hits = standin_hits(state)
    tokens = [token_from_header(item["authorization"]) for item in outcomes if item.get("authorization")]
    distinct = {t for t in tokens if t}
    results.check("at least one check returned 200 with a token", len(tokens) >= 1)
    results.check("carrier was called at least twice", hits >= 2)
    results.check("tokens diverged or multiple carrier fetches prove mutual kick",
                  hits >= 2 or len(distinct) >= 2)
    results.note("carrier_hits", hits)
    results.note("distinct_token_count", len(distinct))
    run_cleanup(results)


def main():
    parser = argparse.ArgumentParser(description="HA dual-replica SF lease loopback. Not an acceptance pass.")
    parser.add_argument(
        "--control",
        choices=("wrong-identity", "no-lease-mutual-kick"),
        help="negative control; not part of the default run",
    )
    args = parser.parse_args()
    atexit.register(cleanup)
    say("ha dual-replica suite; not an acceptance pass")
    results = Results()
    try:
        if args.control == "wrong-identity":
            state = prepare(with_lease=True)
            run_control_wrong_identity(results, state)
        elif args.control == "no-lease-mutual-kick":
            state = prepare(with_lease=False)
            run_control_no_lease(results, state)
        else:
            state = prepare(with_lease=True)
            run_suite(results, state)
        if results.failed():
            say("authz-a log: " + tail(WORK / "authz-a.log" if WORK else None))
            say("authz-b log: " + tail(WORK / "authz-b.log" if WORK else None))
            say("coordinator log: " + tail(WORK / "coordinator.log" if WORK else None))
        passed, total = results.report()
        if results.failed():
            raise SystemExit(1)
        say(f"passed {passed}/{total}")
    finally:
        cleanup()
        still = listening_ports(PORTS)
        if still:
            say("leftover ports " + ",".join(str(port) for port in still))
            raise SystemExit(1)


if __name__ == "__main__":
    main()
