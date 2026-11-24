"""Loopback evidence for the API Fabric publication adapter. Not an acceptance pass.

The pool gateway is the locked agentgateway 1.7.0 binary on 127.0.0.1.
gateway-fabric loads the same bytes offline with the locked image
(cr.agentgateway.dev/agentgateway@sha256:60216aafb03d37f94e952ff3d51d2f630a65b10ecaebdc0a864882f92610c45b)
in a scratch container. The container has its own network namespace, so it can
bind the same gateway ports. PublishedDigest keeps those ports; they are not rewritten.

    /home/tops/workspace/idp-gateway/.venv/bin/python tests/integration/fabric/run.py
    /home/tops/workspace/idp-gateway/.venv/bin/python tests/integration/fabric/run.py --control skip-authz-reload
    /home/tops/workspace/idp-gateway/.venv/bin/python tests/integration/fabric/run.py --control bad-binding

Ports 27721-27735 only. No Docker container whose name lacks idp-gateway-fabric is touched.
Proxy variables are removed before any subprocess or local request.
"""
import argparse
import atexit
import base64
import copy
import datetime
import hashlib
import http.client
import ipaddress
import json
import os
import re
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

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from jwt import encode as jwt_encode

ROOT = Path(__file__).resolve().parents[3]
LOCK = ROOT / "deploy/agentgateway/agentgateway.lock.json"
SPEC_PATH = ROOT / "deploy/providers/wanbexpress/compile-spec.json"
BINARY = Path.home() / ".local/opt/agentgateway/1.7.0/agentgateway"
EXPECTED_SHA = "c7ef326b7b5702451e94bab55ff484d600d5abdc5344a4cdf7c72fc0bcff9e24"
EXPECTED_INDEX = "sha256:60216aafb03d37f94e952ff3d51d2f630a65b10ecaebdc0a864882f92610c45b"
CONTAINER = "idp-gateway-fabric-stage"

LISTEN, READBACK, ADMIN, STATS, READY = 27721, 27722, 27723, 27724, 27725
STAGING_PUBLISH, UPSTREAM, AUTHZ, FABRIC = 27726, 27727, 27728, 27729
PORTS = tuple(range(27721, 27736))

CALLER_HOST = "egress-api.idp.test"
ISSUER = "https://issuer.example/fabric"
AUDIENCE = "idp-egress-gateway"
TARGET = "fabric-target:egress-test"
BINDING_REF = "gatekeeper:wanbexpress-test"
PUBLISHER_ID = "spiffe://idp.test/gateway-control/publisher"
GATEWAY_ID = "spiffe://idp.test/egress/agentgateway"
FABRIC_ID = "spiffe://idp.test/fabric/publisher"
OTHER_ID = "spiffe://idp.test/fabric/other"
REVOKER_ID = "spiffe://idp.test/egress/revoker"
AUTHZ_NAME = "authz.idp.test"
READBACK_NAME = "readback.idp.test"
FABRIC_NAME = "fabric.idp.test"
HOST_NAME = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$")
TERMINAL = {"ACTIVE", "REJECTED", "FAILED", "CANCELED", "SUPERSEDED", "REVOKED", "UNKNOWN", "PARTIAL"}

WORK = None
TOKEN = ""
DEV_TOKEN = ""
UPSTREAM_NAME = ""
UPSTREAM_IP = ""
IMAGE = ""
HITS = []
HIT_LOCK = threading.Lock()
SERVERS = []
PROCS = []
CLEANED = False


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


def redact(text):
    if not isinstance(text, str):
        text = str(text)
    for secret in (TOKEN, DEV_TOKEN):
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


def gateway_env():
    env = go_env()
    env["SESSION_KEY"] = os.urandom(32).hex()
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


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_binary():
    if not BINARY.is_file():
        die(f"locked agentgateway is not at {BINARY}")
    got = sha256_file(BINARY)
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    want = {value.lower() for value in lock.get("sha256", {}).values()}
    if got not in want:
        die(f"agentgateway sha256 {got} does not match the lock file")
    if got != EXPECTED_SHA:
        die(f"agentgateway sha256 {got} is not the measured 1.7.0 binary")
    index = lock.get("image", {}).get("index", "")
    if index != EXPECTED_INDEX:
        die(f"lock file index {index} is not the measured image")
    global IMAGE
    IMAGE = lock["image"]["repository"] + "@" + index
    return got


def image_present():
    proc = subprocess.run(
        ["docker", "image", "inspect", IMAGE],
        env=go_env(), capture_output=True, text=True,
    )
    if proc.returncode != 0:
        die("locked agentgateway image is not present locally; this suite does not pull it")


def remove_fabric_containers():
    env = go_env()
    listed = subprocess.run(
        ["docker", "ps", "-aq", "--filter", "name=idp-gateway-fabric"],
        env=env, capture_output=True, text=True,
    )
    ids = [line for line in listed.stdout.split() if line]
    if not ids:
        return []
    subprocess.run(["docker", "rm", "-f", *ids], env=env, capture_output=True, text=True)
    return ids


def fabric_containers():
    listed = subprocess.run(
        ["docker", "ps", "-a", "--filter", "name=idp-gateway-fabric", "--format", "{{.Names}}"],
        env=go_env(), capture_output=True, text=True,
    )
    return [line for line in listed.stdout.splitlines() if line.strip()]


def build(pkg, dest):
    proc = subprocess.run(
        ["go", "build", "-o", str(dest), pkg],
        cwd=ROOT, env=go_env(), capture_output=True, text=True,
    )
    if proc.returncode != 0:
        die(f"go build {pkg} failed: {(proc.stdout + proc.stderr)[-1500:]}")


def loopback_name():
    for raw in Path("/etc/hosts").read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        try:
            ip = ipaddress.ip_address(parts[0])
        except ValueError:
            continue
        if ip.version != 4 or not ip.is_loopback:
            continue
        for name in parts[1:]:
            if HOST_NAME.fullmatch(name):
                return name, str(ip)
    die("/etc/hosts has no loopback name the compiler accepts as a DNS hostname")


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


def make_leaf(ca_key, ca_cert, common_name, eku, dns=(), uris=()):
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
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
    )
    names = [x509.DNSName(item) for item in dns]
    names += [x509.UniformResourceIdentifier(item) for item in uris]
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    return key, builder.sign(ca_key, hashes.SHA256())


def b64_coord(number):
    return base64.urlsafe_b64encode(number.to_bytes(32, "big")).rstrip(b"=").decode()


def issue_material():
    global TOKEN, DEV_TOKEN
    tls = WORK / "tls"
    pki = WORK / "pki"
    tls.mkdir(mode=0o700)
    pki.mkdir(mode=0o700)
    ca_key, ca_cert = make_ca("fabric-loopback-ca")
    write_cert(tls / "ca.crt", ca_cert)
    leaves = {
        "gateway-readback": (ExtendedKeyUsageOID.SERVER_AUTH, (READBACK_NAME,), ()),
        "gateway": (ExtendedKeyUsageOID.CLIENT_AUTH, (), (GATEWAY_ID,)),
    }
    for filename, (eku, dns, uris) in leaves.items():
        key, cert = make_leaf(ca_key, ca_cert, filename, eku, dns=dns, uris=uris)
        write_key(tls / f"{filename}.key", key)
        write_cert(tls / f"{filename}.crt", cert)
    pki_leaves = {
        "authz": (ExtendedKeyUsageOID.SERVER_AUTH, (AUTHZ_NAME,), ()),
        "fabric": (ExtendedKeyUsageOID.SERVER_AUTH, (FABRIC_NAME,), ()),
        "publisher": (ExtendedKeyUsageOID.CLIENT_AUTH, (), (PUBLISHER_ID,)),
        "fabric-client": (ExtendedKeyUsageOID.CLIENT_AUTH, (), (FABRIC_ID,)),
        "other": (ExtendedKeyUsageOID.CLIENT_AUTH, (), (OTHER_ID,)),
        "revoker": (ExtendedKeyUsageOID.CLIENT_AUTH, (), (REVOKER_ID,)),
    }
    for filename, (eku, dns, uris) in pki_leaves.items():
        key, cert = make_leaf(ca_key, ca_cert, filename, eku, dns=dns, uris=uris)
        write_key(pki / f"{filename}.key", key)
        write_cert(pki / f"{filename}.crt", cert)
    sign = new_key()
    numbers = sign.public_key().public_numbers()
    (tls / "jwks.json").write_text(json.dumps({"keys": [{
        "kty": "EC", "crv": "P-256", "kid": "suite", "alg": "ES256", "use": "sig",
        "x": b64_coord(numbers.x), "y": b64_coord(numbers.y),
    }]}), encoding="utf-8")
    now = int(time.time())
    TOKEN = jwt_encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "CLIENT-ID-BLUE", "tenant_id": "TENANT-ID-BLUE",
         "exp": now + 3600, "nbf": now - 60},
        pem_key(sign), algorithm="ES256", headers={"kid": "suite", "typ": "JWT"},
    )
    DEV_TOKEN = "dev-" + os.urandom(16).hex()
    secrets = WORK / "secrets"
    secrets.mkdir(mode=0o700)
    private_json(secrets / "tokens.json", json.dumps({
        BINDING_REF + "/account-blue": {"account": "blue-dev", "token": DEV_TOKEN},
    }))
    private_json(secrets / "revocations.json", json.dumps({"epoch": 0, "revoked_accounts": {}}))


def private_json(path, text):
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)
    if path.stat().st_mode & 0o077:
        die(f"{path} is readable by others")


def mkdir0700(path):
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)


def pool_spec():
    spec = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
    spec["pool"].update({
        "listen_port": LISTEN,
        "bind_address": "127.0.0.1",
        "readback_port": READBACK,
        "admin_addr": f"127.0.0.1:{ADMIN}",
        "stats_addr": f"127.0.0.1:{STATS}",
        "readiness_addr": f"127.0.0.1:{READY}",
        "publisher_identity": PUBLISHER_ID,
        "tls_dir": "tls",
        "jwt_issuer": ISSUER,
        "jwt_audiences": [AUDIENCE],
        "jwks_file": "tls/jwks.json",
        "ext_authz": {"host": f"127.0.0.1:{AUTHZ}", "hostname": AUTHZ_NAME, "timeout": "2s"},
    })
    spec["provider"].update({
        "policy_version": "wanbexpress-fabric",
        "upstream_host": UPSTREAM_NAME,
        "upstream_port": UPSTREAM,
        "rewrite_authority": UPSTREAM_NAME,
        "plain_http_sandbox_host": UPSTREAM_NAME,
        "route_timeout": "5s",
    })
    spec["access"]["policy_notes"] = "Loopback fabric suite. Names are not product constants."
    return spec


def write_specs():
    spec = pool_spec()
    (WORK / "pool-base.json").write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
    initial = copy.deepcopy(spec)
    initial["provider"]["policy_version"] = "wanbexpress-fabric-initial"
    initial["routes"] = [route_named(spec, "whoami.get", "GET")]
    (WORK / "initial.json").write_text(json.dumps(initial, indent=2) + "\n", encoding="utf-8")
    binding = {
        "binding_id": "bind-wanbexpress",
        "provider_id": "wanbexpress",
        "environment": "TEST",
        "auth_scheme": "API_KEY",
        "account_resolution": "GATEKEEPER_AUTHORIZED_ACCOUNT",
        "gateway_workload_id": GATEWAY_ID,
        "authorized_credential_ref": BINDING_REF,
        "approval_ref": "APPROVAL-SANDBOX-001",
    }
    (WORK / "bindings.json").write_text(json.dumps(binding, indent=2) + "\n", encoding="utf-8")
    bad = dict(binding)
    bad["auth_scheme"] = "OAUTH2_AUTHORIZATION_CODE"
    (WORK / "bindings-bad.json").write_text(json.dumps(bad, indent=2) + "\n", encoding="utf-8")
    return spec


def route_named(spec, operation, method):
    for route in spec["routes"]:
        if route["operation_id"] == operation and route["method"] == method:
            return route
    die(f"catalog has no {method} {operation}")


def compile_initial():
    gateway = WORK / "config" / "config.yaml"
    policy = WORK / "policy.json"
    proc = subprocess.run(
        [str(WORK / "gateway-control"), "compile",
         "--spec", str(WORK / "initial.json"),
         "--output-gateway", str(gateway),
         "--output-policy", str(policy),
         "--agentgateway", str(BINARY),
         "--lock-file", str(LOCK)],
        cwd=WORK, env=go_env(), capture_output=True, text=True,
    )
    if proc.returncode != 0:
        die("compile initial failed: " + (proc.stdout + proc.stderr)[-1500:])
    line = json.loads(proc.stdout)
    if line.get("outcome") != "COMPILED" or line.get("native_validated") is not True:
        die(f"compile initial line {line}")
    shutil.copyfile(policy, WORK / "policy-frozen.json")
    shutil.copyfile(policy, WORK / "policy-live.json")


def spawn(argv, log_name, env=None):
    log_path = WORK / log_name
    handle = open(log_path, "w", encoding="utf-8")
    proc = subprocess.Popen(
        argv, cwd=WORK, env=env or go_env(), stdout=handle, stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    PROCS.append((proc, handle, log_path))
    return proc, log_path


def stop_proc(proc, kill=False):
    if proc is None or proc.poll() is not None:
        return
    sig = signal.SIGKILL if kill else signal.SIGTERM
    for action in (
        lambda: os.killpg(proc.pid, sig),
        lambda: os.kill(proc.pid, sig),
    ):
        try:
            action()
        except OSError:
            pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        for action in (
            lambda: os.killpg(proc.pid, signal.SIGKILL),
            lambda: os.kill(proc.pid, signal.SIGKILL),
        ):
            try:
                action()
            except OSError:
                pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def sweep_suite_processes():
    # Children started with start_new_session survive the parent if a handle was lost.
    # Only processes whose cwd or command line is this suite's temp directory are signaled.
    prefix = "/tmp/idp-gateway-fabric-"
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid == os.getpid():
            continue
        try:
            cwd = os.readlink(f"/proc/{entry}/cwd")
            cmdline = open(f"/proc/{entry}/cmdline", "rb").read().replace(b"\0", b" ").decode("utf-8", "replace")
        except OSError:
            continue
        if prefix in cwd or prefix in cmdline:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass


def stop_procs():
    for proc, handle, _log in list(PROCS):
        stop_proc(proc)
        handle.close()
    PROCS.clear()


def tail(path):
    if path is None or not Path(path).exists():
        return ""
    return redact(Path(path).read_text(encoding="utf-8", errors="replace")[-1200:])


def wait_listen(proc, log_path, ports, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            die("process exited: " + tail(log_path))
        if all(port in listening_ports(ports) for port in ports):
            return
        time.sleep(0.05)
    die("process did not listen on " + ",".join(str(port) for port in ports) + ": " + tail(log_path))


def wait_quiet(ports, seconds=5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not listening_ports(ports):
            return
        time.sleep(0.05)


class QuietHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def _read(self):
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _send(self, status, body):
        raw = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def upstream_handler():
    class Upstream(QuietHandler):
        def do_GET(self):
            self._keep()
            self._send(200, b'{"Data":{"ProcessCode":"who-1"}}')

        def do_POST(self):
            self._keep(self._read())
            self._send(200, b'{"Data":{"ProcessCode":"ok-1"}}')

        def do_DELETE(self):
            self._keep()
            self._send(200, b'{"Data":{"ProcessCode":"ok-1"}}')

        def _keep(self, body=b""):
            values = []
            for key in self.headers:
                for value in self.headers.get_all(key) or []:
                    values.append(value)
            joined = "\n".join(values)
            item = {
                "method": self.command,
                "path": self.path.split("?", 1)[0],
                "authorization": self.headers.get("Authorization") or "",
                "account": self.headers.get("X-Provider-Account") or "",
                "jwt": TOKEN in joined or TOKEN.encode() in body,
            }
            with HIT_LOCK:
                HITS.append(item)
    return Upstream


def start_upstream():
    httpd = ThreadingHTTPServer((UPSTREAM_IP, UPSTREAM), upstream_handler())
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    SERVERS.append(httpd)


def stop_servers():
    for httpd in list(SERVERS):
        httpd.shutdown()
        httpd.server_close()
    SERVERS.clear()


def take_hits():
    with HIT_LOCK:
        items = list(HITS)
        HITS.clear()
        return items


def authz_argv(policy):
    pki = WORK / "pki"
    return [
        str(WORK / "gateway-authz"),
        "--listen", f"127.0.0.1:{AUTHZ}",
        "--tls-cert", str(pki / "authz.crt"),
        "--tls-key", str(pki / "authz.key"),
        "--client-ca", str(WORK / "tls" / "ca.crt"),
        "--policy", str(policy),
        "--developer-tokens", str(WORK / "secrets" / "tokens.json"),
        "--gateway-identity", GATEWAY_ID,
        "--revocations", str(WORK / "secrets" / "revocations.json"),
        "--revoker-identity", REVOKER_ID,
        "--publisher-identity", PUBLISHER_ID,
    ]


def fabric_argv(policy, bindings):
    pki = WORK / "pki"
    return [
        str(WORK / "gateway-fabric"),
        "--listen", f"127.0.0.1:{FABRIC}",
        "--tls-cert", str(pki / "fabric.crt"),
        "--tls-key", str(pki / "fabric.key"),
        "--client-ca", str(WORK / "tls" / "ca.crt"),
        "--fabric-identity", FABRIC_ID,
        "--target-id", TARGET,
        "--pool-base", str(WORK / "pool-base.json"),
        "--bindings", str(bindings),
        "--state-dir", str(WORK / "state"),
        "--agentgateway", str(BINARY),
        "--lock-file", str(LOCK),
        "--compile-tls-dir", str(WORK / "tls"),
        "--config-dir", str(WORK / "config"),
        "--config-name", "config.yaml",
        "--history-dir", str(WORK / "history"),
        "--read-back", f"127.0.0.1:{READBACK}",
        "--read-back-name", READBACK_NAME,
        "--publisher-cert", str(pki / "publisher.crt"),
        "--publisher-key", str(pki / "publisher.key"),
        "--publisher-ca", str(WORK / "tls" / "ca.crt"),
        "--authz-policy-file", str(policy),
        "--authz", f"127.0.0.1:{AUTHZ}",
        "--authz-name", AUTHZ_NAME,
        "--staging-image", IMAGE,
        "--staging-name", CONTAINER,
        "--staging-tls-dir", str(WORK / "tls"),
        "--staging-work-dir", str(WORK / "staging-work"),
        "--staging-publish", f"127.0.0.1:{STAGING_PUBLISH}",
        "--staging-container-port", str(READBACK),
    ]


def tls_conn(port, cert_name, server_name, timeout=20):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.load_verify_locations(cafile=str(WORK / "tls" / "ca.crt"))
    if cert_name:
        context.load_cert_chain(str(WORK / "pki" / f"{cert_name}.crt"), str(WORK / "pki" / f"{cert_name}.key"))
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        tls = context.wrap_socket(sock, server_hostname=server_name)
    except Exception:
        sock.close()
        raise
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    conn.sock = tls
    return conn


def read_response(conn):
    try:
        resp = conn.getresponse()
        raw = resp.read()
        headers = {name.lower(): value for name, value in resp.headers.items()}
        try:
            body = json.loads(raw.decode("utf-8")) if raw else {}
        except json.JSONDecodeError:
            body = {"_raw": raw.decode("utf-8", "replace")}
        return resp.status, body, headers, raw
    finally:
        try:
            conn.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
        except OSError:
            pass
        conn.close()


def fabric_request(method, path, body=None, cert="fabric-client", timeout=60):
    conn = tls_conn(FABRIC, cert, FABRIC_NAME, timeout=timeout)
    data = body if isinstance(body, bytes) else (body.encode("utf-8") if isinstance(body, str) else None)
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    try:
        conn.request(method, path, body=data, headers=headers)
        status, parsed, hdrs, raw = read_response(conn)
        return status, parsed, raw
    except Exception as exc:
        return None, {"_error": type(exc).__name__ + ": " + str(exc)}, b""


def authz_request(method, path, cert):
    conn = tls_conn(AUTHZ, cert, AUTHZ_NAME, timeout=5)
    try:
        conn.request(method, path, headers={"Accept": "application/json"})
        return read_response(conn)
    except Exception as exc:
        return None, {"_error": type(exc).__name__ + ": " + str(exc)}, {}, b""


def policy_version():
    status, body, _headers, _raw = authz_request("GET", "/v1/egress/policy-version", "publisher")
    if status != 200 or not isinstance(body, dict):
        return ""
    return body.get("policy_version") or ""


def config_bytes():
    return (WORK / "config" / "config.yaml").read_bytes()


def config_sha():
    return hashlib.sha256(config_bytes()).hexdigest()


def policy_sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_state():
    path = WORK / "state" / "state.json"
    if not path.exists():
        return {"generation": 0, "records": [], "idempotency": {}}
    return json.loads(path.read_text(encoding="utf-8"))


def envelope(route, generation, key, release, approval=None, **overrides):
    intent = {
        "intent_id": route["intent_id"],
        "gateway_pool": "egress-test",
        "traffic_class": "EGRESS",
        "environment": "TEST",
        "provider_id": "wanbexpress",
        "operation_id": route["operation_id"],
        "logical_path": route["logical_path"],
        "allowed_methods": [route["method"]],
        "upstream_hostname": UPSTREAM_NAME,
        "upstream_port": UPSTREAM,
        "upstream_sni": UPSTREAM_NAME,
        "authz_profile": route["authz_profile"],
        "approval_ref": approval or route["approval_ref"],
        "expected_generation": generation,
        "contract_ref": "consumer-api-wanbexpress-v1",
        "credential_binding_ref": BINDING_REF,
        "redirect_policy": "DENY",
        "upstream_tls": route["upstream_tls"],
        "provider_account_strategy": "GATEKEEPER_DECISION_BINDING",
        "transport": "HTTP",
        "policy_bundle_ref": route["policy_bundle_ref"],
    }
    intent.update(overrides)
    return {
        "idempotency_key": key,
        "release_ref": release,
        "target_id": TARGET,
        "intent": intent,
    }


def reorder(value):
    if isinstance(value, dict):
        return {key: reorder(value[key]) for key in reversed(list(value))}
    if isinstance(value, list):
        return [reorder(item) for item in value]
    return value


def post_json(document):
    raw = json.dumps(document, separators=(",", ":")).encode("utf-8")
    return fabric_request("POST", "/v1/route-intents", raw)


def post_raw(raw):
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    return fabric_request("POST", "/v1/route-intents", raw)


def wait_state(intent_id, seconds=50):
    deadline = time.monotonic() + seconds
    last = (None, {})
    while time.monotonic() < deadline:
        status, body, _raw = fabric_request("GET", f"/v1/route-intents/{intent_id}/status", timeout=10)
        last = (status, body if isinstance(body, dict) else {})
        if status == 200 and body.get("state") in TERMINAL:
            return status, body
        time.sleep(0.2)
    return last


def gateway_call(method, path, body=None):
    take_hits()
    headers = {
        "Host": CALLER_HOST,
        "Accept": "application/json",
        "Authorization": "Bearer " + TOKEN,
        "X-Provider-Account": "account-blue",
    }
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        headers["Content-Type"] = "application/json"
    conn = http.client.HTTPConnection("127.0.0.1", LISTEN, timeout=8)
    try:
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        return {"status": resp.status, "body": raw[:300].decode("utf-8", "replace"), "hits": take_hits()}
    except Exception as exc:
        return {"status": None, "error": type(exc).__name__ + ": " + str(exc), "body": "", "hits": take_hits()}
    finally:
        conn.close()


def credential_ok(hit):
    auth = hit.get("authorization") or ""
    return (
        auth.startswith("Hc-OweDeveloper ")
        and DEV_TOKEN in auth
        and not hit.get("jwt")
        and TOKEN not in auth
        and not hit.get("account")
    )


def control_line(argv):
    proc = subprocess.run(argv, cwd=WORK, env=go_env(), capture_output=True, text=True)
    parsed = {}
    if proc.stdout.strip():
        try:
            parsed = json.loads(proc.stdout)
        except json.JSONDecodeError:
            parsed = {"_raw": proc.stdout[-300:]}
    return proc.returncode, parsed, (proc.stderr or "")[-300:]


def authz_admin(command, **extra):
    pki = WORK / "pki"
    argv = [
        str(WORK / "gateway-control"), command,
        "--authz", f"127.0.0.1:{AUTHZ}",
        "--authz-name", AUTHZ_NAME,
        "--tls-cert", str(pki / "revoker.crt"),
        "--tls-key", str(pki / "revoker.key"),
        "--tls-ca", str(WORK / "tls" / "ca.crt"),
    ]
    for key, value in extra.items():
        argv.extend(["--" + key.replace("_", "-"), value])
    return control_line(argv)


def no_address_clash(results):
    blob = tail(WORK / "fabric.log") + "\n" + tail(WORK / "gateway.log")
    results.check(
        "neither log says address already in use",
        "address already in use" not in blob.lower(),
    )


def run_suite(results, spec):
    parcels = route_named(spec, "parcels.create", "POST")
    whoami = route_named(spec, "whoami.get", "GET")
    parcels_get = route_named(spec, "parcels.get", "GET")
    version_before = policy_version()
    gw_pid = PROCS[1][0].pid if len(PROCS) > 1 else None
    authz_pid = PROCS[0][0].pid

    results.case("FB-01", "first publication reaches ACTIVE and the new route is reloaded")
    before = gateway_call("POST", "/providers/wanbexpress/v1/parcels", b'{"ReferenceId":"parcel-1"}')
    who_before = gateway_call("GET", "/providers/wanbexpress/v1/whoami")
    results.check("parcels is refused before publication", before["status"] in (404, 403))
    results.check("the initial whoami route is open", who_before["status"] == 200)
    results.note("before", {"parcels": before["status"], "whoami": who_before["status"]})
    body = envelope(parcels, 0, "fabric-parcels-create-0001", "fabric-release:parcels/0001")
    blocked_body = envelope(whoami, 0, "fabric-whoami-blocked-0001", "fabric-release:whoami/blocked")
    status, accepted, _raw = post_json(body)
    busy_status, busy_body, _raw = post_json(blocked_body)
    results.check("POST returns 202", status == 202)
    results.check(
        "202 body is intent_id, release_ref, and DRAFT",
        isinstance(accepted, dict)
        and accepted.get("intent_id") == parcels["intent_id"]
        and accepted.get("release_ref") == "fabric-release:parcels/0001"
        and accepted.get("state") == "DRAFT"
        and set(accepted) == {"intent_id", "release_ref", "state"},
    )
    results.check(
        "a second key is 409 while the first publication is open",
        busy_status == 409 and isinstance(busy_body, dict) and busy_body.get("reason") == "publish_in_progress",
    )
    results.note("busy", {"status": busy_status, "body": busy_body})
    got, view = wait_state(parcels["intent_id"])
    results.check("GET status is 200", got == 200)
    results.check("state is ACTIVE", isinstance(view, dict) and view.get("state") == "ACTIVE")
    results.check(
        "desired_digest equals observed_digest and both are set",
        isinstance(view, dict) and view.get("desired_digest") and view.get("desired_digest") == view.get("observed_digest"),
    )
    after = gateway_call("POST", "/providers/wanbexpress/v1/parcels", b'{"ReferenceId":"parcel-1"}')
    hit = after["hits"][0] if len(after["hits"]) == 1 else {}
    results.check("the published route returns 200", after["status"] == 200)
    results.check("the stand-in saw one request", len(after["hits"]) == 1)
    results.check("the stand-in saw Hc-OweDeveloper and not the caller JWT", credential_ok(hit))
    version_after = policy_version()
    results.check(
        "policy_version advanced without restarting gateway-authz",
        version_after.startswith("wanbexpress-fabric-g0-") and version_after != version_before,
    )
    results.check("the gateway process is the same one", gateway_pid() == gw_pid)
    results.check("gateway-authz is the same process", authz_proc().pid == authz_pid and authz_proc().poll() is None)
    state = load_state()
    results.check("the pool generation is 1", state.get("generation") == 1)
    results.check("the blocked key was not stored", "fabric-whoami-blocked-0001" not in state.get("idempotency", {}))
    no_address_clash(results)
    if after["status"] != 200 or view.get("state") != "ACTIVE":
        results.note("status", view)
        results.note("call", after)
        results.note("fabric_log", tail(WORK / "fabric.log"))
        results.note("gateway_log", tail(WORK / "gateway.log"))
        results.note("authz_log", tail(WORK / "authz.log"))
    if results.failed():
        return

    results.case("FB-02", "replay, same-key conflict, and a stale generation that does not consume the key")
    sha_before = config_sha()
    pol_before = policy_sha(WORK / "policy.json")
    replay, replay_body, _raw = post_json(reorder(body))
    results.check("reordered JSON replays 202", replay == 202)
    results.check(
        "the replay body matches the first 202, including DRAFT",
        replay_body == accepted,
    )
    got, view = fabric_request("GET", f"/v1/route-intents/{parcels['intent_id']}/status")[:2]
    results.check("GET still reports ACTIVE", got == 200 and view.get("state") == "ACTIVE")
    conflict = envelope(parcels, 0, "fabric-parcels-create-0001", "fabric-release:parcels/0001", approval="APPROVAL-SANDBOX-009")
    conflict_status, conflict_body, _raw = post_json(conflict)
    results.check(
        "the same key with a different approval_ref is 409",
        conflict_status == 409 and conflict_body.get("reason") == "idempotency_key_reused",
    )
    stale = envelope(whoami, 0, "fabric-whoami-stale-0001", "fabric-release:whoami/0001")
    stale_status, stale_body, _raw = post_json(stale)
    results.check(
        "expected_generation 0 is 409 once the pool is at 1",
        stale_status == 409 and stale_body.get("reason") == "generation_conflict",
    )
    state = load_state()
    results.check("generation is still 1", state.get("generation") == 1)
    results.check("the stale key was not stored", "fabric-whoami-stale-0001" not in state.get("idempotency", {}))
    results.check("the pool snapshot and policy file are unchanged", config_sha() == sha_before and policy_sha(WORK / "policy.json") == pol_before)
    fresh = envelope(whoami, 1, "fabric-whoami-stale-0001", "fabric-release:whoami/0001")
    fresh_status, fresh_body, _raw = post_json(fresh)
    results.check(
        "the same new key is accepted at generation 1",
        fresh_status == 202
        and fresh_body.get("intent_id") == whoami["intent_id"]
        and fresh_body.get("release_ref") == "fabric-release:whoami/0001"
        and fresh_body.get("state") == "DRAFT",
    )
    if results.failed():
        results.note("replay", replay_body)
        results.note("conflict", conflict_body)
        results.note("stale", stale_body)
        return

    results.case("FB-03", "the second route stays ACTIVE beside the first, then an update supersedes")
    got, view = wait_state(whoami["intent_id"])
    results.check("whoami reaches ACTIVE", got == 200 and view.get("state") == "ACTIVE")
    results.check(
        "whoami digests match",
        view.get("desired_digest") and view.get("desired_digest") == view.get("observed_digest"),
    )
    got_p, view_p = fabric_request("GET", f"/v1/route-intents/{parcels['intent_id']}/status")[:2]
    results.check("parcels is still ACTIVE", got_p == 200 and view_p.get("state") == "ACTIVE")
    both_parcels = gateway_call("POST", "/providers/wanbexpress/v1/parcels", b'{"ReferenceId":"parcel-2"}')
    both_who = gateway_call("GET", "/providers/wanbexpress/v1/whoami")
    results.check("parcels still returns 200", both_parcels["status"] == 200 and credential_ok(both_parcels["hits"][0] if both_parcels["hits"] else {}))
    results.check("whoami returns 200 on the second route", both_who["status"] == 200)
    results.check("generation is 2", load_state().get("generation") == 2)
    updated = envelope(
        parcels, 2, "fabric-parcels-update-0002", "fabric-release:parcels/0002", approval="APPROVAL-SANDBOX-002",
    )
    upd_status, upd_body, _raw = post_json(updated)
    results.check("the update is accepted", upd_status == 202 and upd_body.get("state") == "DRAFT")
    got_u, view_u = wait_state(parcels["intent_id"])
    results.check("the new parcels version is ACTIVE", got_u == 200 and view_u.get("state") == "ACTIVE")
    records = [item for item in load_state().get("records", []) if item.get("intent_id") == parcels["intent_id"]]
    states = {item.get("state") for item in records}
    who_records = [item for item in load_state().get("records", []) if item.get("intent_id") == whoami["intent_id"]]
    results.check("the previous parcels record is SUPERSEDED", "SUPERSEDED" in states and "ACTIVE" in states)
    results.check("whoami's record is still ACTIVE", any(item.get("state") == "ACTIVE" for item in who_records))
    results.check("generation is 3", load_state().get("generation") == 3)
    still_who = gateway_call("GET", "/providers/wanbexpress/v1/whoami")
    still_parcels = gateway_call("POST", "/providers/wanbexpress/v1/parcels", b'{"ReferenceId":"parcel-3"}')
    results.check("whoami still returns 200 after the supersede", still_who["status"] == 200)
    results.check("parcels still returns 200 after the supersede", still_parcels["status"] == 200)
    if view.get("state") != "ACTIVE" or view_u.get("state") != "ACTIVE":
        results.note("whoami_status", view)
        results.note("update_status", view_u)
        results.note("fabric_log", tail(WORK / "fabric.log"))
    if results.failed():
        return

    results.case("FB-04", "synchronous 422 leaves the pool, the policy file, and the generation alone")
    sha_before = config_sha()
    pol_before = policy_sha(WORK / "policy.json")
    gen_before = load_state().get("generation")
    keys_before = set(load_state().get("idempotency", {}))
    base = envelope(parcels, gen_before, "fabric-reject-placeholder-0001", "fabric-release:reject/0001")
    samples = []

    unknown = copy.deepcopy(base)
    unknown["idempotency_key"] = "fabric-reject-unknown-0001"
    unknown["unexpected"] = "no"
    samples.append(("unknown field", unknown, None))

    dup_doc = json.dumps(
        envelope(parcels, gen_before, "fabric-reject-duplicate-0001", "fabric-release:reject/0002"),
        separators=(",", ":"),
    )
    dup = '{"idempotency_key":"fabric-reject-duplicate-0001",' + dup_doc[1:]
    samples.append(("duplicate key", None, dup))

    for secret_name, secret_key in (("api_key", "fabric-reject-apikey-0001"), ("client_secret", "fabric-reject-secret-0001")):
        secret = copy.deepcopy(base)
        secret["idempotency_key"] = secret_key
        secret["intent"] = dict(secret["intent"])
        secret["intent"][secret_name] = "sekret-value"
        samples.append((secret_name, secret, None))

    envref = copy.deepcopy(base)
    envref["idempotency_key"] = "fabric-reject-envref-0001"
    envref["intent"] = dict(envref["intent"])
    envref["intent"]["approval_ref"] = "APPROVAL-${SECRET_VAR}"
    samples.append(("environment reference", envref, None))

    prod = copy.deepcopy(base)
    prod["idempotency_key"] = "fabric-reject-prodhttp-0001"
    prod["intent"] = dict(prod["intent"])
    prod["intent"]["environment"] = "PROD"
    prod["intent"]["gateway_pool"] = "egress-prod"
    prod["intent"]["upstream_tls"] = "PLAIN_HTTP_SANDBOX_EXCEPTION"
    samples.append(("PROD plain HTTP", prod, None))

    missing = copy.deepcopy(base)
    missing["idempotency_key"] = "fabric-reject-missing-0001"
    missing["intent"] = dict(missing["intent"])
    missing["intent"]["operation_id"] = "missing.op"
    missing["intent"]["logical_path"] = "/providers/wanbexpress/v1/missing"
    samples.append(("unknown operation", missing, None))

    foreign = copy.deepcopy(base)
    foreign["idempotency_key"] = "fabric-reject-host-0001"
    foreign["intent"] = dict(foreign["intent"])
    foreign["intent"]["upstream_hostname"] = "not-the-upstream.example"
    foreign["intent"]["upstream_sni"] = "not-the-upstream.example"
    samples.append(("unknown upstream", foreign, None))

    methods = copy.deepcopy(base)
    methods["idempotency_key"] = "fabric-reject-methods-0001"
    methods["intent"] = dict(methods["intent"])
    methods["intent"]["allowed_methods"] = ["POST", "GET"]
    samples.append(("two methods", methods, None))

    target = copy.deepcopy(base)
    target["idempotency_key"] = "fabric-reject-target-0001"
    target["target_id"] = "fabric-target:somewhere-else"
    samples.append(("target_id", target, None))

    pool = copy.deepcopy(base)
    pool["idempotency_key"] = "fabric-reject-pool-0001"
    pool["intent"] = dict(pool["intent"])
    pool["intent"]["gateway_pool"] = "egress-test-other"
    samples.append(("gateway_pool", pool, None))

    binding = copy.deepcopy(base)
    binding["idempotency_key"] = "fabric-reject-binding-0001"
    binding["intent"] = dict(binding["intent"])
    binding["intent"]["credential_binding_ref"] = "gatekeeper:not-registered"
    samples.append(("unknown binding", binding, None))

    for label, document, raw in samples:
        if raw is None:
            got, parsed, _raw = post_json(document)
        else:
            got, parsed, _raw = post_raw(raw)
        results.check(f"{label} is 422", got == 422)
        if got != 422:
            results.note(label, {"status": got, "body": parsed})
    state = load_state()
    results.check("generation is unchanged", state.get("generation") == gen_before)
    results.check("the snapshot is unchanged", config_sha() == sha_before)
    results.check("the policy file is unchanged", policy_sha(WORK / "policy.json") == pol_before)
    results.check("no 422 key was stored", set(state.get("idempotency", {})) == keys_before)
    if results.failed():
        return

    results.case("FB-05", "mTLS identity and request hygiene")
    results.check("a client without a certificate fails the handshake", client_without_certificate_fails())
    foreign_post, foreign_body, _raw = fabric_request("POST", "/v1/route-intents", b"{}", cert="other")
    foreign_get, foreign_get_body, _raw = fabric_request(
        "GET", f"/v1/route-intents/{parcels['intent_id']}/status", cert="other",
    )
    results.check("POST with the wrong SPIFFE URI is 401", foreign_post == 401)
    results.check("GET with the wrong SPIFFE URI is 401", foreign_get == 401)
    results.check(
        "401 bodies do not echo the route",
        parcels["intent_id"] not in json.dumps(foreign_body) and parcels["intent_id"] not in json.dumps(foreign_get_body),
    )
    two_host = two_host_request()
    results.check("two Host headers are 400", two_host["status"] == 400)
    missing_id = "gwi-not-a-real-intent"
    missing_status, missing_body, missing_raw = fabric_request("GET", f"/v1/route-intents/{missing_id}/status")
    results.check("an unknown intent_id is 404", missing_status == 404)
    results.check("the 404 body does not echo the path", missing_id.encode() not in missing_raw)
    check_status, _check_body, check_headers, _raw = authz_request("POST", "/v1/extauthz/check", "publisher")
    rev_status, _rev_body, rev_headers, _raw = authz_request("GET", "/v1/egress/revocations", "publisher")
    results.check("the publisher certificate cannot call extauthz", check_status == 401)
    results.check("the publisher certificate cannot call revocations", rev_status == 401)
    results.check(
        "those 401 responses have no Authorization header",
        "authorization" not in check_headers and "authorization" not in rev_headers,
    )
    if two_host["status"] != 400:
        results.note("two_host", two_host)
    if results.failed():
        return

    results.case("FB-06", "revoke and ban take effect without a fabric publication")
    gen_before = load_state().get("generation")
    sha_before = config_sha()
    code, report, err = authz_admin("revoke", account="account-blue", reason="fabric-suite")
    denied = gateway_call("POST", "/providers/wanbexpress/v1/parcels", b'{"ReferenceId":"parcel-4"}')
    results.check("revoke exits 0", code == 0 and report.get("outcome") == "REVOKED")
    results.check("the next parcels request is 403", denied["status"] == 403)
    code, report, err = authz_admin("restore", account="account-blue")
    restored = gateway_call("POST", "/providers/wanbexpress/v1/parcels", b'{"ReferenceId":"parcel-5"}')
    results.check("restore exits 0", code == 0 and report.get("outcome") == "LIFTED")
    results.check("the next parcels request is 200", restored["status"] == 200)
    code, report, err = authz_admin("ban", operation="parcels.create", reason="fabric-suite")
    banned = gateway_call("POST", "/providers/wanbexpress/v1/parcels", b'{"ReferenceId":"parcel-6"}')
    who_open = gateway_call("GET", "/providers/wanbexpress/v1/whoami")
    results.check("ban exits 0", code == 0 and report.get("outcome") == "BANNED")
    results.check("the banned operation is 403", banned["status"] == 403)
    results.check("whoami is not banned", who_open["status"] == 200)
    code, report, err = authz_admin("unban", operation="parcels.create")
    opened = gateway_call("POST", "/providers/wanbexpress/v1/parcels", b'{"ReferenceId":"parcel-7"}')
    results.check("unban exits 0", code == 0 and report.get("outcome") == "LIFTED")
    results.check("parcels is 200 after unban", opened["status"] == 200)
    results.check("revoke and ban did not publish", load_state().get("generation") == gen_before and config_sha() == sha_before)
    if denied["status"] != 403 or restored["status"] != 200 or opened["status"] != 200:
        results.note("revoke_err", err)
        results.note("denied", denied["status"])
        results.note("restored", restored["status"])
        results.note("opened", opened["status"])
    if results.failed():
        return

    results.case("FB-07", "a damaged policy file does not replace the loaded registry")
    good = (WORK / "policy.json").read_bytes()
    version_good = policy_version()
    atomic_replace(WORK / "policy.json", b"{")
    time.sleep(0.3)
    kept = gateway_call("POST", "/providers/wanbexpress/v1/parcels", b'{"ReferenceId":"parcel-8"}')
    version_kept = policy_version()
    results.check("a valid request stays 200 on the previous registry", kept["status"] == 200)
    results.check("policy_version stays the previous value", version_kept == version_good and version_kept != "")
    atomic_replace(WORK / "policy.json", good)
    time.sleep(0.3)
    back = gateway_call("POST", "/providers/wanbexpress/v1/parcels", b'{"ReferenceId":"parcel-9"}')
    results.check("restoring the policy file keeps the route at 200", back["status"] == 200)
    results.check("policy_version is the restored value", policy_version() == version_good)
    if kept["status"] != 200:
        results.note("kept", kept)
        results.note("authz_log", tail(WORK / "authz.log"))
    if results.failed():
        return

    results.case("FB-08", "a read-back miss becomes UNKNOWN, then reconcile converges")
    sha_before = config_sha()
    version_before = policy_version()
    drift = envelope(parcels_get, load_state().get("generation"), "fabric-drift-parcels-get-0001", "fabric-release:drift/0001")
    started, started_body, _raw = post_json(drift)
    results.check("the drift publication is accepted", started == 202 and started_body.get("state") == "DRAFT")
    killed = False
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline and not killed:
        if config_sha() != sha_before:
            stop_proc(gateway_proc(), kill=True)
            killed = True
            break
        time.sleep(0.05)
    results.check("the new snapshot was written before the gateway was stopped", killed)
    got, view = wait_state(parcels_get["intent_id"], seconds=45)
    results.check("status is UNKNOWN", got == 200 and view.get("state") == "UNKNOWN")
    results.check("UNKNOWN is not reported as ACTIVE or FAILED", view.get("state") == "UNKNOWN")
    results.check(
        "the fabric record does not say OVERTAKEN",
        all(item.get("state") != "OVERTAKEN" for item in load_state().get("records", [])),
    )
    if view.get("state") != "UNKNOWN":
        results.note("drift_status", view)
        results.note("fabric_log", tail(WORK / "fabric.log"))
        results.note("gateway_log", tail(WORK / "gateway.log"))
        return
    start_gateway()
    wait_listen(gateway_proc(), WORK / "gateway.log", (LISTEN, READBACK), seconds=15)
    restart_fabric()
    got, view = wait_state(parcels_get["intent_id"], seconds=30)
    recovered = gateway_call("POST", "/providers/wanbexpress/v1/parcels", b'{"ReferenceId":"parcel-10"}')
    hidden = gateway_call("GET", "/providers/wanbexpress/v1/parcels/ABC123")
    results.check("reconcile finishes as FAILED", got == 200 and view.get("state") == "FAILED")
    results.check("the previous route returns 200 after reconcile", recovered["status"] == 200)
    results.check("the drifted route is not left exposed", hidden["status"] in (404, 403))
    results.check("policy_version is back to the previous registry", policy_version() == version_before)
    results.check("OVERTAKEN is still not a fabric state", view.get("state") != "OVERTAKEN")
    if view.get("state") != "FAILED" or recovered["status"] != 200:
        results.note("after", view)
        results.note("recovered", recovered["status"])
        results.note("hidden", hidden["status"])
        results.note("fabric_log", tail(WORK / "fabric.log"))
        results.note("gateway_log", tail(WORK / "gateway.log"))


def gateway_pid():
    proc = gateway_proc()
    return proc.pid if proc is not None and proc.poll() is None else None


def gateway_proc():
    for proc, _handle, log_path in PROCS:
        if log_path.name == "gateway.log" and proc.poll() is None:
            return proc
    return None


def authz_proc():
    for proc, _handle, log_path in PROCS:
        if log_path.name == "authz.log" and proc.poll() is None:
            return proc
    return None


def fabric_proc():
    for proc, _handle, log_path in PROCS:
        if log_path.name == "fabric.log" and proc.poll() is None:
            return proc
    return None


def atomic_replace(path, content):
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(content)
    os.replace(tmp, path)


def client_without_certificate_fails():
    # TLS 1.3 can return from wrap_socket before the server's certificate alert is visible.
    # A following read or write is what surfaces "client didn't provide a certificate".
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.load_verify_locations(cafile=str(WORK / "tls" / "ca.crt"))
    sock = socket.create_connection(("127.0.0.1", FABRIC), timeout=5)
    try:
        tls = context.wrap_socket(sock, server_hostname=FABRIC_NAME)
        tls.sendall(
            b"GET /v1/route-intents/gwi-none/status HTTP/1.1\r\nHost: fabric.idp.test\r\nConnection: close\r\n\r\n"
        )
        data = tls.recv(256)
        return not data.startswith(b"HTTP/")
    except (ssl.SSLError, OSError, ConnectionError):
        return True
    finally:
        try:
            sock.close()
        except OSError:
            pass


def two_host_request():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.load_verify_locations(cafile=str(WORK / "tls" / "ca.crt"))
    context.load_cert_chain(str(WORK / "pki" / "fabric-client.crt"), str(WORK / "pki" / "fabric-client.key"))
    sock = socket.create_connection(("127.0.0.1", FABRIC), timeout=5)
    try:
        tls = context.wrap_socket(sock, server_hostname=FABRIC_NAME)
        raw = (
            "POST /v1/route-intents HTTP/1.1\r\n"
            "Host: fabric.idp.test\r\n"
            "Host: other.example\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        tls.sendall(raw.encode("ascii"))
        data = b""
        while True:
            chunk = tls.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                break
        line = data.split(b"\r\n", 1)[0].decode("latin1", "replace")
        status = None
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
        return {"status": status, "line": line}
    except Exception as exc:
        return {"status": None, "error": type(exc).__name__ + ": " + str(exc)}
    finally:
        try:
            sock.close()
        except OSError:
            pass


def retire(log_name):
    kept = []
    for proc, handle, log_path in PROCS:
        if log_path.name == log_name:
            stop_proc(proc, kill=True)
            handle.close()
        else:
            kept.append((proc, handle, log_path))
    PROCS[:] = kept


def start_gateway():
    retire("gateway.log")
    proc, _log = spawn([str(BINARY), "-f", "config/config.yaml"], "gateway.log", gateway_env())
    return proc


def start_fabric(policy, bindings):
    proc, _log = spawn(fabric_argv(policy, bindings), "fabric.log")
    return proc


def restart_fabric():
    retire("fabric.log")
    wait_quiet((FABRIC,), seconds=5)
    proc, log_path = spawn(fabric_argv(WORK / "policy.json", WORK / "bindings.json"), "fabric.log")
    wait_listen(proc, log_path, (FABRIC,), seconds=15)


def boot(authz_policy, fabric_policy, bindings):
    authz, authz_log = spawn(authz_argv(authz_policy), "authz.log")
    wait_listen(authz, authz_log, (AUTHZ,), seconds=15)
    gateway = start_gateway()
    wait_listen(gateway, WORK / "gateway.log", (LISTEN, READBACK, ADMIN), seconds=15)
    fabric = start_fabric(fabric_policy, bindings)
    wait_listen(fabric, WORK / "fabric.log", (FABRIC,), seconds=15)


def run_control_skip(results):
    results.case("control-skip-authz-reload", "FB-01 must fail when gateway-authz keeps the old policy file")
    spec = json.loads((WORK / "pool-base.json").read_text(encoding="utf-8"))
    parcels = route_named(spec, "parcels.create", "POST")
    sha_before = config_sha()
    body = envelope(parcels, 0, "fabric-parcels-create-0001", "fabric-release:parcels/0001")
    status, accepted, _raw = post_json(body)
    results.check("the intent is still accepted for asynchronous publication", status == 202 and accepted.get("state") == "DRAFT")
    got, view = wait_state(parcels["intent_id"], seconds=40)
    call = gateway_call("POST", "/providers/wanbexpress/v1/parcels", b'{"ReferenceId":"parcel-1"}')
    results.check("the publication does not become ACTIVE", view.get("state") != "ACTIVE")
    results.check("parcels is not 200", call["status"] != 200)
    results.check("the pool snapshot was not replaced", config_sha() == sha_before)
    results.check("generation is still 0", load_state().get("generation") == 0)
    results.note("state", view.get("state"))
    results.note("call", call.get("status"))
    if view.get("state") == "ACTIVE" or call["status"] == 200:
        results.note("fabric_log", tail(WORK / "fabric.log"))


def run_control_binding(results):
    results.case("control-bad-binding", "FB-01 must fail when the binding scheme is OAUTH2_AUTHORIZATION_CODE")
    spec = json.loads((WORK / "pool-base.json").read_text(encoding="utf-8"))
    parcels = route_named(spec, "parcels.create", "POST")
    sha_before = config_sha()
    pol_before = policy_sha(WORK / "policy.json")
    body = envelope(parcels, 0, "fabric-parcels-create-0001", "fabric-release:parcels/0001")
    status, accepted, _raw = post_json(body)
    call = gateway_call("POST", "/providers/wanbexpress/v1/parcels", b'{"ReferenceId":"parcel-1"}')
    results.check("the publication is refused with 422", status == 422)
    results.check("no 202 is returned", status != 202)
    results.check("parcels is not opened", call["status"] != 200)
    results.check("the snapshot is unchanged", config_sha() == sha_before)
    results.check("the policy file is unchanged", policy_sha(WORK / "policy.json") == pol_before)
    results.check("generation is still 0", load_state().get("generation") == 0)
    results.note("status", status)
    results.note("body", accepted)
    results.note("call", call.get("status"))


def prepare():
    global WORK, UPSTREAM_NAME, UPSTREAM_IP
    scrub_proxy()
    sweep_suite_processes()
    time.sleep(0.2)
    for leftover in Path("/tmp").glob("idp-gateway-fabric-*"):
        shutil.rmtree(leftover, ignore_errors=True)
    ensure_free(PORTS)
    got = check_binary()
    say("agentgateway sha256 " + got)
    image_present()
    say("staging image " + IMAGE)
    remove_fabric_containers()
    UPSTREAM_NAME, UPSTREAM_IP = loopback_name()
    say(f"upstream {UPSTREAM_NAME} -> {UPSTREAM_IP}:{UPSTREAM}")
    WORK = Path(tempfile.mkdtemp(prefix="idp-gateway-fabric-"))
    (WORK / "config").mkdir(mode=0o755)
    mkdir0700(WORK / "state")
    mkdir0700(WORK / "history")
    (WORK / "staging-work").mkdir(mode=0o700)
    issue_material()
    write_specs()
    build("./cmd/gateway-control", WORK / "gateway-control")
    build("./cmd/gateway-authz", WORK / "gateway-authz")
    build("./cmd/gateway-fabric", WORK / "gateway-fabric")
    compile_initial()
    start_upstream()


def cleanup():
    global CLEANED
    if CLEANED:
        return
    CLEANED = True
    stop_procs()
    sweep_suite_processes()
    stop_servers()
    remove_fabric_containers()
    if WORK is not None:
        shutil.rmtree(WORK, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Fabric publication loopback evidence. Not an acceptance pass.")
    parser.add_argument(
        "--control",
        choices=("skip-authz-reload", "bad-binding"),
        help="negative control; not part of the default run",
    )
    args = parser.parse_args()
    atexit.register(cleanup)
    say("fabric loopback suite; not an acceptance pass")
    results = Results()
    try:
        prepare()
        if args.control == "skip-authz-reload":
            boot(WORK / "policy-frozen.json", WORK / "policy-live.json", WORK / "bindings.json")
            run_control_skip(results)
        elif args.control == "bad-binding":
            boot(WORK / "policy.json", WORK / "policy.json", WORK / "bindings-bad.json")
            run_control_binding(results)
        else:
            boot(WORK / "policy.json", WORK / "policy.json", WORK / "bindings.json")
            run_suite(results, json.loads((WORK / "pool-base.json").read_text(encoding="utf-8")))
            results.case("cleanup", "no fabric container and no listen port left by the suite")
            # Containers are removed in cleanup(), after this check sees the steady state.
            left = fabric_containers()
            results.check("no idp-gateway-fabric container is left", left == [])
            if left:
                results.note("containers", left)
        if results.failed():
            say("fabric log: " + tail(WORK / "fabric.log"))
            say("gateway log: " + tail(WORK / "gateway.log"))
            say("authz log: " + tail(WORK / "authz.log"))
        passed, total = results.report()
        if results.failed():
            raise SystemExit(1)
        say(f"passed {passed}/{total}")
    finally:
        cleanup()
        still = listening_ports(PORTS)
        containers = []
        try:
            containers = fabric_containers()
        except Exception:
            containers = ["docker-query-failed"]
        if still or containers:
            say("leftover ports " + ",".join(str(port) for port in still))
            say("leftover containers " + ",".join(containers))
            raise SystemExit(1)


if __name__ == "__main__":
    main()
