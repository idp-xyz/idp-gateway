"""Loopback evidence that pool.tracing compiles and the locked data plane synthesizes a trace.

This is not an acceptance pass. It does not approve an SLO.

    /home/tops/workspace/idp-gateway/.venv/bin/python tests/integration/observability/run.py
    /home/tops/workspace/idp-gateway/.venv/bin/python tests/integration/observability/run.py --control drop-tracing

The default run is cases A-D plus one gateway-authz check. --control drop-tracing is not
part of that run: it deletes the tracing block from an otherwise identical compiled file
and expects case A to fail. Ports are 27701-27709 only.
"""
import argparse
import base64
import datetime
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import struct
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
BINARY = Path.home() / ".local/opt/agentgateway/1.7.0/agentgateway"
EXPECTED_SHA = "c7ef326b7b5702451e94bab55ff484d600d5abdc5344a4cdf7c72fc0bcff9e24"

LISTEN, STATS, READY, READBACK = 27701, 27702, 27703, 27704
UPSTREAM, COLLECTOR = 27705, 27706
ADMIN_ON, ADMIN_OFF, AUTHZ_METRICS = 27707, 27708, 27709
PORTS = (LISTEN, STATS, READY, READBACK, UPSTREAM, COLLECTOR, ADMIN_ON, ADMIN_OFF, AUTHZ_METRICS)

PUBLIC = "probe.example"
ISSUER = "https://issuer.example/obs"
AUDIENCE = "idp-observability"
PUBLISHER = "spiffe://idp.test/gateway-control/publisher"
GATEWAY_ID = "spiffe://idp.test/egress/agentgateway"
AUTHZ_NAME = "authz.idp.test"
TRACEPARENT_RE = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")
SENT_TRACE = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

WORK = None
TOKEN = ""
SESSION_KEYS = []
CREDENTIAL = ""
UPSTREAM_HITS = []
COLLECTOR_HITS = []
LOCKS = {"up": threading.Lock(), "col": threading.Lock()}
SERVERS = []
PROCS = []


class Results:
    def __init__(self):
        self.cases = []
        self.current = None

    def case(self, case_id, title):
        self.current = {"id": case_id, "title": title, "checks": [], "notes": []}
        self.cases.append(self.current)
        return self.current

    def check(self, text, ok):
        self.current["checks"].append({"check": text, "ok": bool(ok)})
        return bool(ok)

    def note(self, text, value):
        self.current["notes"].append({"note": text, "value": value})

    def failed(self):
        return [case for case in self.cases if any(not item["ok"] for item in case["checks"])]

    def report(self):
        for case in self.cases:
            bad = [item["check"] for item in case["checks"] if not item["ok"]]
            passed = sum(item["ok"] for item in case["checks"])
            say(f"{case['id']} {'FAIL' if bad else 'pass'}  {passed}/{len(case['checks'])}  {case['title']}")
            for item in case["notes"]:
                say("    " + item["note"] + ": " + clip(item["value"]))
            for item in bad:
                say("    not met: " + item)


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
    for secret in (TOKEN, CREDENTIAL, *SESSION_KEYS):
        if secret:
            text = text.replace(secret, "[redacted]")
    return text


def go_env():
    env = {key: value for key, value in os.environ.items() if "proxy" not in key.lower()}
    env["PATH"] = "/usr/local/go/bin:" + env.get("PATH", "")
    env["CGO_ENABLED"] = "0"
    return env


def gateway_env():
    env = go_env()
    key = os.urandom(32).hex()
    SESSION_KEYS.append(key)
    env["SESSION_KEY"] = key
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
    want = list(lock.get("sha256", {}).values())
    if got not in want:
        die(f"agentgateway sha256 {got} does not match the lock file")
    if got != EXPECTED_SHA:
        die(f"agentgateway sha256 {got} is not the measured 1.7.0 binary")
    return got


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


def make_leaf(ca_key, ca_cert, common_name, eku, dns=(), ips=(), uris=()):
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
    names += [x509.IPAddress(ipaddress.ip_address(item)) for item in ips]
    names += [x509.UniformResourceIdentifier(item) for item in uris]
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    return key, builder.sign(ca_key, hashes.SHA256())


def b64_coord(number):
    return base64.urlsafe_b64encode(number.to_bytes(32, "big")).rstrip(b"=").decode()


def issue_gateway_material():
    global TOKEN
    tls = WORK / "tls"
    tls.mkdir()
    ca_key, ca_cert = make_ca("obs-ca")
    write_cert(tls / "ca.crt", ca_cert)
    key, cert = make_leaf(
        ca_key, ca_cert, "readback", ExtendedKeyUsageOID.SERVER_AUTH, ips=("127.0.0.1",),
    )
    write_key(tls / "gateway-readback.key", key)
    write_cert(tls / "gateway-readback.crt", cert)
    signing = new_key()
    numbers = signing.public_key().public_numbers()
    (tls / "jwks.json").write_text(json.dumps({"keys": [{
        "kty": "EC", "crv": "P-256", "kid": "suite", "alg": "ES256", "use": "sig",
        "x": b64_coord(numbers.x), "y": b64_coord(numbers.y),
    }]}), encoding="utf-8")
    now = int(time.time())
    TOKEN = jwt_encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "suite-caller", "exp": now + 3600, "nbf": now - 60},
        pem_key(signing), algorithm="ES256", headers={"kid": "suite", "typ": "JWT"},
    )


def pool(admin, tracing):
    body = {
        "name": "ai-test",
        "environment": "TEST",
        "public_hostname": PUBLIC,
        "path_prefix": "/agent",
        "listen_port": LISTEN,
        "bind_address": "127.0.0.1",
        "admin_addr": f"127.0.0.1:{admin}",
        "stats_addr": f"127.0.0.1:{STATS}",
        "readiness_addr": f"127.0.0.1:{READY}",
        "readback_port": READBACK,
        "publisher_identity": PUBLISHER,
        "tls_dir": "tls",
        "jwt_issuer": ISSUER,
        "jwt_audiences": [AUDIENCE],
        "jwks_file": "tls/jwks.json",
        "notes": "Loopback observability suite only. Not a product constant.",
    }
    if tracing:
        body["tracing"] = {
            "host": f"127.0.0.1:{COLLECTOR}",
            "protocol": "http",
            "path": "/v1/traces",
            "service_name": "idp-ai-gateway",
            "random_sampling": 1.0,
            "client_sampling": 1.0,
        }
    return body


def spec(admin, tracing):
    return {
        "traffic_class": "AI",
        "pool": pool(admin, tracing),
        "intent": {
            "intent_id": "gwi-ai-obs",
            "ai_protocol": "A2A",
            "ai_target_ref": "ai:example/obs-agent",
            "authz_profile": "ai-identity-v1",
            "approval_ref": "APPROVAL-PENDING-003",
            "expected_generation": 0,
            "policy_bundle_ref": "policy:ai-standard-v1",
        },
        "a2a": {"agent": {
            "host": "127.0.0.1", "port": UPSTREAM, "path_prefix": "/", "route_timeout": "5s",
        }},
    }


def compile_spec(control, label, admin, tracing):
    spec_path = WORK / f"{label}.json"
    spec_path.write_text(json.dumps(spec(admin, tracing), indent=2) + "\n", encoding="utf-8")
    gateway = WORK / f"{label}.compiled.yaml"
    policy = WORK / f"{label}.policy.json"
    proc = subprocess.run(
        [str(control), "compile", "--spec", str(spec_path),
         "--output-gateway", str(gateway), "--output-policy", str(policy),
         "--agentgateway", str(BINARY), "--lock-file", str(LOCK)],
        cwd=WORK, env=go_env(), capture_output=True, text=True,
    )
    if proc.returncode != 0:
        die(f"compile {label} failed: {(proc.stdout + proc.stderr)[-2000:]}")
    line = json.loads(proc.stdout)
    if line.get("outcome") != "COMPILED" or line.get("native_validated") is not True or line.get("routes") != 1:
        die(f"compile {label} line {line}")
    body = gateway.read_bytes()
    if hashlib.sha256(body).hexdigest() != line.get("gateway_sha256"):
        die(f"compile {label} bytes do not match gateway_sha256")
    if TOKEN.encode() in body:
        die("compile wrote the caller token into the gateway file")
    return body


def drop_tracing_block(text):
    lines = text.splitlines(keepends=True)
    out = []
    index = 0
    removed = 0
    while index < len(lines):
        if lines[index].startswith("  tracing:"):
            removed += 1
            index += 1
            while index < len(lines) and lines[index].startswith("    "):
                removed += 1
                index += 1
            continue
        out.append(lines[index])
        index += 1
    if removed < 2:
        die("the compiled file had no tracing block to delete")
    result = "".join(out)
    if "tracing:" in result:
        die("tracing remained after the block was deleted")
    return result


def extracted_hosts(text):
    proc = subprocess.run(
        ["sed", "-n", r"s/^[[:space:]-]*host:[[:space:]]*\([^[:space:]#]*\).*/\1/p"],
        input=text, text=True, capture_output=True, check=False,
    )
    if proc.returncode != 0:
        die("sed failed while checking pin-egress extraction: " + proc.stderr[-300:])
    found = []
    for line in proc.stdout.splitlines():
        cleaned = line.replace('"', "").replace("'", "")
        if re.fullmatch(r"[A-Za-z0-9._-]+:[0-9]{1,5}", cleaned):
            found.append(cleaned)
    return found


def spawn(argv, log_name, env):
    log_path = WORK / log_name
    handle = open(log_path, "w", encoding="utf-8")
    proc = subprocess.Popen(
        argv, cwd=WORK, env=env, stdout=handle, stderr=subprocess.STDOUT, start_new_session=True,
    )
    PROCS.append((proc, handle, log_path))
    return proc, log_path


def stop_procs():
    for proc, handle, _log in list(PROCS):
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, 15)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, 9)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=5)
        handle.close()
    PROCS.clear()


def tail(path):
    if not path.exists():
        return ""
    return redact(path.read_text(encoding="utf-8", errors="replace")[-800:])


def wait_listen(proc, log_path, ports, seconds=15):
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
    still = listening_ports(ports)
    if still:
        die("ports still listening after stop: " + ", ".join(str(port) for port in still))


class QuietHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def _read(self):
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _send(self, status, body, content_type):
        if isinstance(body, bytes):
            raw = body
        elif isinstance(body, str):
            raw = body.encode("utf-8")
        else:
            raw = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def upstream_handler():
    class Upstream(QuietHandler):
        def do_GET(self):
            self._keep()
            self._send(200, {
                "name": "obs-standin",
                "version": "0",
                "protocolVersion": "0.3.0",
                "url": "http://probe.example/agent",
            }, "application/json")

        def do_POST(self):
            self._keep(self._read())
            self._send(200, b"ok", "text/plain")

        def _keep(self, body=b""):
            item = {
                "method": self.command,
                "path": self.path,
                "traceparent": self.headers.get_all("traceparent") or [],
                "content_type": self.headers.get("Content-Type"),
                "body_len": len(body),
            }
            with LOCKS["up"]:
                UPSTREAM_HITS.append(item)
    return Upstream


def collector_handler():
    class Collector(QuietHandler):
        def do_POST(self):
            body = self._read()
            item = {
                "path": self.path,
                "content_type": self.headers.get("Content-Type") or "",
                "body": body,
            }
            with LOCKS["col"]:
                COLLECTOR_HITS.append(item)
            self._send(200, b"{}", "application/json")

        def do_GET(self):
            self._send(200, b"ok", "text/plain")
    return Collector


def start_server(port, handler):
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    SERVERS.append(httpd)
    return httpd


def stop_servers():
    for httpd in list(SERVERS):
        httpd.shutdown()
        httpd.server_close()
    SERVERS.clear()


def stop_server(port):
    kept = []
    for httpd in SERVERS:
        if httpd.server_address[1] == port:
            httpd.shutdown()
            httpd.server_close()
        else:
            kept.append(httpd)
    SERVERS[:] = kept


def take_upstream():
    with LOCKS["up"]:
        items = list(UPSTREAM_HITS)
        UPSTREAM_HITS.clear()
        return items


def collector_snapshot():
    with LOCKS["col"]:
        return list(COLLECTOR_HITS)


def reset_socket(sock):
    if sock is None:
        return
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass


def call(path, traceparent=None, timeout=8):
    headers = {"Host": PUBLIC, "Accept": "application/json", "Authorization": "Bearer " + TOKEN}
    if traceparent:
        headers["traceparent"] = traceparent
    conn = http.client.HTTPConnection("127.0.0.1", LISTEN, timeout=timeout)
    try:
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        return {"status": resp.status, "body": redact(raw[:200].decode("utf-8", "replace"))}
    except Exception as exc:
        return {"status": None, "error": type(exc).__name__ + ": " + redact(str(exc)), "body": ""}
    finally:
        reset_socket(conn.sock)
        conn.close()


def parse_traceparent(values):
    if len(values) != 1:
        return None
    match = TRACEPARENT_RE.fullmatch(values[0].strip())
    if not match:
        return None
    return {"raw": values[0].strip(), "trace_id": match.group(1), "span_id": match.group(2), "flags": match.group(3)}


def body_has_trace(body, trace_id):
    if trace_id.encode("ascii") in body:
        return True
    try:
        raw = bytes.fromhex(trace_id)
    except ValueError:
        return False
    return raw in body


def wait_for_trace(trace_id, seconds=3):
    deadline = time.monotonic() + seconds
    while True:
        hits = [item for item in collector_snapshot() if body_has_trace(item["body"], trace_id)]
        if hits:
            return hits
        if time.monotonic() >= deadline:
            return []
        time.sleep(0.05)


def content_types(hits):
    return sorted({item["content_type"] for item in hits})


def start_gateway(config_bytes, label, admin):
    path = WORK / f"{label}.yaml"
    path.write_bytes(config_bytes)
    proc, log_path = spawn([str(BINARY), "-f", path.name], f"{label}.log", gateway_env())
    wait_listen(proc, log_path, (LISTEN, READBACK), seconds=15)
    return proc, log_path


def one_upstream(response):
    hits = take_upstream()
    return response, hits


def case_a(results):
    results.case("A", "no caller traceparent; upstream and collector share the synthesized trace id")
    before = len(collector_snapshot())
    response, hits = one_upstream(call("/agent/.well-known/agent-card.json"))
    parsed = parse_traceparent(hits[0]["traceparent"]) if len(hits) == 1 else None
    results.check("the data-plane request is HTTP 200", response.get("status") == 200)
    results.check("the upstream stand-in received one request", len(hits) == 1)
    results.check("the upstream request has one W3C traceparent", parsed is not None)
    if parsed is None:
        results.note("upstream", hits)
        results.note("response", response)
        results.check("the collector body contains that trace id", False)
        return
    found = wait_for_trace(parsed["trace_id"], seconds=8)
    results.check("the collector stored a body containing that trace id", bool(found))
    types = content_types(found)
    results.note("traceparent", parsed["raw"])
    results.note("trace_id", parsed["trace_id"])
    results.note("upstream_span_id", parsed["span_id"])
    results.note("collector_content_type", types)
    results.note("collector_paths", sorted({item["path"] for item in found}))
    results.note("collector_new_posts", len(collector_snapshot()) - before)
    if not found:
        posts = collector_snapshot()
        results.note("response", response)
        results.note("all_content_types", content_types(posts))
        results.note("post_lengths", [len(item["body"]) for item in posts])


def case_b(results):
    results.case("B", "caller traceparent is kept; span id may differ")
    response, hits = one_upstream(call("/agent/.well-known/agent-card.json", SENT_TRACE))
    parsed = parse_traceparent(hits[0]["traceparent"]) if len(hits) == 1 else None
    want = "4bf92f3577b34da6a3ce929d0e0e4736"
    results.check("the data-plane request is HTTP 200", response.get("status") == 200)
    results.check("the upstream trace id is the caller's trace id", parsed is not None and parsed["trace_id"] == want)
    if parsed is None:
        results.note("upstream", hits)
        results.check("the collector body contains that trace id", False)
        return
    found = wait_for_trace(want, seconds=8)
    results.check("the collector body contains that trace id", bool(found))
    results.note("upstream_span_id", parsed["span_id"])
    results.note("caller_span_id", "00f067aa0ba902b7")
    results.note("span_id_differs", parsed["span_id"] != "00f067aa0ba902b7")
    results.note("collector_content_type", content_types(found))


def case_c(results):
    results.case("C", "collector is not listening; the data-plane request still succeeds")
    stop_server(COLLECTOR)
    quiet = COLLECTOR not in listening_ports((COLLECTOR,))
    response, hits = one_upstream(call("/agent/.well-known/agent-card.json", timeout=8))
    results.check("nothing is listening on the collector port", quiet)
    results.check("the data-plane request is HTTP 200", response.get("status") == 200)
    results.check("the upstream stand-in still received the request", len(hits) == 1)
    if response.get("status") != 200:
        results.note("response", response)


def case_d(results):
    results.case("D", "tracing omitted; upstream sees no traceparent")
    response, hits = one_upstream(call("/agent/.well-known/agent-card.json"))
    parents = hits[0]["traceparent"] if len(hits) == 1 else ["(no single request)"]
    results.check("the data-plane request is HTTP 200", response.get("status") == 200)
    results.check("the upstream stand-in received one request", len(hits) == 1)
    results.check("the upstream request has no traceparent", parents == [])
    if parents:
        results.note("traceparent", parents)
        results.note("response", response)


def run_data_plane(results, control_bin):
    traced = compile_spec(control_bin, "traced", ADMIN_ON, True)
    plain_same = compile_spec(control_bin, "plain-same", ADMIN_ON, False)
    plain = compile_spec(control_bin, "plain", ADMIN_OFF, False)
    traced_text = traced.decode("utf-8")
    plain_text = plain_same.decode("utf-8")
    hosts = extracted_hosts(traced_text)
    results.case("compile", "gateway-control compile, pin-egress host extraction")
    results.check("the traced document names the collector host", f"host: '127.0.0.1:{COLLECTOR}'" in traced_text)
    results.check("the omitted document has no tracing key", "tracing:" not in plain_text)
    results.check(
        "deleting the tracing block leaves the omitted document",
        drop_tracing_block(traced_text) == plain_text,
    )
    results.check(
        "pin-egress extraction keeps the quoted collector host",
        f"127.0.0.1:{COLLECTOR}" in hosts,
    )
    results.note("pin_egress", "deploy/compose/pin-egress.sh")
    results.note("extracted_hosts", hosts)
    if results.failed():
        return
    start_server(UPSTREAM, upstream_handler())
    start_server(COLLECTOR, collector_handler())
    proc, log_path = start_gateway(traced, "traced", ADMIN_ON)
    try:
        case_a(results)
        case_b(results)
        case_c(results)
    finally:
        for case in results.cases:
            if case["id"] == "A" and any(not item["ok"] for item in case["checks"]):
                case["notes"].append({"note": "log", "value": tail(log_path)})
                case["notes"].append({"note": "collector_posts_after_wait", "value": len(collector_snapshot())})
        stop_procs()
        wait_quiet((LISTEN, READBACK, ADMIN_ON))
    start_gateway(plain, "plain", ADMIN_OFF)
    try:
        case_d(results)
    finally:
        stop_procs()
        wait_quiet((LISTEN, READBACK, ADMIN_OFF))


def run_control(results, control_bin):
    traced = compile_spec(control_bin, "traced", ADMIN_ON, True)
    mutated = drop_tracing_block(traced.decode("utf-8")).encode("utf-8")
    results.case("control", "delete the tracing block; case A must not hold")
    results.check("the mutated file has no tracing key", b"tracing:" not in mutated)
    results.check("the mutated file differs from the compiler output", mutated != traced)
    start_server(UPSTREAM, upstream_handler())
    start_server(COLLECTOR, collector_handler())
    try:
        start_gateway(mutated, "control", ADMIN_ON)
        response, hits = one_upstream(call("/agent/.well-known/agent-card.json"))
    finally:
        stop_procs()
        stop_servers()
        wait_quiet((LISTEN, READBACK, ADMIN_ON, UPSTREAM, COLLECTOR))
    parents = hits[0]["traceparent"] if len(hits) == 1 else ["(no single request)"]
    synthesized = response.get("status") == 200 and len(hits) == 1 and parse_traceparent(parents) is not None
    # Case A requires a synthesized traceparent. The control passes only when that is absent.
    results.check("case A does not hold: upstream has no W3C traceparent", not synthesized)
    results.note("status", response.get("status"))
    results.note("upstream_traceparent", parents)
    results.note("collector_posts", len(collector_snapshot()))


def private_json(path, text):
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        die(f"{path.name} is readable by others")


def authz_material():
    global CREDENTIAL
    folder = WORK / "authz"
    folder.mkdir()
    ca_key, ca_cert = make_ca("authz-ca")
    write_cert(folder / "ca.crt", ca_cert)
    server_key, server_cert = make_leaf(
        ca_key, ca_cert, AUTHZ_NAME, ExtendedKeyUsageOID.SERVER_AUTH, dns=(AUTHZ_NAME,),
    )
    client_key, client_cert = make_leaf(
        ca_key, ca_cert, "gateway", ExtendedKeyUsageOID.CLIENT_AUTH, uris=(GATEWAY_ID,),
    )
    write_key(folder / "server.key", server_key)
    write_cert(folder / "server.crt", server_cert)
    write_key(folder / "client.key", client_key)
    write_cert(folder / "client.crt", client_cert)
    CREDENTIAL = "obs-cred-" + os.urandom(16).hex()
    policy = {
        "version": "policy-obs",
        "default_decision": "DENY",
        "registered_operations": [{
            "route_id": "mockcarrier-tracking-get",
            "provider_id": "mockcarrier",
            "operation_id": "tracking.get",
            "environment": "TEST",
            "method": "GET",
            "path_prefix": "/providers/mockcarrier/v1/tracking",
            "credential_binding_ref": "gatekeeper:mockcarrier-test",
            "allowed_tenants": ["tenant-blue"],
            "accounts_by_tenant": {"tenant-blue": ["account-blue"]},
            "allowed_service_ids": ["parcel-service"],
        }],
    }
    private_json(folder / "policy.json", json.dumps(policy))
    private_json(
        folder / "credentials.json",
        json.dumps({"gatekeeper:mockcarrier-test/account-blue": CREDENTIAL}),
    )
    return folder


def authz_call(port, folder):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(folder / "ca.crt"))
    context.load_cert_chain(str(folder / "client.crt"), str(folder / "client.key"))
    context.check_hostname = True
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        tls = context.wrap_socket(sock, server_hostname=AUTHZ_NAME)
    except Exception:
        sock.close()
        raise
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.sock = tls
    headers = {
        "x-idp-verified-subject": "parcel-service",
        "x-idp-verified-tenant": "tenant-blue",
        "x-idp-verified-env": "TEST",
        "x-idp-route-id": "mockcarrier-tracking-get",
        "x-idp-provider-id": "mockcarrier",
        "x-idp-operation-id": "tracking.get",
        "x-idp-environment": "TEST",
        "x-idp-method": "GET",
        "x-idp-path": "/providers/mockcarrier/v1/tracking/TRK-1",
    }
    try:
        conn.request("GET", "/v1/extauthz/check", headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        present = "authorization" in {name.lower() for name in resp.headers.keys()}
        return {"status": resp.status, "body": raw, "authorization_present": present}
    finally:
        reset_socket(conn.sock)
        conn.close()


def authz_metrics_get(port, path, tls_folder=None):
    if tls_folder is None:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            reset_socket(conn.sock)
            conn.close()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(tls_folder / "ca.crt"))
    context.load_cert_chain(str(tls_folder / "client.crt"), str(tls_folder / "client.key"))
    context.check_hostname = True
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    tls = context.wrap_socket(sock, server_hostname=AUTHZ_NAME)
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.sock = tls
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        reset_socket(conn.sock)
        conn.close()


def run_authz(results, binary):
    results.case("authz", "one allowed check: audit JSONL mode 0600, metrics, mTLS does not serve /metrics")
    folder = authz_material()
    audit_path = WORK / "audit.jsonl"
    proc, log_path = spawn(
        [str(binary),
         "--listen", f"127.0.0.1:{UPSTREAM}",
         "--tls-cert", str(folder / "server.crt"),
         "--tls-key", str(folder / "server.key"),
         "--client-ca", str(folder / "ca.crt"),
         "--policy", str(folder / "policy.json"),
         "--credentials", str(folder / "credentials.json"),
         "--gateway-identity", GATEWAY_ID,
         "--otlp-traces-url", f"http://127.0.0.1:{COLLECTOR}/v1/traces",
         "--audit-log", str(audit_path),
         "--metrics-listen", f"127.0.0.1:{AUTHZ_METRICS}"],
        "authz.log", go_env(),
    )
    try:
        wait_listen(proc, log_path, (UPSTREAM, AUTHZ_METRICS), seconds=10)
        answer = authz_call(UPSTREAM, folder)
        results.check("the check is allowed", answer["status"] == 200 and answer["authorization_present"])
        text = audit_path.read_text(encoding="utf-8") if audit_path.exists() else ""
        lines = [line for line in text.splitlines() if line]
        mode = stat.S_IMODE(audit_path.stat().st_mode) if audit_path.exists() else 0
        results.check("one audit JSONL line exists", len(lines) == 1)
        results.check("the audit file mode is 0600", mode == 0o600)
        leaked = False
        parsed = None
        if len(lines) == 1:
            leaked = (
                CREDENTIAL in lines[0]
                or "authorization" in lines[0].lower()
                or "secret" in lines[0].lower()
                or "bearer" in lines[0].lower()
            )
            try:
                parsed = json.loads(lines[0])
            except json.JSONDecodeError:
                parsed = None
        results.check("the audit line has no token, secret, or authorization value", len(lines) == 1 and not leaked)
        results.check(
            "the audit line is an egress decision",
            isinstance(parsed, dict) and parsed.get("event_type") == "egress_decision" and parsed.get("outcome") == "ALLOW",
        )
        status, body = authz_metrics_get(AUTHZ_METRICS, "/metrics")
        metric = b"idp_gateway_authz_decisions_total"
        results.check("GET /metrics returns idp_gateway_authz_decisions_total", status == 200 and metric in body)
        results.check("the metrics body has no credential value", CREDENTIAL.encode() not in body)
        denied, denied_body = authz_metrics_get(UPSTREAM, "/metrics", folder)
        results.check("the mTLS listen port does not serve /metrics", denied == 404 and metric not in denied_body)
        if answer["status"] != 200 or denied != 404 or len(lines) != 1:
            results.note("authz_status", answer["status"])
            results.note("metrics_status", status)
            results.note("mtls_metrics_status", denied)
            results.note("audit_mode", oct(mode))
    except SystemExit:
        results.note("authz_log", tail(log_path))
        raise
    finally:
        stop_procs()
        wait_quiet((UPSTREAM, AUTHZ_METRICS))


def cleanup():
    stop_procs()
    stop_servers()


def main():
    parser = argparse.ArgumentParser(description="Observability loopback evidence. Not an acceptance pass.")
    parser.add_argument("--control", choices=("drop-tracing",), help="negative control; not part of the default run")
    args = parser.parse_args()
    say("observability loopback suite; not an acceptance pass")
    ensure_free(PORTS)
    got = check_binary()
    say("agentgateway sha256 " + got)
    global WORK
    WORK = Path(tempfile.mkdtemp(prefix="idp-obs-"))
    results = Results()
    try:
        control_bin = WORK / "gateway-control"
        build("./cmd/gateway-control", control_bin)
        issue_gateway_material()
        if args.control == "drop-tracing":
            run_control(results, control_bin)
        else:
            run_data_plane(results, control_bin)
            stop_servers()
            wait_quiet((UPSTREAM, COLLECTOR))
            authz_bin = WORK / "gateway-authz"
            build("./cmd/gateway-authz", authz_bin)
            run_authz(results, authz_bin)
        results.report()
        left = listening_ports(PORTS)
        if left:
            die("left listening: " + ", ".join(str(port) for port in left))
        if results.failed():
            raise SystemExit(1)
    finally:
        cleanup()
        if WORK is not None:
            # Leave no suite process. The temp dir can go; it holds no product state.
            subprocess.run(["rm", "-rf", str(WORK)], check=False)
    say("ports 27701-27709 are not listening")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        cleanup()
        say("suite error: " + type(exc).__name__ + ": " + redact(str(exc)))
        raise SystemExit(2)
