"""Loopback suite for compiled LLM, MCP, and A2A configs.

This is not an acceptance pass. It compiles with gateway-control, then starts
the locked agentgateway on that file. Without --control the file given to the
gateway is the compiler's output, byte for byte. Stand-ins only. No docker in
this mode.

    .venv/bin/python tests/integration/aigateway/run.py
    .venv/bin/python tests/integration/aigateway/run.py --control mcp-no-allowlist
    .venv/bin/python tests/integration/aigateway/run.py --evidence

--evidence writes evidence/loopback.json and is refused together with --control.
The parent runs --evidence from a clean tree after committing. Do not commit
the evidence from a dirty tree.
"""
import argparse
import base64
import datetime
import hashlib
import http.client
import ipaddress
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from jwt import encode as jwt_encode

import standin

ROOT = Path(__file__).resolve().parents[3]
LOCK = ROOT / "deploy/agentgateway/agentgateway.lock.json"
BINARY = Path.home() / ".local/opt/agentgateway/1.7.0/agentgateway"
HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "evidence" / "loopback.json"

# One gateway start binds six ports. The admin port stays in TIME-WAIT after the
# process exits, because the read-back route connects to it. Each start gets its
# own admin port. The others are reused; client sockets are reset so they do not
# leave the listen and read-back ports in TIME-WAIT.
LISTEN, STATS, READY, READBACK, UPSTREAM = 27661, 27663, 27664, 27665, 27666
ADMIN_PORTS = (27667, 27668, 27669, 27670, 27671, 27672, 27673, 27674)
SHARED_PORTS = (LISTEN, STATS, READY, READBACK, UPSTREAM)
ALL_PORTS = SHARED_PORTS + ADMIN_PORTS
ADMIN_CURSOR = 0
PUBLIC = "ai.example"
ISSUER = "https://issuer.example/ai"
AUDIENCE = "example-ai"
PUBLISHER = "spiffe://idp.test/gateway-control/publisher"
GATEWAY_ID = "spiffe://idp.test/ai-pool/gateway"
MCP_DNS = "mcp.standin.test"
AGENT_DNS = "agent.standin.test"
OTHER_DNS = "other.standin.test"
PEM_MARKERS = ("-----BEGIN ",)

INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-06-18", "capabilities": {},
    "clientInfo": {"name": "loopback-suite", "version": "0"},
}}
SEND = {"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {"message": {
    "kind": "message", "messageId": "m-1", "role": "user",
    "parts": [{"kind": "text", "text": "hello"}],
}}}
EXTRA = {
    "Cookie": "a=b",
    "X-Forwarded-For": "203.0.113.9",
    "X-Provider-Account": "acct",
    "X-Not-Registered": "caller-header",
    "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
}
FORBIDDEN = ("cookie", "x-forwarded-for", "x-provider-account", "x-not-registered", "authorization")

WORK = None
BOOK = None
API_KEY = ""
TOKENS = {}
SESSION_KEYS = []
COMPILED = {}
ARGS = None


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

    def note(self, text, value):
        self.current["notes"].append({"note": text, "value": value})

    def failed(self):
        return [case for case in self.cases if any(not item["ok"] for item in case["checks"])]

    def report(self):
        for case in self.cases:
            bad = [item["check"] for item in case["checks"] if not item["ok"]]
            passed = sum(item["ok"] for item in case["checks"])
            say(f"{case['id']} {'FAIL' if bad else 'pass'}  {passed}/{len(case['checks'])}")
            for item in case["notes"]:
                say("    " + item["note"] + ": " + json.dumps(item["value"], ensure_ascii=False)[:600])
            for item in bad:
                say("    not met: " + item)


def say(text):
    print(text, flush=True)


def die(text):
    say(text)
    raise SystemExit(2)


def strip_proxy(env):
    return {key: value for key, value in env.items() if "proxy" not in key.lower()}


def go_env():
    env = strip_proxy(os.environ.copy())
    env["PATH"] = "/usr/local/go/bin:" + env.get("PATH", "")
    return env


def port_free(port):
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", port))
    except OSError:
        return False
    finally:
        sock.close()
    return True


def listening_ports(ports):
    # A connect() to a TIME-WAIT socket can keep that socket alive. Read the
    # kernel table instead: only state 0A is a process listening.
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


def ensure_free(ports, wait):
    deadline = time.monotonic() + wait
    while True:
        listening = listening_ports(ports)
        if listening:
            die("refusing to start; a process is listening on 127.0.0.1: " + ", ".join(str(port) for port in listening))
        busy = [port for port in ports if not port_free(port)]
        if not busy:
            return
        if time.monotonic() >= deadline:
            die("refusing to start; port busy on 127.0.0.1: " + ", ".join(str(port) for port in busy))
        time.sleep(0.5)


def ports_for(admin):
    return SHARED_PORTS + (admin,)


def next_admin():
    global ADMIN_CURSOR
    if ADMIN_CURSOR >= len(ADMIN_PORTS):
        die("the suite ran out of admin ports in 27667-27674")
    port = ADMIN_PORTS[ADMIN_CURSOR]
    ADMIN_CURSOR += 1
    return port


def sha256_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_binary():
    if not BINARY.is_file():
        die(f"locked agentgateway is not at {BINARY}")
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    want = {value.lower() for value in lock.get("sha256", {}).values()}
    got = sha256_file(BINARY)
    if got not in want:
        die(f"agentgateway sha256 {got} does not match the lock file")
    if got != "c7ef326b7b5702451e94bab55ff484d600d5abdc5344a4cdf7c72fc0bcff9e24":
        die(f"agentgateway sha256 {got} is not the measured 1.7.0 binary")
    return lock, got


def build_control(dest):
    proc = subprocess.run(
        ["go", "build", "-o", str(dest), "./cmd/gateway-control"],
        cwd=ROOT, env=go_env(), capture_output=True, text=True,
    )
    if proc.returncode != 0:
        die("go build failed: " + (proc.stderr or proc.stdout)[-1500:])


def name_of(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def new_key():
    return ec.generate_private_key(ec.SECP256R1())


def write_key(path, key):
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    ))
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


def pem_of(key):
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    )


def make_tokens(jwks_path):
    key = new_key()
    other = new_key()
    numbers = key.public_key().public_numbers()
    jwks_path.write_text(json.dumps({"keys": [{
        "kty": "EC", "crv": "P-256", "kid": "suite", "alg": "ES256", "use": "sig",
        "x": b64_coord(numbers.x), "y": b64_coord(numbers.y),
    }]}), encoding="utf-8")
    now = int(time.time())

    def token(private, issuer, audience, exp, nbf):
        return jwt_encode(
            {"iss": issuer, "aud": audience, "sub": "suite-caller", "exp": exp, "nbf": nbf},
            pem_of(private), algorithm="ES256", headers={"kid": "suite", "typ": "JWT"},
        )

    return {
        "good": token(key, ISSUER, AUDIENCE, now + 3600, now - 60),
        "audience": token(key, ISSUER, "other-audience", now + 3600, now - 60),
        "issuer": token(key, "https://other.example/nope", AUDIENCE, now + 3600, now - 60),
        "expired": token(key, ISSUER, AUDIENCE, now - 3600, now - 7200),
        "other": token(other, ISSUER, AUDIENCE, now + 3600, now - 60),
    }


def issue_material():
    global API_KEY, TOKENS
    tls = WORK / "tls"
    tls.mkdir()
    ca_key, ca_cert = make_ca("loopback-ca")
    write_cert(tls / "ca.crt", ca_cert)
    other_key, other_cert = make_ca("another-ca")
    write_cert(tls / "other-ca.crt", other_cert)
    leaves = {
        "gateway": (ca_key, ca_cert, "gateway", ExtendedKeyUsageOID.CLIENT_AUTH, (), (), (GATEWAY_ID,)),
        "gateway-readback": (ca_key, ca_cert, "readback", ExtendedKeyUsageOID.SERVER_AUTH, (), ("127.0.0.1",), ()),
        "publisher": (ca_key, ca_cert, "publisher", ExtendedKeyUsageOID.CLIENT_AUTH, (), (), (PUBLISHER,)),
        MCP_DNS: (ca_key, ca_cert, MCP_DNS, ExtendedKeyUsageOID.SERVER_AUTH, (MCP_DNS,), (), ()),
        AGENT_DNS: (ca_key, ca_cert, AGENT_DNS, ExtendedKeyUsageOID.SERVER_AUTH, (AGENT_DNS,), (), ()),
        "untrusted-" + MCP_DNS: (other_key, other_cert, MCP_DNS, ExtendedKeyUsageOID.SERVER_AUTH, (MCP_DNS,), (), ()),
        "untrusted-" + AGENT_DNS: (other_key, other_cert, AGENT_DNS, ExtendedKeyUsageOID.SERVER_AUTH, (AGENT_DNS,), (), ()),
    }
    for filename, args in leaves.items():
        key, cert = make_leaf(*args)
        write_key(tls / f"{filename}.key", key)
        write_cert(tls / f"{filename}.crt", cert)
    API_KEY = "suite-llm-" + os.urandom(8).hex()
    (tls / "ai-api-key").write_text(API_KEY, encoding="utf-8")
    (tls / "ai-api-key").chmod(0o600)
    TOKENS = make_tokens(tls / "jwks.json")


def pool(prefix, admin):
    return {
        "name": "ai-test",
        "environment": "TEST",
        "public_hostname": PUBLIC,
        "path_prefix": prefix,
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
        "notes": "Loopback suite only. Names ending in .example or .test are not product constants.",
    }


def intent(protocol, ref):
    return {
        "intent_id": "gwi-ai-" + protocol.lower(),
        "ai_protocol": protocol,
        "ai_target_ref": ref,
        "authz_profile": "ai-identity-v1",
        "approval_ref": "APPROVAL-PENDING-003",
        "expected_generation": 0,
        "policy_bundle_ref": "policy:ai-standard-v1",
    }


def llm_spec(admin):
    return {
        "traffic_class": "AI",
        "pool": pool("/llm", admin),
        "intent": intent("LLM", "ai:example/loopback-llm"),
        "provider": {
            "name": "example", "kind": "openai", "api_key_file": "tls/ai-api-key",
            "base_url": f"http://127.0.0.1:{UPSTREAM}/v1",
        },
        "models": [{"name": "example-model"}],
    }


def mcp_spec(admin, tls_hostname):
    target = {"name": "standin", "host": "127.0.0.1", "port": UPSTREAM, "path": "/mcp"}
    if tls_hostname:
        target["tls_hostname"] = tls_hostname
    return {
        "traffic_class": "AI",
        "pool": pool("/tools", admin),
        "intent": intent("MCP", "ai:example/loopback-mcp"),
        "mcp": {"target": target},
    }


def a2a_spec(admin):
    return {
        "traffic_class": "AI",
        "pool": pool("/agent", admin),
        "intent": intent("A2A", "ai:example/loopback-a2a"),
        "a2a": {"agent": {
            "host": "127.0.0.1", "port": UPSTREAM, "tls_hostname": AGENT_DNS,
            "path_prefix": "/", "route_timeout": "5s",
        }},
    }


def compile_spec(spec, label):
    spec_path = WORK / f"{label}.json"
    spec_path.write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
    gateway = WORK / f"{label}.compiled.yaml"
    policy = WORK / f"{label}.policy.json"
    proc = subprocess.run(
        [str(WORK / "gateway-control"), "compile", "--spec", str(spec_path),
         "--output-gateway", str(gateway), "--output-policy", str(policy),
         "--agentgateway", str(BINARY), "--lock-file", str(LOCK)],
        cwd=WORK, env=go_env(), capture_output=True, text=True,
    )
    if proc.returncode != 0:
        die(f"compile {label} failed: {(proc.stdout + proc.stderr)[-1500:]}")
    line = json.loads(proc.stdout)
    if line.get("outcome") != "COMPILED" or line.get("native_validated") is not True or line.get("routes") != 1:
        die(f"compile {label} line {line}")
    body = gateway.read_bytes()
    if hashlib.sha256(body).hexdigest() != line.get("gateway_sha256"):
        die(f"compile {label} gateway bytes do not match gateway_sha256")
    if API_KEY and API_KEY.encode() in body:
        die(f"compile {label} wrote the API key into the gateway file")
    COMPILED[label] = hashlib.sha256(body).hexdigest()
    return body


def route_named(doc, suffix):
    matches = [route for route in doc.get("routes") or [] if str(route.get("name", "")).endswith(suffix)]
    if len(matches) != 1:
        die(f"expected one route ending {suffix}")
    return matches[0]


def apply_control(compiled, protocol):
    control = ARGS.control
    if control is None:
        return compiled
    applies = (
        control == "no-readback-route"
        or (control == "llm-no-policies" and protocol == "LLM")
        or (control in ("mcp-no-allowlist", "mcp-no-path-rule") and protocol == "MCP")
        or (control == "a2a-no-policy" and protocol == "A2A")
    )
    if not applies:
        return compiled
    doc = yaml.safe_load(compiled)
    if control == "no-readback-route":
        before = doc.get("routes") or []
        doc["routes"] = [route for route in before if route.get("name") != "read-back"]
        if len(doc["routes"]) == len(before):
            die("control no-readback-route found no read-back route")
    elif control == "mcp-no-allowlist":
        route_named(doc, "-mcp")["policies"].pop("transformations")
    elif control == "mcp-no-path-rule":
        route_named(doc, "-mcp")["policies"].pop("authorization")
    elif control == "a2a-no-policy":
        policies = route_named(doc, "-a2a")["policies"]
        if "a2a" not in policies:
            die("control a2a-no-policy found no a2a policy")
        policies.pop("a2a")
    elif control == "llm-no-policies":
        policies = (doc.get("llm") or {}).get("policies")
        if not policies:
            die("control llm-no-policies found no llm.policies")
        doc["llm"].pop("policies")
    else:
        die("unknown control " + control)
    mutated = yaml.safe_dump(doc, sort_keys=False, width=10000).encode()
    if mutated == compiled:
        die("control did not change the compiled file")
    return mutated


def file_for_gateway(compiled, label, protocol):
    given = apply_control(compiled, protocol)
    path = WORK / f"{label}.yaml"
    path.write_bytes(given)
    if ARGS.control is None and path.read_bytes() != compiled:
        die("without --control the file given to the gateway is not the compiler output")
    if ARGS.control is None and given != compiled:
        die("without --control the suite changed the compiler output")
    return path


def gateway_env():
    env = go_env()
    key = os.urandom(32).hex()
    SESSION_KEYS.append(key)
    env["SESSION_KEY"] = key
    return env


def start_gateway(config, label):
    log_path = WORK / f"{label}.log"
    log_file = open(log_path, "w", encoding="utf-8")
    proc = subprocess.Popen(
        [str(BINARY), "-f", config.name],
        cwd=WORK, env=gateway_env(), stdout=log_file, stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    return proc, log_path, log_file


def stop_gateway(proc, log_file):
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
    log_file.close()


def wait_listen(proc, log_path):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            die("gateway exited: " + tail(log_path))
        if port_open(LISTEN) and port_open(READBACK):
            return
        time.sleep(0.1)
    die("gateway did not listen: " + tail(log_path))


def port_open(port):
    sock = socket.socket()
    sock.settimeout(0.2)
    try:
        sock.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def tail(path):
    if not path.exists():
        return ""
    text = path.read_text(encoding="utf-8", errors="replace")
    return redact(text[-800:])


def redact(text):
    for secret in secret_values():
        if secret:
            text = text.replace(secret, "[redacted]")
    return text


def secret_values():
    values = [API_KEY, *TOKENS.values(), *SESSION_KEYS]
    return [value for value in values if value]


def secret_hits(text):
    hits = []
    if API_KEY and API_KEY in text:
        hits.append("api key")
    for name, value in TOKENS.items():
        if value and value in text:
            hits.append("jwt:" + name)
    for value in SESSION_KEYS:
        if value and value in text:
            hits.append("session key")
    if any(marker in text for marker in PEM_MARKERS):
        hits.append("pem")
    return hits


def call(method, path, body=None, headers=None, token=None, timeout=8):
    hdrs = {"Host": PUBLIC, "Accept": "application/json, text/event-stream"}
    if body is not None:
        hdrs["Content-Type"] = "application/json"
    if token:
        hdrs["Authorization"] = "Bearer " + token
    if headers:
        hdrs.update(headers)
    conn = http.client.HTTPConnection("127.0.0.1", LISTEN, timeout=timeout)
    try:
        raw_body = None if body is None else json.dumps(body)
        conn.request(method, path, raw_body, hdrs)
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8", "replace")
        ctype = resp.getheader("Content-Type") or ""
        return {
            "status": resp.status,
            "ctype": ctype,
            "session": resp.getheader("Mcp-Session-Id"),
            "location": resp.getheader("Location"),
            "set_cookie": resp.getheader("Set-Cookie"),
            "json": parse_body(raw, ctype),
            "raw": redact(raw[:400]),
        }
    except Exception as exc:
        return {"status": None, "error": type(exc).__name__, "raw": ""}
    finally:
        reset_socket(conn.sock)
        conn.close()


def parse_body(raw, ctype):
    if ctype.startswith("text/event-stream"):
        parsed = None
        for line in raw.splitlines():
            if line.startswith("data:"):
                try:
                    parsed = json.loads(line[5:].strip())
                except json.JSONDecodeError:
                    pass
        return parsed
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def read_back(path, client_cert):
    ctx = ssl.create_default_context(cafile=str(WORK / "tls" / "ca.crt"))
    if client_cert:
        ctx.load_cert_chain(str(WORK / "tls" / "publisher.crt"), str(WORK / "tls" / "publisher.key"))
    conn = http.client.HTTPSConnection("127.0.0.1", READBACK, context=ctx, timeout=5)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        resp.read()
        return {"status": resp.status, "handshake": True}
    except Exception as exc:
        return {"status": None, "handshake": False, "error": type(exc).__name__}
    finally:
        reset_socket(getattr(conn, "sock", None))
        conn.close()


def reset_socket(sock):
    if sock is None:
        return
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass


def start_standin(kind, cert_name=None):
    tls = WORK / "tls"
    secrets = tuple(TOKENS.values())
    if kind == "llm":
        return standin.serve(UPSTREAM, standin.llm_handler(BOOK, API_KEY, secrets))
    if kind == "mcp":
        handler = standin.mcp_handler(BOOK, secrets)
        if not cert_name:
            return standin.serve(UPSTREAM, handler)
        return standin.serve(
            UPSTREAM, handler, str(tls / f"{cert_name}.crt"), str(tls / f"{cert_name}.key"), str(tls / "ca.crt"),
        )
    handler = standin.a2a_handler(BOOK, f"https://{AGENT_DNS}:{UPSTREAM}/internal", secrets)
    return standin.serve(
        UPSTREAM, handler, str(tls / f"{cert_name}.crt"), str(tls / f"{cert_name}.key"), str(tls / "ca.crt"),
    )


def stop_standin(server):
    server.shutdown()
    server.server_close()


def run_gateway(label, spec, protocol, standins, fn, admin):
    global BOOK
    ensure_free(ports_for(admin), 90)
    BOOK = standin.Book()
    compiled = compile_spec(spec, label)
    config = file_for_gateway(compiled, label, protocol)
    servers = [start_standin(*item) for item in standins]
    proc, log_path, log_file = start_gateway(config, label)
    try:
        wait_listen(proc, log_path)
        time.sleep(0.3)
        fn(log_path)
    finally:
        stop_gateway(proc, log_file)
        for server in servers:
            stop_standin(server)
        ensure_free(SHARED_PORTS, 90)


def check_log(results, log_path):
    text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
    hits = secret_hits(text)
    results.check("the gateway log has no JWT and no key material", hits == [])
    if hits:
        results.note("log hits", hits)


def host_of(record):
    return (record.get("seen") or {}).get("host")


def host_is(record, expected):
    seen = host_of(record) or ""
    return seen == expected or seen.startswith(expected + ":")


def forbidden(records):
    found = []
    for record in records:
        for name in FORBIDDEN:
            if name in record["headers"]:
                found.append(name)
    return sorted(set(found))


def cert_names(records):
    return sorted({
        (record.get("client_cert") or {}).get("cn")
        for record in records if record.get("client_cert")
    })


def rpc_code(response):
    body = response.get("json")
    if isinstance(body, dict) and isinstance(body.get("error"), dict):
        return body["error"].get("code")
    return None


def run_readback(results, case_id):
    results.case(case_id, "publisher certificate reads config_dump and runtime; another path is 404; no client certificate fails the handshake")
    dump = read_back("/config_dump", True)
    runtime = read_back("/api/runtime", True)
    other = read_back("/not-a-readback-path", True)
    bare = read_back("/config_dump", False)
    results.check("GET /config_dump with the publisher certificate is 200", dump.get("status") == 200)
    results.check("GET /api/runtime with the publisher certificate is 200", runtime.get("status") == 200)
    results.check("another path on the read-back port is 404", other.get("status") == 404)
    results.check("without a client certificate the TLS handshake fails", bare.get("handshake") is False and bare.get("status") is None)
    results.note("read-back", {
        "config_dump": dump.get("status"), "runtime": runtime.get("status"),
        "other": other.get("status"), "without_certificate": bare.get("error") or bare.get("status"),
    })


def run_auth(results, case_id, call_one, other_host_status=404):
    case = results.case(case_id, "missing and wrong tokens are refused; another Host is refused")
    probes = (
        ("no JWT is 401 and the stand-in received nothing", None, None, 401),
        ("wrong audience is 401 and the stand-in received nothing", "audience", None, 401),
        ("wrong issuer is 401 and the stand-in received nothing", "issuer", None, 401),
        ("expired token is 401 and the stand-in received nothing", "expired", None, 401),
        ("a token signed by another key is 401 and the stand-in received nothing", "other", None, 401),
    )
    for title, token_name, headers, want in probes:
        response = call_one(None if token_name is None else TOKENS[token_name], headers)
        got = BOOK.take()
        results.check(title, response.get("status") == want and got == [])
        if response.get("status") != want or got:
            results.note(title, {"status": response.get("status"), "error": response.get("error"), "records": len(got), "raw": response.get("raw")})
    response = call_one(TOKENS["good"], {"Host": "other.example"})
    got = BOOK.take()
    results.check(
        f"another Host is {other_host_status} and the stand-in received nothing",
        response.get("status") == other_host_status and got == [],
    )
    if response.get("status") != other_host_status or got:
        results.note("another Host", {"status": response.get("status"), "records": len(got), "paths": [record["path"] for record in got], "raw": response.get("raw")})
    return case


def finish_auth(results, case, log_path):
    results.current = case
    results.check("the caller's JWT never reaches a stand-in", BOOK.saw_caller_jwt is False)
    text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
    hits = secret_hits(text)
    results.check("the gateway log has no JWT and no key material", hits == [])
    if hits:
        results.note("log hits", hits)


def llm_call(token, headers):
    return call("POST", "/llm/v1/chat/completions", {"model": "example-model", "messages": [{"role": "user", "content": "hi"}]}, headers, token)


def run_llm(results):
    admin = next_admin()

    def body(log_path):
        run_readback(results, "RB-LLM")
        auth = run_auth(results, "AUTH-LLM", llm_call, other_host_status=403)
        results.case("LLM-01", "chat reaches the stand-in with the key and only the allowlisted headers; the two response headers do not come back")
        response = llm_call(TOKENS["good"], EXTRA)
        got = BOOK.take()
        paths = [record["path"] for record in got]
        results.check("POST /llm/v1/chat/completions reaches the stand-in as /v1/chat/completions", "/v1/chat/completions" in paths)
        results.check("the stand-in saw the API key from the key file", any(record.get("key_in_authorization") for record in got))
        results.check("the caller gets the stand-in's completion", response.get("status") == 200 and "standin-completion" in (response.get("raw") or ""))
        results.check(
            "Cookie, X-Forwarded-For, X-Provider-Account and X-Not-Registered do not reach the stand-in",
            bool(got) and not any(name in record["headers"] for record in got for name in ("cookie", "x-forwarded-for", "x-provider-account", "x-not-registered")),
        )
        results.check("Location and Set-Cookie do not reach the caller", response.get("location") is None and response.get("set_cookie") is None)
        compiled = (WORK / "llm.compiled.yaml").read_bytes()
        results.check("the compiled YAML does not contain the key", API_KEY.encode() not in compiled)
        results.note("llm", {"status": response.get("status"), "paths": paths, "headers": [record["headers"] for record in got[:1]], "location": response.get("location"), "set_cookie": response.get("set_cookie")})

        results.case("LLM-MODELS", "GET /llm/v1/models is answered by the gateway and lists the spec's model")
        listed = call("GET", "/llm/v1/models", None, None, TOKENS["good"])
        listed_records = BOOK.take()
        results.check("GET /llm/v1/models is 200 and lists example-model", listed.get("status") == 200 and "example-model" in (listed.get("raw") or ""))
        results.check("the stand-in received nothing for GET /llm/v1/models", listed_records == [])
        results.note("models", {"status": listed.get("status"), "raw": listed.get("raw")})

        results.case("LLM-PATHS", "only the two compiled endpoints are forwarded")
        refused = (
            ("POST", "/llm/other", {"model": "example-model"}),
            ("POST", "/llm/v1/embeddings", {"model": "example-model", "input": "hi"}),
            ("POST", "/llm/v1/chat/completions/", {"model": "example-model", "messages": [{"role": "user", "content": "hi"}]}),
            ("GET", "/llm/v1/chat/completions", None),
            ("POST", "/llm/v1/models", {"model": "example-model"}),
        )
        for method, path, payload in refused:
            one = call(method, path, payload, None, TOKENS["good"])
            seen = BOOK.take()
            results.check(f"{method} {path} is 403 and the stand-in received nothing", one.get("status") == 403 and seen == [])
            if one.get("status") != 403 or seen:
                results.note(f"{method} {path}", {
                    "status": one.get("status"),
                    "records": len(seen),
                    "paths": [record["path"] for record in seen],
                    "key": [record.get("key_in_authorization") for record in seen],
                    "raw": one.get("raw"),
                })

        results.case("LLM-UNKNOWN", "a model the spec does not list is 404 and the stand-in received nothing")
        unknown = call(
            "POST", "/llm/v1/chat/completions",
            {"model": "not-a-listed-model", "messages": [{"role": "user", "content": "hi"}]},
            None, TOKENS["good"],
        )
        unknown_records = BOOK.take()
        results.check("an unlisted model is 404 and the stand-in received nothing", unknown.get("status") == 404 and unknown_records == [])
        if unknown.get("status") != 404 or unknown_records:
            results.note("unlisted model", {"status": unknown.get("status"), "records": len(unknown_records), "raw": unknown.get("raw")})

        queried = call(
            "POST", "/llm/v1/chat/completions?x=1",
            {"model": "example-model", "messages": [{"role": "user", "content": "hi"}]},
            None, TOKENS["good"],
        )
        queried_records = BOOK.take()
        results.note("query string on the chat path", {
            "status": queried.get("status"),
            "raw_paths": [record.get("raw_path") for record in queried_records],
        })
        finish_auth(results, auth, log_path)

    run_gateway("llm", llm_spec(admin), "LLM", [("llm", None)], body, admin)


def session_headers(session_id):
    headers = {"Mcp-Protocol-Version": "2025-06-18"}
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    return headers


def mcp_ok(response):
    body = response.get("json")
    return response.get("status") == 200 and isinstance(body, dict) and "result" in body and "error" not in body


def run_mcp_tls(results):
    admin = next_admin()

    def body(log_path):
        run_readback(results, "RB-MCP")
        auth = run_auth(results, "AUTH-MCP", lambda token, headers: call("POST", "/tools", INIT, headers, token))
        results.case("MCP-TLS", "MCP over TLS: session, allowlist, path rule, methods, and the measured response headers")
        opened = call("POST", "/tools", INIT, EXTRA, TOKENS["good"])
        init_records = BOOK.take()
        session_id = opened.get("session")
        notified = call("POST", "/tools", {"jsonrpc": "2.0", "method": "notifications/initialized"}, session_headers(session_id), TOKENS["good"])
        BOOK.take()
        listed = call("POST", "/tools", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, session_headers(session_id), TOKENS["good"])
        list_records = BOOK.take()
        called = call("POST", "/tools", {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "echo", "arguments": {"text": "hi"}}}, {**session_headers(session_id), **EXTRA}, TOKENS["good"])
        call_records = BOOK.take()
        results.check("initialize is 200 and returns a session id", opened.get("status") == 200 and bool(session_id) and isinstance(opened.get("json"), dict) and "result" in opened["json"])
        results.check("notifications/initialized is 202", notified.get("status") == 202)
        results.check("tools/list works", mcp_ok(listed) and "echo" in (listed.get("raw") or ""))
        results.check("tools/call works", mcp_ok(called) and "standin ran echo" in (called.get("raw") or ""))
        seen = init_records + call_records
        results.check("the target saw the gateway client certificate", cert_names(seen) == ["gateway"])
        results.check("the target saw the rewritten Host", bool(seen) and all(host_is(record, MCP_DNS) for record in seen))
        results.check("Cookie, X-Forwarded-For, X-Provider-Account and X-Not-Registered do not reach the target", forbidden(seen) == [])
        deeper = call("POST", "/tools/deeper", {"jsonrpc": "2.0", "id": 4, "method": "tools/list"}, session_headers(session_id), TOKENS["good"])
        deeper_records = BOOK.take()
        results.check("a path one segment deeper is 403 and the target received nothing", deeper.get("status") == 403 and deeper_records == [])
        put = call("PUT", "/tools", None, session_headers(session_id), TOKENS["good"])
        put_records = BOOK.take()
        results.check("PUT is 404 and the target received nothing", put.get("status") == 404 and put_records == [])
        bare = call("POST", "/tools", {"jsonrpc": "2.0", "id": 5, "method": "tools/list"}, session_headers(session_id), None)
        bare_records = BOOK.take()
        results.check("a session id without a JWT is 401 and the target received nothing", bare.get("status") == 401 and bare_records == [])
        deleted = call("DELETE", "/tools", None, session_headers(session_id), TOKENS["good"])
        deleted_records = BOOK.take()
        reused = call("POST", "/tools", {"jsonrpc": "2.0", "id": 6, "method": "tools/list"}, session_headers(session_id), TOKENS["good"])
        reused_records = BOOK.take()
        results.note("response headers the caller saw", {
            "initialize_location": opened.get("location"), "initialize_set_cookie": opened.get("set_cookie"),
            "tools_list_location": listed.get("location"), "tools_list_set_cookie": listed.get("set_cookie"),
        })
        results.note("headers the target saw", [record["headers"] for record in seen])
        results.note("rewritten host", [host_of(record) for record in seen])
        results.note("client certificate", [record.get("client_cert") for record in seen[:1]])
        results.note("DELETE then reuse", {
            "delete_status": deleted.get("status"), "target_saw_delete": [record["method"] for record in deleted_records],
            "reuse_status": reused.get("status"), "target_saw_reuse": [record.get("rpc") for record in reused_records],
            "reuse_has_result": isinstance(reused.get("json"), dict) and "result" in (reused.get("json") or {}),
        })
        results.note("deeper and put", {"deeper": deeper.get("status"), "put": put.get("status")})
        if not list_records:
            results.note("tools/list target records", 0)
        finish_auth(results, auth, log_path)

    run_gateway("mcp-tls", mcp_spec(admin, MCP_DNS), "MCP", [("mcp", MCP_DNS)], body, admin)


def run_mcp_plain(results):
    admin = next_admin()

    def body(_log):
        results.case("MCP-PLAIN", "MCP on plain loopback completes a session; the Host the target saw is recorded")
        opened = call("POST", "/tools", INIT, None, TOKENS["good"])
        init_records = BOOK.take()
        session_id = opened.get("session")
        call("POST", "/tools", {"jsonrpc": "2.0", "method": "notifications/initialized"}, session_headers(session_id), TOKENS["good"])
        BOOK.take()
        listed = call("POST", "/tools", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, session_headers(session_id), TOKENS["good"])
        BOOK.take()
        called = call("POST", "/tools", {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "echo", "arguments": {"text": "hi"}}}, session_headers(session_id), TOKENS["good"])
        BOOK.take()
        results.check("plain loopback initialize, tools/list and tools/call work",
                      opened.get("status") == 200 and bool(session_id) and mcp_ok(listed) and mcp_ok(called))
        results.note("host the target saw", [host_of(record) for record in init_records])
        check_log(results, _log)

    run_gateway("mcp-plain", mcp_spec(admin, None), "MCP", [("mcp", None)], body, admin)


def run_mcp_failure(results, case_id, title, tls_hostname, standins):
    admin = next_admin()

    def body(_log):
        results.case(case_id, title)
        response = call("POST", "/tools", INIT, None, TOKENS["good"], timeout=20)
        got = BOOK.take()
        code = rpc_code(response)
        results.check("initialize is HTTP 500 with JSON-RPC -32603", response.get("status") == 500 and code == -32603)
        results.check("the target application received nothing", got == [])
        message = None
        body_json = response.get("json")
        if isinstance(body_json, dict) and isinstance(body_json.get("error"), dict):
            message = body_json["error"].get("message")
        results.note("failure", {"status": response.get("status"), "code": code, "message": message, "error": response.get("error"), "records": len(got)})
        check_log(results, _log)

    run_gateway(case_id.lower(), mcp_spec(admin, tls_hostname), "MCP", standins, body, admin)


def run_a2a(results):
    admin = next_admin()

    def body(log_path):
        run_readback(results, "RB-A2A")
        auth = run_auth(results, "AUTH-A2A", lambda token, headers: call("GET", "/agent/.well-known/agent-card.json", None, headers, token))
        results.case("A2A-TLS", "A2A over TLS: rewritten card, allowlist, method binding, and stripped response headers")
        card = call("GET", "/agent/.well-known/agent-card.json", None, None, TOKENS["good"])
        card_records = BOOK.take()
        posted = call("POST", "/agent", SEND, EXTRA, TOKENS["good"])
        post_records = BOOK.take()
        url = card.get("json", {}).get("url") if isinstance(card.get("json"), dict) else None
        results.check("the card is 200 and url is http://ai.example/agent", card.get("status") == 200 and url == "http://ai.example/agent")
        results.check("POST /agent reaches the agent at /", posted.get("status") == 200 and any(record["path"] == "/" and record["method"] == "POST" for record in post_records))
        results.check("the caller gets the agent's answer", "standin-agent-answer" in (posted.get("raw") or ""))
        seen = card_records + post_records
        results.check("the agent saw the gateway client certificate", cert_names(post_records) == ["gateway"])
        results.check("the agent saw the rewritten Host", bool(post_records) and all(host_is(record, AGENT_DNS) for record in post_records))
        results.check("only allowlisted caller headers reach the agent", forbidden(seen) == [])
        results.check("Location and Set-Cookie do not reach the caller",
                      card.get("location") is None and card.get("set_cookie") is None and posted.get("location") is None and posted.get("set_cookie") is None)
        refused = (
            ("GET", "/agent", None, 403),
            ("POST", "/agent/.well-known/agent-card.json", SEND, 403),
            ("GET", "/agent/.well-known/agent.json", None, 403),
            ("GET", "/agent/", None, 403),
            ("POST", "/agent/other", SEND, 403),
            ("DELETE", "/agent", None, 404),
        )
        for method, path, payload, want in refused:
            response = call(method, path, payload, None, TOKENS["good"])
            got = BOOK.take()
            results.check(f"{method} {path} is {want} and the agent received nothing", response.get("status") == want and got == [])
            if response.get("status") != want or got:
                results.note(f"{method} {path}", {"status": response.get("status"), "records": len(got), "raw": response.get("raw")})
        forwarded = call("GET", "/agent/.well-known/agent-card.json", None, {"X-Forwarded-Proto": "https"}, TOKENS["good"])
        BOOK.take()
        forwarded_url = forwarded.get("json", {}).get("url") if isinstance(forwarded.get("json"), dict) else None
        results.note("card url when the caller sends X-Forwarded-Proto https", forwarded_url)
        results.note("card url", url)
        results.note("agent saw", {
            "paths": [record["path"] for record in post_records],
            "host": [host_of(record) for record in post_records],
            "headers": [record["headers"] for record in post_records[:1]],
            "cert": [record.get("client_cert") for record in post_records[:1]],
        })
        finish_auth(results, auth, log_path)

    run_gateway("a2a", a2a_spec(admin), "A2A", [("a2a", AGENT_DNS)], body, admin)


def run_a2a_bad_ca(results):
    admin = next_admin()

    def body(_log):
        results.case("A2A-OTHER-CA", "an agent certificate from another CA is 503 and the agent application received nothing")
        card = call("GET", "/agent/.well-known/agent-card.json", None, None, TOKENS["good"], timeout=20)
        card_records = BOOK.take()
        posted = call("POST", "/agent", SEND, None, TOKENS["good"], timeout=20)
        post_records = BOOK.take()
        results.check("the card is 503 and the agent application received nothing", card.get("status") == 503 and card_records == [])
        results.check("POST is 503 and the agent application received nothing", posted.get("status") == 503 and post_records == [])
        results.note("other ca", {"card": card.get("status"), "card_raw": card.get("raw"), "post": posted.get("status"), "post_raw": posted.get("raw")})
        check_log(results, _log)

    run_gateway("a2a-other-ca", a2a_spec(admin), "A2A", [("a2a", "untrusted-" + AGENT_DNS)], body, admin)


def evidence_document(lock, digest, started, finished, wall, results):
    checks = [item for case in results.cases for item in case["checks"]]
    cases = []
    for case in results.cases:
        failed = any(not item["ok"] for item in case["checks"])
        cases.append({
            "id": case["id"], "title": case["title"], "result": "fail" if failed else "pass",
            "checks": [{"check": item["check"], "result": "pass" if item["ok"] else "fail"} for item in case["checks"]],
            "notes": case["notes"],
        })
    porcelain = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain=v1", "-uall"], capture_output=True, text=True).stdout
    return {
        "kind": "AI loopback: gateway-control compile, then the locked agentgateway on the compiled file, stand-ins on 127.0.0.1",
        "not_an_acceptance_pass": True,
        "operator_and_approver": "Not recorded. This file records what was run and what was seen. It is not an acceptance pass and it is not a gate decision.",
        "control": ARGS.control,
        "agentgateway": {
            "version": lock.get("version"), "git_revision": lock.get("git_revision"),
            "image": lock.get("image", {}).get("repository"), "local_binary_sha256": digest,
        },
        "repository": {
            "commit": subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip(),
            "uncommitted_files": len([line for line in porcelain.splitlines() if line.strip()]),
        },
        "compiled_gateway_sha256": COMPILED,
        "environment": ["TEST"],
        "started_at_utc": started,
        "finished_at_utc": finished,
        "wall_seconds": round(wall, 2),
        "ports": {
            "listen": LISTEN, "stats": STATS, "readiness": READY, "readback": READBACK,
            "upstream": UPSTREAM, "admin": list(ADMIN_PORTS[:ADMIN_CURSOR]),
        },
        "cases": cases,
        "summary": {
            "cases": len(cases),
            "cases_failed": sum(1 for case in cases if case["result"] == "fail"),
            "checks": len(checks),
            "checks_passed": sum(1 for item in checks if item["ok"]),
            "checks_failed": sum(1 for item in checks if not item["ok"]),
        },
    }


def write_evidence(document):
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(json.dumps(document, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    text = EVIDENCE.read_text(encoding="utf-8")
    hits = secret_hits(text)
    if hits:
        EVIDENCE.unlink()
        say("EVIDENCE NOT KEPT: the file held " + ", ".join(hits))
        return False
    say(f"evidence written: {EVIDENCE}")
    return True


def run(lock, digest, wall_start):
    global WORK
    started = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    ensure_free(ALL_PORTS, 90)
    waited = time.monotonic() - wall_start
    if waited >= 1:
        say(f"waited {round(waited, 1)}s for ports left in TIME-WAIT")
    wall_start = time.monotonic()
    build_control(WORK / "gateway-control")
    issue_material()
    results = Results()
    run_llm(results)
    run_mcp_tls(results)
    run_mcp_plain(results)
    run_mcp_failure(results, "MCP-OTHER-CA", "MCP target certificate from another CA: initialize is 500 and the target application received nothing", MCP_DNS, [("mcp", "untrusted-" + MCP_DNS)])
    run_mcp_failure(results, "MCP-NAME", "MCP tls_hostname does not match the certificate: initialize is 500 and the target application received nothing", OTHER_DNS, [("mcp", MCP_DNS)])
    run_mcp_failure(results, "MCP-DOWN", "nothing listening for the MCP target: initialize is 500 and the target application received nothing", MCP_DNS, [])
    run_a2a(results)
    run_a2a_bad_ca(results)
    results.report()
    failed = results.failed()
    finished = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    wall = time.monotonic() - wall_start
    kept = True
    if ARGS.evidence:
        kept = write_evidence(evidence_document(lock, digest, started, finished, wall, results))
    checks = [item for case in results.cases for item in case["checks"]]
    passed = sum(item["ok"] for item in checks)
    say(f"{len(results.cases) - len(failed)}/{len(results.cases)} cases, {passed}/{len(checks)} checks, wall {round(wall, 2)}s")
    return 0 if not failed and kept else 1


def main():
    global ARGS, WORK
    parser = argparse.ArgumentParser(description="Run compiled AI configs on the locked agentgateway. Not an acceptance pass.")
    parser.add_argument("--control", choices=["llm-no-policies", "mcp-no-allowlist", "mcp-no-path-rule", "a2a-no-policy", "no-readback-route"])
    parser.add_argument("--evidence", action="store_true")
    ARGS = parser.parse_args()
    if ARGS.evidence and ARGS.control:
        print("refused: --evidence cannot be combined with --control", file=sys.stderr)
        return 2
    wall_start = time.monotonic()
    lock, digest = check_binary()
    WORK = Path(tempfile.mkdtemp(prefix="aigateway-"))
    say(f"work {WORK}")
    code = 2
    try:
        code = run(lock, digest, wall_start)
        return code
    finally:
        if WORK is not None and os.environ.get("AIGATEWAY_KEEP_WORK") == "1":
            say(f"work kept at {WORK}")
        elif WORK is not None:
            import shutil
            shutil.rmtree(WORK, ignore_errors=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(2)
