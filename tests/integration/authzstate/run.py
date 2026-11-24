"""Loopback evidence for shared revocation and quota. Not an acceptance pass.

Real processes only: authz-state and two gateway-authz replicas. Direct mTLS to
/v1/extauthz/check. No agentgateway, no Gatekeeper, no Docker.

    /home/tops/workspace/idp-gateway/.venv/bin/python tests/integration/authzstate/run.py
    /home/tops/workspace/idp-gateway/.venv/bin/python tests/integration/authzstate/run.py --control no-state
    /home/tops/workspace/idp-gateway/.venv/bin/python tests/integration/authzstate/run.py --control wrong-identity

Ports 27861-27875 only. Proxy variables are removed before any subprocess or local request.
"""
from __future__ import annotations

import argparse
import atexit
import datetime
import http.client
import json
import os
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[3]

STATE, AUTHZ_A, AUTHZ_B = 27861, 27862, 27863
PORTS = tuple(range(27861, 27876))

AUTHZ_ID = "spiffe://idp.test/as/gateway-authz"
GATEWAY_ID = "spiffe://idp.test/as/gateway"
REVOKER_ID = "spiffe://idp.test/as/revoker"
OTHER_ID = "spiffe://idp.test/as/other"
STATE_NAME = "state.as.idp.test"
AUTHZ_A_NAME = "authz-a.as.idp.test"
AUTHZ_B_NAME = "authz-b.as.idp.test"

BINDING = "gatekeeper:carrier-as"
BLUE = "account-blue"
GREEN = "account-green"
TENANT = "tenant-blue"
SERVICE = "parcel-service"
PROVIDER = "carrier"

OPS = {
    "orders.create": ("POST", "/providers/carrier/v1/orders", "carrier-orders-create"),
    "tracking.get": ("GET", "/providers/carrier/v1/tracking", "carrier-tracking-get"),
    "labels.print": ("POST", "/providers/carrier/v1/labels", "carrier-labels-print"),
}

WORK = None
PROCS = []
CLEANED = False
SECRETS = []


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
        total = passed = 0
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


def mkdir0700(path):
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)


def start_proc(name, argv, port):
    log_path = WORK / f"{name}.log"
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


def stop_named(name):
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
        if entry["port"] is not None:
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


def tail(path):
    if path is None or not Path(path).exists():
        return ""
    return redact(Path(path).read_text(encoding="utf-8", errors="replace")[-1500:])


def pid_of(name):
    for entry in PROCS:
        if entry["name"] == name and entry["proc"].poll() is None:
            return entry["proc"].pid
    return None


def log_text(name):
    path = WORK / f"{name}.log"
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


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


def client_context(cert_name):
    tls = WORK / "tls"
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(tls / "ca.crt")
    ctx.load_cert_chain(tls / f"{cert_name}.crt", tls / f"{cert_name}.key")
    return ctx


def extauthz(port, server_name, account, operation, cert_name="gateway"):
    method, path, route = OPS[operation]
    headers = {
        "x-idp-verified-subject": SERVICE,
        "x-idp-verified-tenant": TENANT,
        "x-idp-verified-env": "TEST",
        "x-idp-route-id": route,
        "x-idp-provider-id": PROVIDER,
        "x-idp-operation-id": operation,
        "x-idp-environment": "TEST",
        "x-idp-method": method,
        "x-idp-path": path,
        "x-provider-account": account,
    }
    conn = LoopbackHTTPS(port, client_context(cert_name), 8, server_name)
    try:
        conn.request(method, "/v1/extauthz/check", headers=headers)
        response = conn.getresponse()
        body = response.read()
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = {}
        return {
            "status": response.status,
            "authorization": response.getheader("Authorization") or "",
            "body": parsed if isinstance(parsed, dict) else {},
            "raw": body.decode("utf-8", errors="replace"),
        }
    finally:
        conn.close()


def post_json(port, server_name, path, payload, cert_name):
    raw = json.dumps(payload).encode("utf-8")
    conn = LoopbackHTTPS(port, client_context(cert_name), 8, server_name)
    try:
        conn.request("POST", path, body=raw, headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        body = response.read()
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = {}
        return {"status": response.status, "body": parsed if isinstance(parsed, dict) else {}, "raw": body.decode("utf-8", errors="replace")}
    finally:
        conn.close()


def coordinator_call(method, path, body=None, cert_name="authz-a"):
    conn = LoopbackHTTPS(STATE, client_context(cert_name), 8, STATE_NAME)
    try:
        headers = {"Content-Type": "application/json"} if body is not None else {}
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        raw = response.read()
        return response.status, raw.decode("utf-8", errors="replace")
    finally:
        conn.close()


def issue_material():
    tls = WORK / "tls"
    ca_key, ca_cert = make_ca("as-loopback-ca")
    write_cert(tls / "ca.crt", ca_cert)
    both = (ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH)
    leaves = {
        "state": ( (ExtendedKeyUsageOID.SERVER_AUTH,), (STATE_NAME,), ("spiffe://idp.test/as/authz-state",) ),
        "authz-a": (both, (AUTHZ_A_NAME,), (AUTHZ_ID,)),
        "authz-b": (both, (AUTHZ_B_NAME,), (AUTHZ_ID,)),
        "gateway": ((ExtendedKeyUsageOID.CLIENT_AUTH,), (), (GATEWAY_ID,)),
        "revoker": ((ExtendedKeyUsageOID.CLIENT_AUTH,), (), (REVOKER_ID,)),
        "other": ((ExtendedKeyUsageOID.CLIENT_AUTH,), (), (OTHER_ID,)),
    }
    for filename, (ekus, dns, uris) in leaves.items():
        key, cert = make_leaf(ca_key, ca_cert, filename, ekus, dns=dns, uris=uris)
        write_key(tls / f"{filename}.key", key)
        write_cert(tls / f"{filename}.crt", cert)


def write_inputs(blue_token, green_token):
    operations = []
    for operation, (method, path, route) in OPS.items():
        operations.append({
            "route_id": route,
            "provider_id": PROVIDER,
            "operation_id": operation,
            "environment": "TEST",
            "method": method,
            "path_prefix": path,
            "credential_binding_ref": BINDING,
            "allowed_tenants": [TENANT],
            "accounts_by_tenant": {TENANT: [BLUE, GREEN]},
            "allowed_service_ids": [SERVICE],
        })
    policy = {"version": "as-state", "default_decision": "DENY", "registered_operations": operations}
    (WORK / "policy.json").write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
    creds = {
        f"{BINDING}/{BLUE}": blue_token,
        f"{BINDING}/{GREEN}": green_token,
    }
    private_json(WORK / "credentials.json", json.dumps(creds))
    limits = {
        "version": "v1",
        "buckets": [{
            "id": "per-account",
            "key_dimensions": ["provider_account"],
            "max_requests": 1,
            "window_seconds": 3600,
        }],
    }
    (WORK / "limits.json").write_text(json.dumps(limits, indent=2) + "\n", encoding="utf-8")
    for name in ("revocations-a.json", "revocations-b.json"):
        private_json(WORK / name, '{"epoch":0,"revoked_accounts":{}}\n')


def authz_argv(leaf, port, revocations, with_state):
    tls = WORK / "tls"
    argv = [
        str(WORK / "gateway-authz"),
        "--listen", f"127.0.0.1:{port}",
        "--tls-cert", str(tls / f"{leaf}.crt"),
        "--tls-key", str(tls / f"{leaf}.key"),
        "--client-ca", str(tls / "ca.crt"),
        "--policy", str(WORK / "policy.json"),
        "--credentials", str(WORK / "credentials.json"),
        "--gateway-identity", GATEWAY_ID,
        "--revocations", str(revocations),
        "--revoker-identity", REVOKER_ID,
        "--rate-limits", str(WORK / "limits.json"),
    ]
    if with_state:
        argv += [
            "--authz-state-url", f"https://127.0.0.1:{STATE}",
            "--authz-state-cert", str(tls / f"{leaf}.crt"),
            "--authz-state-key", str(tls / f"{leaf}.key"),
            "--authz-state-ca", str(tls / "ca.crt"),
            "--authz-state-name", STATE_NAME,
        ]
    return argv


def start_state():
    tls = WORK / "tls"
    return start_proc("authz-state", [
        str(WORK / "authz-state"),
        "--listen", f"127.0.0.1:{STATE}",
        "--tls-cert", str(tls / "state.crt"),
        "--tls-key", str(tls / "state.key"),
        "--client-ca", str(tls / "ca.crt"),
        "--authz-identity", AUTHZ_ID,
        "--state-file", str(WORK / "state.json"),
    ], STATE)


def start_authz(label, port, leaf, with_state):
    revocations = WORK / ("revocations-a.json" if label.endswith("a") else "revocations-b.json")
    return start_proc(label, authz_argv(leaf, port, revocations, with_state), port)


def prepare(with_state):
    global WORK
    scrub_proxy()
    ensure_free(PORTS)
    WORK = Path(tempfile.mkdtemp(prefix="idp-gateway-authzstate-", dir="/tmp"))
    os.chmod(WORK, 0o700)
    mkdir0700(WORK / "tls")
    blue = "blue-" + os.urandom(8).hex()
    green = "green-" + os.urandom(8).hex()
    remember_secret(blue)
    remember_secret(green)
    issue_material()
    write_inputs(blue, green)
    build("./cmd/gateway-authz", WORK / "gateway-authz")
    build("./cmd/authz-state", WORK / "authz-state")
    if with_state:
        start_state()
    start_authz("authz-a", AUTHZ_A, "authz-a", with_state)
    start_authz("authz-b", AUTHZ_B, "authz-b", with_state)


def cleanup():
    global CLEANED, WORK
    if CLEANED:
        return
    CLEANED = True
    stop_procs()
    wait_quiet(PORTS, seconds=8)
    if WORK is not None:
        shutil.rmtree(WORK, ignore_errors=True)
        WORK = None


def denied(got, code):
    return (
        got["status"] == 403
        and got["authorization"] == ""
        and got["body"].get("result") == "DENY"
        and got["body"].get("reason_code") == code
    )


def run_suite(results):
    pid_a = pid_of("authz-a")
    pid_b = pid_of("authz-b")
    pid_s = pid_of("authz-state")

    results.case("AS-02", "ban on A is denied on B; another operation stays allowed")
    ban = post_json(AUTHZ_A, AUTHZ_A_NAME, "/v1/egress/operation-bans",
                    {"operation_id": "tracking.get", "banned": True, "reason": "abuse"}, "revoker")
    banned = extauthz(AUTHZ_B, AUTHZ_B_NAME, BLUE, "tracking.get")
    allowed = extauthz(AUTHZ_B, AUTHZ_B_NAME, BLUE, "labels.print")
    epoch_after_allow = allowed["body"].get("revocation_epoch")
    results.check("ban request is 200", ban["status"] == 200 and ban["body"].get("banned") is True)
    results.check("B denies the banned operation", denied(banned, "OPERATION_BANNED"))
    results.check("B still allows another operation", allowed["status"] == 200 and allowed["authorization"].startswith("Bearer "))
    results.check("PIDs unchanged after the ban", pid_of("authz-a") == pid_a and pid_of("authz-b") == pid_b and pid_of("authz-state") == pid_s)
    results.note("epoch_after_allow", epoch_after_allow)

    results.case("AS-01", "revoke on A is denied on B and the epoch advances")
    revoke = post_json(AUTHZ_A, AUTHZ_A_NAME, "/v1/egress/revocations",
                       {"account_id": BLUE, "revoked": True, "reason": "key leaked"}, "revoker")
    denied_b = extauthz(AUTHZ_B, AUTHZ_B_NAME, BLUE, "labels.print")
    epoch = denied_b["body"].get("revocation_epoch")
    results.check("revoke request is 200", revoke["status"] == 200 and revoke["body"].get("revoked") is True)
    results.check("B denies the revoked account", denied(denied_b, "ACCOUNT_REVOKED"))
    results.check("epoch advanced", isinstance(epoch, int) and isinstance(epoch_after_allow, int) and epoch > epoch_after_allow)
    results.check("A and B keep the same PIDs", pid_of("authz-a") == pid_a and pid_of("authz-b") == pid_b)
    results.note("epoch", epoch)

    results.case("AS-03", "shared quota max 1: second replica is 429")
    first = extauthz(AUTHZ_A, AUTHZ_A_NAME, GREEN, "orders.create")
    second = extauthz(AUTHZ_B, AUTHZ_B_NAME, GREEN, "orders.create")
    results.check("first allow on A is 200", first["status"] == 200 and first["authorization"].startswith("Bearer "))
    results.check("second check on B is 429 RATE_LIMITED",
                  second["status"] == 429 and second["body"].get("result") == "DENY" and second["body"].get("reason_code") == "RATE_LIMITED")
    results.check("429 has no credential header", second["authorization"] == "")
    results.note("second_status", second["status"])

    results.case("AS-04", "coordinator down fails closed")
    stop_named("authz-state")
    quiet = STATE not in listening_ports([STATE])
    left_a = extauthz(AUTHZ_A, AUTHZ_A_NAME, GREEN, "orders.create")
    left_b = extauthz(AUTHZ_B, AUTHZ_B_NAME, GREEN, "labels.print")
    def unavailable(got):
        return (
            got["status"] == 503
            and got["status"] != 200
            and got["authorization"] == ""
            and got["body"].get("result") == "INDETERMINATE"
            and got["body"].get("reason_code") == "REVOCATION_STATE_UNAVAILABLE"
        )
    results.check("coordinator is no longer listening", quiet)
    results.check("A is revocation-unavailable, not 200", unavailable(left_a))
    results.check("B is revocation-unavailable, not 200", unavailable(left_b))
    results.check("authz PIDs still the same", pid_of("authz-a") == pid_a and pid_of("authz-b") == pid_b)
    results.note("authz_a", left_a["status"])
    results.note("authz_b", left_b["status"])

    results.case("cleanup", "no leftover listeners on suite ports")
    stop_procs()
    wait_quiet(PORTS, seconds=8)
    left = listening_ports(PORTS)
    results.check("suite ports are free", left == [])
    if left:
        results.note("left", left)


def run_control_no_state(results):
    results.case("control-no-state", "without the state URL local buckets do not share")
    first = extauthz(AUTHZ_A, AUTHZ_A_NAME, BLUE, "orders.create")
    second = extauthz(AUTHZ_B, AUTHZ_B_NAME, BLUE, "orders.create")
    results.check("A returns 200", first["status"] == 200 and first["authorization"].startswith("Bearer "))
    results.check("B also returns 200", second["status"] == 200 and second["authorization"].startswith("Bearer "))
    results.check("neither response is 429", first["status"] != 429 and second["status"] != 429)
    results.note("statuses", [first["status"], second["status"]])
    run_cleanup(results)


def run_control_wrong_identity(results):
    results.case("control-wrong-identity", "wrong SPIFFE is 401")
    check = extauthz(AUTHZ_A, AUTHZ_A_NAME, BLUE, "orders.create", cert_name="other")
    status, raw = coordinator_call("POST", "/v1/authz-state/mutate", body=b"{not-json BODY-MARKER", cert_name="other")
    snap, snap_raw = coordinator_call("GET", "/v1/authz-state/snapshot", cert_name="other")
    logs = log_text("authz-state")
    results.check("authz check is 401", check["status"] == 401 and check["authorization"] == "")
    results.check("coordinator mutate with a bad body is 401", status == 401)
    results.check("coordinator snapshot is 401", snap == 401)
    results.check("coordinator log does not contain the bad body", "BODY-MARKER" not in logs and "BODY-MARKER" not in raw and "BODY-MARKER" not in snap_raw)
    results.note("authz_status", check["status"])
    results.note("coordinator_status", status)
    run_cleanup(results)


def run_cleanup(results):
    results.case("cleanup", "no leftover listeners on suite ports")
    stop_procs()
    wait_quiet(PORTS, seconds=8)
    left = listening_ports(PORTS)
    results.check("suite ports are free", left == [])


def main():
    parser = argparse.ArgumentParser(description="Shared revocation and quota loopback. Not an acceptance pass.")
    parser.add_argument("--control", choices=("no-state", "wrong-identity"), help="negative control; not part of the default run")
    args = parser.parse_args()
    atexit.register(cleanup)
    say("authz-state dual-replica suite; not an acceptance pass")
    results = Results()
    try:
        if args.control == "no-state":
            prepare(with_state=False)
            run_control_no_state(results)
        elif args.control == "wrong-identity":
            prepare(with_state=True)
            run_control_wrong_identity(results)
        else:
            prepare(with_state=True)
            run_suite(results)
        if results.failed() and WORK is not None:
            say("authz-a log: " + tail(WORK / "authz-a.log"))
            say("authz-b log: " + tail(WORK / "authz-b.log"))
            say("authz-state log: " + tail(WORK / "authz-state.log"))
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
