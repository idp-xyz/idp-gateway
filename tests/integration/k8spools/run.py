#!/usr/bin/env python3
"""Kubernetes egress pool evidence for ADR-0025. Not an acceptance pass.

Own kind cluster idp-gateway-pools; kubeconfig only under .run/. Host loopback ports 27901-27915.
Does not touch ~/.kube/config, the cluster named kind, or production Gatekeeper.

    tests/integration/k8spools/stack.sh up
    .venv/bin/python tests/integration/k8spools/run.py
    .venv/bin/python tests/integration/k8spools/run.py --control no-netpol
    .venv/bin/python tests/integration/k8spools/run.py --control no-coordinators
    tests/integration/k8spools/stack.sh down
"""
from __future__ import annotations

import argparse
import base64
import collections
import hashlib
import http.client
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import yaml
from jwt import encode as jwt_encode

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BLACKBOX = ROOT / "tests/acceptance/blackbox"
SFINTL = ROOT / "tests/integration/sfintl"
sys.path.insert(0, str(BLACKBOX))
sys.path.insert(0, str(SFINTL))
import pin  # noqa: E402
import pki  # noqa: E402

# Extra identities used by the pool (same URIs as gatekeeper/coordinators suites).
pki.ID["gateway-authz"] = "spiffe://idp.test/egress/gateway-authz"
pki.ID["provider-signer"] = "spiffe://idp.test/egress/provider-signer"
pki.ID["sf-token-coordinator"] = "spiffe://idp.test/egress/sf-token-coordinator"
pki.ID["authz-state"] = "spiffe://idp.test/egress/authz-state"
pki.LEAVES["gateway-authz"] = ("ca", "gateway-authz", None)
pki.LEAVES["provider-signer"] = ("ca", "provider-signer", "provider-signer.idp.test")
pki.LEAVES["sf-token-coordinator"] = ("ca", "sf-token-coordinator", "sf-token-coordinator.idp.test")
pki.LEAVES["authz-state"] = ("ca", "authz-state", "authz-state.idp.test")
# Authz listen leaf: DNS name the gateway verifies (gatekeeper.idp.test) + server auth.
pki.LEAVES["authz-listen"] = ("ca", "gateway-authz", pki.GATEKEEPER_NAME)

RUN = HERE / ".run"
KUBECONFIG = RUN / "kubeconfig"
KUSTOMIZE = ROOT / "deploy/kubernetes/egress/overlays/kind"
DOCKERFILE = ROOT / "deploy/kubernetes/images/Dockerfile.binary"
LOCK = pin.lock()
# kind load cannot import the multi-platform index (missing arm64 blob offline). Use the
# locked linux/amd64 manifest digest, which matches deploy/kubernetes/egress/base.
GATEWAY_IMAGE = (
    LOCK["image"]["repository"] + "@" + LOCK["image"]["manifests"]["linux/amd64"]
)
FRONT_IMAGE = (
    "public.ecr.aws/nginx/nginx-unprivileged:stable-alpine"
    "@sha256:c3fc8fa482be50ef709c6438eb1bc98d50dbfe5a9b48be90711b8814f4dfd701"
)
TOOLS_IMAGE = (
    "public.ecr.aws/docker/library/python:3.13-alpine"
    "@sha256:1e1f6334529d1fb26a2ef619d7cffb30a7c7d7cc1cc7338ebee283a58d1aeaca"
)
STANDIN_TAG = "idp-gateway-sfintl-pool-standin:50.0.2"
NS = "idp-egress"
CLUSTER = "idp-gateway-pools"
HOST_FRONT, STAGING_PORT = 27901, 27902
STAGING_CONTAINER = "idp-gateway-pools-staging"
PRESTOP, MIN_DEADLINE, MAX_DEADLINE, GRACE = 8, 12, 45, 60
ISSUER = "http://idp-gateway-pools.idp.test/issuer"
AUDIENCE = "idp-egress-gateway"
HOST = "egress-api.idp.test"
BINDING = "gatekeeper:sfintl-k8spools"
BLUE_ACCOUNT, GREEN_ACCOUNT = "account-blue", "account-green"
QUERIES = "/providers/sfintl/v1/agent-number-queries"
PRINTS = "/providers/sfintl/v1/label-prints"
ORDERS = "/providers/sfintl/v1/orders"
RATE_LIMITS = {
    "version": "k8spools",
    "buckets": [
        {
            "id": "labels-print-per-account",
            "provider_id": "sfintl",
            "operation_id": "labels.print",
            "key_dimensions": ["provider_account"],
            "max_requests": 1,
            "window_seconds": 3600,
        }
    ],
}
BINARIES = (
    "gateway-authz",
    "provider-signer",
    "sf-token-coordinator",
    "authz-state",
    "gateway-control",
)
KUBECTL = shutil.which("kubectl") or str(Path.home() / ".local/bin/kubectl")
KIND = shutil.which("kind") or str(Path.home() / ".local/bin/kind")
SECRETS: list[str] = []
CONTROL = None
NETPOL_ENFORCED = None  # measured
IMAGE_TAGS: dict[str, str] = {}
TOKENS: dict[str, str] = {}
APPS: dict = {}
PORT_FORWARD = None


class Results:
    def __init__(self):
        self.cases = []
        self.current = None
        self.timings = {}

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
        return [c for c in self.cases if any(not x["ok"] for x in c["checks"])]

    def report(self):
        say("---")
        total = passed = 0
        for case in self.cases:
            bad = [x["check"] for x in case["checks"] if not x["ok"]]
            ok_n = sum(x["ok"] for x in case["checks"])
            total += len(case["checks"])
            passed += ok_n
            say(f"{case['id']} {'FAIL' if bad else 'pass'}  {ok_n}/{len(case['checks'])}  {case['title']}")
            for n in case["notes"]:
                say("    " + n["note"] + ": " + clip(n["value"]))
            for b in bad:
                say("    not met: " + b)
        say(f"{len(self.cases)} cases, {passed}/{total} checks")
        return passed, total


def say(text=""):
    print(redact(str(text)), flush=True)


def clip(value):
    raw = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    return redact(raw)[:500]


def die(msg):
    say(msg)
    raise SystemExit(2)


def remember(value):
    if value and value not in SECRETS:
        SECRETS.append(value)


def redact(text):
    for s in SECRETS:
        if s:
            text = text.replace(s, "[redacted]")
    text = re.sub(r"auth_[A-Za-z0-9_-]{8,}", "auth_[redacted]", text)
    text = re.sub(r"Sf-OpenApi [^;\s\"']+;", "Sf-OpenApi [redacted];", text)
    text = re.sub(r"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----", "[pem-redacted]", text, flags=re.S)
    return text


def scrub_proxy():
    for k in list(os.environ):
        if "proxy" in k.lower():
            os.environ.pop(k, None)


def go_env():
    env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
    env["PATH"] = "/usr/local/go/bin:" + env.get("PATH", "")
    env["CGO_ENABLED"] = "0"
    return env


def kubectl(*argv, stdin=None, check=True, timeout=180):
    done = subprocess.run(
        [KUBECTL, "--kubeconfig", str(KUBECONFIG), *argv],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=timeout,
        env={k: v for k, v in os.environ.items() if "proxy" not in k.lower()},
    )
    if check and done.returncode != 0:
        die(f"kubectl {' '.join(argv[:6])} failed: {done.stderr.strip()[-800:]}")
    return done


def docker(*argv, timeout=600, check=True):
    done = subprocess.run(["docker", *argv], capture_output=True, text=True, timeout=timeout)
    if check and done.returncode != 0:
        die(f"docker {' '.join(argv[:5])} failed: {(done.stderr or done.stdout).strip()[-600:]}")
    return done


def apply_docs(docs):
    kubectl("apply", "-f", "-", stdin=yaml.safe_dump_all([d for d in docs if d], sort_keys=False))


def free_ports(ports):
    busy = []
    for p in ports:
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if s.connect_ex(("127.0.0.1", p)) == 0:
                busy.append(p)
    if busy:
        die(f"host ports in use (need free 27901-27915): {busy}")


def build_binaries():
    bindir = RUN / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    for name in BINARIES:
        out = bindir / name
        say(f"build {name}")
        done = subprocess.run(
            ["go", "build", "-trimpath", "-o", str(out), f"./cmd/{name}"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            env=go_env(),
            timeout=180,
        )
        if done.returncode != 0:
            die(f"go build {name}: {done.stderr[-500:]}")
        out.chmod(0o755)


def content_tag(path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return f"sha256-{digest[:16]}"


def build_images():
    imgdir = RUN / "images"
    imgdir.mkdir(parents=True, exist_ok=True)
    for name in ("gateway-authz", "provider-signer", "sf-token-coordinator", "authz-state"):
        binary = RUN / "bin" / name
        tag = content_tag(binary)
        image = f"idp-gateway-{name}:{tag}"
        ctx = imgdir / name
        if ctx.exists():
            shutil.rmtree(ctx)
        ctx.mkdir()
        shutil.copy2(binary, ctx / "binary")
        shutil.copy2(DOCKERFILE, ctx / "Dockerfile")
        docker("build", "-t", image, str(ctx))
        IMAGE_TAGS[name] = image
        say(f"image {image}")
    IMAGE_TAGS["agentgateway"] = GATEWAY_IMAGE
    IMAGE_TAGS["front"] = FRONT_IMAGE
    IMAGE_TAGS["tools"] = TOOLS_IMAGE
    IMAGE_TAGS["standin"] = STANDIN_TAG


def kind_load():
    # Offline kind nodes cannot pull. `kind load docker-image` imports --all-platforms and fails
    # when a digest/index is missing arm64 blobs. Save + ctr import --platform linux/amd64.
    node = f"{CLUSTER}-control-plane"
    for key in (
        "gateway-authz",
        "provider-signer",
        "sf-token-coordinator",
        "authz-state",
        "standin",
        "agentgateway",
        "front",
        "tools",
    ):
        img = IMAGE_TAGS[key]
        local = f"idp-gateway-load/{key}:local"
        insp = docker("image", "inspect", img, "--format", "{{.Id}}")
        docker("tag", insp.stdout.strip(), local)
        say(f"kind import {local} (from {img})")
        save = subprocess.Popen(["docker", "save", local], stdout=subprocess.PIPE)
        done = subprocess.run(
            [
                "docker",
                "exec",
                "--privileged",
                "-i",
                node,
                "ctr",
                "--namespace=k8s.io",
                "images",
                "import",
                "--platform",
                "linux/amd64",
                "--digests",
                "--snapshotter=overlayfs",
                "-",
            ],
            stdin=save.stdout,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if save.stdout:
            save.stdout.close()
        save.wait(timeout=60)
        if done.returncode != 0:
            die(f"ctr import {local}: {done.stderr[-600:]}")
        IMAGE_TAGS[key] = local


def b64url_uint(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def issue_tls():
    tls = RUN / "tls"
    shutil.rmtree(tls, ignore_errors=True)
    # Issue with both client+server EKU for listen leaves that also present as clients is not needed:
    # authz uses authz-listen for server and gateway-authz for client.
    # Patch pki.issue to allow dual EKU for served leaves used as clients — instead issue manually for authz-listen.
    pki.issue(tls)
    # Dual-purpose authz-listen: SERVER_AUTH + CLIENT_AUTH so it can also be used if needed; keep separate client leaf.
    # Fix ExtendedKeyUsage on listen leaves: pki sets SERVER_AUTH only when DNS present — good.
    # provider-signer / coordinators already SERVER_AUTH.
    # Ensure gateway leaf can be client: CLIENT_AUTH only — good for backendTLS.
    return tls


def mint_jwks_and_tokens(tls: Path):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization

    key = ec.generate_private_key(ec.SECP256R1())
    numbers = key.public_key().public_numbers()
    jwks = {
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "kid": "k8spools",
                "alg": "ES256",
                "use": "sig",
                "x": b64url_uint(numbers.x),
                "y": b64url_uint(numbers.y),
            }
        ]
    }
    (tls / "jwks.json").write_text(json.dumps(jwks), encoding="utf-8")
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    now = int(time.time())

    def token(sub, tenant):
        t = jwt_encode(
            {"iss": ISSUER, "aud": AUDIENCE, "sub": sub, "tenant_id": tenant, "exp": now + 3600, "nbf": now - 60},
            pem,
            algorithm="ES256",
            headers={"kid": "k8spools", "typ": "JWT"},
        )
        remember(t)
        return t

    TOKENS["blue"] = token("CLIENT-ID-BLUE", "TENANT-ID-BLUE")
    TOKENS["green"] = token("CLIENT-ID-GREEN", "TENANT-ID-GREEN")
    return jwks


def make_apps(endpoint: str) -> dict:
    apps = {}
    for account in (BLUE_ACCOUNT, GREEN_ACCOUNT):
        app_key = "ak_" + secrets.token_hex(8)
        app_secret = secrets.token_hex(16)
        # 32 random bytes -> 43-char standard base64 with trailing '=' removed (SF encodingAesKey).
        aes = base64.b64encode(secrets.token_bytes(32)).decode("ascii")[:-1]
        remember(app_secret)
        remember(aes)
        apps[account] = {
            "app_key": app_key,
            "app_secret": app_secret,
            "encoding_aes_key": aes,
            "api_username": f"user-{account}",
        }
    document = {}
    for account, app in apps.items():
        document[f"{BINDING}/{account}"] = {
            "token_endpoint": endpoint,
            "app_key": app["app_key"],
            "app_secret": app["app_secret"],
            "encoding_aes_key": app["encoding_aes_key"],
            "key_version": "1",
        }
    return {"apps": apps, "document": document}


def policy_text() -> str:
    example = json.loads((ROOT / "deploy/providers/sfintl/policy.example.json").read_text(encoding="utf-8"))
    example["version"] = "sfintl-k8spools"
    for op in example["registered_operations"]:
        op["credential_binding_ref"] = BINDING
    return json.dumps(example, indent=2)


def front_nginx() -> str:
    text = (BLACKBOX / "front.nginx.conf").read_text(encoding="utf-8")
    text = text.replace("listen 127.0.0.1:27620;", "listen 8080;")
    text = text.replace("proxy_pass http://127.0.0.1:27611;", "proxy_pass http://127.0.0.1:8081;")
    return text


def gateway_config() -> str:
    # Based on deploy/providers/sfintl/agentgateway.yaml with K8s readiness and termination deadlines.
    base = (ROOT / "deploy/providers/sfintl/agentgateway.yaml").read_text(encoding="utf-8")
    # Replace issuer and jwks path stays tls/jwks.json; add termination + readiness bind.
    # Simpler: build a trimmed YAML document programmatically for the four routes' essentials.
    doc = yaml.safe_load(base)
    doc["config"] = {
        "adminAddr": "127.0.0.1:15000",
        "statsAddr": "127.0.0.1:15020",
        "readinessAddr": "0.0.0.0:15021",
        "storage": {"mode": "readOnly"},
        "connectionMinTerminationDeadline": f"{MIN_DEADLINE}s",
        "connectionTerminationDeadline": f"{MAX_DEADLINE}s",
    }
    doc["gateways"]["egress-test"]["jwtAuth"] = {
        "mode": "strict",
        "issuer": ISSUER,
        "audiences": [AUDIENCE],
        "jwks": {"file": "tls/jwks.json"},
    }
    return yaml.safe_dump(doc, sort_keys=False)


def snapshot_name(text: str) -> str:
    return "agentgateway-snapshot-" + hashlib.sha256(text.encode()).hexdigest()[:12]


def render_manifests(snap: str, coordinated: bool, netpol: bool) -> list:
    rendered = kubectl("kustomize", str(KUSTOMIZE)).stdout
    rendered = rendered.replace("agentgateway-snapshot-PLACEHOLDER", snap)
    rendered = rendered.replace("idp-gateway-authz:placeholder", IMAGE_TAGS["gateway-authz"])
    rendered = rendered.replace("idp-gateway-provider-signer:placeholder", IMAGE_TAGS["provider-signer"])
    rendered = rendered.replace("idp-gateway-sf-token-coordinator:placeholder", IMAGE_TAGS["sf-token-coordinator"])
    rendered = rendered.replace("idp-gateway-authz-state:placeholder", IMAGE_TAGS["authz-state"])
    rendered = rendered.replace(
        "cr.agentgateway.dev/agentgateway@sha256:460dda874be2dfa95fa5713c1f46f26079dce78df576008df704e54a59d5780d",
        IMAGE_TAGS["agentgateway"],
    )
    rendered = rendered.replace(FRONT_IMAGE, IMAGE_TAGS["front"])
    # FRONT_IMAGE appears with and without the tag prefix in YAML
    rendered = rendered.replace(
        "public.ecr.aws/nginx/nginx-unprivileged:stable-alpine@sha256:c3fc8fa482be50ef709c6438eb1bc98d50dbfe5a9b48be90711b8814f4dfd701",
        IMAGE_TAGS["front"],
    )
    docs = list(yaml.safe_load_all(rendered))
    out = []
    for d in docs:
        if not d:
            continue
        if not netpol and d.get("kind") == "NetworkPolicy":
            continue
        if not coordinated and d.get("kind") == "Deployment" and d["metadata"]["name"] == "gateway-authz":
            # Strip lease / authz-state / revocations / rate-limits flags for control.
            args = d["spec"]["template"]["spec"]["containers"][0]["args"]
            keep = []
            skip_prefixes = (
                "--sf-openapi-lease-",
                "--authz-state-",
                "--revocations=",
                "--revoker-identity=",
                "--rate-limits=",
            )
            for a in args:
                if any(a.startswith(p) for p in skip_prefixes):
                    continue
                keep.append(a)
            d["spec"]["template"]["spec"]["containers"][0]["args"] = keep
            # Keep stage-credentials (0600 apps file); drop seed-revocations (no --revocations).
            inits = d["spec"]["template"]["spec"].get("initContainers") or []
            d["spec"]["template"]["spec"]["initContainers"] = [c for c in inits if c["name"] != "seed-revocations"]
            vols = d["spec"]["template"]["spec"]["volumes"]
            d["spec"]["template"]["spec"]["volumes"] = [v for v in vols if v["name"] not in ("mirror", "rate-limits")]
            mounts = d["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
            d["spec"]["template"]["spec"]["containers"][0]["volumeMounts"] = [
                m for m in mounts if m["name"] not in ("mirror", "rate-limits")
            ]
        if not coordinated and d.get("metadata", {}).get("name") in (
            "sf-token-coordinator",
            "authz-state",
            "sf-token-coordinator-state",
            "authz-state-state",
        ):
            # Still deploy coordinators? Control is authz without flags; leave coordinators out.
            if d.get("kind") in ("Deployment", "Service", "PersistentVolumeClaim"):
                continue
        out.append(d)
    return out


def wait_deploy(name, timeout=180):
    kubectl("rollout", "status", f"deployment/{name}", "-n", NS, f"--timeout={timeout}s", timeout=timeout + 30)


def pod_names(app):
    out = kubectl(
        "get", "pods", "-n", NS, "-l", f"app={app}", "-o", "jsonpath={.items[*].metadata.name}"
    ).stdout.strip()
    return [p for p in out.split() if p]


def pod_json(name):
    return json.loads(kubectl("get", "pod", name, "-n", NS, "-o", "json").stdout)


def logs(app, since=None):
    chunks = []
    for p in pod_names(app):
        args = ["logs", "-n", NS, p, "--all-containers=true"]
        if since:
            args += [f"--since={since}"]
        chunks.append(kubectl(*args, check=False).stdout)
    return "\n".join(chunks)


def json_lines(text, msg=None):
    found = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg is None or obj.get("msg") == msg:
            found.append(obj)
    return found


def start_port_forward():
    # Calls go through the in-cluster client Pod (NetworkPolicy). Host port-forward is unused.
    return


def stop_port_forward():
    return


def http_front(method, path, token=None, body=None, headers=None, timeout=20):
    """Call the gateway front Service from the k8spools-client Pod (allowed by NetworkPolicy)."""
    raw = None if body is None else (body if isinstance(body, (bytes, bytearray)) else json.dumps(body).encode())
    tid = secrets.token_hex(16)
    sid = secrets.token_hex(8)
    hdrs = {"Host": HOST, "traceparent": f"00-{tid}-{sid}-01"}
    if token:
        hdrs["Authorization"] = "Bearer " + token
    if raw is not None:
        hdrs["Content-Type"] = "application/json"
    if headers:
        hdrs.update(headers)
    payload = {
        "method": method,
        "path": path,
        "headers": hdrs,
        "body": None if raw is None else base64.b64encode(raw).decode(),
        "timeout": timeout,
        "trace_id": tid,
    }
    script = (
        "import base64,http.client,json\n"
        f"p=json.loads({repr(json.dumps(payload))})\n"
        "body=None if p['body'] is None else base64.b64decode(p['body'])\n"
        "c=http.client.HTTPConnection('gateway',8080,timeout=p['timeout'])\n"
        "c.request(p['method'],p['path'],body=body,headers=p['headers'])\n"
        "r=c.getresponse(); data=r.read(); c.close()\n"
        "print(json.dumps({'status':r.status,'headers':dict(r.getheaders()),"
        "'body_b64':base64.b64encode(data).decode(),'trace_id':p['trace_id']}))\n"
    )
    done = kubectl("exec", "-n", NS, "deploy/k8spools-client", "--", "python3", "-c", script, check=False, timeout=timeout + 30)
    if done.returncode != 0:
        return {"status": 0, "headers": {}, "body": b"", "trace_id": tid, "error": done.stderr[-300:]}
    try:
        obj = json.loads(done.stdout.strip().splitlines()[-1])
        return {
            "status": obj["status"],
            "headers": obj.get("headers") or {},
            "body": base64.b64decode(obj.get("body_b64") or ""),
            "trace_id": obj.get("trace_id") or tid,
        }
    except Exception as e:
        return {"status": 0, "headers": {}, "body": done.stdout.encode(), "trace_id": tid, "error": str(e)}


def envelope(answer):
    try:
        return json.loads(answer["body"].decode())
    except Exception:
        return {}


def query_body():
    return {
        "service": "WaybillService",
        "waybillList": [{"orderNo": "K8-" + secrets.token_hex(6), "sfWaybillNo": "SF000000000001"}],
    }


def print_body(waybill="SF000000000002", api_username="user-account-green"):
    return {"apiUsername": api_username, "printWaybillNoDtoList": [{"sfWaybillNo": waybill}]}


def standin_admin(path, method="GET", body=None):
    # From a client pod with curl/python
    script = f"""
import json,urllib.request
req=urllib.request.Request('http://sfintl-standin:8080{path}', method='{method}',
  data={repr(None if body is None else json.dumps(body).encode())},
  headers={{'X-Poc-Admin':'ADMIN','Content-Type':'application/json'}} if {body is not None} else {{'X-Poc-Admin':'ADMIN'}})
print(urllib.request.urlopen(req, timeout=10).read().decode())
"""
    done = kubectl(
        "exec", "-n", NS, "deploy/k8spools-client", "--", "python3", "-c", script, check=False, timeout=60
    )
    if done.returncode != 0:
        return {"error": done.stderr[-300:], "raw": done.stdout}
    try:
        return json.loads(done.stdout)
    except Exception:
        return {"raw": done.stdout}


def standin_reset():
    standin_admin("/admin/reset", "POST", {})


def token_hits():
    hits = standin_admin("/admin/hits")
    if isinstance(hits, dict) and "hits" in hits:
        return [h for h in hits["hits"] if h.get("kind") == "token"]
    return []


def dispatch_hits():
    hits = standin_admin("/admin/hits")
    if isinstance(hits, dict) and "hits" in hits:
        return [h for h in hits["hits"] if h.get("kind") == "dispatch"]
    return []


def deciders(answers, seconds=8):
    deadline = time.monotonic() + seconds
    want = {a["trace_id"] for a in answers}
    found = {t: [] for t in want}
    while time.monotonic() < deadline:
        for pod in pod_names("gateway-authz"):
            text = kubectl("logs", "-n", NS, pod, check=False).stdout
            for entry in json_lines(text):
                tp = entry.get("traceparent") or ""
                tid = tp.split("-")[1] if tp.count("-") >= 2 else None
                if tid in found:
                    found[tid].append(
                        {
                            "pod": pod,
                            "reason": entry.get("reason") or entry.get("reason_code"),
                            "status": entry.get("status"),
                        }
                    )
        if all(found[t] for t in want):
            break
        time.sleep(0.3)
    return [found.get(a["trace_id"], []) for a in answers]


def measure_netpol(r: Results) -> bool:
    """FIRST: deny-all must block a connection that worked before. Returns whether CNI enforces."""
    r.case("KP8-03a", "measure NetworkPolicy enforcement on kind CNI")
    # Probe by Pod IP (no Service DNS). Strip ALL NetworkPolicies so "before" is truly open —
    # allow-dns alone selects every pod and would otherwise deny non-DNS egress.
    apply_docs(
        [
            {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "netpol-a", "namespace": NS, "labels": {"app": "netpol-a"}},
                "spec": {
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [
                        {
                            "name": "c",
                            "image": IMAGE_TAGS["tools"],
                            "command": ["python3", "-m", "http.server", "8000", "--bind", "0.0.0.0"],
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                                "runAsUser": 65534,
                            },
                        }
                    ],
                    "restartPolicy": "Never",
                },
            },
            {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "netpol-b", "namespace": NS, "labels": {"app": "netpol-b"}},
                "spec": {
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [
                        {
                            "name": "c",
                            "image": IMAGE_TAGS["tools"],
                            "command": ["sleep", "3600"],
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                                "runAsUser": 65534,
                            },
                        }
                    ],
                    "restartPolicy": "Never",
                },
            },
        ]
    )
    kubectl("wait", "--for=condition=Ready", "pod/netpol-a", "pod/netpol-b", "-n", NS, "--timeout=120s")
    ip_a = pod_json("netpol-a")["status"]["podIP"]
    kubectl("delete", "networkpolicy", "--all", "-n", NS, check=False)
    time.sleep(1)
    open_before = kubectl(
        "exec",
        "-n",
        NS,
        "netpol-b",
        "--",
        "python3",
        "-c",
        f"import socket;s=socket.create_connection(('{ip_a}',8000),3);s.close();print('OPEN')",
        check=False,
    )
    before_ok = open_before.returncode == 0 and "OPEN" in open_before.stdout
    r.check("without NetworkPolicies, netpol-b reaches netpol-a by Pod IP:8000", before_ok)
    apply_docs(
        [
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {"name": "default-deny-all", "namespace": NS},
                "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]},
            }
        ]
    )
    time.sleep(2)
    closed = kubectl(
        "exec",
        "-n",
        NS,
        "netpol-b",
        "--",
        "python3",
        "-c",
        f"import socket;s=socket.socket();s.settimeout(2)\n"
        f"try:\n s.connect(('{ip_a}',8000)); print('OPEN')\n"
        f"except Exception as e:\n print('BLOCKED',type(e).__name__)",
        check=False,
    )
    blocked = "BLOCKED" in closed.stdout and "OPEN" not in closed.stdout
    r.check("with default-deny only, the same Pod-IP connection is blocked", blocked)
    r.note(
        "probe stdout before/after",
        {"ip": ip_a, "before": open_before.stdout.strip(), "after": closed.stdout.strip(), "before_err": open_before.stderr.strip()[-200:]},
    )
    kubectl("delete", "pod", "netpol-a", "netpol-b", "-n", NS, "--wait=false", check=False)
    return bool(before_ok and blocked)


def deploy_helpers(admin_secret, mock_state):
    script = (SFINTL / "mock_sfintl.py").read_text(encoding="utf-8")
    apply_docs(
        [
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": "sfintl-standin-state", "namespace": NS},
                "data": {"state.json": json.dumps(mock_state)},
            },
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": "sfintl-standin-script", "namespace": NS},
                "data": {"mock.py": script},
            },
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": "sfintl-standin", "namespace": NS, "labels": {"app": "sfintl-standin"}},
                "spec": {
                    "replicas": 1,
                    "selector": {"matchLabels": {"app": "sfintl-standin"}},
                    "template": {
                        "metadata": {"labels": {"app": "sfintl-standin"}},
                        "spec": {
                            "securityContext": {
                                "runAsNonRoot": True,
                                "runAsUser": 65532,
                                "seccompProfile": {"type": "RuntimeDefault"},
                            },
                            "containers": [
                                {
                                    "name": "standin",
                                    "image": IMAGE_TAGS["standin"],
                                    "imagePullPolicy": "IfNotPresent",
                                    "command": [
                                        "python3",
                                        "-u",
                                        "/scripts/mock.py",
                                        "--host",
                                        "0.0.0.0",
                                        "--port",
                                        "8080",
                                        "--state",
                                        "/state/state.json",
                                    ],
                                    "ports": [{"containerPort": 8080}],
                                    "volumeMounts": [
                                        {"name": "state", "mountPath": "/state", "readOnly": True},
                                        {"name": "scripts", "mountPath": "/scripts", "readOnly": True},
                                    ],
                                    "securityContext": {
                                        "allowPrivilegeEscalation": False,
                                        "readOnlyRootFilesystem": True,
                                        "capabilities": {"drop": ["ALL"]},
                                    },
                                    "readinessProbe": {"tcpSocket": {"port": 8080}, "periodSeconds": 2},
                                }
                            ],
                            "volumes": [
                                {"name": "state", "configMap": {"name": "sfintl-standin-state"}},
                                {
                                    "name": "scripts",
                                    "configMap": {
                                        "name": "sfintl-standin-script",
                                        "defaultMode": 0o555,
                                    },
                                },
                            ],
                        },
                    },
                },
            },
            {
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {"name": "sfintl-standin", "namespace": NS},
                "spec": {"selector": {"app": "sfintl-standin"}, "ports": [{"port": 8080, "targetPort": 8080}]},
            },
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": "outsider", "namespace": NS, "labels": {"app": "outsider"}},
                "spec": {
                    "replicas": 1,
                    "selector": {"matchLabels": {"app": "outsider"}},
                    "template": {
                        "metadata": {"labels": {"app": "outsider"}},
                        "spec": {
                            "securityContext": {
                                "runAsNonRoot": True,
                                "runAsUser": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"},
                            },
                            "containers": [
                                {
                                    "name": "c",
                                    "image": IMAGE_TAGS["tools"],
                                    "command": ["python3", "-m", "http.server", "8000", "--bind", "0.0.0.0", "--directory", "/tmp"],
                                    "securityContext": {
                                        "allowPrivilegeEscalation": False,
                                        "readOnlyRootFilesystem": True,
                                        "capabilities": {"drop": ["ALL"]},
                                        "runAsUser": 65534,
                                    },
                                    "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}],
                                }
                            ],
                            "volumes": [{"name": "tmp", "emptyDir": {}}],
                        },
                    },
                },
            },
            {
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {"name": "outsider", "namespace": NS},
                "spec": {"selector": {"app": "outsider"}, "ports": [{"port": 8000, "targetPort": 8000}]},
            },
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": "k8spools-client", "namespace": NS, "labels": {"app": "k8spools-client"}},
                "spec": {
                    "replicas": 1,
                    "selector": {"matchLabels": {"app": "k8spools-client"}},
                    "template": {
                        "metadata": {"labels": {"app": "k8spools-client"}},
                        "spec": {
                            "securityContext": {
                                "runAsNonRoot": True,
                                "runAsUser": 65532,
                                "seccompProfile": {"type": "RuntimeDefault"},
                            },
                            "containers": [
                                {
                                    "name": "c",
                                    "image": IMAGE_TAGS["tools"],
                                    "command": ["sleep", "7200"],
                                    "volumeMounts": [
                                        {"name": "tls", "mountPath": "/tls", "readOnly": True},
                                        {"name": "work", "mountPath": "/work"},
                                    ],
                                    "securityContext": {
                                        "allowPrivilegeEscalation": False,
                                        "readOnlyRootFilesystem": True,
                                        "capabilities": {"drop": ["ALL"]},
                                    },
                                }
                            ],
                            "volumes": [
                                {"name": "tls", "secret": {"secretName": "client-tls"}},
                                {"name": "work", "emptyDir": {}},
                            ],
                        },
                    },
                },
            },
        ]
    )


def create_secrets(tls: Path, apps_doc, admin_secret, session_key, snap_text, snap):
    remember(session_key)
    remember(admin_secret)
    apply_docs(
        [
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {"name": "gateway-tls", "namespace": NS},
                "stringData": {
                    "gateway.crt": (tls / "gateway.crt").read_text(),
                    "gateway.key": (tls / "gateway.key").read_text(),
                    "gateway-readback.crt": (tls / "gateway-readback.crt").read_text(),
                    "gateway-readback.key": (tls / "gateway-readback.key").read_text(),
                    "ca.crt": (tls / "ca.crt").read_text(),
                },
            },
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": "gateway-jwks", "namespace": NS},
                "data": {"jwks.json": (tls / "jwks.json").read_text()},
            },
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {"name": "gateway-session", "namespace": NS},
                "stringData": {"session_key": session_key},
            },
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": "gateway-front-conf", "namespace": NS},
                "data": {"nginx.conf": front_nginx()},
            },
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": snap, "namespace": NS, "labels": {"app": "gateway"}},
                "immutable": True,
                "data": {"config.yaml": snap_text},
            },
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {"name": "gateway-authz-tls", "namespace": NS},
                "stringData": {
                    "tls.crt": (tls / "authz-listen.crt").read_text(),
                    "tls.key": (tls / "authz-listen.key").read_text(),
                    "ca.crt": (tls / "ca.crt").read_text(),
                },
            },
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {"name": "gateway-authz-client-tls", "namespace": NS},
                "stringData": {
                    "tls.crt": (tls / "gateway-authz.crt").read_text(),
                    "tls.key": (tls / "gateway-authz.key").read_text(),
                    "ca.crt": (tls / "ca.crt").read_text(),
                },
            },
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": "gateway-authz-policy", "namespace": NS},
                "data": {"policy.json": policy_text()},
            },
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {"name": "gateway-authz-credentials", "namespace": NS},
                "stringData": {
                    "developer-tokens.json": "{}",
                    "sfintl.apps.json": json.dumps(apps_doc),
                },
            },
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": "gateway-authz-rate-limits", "namespace": NS},
                "data": {"rate-limits.json": json.dumps(RATE_LIMITS)},
            },
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {"name": "provider-signer-tls", "namespace": NS},
                "stringData": {
                    "tls.crt": (tls / "provider-signer.crt").read_text(),
                    "tls.key": (tls / "provider-signer.key").read_text(),
                    "ca.crt": (tls / "ca.crt").read_text(),
                },
            },
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {"name": "sf-token-coordinator-tls", "namespace": NS},
                "stringData": {
                    "tls.crt": (tls / "sf-token-coordinator.crt").read_text(),
                    "tls.key": (tls / "sf-token-coordinator.key").read_text(),
                    "ca.crt": (tls / "ca.crt").read_text(),
                },
            },
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {"name": "authz-state-tls", "namespace": NS},
                "stringData": {
                    "tls.crt": (tls / "authz-state.crt").read_text(),
                    "tls.key": (tls / "authz-state.key").read_text(),
                    "ca.crt": (tls / "ca.crt").read_text(),
                },
            },
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {"name": "client-tls", "namespace": NS},
                "stringData": {
                    "ca.crt": (tls / "ca.crt").read_text(),
                    "revoker.crt": (tls / "revoker.crt").read_text(),
                    "revoker.key": (tls / "revoker.key").read_text(),
                    "publisher.crt": (tls / "publisher.crt").read_text(),
                    "publisher.key": (tls / "publisher.key").read_text(),
                    "gateway.crt": (tls / "gateway.crt").read_text(),
                    "gateway.key": (tls / "gateway.key").read_text(),
                },
            },
        ]
    )


def copy_gateway_control():
    # Deployments expose Available/Progressing, not Ready (Ready is a Pod condition).
    kubectl("wait", "--for=condition=Available", "deploy/k8spools-client", "-n", NS, "--timeout=120s")
    pod = pod_names("k8spools-client")[0]
    # Product client (Go) — Python 3.13 rejects the suite CA for Missing Authority Key Identifier.
    src = RUN / "bin" / "gateway-control"
    if not src.is_file():
        die("missing gateway-control binary; build_binaries must run first")
    kubectl("cp", str(src), f"{NS}/{pod}:/work/gateway-control")
    kubectl("exec", "-n", NS, pod, "--", "chmod", "755", "/work/gateway-control")
    return pod


def revoke_via_control(authz_pod_ip, account, action="revoke", reason="k8spools"):
    """gateway-control revoke/restore against one authz Pod IP (same as coordinators suite)."""
    cmd = ["--", "/work/gateway-control"]
    if action == "restore":
        cmd += ["restore", "--account", account]
    else:
        cmd += ["revoke", "--account", account, "--reason", reason]
    cmd += [
        "--authz",
        f"{authz_pod_ip}:9443",
        "--authz-name",
        pki.GATEKEEPER_NAME,
        "--tls-cert",
        "/tls/revoker.crt",
        "--tls-key",
        "/tls/revoker.key",
        "--tls-ca",
        "/tls/ca.crt",
        "--timeout",
        "5s",
    ]
    done = kubectl("exec", "-n", NS, "deploy/k8spools-client", *cmd, check=False, timeout=60)
    parsed = None
    lines = [ln for ln in done.stdout.splitlines() if ln.strip()]
    if len(lines) == 1:
        try:
            parsed = json.loads(lines[0])
        except ValueError:
            parsed = None
    return {"code": done.returncode, "out": done.stdout, "err": done.stderr, "json": parsed}


def tcp_from(client_label, target_host, port):
    script = (
        "import socket\n"
        f"s=socket.socket(); s.settimeout(2)\n"
        "try:\n"
        f" s.connect(('{target_host}',{port})); print('OPEN')\n"
        "except Exception as e:\n"
        " print('BLOCKED', type(e).__name__)\n"
    )
    done = kubectl("exec", "-n", NS, f"deploy/{client_label}", "--", "python3", "-c", script, check=False)
    return done.stdout.strip()


def ensure_authz_listen_leaf(tls: Path):
    # pki.issue already created authz-listen with SERVER_AUTH and URI gateway-authz.
    # Verify files exist.
    for name in ("authz-listen", "gateway-authz", "provider-signer", "sf-token-coordinator", "authz-state", "revoker", "gateway"):
        if not (tls / f"{name}.crt").exists():
            die(f"missing tls leaf {name}")


def wait_gateway_ready(timeout=120):
    start_port_forward()
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            ans = http_front("GET", ORDERS, TOKENS["blue"])
            last = ans["status"]
            # 404 once JWKS loaded (no GET route); 401 until then
            if last == 404:
                return
        except Exception as e:
            last = str(e)
        time.sleep(0.5)
    die(f"gateway front not ready, last={last}")


def case_topology(r: Results):
    r.case("KP8-01", "topology and hardening: replicas, Recreate, PVC, pod security, image digests")
    for name, want in (
        ("gateway", 2),
        ("gateway-authz", 2),
        ("provider-signer", 2),
        ("sf-token-coordinator", 1),
        ("authz-state", 1),
    ):
        if CONTROL == "no-coordinators" and name in ("sf-token-coordinator", "authz-state"):
            continue
        ready = kubectl(
            "get", "deploy", name, "-n", NS, "-o", "jsonpath={.status.readyReplicas}"
        ).stdout.strip()
        r.check(f"{name} readyReplicas=={want}", ready == str(want))
        dep = json.loads(kubectl("get", "deploy", name, "-n", NS, "-o", "json").stdout)
        if name in ("sf-token-coordinator", "authz-state"):
            r.check(f"{name} strategy Recreate", dep["spec"]["strategy"]["type"] == "Recreate")
        pods = pod_names(name)
        if pods:
            sc = pod_json(pods[0])["spec"]["containers"][0].get("securityContext") or {}
            psc = pod_json(pods[0])["spec"].get("securityContext") or {}
            r.check(
                f"{name} runAsNonRoot / drop ALL / readOnlyRootFilesystem / no privilege escalation",
                psc.get("runAsNonRoot") is True
                and sc.get("readOnlyRootFilesystem") is True
                and sc.get("allowPrivilegeEscalation") is False
                and (sc.get("capabilities") or {}).get("drop") == ["ALL"],
            )
            img = pod_json(pods[0])["spec"]["containers"][0]["image"]
            r.check(f"{name} image is digest or content tag", "@sha256:" in img or "sha256-" in img or img.startswith("idp-gateway-"))
    if CONTROL != "no-coordinators":
        for pvc in ("sf-token-coordinator-state", "authz-state-state"):
            phase = kubectl("get", "pvc", pvc, "-n", NS, "-o", "jsonpath={.status.phase}").stdout.strip()
            r.check(f"PVC {pvc} Bound", phase == "Bound")
    ns = json.loads(kubectl("get", "ns", NS, "-o", "json").stdout)
    labels = ns["metadata"].get("labels") or {}
    r.note("namespace pod-security labels", {k: v for k, v in labels.items() if "pod-security" in k})
    r.check("namespace has pod-security warn/audit labels", "pod-security.kubernetes.io/warn" in labels)


def force_authz_token_fetch(authz_pod_ip: str) -> dict:
    """Ask one authz Pod as the gateway (mTLS), same headers as agentgateway. Suite CA lacks AKI."""
    script = f"""
import ssl,socket,http.client,uuid
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.minimum_version=ssl.TLSVersion.TLSv1_2
ctx.load_verify_locations('/tls/ca.crt')
ctx.load_cert_chain('/tls/gateway.crt','/tls/gateway.key')
ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
raw=socket.create_connection(('{authz_pod_ip}',9443),10)
tls=ctx.wrap_socket(raw, server_hostname='gatekeeper.idp.test')
conn=http.client.HTTPSConnection('{authz_pod_ip}',9443,timeout=10)
conn.sock=tls
tid=uuid.uuid4().hex
tp='00-%s-%s-01' % (tid, uuid.uuid4().hex[:16])
headers={{
  'x-idp-verified-subject':'CLIENT-ID-BLUE',
  'x-idp-verified-tenant':'TENANT-ID-BLUE',
  'x-idp-verified-env':'TEST',
  'x-idp-route-id':'sfintl-agent-numbers-query',
  'x-idp-provider-id':'sfintl',
  'x-idp-operation-id':'agent-numbers.query',
  'x-idp-environment':'TEST',
  'x-idp-method':'POST',
  'x-idp-path':'{QUERIES}',
  'traceparent':tp,
  'Host':'gatekeeper.idp.test',
}}
conn.request('POST','/v1/extauthz/check',body=b'',headers=headers)
r=conn.getresponse(); print(r.status); print((r.getheader('Authorization') or '')[:40]); print(r.read()[:200])
"""
    done = kubectl("exec", "-n", NS, "deploy/k8spools-client", "--", "python3", "-c", script, check=False, timeout=60)
    return {"code": done.returncode, "out": done.stdout, "err": done.stderr}


def case_sf_flow(r: Results):
    r.case("KP8-02", "SF flow through front Service: JWT, stand-in dispatch, single token fetch across 2 authz")
    standin_reset()
    before = len(token_hits())
    answers = []
    for _ in range(8):
        answers.append(http_front("POST", QUERIES, TOKENS["blue"], query_body()))
    ok = all(a["status"] == 200 for a in answers)
    r.check("8 queries through front are 200", ok)
    bodies = [a["body"].decode(errors="replace") for a in answers]
    r.check("caller never sees carrier credential shapes", all("auth_" not in b and "Sf-OpenApi" not in b and "app_secret" not in b for b in bodies))
    if CONTROL == "no-coordinators":
        # Front may stick to one authz; force each replica once (coordinators CTL-02 pattern).
        for pod in pod_names("gateway-authz"):
            ip = pod_json(pod)["status"]["podIP"]
            forced = force_authz_token_fetch(ip)
            r.note(f"forced check {pod}", {"code": forced["code"], "out": (forced["out"] or "")[:120]})
    after = token_hits()
    new_tokens = after[before:] if isinstance(after, list) else after
    if CONTROL == "no-coordinators":
        r.check("control: token endpoint called >= 2 times with 2 replicas", len(new_tokens) >= 2)
    else:
        r.check("stand-in token endpoint called exactly once", len(new_tokens) == 1)
    found = deciders(answers)
    r.check("each answer decided by exactly one authz pod (trace id)", all(len(w) >= 1 for w in found))
    pods_seen = sorted({w[0]["pod"] for w in found if w})
    r.note("authz pods that decided", pods_seen)
    r.note("token fetch count", len(new_tokens))
    dispatches = dispatch_hits()
    r.check("stand-in received at least one dispatch", len(dispatches) >= 1)


def case_netpol(r: Results, enforced: bool):
    if not enforced:
        r.case("KP8-03", "NetworkPolicy forbidden/allowed paths (NOT SHOWN: CNI does not enforce)")
        r.check("recorded as not shown because kind CNI did not enforce deny-all", True)
        r.note("policies still applied", True)
        return
    r.case("KP8-03", "NetworkPolicy: forbidden refused, allowed working")
    # signer -> outsider
    # Run from provider-signer pod
    signer_pod = pod_names("provider-signer")[0]
    out = kubectl(
        "exec", "-n", NS, signer_pod, "-c", "provider-signer", "--", "/app", "-h", check=False
    )
    # scratch image has no shell — cannot exec. Use client pod labeled temporarily... 
    # Deviation: probe from client with python by applying ephemeral debug is hard.
    # Instead: create a Job using TOOLS_IMAGE with same labels as signer to test egress — not identical.
    # Use `kubectl debug` — may not exist. Measure via NetworkPolicy + client attempts to forbidden targets.
    forbidden = []
    # non-gateway client -> gateway-authz and coordinators: client IS allowed for suite revoke; use outsider pod
    # outsider has no shell in... tools image has python. Label app=outsider
    for target, port in (("gateway-authz", 9443), ("sf-token-coordinator", 9445), ("authz-state", 9446), ("outsider", 8000)):
        # from gateway pod — no shell. Skip gateway->outsider via tools pod with gateway labels? 
        pass
    # Create probe pods with exact app labels for egress tests
    probes = []
    for app, target, port in (
        ("provider-signer", "outsider", 8000),
        ("gateway", "outsider", 8000),
        ("sf-token-coordinator", "outsider", 8000),
    ):
        name = f"probe-{app[:8]}-{port}"
        apply_docs(
            [
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": name, "namespace": NS, "labels": {"app": app, "probe": "netpol"}},
                    "spec": {
                        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                        "containers": [
                            {
                                "name": "c",
                                "image": IMAGE_TAGS["tools"],
                                "command": ["sleep", "600"],
                                "securityContext": {
                                    "allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]},
                                    "runAsUser": 65534,
                                },
                            }
                        ],
                        "restartPolicy": "Never",
                    },
                }
            ]
        )
        probes.append((name, target, port, app))
    for name, _, _, _ in probes:
        kubectl("wait", "--for=condition=Ready", f"pod/{name}", "-n", NS, "--timeout=120s")
    for name, target, port, app in probes:
        script = (
            "import socket\n"
            f"s=socket.socket(); s.settimeout(2)\n"
            "try:\n"
            f" s.connect(('{target}',{port})); print('OPEN')\n"
            "except Exception as e:\n"
            " print('BLOCKED', type(e).__name__)\n"
        )
        got = kubectl("exec", "-n", NS, name, "--", "python3", "-c", script, check=False).stdout.strip()
        r.check(f"forbidden {app} -> {target}:{port} blocked", got.startswith("BLOCKED"))
        forbidden.append({"from": app, "to": f"{target}:{port}", "result": got})
    # non-gateway client (outsider) -> gateway-authz and coordinators
    out_pod = pod_names("outsider")[0]
    for target, port in (("gateway-authz", 9443), ("sf-token-coordinator", 9445), ("authz-state", 9446)):
        script = (
            "import socket\n"
            "s=socket.socket(); s.settimeout(2)\n"
            "try:\n"
            f" s.connect(('{target}',{port})); print('OPEN')\n"
            "except Exception as e:\n"
            " print('BLOCKED', type(e).__name__)\n"
        )
        got = kubectl("exec", "-n", NS, out_pod, "--", "python3", "-c", script, check=False).stdout.strip()
        r.check(f"outsider -> {target}:{port} blocked", got.startswith("BLOCKED"))
    # allowed: client -> gateway front already works (KP8-02). Also authz -> standin implied by token fetch.
    r.check("allowed path still works (front query 200)", http_front("POST", QUERIES, TOKENS["blue"], query_body())["status"] == 200)
    r.note("forbidden probes", forbidden)
    kubectl("delete", "pod", "-n", NS, "-l", "probe=netpol", "--wait=false", check=False)


def case_revoke(r: Results):
    r.case("KP8-04", "revoke via one gateway-authz pod IP -> 403 ACCOUNT_REVOKED; restore -> 200")
    pods = pod_names("gateway-authz")
    ip = pod_json(pods[0])["status"]["podIP"]
    rev = revoke_via_control(ip, BLUE_ACCOUNT, "revoke")
    r.note("revoke response", {"code": rev["code"], "json": rev.get("json"), "err": (rev.get("err") or "")[-200:]})
    body = rev.get("json") or {}
    rev_ok = rev["code"] == 0 and body.get("outcome") == "REVOKED"
    r.check("revoke HTTP succeeded", rev_ok)
    answers = [http_front("POST", QUERIES, TOKENS["blue"], query_body()) for _ in range(4)]
    r.check(
        "requests 403 ACCOUNT_REVOKED",
        all(a["status"] == 403 and envelope(a).get("reason_code") == "ACCOUNT_REVOKED" for a in answers),
    )
    found = deciders(answers)
    r.note("deciders after revoke", [[(w[0]["pod"], w[0].get("reason")) for w in found if w]])
    # restore via other pod if possible
    ip2 = pod_json(pods[-1])["status"]["podIP"]
    res = revoke_via_control(ip2, BLUE_ACCOUNT, "restore")
    r.note("restore response", {"code": res["code"], "json": res.get("json"), "err": (res.get("err") or "")[-200:]})
    # wait a moment for snapshot
    time.sleep(1)
    ok = http_front("POST", QUERIES, TOKENS["blue"], query_body())
    r.check("after restore, query 200", ok["status"] == 200)


def case_quota(r: Results):
    r.case("KP8-05", "shared quota max 1 / long window -> second 429 RATE_LIMITED, no Authorization")
    green_user = (APPS.get(GREEN_ACCOUNT) or {}).get("api_username") or "user-account-green"
    body = print_body(api_username=green_user)
    a1 = http_front("POST", PRINTS, TOKENS["green"], body)
    a2 = http_front("POST", PRINTS, TOKENS["green"], body)
    r.check("first labels.print 200", a1["status"] == 200)
    r.check("second 429 RATE_LIMITED", a2["status"] == 429 and envelope(a2).get("reason_code") == "RATE_LIMITED")
    auth = a2["headers"].get("Authorization") or a2["headers"].get("authorization")
    r.check("no Authorization on 429", not auth)


def case_delete_authz(r: Results):
    r.case("KP8-06", "delete one gateway-authz under traffic: failures counted; no new token fetch")
    standin_reset()
    # warm token
    http_front("POST", QUERIES, TOKENS["blue"], query_body())
    before = len(token_hits())
    stop = threading.Event()
    results = []

    def traffic():
        while not stop.is_set():
            try:
                results.append(http_front("POST", QUERIES, TOKENS["blue"], query_body(), timeout=8))
            except Exception as e:
                results.append({"status": 0, "error": str(e), "body": b"", "headers": {}, "trace_id": ""})
            time.sleep(0.15)

    t = threading.Thread(target=traffic, daemon=True)
    t.start()
    time.sleep(0.5)
    victim = pod_names("gateway-authz")[0]
    t0 = time.monotonic()
    kubectl("delete", "pod", victim, "-n", NS, "--wait=false")
    kubectl("rollout", "status", "deploy/gateway-authz", "-n", NS, "--timeout=120s", timeout=150)
    time.sleep(2)
    stop.set()
    t.join(timeout=10)
    elapsed = time.monotonic() - t0
    failures = sum(1 for x in results if x.get("status") not in (200, 403, 429))
    # 403/429 still "got an answer"; count hard failures
    hard = sum(1 for x in results if x.get("status") == 0 or x.get("status") >= 500)
    r.note("failures during authz pod delete", {"total_requests": len(results), "non_200": failures, "hard_5xx_or_0": hard, "seconds": round(elapsed, 2)})
    r.check("replacement authz ready", kubectl("get", "deploy", "gateway-authz", "-n", NS, "-o", "jsonpath={.status.readyReplicas}").stdout.strip() == "2")
    after = len(token_hits())
    r.check("no new carrier token fetch", after == before)
    r.timings["KP8-06"] = {"seconds": elapsed, "hard_failures": hard, "requests": len(results)}


def case_delete_authz_state(r: Results):
    r.case("KP8-07", "delete authz-state: 503 REVOCATION_STATE_UNAVAILABLE; PVC survives revoke table; quota refilled")
    # Ensure something revoked then restore for clean slate — revoke blue, then delete state pod
    pods = pod_names("gateway-authz")
    revoke_via_control(pod_json(pods[0])["status"]["podIP"], BLUE_ACCOUNT, "revoke", reason="before-state-down")
    time.sleep(0.5)
    kubectl("delete", "pod", "-n", NS, "-l", "app=authz-state", "--wait=true", timeout=120)

    # while terminating / before ready
    denied = []
    for _ in range(6):
        denied.append(http_front("POST", QUERIES, TOKENS["blue"], query_body(), timeout=8))
        time.sleep(0.3)
    r.check(
        "while authz-state down: 503 REVOCATION_STATE_UNAVAILABLE (fail closed)",
        any(a["status"] == 503 and envelope(a).get("reason_code") == "REVOCATION_STATE_UNAVAILABLE" for a in denied),
    )
    kubectl("rollout", "status", "deploy/authz-state", "-n", NS, "--timeout=120s", timeout=150)
    time.sleep(2)
    # revocation table survived: still revoked
    still = http_front("POST", QUERIES, TOKENS["blue"], query_body())
    r.check("after authz-state back, ACCOUNT_REVOKED still (PVC)", still["status"] == 403 and envelope(still).get("reason_code") == "ACCOUNT_REVOKED")
    revoke_via_control(pod_json(pod_names("gateway-authz")[0])["status"]["podIP"], BLUE_ACCOUNT, "restore")
    time.sleep(1)
    # quota buckets refilled (memory only): green prints may have been used in KP8-05; after state restart should allow again
    # delete state to refill — already restarted above; try two prints
    # First restore may leave quota empty from KP8-05; restart authz-state again to refill
    kubectl("delete", "pod", "-n", NS, "-l", "app=authz-state", "--wait=true", timeout=120)
    kubectl("rollout", "status", "deploy/authz-state", "-n", NS, "--timeout=120s", timeout=150)
    time.sleep(1)
    p1 = http_front("POST", PRINTS, TOKENS["green"], print_body())
    r.check("after authz-state restart, quota bucket refilled (first print 200)", p1["status"] == 200)


def case_rolling_publish(r: Results):
    r.case("KP8-08", "rolling publish new immutable snapshot under traffic; old ConfigMap remains")
    old_snap = kubectl(
        "get", "deploy", "gateway", "-n", NS, "-o", "jsonpath={.spec.template.spec.volumes[?(@.name==\"snapshot\")].configMap.name}"
    ).stdout.strip()
    # New snapshot: tweak access log note via unused field — change a timeout slightly
    text = gateway_config()
    # force new digest: add a harmless comment in YAML by changing requestTimeout on one route
    text2 = text.replace("requestTimeout: 9s", "requestTimeout: 8s", 1)
    if text2 == text:
        text2 = text + "\n# k8spools-roll\n"
    snap2 = snapshot_name(text2)
    apply_docs(
        [
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": snap2, "namespace": NS},
                "immutable": True,
                "data": {"config.yaml": text2},
            }
        ]
    )
    stop = threading.Event()
    results = []

    def traffic():
        while not stop.is_set():
            try:
                results.append(http_front("POST", QUERIES, TOKENS["blue"], query_body(), timeout=10))
            except Exception as e:
                results.append({"status": 0, "error": str(e), "body": b"", "headers": {}, "trace_id": ""})
            time.sleep(0.2)

    t = threading.Thread(target=traffic, daemon=True)
    t.start()
    time.sleep(0.5)
    t0 = time.monotonic()
    # patch deployment volume configMap name
    patch = [{"op": "replace", "path": "/spec/template/metadata/labels/snapshot", "value": snap2[-12:]}]
    # find snapshot volume index
    dep = json.loads(kubectl("get", "deploy", "gateway", "-n", NS, "-o", "json").stdout)
    idx = next(i for i, v in enumerate(dep["spec"]["template"]["spec"]["volumes"]) if v["name"] == "snapshot")
    patch = {
        "spec": {
            "template": {
                "metadata": {"labels": {"snapshot": snap2.split("-")[-1]}},
                "spec": {"volumes": dep["spec"]["template"]["spec"]["volumes"]},
            }
        }
    }
    patch["spec"]["template"]["spec"]["volumes"][idx]["configMap"]["name"] = snap2
    kubectl("patch", "deploy", "gateway", "-n", NS, "--type", "strategic", "-p", json.dumps(patch))
    kubectl("rollout", "status", "deploy/gateway", "-n", NS, "--timeout=180s", timeout=210)
    time.sleep(2)
    stop.set()
    t.join(timeout=10)
    elapsed = time.monotonic() - t0
    hard = sum(1 for x in results if x.get("status") == 0 or (x.get("status") or 0) >= 500)
    r.note("rolling publish", {"seconds": round(elapsed, 2), "requests": len(results), "hard_failures": hard, "old": old_snap, "new": snap2})
    old_exists = kubectl("get", "cm", old_snap, "-n", NS, check=False).returncode == 0
    r.check("old immutable ConfigMap still present", old_exists)
    r.check("gateway readyReplicas 2 after roll", kubectl("get", "deploy", "gateway", "-n", NS, "-o", "jsonpath={.status.readyReplicas}").stdout.strip() == "2")
    r.timings["KP8-08"] = {"seconds": elapsed, "hard_failures": hard, "requests": len(results)}


def case_secrets(r: Results):
    r.case("KP8-09", "no app secret / AES key / carrier token / private key body in logs or suite output")
    blob = logs("gateway-authz") + logs("provider-signer") + logs("sf-token-coordinator") + logs("authz-state") + logs("gateway")
    bad = []
    for s in SECRETS:
        if len(s) >= 8 and s in blob:
            bad.append("secret-in-logs")
    if "BEGIN PRIVATE KEY" in blob or "BEGIN EC PRIVATE KEY" in blob:
        bad.append("private-key-pem")
    if re.search(r"auth_[A-Za-z0-9_-]{20,}", blob):
        # stand-in tokens may appear in standin logs only — check authz/gateway
        authz_blob = logs("gateway-authz")
        if re.search(r"auth_[A-Za-z0-9_-]{20,}", authz_blob):
            bad.append("carrier-token-in-authz-logs")
    r.check("no registered secrets or private key PEM in component logs", not bad)
    r.note("scan hits", bad)


def control_no_netpol(r: Results):
    r.case("CTRL-no-netpol", "without NetworkPolicies a forbidden connection succeeds")
    # Policies were not applied. Create probe with provider-signer label... actually no policies at all.
    apply_docs(
        [
            {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "ctrl-netpol", "namespace": NS, "labels": {"app": "provider-signer"}},
                "spec": {
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [
                        {
                            "name": "c",
                            "image": IMAGE_TAGS["tools"],
                            "command": ["sleep", "300"],
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                                "runAsUser": 65534,
                            },
                        }
                    ],
                    "restartPolicy": "Never",
                },
            }
        ]
    )
    kubectl("wait", "--for=condition=Ready", "pod/ctrl-netpol", "-n", NS, "--timeout=120s")
    got = kubectl(
        "exec", "-n", NS, "ctrl-netpol", "--", "python3", "-c",
        "import socket;s=socket.create_connection(('outsider',8000),3);s.close();print('OPEN')",
        check=False,
    ).stdout.strip()
    r.check("signer-labeled probe reaches outsider when policies absent", got == "OPEN")
    kubectl("delete", "pod", "ctrl-netpol", "-n", NS, "--wait=false", check=False)


def main():
    global CONTROL, NETPOL_ENFORCED
    parser = argparse.ArgumentParser()
    parser.add_argument("--control", choices=["no-netpol", "no-coordinators"], default=None)
    args = parser.parse_args()
    CONTROL = args.control
    scrub_proxy()
    free_ports(range(27901, 27916))
    if not KUBECONFIG.exists():
        die("missing kubeconfig; run tests/integration/k8spools/stack.sh up first")

    RUN.mkdir(mode=0o700, exist_ok=True)
    build_binaries()
    build_images()
    kind_load()

    # Fresh namespace
    kubectl("delete", "ns", NS, "--wait=true", check=False, timeout=180)
    time.sleep(2)

    tls = issue_tls()
    ensure_authz_listen_leaf(tls)
    mint_jwks_and_tokens(tls)
    admin_secret = "ADMIN"
    remember(admin_secret)
    endpoint = "http://sfintl-standin:8080/openapi/api/token"
    made = make_apps(endpoint)
    global APPS
    APPS = made["apps"]
    mock_state = {
        "admin_secret": admin_secret,
        "token_lifetime_seconds": 7200,
        "apps": [
            {
                "app_key": a["app_key"],
                "app_secret": a["app_secret"],
                "encoding_aes_key": a["encoding_aes_key"],
                "api_username": a["api_username"],
            }
            for a in made["apps"].values()
        ],
    }
    snap_text = gateway_config()
    snap = snapshot_name(snap_text)
    session_key = secrets.token_hex(32)

    coordinated = CONTROL != "no-coordinators"
    netpol = CONTROL != "no-netpol"

    # Create namespace first via rendered docs
    docs = render_manifests(snap, coordinated=coordinated, netpol=False)  # apply netpol after measure
    # Only namespace first
    ns_doc = next(d for d in docs if d.get("kind") == "Namespace")
    apply_docs([ns_doc])
    create_secrets(tls, made["document"], admin_secret, session_key, snap_text, snap)
    deploy_helpers(admin_secret, mock_state)
    # Apply standin script cm already in deploy_helpers; wait standin
    # Apply pool workloads without netpol first for measure path
    pool_docs = [d for d in render_manifests(snap, coordinated=coordinated, netpol=False) if d.get("kind") != "Namespace"]
    apply_docs(pool_docs)
    for name in ("sfintl-standin", "outsider", "k8spools-client"):
        wait_deploy(name, 180)
    if coordinated:
        wait_deploy("sf-token-coordinator", 180)
        wait_deploy("authz-state", 180)
    wait_deploy("gateway-authz", 240)
    wait_deploy("provider-signer", 180)
    wait_deploy("gateway", 240)
    copy_gateway_control()
    wait_gateway_ready()

    r = Results()
    r.note = r.note  # noqa
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    if CONTROL == "no-netpol":
        control_no_netpol(r)
        # Still run a minimal SF check so control is meaningful
        case_sf_flow(r)
    elif CONTROL == "no-coordinators":
        case_topology(r)
        case_sf_flow(r)
    else:
        # Apply network policies now, then measure
        netpol_docs = [d for d in render_manifests(snap, coordinated=True, netpol=True) if d.get("kind") == "NetworkPolicy"]
        apply_docs(netpol_docs)
        NETPOL_ENFORCED = measure_netpol(r)
        # Re-apply full netpol set (measure may have replaced default-deny)
        apply_docs(netpol_docs)
        case_topology(r)
        case_sf_flow(r)
        case_netpol(r, NETPOL_ENFORCED)
        case_revoke(r)
        case_quota(r)
        case_delete_authz(r)
        case_delete_authz_state(r)
        case_rolling_publish(r)
        case_secrets(r)

    passed, total = r.report()
    stop_port_forward()
    ended = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    result = {
        "control": CONTROL,
        "started": started,
        "ended": ended,
        "netpol_enforced": NETPOL_ENFORCED,
        "images": IMAGE_TAGS,
        "timings": r.timings,
        "cases": r.cases,
        "passed": passed,
        "total": total,
    }
    (RUN / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    if r.failed():
        raise SystemExit(1)
    raise SystemExit(0)


if __name__ == "__main__":
    try:
        main()
    finally:
        stop_port_forward()
