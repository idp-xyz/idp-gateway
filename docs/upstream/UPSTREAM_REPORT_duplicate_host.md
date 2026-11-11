# Report to agentgateway: HTTP/1.1 request with two `Host` header lines is accepted

> **Status: submitted on 2026-11-11, not answered yet.** It was filed through agentgateway's private reporting channel as advisory `GHSA-gccc-c8q8-cjmm`, which only the reporting account and the maintainers can open. On 2026-11-11 it was in triage.
> Why that channel: agentgateway's `SECURITY.md` (read again at the pinned revision on 2026-11-11) asks that anything that might be a vulnerability be reported privately, at <https://github.com/agentgateway/agentgateway/security/advisories/new>, and notes that a private report can later be made public but a public issue cannot be made private. The same policy counts as a vulnerability what "defeats a promised security boundary"; by that measure the maintainers may well file this as a conformance bug, and can open the public issue themselves.
> Checked on 2026-11-11 before sending: three keyword searches of the upstream issues and pull requests found no public report of it; #4361, which the text mentions, is still open.
> What was sent is the text below the line as it stood at commit `128ca4a`, followed by two notes from the reporter: when it was observed, and that the text was already public in this repository. Only the "Version" section has changed since: it now also lists the binary of the container image, on which the observations were repeated on 2026-11-11 with the same result in every row. The advisory names the release binary only.

---

## Summary

On an HTTP listener, agentgateway accepts an HTTP/1.1 request that contains two `Host` header field lines. It routes on the first line, forwards only the first line to the backend, and discards the second; its log does not mention it.

RFC 9112 §3.2 requires a 400 response here:

> A server MUST respond with a 400 (Bad Request) status code to any HTTP/1.1 request message that lacks a Host header field and to any request message that contains more than one Host header field line or a Host header field with an invalid field value.

The missing-`Host` half of that sentence is already implemented (the gateway answers `400 invalid request`). The more-than-one half is not.

## Version

Version 1.7.0, `git_revision` `26f5aebe99a36a037fe54f8080a608aca5547e15` (from `--version`), on Linux (Ubuntu 24.04 under WSL2). Both published builds of it, with the same result:

| `build_target` (from `--version`) | Where the binary came from |
|---|---|
| `x86_64-unknown-linux-musl` | `agentgateway-linux-amd64` from the GitHub release page, SHA-256 checked |
| `x86_64-unknown-linux-gnu` | `/app/agentgateway` taken out of `cr.agentgateway.dev/agentgateway:v1.7.0` (linux/amd64 manifest `sha256:460dda874be2dfa95fa5713c1f46f26079dce78df576008df704e54a59d5780d`) and run on the host |

## Reproduction

`config.yaml` — two routes that differ only in hostname, no policies:

```yaml
config:
  adminAddr: 127.0.0.1:27614
  statsAddr: 127.0.0.1:27615
  readinessAddr: 127.0.0.1:27616

gateways:
  default:
    port: 27611
    protocol: HTTP

routes:
- name: route-a
  gateways: [default]
  hostnames: ["a.test"]
  backends:
  - host: 127.0.0.1:27612
- name: route-b
  gateways: [default]
  hostnames: ["b.test"]
  backends:
  - host: 127.0.0.1:27617
```

`backend.py` — answers with its own name and the `Host` lines it received:

```python
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NAME, PORT = sys.argv[1], int(sys.argv[2])


class H(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        body = json.dumps({'backend': NAME, 'host_headers_received': self.headers.get_all('Host') or []}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


ThreadingHTTPServer(('127.0.0.1', PORT), H).serve_forever()
```

Start everything:

```bash
python3 backend.py backend-a 27612 &
python3 backend.py backend-b 27617 &
SESSION_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))') agentgateway -f config.yaml &
```

Send a request with two `Host` lines (a raw socket, because most HTTP clients will not send this):

```bash
printf 'GET /x HTTP/1.1\r\nHost: a.test\r\nHost: b.test\r\nConnection: close\r\n\r\n' | nc 127.0.0.1 27611
```

On 1.7.0 that prints `HTTP/1.1 200 OK` and `{"backend": "backend-a", "host_headers_received": ["a.test"]}`.

The table below was produced with a Python socket that sends the same bytes, varying only the `Host` lines.

## Observed

| `Host` lines sent, in order | Status | Served by | `Host` lines the backend received |
|---|---|---|---|
| `a.test` (control) | 200 | backend-a | `a.test` |
| `b.test` (control) | 200 | backend-b | `b.test` |
| `a.test`, `b.test` | **200** | backend-a | `a.test` |
| `b.test`, `a.test` | **200** | backend-b | `b.test` |
| `a.test`, `a.test` | **200** | backend-a | `a.test` |
| `a.test`, `unknown.test` | **200** | backend-a | `a.test` |
| `unknown.test`, `a.test` | 404 `route not found` | — | — |
| `unknown.test` (control) | 404 `route not found` | — | — |
| none | 400 `invalid request` | — | — |

The gateway log has one line for such a request, at `info`, with the first value as `http.host` and nothing about the second. For `a.test`, `b.test` on 1.7.0 (the whole line):

```
2026-11-10T14:41:51.561603Z	info	request gateway=default/default listener=default route=default/route-a endpoint=127.0.0.1:27612 src.addr=127.0.0.1:46258 http.method=GET http.host=a.test http.path=/x http.version=HTTP/1.1 http.status=200 protocol=http duration=1ms
```

## Expected

`400 Bad Request` for every row with two `Host` lines, including the row where both lines carry the same value, with nothing forwarded.

## Impact, as far as we could establish it

Stated carefully, because we did not find a bypass in agentgateway alone:

- The gateway is consistent with itself. Routing, the access log and the forwarded request all use the first line, and the backend never sees two. We did not observe a disagreement between the gateway and the backend behind it.
- The exposure is in a chain. A component in front of agentgateway that does not reject such a request, makes a decision on a different `Host` line than the first (a WAF rule, a per-host ACL, a tenant mapping, a cache key), and passes both lines on, will have made its decision about one host while agentgateway routes to another. Rejecting the request is what removes that ambiguity regardless of what sits in front, which is why the RFC puts the obligation on every server.
- We found no way to detect or refuse the request from configuration. The configuration schema has no setting for it. In a CEL authorization rule, `request.headers["host"]` did not yield a value we could test and `request.host` reflected the first line only, so a rule cannot tell that a second line was present. (Tried separately from the reproduction above.)

## Not tested

- HTTP/2 (`:authority` together with a `host` header, or repeated pseudo-headers).
- TLS listeners, and listeners with protocols other than `HTTP`.
- A request in absolute-form whose authority differs from the `Host` line.
- A `Host` header with an invalid field value; issue #4361 (malformed `Host` returns 503 instead of 400) looks related and may share a fix.
- Platforms other than Linux x86_64.

## Workaround in use

A reverse proxy in front of the listener that rejects the request. With nginx 1.30.6 forwarding to the 1.7.0 gateway of the reproduction above, the five two-`Host` rows and the no-`Host` row are answered 400 by nginx, and the gateway log gains a line only for the three single-`Host` controls. This depends on callers being unable to reach the gateway listener directly.
