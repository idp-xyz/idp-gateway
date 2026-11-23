"""In-process stand-ins for the AI loopback suite.

Nothing here listens outside 127.0.0.1. Records keep header names and a few
values. They do not keep Authorization, the caller's JWT, or key material.
"""
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WATCH = (
    "host", "cookie", "x-not-registered", "x-forwarded-for", "x-provider-account",
    "traceparent", "accept", "content-type", "mcp-session-id", "mcp-protocol-version",
)


class Book:
    def __init__(self):
        self._lock = threading.Lock()
        self.records = []
        self.saw_caller_jwt = False

    def note(self, kind, handler, extra=None, secrets=()):
        auth = handler.headers.get("Authorization") or ""
        if any(secret and secret in auth for secret in secrets):
            self.saw_caller_jwt = True
        rec = {
            "standin": kind,
            "method": handler.command,
            "path": handler.path.split("?", 1)[0],
            "raw_path": handler.path,
            "authorization": "present" if auth else "absent",
            "client_cert": peer_cert(handler),
            "seen": {name: handler.headers.get(name) for name in WATCH if handler.headers.get(name) is not None},
            "headers": sorted({key.lower() for key in handler.headers.keys()}),
        }
        if extra:
            rec.update(extra)
        with self._lock:
            self.records.append(rec)

    def take(self):
        with self._lock:
            got = list(self.records)
            self.records.clear()
            return got


def peer_cert(handler):
    try:
        cert = handler.connection.getpeercert()
    except Exception:
        return None
    if not cert:
        return None
    subject = {}
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            subject[key] = value
    uris = [value for kind, value in cert.get("subjectAltName", ()) if kind == "URI"]
    return {"cn": subject.get("commonName"), "uris": uris}


class ReuseServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(port, handler, cert=None, key=None, ca=None):
    server = ReuseServer(("127.0.0.1", port), handler)
    if cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        ctx.load_verify_locations(ca)
        ctx.verify_mode = ssl.CERT_REQUIRED
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def llm_handler(book, api_key, secrets=()):
    class LLM(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            auth = self.headers.get("Authorization") or ""
            book.note("llm", self, {"key_in_authorization": bool(api_key) and api_key in auth}, secrets)
            self._reply(200, {
                "id": "chatcmpl-standin",
                "object": "chat.completion",
                "model": "example-model",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": "standin-completion"},
                    "finish_reason": "stop",
                }],
            })

        def do_GET(self):
            book.note("llm", self, {"key_in_authorization": False}, secrets)
            self._reply(404, {"error": "not found"})

        def _reply(self, status, body):
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Location", "https://llm.standin.test/elsewhere")
            self.send_header("Set-Cookie", "llm=1")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *_args):
            pass

    return LLM


def mcp_handler(book, secrets=()):
    class MCP(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                book.note("mcp", self, {"rpc": "(not json)"}, secrets)
                return self._reply(400, {"error": "not json"})
            method, mid = msg.get("method"), msg.get("id")
            book.note("mcp", self, {"rpc": method}, secrets)
            if method == "initialize":
                return self._reply(200, {
                    "jsonrpc": "2.0", "id": mid,
                    "result": {
                        "protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-06-18"),
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "standin-server", "version": "0"},
                    },
                }, {"Mcp-Session-Id": "standin-session"})
            if mid is None:
                return self._reply(202, None)
            if method == "tools/list":
                return self._reply(200, {"jsonrpc": "2.0", "id": mid, "result": {"tools": [{
                    "name": "echo", "description": "returns its text",
                    "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]},
                }]}})
            if method == "tools/call":
                name = msg.get("params", {}).get("name")
                return self._reply(200, {"jsonrpc": "2.0", "id": mid, "result": {
                    "content": [{"type": "text", "text": "standin ran %s" % name}],
                    "isError": False,
                }})
            return self._reply(200, {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}})

        def do_GET(self):
            book.note("mcp", self, {"rpc": "(GET)"}, secrets)
            self._reply(405, {"error": "method"})

        def do_DELETE(self):
            book.note("mcp", self, {"rpc": "(DELETE)"}, secrets)
            self._reply(200, None)

        def do_PUT(self):
            book.note("mcp", self, {"rpc": "(PUT)"}, secrets)
            self._reply(200, {"error": "put"})

        def _reply(self, status, body, headers=None):
            raw = b"" if body is None else json.dumps(body).encode()
            extra = {"Location": "https://mcp.standin.test/elsewhere", "Set-Cookie": "mcp=1"}
            extra.update(headers or {})
            self.send_response(status)
            if body is not None:
                self.send_header("Content-Type", "application/json")
            for key, value in extra.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *_args):
            pass

    return MCP


def a2a_handler(book, card_url, secrets=()):
    card = {
        "name": "standin-agent", "description": "loopback stand-in", "url": card_url,
        "version": "0.0.1", "protocolVersion": "0.3.0", "capabilities": {"streaming": False},
        "defaultInputModes": ["text"], "defaultOutputModes": ["text"],
        "skills": [{"id": "echo", "name": "echo", "description": "echo", "tags": []}],
    }

    class A2A(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            book.note("a2a", self, secrets=secrets)
            path = self.path.split("?", 1)[0]
            if path in ("/.well-known/agent-card.json", "/.well-known/agent.json"):
                return self._reply(200, card)
            self._reply(404, {"error": "not found"})

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            try:
                msg = json.loads(raw)
                method = msg.get("method")
            except json.JSONDecodeError:
                method = "(not json)"
            book.note("a2a", self, {"rpc": method}, secrets)
            self._reply(200, {"jsonrpc": "2.0", "id": 1, "result": {
                "kind": "message", "messageId": "m-2", "role": "agent",
                "parts": [{"kind": "text", "text": "standin-agent-answer"}],
            }})

        def do_DELETE(self):
            book.note("a2a", self, secrets=secrets)
            self._reply(200, {"error": "delete"})

        def _reply(self, status, body):
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Location", "https://agent.standin.test/elsewhere")
            self.send_header("Set-Cookie", "agent=1")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *_args):
            pass

    return A2A
