"""PoC-F06 support: a self-signed HTTPS endpoint that logs every request.

Run this, point Signal at it with --llm-uri https://127.0.0.1:8443/v1, and
compare --llm-ssl-verify true against --llm-ssl-verify false. With verification
left on the TLS handshake is refused; with it off the request - carrying the
Bearer API key and prompt content - is accepted by an endpoint presenting an
untrusted certificate, and this server records it.

The listener is dual-protocol: the first byte of each connection decides. A TLS
ClientHello (0x16) is wrapped with the self-signed certificate exactly as before;
a plain HTTP request is answered in the clear. That second mode exists so the
same port can be opened in a browser preview, because the platform proxy speaks
plain HTTP to the sandbox and a TLS-only backend behind it cannot be reached.
F-06 itself always uses the TLS path.

    python3 poc/07-poc-f06-tls-endpoint.py 8443 poc-f06-requests.log
    curl -k https://127.0.0.1:8443/v1/models     # PoC path (TLS, untrusted cert)
    curl    http://127.0.0.1:8443/               # preview page listing requests
"""
import html
import http.server
import json
import socket
import ssl
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8443
LOGFILE = sys.argv[2] if len(sys.argv) > 2 else "poc-f06-requests.log"


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _record(self, body):
        with open(LOGFILE, "a") as fh:
            fh.write(json.dumps({
                "method": self.command,
                "path": self.path,
                "headers": {k: v for k, v in self.headers.items()},
                "body": body,
            }) + "\n")

    def _send(self, payload, ctype):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _index(self):
        """A human-readable view of the log, for the browser preview."""
        rows = []
        try:
            with open(LOGFILE) as fh:
                for line in fh:
                    try:
                        d = json.loads(line)
                    except ValueError:
                        continue
                    auth = (d.get("headers") or {}).get("Authorization", "")
                    rows.append(
                        "<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td>%d</td></tr>"
                        % (html.escape(d.get("method", "")), html.escape(d.get("path", "")),
                           html.escape(auth) or "&mdash;", len(d.get("body") or "")))
        except OSError:
            pass
        body = """<!doctype html><meta charset="utf-8">
<title>F-06 TLS test endpoint</title>
<style>
 body{font:15px/1.5 system-ui,sans-serif;margin:2rem;max-width:60rem;color:#1a1a1a}
 h1{font-size:1.3rem;margin:0 0 .3rem} p.sub{color:#555;margin:0 0 1.4rem}
 table{border-collapse:collapse;width:100%} th,td{text-align:left;padding:.45rem .6rem;
 border-bottom:1px solid #e3e3e3;vertical-align:top} th{background:#f6f6f6;font-size:.85rem;
 text-transform:uppercase;letter-spacing:.03em;color:#444} code{font-size:.9em;word-break:break-all}
 .note{background:#fff8e1;border-left:4px solid #f4b400;padding:.7rem .9rem;margin:1.2rem 0;
 font-size:.92rem} .empty{color:#777;padding:1rem 0}
</style>
<h1>F-06 test endpoint &mdash; request log</h1>
<p class="sub">Self-signed HTTPS listener used to demonstrate <code>--llm-ssl-verify false</code>.
This page is served over plain HTTP so it can be previewed in a browser.</p>
<div class="note">The PoC path is <code>https://&lt;host&gt;:8443/v1</code> with an untrusted
certificate. Requests recorded below arrived on that endpoint and carry whatever
<code>Authorization</code> header the client sent.</div>
<table><thead><tr><th>Method</th><th>Path</th><th>Authorization</th><th>Body bytes</th></tr></thead>
<tbody>""" + ("".join(rows) if rows else
                 '<tr><td colspan="4" class="empty">No requests logged yet.</td></tr>') + """
</tbody></table>"""
        self._send(body.encode(), "text/html; charset=utf-8")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._record("")
            return self._index()
        self._record("")
        payload = json.dumps({"object": "list", "data": [{"id": "mock", "object": "model"}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        self._record(body)
        payload = json.dumps({
            "id": "chatcmpl-mock", "object": "chat.completion", "created": 0,
            "model": "mock-model",
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": "ok"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class DualProtocolServer(http.server.ThreadingHTTPServer):
    """TLS for a ClientHello, plain HTTP for anything else.

    Wrapping the listening socket (the previous approach) made every connection
    TLS, which is correct for F-06 but unreachable through a plain-HTTP proxy.
    Peeking one byte keeps the PoC path byte-identical while letting the same
    port answer a browser.
    """

    def __init__(self, addr, handler, ctx):
        self.ctx = ctx
        super().__init__(addr, handler)

    def get_request(self):
        sock, addr = self.socket.accept()
        try:
            first = sock.recv(1, socket.MSG_PEEK)
        except OSError:
            return sock, addr
        if first == b"\x16":                     # TLS handshake record
            try:
                sock = self.ctx.wrap_socket(sock, server_side=True)
            except (ssl.SSLError, OSError):
                # The client refused the certificate and aborted the handshake -
                # that is the expected outcome when verification is left on.
                # Hand the handler an already-closed socket so it sees EOF and
                # finishes quietly, instead of reading from a dead descriptor
                # and raising EBADF in a worker thread.
                try:
                    sock.close()
                except OSError:
                    pass
                closed, other = socket.socketpair()
                other.close()
                return closed, addr
        return sock, addr


if __name__ == "__main__":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("poc-f06-selfsigned.pem", "poc-f06-selfsigned.key")
    httpd = DualProtocolServer(("0.0.0.0", PORT), Handler, ctx)
    print(f"endpoint listening on 0.0.0.0:{PORT} "
          f"(TLS with the self-signed cert, plain HTTP for the preview), "
          f"logging to {LOGFILE}")
    httpd.serve_forever()
