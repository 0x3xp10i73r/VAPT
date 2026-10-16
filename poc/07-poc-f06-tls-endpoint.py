"""PoC-F06 support: a self-signed HTTPS endpoint that logs every request.

Run this, point Signal at it with --llm-uri https://127.0.0.1:8443/v1, and
compare --llm-ssl-verify true against --llm-ssl-verify false. With verification
left on the TLS handshake is refused; with it off the request - carrying the
Bearer API key and prompt content - is accepted by an endpoint presenting an
untrusted certificate, and this server records it.
"""
import http.server
import json
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

    def do_GET(self):
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


if __name__ == "__main__":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("poc-f06-selfsigned.pem", "poc-f06-selfsigned.key")
    httpd = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"self-signed HTTPS endpoint listening on 0.0.0.0:{PORT}, logging to {LOGFILE}")
    httpd.serve_forever()
