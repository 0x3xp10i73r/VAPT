"""Capture exactly what the scanner sends to an LLM endpoint (PoC for F-16).

Runs an OpenAI-compatible chat/embeddings endpoint that records every request
body, then answers plausibly so a scan can complete. Point the CLI at it with
`--llm-uri http://127.0.0.1:<port>/v1`.

    python3 13-capture-llm-payload.py 8899 /tmp/poc-f16-payload.log
    # then, in another shell:
    HOME=<sandbox> TIKTOKEN_CACHE_DIR=<seeded-cache> ./signal-pyarmor-linux-x86_64 <target> \
        --llm-mode byo --llm-uri http://127.0.0.1:8899/v1 --llm-key CANARY_KEY_123
    grep -c AKIAIOSFODNN7EXAMPLE /tmp/poc-f16-payload.log   # literal from the target

The log holds one block per request: path, selected headers, and the full body.
Nothing is written back to the target, and no request is forwarded anywhere.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
LOG = sys.argv[2] if len(sys.argv) > 2 else "/tmp/poc-f16-payload.log"
REDACT_HEADERS = {"authorization", "x-api-key", "api-key"}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _record(self, body):
        with open(LOG, "a") as fh:
            fh.write("\n" + "=" * 78 + "\n")
            fh.write("POST %s\n" % self.path)
            for k, v in self.headers.items():
                fh.write("  %s: %s\n" % (k, "<redacted>" if k.lower() in REDACT_HEADERS else v))
            fh.write("BODY (%d bytes):\n%s\n" % (len(body), body.decode("utf-8", "replace")))
            fh.flush()

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        self._record(raw)
        try:
            req = json.loads(raw or b"{}")
        except Exception:
            req = {}

        if "embed" in self.path or req.get("input") is not None:
            inputs = req.get("input")
            count = len(inputs) if isinstance(inputs, list) else 1
            payload = {
                "object": "list", "model": req.get("model", "poc-model"),
                "data": [{"object": "embedding", "index": i,
                          "embedding": [0.01 * ((i + j) % 17) for j in range(1536)]}
                         for i in range(count)],
                "usage": {"prompt_tokens": count, "total_tokens": count},
            }
        else:
            payload = {
                "id": "chatcmpl-poc", "object": "chat.completion", "created": 0,
                "model": req.get("model", "poc-model"),
                "choices": [{"index": 0, "finish_reason": "stop",
                             "message": {"role": "assistant", "content": '{"results": []}'}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        data = b'{"object":"list","data":[]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("capturing LLM payloads on :%d -> %s" % (PORT, LOG), flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
