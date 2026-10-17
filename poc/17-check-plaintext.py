#!/usr/bin/env python3
"""PoC: LLM traffic is accepted over plaintext HTTP - bearer token included.

The product's default endpoint is HTTPS, but the scheme is never enforced: a
`.signal` config (or --llm-uri) may say `http://`, and the tool will send the
LLM credential and the request body over an unencrypted socket without a word
of warning.

This check proves it end to end:

  A. accept   - a config with `uri = http://<addr>:<port>/v1` is accepted and
                the agent probes actually arrive on a cleartext socket
  B. leak     - the `Authorization: Bearer <canary>` header arrives in a request
                whose first bytes are `POST /v1/chat/completions HTTP/1.1`,
                i.e. there was no TLS handshake in front of it
  C. silent   - the run prints no insecure-transport warning or refusal

The listener binds 0.0.0.0 and the tool is pointed at the host's non-loopback
address when one exists, so this is not a loopback-only quirk.

Run it with any Python 3.8+ - nothing is imported from the product:

    python3 poc/17-check-plaintext.py
    python3 poc/17-check-plaintext.py --binary /path/to/signal-pyarmor-linux-x86_64

Exit codes: 0 = reproduced, 1 = a claim failed, 2 = not set up.
"""
import argparse
import http.server
import json
import os
import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import threading

CANARY = "CANARY_PLAINTEXT_9f31c2"
BINARY_NAME = "signal-pyarmor-linux-x86_64"
AGENTS = (
    "SINGLEFILESCAN_AGENT", "DATAFLOW_AGENT", "OVERSIGHT_AGENT",
    "EXPLOITATION_AGENT", "SCA_AGENT", "MERGEKEY_EMBED_AGENT",
    "OVERSIGHT_EMBED_AGENT",
)
# Deliberately contains no bare "plaintext"/"cleartext": a file name or a path
# the operator chose can contain those words, and that is not a warning.
WARNING_WORDS = (
    "insecure", "unencrypted", "not encrypted", "plain http", "over http",
    "tls required", "https required", "ssl required", "refusing to",
    "refused to", "must use https", "scheme not allowed",
)


# ------------------------------------------------------------------ locate
def find_binary(explicit):
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    here = os.path.dirname(os.path.abspath(__file__))
    for c in (os.environ.get("SIGNAL_BIN", ""),
              os.path.join(os.path.dirname(here), BINARY_NAME),
              os.path.join(os.getcwd(), BINARY_NAME),
              os.path.join("/tmp/vapt", BINARY_NAME)):
        if c and os.path.isfile(c):
            return c
    return None


def free_port():
    s = socket.socket()
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def outward_address():
    """The host's non-loopback address, or None. Sends no packets."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        addr = s.getsockname()[0]
        s.close()
        return None if addr.startswith("127.") else addr
    except OSError:
        return None


# ------------------------------------------------------------------ listener
class Recording(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _record(self, body):
        self.server.seen.append({
            "requestline": self.requestline,
            "path": self.path,
            "headers": dict(self.headers),
            "body": body,
            "peer": self.client_address[0],
        })

    def _reply(self, obj):
        payload = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._record("")
        self._reply({"object": "list", "data": [{"id": "poc-model", "object": "model"}]})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        self._record(body)
        if "embedding" in self.path:
            self._reply({"object": "list", "data": [{"object": "embedding",
                                                     "index": 0, "embedding": [0.1] * 8}],
                         "model": "poc-model", "usage": {"prompt_tokens": 1, "total_tokens": 1}})
        else:
            self._reply({"id": "msg_poc", "object": "chat.completion", "created": 0,
                         "model": "poc-model",
                         "choices": [{"index": 0, "finish_reason": "stop",
                                      "message": {"role": "assistant", "content": "ok"}}],
                         "usage": {"prompt_tokens": 1, "completion_tokens": 1,
                                   "total_tokens": 2}})


# ------------------------------------------------------------------ helpers
def write_config(path, uri, port):
    lines = ["[LLM]", "mode = byo", "uri = %s" % uri, "key = %s" % CANARY,
             "model = poc-model", "timeout = 15", ""]
    for agent in AGENTS:
        lines += ["[LLM_%s]" % agent, "model = poc-model"]
    path.write_text("\n".join(lines) + "\n")


def verdict(ok, text):
    print("   %s %s" % ("PASS -" if ok else "FAIL -", text))
    return ok


def main():
    ap = argparse.ArgumentParser(description="cleartext LLM transport check")
    ap.add_argument("--binary", help="path to " + BINARY_NAME)
    ap.add_argument("--keep", action="store_true", help="keep the work directory")
    ap.add_argument("--timeout", type=int, default=120, help="seconds for the run (default 120)")
    args = ap.parse_args()

    binary = find_binary(args.binary)
    if not binary:
        print("binary not found - pass --binary /path/to/" + BINARY_NAME)
        return 2
    if not os.access(binary, os.X_OK):
        print("binary is not executable: %s" % binary)
        return 2

    work = pathlib.Path(tempfile.mkdtemp(prefix="poc-plaintext-"))
    target = work / "target"
    target.mkdir()
    (target / "app.py").write_text(
        "MARKER = 'POC-PLAINTEXT-SOURCE-SENTINEL'\n"
        "def f(c):\n    return c\n")

    port = free_port()
    addr = outward_address() or "127.0.0.1"
    loopback_only = addr == "127.0.0.1"
    uri = "http://%s:%d/v1" % (addr, port)
    cfg = work / "poc-transport.signal"
    write_config(cfg, uri, port)

    server = http.server.ThreadingHTTPServer(("0.0.0.0", port), Recording)
    server.seen = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    print("plaintext transport check - LLM traffic over http://")
    print("binary    : %s" % binary)
    print("endpoint  : %s" % uri)
    print("listener  : 0.0.0.0:%d (%s)" %
          (port, "non-loopback address available" if not loopback_only
                 else "no non-loopback address - testing loopback only"))
    if loopback_only:
        print("   NOTE - this host has no outward address, so only the loopback path is shown;")
        print("          the scheme acceptance is the same either way")

    env = dict(os.environ)
    for var in ("PYTHONHOME", "PYTHONPATH", "TIKTOKEN_CACHE_DIR"):
        env.pop(var, None)
    cmd = [binary, str(target), "--config", str(cfg), "--check-llm-json", "true"]
    print("\nrunning: %s" % " ".join(cmd))
    try:
        proc = subprocess.run(cmd, cwd=str(work), env=env, timeout=args.timeout,
                              capture_output=True, text=True, errors="replace")
        output, code = (proc.stdout or "") + (proc.stderr or ""), proc.returncode
    except subprocess.TimeoutExpired as exc:
        output = ((exc.stdout or b"") + (exc.stderr or b"")).decode("utf-8", "replace") \
            if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        code = None
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    seen = server.seen
    print("\n== A. a cleartext http:// endpoint is accepted ==")
    print("   requests received: %d" % len(seen))
    for r in seen[:3]:
        print("   %-8s %s" % ("POST" if r["requestline"].startswith("POST") else "GET", r["path"]))

    a_ok = len(seen) > 0
    a_ok &= verdict(bool(seen), "the tool connected to a plain HTTP endpoint (%d request(s))"
                    % len(seen))

    print("\n== B. the bearer credential crosses the wire unencrypted ==")
    auths = [r["headers"].get("Authorization", "") for r in seen]
    with_key = [a for a in auths if CANARY in a]
    plain = [r for r in seen if r["requestline"].split(" ")[0] in ("POST", "GET")
             and r["requestline"].startswith(r["requestline"].split(" ")[0] + " ")]
    if with_key:
        print("   seen: %s" % with_key[0])
    b_ok = verdict(bool(with_key),
                   "Authorization: Bearer <canary> arrived over the plaintext socket")
    b_ok &= verdict(bool(plain) and bool(seen),
                    "request line is cleartext HTTP (%r), so no TLS handshake preceded it"
                    % (seen[0]["requestline"] if seen else ""))

    print("\n== C. nothing warns the operator ==")
    # The "Reading config from <path>" echo is not a warning, whatever the path
    # happens to be called.
    scanned = "\n".join(ln for ln in output.splitlines()
                        if not ln.startswith("Reading config from"))
    hits = sorted({w for w in WARNING_WORDS if w in scanned.lower()})
    if hits:
        print("   matched: %s" % ", ".join(hits))
    c_ok = verdict(not hits, "no insecure-transport warning or refusal in the output")
    attempted = "error_code" in output or "passed" in output
    c_ok &= verdict(attempted, "the run actually reached the LLM layer (not a config error)")

    score = sum(1 for x in (a_ok, b_ok, c_ok) if x)
    print("\n== summary ==")
    print("   %s accept" % ("PASS" if a_ok else "FAIL"))
    print("   %s leak" % ("PASS" if b_ok else "FAIL"))
    print("   %s silent" % ("PASS" if c_ok else "FAIL"))
    print("   plaintext transport reproduced: %d/3" % score)
    print("""
   What this shows: the CLI takes an http:// endpoint from its config, sends the
   bearer credential to it over an unencrypted socket, and does so silently. The
   same client and the same endpoint carry scan payloads, so source code follows
   this path whenever the operator (or a shared .signal) selects http.

   What it does not show: the scan payloads themselves - --check-llm-json probes
   with a fixed "Hello" prompt, and a full scan needs the tokenizer cache (F-05)
   before its first call. It also does not show an attacker position: on-path
   observation is a consequence of the cleartext choice, not demonstrated here.

   The default endpoint is https, so this needs an http:// endpoint to be
   configured - which is the point: transport security is optional, not enforced,
   and there is no warning when it is dropped.""")
    if args.keep:
        print("\n   work directory kept: %s" % work)
    else:
        import shutil
        shutil.rmtree(work, ignore_errors=True)
    return 0 if score == 3 else 1


if __name__ == "__main__":
    raise SystemExit(main())
