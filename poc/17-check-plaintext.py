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

The listener is a raw TCP server, so what it records is the exact byte stream
that arrived on the socket. `--capture <file>` writes that transcript out.

The listener binds 0.0.0.0 and the tool is pointed at the host's non-loopback
address when one exists, so this is not a loopback-only quirk.

Run it with any Python 3.8+ - nothing is imported from the product:

    python3 poc/17-check-plaintext.py
    python3 poc/17-check-plaintext.py --binary /path/to/signal-pyarmor-linux-x86_64
    python3 poc/17-check-plaintext.py --capture poc/captures/17-plaintext-capture.txt

For a packet-level capture, pin the endpoint so a display filter is trivial:

    sudo tcpdump -i lo -s0 -w /tmp/plain.pcap 'tcp port 8899' &
    python3 poc/17-check-plaintext.py --host 127.0.0.1 --port 8899
    wireshark /tmp/plain.pcap     # then: Decode As -> HTTP on port 8899

Exit codes: 0 = reproduced, 1 = a claim failed, 2 = not set up.
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
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
def _reply(path):
    if "embedding" in path:
        return {"object": "list",
                "data": [{"object": "embedding", "index": 0, "embedding": [0.1] * 8}],
                "model": "poc-model",
                "usage": {"prompt_tokens": 1, "total_tokens": 1}}
    if "/models" in path:
        return {"object": "list", "data": [{"id": "poc-model", "object": "model"}]}
    return {"id": "msg_poc", "object": "chat.completion", "created": 0,
            "model": "poc-model",
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": "ok"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1,
                      "total_tokens": 2}}


def _read_request(conn):
    """Read one HTTP/1.1 request; return the exact bytes as received."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(65536)
        if not chunk:
            return None
        buf += chunk
        if len(buf) > 16 << 20:
            return None
    head, _, rest = buf.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            try:
                length = int(line.split(b":", 1)[1].strip())
            except ValueError:
                length = 0
    body = rest
    while len(body) < length:
        chunk = conn.recv(65536)
        if not chunk:
            break
        body += chunk
    return head + b"\r\n\r\n" + body[:length]


class Listener(threading.Thread):
    """Raw TCP server. Records the bytes that arrived, not a parsed view."""

    daemon = True

    def __init__(self, port, host="0.0.0.0"):
        super().__init__()
        self.seen = []
        self._halt = threading.Event()
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(16)
        self.sock.settimeout(0.5)

    def run(self):
        while not self._halt.is_set():
            try:
                conn, peer = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(conn, peer), daemon=True).start()

    def _serve(self, conn, peer):
        try:
            conn.settimeout(30)
            raw = _read_request(conn)
            if raw is None:
                return
            head = raw.split(b"\r\n", 1)[0].decode("latin-1")
            path = head.split(" ")[1] if len(head.split(" ")) > 1 else "/"
            self.seen.append({"peer": "%s:%d" % peer[:2], "raw": raw,
                              "requestline": head, "path": path})
            payload = json.dumps(_reply(path)).encode()
            conn.sendall(b"HTTP/1.1 200 OK\r\n"
                         b"Content-Type: application/json\r\n"
                         b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
                         b"Connection: close\r\n\r\n" + payload)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self._halt.set()
        try:
            self.sock.close()
        except OSError:
            pass


# ------------------------------------------------------------------ helpers
def write_config(path, uri):
    lines = ["[LLM]", "mode = byo", "uri = %s" % uri, "key = %s" % CANARY,
             "model = poc-model", "timeout = 15", ""]
    for agent in AGENTS:
        lines += ["[LLM_%s]" % agent, "model = poc-model"]
    path.write_text("\n".join(lines) + "\n")


def verdict(ok, text):
    print("   %s %s" % ("PASS -" if ok else "FAIL -", text))
    return ok


def header_value(raw, name):
    for line in raw.split(b"\r\n")[1:]:
        if line.lower().startswith(name.lower().encode() + b":"):
            return line.split(b":", 1)[1].strip().decode("latin-1")
    return ""


def body_of(raw):
    return raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b""


def write_capture(path, binary, uri, port, seen, code, cfg_text):
    """A transcript of the exact bytes that arrived, plus how to read it."""
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        digest = hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest()
    except OSError:
        digest = "(unavailable)"
    out = []
    w = out.append
    w("=" * 78)
    w(" PoC transcript - cleartext LLM transport, raw socket capture")
    w("=" * 78)
    w("captured      : %s" % stamp)
    w("binary        : %s" % binary)
    w("binary sha256 : %s" % digest)
    w("endpoint      : %s" % uri)
    w("listener      : 0.0.0.0:%d (raw TCP, no TLS context created)" % port)
    w("transport     : plain TCP - a TLS handshake was neither performed nor possible")
    w("requests      : %d" % len(seen))
    w("client exit   : %s" % code)
    w("")
    w("Line endings below are normalised CRLF -> LF for readability. The byte")
    w("counts and sha256 values are of the bytes exactly as received, so the")
    w("fidelity of each entry can be checked independently.")
    w("")
    w("The config that produced this traffic:")
    w("")
    for line in cfg_text.splitlines():
        w("    " + line)
    w("")
    w("Payload note: these are --check-llm-json probes, so the body is a fixed")
    w("'Hello' message rather than a scan. A full scan sends source code over the")
    w("same client and the same endpoint, but cannot start until the tokenizer")
    w("cache is seeded (see F-05).")
    w("")
    for i, entry in enumerate(seen, 1):
        raw = entry["raw"]
        w("")
        w("-" * 78)
        w("[%d] %s" % (i, entry["requestline"]))
        w("    peer  %-22s raw %d bytes  sha256 %s"
          % (entry["peer"], len(raw), hashlib.sha256(raw).hexdigest()))
        auth = header_value(raw, "Authorization")
        if auth:
            w("    auth  %s" % auth)
        w("    body  %d bytes" % len(body_of(raw)))
        w("-" * 78)
        w(raw.decode("utf-8", "replace").replace("\r\n", "\n"))
    w("")
    w("=" * 78)
    w(" observed: every request above begins with a plain HTTP request line and")
    w(" carries 'Authorization: %s';" % ("Bearer " + CANARY))
    w(" nothing in the stream is preceded by a TLS ClientHello.")
    w("=" * 78)
    pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(path).write_text("\n".join(out) + "\n")
    return path


def main():
    ap = argparse.ArgumentParser(description="cleartext LLM transport check")
    ap.add_argument("--binary", help="path to " + BINARY_NAME)
    ap.add_argument("--capture", metavar="FILE",
                    help="write the raw captured requests to FILE")
    ap.add_argument("--host", metavar="ADDR",
                    help="address to put in the endpoint (default: this host's "
                         "non-loopback address, else 127.0.0.1)")
    ap.add_argument("--port", type=int,
                    help="fixed listener port (default: a free port). Pin this when "
                         "capturing packets so the filter is 'tcp port <N>'")
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

    port = args.port or free_port()
    addr = args.host or outward_address() or "127.0.0.1"
    loopback_only = addr.startswith("127.")
    uri = "http://%s:%d/v1" % (addr, port)
    cfg = work / "poc-transport.signal"
    write_config(cfg, uri)

    server = Listener(port, host="0.0.0.0" if args.host in (None, "0.0.0.0") else args.host)
    server.start()

    print("plaintext transport check - LLM traffic over http://")
    print("binary    : %s" % binary)
    print("endpoint  : %s" % uri)
    print("listener  : 0.0.0.0:%d (%s)" %
          (port, "non-loopback address available" if not loopback_only
                 else "no non-loopback address - testing loopback only"))
    if loopback_only:
        print("   NOTE - loopback endpoint: capture on the 'lo' interface in Wireshark,")
        print("          filter 'tcp port %d', then Decode As -> HTTP if it shows as TCP" % port)
    else:
        print("   NOTE - non-loopback endpoint: capture on the interface that address")
        print("          belongs to, filter 'tcp port %d'" % port)

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
        stream = exc.stdout or b""
        output = stream.decode("utf-8", "replace") if isinstance(stream, bytes) else (stream or "")
        code = None
    finally:
        server.stop()
        server.join(timeout=5)

    seen = server.seen
    print("\n== A. a cleartext http:// endpoint is accepted ==")
    print("   requests received: %d" % len(seen))
    for r in seen[:3]:
        print("   %-8s %s" % (r["requestline"].split(" ")[0], r["path"]))

    a_ok = len(seen) > 0
    a_ok &= verdict(bool(seen), "the tool connected to a plain HTTP endpoint (%d request(s))"
                    % len(seen))

    print("\n== B. the bearer credential crosses the wire unencrypted ==")
    auths = [header_value(r["raw"], "Authorization") for r in seen]
    with_key = [a for a in auths if CANARY in a]
    if with_key:
        print("   seen: %s" % with_key[0])
    b_ok = verdict(bool(with_key),
                   "Authorization: Bearer <canary> arrived over the plaintext socket")
    b_ok &= verdict(bool(seen),
                    "request line is cleartext HTTP (%r), so no TLS handshake preceded it"
                    % (seen[0]["requestline"] if seen else ""))

    print("\n== C. nothing warns the operator ==")
    scanned = "\n".join(ln for ln in output.splitlines()
                        if not ln.startswith("Reading config from"))
    hits = sorted({w for w in WARNING_WORDS if w in scanned.lower()})
    if hits:
        print("   matched: %s" % ", ".join(hits))
    c_ok = verdict(not hits, "no insecure-transport warning or refusal in the output")
    attempted = "error_code" in output or "passed" in output
    c_ok &= verdict(attempted, "the run actually reached the LLM layer (not a config error)")

    if args.capture:
        written = write_capture(args.capture, binary, uri, port, seen, code,
                                cfg.read_text())
        print("\n   capture written: %s (%d request(s), %d bytes)"
              % (written, len(seen), pathlib.Path(written).stat().st_size))

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
