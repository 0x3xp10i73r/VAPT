#!/usr/bin/env python3
"""Can the API key go on the command line, and what should be used instead?

Claims checked, each PASS/FAIL:

  A  a key passed as --llm-key is readable by any local user in /proc/<pid>/cmdline
  B  the tool's own log masks that key (the exposure is the OS, not the log)
  C  the same key supplied only from a --config file reaches the endpoint unchanged,
     so a file is a working alternative to the flag
  D  a .env is NOT read: with no key in the flag or the config the run still fails
     with "At least one LLM API key must be set", even with .env present

Requires the binary in the repository root. Writes nothing outside a temp dir.

    python3 poc/21-check-argv-keys.py
"""
import http.server
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import time

BIN = pathlib.Path(__file__).resolve().parents[1] / "signal-pyarmor-linux-x86_64"

CANARY_ARGV = "CANARY_ARGV_F21_ARGV"
CANARY_CONFIG = "CANARY_F21_CONFIG"
CANARY_ENV = ["CANARY_F21_DOTENV_1", "CANARY_F21_DOTENV_2", "CANARY_F21_DOTENV_3"]

AGENTS = ("SINGLEFILESCAN", "DATAFLOW", "OVERSIGHT", "EXPLOITATION",
          "SCA", "MERGEKEY_EMBED", "OVERSIGHT_EMBED")


def config_text(uri, key=None):
    out = ["[LLM]", "mode = byo", "uri = %s" % uri, "model = m", "timeout = 15"]
    if key:
        out.append("key = %s" % key)
    for a in AGENTS:
        out += ["", "[LLM_%s_AGENT]" % a, "model = m"]
    return "\n".join(out) + "\n"


class Recorder(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _record(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        self.server.requests.append({
            "path": self.path,
            "auth": self.headers.get("Authorization", ""),
        })

    def _send(self, obj):
        payload = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._record()
        self._send({"object": "list", "data": [{"id": "m", "object": "model"}]})

    def do_POST(self):
        self._record()
        self._send({"id": "x", "object": "chat.completion", "created": 0, "model": "m",
                    "choices": [{"index": 0, "finish_reason": "stop",
                                 "message": {"role": "assistant", "content": "ok"}}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})


def start_mock():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Recorder)
    srv.requests = []
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def run(args, cwd, timeout=120):
    return subprocess.Popen([str(BIN)] + args, cwd=cwd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)


def finish(p, timeout=120):
    try:
        out, _ = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        out, _ = p.communicate()
    return p.returncode, out or ""


def main():
    if not BIN.is_file():
        print("binary not found at %s" % BIN)
        return 2

    srv = start_mock()
    uri = "http://127.0.0.1:%d/v1" % srv.server_address[1]
    work = pathlib.Path(tempfile.mkdtemp(prefix="poc21-"))
    target = work / "target"
    target.mkdir()
    (target / "app.py").write_text("print('hello')\n")
    results = []

    # --- A: argv, as any local user sees it ---------------------------------
    d = work / "a"
    d.mkdir()
    (d / "cfg.signal").write_text(config_text(uri))
    p = run(["./target", "--config", "./cfg.signal", "--llm-key", CANARY_ARGV,
             "--check-llm", "false"], cwd=d)
    raw, mode = b"", None
    for _ in range(300):
        try:
            raw = pathlib.Path("/proc/%d/cmdline" % p.pid).read_bytes()
            mode = os.stat("/proc/%d/cmdline" % p.pid).st_mode & 0o777
        except (FileNotFoundError, ProcessLookupError):
            break
        if raw:
            break
        time.sleep(0.01)
    rc, _ = finish(p)

    argv = [x.decode() for x in raw.split(b"\0") if x] if raw else []
    has_argv = CANARY_ARGV in argv
    results.append(has_argv)
    print("== A. key on the command line ==")
    print("   pid %d, exit %d" % (p.pid, rc))
    print("   /proc/%d/cmdline mode: %s" % (p.pid, oct(mode) if mode else "gone"))
    if has_argv:
        i = argv.index("--llm-key")
        print("   argv[%d]: --llm-key" % i)
        print("   argv[%d]: %s" % (i + 1, argv[i + 1]))
    print("   %s - any local user can read the key from /proc" %
          ("PASS" if has_argv else "FAIL"))

    # --- B: the tool's own log masks it -------------------------------------
    log = (d / "signal.log").read_text(errors="replace") if (d / "signal.log").exists() else ""
    masked = "llm-key=********" in log
    leaked = log.count(CANARY_ARGV)
    results.append(masked and leaked == 0)
    print("== B. the tool's own log ==")
    print("   masked occurrences: %d, raw occurrences: %d" % (log.count("llm-key=********"), leaked))
    print("   %s - logs are redacted; the exposure is the process table" %
          ("PASS" if masked and leaked == 0 else "FAIL"))

    # --- C: a config file carries the key just as well ----------------------
    d = work / "c"
    d.mkdir()
    (d / "cfg.signal").write_text(config_text(uri, CANARY_CONFIG))
    srv.requests.clear()
    p = run(["./target", "--config", "./cfg.signal", "--check-llm", "true"], cwd=d)
    rc, _ = finish(p)
    auths = {r["auth"] for r in srv.requests}
    cfg_ok = ("Bearer " + CANARY_CONFIG) in auths and "--llm-key" not in " ".join(p.args)
    results.append(cfg_ok)
    print("== C. key from --config only ==")
    print("   exit %d, %d request(s) at the endpoint" % (rc, len(srv.requests)))
    print("   Authorization: %s" % (sorted(auths)[0] if auths else "none"))
    print("   %s - a config file is a working alternative to the flag" %
          ("PASS" if cfg_ok else "FAIL"))

    # --- D: .env is not read ------------------------------------------------
    d = work / "d"
    d.mkdir()
    (d / "cfg.signal").write_text(config_text(uri))          # no key
    (d / ".env").write_text("LLM_KEY=%s\nSIGNAL_LLM_KEY=%s\nOPENAI_API_KEY=%s\n"
                            % tuple(CANARY_ENV))
    srv.requests.clear()
    p = run(["./target", "--config", "./cfg.signal", "--check-llm", "true"], cwd=d)
    rc, out = finish(p)
    env_used = any(any(c in r["auth"] for c in CANARY_ENV) for r in srv.requests)
    msg = "At least one LLM API key must be set" in out
    results.append(msg and not env_used and rc == 117)
    print("== D. .env in the working directory ==")
    print("   exit %d, requests carrying a .env canary: %d" % (rc, len(srv.requests)))
    print("   error: %s" % ("At least one LLM API key must be set" if msg else "none"))
    print("   %s - .env is not a supported channel for this key" %
          ("PASS" if msg and not env_used and rc == 117 else "FAIL"))

    srv.shutdown()
    print()
    print("   argv/config key handling: %d/%d" % (sum(results), len(results)))
    print("   use --config with mode 0600; do not pass keys on the command line")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
