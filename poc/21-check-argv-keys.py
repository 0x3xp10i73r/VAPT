#!/usr/bin/env python3
"""F-07 / CWE-214: API keys exposed in visible process arguments.

Claims checked, each PASS/FAIL:

  A  --llm-key is present as a separate cleartext field in /proc/<pid>/cmdline;
     if passwordless sudo is available, also read it as the *nobody* user
  B  the tool's own log masks that key (the exposure is in argv, not the log)
  C  a key supplied *only* through --config reaches a loopback endpoint, showing
     that a file is a working alternative to the vulnerable command-line flag
  D  an ordinary .env does not substitute for the config file in this mode

Use only synthetic canaries. Does not contact a real LLM. The first run can
reassemble the pinned binary from this repository's binary-drop branch.

    env -u PYTHONHOME -u PYTHONPATH python3 poc/21-check-argv-keys.py
"""
import argparse
import hashlib
import http.server
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time

REPO = pathlib.Path(__file__).resolve().parents[1]
BINARY_NAME = "signal-pyarmor-linux-x86_64"
EXPECTED_SIZE = 116823456
EXPECTED_SHA256 = "47b9fa7236a5be5ed37a9186d55a6a84b8d2ef65fd0ab9e2fa744b0641c7d915"


def verify_binary(path):
    """Refuse a binary other than the one stored in this repository (v1.0)."""
    path = path.expanduser().resolve()
    if not path.is_file():
        raise ValueError("binary not found: %s" % path)
    if path.stat().st_size != EXPECTED_SIZE:
        raise ValueError("wrong binary size: %s" % path)
    h = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            h.update(block)
    if h.hexdigest() != EXPECTED_SHA256:
        raise ValueError("wrong binary SHA-256: %s" % path)
    if not os.access(path, os.X_OK):
        raise ValueError("binary is not executable (chmod +x): %s" % path)
    return path


def find_binary(explicit=None):
    if explicit:
        return verify_binary(pathlib.Path(explicit))
    for path in (REPO / BINARY_NAME, pathlib.Path("/tmp/vapt") / BINARY_NAME):
        if path.is_file():
            return verify_binary(path)

    # Download *only* from this checkout's own binary-drop branch, never a
    # third-party binary. SHA-256 verification prevents a mistaken artefact.
    print("binary absent; reassembling from this repo's binary-drop branch...")
    git = ["git", "-C", str(REPO)]
    ref = "refs/remotes/origin/binary-drop"
    cached = subprocess.run(git + ["rev-parse", "--verify", "--quiet", ref + "^{commit}"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if cached.returncode:
        subprocess.run(git + ["fetch", "--no-tags", "origin", "binary-drop:" + ref],
                       check=True)
    path = pathlib.Path("/tmp/vapt") / BINARY_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_name(path.name + ".assembling-%d" % os.getpid())
    try:
        with partial.open("wb") as output:
            for index in ("00", "01"):
                subprocess.run(git + ["show", ref + ":" + BINARY_NAME + ".part-" + index],
                               stdout=output, check=True)
        partial.chmod(0o700)
        verify_binary(partial)
        partial.replace(path)
    finally:
        partial.unlink(missing_ok=True)
    return path


def other_uid_read(pid, canary):
    """Optional extra check: read /proc as uid nobody, never as root."""
    proc = "/proc/%d/cmdline" % pid
    if os.geteuid() == 0 and shutil.which("setpriv"):
        cmd = ["setpriv", "--reuid", "nobody", "--regid", "nogroup",
               "--clear-groups", "cat", proc]
    elif shutil.which("sudo"):
        cmd = ["sudo", "-n", "-u", "nobody", "--", "cat", proc]
    else:
        return None, "no passwordless sudo/setpriv; optional check skipped"
    try:
        probe = subprocess.run(cmd, capture_output=True, timeout=3)
    except (OSError, subprocess.TimeoutExpired):
        return None, "cannot run unprivileged probe; optional check skipped"
    if probe.returncode and cmd[0] == "sudo" and probe.stderr.lstrip().startswith(b"sudo:"):
        return None, "non-interactive sudo unavailable; optional check skipped"
    return probe.returncode == 0 and canary.encode() in probe.stdout, "uid nobody"

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


def run(binary, args, cwd):
    # No inherited real keys may affect the controls. Force outbound HTTP(S)
    # through a *loopback* refusing proxy: F-05's missing tokenizer vocabulary
    # must not send this PoC to a third party. The mock endpoint bypasses it.
    ignored = ("PYTHONHOME", "PYTHONPATH", "LLM_KEY", "SIGNAL_LLM_KEY",
               "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AWS_BEARER_TOKEN_BEDROCK")
    clean_env = {k: v for k, v in os.environ.items() if k not in ignored}
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy",
                "https_proxy", "all_proxy"):
        clean_env[key] = "http://127.0.0.1:9"
    for key in ("NO_PROXY", "no_proxy"):
        clean_env[key] = "localhost,127.0.0.1,::1"
    cache = cwd / "tkcache"
    cache.mkdir(exist_ok=True)
    clean_env["TIKTOKEN_CACHE_DIR"] = str(cache)
    return subprocess.Popen([str(binary)] + args, cwd=cwd, env=clean_env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def finish(p, timeout=120):
    try:
        out, _ = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        out, _ = p.communicate()
    return p.returncode, out or ""


def show_check(number, title, passed, *details):
    """Show the observed behavior first; PASS means verified, not 'secure'."""
    print("%d/4  %s — %s" % (number, "PASS" if passed else "FAIL", title))
    for detail in details:
        print("     %s" % detail)
    print()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", help="path to the v1.0 ELF (otherwise find or fetch it from this repo)")
    opts = parser.parse_args()
    if not pathlib.Path("/proc/self/cmdline").is_file():
        print("Linux /proc is required for the CWE-214 test", file=sys.stderr)
        return 2
    try:
        binary = find_binary(opts.binary)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print("cannot use repository binary: %s" % exc, file=sys.stderr)
        return 2
    print("F-07 / CWE-214 — Can a command-line API key be seen by others?")
    print("Using FAKE keys; LLM requests go only to a local test server.")
    print("PASS means an observation was confirmed, NOT that Signal is safe.")
    print("Signal binary: v1.0 SHA-256 verified (%s)" % binary)
    print()

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
    srv.requests.clear()
    p = run(binary, [str(target), "--config", "./cfg.signal", "--llm-key", CANARY_ARGV,
                     "--check-llm", "true"], cwd=d)
    raw, mode = b"", None
    for _ in range(300):
        try:
            raw = pathlib.Path("/proc/%d/cmdline" % p.pid).read_bytes()
            mode = os.stat("/proc/%d/cmdline" % p.pid).st_mode & 0o777
        except (FileNotFoundError, ProcessLookupError):
            break
        if CANARY_ARGV.encode() in raw:
            break
        time.sleep(0.01)
    other_ok, other_note = other_uid_read(p.pid, CANARY_ARGV) if CANARY_ARGV.encode() in raw else (None, "process exited")
    finish(p)

    argv = [x.decode(errors="replace") for x in raw.split(b"\0") if x] if raw else []
    has_argv = any(argv[i:i + 2] == ["--llm-key", CANARY_ARGV] for i in range(len(argv) - 1))
    cli_auth = sum(r["auth"] == "Bearer " + CANARY_ARGV for r in srv.requests)
    results.append(has_argv and mode is not None and bool(mode & 0o004) and cli_auth > 0)
    if other_ok is True:
        other_line = "Could a DIFFERENT local user read it? YES (tested as 'nobody')"
    elif other_ok is False:
        other_line = "Different-user read: NOT CONFIRMED (this host may restrict /proc)"
    else:
        other_line = "Different-user check: SKIPPED (%s)" % other_note
    show_check(1, "Key on the command line is exposed", results[-1],
               "Started Signal with: --llm-key %s" % CANARY_ARGV,
               "Found in Linux's process list (/proc/%d/cmdline): %s" %
               (p.pid, "--llm-key " + CANARY_ARGV if has_argv else "KEY NOT FOUND"),
               other_line,
               "Did Signal use this fake key? %s (%d local test requests received it)" %
               ("YES" if cli_auth else "NO", cli_auth))

    # --- B: the tool's own log masks it -------------------------------------
    # The --check-llm validation used for A returns *before* the regular scan
    # logger starts. Make a second run so the log-redaction control is real.
    d = work / "b"
    d.mkdir()
    (d / "cfg.signal").write_text(config_text(uri))
    p = run(binary, [str(target), "--config", "./cfg.signal", "--llm-key", CANARY_ARGV,
                     "--check-llm", "false"], cwd=d)
    finish(p)
    log = (d / "signal.log").read_text(errors="replace") if (d / "signal.log").exists() else ""
    masked = "llm-key=********" in log
    leaked = log.count(CANARY_ARGV)
    results.append(masked and leaked == 0)
    show_check(2, "Signal's own log hides the key, but the process list does not", results[-1],
               "Log entry for --llm-key: %s" %
               ("--llm-key=********" if masked else "NO MASKED ENTRY FOUND"),
               "Fake key printed in Signal's log: %s" % ("YES" if leaked else "NO"))

    # --- C: a config file carries the key just as well ----------------------
    d = work / "c"
    d.mkdir()
    (d / "cfg.signal").write_text(config_text(uri, CANARY_CONFIG))
    (d / "cfg.signal").chmod(0o600)
    srv.requests.clear()
    p = run(binary, [str(target), "--config", "./cfg.signal", "--check-llm", "true"], cwd=d)
    finish(p)
    auths = {r["auth"] for r in srv.requests}
    cfg_ok = ("Bearer " + CANARY_CONFIG) in auths and "--llm-key" not in p.args
    results.append(cfg_ok)
    show_check(3, "Safer option: a protected config file works", results[-1],
               "Put a different fake key in a private config file (mode 0600).",
               "Was this key on the command line? %s" %
               ("YES" if "--llm-key" in p.args else "NO"),
               "Did Signal accept the config-file key? %s (%d local test requests)" %
               ("YES" if "Bearer " + CANARY_CONFIG in auths else "NO", len(srv.requests)))

    # --- D: .env is not read ------------------------------------------------
    d = work / "d"
    d.mkdir()
    (d / "cfg.signal").write_text(config_text(uri))          # no key
    (d / ".env").write_text("LLM_KEY=%s\nSIGNAL_LLM_KEY=%s\nOPENAI_API_KEY=%s\n"
                            % tuple(CANARY_ENV))
    srv.requests.clear()
    p = run(binary, [str(target), "--config", "./cfg.signal", "--check-llm", "true"], cwd=d)
    rc, out = finish(p)
    env_hits = [r for r in srv.requests if any(c in r["auth"] for c in CANARY_ENV)]
    env_used = bool(env_hits)
    msg = "At least one LLM API key must be set" in out
    results.append(msg and not env_used and rc == 117)
    show_check(4, "A .env file alone does NOT supply the key", results[-1],
               "Created .env with fake LLM_KEY, SIGNAL_LLM_KEY and OPENAI_API_KEY values.",
               "Signal's response: %s" %
               ('"At least one LLM API key must be set"' if msg else "no missing-key error"),
               "Local test server received a key from .env: %s" %
               ("YES" if env_used else "NO"))

    srv.shutdown()
    print("F-07 reproduced: %d/%d (CWE-214)" % (sum(results), len(results)))
    if all(results):
        if other_ok is True:
            print("CONCLUSION: Another local account could read the fake API key while Signal ran.")
        else:
            print("CONCLUSION: The fake key appeared in the process list; access from a")
            print("different account was not confirmed on this machine.")
        print("RISK: Someone with local access could copy a real key passed via --llm-key.")
        print("This does not by itself give a remote attacker access.")
        print("Use --config with permission 0600 instead; .env is not auto-loaded.")
    else:
        print("INCONCLUSIVE: At least one check failed. See the FAIL lines above.")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
