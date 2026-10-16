#!/bin/sh
# setup-check.sh — verify the client environment before running the Signal PoC kit.
#
# Usage:  bash setup-check.sh [/path/to/signal-pyarmor-linux-x86_64]
#         (default: ./signal-pyarmor-linux-x86_64 in the current directory)
#
# Exit code 0 = environment ready (warnings allowed), 1 = blocking problems.

set -u
BIN="${1:-./signal-pyarmor-linux-x86_64}"
EXPECT_SHA="47b9fa7236a5be5ed37a9186d55a6a84b8d2ef65fd0ab9e2fa744b0641c7d915"
fail=0; warn=0

ok()   { printf '  [ OK ]  %s\n' "$1"; }
bad()  { printf '  [FAIL]  %s\n' "$1"; fail=$((fail+1)); }
note() { printf '  [WARN]  %s\n' "$1"; warn=$((warn+1)); }

echo "===================================================================="
echo " Black Duck Signal 2026.9.0 — PoC kit environment check"
echo " target binary: $BIN"
echo "===================================================================="

# --- platform ------------------------------------------------------------
case "$(uname -s)" in
  Linux) ok "platform: Linux ($(uname -r))" ;;
  *)     bad "platform: $(uname -s) — the target is a Linux x86_64 ELF; use WSL2/Docker on Windows" ;;
esac
case "$(uname -m)" in
  x86_64) ok "architecture: x86_64" ;;
  *)      bad "architecture: $(uname -m) — binary requires x86_64" ;;
esac

# --- target binary -------------------------------------------------------
if [ -x "$BIN" ]; then
  ok "binary present and executable"
  H=$(sha256sum "$BIN" 2>/dev/null | cut -d' ' -f1)
  if [ "$H" = "$EXPECT_SHA" ]; then
    ok "SHA-256 matches the assessed binary (Signal 2026.9.0)"
  else
    note "SHA-256 mismatch (got ${H:-<none>}) — different version/build; PoCs were validated against 2026.9.0 and may behave differently"
    "$BIN" --version >/dev/null 2>&1 && note "binary self-reports: $("$BIN" --version 2>/dev/null | tr -d '\n')"
  fi
else
  bad "binary not found or not executable: $BIN"
  echo "         pass the path explicitly:  bash setup-check.sh /path/to/signal-pyarmor-linux-x86_64"
fi

# --- tools ---------------------------------------------------------------
if command -v python3 >/dev/null 2>&1; then
  ok "python3: $(python3 -V 2>&1)"
else
  bad "python3 is required (apt install python3)"
fi

if python3 -c "import venv" >/dev/null 2>&1; then
  ok "python3 venv module (SIG-02 bundle extraction)"
else
  note "python3 venv module missing (apt install python3-venv) — SIG-02 will be skipped"
fi

if command -v gcc >/dev/null 2>&1; then
  ok "gcc: $(gcc --version 2>/dev/null | head -1) (CHK-04 LD_PRELOAD)"
else
  note "gcc missing (apt install gcc) — CHK-04 will be skipped"
fi

if command -v readelf >/dev/null 2>&1 && command -v nm >/dev/null 2>&1; then
  ok "binutils (readelf/nm) for hardening checks"
else
  note "binutils missing (apt install binutils) — manual hardening checks unavailable"
fi

# --- port ----------------------------------------------------------------
if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -q ':8899 '; then
  note "port 8899 already in use — start the runner with --port 8890 (and update nothing else; the kit self-configures)"
fi

# --- disk space (SIG-02 extracts ~450 MB + patched copy ~112 MB) ---------
AVAIL_KB=$(df -Pk . 2>/dev/null | awk 'NR==2 {print $4}')
if [ -n "${AVAIL_KB:-}" ] && [ "$AVAIL_KB" -lt 1500000 ] 2>/dev/null; then
  note "only $((AVAIL_KB/1024)) MB free — SIG-02/CHK-03 need ~1.5 GB headroom in the workdir"
fi

# --- network (non-fatal; determines which PoC outcomes to expect) --------
if curl -m 8 -sf -o /dev/null https://pypi.org/simple/ 2>/dev/null; then
  ok "internet reachable (pypi.org — SIG-02 pip install)"
else
  note "pypi.org unreachable — SIG-02 (bundle extraction) will be skipped"
fi
if curl -m 8 -sf -o /dev/null https://openaipublic.blob.core.windows.net/encodings/cl100k_base.tiktoken 2>/dev/null; then
  ok "tiktoken CDN reachable (SIG-01b/SIG-05a run fully online)"
  note "CDN download succeeded — a ~1.7 MB encoding file was just fetched; this is exactly what SIG-05a demonstrates"
else
  note "tiktoken CDN unreachable — SIG-05a will show 'fetch attempted (blocked)' + E63 (still REPRODUCED); SIG-01b needs --tiktoken-file (see REPRODUCTION-GUIDE.md)"
fi

echo "--------------------------------------------------------------------"
if [ "$fail" -gt 0 ]; then
  echo " RESULT: $fail blocking issue(s), $warn warning(s). Fix the FAIL items first."
  exit 1
fi
echo " RESULT: environment ready ($fail blocking, $warn warning(s))."
echo " Next:   python3 run_all_pocs.py --binary $BIN"
exit 0
