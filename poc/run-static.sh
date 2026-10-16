#!/usr/bin/env bash
# Run the PoCs that need no LLM endpoint or network, i.e. everything that can be
# checked on a machine with no egress. Prints one line per PoC with the number
# that matters, and exits non-zero if any of them failed.
#
#   bash poc/run-static.sh              # work dir = the extraction's parent
#   bash poc/run-static.sh --work ~/VAPT
#
# Run poc/00-setup.sh first: this script needs the merged tree, pyhome and
# py313host that it builds.
set -uo pipefail

POC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK=""
while [ $# -gt 0 ]; do
    case "$1" in
        --work) WORK="${2:?--work needs a directory}"; shift 2 ;;
        -h|--help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1 (try --help)" >&2; exit 2 ;;
    esac
done

# Locate the extraction, then derive everything else from it.
find_extract() {
    local cands=()
    [ -n "${SIGNAL_EXTRACT:-}" ] && cands+=("$SIGNAL_EXTRACT")
    [ -n "$WORK" ] && cands+=("$WORK/signal-pyarmor-linux-x86_64_extracted")
    cands+=("$PWD/signal-pyarmor-linux-x86_64_extracted"
            "$(cd "$POC/.." && pwd)/signal-pyarmor-linux-x86_64_extracted"
            "/tmp/vapt/signal-pyarmor-linux-x86_64_extracted")
    for c in "${cands[@]}"; do
        [ -d "$c/PYZ.pyz_extracted" ] && { printf '%s\n' "$c"; return 0; }
    done
    return 1
}

EX="$(find_extract)" || {
    echo "No extraction found. Run poc/00-setup.sh first (see poc/README.md)." >&2
    exit 1
}
[ -n "$WORK" ] || WORK="$(dirname "$(cd "$EX" && pwd)")"

HOST=""
for c in "$WORK/py313host" "$PWD/py313host" "$(dirname "$POC")/py313host"; do
    [ -x "$c" ] && { HOST="$c"; break; }
done
[ -n "$HOST" ] || { echo "py313host not found under $WORK — run poc/00-setup.sh" >&2; exit 1; }

export PYTHONHOME="$WORK/pyhome"
export PYTHONPATH="$WORK/merged:$EX/base_library.zip"
export PYTHONIOENCODING=utf-8

MERGED="${PYTHONPATH%%:*}"
[ -d "$MERGED" ] || { echo "merged tree missing: $MERGED — run poc/00-setup.sh" >&2; exit 1; }
[ -d "$PYTHONHOME" ] || { echo "pyhome missing: $PYTHONHOME — run poc/00-setup.sh" >&2; exit 1; }

echo "extraction : $EX"
echo "host       : $HOST"
LIB="$EX/libpython3.13.so.1.0"
[ -r "$LIB" ] && echo "libpython  : $LIB" || echo "libpython  : MISSING at $LIB"
echo

fails=0
run() {                      # run <label> <finding> <expect-grep> <cmd...>
    local label="$1" finding="$2" expect="$3"; shift 3
    local out rc
    out="$("$@" 2>&1)"; rc=$?
    local got
    got="$(printf '%s\n' "$out" | grep -m1 -E "$expect" | sed 's/^[[:space:]]*//' || true)"
    if [ $rc -eq 0 ] && [ -n "$got" ]; then
        printf '  ok   %-26s %-14s %s\n' "$label" "$finding" "$(printf '%s' "$got" | cut -c1-58)"
    else
        fails=$((fails + 1))
        printf '  FAIL %-26s %-14s rc=%s %s\n' "$label" "$finding" "$rc" \
               "$(printf '%s\n' "$out" | head -2 | tr '\n' ' ' | cut -c1-90)"
    fi
}

cd "$WORK" || exit 1
run 03-armored-module-survey  "F-03 F-14" "imported successfully"   "$HOST" "$POC/03-armored-module-survey.py"
run 04-protected-metadata    "F-03"      "total harvested entries" "$HOST" "$POC/04-protected-metadata-dump.py"
run 05-poc-f01-host-shell    "F-01"      "host file .* created"    "$HOST" "$POC/05-poc-f01-host-shell.py"
run 06-poc-f02-workspace     "F-02"      "mode=0o755"              "$HOST" "$POC/06-poc-f02-workspace.py" --extract "$EX"
run 08-runtime-versions      "F-04 F-09" "^ssl +:"                 "$HOST" "$POC/08-collect-runtime-versions.py"
run 09-advisory-ranges       "F-11 F-12" "affected range: [0-9]+"  "$HOST" "$POC/09-check-advisory-ranges.py"
run 10-introspect-module     "F-03"      "classes    : [0-9]+"     "$HOST" "$POC/10-introspect-protected-module.py"
run 11-pockit-endpoint       "F-15"      "https://llm.labs.blackduck.com" "$HOST" "$POC/11-analyse-pockit-endpoint.py"
run 12-disassemble-pyc       "F-01 F-02" "^### .*run_shell"        "$HOST" "$POC/12-disassemble-pyc.py" pockit/agents/shared_tools.pyc run_shell

echo
if [ "$fails" -eq 0 ]; then
    echo "all nine static PoCs reproduced. The environment is sound."
    cat <<'EOF'

Not covered here, because each needs the real binary and a listening endpoint
(see poc/README.md, "Dynamic — needs the real binary"):

  F-05  the mandatory tokenizer fetch      -> run a scan with no seeded cache
  F-06  --llm-ssl-verify false             -> poc/07 + two scans
  F-15  PoCKit's Docker gate and endpoint  -> docker stub + a scan
  F-16  what a scan sends to the LLM       -> poc/13 + a scan

Seed the cache first, or every scan stops before its first request:

    ./py313host poc/seed-tokenizer-cache.py
EOF
    exit 0
fi
echo "$fails static PoC(s) failed — the two lines above each failure are the diagnosis." >&2
exit 1
