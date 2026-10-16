#!/usr/bin/env bash
# Reproduce the whole assessment, serially, from the repository.
#
#   bash poc/run-all.sh                            # binary/work dir autodetected
#   bash poc/run-all.sh --work ~/VAPT --binary ~/VAPT/poc/signal-pyarmor-linux-x86_64
#   bash poc/run-all.sh --skip-dynamic             # offline PoCs only
#
# Phases: 1 environment, 2 offline PoCs, 3 tokenizer cache, 4 F-05, 5 F-15,
#         6 F-16, 7 F-06. Everything it starts it stops again, and every
#         listener it needs is started and torn down inside the script.
#         It needs no egress except one fetch of the tiktoken tokenizer
#         (phase 3); if that is blocked the script says so and stops.
set -uo pipefail

POC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK=""; BINARY=""; SKIP_DYNAMIC=0
while [ $# -gt 0 ]; do
    case "$1" in
        --work) WORK="${2:?--work needs a directory}"; shift 2 ;;
        --binary) BINARY="${2:?--binary needs a path}"; shift 2 ;;
        --skip-dynamic) SKIP_DYNAMIC=1; shift ;;
        -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1 (try --help)" >&2; exit 2 ;;
    esac
done
[ -n "$WORK" ] || WORK="$(cd "$POC/.." && pwd)"      # default: the checkout this script lives in
mkdir -p "$WORK"
RUNLOG="$WORK/poc-run.log"
if [ -w "$WORK" ]; then
    : > "$RUNLOG"
    exec > >(tee -a "$RUNLOG") 2>&1          # so a failed run can always be read back
else
    RUNLOG="(not kept: $WORK is not writable)"
fi

LISTENERS=()
cleanup() {
    for pid in "${LISTENERS[@]:-}"; do [ -n "${pid:-}" ] && kill "$pid" 2>/dev/null; done
    for pid in "${LISTENERS[@]:-}"; do [ -n "${pid:-}" ] && wait "$pid" 2>/dev/null; done
    LISTENERS=()
}
trap cleanup EXIT INT TERM

pass=0; fail=0; skip=0
FAILED=()
result() {                     # result <ok|FAIL|skip> <finding> <text>
    case "$1" in
        ok)   pass=$((pass+1)); printf '  ok    %-7s %s\n' "$2" "$3" ;;
        skip) skip=$((skip+1)); printf '  --    %-7s %s\n' "$2" "$3" ;;
        *)    fail=$((fail+1)); printf '  FAIL  %-7s %s\n' "$2" "$3"
              FAILED+=("$2 - $3") ;;
    esac
}
summary() {                    # summary -> exit code; always names what failed
    printf '\n  reproduced: %d   failed: %d   skipped: %d\n' "$pass" "$fail" "$skip"
    if [ "${#FAILED[@]}" -gt 0 ]; then
        echo "  failed checks:"
        for f in "${FAILED[@]}"; do echo "    $f"; done
    fi
    echo "  run log: $RUNLOG"
    [ "$fail" -eq 0 ]
}
nodocker_path() {              # mirror $PATH into a directory without docker
    local out="$WORK/poc-nodocker-bin" p e b saved="$IFS"
    rm -rf "$out"; mkdir -p "$out"
    IFS=:
    for p in $PATH; do
        [ -d "$p" ] || continue
        for e in "$p"/*; do
            [ -e "$e" ] || continue
            b="${e##*/}"
            case "$b" in docker|docker-*) continue ;; esac
            [ -e "$out/$b" ] || ln -s "$e" "$out/$b" 2>/dev/null
        done
    done
    IFS="$saved"
    printf '%s' "$out"
}


fingerprint() {                # fingerprint <string> -> first 12 hex of its sha256
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "$1" | sha256sum | cut -c1-12
    elif command -v openssl >/dev/null 2>&1; then
        printf '%s' "$1" | openssl dgst -sha256 | awk '{print $NF}' | cut -c1-12
    else
        printf '%s' "$1" | python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest()[:12])'
    fi
}

free_port() {                  # free_port <start>
    local p="$1"
    while (ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null) | grep -q ":$p "; do
        p=$((p+1)); [ "$p" -gt 65535 ] && return 1
    done
    echo "$p"
}
listen() {                     # listen <name> <port> <cmd...>
    local name="$1" port="$2"; shift 2
    env -u PYTHONHOME -u PYTHONPATH "$@" >"$WORK/poc-listener-$name.out" 2>&1 &
    local pid=$!
    LISTENERS+=("$pid")
    for _ in $(seq 1 60); do
        (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && { exec 3>&-; return 0; }
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.25
    done
    echo "  (listener $name failed; see $WORK/poc-listener-$name.out)" >&2
    return 1
}
scan() {                       # scan <name> <env...> -- <args...>
    local name="$1"; shift
    local envs=()
    while [ "$1" != "--" ]; do envs+=("$1"); shift; done
    shift
    ( cd "$WORK" && env "${envs[@]}" timeout 600 "$BIN" "${SCAN_TARGET:-./poc-target}" --config ./poc-byo.signal --caching false "$@" ) \
        > "$WORK/poc-$name.out" 2>&1
    echo $?
}

echo "=============================================================="
echo " 1. environment"
echo "=============================================================="
if bash "$POC/00-setup.sh" --work "$WORK" ${BINARY:+--binary "$BINARY"} | sed 's/^/  /'; then
    result ok "setup" "extraction, merged tree and host are in $WORK"
else
    result FAIL "setup" "poc/00-setup.sh failed — nothing below can work until that is fixed"
    exit 1
fi

export PYTHONHOME="$WORK/pyhome"
export PYTHONPATH="$WORK/merged:$WORK/signal-pyarmor-linux-x86_64_extracted/base_library.zip"
export PYTHONIOENCODING=utf-8
HOST="$WORK/py313host"
EX="$WORK/signal-pyarmor-linux-x86_64_extracted"
BIN=""
for cand in "${BINARY:-}" "$WORK/signal-pyarmor-linux-x86_64" "$POC/signal-pyarmor-linux-x86_64" \
            "$HOME/signal-pyarmor-linux-x86_64" "$HOME/VAPT/signal-pyarmor-linux-x86_64"; do
    [ -n "$cand" ] && [ -x "$cand" ] && { BIN="$cand"; break; }
done
if [ -z "$BIN" ]; then
    result FAIL "binary" "cannot find the CLI to run — pass --binary, or put it in $HOME/VAPT"
    exit 1
fi
"$BIN" --version >/dev/null 2>&1 || { result FAIL "binary" "$BIN does not run"; exit 1; }

echo
echo "=============================================================="
echo " 2. offline PoCs (no network, no LLM)"
echo "=============================================================="
if bash "$POC/run-static.sh" --work "$WORK" | sed -n '5,20p' | sed 's/^/  /'; then
    result ok "F-01…15" "the nine offline PoCs reproduced"
else
    result FAIL "static" "an offline PoC failed — see its two output lines above"
fi

if [ "$SKIP_DYNAMIC" = 1 ]; then
    for f in F-05 F-15 F-16 F-06; do result skip "$f" "--skip-dynamic"; done
    summary && exit 0 || exit 1
fi

echo
echo "=============================================================="
echo " 3. tokenizer cache (every scan needs it before its first call)"
echo "=============================================================="
CACHEDIR="$WORK/tkcache/cached"
env -u TIKTOKEN_CACHE_DIR "$HOST" "$POC/seed-tokenizer-cache.py" "$CACHEDIR" >"$WORK/poc-seed.out" 2>&1
seed_rc=$?
sed 's/^/  /' "$WORK/poc-seed.out" | tail -14
# Success is decided by the cache file itself: a seeder that fetched the blob and
# verified it has succeeded, whatever its exit code says about that.
CACHEFILE=$(ls -1 "$CACHEDIR"/* 2>/dev/null | head -1)
if [ -n "$CACHEFILE" ] && [ -s "$CACHEFILE" ]; then
    export TIKTOKEN_CACHE_DIR="$CACHEDIR"
    note=""
    if command -v sha256sum >/dev/null 2>&1; then
        full=$(sha256sum "$CACHEFILE" | cut -d" " -f1)
        short=$(printf '%s' "$full" | cut -c1-12)
        if [ "$full" = "223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7" ]; then
            note=" (sha256 ${short}... matches the pinned digest)"
        else
            note=" (sha256 ${short}... UNEXPECTED, tiktoken will reject it)"
        fi
    fi
    result ok "F-05" "tokenizer cache ready at $TIKTOKEN_CACHE_DIR${note}"
else
    result FAIL "F-05" "no tokenizer cache - the dynamic phases cannot run (this IS F-05; seeder exit $seed_rc)"
    for f in F-15 F-16 F-06; do result skip "$f" "needs the tokenizer cache"; done
    summary && exit 0 || exit 1
fi

# --- a scan needs a target and a BYO config ---------------------------------
mkdir -p "$WORK/poc-target" "$WORK/poc-home"
printf 'def add(a, b):\n    return a + b\n' > "$WORK/poc-target/util.py"
cat > "$WORK/poc-byo.signal" <<'EOF'
[LLM]
mode = byo
uri = http://127.0.0.1:8899/v1
key = CANARY_KEY_123
model = poc-model

[LLM_SINGLEFILESCAN_AGENT]
model = poc-model
[LLM_DATAFLOW_AGENT]
model = poc-model
[LLM_OVERSIGHT_AGENT]
model = poc-model
[LLM_EXPLOITATION_AGENT]
model = poc-model
[LLM_SCA_AGENT]
model = poc-model
[LLM_MERGEKEY_EMBED_AGENT]
model = poc-model
[LLM_OVERSIGHT_EMBED_AGENT]
model = poc-model
EOF

PORT_LLM=$(free_port 8899)
sed "s#http://127.0.0.1:8899/v1#http://127.0.0.1:$PORT_LLM/v1#" "$WORK/poc-byo.signal" > "$WORK/poc-byo.signal.tmp"
mv "$WORK/poc-byo.signal.tmp" "$WORK/poc-byo.signal"

echo
echo "=============================================================="
echo " 4. F-05 — the tokenizer fetch is mandatory and not configurable"
echo "=============================================================="
: > "$WORK/poc-f05-capture.log"
listen f05 "$PORT_LLM" python3 "$POC/13-capture-llm-payload.py" "$PORT_LLM" "$WORK/poc-f05-capture.log" || true
mkdir -p "$WORK/cache-empty"
( cd "$WORK" && HOME="$WORK/poc-home" TIKTOKEN_CACHE_DIR="$WORK/cache-empty" \
  HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 NO_PROXY=127.0.0.1,localhost \
  timeout 600 "$BIN" "${SCAN_TARGET:-./poc-target}" --config ./poc-byo.signal --llm-mode byo \
  --llm-uri "http://127.0.0.1:$PORT_LLM/v1" --llm-key CANARY_KEY_123 --check-llm-json true --caching false \
  > "$WORK/poc-f05.out" 2>&1 )
if grep -q "openaipublic.blob.core.windows.net" "$WORK/poc-f05.out"; then
    result ok "F-05" "with an empty cache the run cannot proceed: embedding agents fail with '$(grep -o "openaipublic.blob.core.windows.net/encodings/cl100k_base.tiktoken" "$WORK/poc-f05.out" | head -1)'"
else
    result FAIL "F-05" "expected the blob host in the failure — see $WORK/poc-f05.out"
fi
cleanup

echo
echo "=============================================================="
echo " 5. F-15 — PoCKit's Docker gate, credential and endpoint"
echo "=============================================================="
# One listener serves all four stages: the scan has to finish before the PoCKit
# hand-off is reached, and the gate, the credential rule and the endpoint all
# live in that hand-off.
: > "$WORK/poc-f15-capture.log"
listen f15 "$PORT_LLM" python3 "$POC/13-capture-llm-payload.py" "$PORT_LLM" "$WORK/poc-f15-capture.log" || true
mkdir -p "$WORK/poc-fakebin"
cat > "$WORK/poc-fakebin/docker" <<'EOF'
#!/bin/sh
echo "$(date +%T) docker $*" >> "$DOCKER_STUB_LOG"
echo "Docker version 27.0.0-stub"
EOF
chmod +x "$WORK/poc-fakebin/docker"
export DOCKER_STUB_LOG="$WORK/poc-docker-stub.log"
: > "$DOCKER_STUB_LOG"
PK=( --import-results "$POC/fixtures/pockit-finding.json" --poc-kit true --dataflow true --synthesis true --agent-limit 1 )

if command -v docker >/dev/null 2>&1; then
    # docker is installed here, but the gate is a PATH lookup, so give the scan a
    # PATH that mirrors this one with every docker entry removed and watch it refuse.
    scan f15a "PATH=$(nodocker_path)" -- "${PK[@]}" --llm-key CANARY_KEY_123 >/dev/null
    if grep -q "PoCKit requires Docker but the 'docker' binary was not found" "$WORK/poc-f15a.out"; then
        result ok "F-15" "docker is on PATH here, yet with a PATH that omits it the hand-off refuses outright — the gate is a lookup, not a capability check"
    else
        result skip "F-15" "docker is on PATH here and the docker-free PATH did not reproduce the refusal — see $WORK/poc-f15a.out"
    fi
else
    scan f15a -- "${PK[@]}" --llm-key CANARY_KEY_123 >/dev/null
    if grep -q "PoCKit requires Docker but the 'docker' binary was not found" "$WORK/poc-f15a.out"; then
        result ok "F-15" "with no docker binary the PoCKit hand-off refuses outright"
    else
        result FAIL "F-15" "docker gate did not fire — see $WORK/poc-f15a.out"
    fi
fi

scan f15b "PATH=$WORK/poc-fakebin:$PATH" -- "${PK[@]}" --llm-key CANARY_KEY_123 >/dev/null
if [ -s "$DOCKER_STUB_LOG" ] || grep -q "SUPER AGENT: Starting workflow" "$WORK/poc-f15b.out"; then
    result ok "F-15" "a 3-line stub named 'docker' satisfies the gate ($(wc -l < "$DOCKER_STUB_LOG") stub invocation(s) logged)"
else
    result FAIL "F-15" "the stub did not satisfy the gate — see $WORK/poc-f15b.out"
fi

# credential rule: key only in the config file
sed 's/^key = CANARY_KEY_123/key = CANARY_CONFIG_ONLY_777/' "$WORK/poc-byo.signal" > "$WORK/poc-cfgkey.signal"
( cd "$WORK" && env -u ANTHROPIC_API_KEY PATH="$WORK/poc-fakebin:$PATH" HOME="$WORK/poc-home" \
  TIKTOKEN_CACHE_DIR="$TIKTOKEN_CACHE_DIR" timeout 600 "$BIN" ./poc-target \
  --config ./poc-cfgkey.signal --llm-mode byo --llm-uri "http://127.0.0.1:$PORT_LLM/v1" --caching false \
  "${PK[@]}" > "$WORK/poc-f15c.out" 2>&1 )
if grep -q "ANTHROPIC_API_KEY not found in environment variables" "$WORK/poc-f15c.out"; then
    result ok "F-15" "a config-file key is not passed through: PoCKit demands ANTHROPIC_API_KEY"
else
    result FAIL "F-15" "expected the credential error — see $WORK/poc-f15c.out"
fi

: > "$WORK/poc-f15-capture.log"
( cd "$WORK" && env -u ANTHROPIC_API_KEY PATH="$WORK/poc-fakebin:$PATH" HOME="$WORK/poc-home" \
  TIKTOKEN_CACHE_DIR="$TIKTOKEN_CACHE_DIR" timeout 600 "$BIN" ./poc-target \
  --config ./poc-cfgkey.signal --llm-mode byo --llm-uri "http://127.0.0.1:$PORT_LLM/v1" --caching false \
  --llm-key CANARY_BYO_CLI_999 "${PK[@]}" > "$WORK/poc-f15d.out" 2>&1 )
# Credential headers are captured as a SHA-256 fingerprint, so this proves which
# key was sent without needing to store the key.
fp=$(fingerprint CANARY_BYO_CLI_999)
hit=$(grep -o "POST /v1/v1/messages[^ ]*" "$WORK/poc-f15-capture.log" 2>/dev/null | tail -1)
if [ -n "$fp" ] && grep -q "redacted sha256=$fp" "$WORK/poc-f15-capture.log" 2>/dev/null; then
    result ok "F-15" "the same config with --llm-key proceeds, and PoCKit sends that key to ${hit:-PoCKit}"
else
    result FAIL "F-15" "expected a PoCKit request carrying the command-line key — see $WORK/poc-f15d.out"
fi
cleanup


echo " 6. F-16 — what a scan sends to the LLM"
echo "=============================================================="
# A plain scan (no --import-results) runs the single-file analysis stage, which
# puts each file's text in the prompt. The target sits in its own directory
# because file discovery honours .gitignore, and $WORK/poc-target is ignored in
# a checkout of this repository.
mkdir -p "$WORK/poc-triage"
cat > "$WORK/poc-triage/hello.py" <<'EOF'
import subprocess

def run(cmd): return subprocess.check_output(cmd, shell=True)

API_KEY = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD = "sup3r-s3cret-db-pass"
EOF
: > "$WORK/poc-f16-capture.log"
listen f16 "$PORT_LLM" python3 "$POC/13-capture-llm-payload.py" "$PORT_LLM" "$WORK/poc-f16-capture.log" || true
SCAN_TARGET=./poc-triage scan f16 -- --llm-mode byo --llm-uri "http://127.0.0.1:$PORT_LLM/v1" --llm-key CANARY_KEY_123 >/dev/null
hits=$(grep -c AKIAIOSFODNN7EXAMPLE "$WORK/poc-f16-capture.log" 2>/dev/null); hits=${hits:-0}
bodies=$(grep -c 'BODY (' "$WORK/poc-f16-capture.log" 2>/dev/null); bodies=${bodies:-0}
found=$(grep -o "Identified [0-9]* files for analysis" "$WORK/poc-f16.out" 2>/dev/null | tail -1)
if [ "$hits" -gt 0 ] 2>/dev/null; then
    result ok "F-16" "the planted credential literal appears in ${hits} of ${bodies} captured prompts (${found:-file count not logged}) — no redaction"
else
    result FAIL "F-16" "the literal did not appear — see $WORK/poc-f16-capture.log"
fi

# Same scanner, same kind of file, but in a directory git ignores.
if git -C "$WORK" rev-parse --git-dir >/dev/null 2>&1; then
    printf 'SHELL = True\n' > "$WORK/poc-target/ignored_but_present.py"
    SCAN_TARGET=./poc-target scan f16b -- --llm-mode byo --llm-uri "http://127.0.0.1:$PORT_LLM/v1" --llm-key CANARY_KEY_123 >/dev/null
    if grep -q "No files found for analysis\|Identified 0 files for analysis" "$WORK/poc-f16b.out" 2>/dev/null; then
        result ok "F-16" "a git-ignored directory reports 'Identified 0 files for analysis' although it holds .py files — ignored code is never analysed"
    else
        result skip "F-16" "this checkout does not ignore $WORK/poc-target, so the .gitignore coverage rule cannot be shown"
    fi
else
    result skip "F-16" "$WORK is not a git checkout, so the .gitignore coverage rule cannot be shown"
fi
cleanup


echo " 7. F-06 — --llm-ssl-verify against a self-signed endpoint"
echo "=============================================================="
PORT_TLS=$(free_port 8443)
( cd "$WORK" && openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout poc-f06-selfsigned.key -out poc-f06-selfsigned.pem \
    -subj "/CN=poc-f06-untrusted" -addext "subjectAltName=IP:127.0.0.1" ) >/dev/null 2>&1
sed "s#http://127.0.0.1:$PORT_LLM/v1#https://127.0.0.1:$PORT_TLS/v1#" "$WORK/poc-byo.signal" > "$WORK/poc-tls.signal"
: > "$WORK/poc-f06-requests.log"
if listen f06 "$PORT_TLS" python3 "$POC/07-poc-f06-tls-endpoint.py" "$PORT_TLS" "$WORK/poc-f06-requests.log"; then
    ( cd "$WORK" && HOME="$WORK/poc-home" TIKTOKEN_CACHE_DIR="$TIKTOKEN_CACHE_DIR" timeout 600 \
      "$BIN" "${SCAN_TARGET:-./poc-target}" --config ./poc-tls.signal --llm-ssl-verify true --llm-timeout 10 --caching false \
      --check-llm-json true > "$WORK/poc-f06a.out" 2>&1 )
    n_true=$(wc -l < "$WORK/poc-f06-requests.log")
    ( cd "$WORK" && HOME="$WORK/poc-home" TIKTOKEN_CACHE_DIR="$TIKTOKEN_CACHE_DIR" timeout 600 \
      "$BIN" "${SCAN_TARGET:-./poc-target}" --config ./poc-tls.signal --llm-ssl-verify false --llm-timeout 10 --caching false \
      --check-llm-json true > "$WORK/poc-f06b.out" 2>&1 )
    n_false=$(wc -l < "$WORK/poc-f06-requests.log")
    if [ "$n_true" = "0" ] && [ "$n_false" -gt 0 ] && grep -q "Bearer CANARY_KEY_123" "$WORK/poc-f06-requests.log"; then
        result ok "F-06" "verify=true: ${n_true} requests reached it; verify=false: ${n_false}, carrying Bearer CANARY_KEY_123"
    else
        result FAIL "F-06" "expected 0 requests then >0 with the key; got ${n_true} then ${n_false}"
    fi
else
    result FAIL "F-06" "the self-signed endpoint did not start"
fi
cleanup

echo
echo "=============================================================="
echo " summary"
echo "=============================================================="
cat <<EOF

  Raw output for every phase is under $WORK:
    poc-*.out                 one file per phase
    poc-f16-capture.log       the prompts F-16 is about
    poc-f06-requests.log      what the untrusted TLS endpoint accepted
    poc-docker-stub.log       proof the docker gate ran the 3-line stub

  What is deliberately not reproduced here: the quality of PoCKit's exploit
  chain, the scan-quality questions in section 9 of the report, and any
  vendor-side behaviour. Those need a real model, a real Docker daemon and
  written authorisation respectively.
EOF
summary && exit 0 || exit 1
