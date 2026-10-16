#!/usr/bin/env bash
# Prepare everything the PoCs need, from the raw binary to a working py313host.
#
# Automates steps 1-5 of README.md (verify, extract, repair, merge, build host)
# and finishes with the smoke test, so you do not have to carry environment
# variables between commands by hand.
#
#   bash poc/00-setup.sh                        # binary + workdir autodetected
#   bash poc/00-setup.sh --work /tmp/vapt
#   bash poc/00-setup.sh --binary ./signal-pyarmor-linux-x86_64 --work ~/vapt
#
# Re-running is safe: completed steps are detected and skipped.
set -euo pipefail

EXPECTED_SHA=47b9fa7236a5be5ed37a9186d55a6a84b8d2ef65fd0ab9e2fa744b0641c7d915
EXPECTED_SIZE=116823456

WORK=/tmp/vapt
BINARY=""
while [ $# -gt 0 ]; do
    case "$1" in
        --work)   WORK="${2:?--work needs a directory}"; shift 2 ;;
        --binary) BINARY="${2:?--binary needs a path}"; shift 2 ;;
        -h|--help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1 (try --help)" >&2; exit 2 ;;
    esac
done

POC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
command -v gcc     >/dev/null || { echo "gcc is required (apt-get install gcc libc6-dev)" >&2; exit 1; }

mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"          # absolute, so later `cd`s cannot change it
cd "$WORK"

# ---------------------------------------------------------------- 1. the binary
REPO_ROOT="$(cd "$POC/.." && pwd)"
CANDIDATES=(
    "$WORK/signal-pyarmor-linux-x86_64"
    "$PWD/signal-pyarmor-linux-x86_64"
    "$REPO_ROOT/signal-pyarmor-linux-x86_64"
    "$HOME/signal-pyarmor-linux-x86_64"
    "/tmp/vapt/signal-pyarmor-linux-x86_64"
)

if [ -n "$BINARY" ]; then
    if [ ! -f "$BINARY" ]; then
        echo "binary not found: $BINARY" >&2
        echo "    current directory: $PWD" >&2
        echo "    (a relative path is resolved against the current directory," >&2
        echo "     so use an absolute one if you are not in the right place)" >&2
        echo >&2
        echo "Locate a copy you already have — this also searches Windows drives:" >&2
        echo "    find \"\$HOME\" /mnt /tmp -maxdepth 6 \\" >&2
        echo "        -name 'signal-pyarmor-linux-x86_64*' -size +50M 2>/dev/null" >&2
        echo >&2
        echo "Or re-fetch it (README.md step 1):" >&2
        echo "    git -C '$REPO_ROOT' fetch origin binary-drop:refs/remotes/origin/binary-drop" >&2
        echo "    git -C '$REPO_ROOT' show origin/binary-drop:signal-pyarmor-linux-x86_64.part-00 > part-00" >&2
        echo "    git -C '$REPO_ROOT' show origin/binary-drop:signal-pyarmor-linux-x86_64.part-01 > part-01" >&2
        echo "    cat part-00 part-01 > '$REPO_ROOT/signal-pyarmor-linux-x86_64'" >&2
        exit 1
    fi
else
    for cand in "${CANDIDATES[@]}"; do
        [ -f "$cand" ] && { BINARY="$cand"; break; }
    done
fi

if [ -z "$BINARY" ]; then
    echo "No binary found. Searched:" >&2
    printf '    %s\n' "${CANDIDATES[@]}" >&2
    echo >&2
    echo "Pass one explicitly with --binary, or fetch it (README.md step 1):" >&2
    echo "    git -C '$REPO_ROOT' fetch origin binary-drop:refs/remotes/origin/binary-drop" >&2
    echo "    git -C '$REPO_ROOT' show origin/binary-drop:signal-pyarmor-linux-x86_64.part-00 > part-00" >&2
    echo "    git -C '$REPO_ROOT' show origin/binary-drop:signal-pyarmor-linux-x86_64.part-01 > part-01" >&2
    echo "    cat part-00 part-01 > '$REPO_ROOT/signal-pyarmor-linux-x86_64'" >&2
    exit 1
fi

echo "== 1. target =="
SIZE=$(stat -c%s "$BINARY")
echo "   $BINARY ($SIZE bytes)"
SHA=$(sha256sum "$BINARY" | cut -d' ' -f1)
if [ "$SIZE" = "$EXPECTED_SIZE" ] && [ "$SHA" = "$EXPECTED_SHA" ]; then
    echo "   sha256 OK — matches the release asset"
else
    echo "   !! size $SIZE and sha256 $SHA" >&2
    echo "   !! EXPECTED $EXPECTED_SIZE and $EXPECTED_SHA" >&2
    echo "   !  refusing to continue: every result depends on this artefact" >&2
    exit 1
fi

EX="$WORK/signal-pyarmor-linux-x86_64_extracted"

# ------------------------------------------------------------- 2. extraction
echo "== 2. extraction =="
if [ -d "$EX/PYZ.pyz_extracted" ]; then
    echo "   already present: $EX"
else
    PYEXT=/tmp/venv/pyenv/bin/pyinstxtractor-ng
    if [ ! -x "$PYEXT" ]; then
        echo "   installing pyinstxtractor-ng into /tmp/venv/pyenv"
        python3 -m venv /tmp/venv/pyenv
        /tmp/venv/pyenv/bin/pip -q install pyinstxtractor-ng
    fi
    "$PYEXT" "$BINARY" > "$WORK/extract.log" 2>&1 || {
        echo "   extraction failed; last lines of $WORK/extract.log:" >&2; tail -5 "$WORK/extract.log" >&2; exit 1; }
    grep -E 'Found [0-9]+ files' "$WORK/extract.log" | sed 's/^\[+\] /   /' || true
    echo "   17 namespace-package warnings expected; see $WORK/extract.log"
fi

# --------------------------------------------------- 3. namespace-package stubs
echo "== 3. namespace-package markers =="
python3 - "$EX" <<'EOF'
import os, sys
root = sys.argv[1]
removed = []
for dirpath, dirnames, _files in os.walk(root):
    for d in dirnames:
        stub = os.path.join(dirpath, d + ".pyc")
        if os.path.exists(stub) and os.path.getsize(stub) <= 32:
            os.remove(stub)
            removed.append(os.path.relpath(stub, root))
print("   removed %d header-only markers" % len(removed))
if len(removed) not in (0, 17):
    print("   note: 17 were expected on a fresh extraction")
EOF

# ------------------------------------------------------------- 4. merged tree
echo "== 4. merged import tree =="
SIGNAL_EXTRACT="$EX" MERGED_OUT="$WORK/merged" python3 "$POC/01-build-merged-tree.py" | sed 's/^/   /'

# ----------------------------------------------------------------- 5. the host
echo "== 5. reconstructed CPython host =="
gcc -o "$WORK/py313host" "$POC/02-rebuild-cpython-host.c" -ldl
echo "   built $WORK/py313host"
mkdir -p "$WORK/pyhome"

export PYTHONHOME="$WORK/pyhome"
export PYTHONPATH="$WORK/merged:$EX/base_library.zip"
export PYTHONIOENCODING=utf-8
echo "== 6. smoke test =="
if "$WORK/py313host" "$POC/08-collect-runtime-versions.py" | sed 's/^/   /'; then
    :
else
    echo "   smoke test failed — the environment is not usable" >&2
    exit 1
fi

cat <<EOF

== ready ==
Everything below assumes this shell:

    export WORK=$WORK
    export SIGNAL_EXTRACT=$EX
    export PYTHONPATH=$WORK/merged:$EX/base_library.zip
    export PYTHONHOME=$WORK/pyhome
    alias py3='env -u PYTHONHOME -u PYTHONPATH python3'

Then, from README.md step 6:
    cd $WORK
    ./py313host $POC/03-armored-module-survey.py     # F-03: 62/62 modules, no licence
    ./py313host $POC/05-poc-f01-host-shell.py        # F-01: host shell
    ./py313host $POC/06-poc-f02-workspace.py --extract "\$SIGNAL_EXTRACT"
    ./py313host $POC/12-disassemble-pyc.py pockit/agents/shared_tools.pyc run_shell

The two scripts that only read bytes off disk also run under your system Python,
which needs no environment at all:
    py3 $POC/11-analyse-pockit-endpoint.py
    py3 $POC/12-disassemble-pyc.py pockit/agents/shared_tools.pyc run_shell

Scans (F-05/F-06/F-15/F-16) additionally need the real binary and a seeded
tokenizer cache — see "The tokenizer dependency" in README.md.
EOF
