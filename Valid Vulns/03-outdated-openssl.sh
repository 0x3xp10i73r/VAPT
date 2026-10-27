#!/usr/bin/env bash
# Use of Outdated OpenSSL Component (F-04).
# Executes the unchanged focused PoC on the runtime bundled inside the binary.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/_prepare.sh"
binary="$(vv_prepare_binary)"
vv_prepare_host "$binary"
export SIGNAL_EXTRACT="$VAPT_WORK/${VAPT_NAME}_extracted"
exec env -u PYTHONHOME -u PYTHONPATH python3 "$VAPT_REPO/poc/15-check-f04.py" "$@"
