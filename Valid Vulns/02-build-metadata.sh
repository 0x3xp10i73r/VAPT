#!/usr/bin/env bash
# Information Exposure Through Build Metadata and Development Artifacts (F-08).
# Executes the unchanged focused PoC against the pinned v1.0 release.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/_prepare.sh"
binary="$(vv_prepare_binary)"
vv_prepare_host "$binary"
export SIGNAL_EXTRACT="$VAPT_WORK/${VAPT_NAME}_extracted"
exec env -u PYTHONHOME -u PYTHONPATH python3 "$VAPT_REPO/poc/16-check-f08.py" \
    --binary "$binary" "$@"
