#!/usr/bin/env bash
# Cleartext Transmission of Sensitive Information.
# Executes the unchanged focused PoC and writes raw HTTP requests to text.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/_prepare.sh"
binary="$(vv_prepare_binary)"
umask 077
exec env -u PYTHONHOME -u PYTHONPATH python3 "$VAPT_REPO/poc/17-check-plaintext.py" \
    --binary "$binary" --capture "$VV_DIR/captures/01-cleartext-requests.txt" "$@"
