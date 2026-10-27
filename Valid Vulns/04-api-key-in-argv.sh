#!/usr/bin/env bash
# API Key Disclosure via Process Command-Line Arguments (F-07 / CWE-214).
# Executes the unchanged focused PoC with synthetic credentials only.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/_prepare.sh"
exec env -u PYTHONHOME -u PYTHONPATH python3 "$VAPT_REPO/poc/21-check-argv-keys.py" "$@"
