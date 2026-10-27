#!/usr/bin/env bash
# Shared preparation for the cleartext, F-08, F-04 and F-07 launchers.
# Sourced by the launchers; the evidence checks themselves remain in poc/.

VV_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VAPT_REPO="$(cd -- "$VV_DIR/.." && pwd)"
VAPT_WORK=/tmp/vapt
VAPT_NAME=signal-pyarmor-linux-x86_64
VAPT_SHA256=47b9fa7236a5be5ed37a9186d55a6a84b8d2ef65fd0ab9e2fa744b0641c7d915
VAPT_SIZE=116823456

vv_verify_binary() {
    local path="$1" size sha
    if [[ ! -f "$path" ]]; then
        printf 'ERROR: binary not found: %s\n' "$path" >&2
        return 2
    fi
    size="$(stat -c '%s' "$path")" || return 2
    sha="$(sha256sum "$path" | cut -d' ' -f1)" || return 2
    if [[ "$size" != "$VAPT_SIZE" || "$sha" != "$VAPT_SHA256" ]]; then
        printf 'ERROR: not the repository v1.0 binary: %s\n' "$path" >&2
        printf '       found size=%s sha256=%s\n' "$size" "$sha" >&2
        printf '       expected size=%s sha256=%s\n' "$VAPT_SIZE" "$VAPT_SHA256" >&2
        return 2
    fi
}

vv_prepare_binary() {
    local path="$VAPT_WORK/$VAPT_NAME" partial="$VAPT_WORK/$VAPT_NAME.partial.$$"
    mkdir -p -- "$VAPT_WORK"
    if [[ ! -f "$path" ]]; then
        printf '[setup] Preparing the v1.0 Signal binary from this repository\n' >&2
        if [[ -f "$VAPT_REPO/$VAPT_NAME" ]]; then
            if ! cp -- "$VAPT_REPO/$VAPT_NAME" "$partial"; then
                rm -f -- "$partial"
                return 2
            fi
        else
            command -v git >/dev/null || { echo 'ERROR: git is required to fetch binary-drop' >&2; return 2; }
            if ! git -C "$VAPT_REPO" rev-parse --verify --quiet \
                  'refs/remotes/origin/binary-drop^{commit}' >/dev/null 2>&1; then
                git -C "$VAPT_REPO" fetch --no-tags origin \
                    binary-drop:refs/remotes/origin/binary-drop >&2 || return 2
            fi
            if ! git -C "$VAPT_REPO" show "origin/binary-drop:$VAPT_NAME.part-00" > "$partial" ||
               ! git -C "$VAPT_REPO" show "origin/binary-drop:$VAPT_NAME.part-01" >> "$partial"; then
                rm -f -- "$partial"
                echo 'ERROR: could not reconstruct the binary from binary-drop' >&2
                return 2
            fi
        fi
        if ! vv_verify_binary "$partial"; then
            rm -f -- "$partial"
            return 2
        fi
        chmod 700 -- "$partial" || return 2
        mv -- "$partial" "$path" || return 2
    fi
    vv_verify_binary "$path" || return 2
    [[ -x "$path" ]] || chmod +x -- "$path"
    printf '%s\n' "$path"
}

vv_prepare_host() {
    local binary="$1" extract="$VAPT_WORK/${VAPT_NAME}_extracted"
    if [[ -x "$VAPT_WORK/py313host" && -d "$VAPT_WORK/pyhome" &&
          -d "$VAPT_WORK/merged" && -d "$extract/PYZ.pyz_extracted" &&
          -f "$extract/base_library.zip" ]]; then
        return 0
    fi
    printf '[setup] Extracting Signal and building its bundled Python host; first run can take several minutes.\n' >&2
    printf '[setup] Full setup log: %s\n' "$VAPT_WORK/valid-vulns-setup.log" >&2
    if ! env -u PYTHONHOME -u PYTHONPATH bash "$VAPT_REPO/poc/00-setup.sh" \
             --binary "$binary" --work "$VAPT_WORK" \
             > "$VAPT_WORK/valid-vulns-setup.log" 2>&1; then
        tail -n 30 "$VAPT_WORK/valid-vulns-setup.log" >&2
        echo 'ERROR: setup failed; see the full log above' >&2
        return 2
    fi
    printf '[setup] Bundled interpreter ready.\n' >&2
}
