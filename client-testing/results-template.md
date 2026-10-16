# Signal 2026.9.0 PoC verification — results

Filled by: ______________________        Date: ____-__-__
Machine/environment owner: ______________________

## 1. Environment

| Item | Value |
|---|---|
| OS / kernel | |
| Virtualization (bare metal / VM / WSL2 / container) | |
| Binary path | |
| Binary SHA-256 | |
| Binary self-reported version (`--version`) | |
| Internet reachable (pypi / tiktoken CDN) | |
| `setup-check.sh` result (paste FAIL/WARN lines if any) | |
| Runner command used | `python3 run_all_pocs.py --binary … ` |
| Runner output dir | `poc-evidence/` |

## 2. PoC outcomes

Copy the verdict lines from `poc-evidence/SUMMARY.md` into the **Actual** column and add
one line of observed evidence (numbers matter: request counts, hit counts, permissions).

| PoC | Finding | Expected | Actual | Observed evidence / notes |
|---|---|---|---|---|
| SIG-01a | `.signal` hijack → API-key theft | REPRODUCED | | |
| SIG-01b | Source-code exfiltration | REPRODUCED | | |
| SIG-01c | Control (outside-repo cwd) | REPRODUCED | | |
| SIG-02 | PoCKit prompt-injection surface | REPRODUCED | | |
| SIG-03a | Import path not deser. RCE (positive) | REPRODUCED | | |
| SIG-03b | Untrusted-cwd artifact ingestion | CONFIRMED | | |
| SIG-04 | check-llm false success | REPRODUCED | | |
| SIG-05a | tiktoken CDN runtime dependency | REPRODUCED | | |
| SIG-06 | Plaintext prompt cache schema | CONFIRMED | | |
| CHK-01 | No PIE (fixed base) | REPRODUCED | | |
| CHK-02 | Partial RELRO | REPRODUCED | | |
| CHK-03 | Unsigned / no self-integrity | REPRODUCED | | |
| CHK-04 | LD_PRELOAD injection | REPRODUCED | | |
| CHK-05 | Key in cleartext memory | REPRODUCED | | |
| CHK-06 | World-readable artifacts | REPRODUCED | | |
| CHK-08 | Plain http:// for credentials | REPRODUCED | | |

Notes on environmental skips (SKIPPED is not a failure of the finding — see CLAUDE.md):

- CHK-04 skipped (no gcc)? re-run after `apt install gcc`: `--only CHK-04`
- SIG-02 skipped (no venv/internet)? re-run after `apt install python3-venv`: `--only SIG-02`
- SIG-05a offline variant shows "fetch attempted (blocked)" + E63 → still REPRODUCED
- SIG-01b offline: re-run with `--tiktoken-file …`

## 3. Deviations from expected

Anything NOT REPRODUCED, unexpected output, crashes, or version-drift observations
(binary hash mismatch with 2026.9.0 assessed build):

-

## 4. Manual verification (optional)

If `../manual-verification/MANUAL-VERIFICATION.md` was also walked through, tick:

- [ ] V-01a key theft observed on capture endpoint
- [ ] V-01b canary source in captured bodies
- [ ] V-01c control (no trigger outside repo)
- [ ] V-03 LD_PRELOAD marker file
- [ ] V-04 memscan Bearer + argv hits
- [ ] V-07 false success + rc 0
- [ ] V-08/09 readelf results
- [ ] V-10 patched copy runs
- [ ] V-11 artifact permissions
- [ ] V-12 fresh-cache CDN download
- [ ] V-13 cache schema dump
- [ ] V-02/V-14 extraction greps
- [ ] CHK-07 positive: `_MEI` dir 0700 during a run

## 5. Attachments

- [ ] `poc-evidence/SUMMARY.md`
- [ ] `poc-evidence/` full folder (per-PoC `.txt`, `attacker-endpoint-log.jsonl`)
- [ ] `setup-check.sh` output
- [ ] Filled environment section above

## 6. Sign-off

Verified by: ______________________        Reviewed by: ______________________
