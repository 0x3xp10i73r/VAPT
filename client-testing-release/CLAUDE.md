# CLAUDE.md — Signal 2026.9.0 PoC verification kit (client environment)

You are helping verify the security findings from a VAPT engagement against **Black Duck
Signal 2026.9.0** (`signal-pyarmor-linux-x86_64`). This folder is a self-contained kit:
run the PoCs, interpret the verdicts, and fill in the results report.

## Ground rules — read before doing anything

1. **Authorized testing only.** Run solely on machines the client controls, against the
   Signal binary they are licensed to use. If the binary's SHA-256 differs from the one
   below, note it and proceed with care — findings were validated on this exact build.
2. **Never attempt to bypass or crack PyArmor** obfuscation or any license check. That is
   explicitly out of scope. The kit never needs it.
3. **All PoC endpoints are `127.0.0.1`.** The kit stands up its own fake OpenAI-compatible
   server. Do not point anything at third-party systems.
4. **Never use a real API key.** The kit generates throwaway canaries (`sk-poc-…`,
   `VAPT-POC-SQLI-…`). Do not substitute real credentials.
5. **Never modify the original binary in place.** PoCs that patch or preload work on
   copies inside the evidence workdir.
6. **Keep all evidence.** Don't delete `poc-evidence*/` contents; they are the audit trail.

## Assessed target

- Binary: `signal-pyarmor-linux-x86_64` (PyInstaller onefile, CPython 3.13.5, PyArmor 9.2.2)
- SHA-256: `47b9fa7236a5be5ed37a9186d55a6a84b8d2ef65fd0ab9e2fa744b0641c7d915`
- Findings under test: 14 (V-01…V-14) → full detail in `docs/FINAL-REPORT-signal-2026.9.0.md`

## Workflow

### Step 1 — environment check

```bash
bash setup-check.sh /path/to/signal-pyarmor-linux-x86_64
```
Fix any `[FAIL]` items. `[WARN]` items only change which PoC outcome to expect (see table).
If the binary is in this folder, the path argument can be omitted.

### Step 2 — run all PoCs (automated)

```bash
python3 run_all_pocs.py --binary /path/to/signal-pyarmor-linux-x86_64
```

- Takes **2–4 minutes** (SIG-02 extracts the ~450 MB bundle; a full scan runs twice).
  Use a generous timeout; do not kill it mid-run.
- Writes per-PoC `.txt` evidence + `SUMMARY.md` into `./poc-evidence/` (git-ignored).
- Single PoC: `--only SIG-01a,SIG-01b,SIG-01c` · list ids: `--list` · other port: `--port 8890`.
- Offline machines: add `--tiktoken-file /path/to/cl100k_base.tiktoken` (see
  `docs/REPRODUCTION-GUIDE.md` for how to obtain it).

### Step 3 — interpret

Read `poc-evidence/SUMMARY.md` and compare against the expected outcomes below. Verdicts:
`REPRODUCED` (the vulnerability/behavior was demonstrated), `CONFIRMED` (design/schema-level
evidence), `SKIPPED` (environment-dependent — see table), `NOT REPRODUCED` (investigate).

### Step 4 — report

Fill `results-template.md` (environment info + one row per PoC + notes), then hand back:
the filled template, `poc-evidence/SUMMARY.md`, and the `poc-evidence/` folder.

### Optional — manual by-hand verification

`docs/MANUAL-VERIFICATION.md` walks through every finding with
copy-paste commands and expected outputs (validated end-to-end on WSL2). Helpers:
`capture_endpoint.py` (fake LLM server) and `memscan.py` (memory scanner, needs sudo).

## Expected outcomes (16 PoC entries, 14 findings)

| PoC | Finding | Expected verdict | Notes |
|---|---|---|---|
| SIG-01a | Repo `.signal` hijacks LLM endpoint → API-key theft | REPRODUCED | ≥5 captured `Bearer` requests |
| SIG-01b | Scanned source code exfiltration | REPRODUCED | ≥1 captured body with the source canary (validated runs: 10) |
| SIG-01c | Control: outside-repo cwd does not trigger | REPRODUCED | 0 requests to the capture endpoint |
| SIG-02 | PoCKit prompt-injection command surface | REPRODUCED | Design-level: prompt files contain `docker exec`/`pip install`/README-following instructions. Needs python3-venv + internet, else SKIPPED |
| SIG-03a | `--import-results` not a deserialization RCE (positive) | REPRODUCED | jsonpickle payloads inert — no marker file |
| SIG-03b | Untrusted-cwd artifact ingestion | CONFIRMED | cache schema + defaults documented |
| SIG-04 | `--check-llm` false success on skipped agents | REPRODUCED | "All LLM endpoints validated successfully." + rc 0 |
| SIG-05a | Runtime tiktoken CDN dependency | REPRODUCED | Online → encoding file downloaded; offline → "fetch attempted (blocked)" + E63. **Both are REPRODUCED** — do not report offline as a failure |
| SIG-06 | Plaintext prompt cache schema | CONFIRMED | `full_llm_cache(prompt,…)` tables |
| CHK-01 | No PIE on main executable | REPRODUCED | `EXEC`, fixed base 0x400000 |
| CHK-02 | Partial RELRO | REPRODUCED | RELRO present, no BIND_NOW |
| CHK-03 | No signature / self-integrity check | REPRODUCED | patched copy still runs |
| CHK-04 | LD_PRELOAD injection | REPRODUCED | needs gcc, else SKIPPED (install gcc, re-run `--only CHK-04`) |
| CHK-05 | API key in cleartext process memory | REPRODUCED | incl. ready-to-send `Bearer` form |
| CHK-06 | World-readable artifacts | REPRODUCED | 0644 under default umask |
| CHK-08 | Plain http:// accepted for credentialed traffic | REPRODUCED | all capture traffic is http |

## Environment-dependent outcomes — how to report them

- **SIG-05a offline:** "fetch attempted (blocked in this network); app hard-exits E63" is
  the expected offline text and counts as REPRODUCED (the CDN dependency is the finding).
- **CHK-04 without gcc:** SKIPPED is environmental, not a pass/fail of the finding.
  Install gcc and re-run `--only CHK-04`.
- **SIG-02 without venv/internet:** SKIPPED is environmental. Install `python3-venv`,
  re-run `--only SIG-02`.
- **SIG-01b offline without `--tiktoken-file`:** may report SKIPPED with a tiktoken hint —
  follow the hint or re-run with the seed file.
- **Any NOT REPRODUCED:** capture the full command, the PoC's `.txt` evidence file, and the
  environment details; do not retry blindly more than once.
- **`--only` note:** after fixing an environmental skip, re-run just that PoC
  (e.g. `--only CHK-04`); the summary table always reflects the latest run for the
  PoCs executed in it.

## Troubleshooting

- `--port` conflict: something already listens on 8899 → `--port 8890`.
- Full-scan stages can sit silent for a couple of minutes (bounded by a 900 s internal
  timeout) — that is normal.
- The runner never needs root. Only the manual `memscan.py` deep-dive needs `sudo`.

## Safety of the kit itself

Every request the target makes goes to the kit's own `127.0.0.1` capture server. The only
outbound traffic the target itself generates is its normal tiktoken encoding download
(SIG-05a demonstrates it) — no scanned code and no canary keys ever leave the machine.
