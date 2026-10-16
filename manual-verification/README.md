# Manual verification kit — Black Duck Signal 2026.9.0 VAPT

Everything you need to verify the VAPT findings **by hand**, in one folder.
For the automated one-command alternative see [`../repro/run_all_pocs.py`](../repro/run_all_pocs.py).

**Target:** `signal-pyarmor-linux-x86_64` — SHA-256
`47b9fa7236a5be5ed37a9186d55a6a84b8d2ef65fd0ab9e2fa744b0641c7d915`
**For AUTHORIZED testing only, on systems you control.**
All "attacker" endpoints are `127.0.0.1`; all keys/canaries are fake (`sk-poc-manual-*`, `VAPT-POC-MANUAL`).

## What's in this folder

| Path | What it is |
|---|---|
| [`MANUAL-VERIFICATION.md`](MANUAL-VERIFICATION.md) | **Start here** — step-by-step, by-hand verification of all 14 findings (V-01…V-14), every command pre-validated against the real binary, with expected outputs and a tick-off checklist |
| [`REPRODUCTION-GUIDE.md`](REPRODUCTION-GUIDE.md) | Prerequisites, WSL2/Docker setup, target-binary reassembly (`binary-drop` branch), offline tiktoken seeding, plus the automated runner walkthrough |
| [`capture_endpoint.py`](capture_endpoint.py) | Standalone fake OpenAI-compatible LLM endpoint (`/v1/chat/completions`, `/v1/embeddings`, `/v1/models`); logs every request incl. `Authorization` headers and bodies to JSONL — used for V-01 / V-05 |
| [`memscan.py`](memscan.py) | Region-wise `/proc/<pid>/mem` scanner (reads `maps`, seeks each region — plain `grep` on `/proc/pid/mem` silently fails) — used for V-04 |
| [`fixtures/evil-repo/`](fixtures/evil-repo/) | Ready-made malicious test repo: `app.py` (canary-tagged), `README.md`, `requirements.txt`, `.signal` (all 7 agents redirected to `http://127.0.0.1:8899/v1`) — identical to what the guide builds by hand |
| [`payloads/marker.c`](payloads/marker.c) | LD_PRELOAD constructor PoC source (V-03) |
| [`payloads/import1.json`](payloads/import1.json), [`import2.json`](payloads/import2.json) | jsonpickle-style `--import-results` deserialization test payloads (V-06 positive control) |

## Findings covered

| # | Severity | Finding | Guide section |
|---|---|---|---|
| V-01 | HIGH | Repo `.signal` hijacks LLM endpoint → API-key theft + source exfil | SIG-01a/b/c |
| V-02 | MED-HIGH | PoCKit prompt-injection command surface | SIG-02 |
| V-03 | MED | LD_PRELOAD injection unmitigated | CHK-04 |
| V-04 | MED | API key in cleartext process memory / argv | CHK-05 |
| V-05 | MED | Plain `http://` for credentialed LLM traffic | CHK-08 |
| V-06 | MED | Untrusted-cwd artifact ingestion (cache/import) | SIG-03a/b |
| V-07 | LOW | `--check-llm` false success on skipped agents | SIG-04 |
| V-08 / V-09 | LOW | No PIE · partial RELRO | CHK-01 / CHK-02 |
| V-10 | LOW | Unsigned, no self-integrity check | CHK-03 |
| V-11 | LOW | World-readable artifacts | CHK-06 |
| V-12 | INFO | Runtime egress deps (managed endpoint + tiktoken CDN) | SIG-05a |
| V-13 | INFO | Plaintext prompt cache schema | SIG-06 |
| V-14 | INFO | Proprietary assets shipped unobfuscated | INFO-01 |

Full details per finding (Description / Impact / Affected / PoC / Remediation):
[`../FINAL-REPORT-signal-2026.9.0.md`](../FINAL-REPORT-signal-2026.9.0.md).
Supporting reports: [`../vapt-report-signal-2026.9.0.md`](../vapt-report-signal-2026.9.0.md) (primary engagement report),
[`../checklist-assessment-signal.md`](../checklist-assessment-signal.md) (thick-client checklist),
[`../signal-binary-analysis.md`](../signal-binary-analysis.md) (packaging/obfuscation analysis).

## Quickstart (3 steps)

```bash
# 1. prerequisites (Linux x86_64 / WSL2)
sudo apt update && sudo apt install -y gcc python3 python3-venv binutils

# 2. get the target binary (see REPRODUCTION-GUIDE.md §0.2 for the binary-drop branch method,
#    or use your own copy) and verify it:
sha256sum signal-pyarmor-linux-x86_64
# 47b9fa7236a5be5ed37a9186d55a6a84b8d2ef65fd0ab9e2fa744b0641c7d915

# 3. open MANUAL-VERIFICATION.md and work through it (~60–90 min for all 14 findings)
```

## One-command sanity check of the helpers

```bash
python3 capture_endpoint.py --port 8899 &      # terminal 1
curl -s localhost:8899/v1/models | head -c 120 # terminal 2 -> {"object": "list", ...
kill %1
```
