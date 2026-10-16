# Client testing kit — Black Duck Signal 2026.9.0 VAPT verification

Self-contained folder for verifying the VAPT findings in the client's own environment,
with or without an AI agent in the terminal (Claude Code auto-reads `CLAUDE.md`).

**For AUTHORIZED testing only, on systems the client controls.**

## What's in this folder

| Path | What it is |
|---|---|
| [`CLAUDE.md`](CLAUDE.md) | Playbook for Claude Code (auto-loaded): ground rules, workflow, expected outcomes, troubleshooting — also useful as a checklist for humans |
| [`setup-check.sh`](setup-check.sh) | Environment check: platform, tools, binary hash, port, disk, network reachability — run this first |
| [`run_all_pocs.py`](run_all_pocs.py) | Master PoC runner — all 16 PoCs in one command (fake LLM endpoint, checksec, patch/LD_PRELOAD/memory-scan/prompt extraction). Same script as `repro/run_all_pocs.py` |
| [`capture_endpoint.py`](capture_endpoint.py) | Standalone fake OpenAI-compatible capture endpoint (for manual runs) |
| [`memscan.py`](memscan.py) | Region-wise `/proc/<pid>/mem` scanner (manual memory check, needs sudo) |
| [`results-template.md`](results-template.md) | Fill-in report template — one row per PoC + environment info |

## Quickstart

```bash
# 0. prerequisites (WSL2/Ubuntu)
sudo apt update && sudo apt install -y python3 python3-venv gcc binutils curl

# 1. put the target binary here (or note its path) and check the environment
bash setup-check.sh ./signal-pyarmor-linux-x86_64

# 2. run everything (2–4 min)
python3 run_all_pocs.py --binary ./signal-pyarmor-linux-x86_64

# 3. review + report
cat poc-evidence/SUMMARY.md
# fill results-template.md
```

### With Claude Code

```bash
cd client-testing        # inside the cloned repo
claude                   # start Claude Code here — it auto-reads CLAUDE.md
```
Then simply tell it: **"Run the PoC verification kit against
./signal-pyarmor-linux-x86_64 and fill in the results template."**
CLAUDE.md contains the full workflow, ground rules, and expected outcomes.

## Getting the target binary

- The client's own licensed copy of Signal 2026.9.0 (`signal-pyarmor-linux-x86_64`).
- Verify the build under test: `sha256sum signal-pyarmor-linux-x86_64` →
  `47b9fa7236a5be5ed37a9186d55a6a84b8d2ef65fd0ab9e2fa744b0641c7d915`.
  A different hash = different build; findings were validated on this one.
- Within the assessment repo, the binary can also be reassembled from the
  `binary-drop` branch — see `../manual-verification/REPRODUCTION-GUIDE.md` §0.2.

## What gets tested

The 14 findings (V-01…V-14) from [`../FINAL-REPORT-signal-2026.9.0.md`](../FINAL-REPORT-signal-2026.9.0.md):
repo-`.signal` endpoint hijack (key theft + source exfiltration), PoCKit prompt-injection
surface, LD_PRELOAD injection, secrets in process memory, plaintext-HTTP BYO endpoints,
untrusted-cwd artifact ingestion, false-success health check, ELF hardening gaps,
unsigned/patchable binary, world-readable artifacts, runtime CDN dependencies,
plaintext prompt cache, and plaintext proprietary assets in the bundle.

By-hand alternatives: [`../manual-verification/MANUAL-VERIFICATION.md`](../manual-verification/MANUAL-VERIFICATION.md)
(validated end-to-end on WSL2).

## Safety

All PoC endpoints are `127.0.0.1`; all credentials are throwaway canaries (`sk-poc-*`).
The kit never bypasses PyArmor or license checks (explicitly out of scope). The only
outbound traffic is the target's own tiktoken encoding download — no scanned code or
canary keys leave the machine.
