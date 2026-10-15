# Thick-Client VAPT Checklist — Completed Assessment

**Target:** Black Duck Signal 2026.9.0 (`signal-pyarmor-linux-x86_64`, SHA-256 `47b9fa72…c7d915`)
**Environment:** isolated Linux x86_64 sandbox (egress: github.com/pypi.org only) · Python 3.11 for tooling
**Companion reports:** `signal-binary-analysis.md` (packaging/obfuscation) · `vapt-report-signal-2026.9.0.md` (SIG-01…06) · `repro/` (PoC + evidence)

**Legend:** ✅ tested · ⚠️ partial / limited by environment · ➖ not applicable (with reason)

> **Environment note:** the sandbox `/tmp` was reset between sessions; the binary was re-fetched from branch `binary-drop`, reassembled, and SHA-256 re-verified before this round. All prior evidence is archived in `repro/evidence/`.

**New findings this round (CHK series):**

| ID | Sev | Finding |
|---|---|---|
| CHK-01 | LOW | Main executable is not PIE (ELF `EXEC`, fixed base 0x400000) — no ASLR for the primary image |
| CHK-02 | LOW | Partial RELRO — no `BIND_NOW`; `.got.plt` remains writable |
| CHK-03 | LOW | Binary is unsigned and has **no self-integrity check** — a patched byte in a mapped page executes normally |
| CHK-04 | MEDIUM | `LD_PRELOAD` code injection into the application process is unmitigated (no signing/anti-tamper) — Linux equivalent of DLL preloading |
| CHK-05 | MEDIUM | API key present in cleartext process memory (incl. ready-to-send `Bearer` form) and in `/proc/<pid>/cmdline` (argv) during execution |
| CHK-06 | LOW | Artifacts created world-readable under default umask (0644): `results.sarif`, cache DB — the cache embeds scanned source code |
| CHK-07 | INFO (positive) | `_MEI` self-extraction dir is 0700 per-run (mkdtemp) — no predictable-path race, no leftovers after clean exit |
| CHK-08 | MEDIUM | BYO LLM endpoints accept plain `http://` — API key and scanned source transmitted unencrypted (capture-verified) |

---

## INFORMATION GATHERING — ✅ complete

- ✅ **Architecture:** three-tier: thick client (self-contained PyInstaller onefile CLI) → AI backend (managed: Black Duck-hosted `llm.core.blackduck.com`; BYO: customer endpoint, OpenAI-compatible) with local state (SQLite/Postgres LLM cache, SARIF/log outputs); optional Docker sidecar for PoCKit.
- ✅ **Technologies:** embedded CPython 3.13.5; PyInstaller 6.x C bootloader; PyArmor 9.2.2 (first-party code); click 8.3.1 + Rich CLI; langchain 1.3.14 / langchain-core 1.4.9, anthropic 0.97.0, openai 2.38.0, pydantic-ai, langgraph; faiss-cpu 1.12.0, numpy 2.3.5, psycopg2/SQLAlchemy, GitPython 3.1.59, tiktoken 0.12.0, cryptography 48.0.1.
- ✅ **Network communication:** managed HTTPS to `llm.core.blackduck.com`; BYO to arbitrary URI **including plain HTTP** (CHK-08); one-time HTTPS fetch of `cl100k_base.tiktoken` from `openaipublic.blob.core.windows.net` (hash-pinned); optional PostgreSQL cache DSN.
- ✅ **Process observation:** bootloader (≈1 MB RSS) `fork`s the application child (≈210 MB RSS at startup; threads during scanning). Bootloader imports `fork`/`execvp`; self-extracts 471 files to a private 0700 `_MEI` dir per run; cleans up on exit.
- ✅ **Functionality/behavior:** config discovery (`.signal`, cwd) → LLM factory (7 agents) → connectivity checks → single-file analysis (crypto/dataflow/oversight/synthesis) → SARIF + cache writes; `--check-llm`, `--import/--export-results`, `--git-diff`, experimental PoCKit pipeline.
- ✅ **Entry points:** `TARGET` path argument; 83 CLI options; `.signal` config from cwd; env vars (`AWS_REGION`, `AWS_BEARER_TOKEN_BEDROCK`, `PYARMOR_*`); file inputs (`--cache-file`, `--checkpoint-file`, `--import-results`, report/log paths); network endpoints above.
- ✅ **Security mechanisms:** no local authn/authz (single-user CLI); credential handling = BYO API keys (bearer to LLM endpoint) or Black Duck managed token; PyArmor runtime license enforcement; log-side secret redaction (works — `--llm-key=********`).

## GUI TESTING — ➖ N/A

No GUI: the application is a CLI/TUI (click + Rich). GUI-object, hidden-form, masked-password and UISpy/Winspy/Window-Detective/Snoop items do not apply. The interactive-surface equivalents (argument/config injection, control bypass) are covered by SIG-01/03 testing. *(Items: display hidden object ➖ · activate disabled functionality ➖ · uncover masked password ➖ · GUI content ➖ · GUI logic/injection ➖ · improper error handling ✅ via CLI — see SIG-04 · privilege escalation ➖ no roles · payment manipulation ➖.)*

## FILE TESTING

- ✅ **Permissions per file/folder:** output artifacts 0644 under default umask (`results.sarif`, cache DB → CHK-06: cache embeds scanned source code, world-readable on multi-user hosts); `_MEI` temp 0700 per-run (CHK-07, positive); binary 0755.
- ✅ **Strong naming / authenticate code signing:** ELF is **unsigned**; release asset unsigned; patched byte in a runtime-mapped page executes fine → no self-integrity check (CHK-03).
- ✅ **Sensitive info on filesystem (symbols/data/configs):** bundle sweep clean (no secrets); symbols stripped (positive); crash dumps N/A; cache/log content below.
- ✅ **Sensitive info in config file:** `.signal` supports per-agent `key`/`uri` — keys may persist in plaintext config; scan log inventories the scanned repo; error log records endpoint URIs.
- ✅ **Hardcoded encryption data:** PyArmor armored key material embedded (`.pyarmor.ikey` section, `PY008246` blobs) — vendor-protected, not recoverable statically.
- ✅ **Cleartext storage of sensitive data:** CONFIRMED — cache DB stores full prompts incl. source code (SIG-03/06); API key in process memory and argv (CHK-05).
- ✅ **Side-channel data leakage:** cache/log/argv/memory channels documented; no `_MEI` leftovers after clean exit.
- ✅ **Unreliable log:** SIG-04 (health-check false success); positive: secret redaction in logs.
- ⚠️ **Framework backdooring:** PyInstaller onefile re-extracts per run (no persistent lib dir to backdoor); bootloader ignores `PYTHON*` env injection paths; `LD_PRELOAD` vector demonstrated (CHK-04).
- ✅ **DLL preloading (Linux equivalent):** `LD_PRELOAD` constructor **executed inside the app process**, unmitigated (CHK-04); no `RPATH`/`RUNPATH` (no rpath hijack); system libs resolved from default paths.
- ✅ **Race condition:** per-run `mkdtemp` (no predictable temp path); concurrent scans sharing `--cache-file` rely on SQLite locking (not adversarially tested — noted for vendor).
- ✅ **Files/content replacement:** binary replacement/patch feasible (CHK-03); cache/checkpoint/import artifacts replaceable in cwd (SIG-03).
- ✅ **Client-side protection bypass via reverse engineering:** PyInstaller layer fully bypassed (extraction, SCA, prompt recovery); PyArmor layer held (no static recovery).
- ✅ **Exported functions:** main binary exports nothing meaningful (copy relocations only); `pyarmor_runtime.so` exports `PyInit_pyarmor_runtime@@PYARMOR_RUNTIME_1` + version tags — not invocable outside the embedded interpreter; no unauthenticated use.
- ➖ **Public methods wrapper:** first-party Python API unreachable without defeating PyArmor (assessed infeasible statically; runtime-dump route out of authorized scope).
- ✅ **Decompile:** third-party `.pyc`s fully recoverable (SCA performed); first-party code armored (negative result documented).
- ✅ **Rebuild / patch / reassemble:** patched copy of the binary runs normally (CHK-03) — rebuild/repackage feasible at bootloader level; CArchive re-pack not required to prove the point.
- ✅ **Decryption/de-obfuscation:** static recovery of first-party source infeasible; `PYARMOR_RKEY`/`PYARMOR_LANG` env probes run without effect on `--version`; **no license bypass attempted** (out of authorized scope).
- ✅ **Lack of obfuscation:** first-party code IS obfuscated; however prompts, CWE profiles, rule CSVs, tests and dist-info ship in plaintext (round-1 finding).
- Tools: `strings` ✅ used · dnSpy/Procmon/Process Hacker ➖ Windows-only (equivalents used: `readelf`/`objdump`/`nm`, `/proc` monitoring, Python).

## REGISTRY TESTING — ➖ N/A

Linux target; no Windows registry. Equivalents assessed: environment variables (`PYARMOR_*`, `AWS_*` — probed, inert for bypass), configuration manipulation (`.signal` → **SIG-01**, the direct analog of "registry manipulation → auth/authorization bypass": it redirects credential-bearing traffic), no system-wide state written (all state in cwd/cache). Regshot/Accessenum ➖.

## NETWORK TESTING

- ✅ **Sensitive data in transit:** CONFIRMED (CHK-08) — BYO `http://` accepted: `Authorization: Bearer <key>` + full scanned source + system prompts in cleartext (capture-verified, `repro/evidence/`); managed default is HTTPS.
- ➖ **Firewall bypass:** not assessable in egress-restricted sandbox; note that SIG-01 (config-driven egress) functionally defeats allowlist-based egress policy.
- ✅ **Traffic manipulation:** endpoint substitution demonstrated (SIG-01); TLS-protected BYO endpoints not MITM-tested (app bundles certifi; CA-override path untested).
- Tools: Wireshark/TCPView ➖ (equivalents: local HTTP capture server, `/proc/net`, `ss`).

## ASSEMBLY TESTING (Linux checksec — PESecurity/BinScope equivalent)

| Mitigation | Main binary | pyarmor_runtime.so |
|---|---|---|
| ASLR (PIE) | ✗ **EXEC, fixed 0x400000** (CHK-01) | ✓ (DYN/PIC) |
| NX / DEP | ✓ (GNU_STACK RW) | ✓ |
| RELRO | ⚠️ **Partial** (RELRO segment, no BIND_NOW → `.got.plt` writable) (CHK-02) | ⚠️ Partial |
| Stack canary | ✓ (`__stack_chk_fail`) | ✓ |
| FORTIFY | ✓ (5 `_chk` imports: `snprintf`, `vsnprintf`, `fread`, `realpath`, `__stack_chk`) | — |
| SafeSEH | ➖ PE/32-bit concept, N/A on ELF x86-64 | ➖ |
| Strong naming | ➖ .NET concept → unsigned ELF (CHK-03) | ➖ |
| ControlFlowGuard | ✗ absent (no `-fcfprotection`/IBT) | ✗ |
| HighEntropyVA | ➖ PE concept (tracks PIE, which is absent) | — |
| Symbols | ✓ stripped | versioned exports only |
| RPATH/RUNPATH | ✓ none | ✓ none |

## MEMORY TESTING

- ✅ **Sensitive data in memory:** CONFIRMED (CHK-05) — in the application child process (210 MB RSS): API key in 3 writable regions **including the ready-to-send `Bearer <key>` form**; full `.signal` config (URI + agent sections) in cleartext; bootloader stack additionally holds the key from argv (also world-readable via `/proc/<pid>/cmdline` to same-user processes).
- ⚠️ **Memory manipulation / auth-authorization bypass via memory:** exposure documented; not performed (debugger absent; bypassing PyArmor license checks = circumvention, out of authorized scope).
- ✅ **Dump analysis:** `/proc/<pid>/mem` scan as process ancestor (needle search across all writable regions).
- ➖ **Process replacement:** N/A (standard exec model, no hollowing indicators).
- ➖ **Modifying assembly in memory:** not performed (no debugger in environment).
- ⚠️ **Debugging / breakpoints:** no `gdb` in sandbox; load-time hooking demonstrated instead (`LD_PRELOAD` constructor — CHK-04); ptrace permitted by kernel policy for ancestors.
- ✅ **Dangerous functions:** imports include `fork`, `execvp`, **`strcpy`** (unsafe copy in bootloader C code), `unlink`, `rmdir` (cleanup) — 84 dynamic imports total.
- Tools: Process Hacker/HxD ➖ (equivalents: `/proc/<pid>/maps`+`mem`, Python, `strings`).

## TRAFFIC TESTING

- ✅ **Traffic flow analysis:** OpenAI-compatible `/v1/chat/completions` + `/v1/embeddings` (token-ID input, base64 float32 output); client fingerprint `OpenAI/Python 2.38.0`, `X-Stainless-*` headers, CPython 3.13.5; Tiktoken CDN fetch at startup of embedding use.
- ✅ **Sensitive data in transit:** key + source + system prompts (CHK-08, evidence archived).
- Tools: Echo Mirage/MITM Relay/Burp ➖ (equivalent: the capture endpoint in `repro/repro_signal_vapt.py`).

## COMMON VULNERABILITIES TESTING

- ✅ **Decompile / reverse engineering:** performed (see FILE TESTING).
- ➖ **OWASP Web/API Top 10:** not a web/API application. Client-side analogs mapped: A01 broken access control ≈ SIG-01 (untrusted config redirects credentialed traffic); A02 cryptographic failures ≈ CHK-08 (plaintext HTTP) + cleartext cache; A05 security misconfiguration ≈ SIG-04; A08 software/data integrity failures ≈ CHK-03/04 (unsigned, injectable); A09 logging failures ≈ SIG-04; prompt injection (MASVS/LLM) ≈ SIG-02.
- ✅ **DLL hijacking:** Linux equivalent tested — `LD_PRELOAD` (CHK-04).
- ✅ **Signature checks (Sigcheck equivalent):** unsigned ELF; no release-asset signature (round 1).
- ✅ **Binary analysis (BinScope equivalent):** checksec table above.
- ✅ **Business logic errors:** SIG-01 (untrusted-cwd trust), SIG-03 (state ingestion), SIG-04 (health-check logic).
- ➖ **TCP/UDP attacks:** client-initiated outbound only; no listening sockets observed during runs.
- ⚠️ **Automated scanning (VCG equivalent):** strings/secrets sweeps, dependency SCA, extraction-based static review performed; code-level static analysis inherently limited by PyArmor.

---

## Remediation pointers (new CHK items)

1. **CHK-03/04:** sign releases (sigstore/cosign or vendor signing) and consider a self-integrity check at startup; document that `LD_PRELOAD`/`LD_LIBRARY_PATH` control implies full compromise (standard Linux threat model — deprioritize vs. SIG-01).
2. **CHK-05:** scrub secrets from argv (accept keys only via env/config-file with 0600 perms); zeroize key material after client construction where feasible.
3. **CHK-06:** create cache/log/report artifacts with 0600 perms by default.
4. **CHK-08:** refuse or warn on non-`https://` BYO LLM URIs.
5. **CHK-01/02:** build bootloader with `-pie -fPIE` and full RELRO (`-Wl,-z,relro,-z,now`) — cheap wins for the vendor's build chain.
