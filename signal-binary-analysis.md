# Binary Analysis — `signal-pyarmor-linux-x86_64`

**Source:** GitHub release `v1.0` ("Binary release"), repo `0x3xp10i73r/VAPT`, delivered via branch `binary-drop` (split into two parts, reassembled and hash-verified)
**Analysis type:** Static triage + controlled dynamic test, performed in an isolated Linux x86_64 sandbox (no outbound network except github.com / pypi.org)
**Date:** 2026-10-15

---

## 1. File identity & integrity

| Property | Value |
|---|---|
| Size | 116,823,456 bytes (111.4 MiB) |
| MD5 | `3405623ef181c1e58ed9afe779ed8036` |
| SHA-1 | `c56602ea47d421155a0ea9ed667d6338455f0d05` |
| SHA-256 | `47b9fa7236a5be5ed37a9186d55a6a84b8d2ef65fd0ab9e2fa744b0641c7d915` |
| Format | ELF64 x86-64 `EXEC`, interpreter `/lib64/ld-linux-x86-64.so.2` |

The reassembled file (from parts `00`+`01`, 94,371,840 + 22,451,616 bytes) is **byte-identical to the original** — SHA-256 provided by the file owner matched exactly.

## 2. Executive summary

The binary is a **PyInstaller 6.x onefile build of Black Duck Signal 2026.9.0** — an AI-powered application-security (SAST/SCA) analysis platform from Black Duck Software. All first-party application code is protected with **PyArmor 9.2.2**, but the packaging layer is fully transparent:

- The PyInstaller CArchive extracts with off-the-shelf tooling (`pyinstxtractor-ng`), exposing ~448 MB of content: 6,379 PYZ modules, resource files, agent prompts, rule databases, the complete (obfuscated) test suite, and wheel metadata with build provenance.
- **No secrets** (API keys, tokens, private keys) were found in any plaintext asset.
- The binary **executes correctly** in the analysis sandbox (`--version`, `--help` OK); self-extraction to a `_MEI*` temp dir works as expected for PyInstaller onefile.
- The proprietary Signal code itself remains PyArmor-armored; recovery would require runtime instrumentation rather than static extraction.

## 3. Packaging analysis

- **Bootstrap:** small ELF (~35 KB `.text`), dynamically linked against `libz.so.1`, `libpthread`, `libdl`, `libc`. Bootloader strings (`pyi-contents-directory _internal`, `pyi-python-flag`, `pyi-bootloader-ignore-signals`, `pyi-runtime-tmpdir`, `_MEIPASS`) identify a **PyInstaller 6.x** bootloader (option strings imply ≥ 6.3; embedded Python 3.13 implies ≥ 6.10).
- **Payload:** appended CArchive registered as an ELF section named **`pydata`** (offset `0xf2d9`, 111.4 MB). MEI cookie (`MEI\x0c\x0b\x0a\x0b\x0e`) at file offset 116,821,247.
  - Package length: 116,759,166 B · TOC: 30,640 B · Python version: 313 · Pylib: `libpython3.13.so.1.0`
- **Entropy:** ~7.99 across the entire payload — consistent with zlib-compressed archive entries, not an additional packer.
- Extraction via `pyinstxtractor-ng` succeeded with zero errors: 6,379 files in the PYZ, 229 top-level PYZ entries, 448 MB total extracted.

## 4. Product identification

From `signal-2026.9.0.dist-info/METADATA`:

- **Name:** Signal, **Version:** 2026.9.0
- **Summary:** "Industry leading AI-powered application security testing platform."
- **Author:** David Bohannon \<bohannon@blackduck.com\> · **License:** MIT · **Requires-Python:** `==3.13.*`
- **Build provenance** (`direct_url.json`): editable install from `file:///builds/siglab/noscan` — an internal CI build path ("siglab/noscan"; the entry point is `no_scan.pyc`, and the CLI tagline is "Analyze code without scanning!").
- **Build timestamps:** PyArmor per-file stamps `2026-09-10T21:32:14–16 UTC`; `uv_cache.json` epoch = **2026-09-10 21:32:35 UTC** (installer: `uv`).

## 5. Obfuscation (PyArmor)

- **Version:** PyArmor **9.2.2 (ci)**, project label **`BlackDuckSignal`**, runtime suffix **`008246`**.
- **Coverage:** every first-party module — `agents/{sast,sca,synthesis}.py`, all config/CLI/logging modules, and the entire `tests/` tree — begins with e.g.:
  `# Pyarmor 9.2.2 (ci), 008246, BlackDuckSignal, 2026-09-10T21:32:14.615940` followed by
  `from pyarmor_runtime_008246 import __pyarmor__` / `__pyarmor__(__name__, __file__, b'PY008246…')` armored bytecode blobs.
- **Runtime package:** `pyarmor_runtime_008246/` ships native runtimes for linux x86_64/aarch64, darwin x86_64/aarch64, and windows x86_64 (620 KB–882 KB each). The Linux x86_64 runtime (`pyarmor_runtime.so`) contains:
  - an ELF section named **`.pyarmor.ikey`** (internal key material),
  - strings `PyArmor v8+ runtime module`, `pyarmor-vax-008246`, `PYARMOR_RKEY`/`PYARMOR_LANG`/`PYARMOR_RUNTIME_1` env hooks, `User-Agent: PYARMOR.CORE`,
  - the enforcement message **"missing license key to run the script"** (license checking is compiled into the runtime). No `license.lic` file ships alongside the runtimes.
- **Assessment:** static recovery of the original bytecode is not feasible; PyArmor 9 restores code objects only inside the native runtime at import time. Bypassing it requires dynamic techniques (runtime instrumentation / memory dump of code objects), which is out of scope for this static pass.

## 6. Component inventory (selected)

| Category | Components (versions where identifiable) |
|---|---|
| LLM clients | anthropic 0.97.0, openai 2.38.0, langchain 1.3.14, langchain-anthropic, langchain-openai, langchain-google-genai 4.2.2, langgraph (+supervisor, checkpoint), pydantic-ai-slim 1.0.10, tiktoken |
| Providers wired | AWS Bedrock (bearer-token auth, `--aws-bearer-token` / `AWS_BEARER_TOKEN_BEDROCK`), Azure direct, GCP Vertex (`--gcp-project/region/service-account`) |
| Retrieval / data | faiss-cpu 1.12.0 (linux), numpy 2.3.5, psycopg2 + libpq 5.17, SQLAlchemy (cyextension), orjson, GitPython ≥ 3.1.59 |
| Crypto / TLS | cryptography 48.0.1, OpenSSL libs, certifi CA bundle |
| Misc | click 8.3.1, httpx 0.28.1 **and** a namespace-duplicated httpx2 2.3.0 (+httpcore/httpcore2), genai_prices 0.0.67, opentelemetry_api 1.43.0, jsonpickle 4.1.1, cvss 3.6 |
| First-party | `agents/{sast,sca,synthesis}`, `agent_config_resolution`, `bedrock_bearer`, `check_llm`, `cli_config`, `llm_uri_config`, `model_config`, `error_mapping`, `callbacks`, `cache_factory`, `embedding_utils`, `logging_config` — all PyArmor-obfuscated |
| Internal extension | **PoCKit 0.1.52** ("Multi-Agent Exploit Generation System"), installed from `file:///builds/siglab/noscan/extensions/pockit-0.1.52-py3-none-any.whl` |

**PoCKit detail (plaintext, not obfuscated):** agent pipeline Research → Environment Setup (Docker) → Exploit → Validate → Fix Verification; CWE-specific profiles for **CWE-22 (path traversal), CWE-79 (XSS), CWE-89 (SQLi)** including `exploit_guidance.md`, `validate_checklist.md`, `profile.yaml`, plus six full agent prompt files (`research_prompt.prompt`, `exploit_creator_prompt.prompt`, `super_agent_prompt.prompt`, …). This is proprietary prompt-engineering IP exposed in the clear.

**Rule data (plaintext):** `data/default_rules.csv` (1,258 SAST rule names/IDs), `rule_coverage.csv` (288 rules, dast/sast classification), `novelty_cwe_map.csv` and `novelty_rule_overrides.csv` — including post-quantum-crypto ("pqc") novelty classification columns.

## 7. CLI surface (dynamic)

`--version` prints `Black Duck Signal version 2026.9.0`. `--help` (884 lines, click/Rich) exposes **83 options**, notably:

- Targeting: `TARGET` positional, `--include-paths/--exclude-paths`, `--extra-extensions`, `--ignore-test-files`, `--skip-generated-files`, `--git-diff*` (diff-scanning), `--large-code-base-size`, `--auto-accept-token-t…`
- Analysis modes: `--dataflow`, `--oversight`, `--synthesis`, `--prioritization`, `--poc-kit*`, `--crypto`, `--misra`, `--pipeline`
- LLM config: `--llm-mode/--llm-model/--llm-uri/--llm-key`, per-agent model overrides (`--llm-dataflow-agent-…`, `--llm-oversight-agent-…`, `--llm-sca-agent-*`), `--llm-prompt-caching`, `--thinking-budget`, `--check-llm` / `--check-llm-json`
- Cloud auth: `--aws-bearer-token`, `--aws-bedrock-region`, `--gcp-project/--gcp-region/--gcp-service-account`
- Caching/output: `--caching`, `--cache-file` (SQLite, default `signal-cache.db`), `--cache-database` (PostgreSQL DSN), `--report-file`, `--export-results`/`--import-results`, `--log-file/--log-level`, `--error-log-file`

## 8. Secrets & sensitive-data sweep

Pattern sweep (OpenAI/Anthropic-style keys, AWS `AKIA…`, GitHub `ghp_…`, Slack tokens, Google `AIza…`, private-key PEM blocks, Bearer headers, generic `api_key=` assignments) across all plaintext assets (`*.py` stubs, YAML, JSON, CSV, prompts, RECORD/METADATA): **no matches**. No hardcoded URLs/endpoints in config/data/prompts either. Sensitive-but-not-secret content: build paths, author email, internal prompts/rules (above), and the full dist-info RECORD (file inventory + SHA-256s of the original package).

## 9. Dynamic test observations

- Executed in the sandbox with egress restricted to github.com/pypi.org: binary starts, self-extracts to a `_MEI*` directory, prints version/help, exits 0.
- No files written outside the temp extraction dir and cwd; no leftover `_MEI*` after clean exit; no network activity was possible/attempted beyond what the restricted environment allows (no requests observed in logs).
- No crash, no anti-debug/anti-VM behavior observed for basic invocation.

## 10. Protection assessment & recommendations

**What an adversary gets without breaking PyArmor:**

1. Full package inventory, versions, and file hashes (RECORD files) → precise dependency attack-surface mapping.
2. All proprietary agent prompts, exploit-guidance profiles, and rule databases in plaintext.
3. The complete obfuscated test suite (module names, test names reveal internal behavior: `test_agent_flag_managed_rejection`, `test_config_precedence`, provider e2e flows).
4. Internal build layout (`/builds/siglab/noscan`), author identity, and exact build timeline.
5. Full CLI surface and per-option help (76 KB) — useful for fingerprinting and probing deployments.

**Recommendations (if this bundle is meant to be distributed externally):**

- Strip the `tests/` tree and wheel dist-info (especially `direct_url.json`, `uv_cache.json`, RECORD) from release builds.
- Move PoCKit prompts/CWE profiles and rule CSVs behind the PyArmor layer or into encrypted resources if they are considered proprietary.
- Verify the PyArmor license mode is a paid/registered one (the `9.2.2 (ci)` marker) and that runtime restrictions (expiry, machine binding) are configured as intended.
- Consider code signing + release-asset integrity publication so consumers can verify provenance (this analysis could only verify integrity against a user-supplied hash).

---

### Method & environment

Analysis performed on the reassembled binary in `/tmp` (never committed to git). Tools: `readelf`, `strings`, `od`, Python 3.11 (custom CArchive cookie parser, entropy), `pyinstxtractor-ng` (PyPI venv). The split parts remain on branch `binary-drop` on the remote for reproducibility; the local clone's fetched pack was pruned after extraction to keep the workspace lean.
