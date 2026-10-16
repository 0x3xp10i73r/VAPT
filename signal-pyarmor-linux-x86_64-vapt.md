# Security Assessment (VAPT) — Black Duck Signal CLI

**Artefact assessed:** `signal-pyarmor-linux-x86_64`

**SHA-256:** `47b9fa7236a5be5ed37a9186d55a6a84b8d2ef65fd0ab9e2fa744b0641c7d915`

**Product / version:** Black Duck Signal **2026.9.0** (package `signal-2026.9.0`, author `bohannon@blackduck.com`)

**Platform:** Linux x86-64 ELF executable, 116,823,456 bytes

**Assessment type:** Static + dynamic (grey-box) review of the distributed binary in an isolated Linux sandbox. No vendor production systems were contacted. LLM endpoints were replaced with a local mock server.

**Assessment date:** 16 October 2026

---

## 1. Artefact identification and integrity

The binary was recovered from the repository hosting it and verified before analysis.

| Property | Value |
|---|---|
| SHA-256 | `47b9fa7236a5be5ed37a9186d55a6a84b8d2ef65fd0ab9e2fa744b0641c7d915` |
| Release-asset digest | `sha256:47b9fa72…c1c7d915` — **matches** |
| Size | 116,823,456 bytes (matches published asset size exactly) |
| Format | ELF 64-bit LSB executable, x86-64, `Type: EXEC` (non-PIE) |
| Interpreter | `/lib64/ld-linux-x86-64.so.2` |
| Build ID | `d3d060968c2b8c41aa17bbc6e127f0d462c98025` |
| Compiler (`​.comment`) | `GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0` |
| Version banner | `Black Duck Signal version 2026.9.0` |

The executable is a **PyInstaller** bootloader hosting a **PyArmor**-protected Python application:

| Layer | Detail |
|---|---|
| Packaging | PyInstaller **6.x or newer** (CArchive format generation 2.1+; the shipped bootstrap modules document PyInstaller ≥ 6.0.0 archive semantics) on **CPython 3.13.5** (`3.13.5 (main, Jul 11 2025)`, built with Clang 20.1.4) |
| Archive | `pydata` section, 116,759,166 bytes; **485 files**, PYZ archive present, **not encrypted** |
| Contents | 6,379 importable modules; 338,522,719 bytes uncompressed |
| Code protection | **PyArmor 9.2.2 (ci)**, build `008246`, project `BlackDuckSignal`, generated `2026-09-10T21:32:14Z` |
| Protected modules | **148 obfuscated `.py` files** — 17 at top level, `agents/` 4, `prompts/` 18, `scans/` 6, `utils/` 24, `tests/` 79 (`tests/unit` 51, `tests/integration` 27) |
| Unprotected modules | `pockit/` (PoCKit), all third-party dependencies, `data/*.csv`, `templates/*`, `pockit/prompts/*.prompt` |

Observed product tree inside the binary: `agents/`, `data/`, `prompts/`, `scans/`, `templates/`, `tests/` (79 files), `utils/`.

---

## 2. Assessment method

1. **Integrity and ELF triage** — `sha256sum`, `readelf -h/-l/-S/-d/-n/-p`, dynamic-symbol inspection.
2. **Archive extraction** — `pyinstxtractor-ng` 2026.7.3 recovered the full CArchive (485 entries) and the PYZ (6,379 modules) to disk.
3. **Runtime reconstruction** — the binary's own `libpython3.13.so.1.0` plus its bundled stdlib were used to build a standalone CPython 3.13 host, allowing frozen `.pyc` modules to be unmarshalled, disassembled and imported exactly as the real interpreter would.
4. **Constant extraction** — 136,438 unique string constants were recovered from 6,374 modules with module-level provenance, and swept for credentials, endpoints, and risky APIs.
5. **Native library fingerprinting** — bundled `.so` files were probed directly (`zlibVersion`, `OpenSSL_version`, `PQlibVersion`) to obtain exact versions rather than relying on filename heuristics.
6. **Dynamic testing** — the CLI was executed with an isolated `HOME`; a local mock LLM endpoint captured every outbound request (headers, bodies) from a controlled `--llm-mode byo` configuration.
7. **Protected-code behaviour** — the PyArmor-protected modules were imported into the reconstructed interpreter to assess whether the protection binds the artefact.

---

## 3. Attack surface summary

**Command-line interface — 79 options.** The surface includes several that materially widen the trust boundary:

- Endpoint and credential control: `--llm-uri`, `--llm-key`, `--llm-mode`, `--llm-ca-bundle`, `--llm-ssl-verify`, `--aws-bearer-token`, `--aws-bedrock-region`, `--gcp-service-account`, `--gcp-project`, `--gcp-region`, per-agent `--llm-<agent>-{uri,key,model,timeout,api-version}` overrides.
- Local state: `--config` (default `.signal`), `--cache-file` (default `signal-cache.db`), `--cache-database` (PostgreSQL connection string), `--checkpoint-file`, `--export-results`, `--import-results`, `--report-file`, `--log-file`, `--error-log-file` (default `signal_errors.json`), `--git-diff-dir` (default `.git_patches`).
- **Autonomous execution: `--poc-kit`, `--poc-kit-log-file`, `--poc-kit-report-dir`.**

**Configuration file.** `.signal` — INI-style, with sections such as `[LLM]`, `[LLM_SINGLEFILESCAN_AGENT]`, `[LLM_DATAFLOW_AGENT]`, `[LLM_OVERSIGHT_AGENT]`, `[LLM_EXPLOITATION_AGENT]`, `[LLM_SCA_AGENT]`, `[LLM_MERGEKEY_EMBED_AGENT]`, `[LLM_OVERSIGHT_EMBED_AGENT]`. Supports `${VAR}` environment-variable interpolation.

**Network egress.** Source code, prompts and metadata are sent to a configured LLM endpoint during scanning; embeddings are sent to separate embedding endpoints. The default endpoint is the vendor-hosted `https://llm.core.blackduck.com` (from `--llm-uri` help output). Additional hosts identified in the artefact: `https://llm.labs.blackduck.com` (a string constant inside `pockit/constants.pyc`), `https://poc.polaris.blackduck.com` and `kbtest.blackducksoftware.com`. One further host is contacted at runtime without being configured: `openaipublic.blob.core.windows.net` (see F-05).

**Local execution.** PoCKit registers a shell-execution tool with `shell=True` and drives Docker for exploit validation.

---

## 4. Findings

| # | Finding | Severity | OWASP | CWE | Status |
|---|---|---|---|---|---|
| F-01 | PoCKit exposes a host shell tool to an LLM agent — prompt injection in scanned content can yield command execution outside the container | **High** — CVSS 3.1 **8.3** | A03:2021 Injection / LLM01 Prompt Injection | CWE-78, CWE-1426 | Confirmed by code analysis |
| F-02 | PoCKit workspace path is predictable, derived from an unvalidated GUID, and created with `exist_ok=True` | **Medium** — CVSS 3.1 **6.2** | A01:2021 Broken Access Control | CWE-377, CWE-379, CWE-22 | Confirmed by code analysis |
| F-03 | PyArmor protection does not bind the artefact — protected modules load and execute outside the packaged binary, with no licence, key or expiry requirement | **Medium** — CVSS 3.1 **6.1** | A04:2021 Insecure Design | CWE-693, CWE-656 | Confirmed by dynamic test |
| F-04 | Bundled TLS stack is OpenSSL 3.0.16 (five patch releases behind), with published CVEs including a High-severity one | **Medium** — CVSS 3.1 **5.6** | A06:2021 Vulnerable and Outdated Components | CWE-1104 | Confirmed (version), reachability constrained |
| F-05 | Undocumented mandatory third-party egress to `openaipublic.blob.core.windows.net`; failure is misreported as an LLM endpoint error | **Low** — CVSS 3.1 **3.7** | A08:2021 Software and Data Integrity Failures | CWE-829, CWE-1059 | Confirmed by dynamic test |
| F-06 | `--llm-ssl-verify false` allows TLS verification to be disabled for endpoints receiving source code | **Low** — CVSS 3.1 **3.7** | A02:2021 Cryptographic Failures | CWE-295 | Confirmed (configurable weakness) |
| F-07 | Credentials are accepted as command-line arguments and are therefore exposed via process listing and CI logs | **Low** — CVSS 3.1 **3.3** | A02:2021 Cryptographic Failures | CWE-214, CWE-522 | Confirmed (design weakness) |
| F-08 | Build-system metadata, an internal build path and the product test suite ship inside the release binary | **Low** — CVSS 3.1 **3.7** | A05:2021 Security Misconfiguration | CWE-200, CWE-540 | Confirmed |
| F-09 | Bundled `libz.so.1` is zlib 1.2.11, affected by CVE-2018-25032 and CVE-2022-37434 | **Informational** | A06:2021 Vulnerable and Outdated Components | CWE-1104 | Confirmed (version); not attacker-reachable |
| F-10 | No code signature or runtime integrity verification for a distributed Python-based binary | **Informational** | A08:2021 Software and Data Integrity Failures | CWE-494, CWE-345 | Observation |

---

## 5. Detailed findings

### F-01 — PoCKit gives an LLM agent a host shell, `shell=True`

- **Severity / CVSS:** **High, 8.3** — `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H`
  *Scoring note:* the score does not capture that `--poc-kit` is **off by default and marked EXPERIMENTAL**. The CLI's own help text states: *"PoCKit is an autonomous agent. It will execute shell commands, install dependencies, run code, and make outbound network requests… Only enable on codebases you own in environments where this activity is authorized."* The rating reflects impact **when the feature is enabled**, which is the intended deployment for exploit validation.

- **Affected components:** `pockit/agents/shared_tools.pyc`, `pockit/agents/{environment_setup,exploit,fix_verification}_agent.pyc`, `pockit/prompts/exploit_creator_prompt.prompt`

- **Evidence.** Disassembly of `register_workspace_tools.<locals>.run_shell` (frozen module `pockit/agents/shared_tools.pyc`, source line 162) shows the tool calls:

  ```python
  subprocess.run(command, shell=True, capture_output=True,
                 text=True, timeout=120, cwd=str(workspace_dir))
  ```

  The keyword tuple `('shell', 'capture_output', 'text', 'timeout', 'cwd')` and the literal `120` are visible in the bytecode. The tool is registered on the agent by `register_workspace_tools(agent, workspace_dir, source_code_path, shell, write)`; `environment_setup_agent`, `exploit_agent` and `fix_verification_agent` all reference it and pass a `shell` argument.

  The tool description handed to the model reads: *"Execute a shell command in the workspace directory and return its output."* The packaged prompt `pockit/prompts/exploit_creator_prompt.prompt` directs the agent to run `docker cp <container_name>:/tmp/pwned ./evidence/pwned` — i.e. a **host** command, not a command inside the container.

- **Explanation.** `cwd` is a working directory, not a sandbox. An agent-authored command such as `cat ~/.aws/credentials > /tmp/ex`, `curl` to an attacker host, or `rm -rf` is executed with the full privileges of the user running Signal. The commands are generated by a language model whose context includes the code under analysis. In a VAPT context the target codebase is, by definition, **untrusted input**: a comment, string literal or config value in the scanned repository can carry a prompt injection that redirects the agent to emit an arbitrary command. The safety of the system therefore rests on the model's instruction-following rather than on a technical control.

  File-oriented tools in the same module (`read_file`, `write_file`, `file_search`) are path-guarded by a `_safe` helper; `run_shell` is not constrained in any comparable way.

- **Impact.** Arbitrary command execution on the machine running the assessment, under the analyst's privileges — including access to LLM API keys, cloud credentials, the source code being analysed, and any reachable internal service. Docker is used as the *target* environment; it does not contain the shell tool.

- **Recommendation.** Do not expose a general shell tool. If exploit validation requires command execution, execute it exclusively inside the container via a container-scoped API (`docker exec` against a fixed container handle), run PoCKit under a dedicated unprivileged identity, remove `shell=True` in favour of `argv`-style invocation, restrict egress with an allowlist, and treat all scanned content as untrusted in the prompts. Ship the feature off unless a second confirmation gate is satisfied.

### F-02 — Predictable, unvalidated PoCKit workspace path

- **Severity / CVSS:** **Medium, 6.2** — `CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N`
- **Affected component:** `pockit/__main__.pyc`

- **Evidence.** Disassembly of `pockit/__main__.pyc` shows two workspace helpers. The default (no `work_directory` supplied) is:

  ```python
  # source line 146-148
  workspace_path = Path(f"/tmp/pockit-{guid}-workspace")
  workspace_path.mkdir(parents=True, exist_ok=True)      # ('parents', 'exist_ok')
  return str(workspace_path)
  ```

  The alternative helper (lines 141-144) resolves `work_directory` against `Path.cwd()` and applies the same `mkdir(parents=True, exist_ok=True)`. In both cases `mkdir` is called with only `parents` and `exist_ok` — no `mode`, no symlink handling — and the directory is created before any validation of its contents.

  `validate_inputs()` validates only that the SARIF file exists and that the source path is a directory. **The GUID is never sanitised** — no regex, no allowlist, no `resolve()` containment check anywhere in the module.

- **Explanation.** Two independent weaknesses:
  1. The `guid` value is interpolated straight into a filesystem path. A GUID read from an untrusted SARIF file containing `../` sequences yields a workspace outside `/tmp`; `mkdir(parents=True, exist_ok=True)` then creates it. The same directory is subsequently the base for `write_file` and for the `cwd` of agent-executed shell commands.
  2. The path is fully predictable and created with `exist_ok=True` and no symlink checks. On a shared host, a local attacker who can guess or influence the GUID can pre-create `/tmp/pockit-<guid>-workspace` as a symlink to a directory of their choosing; Signal adopts it silently and proceeds.

  This is the classic insecure-temporary-directory pattern.

- **Impact.** Local denial of service or tampering, directory creation at attacker-chosen paths, and workspace redirection — which in combination with F-01 places agent-executed commands in an attacker-selected working directory. Scope is limited to the local machine, and exploitation needs a local foothold or the ability to supply an untrusted SARIF.

- **Recommendation.** Ignore the supplied GUID for path construction; use `tempfile.mkdtemp()` (mode `0700`); if a name must be derived, validate it against a strict allowlist and verify containment with `Path.resolve()` after creation, refusing symlinks (`os.open(..., O_NOFOLLOW | O_DIRECTORY)`).

### F-03 — PyArmor does not bind the artefact; protection is obfuscation only

- **Severity / CVSS:** **Medium, 6.1** — `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **Affected components:** `pyarmor_runtime_008246/`, the 148 PyArmor-wrapped modules

- **Evidence.** The PyInstaller component of the protection is trivially removable and was in fact removed: the CArchive is **not encrypted**, and `pyinstxtractor-ng` recovered all 485 files including `pyarmor_runtime_008246/linux_x86_64/pyarmor_runtime.so` and the obfuscated sources.

  The obfuscated modules were then loaded in a Python **3.13.5** interpreter reconstructed from the binary's own `libpython3.13.so.1.0`. Results:

  | Module | Outcome |
  |---|---|
  | `llm_uri_config` | imported, members enumerated |
  | `cli_config` | imported, **132 public members** enumerated |
  | `models` | imported, 24 classes exposed (`Result`, `ZeroDay`, `ChainFinding`, `SynthesisReport`, `OversightReviewResponse`, …) |
  | `prompts`, `agents`, `scans.*`, `utils.*` | runtime loaded, further imports blocked only by environment gaps in the reconstruction |

  *No licence file, key file, expiry date, machine binding or online activation was required.* The runtime banner confirms build profile `ci`.

- **Explanation.** PyArmor without **restrict mode / binding** protects confidentiality by obfuscation alone. Once the wrapper is removed, the protected code runs under an ordinary CPython provided the matching runtime is present, and the module namespace, class layout, function signatures and type structure are recoverable through normal introspection. Individual function bodies remain encrypted and are decrypted on demand; naive extraction attempts (`__code__` access on protected functions) produced crashes (`EOFError` / `SIGSEGV`) rather than plaintext, so **full source recovery was not achieved** during this assessment. That bounds the finding but does not negate it: the intended guarantee — that the software only runs as the vendor packaged it, on the vendor's terms — is not enforced.

- **Impact.** The protection's purpose is defeated for a motivated party with the binary in hand. Internal API contracts, class/schema design and the `.signal` configuration model are exposed; a researcher can drive product internals standalone, accelerate reverse engineering, and prepare tampering. It does not, by itself, grant access to vendor systems.

- **Recommendation.** For releases where the protection is a commercial requirement, use PyArmor's binding/restrict modes, add licence-file validation with expiry and machine binding, add integrity self-checks over the runtime library, and consider BCC mode for the most sensitive modules. Independently: treat the wrapper as a speed bump, and keep genuine secrets server-side rather than in the shipped artefact.

### F-04 — Bundled TLS stack OpenSSL 3.0.16 is outdated

- **Severity / CVSS:** **Medium, 5.6** — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L`
- **Affected components:** the interpreter's `_ssl` module — `ssl.OPENSSL_VERSION` → `OpenSSL 3.0.16 11 Feb 2025`, confirmed by executing the bundled runtime. This is the stack used for **all** HTTPS traffic to LLM endpoints. A **second, independently bundled** OpenSSL ships in `psycopg2_binary.libs/libcrypto-2e26a48f.so.3` at version **`OpenSSL 3.5.4 30 Sep 2025`** (used only for PostgreSQL connections via `--cache-database`).

- **Explanation.** Both bundled OpenSSL builds are behind their upstream patch levels. OpenSSL 3.0.16 is five patch releases behind the 3.0.x line (3.0.21); 3.5.4 is three behind the 3.5.x line (3.5.7). Published issues affecting the shipped versions include:

  | CVE | Severity | Summary | 3.0.x fixed in | 3.5.x fixed in |
  |---|---|---|---|---|
  | CVE-2025-15467 | High (CVSS 9.8) | Stack buffer overflow parsing CMS AuthEnvelopedData AEAD parameters | 3.0.19 | 3.5.5 |
  | CVE-2025-9230 | Moderate | Out-of-bounds read/write in RFC 3211 KEK unwrap | 3.0.18 | 3.5.4 |
  | CVE-2025-9232 | Low | Out-of-bounds read in HTTP client `no_proxy` handling | 3.0.18 | 3.5.4 |
  | CVE-2025-69419 / -69420 / -69421 | Moderate / Low | PKCS#12 and PKCS#7 parsing faults | 3.0.19 | 3.5.5 |
  | CVE-2026-42767 | Moderate | FFC-DH peer validation | 3.0.21 | 3.5.7 |

  Both shipped versions (3.0.16 and 3.5.4) fall inside the affected ranges for **CVE-2025-15467**. The 3.5.4 build has at least the 3.5.4 fix for CVE-2025-9230/-9232 and is otherwise affected by the remaining rows.

  **Reachability.** The highest-severity items sit in CMS/PKCS#12/PKCS#7 and OpenSSL HTTP-client code paths. Python's `ssl` module exposes TLS only, and the CLI does not parse CMS or PKCS#12 material through it — `cryptography` 48.0.1 carries its own OpenSSL build. These CVEs are therefore **not demonstrated to be reachable** from the CLI, and the score reflects that constraint. The finding stands as an outdated-component and patch-management issue: a TLS-stack downgrade or future reachable defect inherits the whole backlog.

  Note that runtime TLS defaults are correct — `verify_mode = CERT_REQUIRED`, `check_hostname = True`, minimum TLS 1.2.

- **Impact.** Latent: reduces the security margin of an outbound channel that carries proprietary source code, and increases exposure if any CVE in the backlog becomes reachable.

- **Recommendation.** Rebuild on a current CPython patch release with OpenSSL ≥ 3.0.21 (or a 3.5.x line), and add a build-time SBOM plus automated CVE gating so shipped interpreters track upstream releases.

### F-05 — Undocumented third-party egress and misleading failure attribution

- **Severity / CVSS:** **Low, 3.7** — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:L`
- **Affected components:** `tiktoken/load.pyc`, embedding agents

- **Evidence.** With a fully local BYO configuration, `--check-llm` reported:

  ```
  E63: HTTPSConnectionPool(host='openaipublic.blob.core.windows.net', port=443):
       Max retries exceeded with url: /encodings/cl100k_base.tiktoken
  ```

  and a subsequent scan **aborted** with exit code 63 and
  `SIGNAL-E63: Unexpected error for provider 'openai_compatible' (agent: mergekey-embed-agent)`.

- **Explanation.** The embedding agents pull the `cl100k_base` BPE vocabulary at runtime from a Microsoft/Azure public blob store. This host is not part of the documented LLM-endpoint configuration, is not controlled by the operator, and is contacted regardless of `--llm-uri`. The error surface attributes the failure to the LLM endpoint, which sends operators down the wrong diagnostic path.

- **Impact.** Undocumented egress to a third party from security tooling that is often deployed in restricted or air-gapped environments; the tool cannot run at all without that reachability, and the operator has no supported way to pre-seed or pin the artefact.

- **Recommendation.** Bundle or pre-fetch the tokenizer vocabulary into the distribution, allow a configurable mirror, honour a documented `TIKTOKEN_CACHE_DIR`/offline setting, and report the failure with an error code that names the real dependency instead of the LLM endpoint.

### F-06 — TLS verification can be disabled for source-code-bearing endpoints

- **Severity / CVSS:** **Low, 3.7** — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`
- **Affected option:** `--llm-ssl-verify` (default `True`)

- **Explanation.** Help text: *"Enable TLS certificate verification for LLM endpoints. Set to False for self-signed certificates."* When disabled, proprietary source code and prompts are sent over a channel where an on-path attacker can read or modify traffic. A correct alternative exists and is also provided (`--llm-ca-bundle`), so the insecure switch is avoidable.

- **Impact.** Man-in-the-middle exposure of analysed source code and of the API key in the `Authorization` header (observed in the `Bearer` header captured at the mock endpoint).

- **Recommendation.** Keep the option but make it noisy: require an explicit acknowledgement flag, emit a prominent warning to stdout and the log, and mark the scan report as having run with verification disabled. Prefer `--llm-ca-bundle` in documentation.

### F-07 — Credentials accepted on the command line

- **Severity / CVSS:** **Low, 3.3** — `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`
- **Affected options:** `--llm-key`, `--llm-<agent>-key`, `--aws-bearer-token`, `--gcp-service-account` (accepts a base64 key), `--cache-database` (may embed a password)

- **Explanation.** Values passed as arguments are visible to any local user through `/proc/<pid>/cmdline`, are typically persisted in shell history, and are frequently echoed by CI runners. The tool's own logging is correct in this respect — an invocation carrying canary values logged the command line as:

  ```
  Invoked with command line: … --llm-key=******** --aws-bearer-token=******** …
  ```

  i.e. **redaction is already implemented**; the residual exposure is the process argument list itself.

- **Impact.** Disclosure of LLM and cloud credentials to a local user or to CI log retention.

- **Recommendation.** Prefer environment variables, a file descriptor, or a secrets file; document `--llm-key` as discouraged. Extend the existing redaction to panic/abort handlers that may print `sys.argv`.

### F-08 — Build metadata, internal path and test suite shipped in the release

- **Severity / CVSS:** **Low, 3.7** — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`
- **Evidence:**

  ```json
  // signal-2026.9.0.dist-info/direct_url.json
  {"url": "file:///builds/siglab/noscan", "dir_info": {"editable": true}}
  ```

  Additional material exposed by unpacking:

  - Internal build path `/builds/siglab/noscan` and the editable-install mode used to build the release.
  - `uv_cache.json` build timestamp (`1789075955` ≈ 2026-09-10), consistent with the PyArmor banner.
  - The complete `tests/` tree — 79 files including `tests/integration/_leak_scan.py` and numerous `test_*_e2e.py` fixtures. Class and function names alone map the product's internal architecture.
  - `pyarmor_runtime_008246/` contains runtimes for **darwin_aarch64, darwin_x86_64, linux_aarch64, windows_x86_64** in a Linux x86-64-only build — unnecessary payload and additional supply-chain surface.
  - Build toolchain: GCC 7.5.0 / Ubuntu 18.04 (EOL since April 2023).

- **Impact.** Accelerates targeted research, exposes internal naming conventions and infrastructure details, and inflates the artefact with code and binaries that are never used on the target platform. A malicious or accidental repackaging would be hard to spot.

- **Recommendation.** Strip `direct_url.json`/`uv_cache.json` and the `tests/` tree from release builds; ship only the runtime for the target platform; build with a supported toolchain; publish an SBOM and signed hashes with the release.

### F-09 — Bundled zlib 1.2.11 (Informational)

- **Evidence.** `zlibVersion()` invoked against the bundled `libz.so.1` returns **`1.2.11`**. Note for accuracy: Python's own `zlib` module reports `1.3.1` and is therefore patched; the 1.2.11 copy is the standalone library linked by the PyInstaller bootloader (`NEEDED libz.so.1`).

- **Explanation.** zlib 1.2.11 is affected by CVE-2018-25032 (memory corruption on deflate with many distant matches) and CVE-2022-37434 (heap buffer over-read/overflow in `inflate` via a large gzip header extra field; requires `inflateGetHeader`), both fixed in 1.2.12/1.2.13.

- **Impact.** Not demonstrated as reachable: the bootloader decompresses its own signed-off archive rather than attacker-supplied data, and the vulnerable code paths need primitives the bootloader does not exercise. Recorded as an outdated-component observation.

- **Recommendation.** Remove the redundant bundled zlib in favour of the interpreter's 1.3.1, or ship 1.2.13+.

### F-10 — No code signature or integrity verification (Informational)

The release is distributed with a SHA-256 in the release metadata and no signature, and the payload is a Python application whose archive can be unpacked, modified and repacked. Any holder of write access to a distribution channel, mirror or CI cache could substitute a trojanised build; detection requires manual hash comparison. **Recommendation:** publish GPG- or Sigstore-signed artefacts and hashes, and add an embedded integrity check over the PyInstaller archive and the PyArmor runtime.

---

## 6. Controls that behaved correctly

Recorded so that the assessment is balanced and so these are not regressed:

1. **Credential redaction in logs.** Sensitive options are masked (`--llm-key=********`, `--aws-bearer-token=********`) — the tool does not write secrets to `signal.log`.
2. **Secure TLS defaults.** `ssl.create_default_context()` semantics: `verify_mode = CERT_REQUIRED`, `check_hostname = True`, minimum TLS 1.2.
3. **No hardcoded live secrets.** The 136K-constant sweep found no live API keys, tokens or private keys. Matches such as `sk-ecdsa-sha2-nistp256` and `sk-budgets-2026-03-13` are library test fixtures; `BEGIN … PRIVATE KEY` markers come from parser/keyword tables and `cryptography` test assets, not embedded credentials.
4. **Cache/TLS tooling.** `truststore` is bundled, allowing use of the platform trust store.
5. **Documented hazard warning.** `--poc-kit` help text explicitly warns that the agent executes shell commands, installs dependencies and makes outbound requests, and instructs operators not to run it against production systems. The risk is documented, even though the technical control is absent (F-01).
6. **`certifi` bundle present** with a per-scan custom-CA override (`--llm-ca-bundle`).

---

## 7. Component inventory and vulnerability analysis

27 `dist-info` records were recovered, plus the declared dependency set from `signal-2026.9.0.dist-info/METADATA`. Versions confirmed by direct inspection:

**Runtime:** CPython 3.13.5 · PyInstaller 6.x+ · PyArmor 9.2.2 (ci) · OpenSSL 3.0.16 · zlib 1.3.1 (builtin) / 1.2.11 (bundled `libz`) · certifi 2025.01.31

**LLM / agent stack:** anthropic 0.97.0 · openai 2.38.0 · langchain 1.3.14 · langchain-core 1.4.9 · langchain-community 0.4.1 · langchain-google-genai 4.2.2 · langgraph ≥ 1.1.10 · langgraph-sdk 0.4.2 · langsmith 0.8.7 · pydantic 2.13.3 · pydantic-core 2.46.3 · pydantic-ai-slim 1.0.10 · genai-prices 0.0.67 · tiktoken · munch 4.0.0 · docstring-parser · griffe · logfire-api

**HTTP / TLS / crypto:** httpx 0.28.1 · httpcore 1.0.9 · httpx2 2.3.0 · httpcore2 2.3.0 · aiohttp 3.14.1 · requests 2.32.5 · urllib3 2.7.0 · websockets 15.0.1 · cryptography 48.0.1 · certifi · truststore · h11 · idna 3.10

**Data / storage:** numpy 2.3.5 · faiss-cpu 1.12.0 · SQLAlchemy 2.0.49 · psycopg2-binary 2.9.11 · orjson · ormsgpack · msgpack · xxhash · zstandard · regex · uuid_utils

**Vendored native libraries** (from `psycopg2_binary.libs` / `faiss_cpu.libs`): OpenSSL 3.5.4 (separate build, see F-04), libpq 5.17, libldap 2.0.200, libkrb5 3.3, libsasl2, libpcre 1.2.0 (PCRE1 — EOL upstream), libselinux, libcom_err, libgfortran/libquadmath 5.0.0, libgomp, libstdc++ (GLIBCXX_3.4.29)

**Vulnerability analysis of the AI framework stack.** The most relevant recent disclosures were checked explicitly against the bundled versions:

| CVE | Component | Affects | Bundled | Verdict |
|---|---|---|---|---|
| CVE-2026-34070 | langchain-core | < 1.2.22 | 1.4.9 | **Not affected** |
| CVE-2025-68664 | langchain-core | < 1.2.5 | 1.4.9 | **Not affected** |
| CVE-2026-28277 | langgraph (msgpack deserialisation) | < 1.0.10 | ≥ 1.1.10 | **Not affected** |
| CVE-2025-67644 | langgraph-checkpoint-sqlite | < 3.0.1 | not bundled | Not applicable |
| CVE-2026-27022 | langgraph-checkpoint-redis | < 1.0.2 | not bundled | Not applicable |
| CVE-2026-26019 | @langchain/community (JS) | ≤ 1.1.13 | n/a | Not applicable |

The AI/agent dependency set is current. The actionable lag is in the **interpreter's OpenSSL (F-04)** and the **redundant zlib 1.2.11 (F-09)**.

**Note on SBOM completeness.** `langgraph` ships no `dist-info` record in the bundle, so its exact version could not be read directly; the product metadata requires `langgraph>=1.1.10,<2.0`, and the CVE check above relies on that declared floor. A vendor-produced SBOM would close this gap.

---

## 8. Attack paths

**AP-1 — Untrusted repository to host compromise (requires `--poc-kit`).** The operator enables PoCKit and scans a third-party or untrusted codebase. A prompt injection embedded in a source file, comment, README or SARIF field reaches the research/exploit agent. The model emits a shell command through `run_shell`, which executes on the host with `shell=True` and the operator's privileges (F-01). Persistence and credential access follow; Docker contains the *target*, not the *commands*. Preconditions: the experimental flag is enabled, and the agent's instruction-following can be redirected.

**AP-2 — Malicious SARIF to workspace redirection (requires `--poc-kit`).** A crafted SARIF supplies a GUID containing traversal sequences. The workspace path is built by interpolation and created with `mkdir(parents=True, exist_ok=True)` (F-02), giving attacker-chosen directory creation and control of the `cwd` used by AP-1.

**AP-3 — Supply-chain substitution.** Because the payload can be unpacked, modified and repacked, and is distributed with only a hash (F-10, F-03), a compromised distribution path yields code execution on every analyst workstation. Mitigated only by out-of-band hash comparison.

---

## 9. Gaps and what was not determined

1. **Full protected-source recovery was not achieved.** PyArmor 9.2.2 function bodies remain encrypted and resist straightforward extraction; the product's business logic was not read. The assessment of F-03 demonstrates the protection is unbound and structurally disclosive, not that source can be trivially reconstructed.
2. **No end-to-end scan completed.** Scanning requires reaching `openaipublic.blob.core.windows.net` for the embedding agents' tokenizer (F-05), which the sandbox could not reach; the run aborted with exit code 63. Consequently the exact composition of the payload sent to the LLM during a full scan (whether whole files, redaction of secrets found in code, and the effect of `--exclude-paths` on dataflow prompts) was **not** verified. Only the `--check-llm` probe payload (`{"messages":[{"content":"Hello","role":"user"}], …}`) and its `Authorization: Bearer` header were captured.
3. **PoCKit was not executed.** `--poc-kit` was not enabled and no exploit was generated or run. F-01 and F-02 rest on static analysis of the shipped code and prompts, which is sufficient to establish the tool's existence and capability, but no dynamic confirmation (Docker launch, agent tool invocation) was performed.
4. **LLM-side risk was not exercised.** Whether the vendor's managed endpoint performs prompt-injection filtering, output sanitisation or tool-call mediation was not testable. `--llm-mode managed` behaviour was not examined.
5. **`--cache-file` / `--cache-database` contents were not characterised.** The SQLite/PostgreSQL LLM query cache was never populated because the scan aborted early; whether cached prompts and responses include source code, and with what file permissions and encryption, remains unverified.
6. **`--import-results` / `--checkpoint-file` deserialisation** was not tested with hostile inputs; these accept JSON produced by the tool itself, but the parser was not fuzzed.
7. **Embedded-credentials review is bounded by obfuscation.** The secret sweep covers the 6,374 modules that could be unmarshalled; string literals inside PyArmor-protected function bodies were not searchable.
8. **Vendor infrastructure was out of scope.** `llm.labs.blackduck.com`, `llm.core.blackduck.com` and `poc.polaris.blackduck.com` were identified but not probed. Testing them requires separate written authorisation.
9. **Binaries and artefacts are not committed to the repository.** The 116 MB binary, the 471 MB extraction and the reconstructed analysis environment live outside version control; the reproduction commands are in Appendix A.

---

## 10. Prioritised remediation

| Priority | Action | Finding |
|---|---|---|
| 1 | Remove the general shell tool from PoCKit; scope execution to the container via a fixed `docker exec` handle, run the feature under a dedicated unprivileged identity, and drop `shell=True`. | F-01 |
| 2 | Replace the GUID-derived workspace path with `tempfile.mkdtemp()` (0700) plus a containment and `O_NOFOLLOW` check; stop using untrusted GUIDs in paths. | F-02 |
| 3 | Rebuild on a current CPython with OpenSSL ≥ 3.0.21 and add build-time CVE gating to the release pipeline. | F-04, F-09 |
| 4 | Bundle or pre-seed the `cl100k_base` vocabulary so scans work without third-party egress; name the real dependency in the error. | F-05 |
| 5 | Enable PyArmor binding/restrict mode and add runtime integrity self-checks if the protection is a commercial requirement. | F-03 |
| 6 | Strip build metadata and the `tests/` tree from releases; ship only the target platform's runtime; publish a signed SBOM. | F-08, F-10 |
| 7 | Add an explicit acknowledgement gate and visible warning when TLS verification is disabled; steer users to `--llm-ca-bundle`. | F-06 |
| 8 | Document environment variables or a secrets file as the preferred credential path; keep the existing log redaction. | F-07 |

---

## Appendix A — Reproduction

```bash
# 1. Verify the artefact
sha256sum signal-pyarmor-linux-x86_64
#   47b9fa7236a5be5ed37a9186d55a6a84b8d2ef65fd0ab9e2fa744b0641c7d915

# 2. Triage the wrapper
readelf -h -l -S -d -n signal-pyarmor-linux-x86_64
readelf -p .comment signal-pyarmor-linux-x86_64

# 3. Unpack the PyInstaller archive (CArchive is not encrypted)
pyinstxtractor-ng signal-pyarmor-linux-x86_64

# 4. Inspect protected-module metadata
head -1 <any protected>.py            # Pyarmor 9.2.2 (ci), 008246, BlackDuckSignal, 2026-09-10T21:32:14

# 5. Confirm protected modules run outside the package (F-03)
#    Using a CPython 3.13 host built against the bundle's own libpython3.13.so.1.0:
#      import llm_uri_config, cli_config, models   -> all succeed, no licence needed

# 6. Confirm the shell tool signature (F-01)
#    disassemble PYZ.pyz_extracted/pockit/agents/shared_tools.pyc -> run_shell
#    subprocess.run(command, ..., shell=True, capture_output=True, text=True, timeout=120, cwd=...)

# 7. Confirm the workspace path (F-02)
#    disassemble PYZ.pyz_extracted/pockit/__main__.pyc
#    Path(f"/tmp/pockit-{guid}-workspace").mkdir(parents=True, exist_ok=True)

# 8. Dynamic: observe egress with a local mock endpoint (F-05)
./signal-pyarmor-linux-x86_64 --check-llm-json true ./target
#   -> E63: HTTPSConnectionPool(host='openaipublic.blob.core.windows.net', port=443)
#      /encodings/cl100k_base.tiktoken
```

## Appendix B — CLI option inventory (79 options)

`--agent-limit`, `--auto-accept-token-truncation`, `--aws-bearer-token`, `--aws-bedrock-region`, `--cache-database`, `--cache-file`, `--caching`, `--check-llm`, `--check-llm-json`, `--checkpoint-file`, `--config`, `--crypto`, `--cvss-threshold`, `--dataflow`, `--disable-default`, `--display-extensions`, `--error-log-file`, `--exclude-paths`, `--export-results`, `--extra-extensions`, `--gcp-project`, `--gcp-region`, `--gcp-service-account`, `--git-diff`, `--git-diff-dir`, `--git-diff-generate-patch`, `--git-diff-reference-branch`, `--git-diff-untracked`, `--help`, `--ignore-test-files`, `--import-results`, `--include-paths`, `--intra-file-shortcircuit`, `--large-code-base-size`, `--llm-api-version`, `--llm-ca-bundle`, `--llm-dataflow-agent-{api-version,key,model,timeout,uri}`, `--llm-exploitation-agent-{api-version,key,model,timeout,uri}`, `--llm-key`, `--llm-limit`, `--llm-mergekey-embed-agent-{api-version,key,model,timeout,uri}`, `--llm-mode`, `--llm-model`, `--llm-model-agent`, `--llm-oversight-agent-*`, `--llm-oversight-embed-agent-*`, `--llm-prompt-caching`, `--llm-sca-agent-{api-version,key,model,timeout,uri}`, `--llm-singlefilescan-agent-*`, `--llm-ssl-verify`, `--llm-tag`, `--llm-timeout`, `--llm-uri`, `--log-file`, `--log-level`, `--misra`, `--model-completion-limit`, `--oversight`, `--oversight-cve-detection`, `--oversight-embedding`, `--oversight-rules-file`, `--pipeline`, `--poc-kit`, `--poc-kit-log-file`, `--poc-kit-report-dir`, `--prioritization`, `--report-file`, `--result-limit`, `--result-preview`, `--show-triage`, `--skip-estimates`, `--skip-generated-files`, `--synthesis`, `--thinking-budget`, `--version`

---

**Conclusion.** The artefact is well-engineered on the security basics — TLS verification is on by default, credentials are redacted from logs, no live secrets are embedded, and the AI-framework dependency set is current against the recent LangChain/LangGraph disclosures. Its material risk is **capability, not defect**. PoCKit ships an autonomous agent holding a host shell with `shell=True` (F-01) operating on a predictably named, unvalidated workspace (F-02); the "isolated Docker container" framing in the help text describes where the *target* runs, not where the *commands* run. **That is the finding to act on before this feature leaves experimental status.** Secondary work is patch hygiene on the bundled OpenSSL 3.0.16 interpreter (F-04) and removing the mandatory third-party tokenizer fetch (F-05).
