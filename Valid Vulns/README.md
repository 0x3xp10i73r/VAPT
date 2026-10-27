# Valid Vulns — Signal PoC launchers

These four scripts run the **same executed PoCs already in `poc/`**, without
copying or changing their checks. Run them separately on Linux or WSL2. Each
launcher locates the repository itself; no `$WORK`, Python 3.13 installation or
manual environment exports are required. All credentials used in tests are
synthetic canaries.

From the repository root, run whichever finding you want to verify:

```bash
bash "Valid Vulns/01-cleartext-transmission.sh"
bash "Valid Vulns/02-build-metadata.sh"
bash "Valid Vulns/03-outdated-openssl.sh"
bash "Valid Vulns/04-api-key-in-argv.sh"
```

| Requested finding | Launcher | Unchanged test executed | Successful summary |
|---|---|---|---|
| Cleartext Transmission of Sensitive Information | `01-cleartext-transmission.sh` | `poc/17-check-plaintext.py` | `plaintext transport reproduced: 3/3` |
| Information Exposure Through Build Metadata and Development Artifacts | `02-build-metadata.sh` | `poc/16-check-f08.py` (F-08) | `F-08 reproduced: 3/3` |
| Use of Outdated OpenSSL Component | `03-outdated-openssl.sh` | `poc/15-check-f04.py` (F-04) | `F-04 reproduced: 3/3` |
| API Key Disclosure via Process Command-Line Arguments | `04-api-key-in-argv.sh` | `poc/21-check-argv-keys.py` (F-07 / CWE-214) | `F-07 reproduced: 4/4` |

The launchers preserve the original PoCs' PASS/FAIL checks and exit codes (0 =
all checks passed; nonzero = failed or could not set up). They do not turn a
version-in-affected-range result into a claim that a CVE is exploitable.

**Verified in this Linux sandbox (27 October 2026):** all four commands exited
0. The cleartext run captured five raw requests and printed `3/3`; the build
metadata and bundled OpenSSL checks each printed `3/3` (the runtime itself
reported OpenSSL 3.0.16); and the argv check printed `4/4` with the canary also
read from the process as the unprivileged `nobody` account.

**One-time preparation.** If the binary is missing, the launchers obtain only
the two parts from this repository's `binary-drop` branch and reconstruct the
v1.0 ELF under `/tmp/vapt/`, validating its size and SHA-256 before running it.
The F-04 and F-08 launchers also run `poc/00-setup.sh` the first time, which
extracts the archive and builds the host for the bundled Python 3.13 runtime.
That step needs `python3`, `python3-venv`, `gcc`, `git`, and (if the extractor is
not installed) access to PyPI. The detailed setup transcript is saved at
`/tmp/vapt/valid-vulns-setup.log`; the launchers print the tail on failure.
All paths in this runbook are relative to the cloned repository, not a shell
variable carried between terminals.

**Cleartext evidence.** The first launcher writes the *raw HTTP requests* it
captured (wire-order headers, body, byte lengths and hashes; CRLF displayed as
LF) to `Valid Vulns/captures/01-cleartext-requests.txt`. The key is fake. A
committed example is also in `poc/captures/17-plaintext-capture.txt`; for
Wireshark on WSL, follow `poc/captures/README.md`. This check demonstrates that
an operator-selected `http://` endpoint accepts a bearer token without TLS or
warning; Signal's default endpoint is HTTPS. The `--check-llm-json` requests are
validation probes, **not a full scan's source code**.

**Other limits.** F-04 proves that the *bundled* interpreter actually uses
OpenSSL 3.0.16 and compares it to published fixed-version boundaries; it does
not execute CVE-2025-15467 or prove that any advisory is reachable from the CLI.
F-08 reads build metadata and shipped development material from the archive;
it does not claim that the compiler stamp is the vendor's own build host.
F-07 uses fake keys and a local LLM mock; when passwordless sudo is available
it also tries the `/proc` read as unprivileged `nobody`. Without sudo, it marks
that optional cross-user test SKIPPED instead of claiming it ran. Never put a
real API key on the command line to test this.
