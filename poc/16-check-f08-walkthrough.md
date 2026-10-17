# `16-check-f08.py` — what it does, line by line

Companion to the F-08 entry in `../signal-pyarmor-linux-x86_64-vapt.md` and to
`../f08-client-brief.md`. Read this if you need to defend, re-run or adapt the
check.

---

## 1. What kind of check this is

F-08 is unusual in this report: **nothing is executed**. Every claim is read out
of the artefact as shipped, so there is no host shell, no mock agent, no
tokenizer cache, and no reconstructed interpreter involved. The script reads
three things:

| Input | How it is found | Used for |
|---|---|---|
| the extracted archive | `./signal-pyarmor-linux-x86_64_extracted/`, or `$SIGNAL_EXTRACT` | sections A and C |
| the shipped executable | `./signal-pyarmor-linux-x86_64`, `--binary`, or `$SIGNAL_BIN` | section B |
| nothing else | — | no imports from the product, no network |

That is why it runs under any Python 3.8+ and does not need `py313host`. It also
means the check cannot fail because of a broken sandbox — only because the
artefact changed.

## 2. Running it

```bash
# normal case, from the directory that holds the extraction and the binary
python3 poc/16-check-f08.py

# explicit paths
python3 poc/16-check-f08.py --binary /path/to/signal-pyarmor-linux-x86_64
SIGNAL_EXTRACT=/path/to/signal-pyarmor-linux-x86_64_extracted python3 poc/16-check-f08.py
```

**If your shell exported `PYTHONHOME`/`PYTHONPATH` for `./py313host`**, clear them
first or the interpreter dies before reading the script (`bad magic number in
'encodings'`):

```bash
env -u PYTHONHOME -u PYTHONPATH python3 poc/16-check-f08.py
```

Exit codes: **0** = all three claims reproduced, **1** = at least one failed,
**2** = no extraction found (run `poc/00-setup.sh`).

Note the inversion: exit **0 means the finding is present**. After remediation
every claim should FAIL and the script should exit 1 — that is your closure
evidence, not a regression.

## 3. The output, line by line

```
F-08 focused check - build provenance and development material in the release
extraction: /tmp/vapt/signal-pyarmor-linux-x86_64_extracted
binary    : /home/user/VAPT/signal-pyarmor-linux-x86_64
```

These two lines are the proof of *what was measured*. If they point at a stale
tree or the wrong binary, nothing below is meaningful — check them first.

### Section A — provenance

```
== A. provenance: where and how the release was built ==
   signal-2026.9.0        file:///builds/siglab/noscan  (editable=True)
   pockit-0.1.52          file:///builds/siglab/noscan/extensions/pockit-0.1.52-py3-none-any.whl  (editable=None)
```

Read from `<dist>.dist-info/direct_url.json`, which pip writes when a package is
installed from a directory or an editable checkout. Two records exist, so the
check reads both:

- **`signal-2026.9.0`** — the product itself. `file:///builds/siglab/noscan` is an
  absolute path on the build host: CI group `siglab`, project `noscan`.
  `editable=True` means it was installed with `pip install -e`, i.e. built from a
  source tree rather than from a wheel.
- **`pockit-0.1.52`** — the bundled dependency, same base path plus the wheel that
  was built there. This is what makes the finding systemic rather than a stray
  file: the whole build inherited the same install layout.

```
   PASS - direct_url.json exposes an absolute build-host checkout path
   PASS - the install is recorded as editable (built from a source tree, not a package)
```

Both are computed from the values above: a `file://` URL containing `builds/`, and
any record with `editable` true. Nothing here is asserted from a hard-coded path —
swap in a build made elsewhere and the lines change or fail.

```
   PASS - uv_cache.json build timestamp: 1789075955 (2026-09-10T21:32:35Z)
```

`uv_cache.json` is residue from `uv`; `timestamp.secs_since_epoch` is converted to
UTC. This is the **first** independent clock.

```
   PASS - PyArmor banner in shipped sources: # Pyarmor 9.2.2 (ci), 008246, BlackDuckSignal, 2026-09-10T21:32:15.141264
```

The banner on the shipped test sources. It records the obfuscator version, build
id, licensee name and a second timestamp — **21:32:15Z**, twenty seconds before
the `uv_cache` value. Two unrelated files agreeing to the second is what makes the
build moment a fact rather than an inference.

The banner is located by scanning the first five lines of each shipped file, not
by assuming it is line 1: three shipped scripts begin with a shebang, and an
earlier version of this check printed `#!/usr/bin/env python3` as if it were the
banner.

### Section B — toolchain

```
== B. toolchain: what built the binary (ELF .comment) ==
   .comment: GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
```

`.comment` is a non-allocated ELF section holding the compiler string. The script
finds it with its own reader (`elf_section()`), about 40 lines, because the
sandbox has no `binutils`:

1. read `e_ident`, confirm `\x7fELF`, note class (32/64) and byte order;
2. read `e_shoff` at `0x28` (ELF64) or `0x20` (ELF32);
3. read `e_shentsize`, `e_shnum`, `e_shstrndx` at `0x3A` / `0x2E`;
4. resolve section names through `.shstrtab`;
5. return the bytes of the first section named `.comment`.

`readelf -p .comment` prints the identical line; the check exists so the result is
reproducible without the tool installed.

```
   compiler: GCC 7.5.0   distro: Ubuntu 18.04   (standard support ended April 2023)
```

The regex `Ubuntu ([0-9.]+)-[^)~]*~([0-9.]+)[^)]*\)\s*([0-9.]+)` takes three
groups from
`GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0` — package version `7.5.0`,
**distro `18.04`**, compiler `7.5.0`. Do not simplify this: a naive
`\(Ubuntu ([\d.]+)` captures **`7.5`** (the GCC version inside the package name)
and prints "Ubuntu 7.5". The release is the suffix after `~`.

```
   PASS - the executable discloses the toolchain that produced it
   NOTE - .text is byte-identical to PyInstaller 6.20.0's stock Linux
          bootloader, which upstream builds in an ubuntu:18.04 container:
          the stamp describes that bootloader, not your own build image
```

**This is the most important correction in the check, and the one most likely to
be challenged.** A PyInstaller executable is a prebuilt *bootloader* with the
Python archive appended, and PyInstaller compiles its official Linux bootloaders
in a container that is literally `FROM ubuntu:18.04`
(`bootloader/Dockerfile.glibc`). So `GCC 7.5.0 / Ubuntu 18.04` is exactly what a
**stock** bootloader always says — it says nothing about the vendor's CI.

The check proves which case applies by hashing `.text`:

```python
STOCK_BOOTLOADERS = {
    "9ecbaec3…53606": "6.18.0/6.19.0",
    "73a4f703…5da5d1f": "6.20.0",
}
```

Those hashes were taken from the `PyInstaller/bootloader/Linux-64bit-intel/run`
file inside the manylinux2014 wheels on PyPI. The shipped executable's `.text`
hash equals **6.20.0**'s exactly, so:

- the bootloader is **unmodified stock** — no custom packer, no patched loader;
- the `.comment` stamp is **upstream's build container**, not the vendor's image;
- the useful fact is the **packaging version: PyInstaller 6.20.0** (which is also
  what makes CVE-2025-59042 not applicable — it affects 6.19.0 and earlier).

If `.text` matched nothing in the table, the script would say so instead, and
*then* the stamp would plausibly describe the vendor's own build image. The check
is written to distinguish the two cases rather than assume either.

### Section C — development material

```
   tests/ tree      : 79 files (4.9 MB), 79 carry a PyArmor banner
```

`rglob("*.py")` under `tests/`, size summed over **all** files (not just `.py`),
banner counted per file. The banner test looks at the first five lines because of
the shebang files; an earlier version tested line 1 and reported `76/79`, which
would have been a false defect.

```
   PASS - test suite ships at all: 79 files
   PASS - every shipped test is itself obfuscated (79/79)
   PASS - an internal 'leak scan' helper is part of the shipped tree: tests/integration/_leak_scan.py
```

Three separate claims. The third is the interesting one for a client: a file named
`_leak_scan.py` inside the shipped tree tells a reader what the vendor scans for.
It is reported as `NOTE` if absent so a different build does not look like a
failure of the whole bucket.

```
   dist-info records: 26 (report records 26)
```

Counted from the filesystem; the parenthetical is the report's value, printed so a
mismatch is visible rather than hidden.

```
   platform runtimes: darwin_aarch64, darwin_x86_64, linux_aarch64, linux_x86_64, windows_x86_64
   PASS - 4 foreign-platform runtime(s) in a linux_x86_64 build, 2.7 MB unused
```

Everything under `pyarmor_runtime_*/` except `HOST_PLATFORM = "linux_x86_64"` is
"foreign". Sizes are summed from the files themselves. The claim is not that they
are malicious — only that they can never load on the target platform and still
have to be reviewed and scanned by every customer.

```
   PASS - declared runtime dependency 'pip-audit==2.10.0' - build tool, module not collected
   PASS - declared runtime dependency 'pyarmor-cli-core-darwin==8.1.0' - build tool, module not collected
   … linux … windows …
```

Read from `Requires-Dist:` in `signal-2026.9.0.dist-info/METADATA`, filtered to
`BUILD_ONLY_DEPS = ("pip-audit", "pyarmor-cli-core")`. For each, the check globs
the extraction for the module (`pip_audit*`, `pyarmor_cli_core*`) and reports
whether it is actually present. It is not — so the defect is the **metadata**, not
a shipped module: every downstream SBOM and every `pip install` from this metadata
inherits build tooling.

```
   NOTE - pockit>=0.1.4 is a hard runtime dependency (an autonomous exploit harness), not an optional extra
```

A `NOTE`, deliberately not a PASS: shipping your own exploit harness is expected
in a security product. The observation is that it is unconditional.

### Summary

```
   PASS provenance
   PASS toolchain
   PASS dev material
   F-08 reproduced: 3/3
```

One line per bucket, then `n/3`. The trailing paragraph states the limit
explicitly: this is information exposure and artefact hygiene, **not** an
exploitable defect — which is why the report scores it Low 3.7.

## 4. Checking it without the script

Every claim has a one-line shell equivalent. If a client asks "how do you know?",
these are the commands:

```bash
E=signal-pyarmor-linux-x86_64_extracted
cat  $E/signal-2026.9.0.dist-info/direct_url.json
cat  $E/pockit-0.1.52.dist-info/direct_url.json
cat  $E/signal-2026.9.0.dist-info/uv_cache.json
head -3 $(find $E/tests -name '*.py' | head -1)
find $E/tests -name '*.py' | wc -l                      # 79
grep -l '^# Pyarmor' $(find $E/tests -name '*.py') | wc -l   # 79 files with a banner
ls -d $E/*.dist-info | wc -l                            # 26
ls $E/pyarmor_runtime_008246/                           # 5 platform dirs
grep -i '^Requires-Dist' $E/signal-2026.9.0.dist-info/METADATA
readelf -p .comment signal-pyarmor-linux-x86_64         # GCC 7.5.0 / Ubuntu 18.04
objcopy -O binary --only-section=.text signal-pyarmor-linux-x86_64 /tmp/text.bin
sha256sum /tmp/text.bin
#   73a4f7031b47c283106e74bc0a82135325e98d7a2de49de6ab8f1b8ef5da5d1f  = PyInstaller 6.20.0
```

The last line is the attribution test: extract `.text` and hash it. That hash
matching PyInstaller 6.20.0's wheel means the `.comment` stamp is upstream's.

## 5. Limits — what the script deliberately does not claim

- **No compromise.** It shows build residue, not a breached runner. The presence
  of `direct_url.json` proves how the build environment installed the package,
  nothing about who had access to it.
- **No source disclosure.** The test tree is obfuscated; the check counts banners,
  it does not recover plaintext.
- **No CVE.** `DISTRO_EOL` is a lookup table for reporting; it is not a
  vulnerability match. The PyInstaller version is identified, but no advisory is
  evaluated here — that is F-08's sibling checks, not this script.
- **Counts are pinned to this build** (`EXPECTED_TESTS`, `EXPECTED_DIST_INFO`).
  They are printed for comparison, not asserted as universal truths.
- **`HOST_PLATFORM` is a constant.** "Foreign" means "not linux_x86_64"; run it on a
  different target and the label is wrong until you change it.
- **The fingerprint table is finite.** A newer PyInstaller produces an unmatched
  `.text`, and the script then reports a custom build — read the NOTE before
  repeating it.

## 6. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Fatal Python error: Failed to import encodings module` / `bad magic number in 'encodings'` | shell still has the `./py313host` exports | `env -u PYTHONHOME -u PYTHONPATH python3 …` |
| `no extraction found — run poc/00-setup.sh first` (exit 2) | `/tmp` wiped, or run from elsewhere | `./poc/00-setup.sh`, or set `SIGNAL_EXTRACT` |
| `FAIL - binary not found; pass --binary …` | checkout without the 116 MB asset | `git fetch origin binary-drop:refs/remotes/origin/binary-drop`, or `--binary` |
| `FAIL - cannot read .comment from …` | wrong file (a script, a truncated download) | verify `sha256sum` against `47b9fa72…c1c7d915` |
| `tests/ tree : 0 files` | pointed at a bare extraction without the archive expanded | use the setup output, not the raw binary |
| `F-08 reproduced: 2/3` after a rebuild | that is **success** for remediation | confirm which bucket still passes — usually provenance residue |

## 7. Change log for this script

- **Initial version** — 3 buckets, 3/3 on the 2026.9.0 release.
- Distro regex fixed: it captured `7.5` (GCC) instead of `18.04` (Ubuntu) from
  `7.5.0-3ubuntu1~18.04`.
- Banner detection moved from "first line of the first file" to "first `# Pyarmor`
  line within the first five lines", so shebang scripts are handled.
- `.comment` attribution added: `.text` is hashed and matched against stock
  PyInstaller bootloaders, so the Ubuntu 18.04 stamp is not mis-reported as the
  vendor's build image. Summary wording changed from "the compiler … the release
  was built with" to "behind its bootloader".
