# F-08 — client briefing note

**Finding:** Build metadata, internal build path, development tooling and the product test suite ship in the release binary.
**Severity:** Low, CVSS 3.1 **3.7** — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` · CWE-200, CWE-540 · A05:2021 Security Misconfiguration.

---

## 1. The 30-second answer

> The shipping binary still carries the fingerprints of the machine that built it: the internal CI path it was installed from, the exact build date, the compiler and operating system used, the complete test suite, four platform runtimes for platforms you don't ship, and build-only tools declared as runtime dependencies.
>
> None of this lets an attacker break in. It is **read-only information exposure** — but it hands a researcher a map of your build pipeline and your internal architecture for free, it makes your SBOM wrong, and it shows the release process isn't scrubbing what it publishes. The fix is in the build config, not the product, and it's cheap.

**Three sentences if they only have a minute:** the product behaves identically; no customer data is exposed; the exposure is about *how the product was built*, and it is fixed at build time.

---

## 2. What the 15 lines mean

Group them into five buckets. This is the order to present them in — provenance first, because it is the most concrete.

| Bucket | What we actually read | Plain English | Why the client should care |
|---|---|---|---|
| **A. Where it was built** | `direct_url.json` → `file:///builds/siglab/noscan`, `editable: true` | The app remembers the exact folder on the build server it was installed from, and that it was installed in developer ("editable") mode rather than from a package | Discloses CI group/project naming and that releases are cut straight from a checkout. It is a targeting lead for your build infrastructure, not an access grant |
| | Same path again in `pockit-0.1.52.dist-info/direct_url.json` | The bundled dependency records the same path, including the wheel it was built from | Shows the residue is systemic across the build, not one stray file |
| **A. When it was built** | `uv_cache.json` = `1789075955` → 2026-09-10 21:32:35Z; PyArmor banner 21:32:15Z | Two independent clocks agree: the release was built on 10 September 2026 at 21:32 UTC | Lets an outsider line the build up against dependency versions and vulnerability disclosure dates |
| **A. How it was protected** | `# Pyarmor 9.2.2 (ci), 008246, BlackDuckSignal, …` | The obfuscator version, build id and licence name are stamped into every protected file | Tells a researcher precisely which protection build to attack, and leaks an internal identifier |
| **B. What built it** | `.comment`: `GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0`; `.text` byte-identical to PyInstaller 6.20.0's stock Linux bootloader | Names the compiler and distro behind the executable, and pins the packaging toolchain exactly | **Attribution: this is upstream PyInstaller's own build container, not your CI.** It fixes the packaging version — it does not show your build image is EOL. Do not let this become "your build server is unsupported" |
| **C. Development material** | `tests/` — 79 files, 4.9 MB, all PyArmor-wrapped, incl. `_leak_scan.py` and 13 `test_*_e2e.py` | The QA suite ships with the product | File, class and fixture names map your internal architecture and test scenarios. No plaintext logic is exposed — the files are obfuscated |
| **D. Unused platform runtimes** | `darwin_aarch64`, `darwin_x86_64`, `linux_aarch64`, `windows_x86_64` inside a linux-x86_64 build — 2.7 MB | Four native blobs for platforms you don't ship | Dead weight, and four more binaries a customer's scanner has to trust and review |
| **E. Misdeclared dependencies** | `Requires-Dist: pip-audit==2.10.0`, `pyarmor-cli-core-{darwin,linux,windows}==8.1.0`, `pockit>=0.1.4` | Build tools and platform-specific packages are declared as things you need at run time | Your SBOM is wrong. Anyone installing from this metadata pulls build tooling, and every scanner will flag it. `pockit` — the autonomous exploit harness — is a *hard* requirement, not an optional extra |

**The one-line root cause:** PyInstaller collected the build environment's installed-package metadata into the release. Everything in the finding follows from that.

---

## 3. Why Low 3.7 and not higher

Say the vector out loud; it pre-empts "why isn't this critical?" and "why is this even a finding?" at the same time.

| Component | Value | What it means in the room |
|---|---|---|
| Attack Vector | **Network** | Anyone who can download the binary can read it |
| Attack Complexity | **High** | On its own it achieves nothing. It only pays off combined with another weakness, or as reconnaissance |
| Privileges / User interaction | **None / None** | No account, no victim action |
| Confidentiality | **Low** | Internal names, paths, versions and build timing — not customer data, not credentials |
| Integrity / Availability | **None / None** | The product behaves exactly the same; nothing is modified |

Contrast for calibration: **F-01 is High 8.3 because it executes commands on the host.** F-08 is information exposure and artefact hygiene. Same report, different class of problem — say so explicitly, because that comparison does most of the work.

---

## 4. The questions you will be asked

**"Can someone hack us with this?"**
No, not with this alone. Nothing here grants access, and we found no evidence that the build server was compromised. What we found is build residue: the artefact remembers where it came from.

**"Then why is it a finding?"**
Three reasons. It is free reconnaissance that shortens an attacker's path; it proves the release pipeline doesn't scrub its output, which matters because that same pipeline produces your trusted, signed binaries; and it makes the SBOM inaccurate, which your customers' scanners *will* notice even if no attacker ever does.

**"Does shipping the tests leak our source code?"**
No. All 79 files are PyArmor-wrapped bytecode; we did not recover plaintext logic. What leaks is the shape of the codebase — file names, class and function names, fixture names, and the presence of an internal leak-scan helper. That is architecture disclosure, not source disclosure.

**"Is Ubuntu 18.04 a CVE — and is that our build server?"**
No CVE, and no: that stamp is not yours. The executable's `.text` is byte-identical to PyInstaller 6.20.0's stock Linux bootloader, and PyInstaller compiles that bootloader upstream in an `ubuntu:18.04` container. So the line identifies the packaging toolchain exactly — useful for inventory — but says nothing about your CI image. Removing it means rebuilding the bootloader, which is optional.

**"Is `pip-audit` a vulnerability?"**
No. It's a packaging defect. It's declared as a runtime dependency but its modules aren't in the artefact — so nothing is actually shipped to exploit. The damage is a wrong SBOM, needless dependency resolution, and scanner noise. One line in the build config fixes it.

**"`pockit` sounds like an exploit tool — are we shipping malware?"**
`pockit` is your own autonomous exploit harness, version 0.1.52, built from the same checkout. In a security product that's expected. The finding is that it's a *hard* dependency rather than optional, so every install and every review carries it whether or not it's used.

**"What does an attacker actually do with this?"**
Downloads the binary, reads it, and learns the CI path, the build date, the obfuscation build and the full dependency inventory. That's targeting data: it makes any *other* weakness faster to exploit and makes social engineering against the CI team easier. It still needs that other weakness to exist.

**"Do we need to recall or emergency-patch?"**
No. The product is not made less secure by shipping this. Fix it in the next scheduled release; if a customer audit is imminent, scrub the metadata and drop the tests first — that's the cheapest, most visible reduction.

**"Will fixing it break anything?"**
No. Every fix is a build or packaging change: exclude `tests/`, single-platform runtime, build tools moved to extras, rebuild on a supported image. No product code changes.

**"How do we prove it's fixed?"**
Rebuild, then re-run `python3 poc/16-check-f08.py`. After remediation every claim should **FAIL** and the script exits non-zero — that's the pass condition for you. Attach the output and the corrected `Requires-Dist` list to the closure evidence.

---

## 5. What to tell them to fix

| Action | Owner | Effort | Removes |
|---|---|---|---|
| Exclude `tests/` from the wheel/PyInstaller spec | Release engineering | hours | 4.9 MB and the architecture disclosure |
| Strip `direct_url.json`, `uv_cache.json` and other `dist-info` residue; build from a wheel in a clean venv instead of an editable install | Release engineering | hours | Build-host path, editable flag, build timestamp |
| Ship only `pyarmor_runtime_008246/linux_x86_64` | Release engineering | trivial | 2.7 MB and three native blobs |
| Move `pip-audit` and `pyarmor-cli-core-*` to build-time extras; decide deliberately whether `pockit` is required | Packaging | trivial | Wrong SBOM, dependency bloat |
| Record PyInstaller 6.20.0 (identified from the bootloader) in the SBOM and track its advisories | Security | trivial | Unknown packaging version; the `.comment` stamp itself is upstream's, not a defect |
| Generate the SBOM from the built artefact and sign it with the release | Release engineering | days | Trust in the published inventory |

---

## 6. Overclaiming traps

Say the left column and you will be corrected in the meeting. Say the right column.

| Don't say | Say |
|---|---|
| "Source code leaked" | "Structure and inventory leaked; the logic stayed obfuscated" |
| "The build server was compromised" | "No evidence of compromise; the build environment is unsupported" |
| "You build on Ubuntu 18.04" | "That stamp is PyInstaller's upstream container; the artefact does not show your build image" |
| "Critical" / "High" | "Low, 3.7 — network-readable, high complexity, confidentiality-only, limited" |
| "Attackers can reach `/builds/siglab/noscan`" | "The path is disclosed; it grants no access" |

---

## 7. If they choose to accept the risk

That is a legitimate decision for a Low, but three things still need an answer:

1. **SBOM accuracy** — customers and procurement consume it; wrong `Requires-Dist` entries are a contract and compliance issue independent of attacker interest.
2. **Release checklist** — add "no build metadata, no tests, one runtime" to the build gate so it doesn't regress on the next cut.
3. **Monitoring** — watch for published unpackers or research targeting PyArmor 9.2.2 / build `008246`, since that build number is public in the artefact.
