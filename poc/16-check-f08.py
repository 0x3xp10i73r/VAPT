"""PoC-F08 (focused): build provenance, internal build path and development
material ship inside the release binary.

F-08 needs no code execution at all: everything below is readable from the
artefact as distributed. This script only automates the reading, and prints
PASS/FAIL per claim:

  A. provenance   - direct_url.json (internal CI build path + editable install,
                    for the product *and* for its pockit dependency), the
                    uv_cache build timestamp and the PyArmor banner timestamp
  B. toolchain    - the ELF .comment section: the compiler and distro behind
                    the executable (parsed here, no binutils needed), matched
                    against PyInstaller's stock bootloader so the stamp is not
                    mis-attributed to the vendor's own build image
  C. dev material - the shipped tests/ tree, the dist-info records, the
                    foreign-platform PyArmor runtimes, and build-only tools
                    declared as runtime dependencies

Run it with any Python 3.8+ - the reconstructed host is not required, because
nothing is imported from the product:

    python3 poc/16-check-f08.py                      # finds the artefacts itself
    python3 poc/16-check-f08.py --binary /path/to/signal-pyarmor-linux-x86_64

Exit codes: 0 = every claim reproduced, 1 = a claim failed, 2 = not set up.
"""
import hashlib
import json
import os
import pathlib
import re
import struct
import sys

# What the report records for build 2026.9.0. A different build may legitimately
# differ; the check prints the measured values next to these either way.
EXPECTED_TESTS = 79
EXPECTED_DIST_INFO = 26
HOST_PLATFORM = "linux_x86_64"
BUILD_ONLY_DEPS = ("pip-audit", "pyarmor-cli-core")

# Standard-support end dates for the distributions a build could name. Only
# used to say whether the toolchain is past end of life; extend as needed.
DISTRO_EOL = {"16.04": "April 2021", "18.04": "April 2023", "20.04": "May 2025"}

# sha256 of .text in PyInstaller's stock Linux-64bit-intel bootloader, taken from
# the manylinux2014 wheels on PyPI. Byte-stable per release, so a match proves the
# executable ships an unmodified upstream bootloader - and upstream compiles it in
# an ubuntu:18.04 container, which is where the .comment stamp comes from.
STOCK_BOOTLOADERS = {
    "9ecbaec380762afad2ac6b2a9c1ba1c70c0bd72b827dbed85c573731df453606": "6.18.0/6.19.0",
    "73a4f7031b47c283106e74bc0a82135325e98d7a2de49de6ab8f1b8ef5da5d1f": "6.20.0",
}


# ------------------------------------------------------------------ locate
def find_extract():
    here = os.path.dirname(os.path.abspath(__file__))
    env = os.environ.get("SIGNAL_EXTRACT")
    cands = ([env] if env else []) + [
        os.path.join(os.getcwd(), "signal-pyarmor-linux-x86_64_extracted"),
        os.path.join(os.path.dirname(here), "signal-pyarmor-linux-x86_64_extracted"),
        "/tmp/vapt/signal-pyarmor-linux-x86_64_extracted",
    ]
    for c in cands:
        if os.path.isdir(os.path.join(c, "PYZ.pyz_extracted")):
            return c
    return None


def find_binary(argv):
    for i, a in enumerate(argv):
        if a == "--binary" and i + 1 < len(argv):
            return argv[i + 1]
    here = os.path.dirname(os.path.abspath(__file__))
    cands = [
        os.environ.get("SIGNAL_BIN", ""),
        os.path.join(os.path.dirname(here), "signal-pyarmor-linux-x86_64"),
        os.path.join(os.getcwd(), "signal-pyarmor-linux-x86_64"),
        "/tmp/vapt/signal-pyarmor-linux-x86_64",
    ]
    for c in cands:
        if c and os.path.isfile(c):
            return c
    return None


# --------------------------------------------------------------- ELF reader
def elf_section(path, wanted):
    """Return the bytes of an ELF section, using only the standard library.

    Reads the section-header table named by e_shoff/e_shnum, resolves names
    through .shstrtab, and returns the payload of the first section called
    `wanted`. Works for ELF32/ELF64 in either byte order; no binutils needed.
    """
    with open(path, "rb") as fh:
        ident = fh.read(16)
        if ident[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        elf_class, elf_data = ident[4], ident[5]
        if elf_class not in (1, 2) or elf_data not in (1, 2):
            raise ValueError("unsupported ELF class/encoding")
        end = "<" if elf_data == 1 else ">"

        if elf_class == 2:                      # ELF64
            fh.seek(0x28)
            (shoff,) = struct.unpack(end + "Q", fh.read(8))
            fh.seek(0x3A)
            shentsize, shnum, shstrndx = struct.unpack(end + "HHH", fh.read(6))
            fmt = end + "IIQQQQIIQQ"
            # section header layout: name, type, flags, addr, offset, size, ...
        else:                                   # ELF32
            fh.seek(0x20)
            (shoff,) = struct.unpack(end + "I", fh.read(4))
            fh.seek(0x2E)
            shentsize, shnum, shstrndx = struct.unpack(end + "HHH", fh.read(6))
            fmt = end + "IIIIIIIIII"

        def section(idx):
            fh.seek(shoff + idx * shentsize)
            f = struct.unpack(fmt, fh.read(struct.calcsize(fmt)))
            return f[0], f[4], f[5]             # name offset, file offset, size

        _name, str_off, str_size = section(shstrndx)
        fh.seek(str_off)
        names = fh.read(str_size)

        for idx in range(shnum):
            name_idx, off, size = section(idx)
            stop = names.index(b"\x00", name_idx)
            if names[name_idx:stop].decode("latin-1") == wanted:
                fh.seek(off)
                return fh.read(size)
    return b""


# -------------------------------------------------------------------- checks
def check_provenance(extract):
    print("== A. provenance: where and how the release was built ==")
    ok = True
    found_urls = []
    for dist in ("signal-2026.9.0", "pockit-0.1.52"):
        p = pathlib.Path(extract) / (dist + ".dist-info") / "direct_url.json"
        if not p.is_file():
            continue
        try:
            doc = json.loads(p.read_text())
        except ValueError:
            print("   FAIL - %s/direct_url.json is not valid JSON" % dist)
            ok = False
            continue
        url = doc.get("url", "")
        editable = (doc.get("dir_info") or {}).get("editable")
        found_urls.append((dist, url, editable))
        print("   %-22s %s  (editable=%s)" % (dist, url, editable))
    if found_urls:
        internal = [u for _d, u, _e in found_urls if u.startswith("file:///") and "builds" in u]
        print("   %s direct_url.json exposes an absolute build-host checkout path"
              % ("PASS -" if internal else "FAIL -"))
        print("   %s the install is recorded as editable (built from a source tree, not a package)"
              % ("PASS -" if any(e for _d, _u, e in found_urls) else "FAIL -"))
        ok = ok and bool(internal) and any(e for _d, _u, e in found_urls)
    else:
        print("   FAIL - no direct_url.json in any dist-info record")
        ok = False

    cache = pathlib.Path(extract) / "signal-2026.9.0.dist-info" / "uv_cache.json"
    if cache.is_file():
        try:
            doc = json.loads(cache.read_text())
            secs = (doc.get("timestamp") or {}).get("secs_since_epoch")
        except ValueError:
            secs = None
        if secs:
            import datetime
            when = datetime.datetime.fromtimestamp(
                secs, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            print("   PASS - uv_cache.json build timestamp: %s (%s)" % (secs, when))
        else:
            print("   FAIL - uv_cache.json present but has no timestamp")
            ok = False
    else:
        print("   NOTE - no uv_cache.json in this build")

    # The PyArmor banner in the shipped sources carries the same build moment,
    # plus the licensee name the runtime was issued to.
    # Find the banner itself rather than assuming it is the first line of the
    # first file: three shipped scripts start with a shebang, so taking line 0
    # would print "#!/usr/bin/env python3" and call it a PyArmor banner.
    banner = None
    tests_dir = pathlib.Path(extract) / "tests"
    if tests_dir.is_dir():
        for p in sorted(tests_dir.rglob("*.py")):
            try:
                head = p.read_text(errors="replace").splitlines()[:5]
            except OSError:
                continue
            banner = next((ln for ln in head if ln.startswith("# Pyarmor")), None)
            if banner:
                break
    if banner:
        print("   PASS - PyArmor banner in shipped sources: %s" % banner)
    else:
        print("   NOTE - no PyArmor banner in the shipped test sources")
    return ok


def check_toolchain(binary):
    print("\n== B. toolchain: what built the binary (ELF .comment) ==")
    if not binary:
        print("   FAIL - binary not found; pass --binary /path/to/signal-pyarmor-linux-x86_64")
        return False
    try:
        comment = elf_section(binary, ".comment")
    except (OSError, ValueError, struct.error) as exc:
        print("   FAIL - cannot read .comment from %s: %s" % (binary, exc))
        return False
    text = [s.decode("latin-1") for s in comment.split(b"\x00") if s.strip()]
    for line in text:
        print("   .comment: %s" % line)
    gcc = next((t for t in text if t.startswith("GCC:")), None)
    if not gcc:
        print("   FAIL - no GCC build stamp in .comment")
        return False
    # e.g. "GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0" -> distro 18.04, gcc 7.5.0
    m = re.search(r"Ubuntu ([0-9.]+)-[^)~]*~([0-9.]+)[^)]*\)\s*([0-9.]+)", gcc)
    if not m:
        print("   NOTE - compiler stamp present but not a recognised Ubuntu release: %s" % gcc)
        return True
    version, distro = m.group(1), m.group(2)
    eol = DISTRO_EOL.get(distro)
    print("   compiler: GCC %s   distro: Ubuntu %s%s"
          % (version, distro, ("   (standard support ended %s)" % eol) if eol else ""))
    print("   PASS - the executable discloses the toolchain that produced it")

    # Attribution matters: PyInstaller's stock Linux bootloader is compiled upstream
    # on ubuntu:18.04, so a .comment stamp alone says nothing about the vendor's CI.
    try:
        text_hash = hashlib.sha256(elf_section(binary, ".text")).hexdigest()
    except (OSError, ValueError, struct.error):
        text_hash = None
    known = STOCK_BOOTLOADERS.get(text_hash) if text_hash else None
    if known:
        print("   NOTE - .text is byte-identical to PyInstaller %s's stock Linux" % known)
        print("          bootloader, which upstream builds in an ubuntu:18.04 container:")
        print("          the stamp describes that bootloader, not your own build image")
    elif text_hash:
        print("   NOTE - .text matches no stock PyInstaller bootloader: this is a custom")
        print("          build, so the stamp plausibly describes your own build image")
    return True


def check_dev_material(extract):
    print("\n== C. development material shipped in the release ==")
    root = pathlib.Path(extract)
    ok = True

    tests = sorted((root / "tests").rglob("*.py")) if (root / "tests").is_dir() else []
    def is_wrapped(p):
        # shebang scripts put the banner on line 2 or 3, so look at the head
        head = p.read_text(errors="replace").splitlines()[:5]
        return any(ln.startswith("# Pyarmor") for ln in head)

    wrapped = sum(1 for p in tests if is_wrapped(p))
    size_mb = 0.0
    if tests:
        size_mb = sum(p.stat().st_size for p in (root / "tests").rglob("*") if p.is_file()) / 1048576
    print("   tests/ tree      : %d files (%.1f MB), %d carry a PyArmor banner"
          % (len(tests), size_mb, wrapped))
    leak = (root / "tests" / "integration" / "_leak_scan.py")
    print("   %s test suite ships at all: %s%s"
          % ("PASS -" if tests else "FAIL -", len(tests), " files"
             if tests else ""))
    print("   %s every shipped test is itself obfuscated (%d/%d)"
          % ("PASS -" if wrapped == len(tests) and tests else "FAIL -", wrapped, len(tests)))
    print("   %s an internal 'leak scan' helper is part of the shipped tree: %s"
          % ("PASS -" if leak.is_file() else "NOTE -", leak.relative_to(root)))
    ok = ok and bool(tests) and wrapped == len(tests) and leak.is_file()

    dists = sorted(p.name for p in root.glob("*.dist-info"))
    print("   dist-info records: %d (report records %d)" % (len(dists), EXPECTED_DIST_INFO))
    ok = ok and bool(dists)

    runtime_root = next((p for p in root.glob("pyarmor_runtime_*") if p.is_dir()), None)
    foreign = []
    if runtime_root:
        for d in sorted(runtime_root.iterdir()):
            if d.is_dir() and d.name != HOST_PLATFORM:
                foreign.append((d.name, sum(f.stat().st_size for f in d.rglob("*") if f.is_file())))
        total = sum(b for _n, b in foreign)
        print("   platform runtimes: %s" % ", ".join(d.name for d in sorted(runtime_root.iterdir()) if d.is_dir()))
        print("   %s %d foreign-platform runtime(s) in a %s build, %.1f MB unused"
              % ("PASS -" if foreign else "FAIL -", len(foreign), HOST_PLATFORM, total / 1048576))
        ok = ok and bool(foreign)
    else:
        print("   FAIL - no pyarmor_runtime_* directory")
        ok = False

    meta = root / "signal-2026.9.0.dist-info" / "METADATA"
    if meta.is_file():
        requires = [ln.split(":", 1)[1].strip() for ln in meta.read_text(errors="replace").splitlines()
                    if ln.lower().startswith("requires-dist:")]
        build_only = [r for r in requires if r.lower().startswith(BUILD_ONLY_DEPS)]
        for dep in build_only:
            name = dep.split("=")[0].split(">")[0].split("[")[0].strip()
            collected = any(root.glob(name.replace("-", "_") + "*")) or \
                        any(root.glob(name.replace("-", "_") + "-*"))
            print("   %s declared runtime dependency '%s' - build tool, module %s"
                  % ("PASS -" if not collected else "NOTE -", dep,
                     "not collected" if not collected else "IS collected"))
        ok = ok and bool(build_only)
        pockit = [r for r in requires if r.lower().startswith("pockit")]
        if pockit:
            print("   NOTE - %s is a hard runtime dependency (an autonomous exploit harness),"
                  " not an optional extra" % pockit[0])
    else:
        print("   FAIL - no METADATA to read declared dependencies from")
        ok = False
    return ok


def main():
    extract = find_extract()
    if not extract:
        print("no extraction found - run poc/00-setup.sh first (see poc/README.md)")
        return 2
    binary = find_binary(sys.argv)
    print("F-08 focused check - build provenance and development material in the release")
    print("extraction: %s" % extract)
    print("binary    : %s\n" % (binary or "(not found)"))

    results = [
        ("provenance", check_provenance(extract)),
        ("toolchain", check_toolchain(binary)),
        ("dev material", check_dev_material(extract)),
    ]
    print("\n== summary ==")
    for label, good in results:
        print("   %s %s" % ("PASS" if good else "FAIL", label))
    n = sum(1 for _l, g in results if g)
    print("   F-08 reproduced: %d/3" % n)
    print("""
   What this shows: the distributed artefact carries the build host's checkout
   path (/builds/<group>/<project>) and the editable-install flag, the build
   timestamp, the compiler and distribution behind its bootloader (upstream's,
   when the bootloader is stock), the complete obfuscated test tree, four unused
   platform-specific PyArmor runtimes, and build-only tools declared as runtime
   dependencies. None of it is needed at run time; all of it is readable without
   executing anything.

   What it does not show: any exploitable defect. This is information exposure
   and artefact hygiene - it accelerates targeted research, leaks internal
   naming and infrastructure, and inflates both the binary and the dependency
   surface. That is why the report scores it Low (3.7) and treats it as patch
   hygiene rather than as an attack path.""")
    return 0 if n == 3 else 1


if __name__ == "__main__":
    raise SystemExit(main())
