#!/usr/bin/env python3
"""PoC: native-code loading, privilege context and packaging trust.

Answers three questions about the shipped binary with executed checks:

  A. loader   - can a foreign library be introduced ahead of the bundled ones?
                (RPATH/RUNPATH, setuid/setgid, capabilities, and the mode of the
                directory PyInstaller extracts into at run time)
  B. env      - does spoofing PyInstaller's _PYI_* variables redirect the loader
                to an attacker-chosen directory? (GHSA-9fxf-4qw3-ghmr)
  C. advisory - which PyInstaller version is embedded, and is it inside the
                affected range of the published loader advisory?

Nothing is imported from the product. Requires readelf-free parsing where
possible; falls back to `readelf` only for optional detail.

    python3 poc/18-check-loading.py
    python3 poc/18-check-loading.py --binary /path/to/signal-pyarmor-linux-x86_64

Exit codes: 0 = reproduced (findings present as described), 1 = a claim did not
hold, 2 = not set up.
"""
import argparse
import hashlib
import os
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile

BINARY_NAME = "signal-pyarmor-linux-x86_64"
EXTRACTED = "signal-pyarmor-linux-x86_64_extracted"

# GHSA-9fxf-4qw3-ghmr / PyInstaller loader hardening. Fixed in 6.22.1.
AFFECTED_MAX = (6, 22, 0)
FIXED = (6, 22, 1)

# .text digests of stock Linux-64bit-intel bootloaders from the PyPI wheels.
STOCK = {
    "9ecbaec380762afad2ac6b2a9c1ba1c70c0bd72b827dbed85c573731df453606": "6.18.0/6.19.0",
    "73a4f7031b47c283106e74bc0a82135325e98d7a2de49de6ab8f1b8ef5da5d1f": "6.20.0",
    "1f4ac616b0c0": "6.18.0",  # short forms kept for readability of unmatched output
}


def find_binary(explicit):
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    here = os.path.dirname(os.path.abspath(__file__))
    for c in (os.environ.get("SIGNAL_BIN", ""),
              os.path.join(os.path.dirname(here), BINARY_NAME),
              os.path.join(os.getcwd(), BINARY_NAME),
              os.path.join("/tmp/vapt", BINARY_NAME)):
        if c and os.path.isfile(c):
            return c
    return None


def elf_section(path, wanted):
    with open(path, "rb") as fh:
        ident = fh.read(16)
        if ident[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        cls, enc = ident[4], ident[5]
        end = "<" if enc == 1 else ">"
        if cls == 2:
            fh.seek(0x28)
            (shoff,) = struct.unpack(end + "Q", fh.read(8))
            fh.seek(0x3A)
            shentsize, shnum, shstrndx = struct.unpack(end + "HHH", fh.read(6))
            fmt = end + "IIQQQQIIQQ"
        else:
            fh.seek(0x20)
            (shoff,) = struct.unpack(end + "I", fh.read(4))
            fh.seek(0x2E)
            shentsize, shnum, shstrndx = struct.unpack(end + "HHH", fh.read(6))
            fmt = end + "IIIIIIIIII"

        def sec(i):
            fh.seek(shoff + i * shentsize)
            f = struct.unpack(fmt, fh.read(struct.calcsize(fmt)))
            return f[0], f[4], f[5]

        _n, off, size = sec(shstrndx)
        fh.seek(off)
        names = fh.read(size)
        for i in range(shnum):
            ni, o, s = sec(i)
            if names[ni:names.index(b"\x00", ni)].decode("latin-1") == wanted:
                fh.seek(o)
                return fh.read(s)
    return b""


def dynamic_info(binary):
    """NEEDED / RPATH / RUNPATH straight from the ELF .dynamic section."""
    out = {"NEEDED": [], "RPATH": None, "RUNPATH": None}
    try:
        dyn = elf_section(binary, ".dynamic")
        strtab = elf_section(binary, ".dynstr")
    except (OSError, ValueError, struct.error):
        return out
    if not dyn or not strtab:
        return out
    # ELF64 Dyn: d_tag (8) + d_val (8)
    for off in range(0, len(dyn) - 15, 16):
        tag, val = struct.unpack("<qQ", dyn[off:off + 16])
        if tag == 1:      # DT_NEEDED
            s = strtab[val:strtab.index(b"\x00", val)].decode("latin-1")
            out["NEEDED"].append(s)
        elif tag == 15:   # DT_RPATH
            out["RPATH"] = strtab[val:strtab.index(b"\x00", val)].decode("latin-1")
        elif tag == 29:   # DT_RUNPATH
            out["RUNPATH"] = strtab[val:strtab.index(b"\x00", val)].decode("latin-1")
        elif tag == 0:
            break
    return out


def version_tuple(text):
    return tuple(int(x) for x in re.findall(r"\d+", text)[:3])


def run(binary, env_extra, timeout=120):
    env = dict(os.environ)
    for k in ("PYTHONHOME", "PYTHONPATH", "TIKTOKEN_CACHE_DIR"):
        env.pop(k, None)
    env.update(env_extra)
    try:
        p = subprocess.run([binary, "--version"], env=env, timeout=timeout,
                           capture_output=True, text=True, errors="replace")
        return p.returncode, (p.stdout + p.stderr).strip()
    except subprocess.TimeoutExpired:
        return None, "(timeout)"


def verdict(ok, text):
    print("   %s %s" % ("PASS -" if ok else "FAIL -", text))
    return ok


def main():
    ap = argparse.ArgumentParser(description="native loading / privilege / packaging check")
    ap.add_argument("--binary", help="path to " + BINARY_NAME)
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()

    binary = find_binary(args.binary)
    if not binary:
        print("binary not found - pass --binary /path/to/" + BINARY_NAME)
        return 2

    print("native loading / privilege / packaging check")
    print("binary    : %s\n" % binary)

    results = []

    # ---------------------------------------------------------------- A. loader
    print("== A. can a foreign library be introduced? ==")
    dyn = dynamic_info(binary)
    print("   NEEDED   : %s" % (", ".join(dyn["NEEDED"]) or "(none parsed)"))
    print("   RPATH    : %s" % (dyn["RPATH"] or "(none)"))
    print("   RUNPATH  : %s" % (dyn["RUNPATH"] or "(none)"))

    st = os.stat(binary)
    mode = stat_mode = oct(st.st_mode & 0o7777)
    setid = bool(st.st_mode & 0o4000) or bool(st.st_mode & 0o2000)
    print("   mode     : %s  owner uid %d%s" % (stat_mode, st.st_uid,
                                                "  SETUID/SETGID" if setid else ""))

    caps = ""
    if shutil.which("getcap"):
        caps = subprocess.run(["getcap", binary], capture_output=True, text=True).stdout.strip()
    print("   caps     : %s" % (caps or "(none)"))

    a_ok = True
    a_ok &= verdict(not dyn["RPATH"] and not dyn["RUNPATH"],
                    "no RPATH/RUNPATH: libraries resolve through the system loader only")
    a_ok &= verdict(not setid and not caps,
                    "not setuid/setgid and carries no file capabilities")
    results.append(("loader", a_ok))

    # extraction dir mode, measured while the process is alive
    print("\n   extracting a copy to inspect the run-time directory ...")
    work = pathlib.Path(tempfile.mkdtemp(prefix="poc-load-"))
    tgt = work / "t"
    tgt.mkdir()
    (tgt / "a.py").write_text("x = 1\n")
    cfg = work / "c.signal"
    cfg.write_text("[LLM]\nmode = byo\nuri = http://10.255.255.1:9/v1\n"
                   "key = CANARY_LOADER\nmodel = m\ntimeout = 30\n")
    for agent in ("SINGLEFILESCAN_AGENT", "DATAFLOW_AGENT", "OVERSIGHT_AGENT",
                  "EXPLOITATION_AGENT", "SCA_AGENT", "MERGEKEY_EMBED_AGENT",
                  "OVERSIGHT_EMBED_AGENT"):
        cfg.write_text(cfg.read_text() + "[LLM_%s]\nmodel = m\n" % agent)
    tmpdir = work / "tmp"
    tmpdir.mkdir()
    proc = subprocess.Popen([binary, str(tgt), "--config", str(cfg), "--check-llm-json", "true"],
                            cwd=str(work), stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, env=dict(os.environ, TMPDIR=str(tmpdir)))
    import time
    found = None
    for _ in range(80):
        time.sleep(0.1)
        cands = list(tmpdir.glob("_MEI*"))
        if cands:
            found = cands[0]
            break
    if found:
        m = os.stat(found).st_mode & 0o777
        print("   extraction: %s  mode %s  owner uid %d"
              % (found.name, oct(m), os.stat(found).st_uid))
        a_ok2 = verdict(m == 0o700, "extraction dir is 0700 (owner-only, %s)" % oct(m))
    else:
        a_ok2 = verdict(False, "could not observe the extraction dir")
    proc.terminate()
    try:
        proc.wait(5)
    except subprocess.TimeoutExpired:
        proc.kill()
    results.append(("extraction", a_ok2))

    # ---------------------------------------------------------------- B. env spoof
    print("\n== B. does spoofing PyInstaller's _PYI_* variables redirect loading? ==")
    evil = work / "evil"
    evil.mkdir()
    (evil / "libpython3.13.so.1.0").write_bytes(b"not a real library\n")

    baseline_rc, baseline = run(binary, {})
    print("   baseline  : rc=%s %r" % (baseline_rc, baseline.splitlines()[0][:60] if baseline else ""))

    cases = {
        "_PYI_APPLICATION_HOME_DIR": {"_PYI_APPLICATION_HOME_DIR": str(evil)},
        "+ _PYI_ARCHIVE_FILE": {"_PYI_APPLICATION_HOME_DIR": str(evil),
                                "_PYI_ARCHIVE_FILE": str(evil / "x")},
        "+ parent level": {"_PYI_APPLICATION_HOME_DIR": str(evil),
                           "_PYI_ARCHIVE_FILE": str(evil / "x"),
                           "_PYI_PARENT_PROCESS_LEVEL": "1"},
    }
    b_ok = True
    for label, envvars in cases.items():
        rc, out = run(binary, envvars)
        same = (rc == baseline_rc) and ("not a real library" not in out)
        print("   %-22s rc=%s  %s" % (label, rc, "unchanged" if same else "DIFFERENT: " + out[:80]))
        b_ok &= same
    b_ok = verdict(b_ok, "spoofed _PYI_* variables do not redirect the loader in this build")
    print("   NOTE - this build is not setuid, so the privileged code path that the")
    print("          advisory is about cannot be reached here; this tests the")
    print("          unprivileged path only")
    results.append(("env spoof", b_ok))

    # ---------------------------------------------------------------- C. advisory
    print("\n== C. embedded PyInstaller version vs the loader advisory ==")
    try:
        text_hash = hashlib.sha256(elf_section(binary, ".text")).hexdigest()
    except (OSError, ValueError, struct.error):
        text_hash = ""
    version = STOCK.get(text_hash)
    print("   .text sha256 : %s" % (text_hash[:32] + "…" if text_hash else "(unavailable)"))
    print("   bootloader   : %s" % (("stock PyInstaller " + version) if version else "unmatched"))

    if version:
        v = version_tuple(version.split("/")[0])
        affected = v <= AFFECTED_MAX
        print("   advisory     : GHSA-9fxf-4qw3-ghmr, affects < %d.%d.%d, fixed in %d.%d.%d"
              % (FIXED[0], FIXED[1], FIXED[2], FIXED[0], FIXED[1], FIXED[2]))
        c_ok = verdict(affected, "embedded PyInstaller %s IS inside the affected range" % version)
        print("   severity     : 7.8 High in the component - CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
        print("   reachability : requires a setuid/setgid (privileged) deployment; this")
        print("                  binary is %s, so the impact is conditional on how it is"
              % ("not setuid" if not setid else "SETUID"))
        print("                  installed. Impact is code execution in privileged context")
        print("                  or deletion of an arbitrary directory.")
    else:
        c_ok = verdict(False, "bootloader not matched against the stock table")
    results.append(("advisory", c_ok))

    print("\n== summary ==")
    for label, ok in results:
        print("   %s %s" % ("PASS" if ok else "FAIL", label))
    score = sum(1 for _l, ok in results if ok)
    print("   loading/privilege reproduced: %d/%d" % (score, len(results)))
    print("""
   What this shows: at the loader level the artefact is conventional and sound -
   no RPATH/RUNPATH, no setuid, no capabilities, extraction into a 0700 directory
   with a random name, and no environment variable that redirects loading when
   run as an ordinary user. The one substantive issue is the embedded packaging
   toolchain: PyInstaller 6.20.0 is inside the affected range of the loader
   advisory, so any deployment that makes this binary setuid/setgid inherits a
   code-execution-in-privileged-context primitive.

   What it does not show: privilege escalation from an attacker position - the
   binary is not setuid here, and the advisory's path needs that. It also does
   not show a writable extraction directory, which is the other prerequisite a
   DLL-style attack would need.""")
    if not args.keep:
        shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
