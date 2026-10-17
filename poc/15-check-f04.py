"""PoC-F04 (focused): the bundled TLS stack is OpenSSL 3.0.16 - outdated.

Checks the three things F-04 actually claims, and prints PASS/FAIL for each:

  A. what ships     - every OpenSSL build in the extracted archive, with the file
                      it lives in (the interpreter's is baked into libpython3.13,
                      a second one ships inside psycopg2's vendored libs)
  B. what runs      - the interpreter's own `ssl` module, executed: version and
                      the TLS defaults a connection actually gets
  C. advisories     - the shipped version against the fixed-version boundary of
                      each published 3.0.x advisory in the report's table

Run it through the reconstructed host, because check B has to ask the bundled
runtime, not your system Python:

    export PYTHONHOME=<work>/pyhome
    export PYTHONPATH=<work>/merged:<work>/<extract>/base_library.zip
    <work>/py313host poc/15-check-f04.py

Exit codes: 0 = every claim reproduced, 1 = a claim failed, 2 = not set up.

What this does NOT show, and the report says so in the same words: that any of
these CVEs is reachable from the CLI. The High-severity ones are in CMS,
PKCS#12 and PKCS#7 parsing; Python's `ssl` module exposes TLS only and the CLI
does not parse those formats through it. This is an outdated-component and
patch-management finding - a security margin that has been spent, not a proven
exploit path.
"""
import os
import pathlib
import re
import ssl
import sys

# The 3.0.x line's newest patch release at the time of the assessment
# (2026-10-16). Patch levels move: re-check before quoting "N behind".
LATEST_30 = (3, 0, 21)

# Advisory snapshot from the report's F-04 table. Each row is a published issue
# with the vendor's fixed-version boundary in the 3.0.x line (and 3.5.x for the
# separately vendored build). "In range" = shipped version < fixed version.
ADVISORIES = [
    # CVE,                severity,  summary,                                        fixed 3.0.x, fixed 3.5.x
    ("CVE-2025-15467", "High", "stack buffer overflow, CMS AuthEnvelopedData AEAD parameters", (3, 0, 19), (3, 5, 5)),
    ("CVE-2025-9230", "Moderate", "out-of-bounds read/write, RFC 3211 KEK unwrap", (3, 0, 18), (3, 5, 4)),
    ("CVE-2025-9232", "Low", "out-of-bounds read, HTTP client no_proxy handling", (3, 0, 18), (3, 5, 4)),
    ("CVE-2025-69419", "Moderate", "PKCS#12 / PKCS#7 parsing fault", (3, 0, 19), (3, 5, 5)),
    ("CVE-2025-69420", "Low", "PKCS#12 / PKCS#7 parsing fault", (3, 0, 19), (3, 5, 5)),
    ("CVE-2025-69421", "Low", "PKCS#12 / PKCS#7 parsing fault", (3, 0, 19), (3, 5, 5)),
    ("CVE-2026-42767", "Moderate", "FFC-DH peer validation", (3, 0, 21), (3, 5, 7)),
]

BANNER = re.compile(rb"OpenSSL ([0-9]+)\.([0-9]+)\.([0-9]+) ([0-9]{1,2} [A-Z][a-z]{2} [0-9]{4})")


def find_extract():
    import os
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


def vstr(v):
    return ".".join(str(x) for x in v)


def scan_builds(root):
    """Every OpenSSL version banner in the archive, attributed to its file."""
    found, seen = [], set()
    root = pathlib.Path(root)
    for path in sorted(root.rglob("*")):
        try:
            if not path.is_file() or path.is_symlink() or path.stat().st_size < 4096:
                continue
            if path.suffix == ".pyc":
                continue
            depth = len(path.relative_to(root).parts)
            if depth > 3:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        m = BANNER.search(data)
        if not m:
            continue
        key = path.resolve()
        if key in seen:
            continue
        seen.add(key)
        found.append((str(path.relative_to(root)), (int(m.group(1)), int(m.group(2)), int(m.group(3))),
                      m.group(4).decode()))
    return found


def check_builds(extract):
    print("== A. what ships: every OpenSSL build in the archive ==")
    builds = scan_builds(extract)
    if not builds:
        print("   FAIL - no OpenSSL banners found under %s" % extract)
        return None, None, False
    for rel, v, date in builds:
        print("   %-52s OpenSSL %s %s" % (rel, vstr(v), date))

    interp = [b for b in builds if "libpython" in b[0]]
    pg = [b for b in builds if "psycopg2" in b[0]]
    print()
    ok = True
    if interp:
        print("   PASS - the interpreter's TLS stack is statically linked inside %s: %s"
              % (interp[0][0], vstr(interp[0][1])))
    else:
        print("   FAIL - no OpenSSL banner in libpython - cannot attribute the TLS stack")
        ok = False
    if pg:
        print("   PASS - a second, independent build ships in %s: %s (psycopg2 / --cache-database only)"
              % (pg[0][0], vstr(pg[0][1])))
    else:
        print("   NOTE - no separately vendored psycopg2 OpenSSL build found in this tree")
    return (interp[0][1] if interp else None), (pg[0][1] if pg else None), ok


def check_runtime(interp_version):
    print("\n== B. what runs: the bundled interpreter's own ssl module ==")
    print("   interpreter: Python %s" % sys.version.split()[0])
    print("   ssl        : %s" % ssl.OPENSSL_VERSION)
    print("   ssl info   : %s" % (ssl.OPENSSL_VERSION_INFO,))

    # Parsed from the version string, not the tuple: this build reports
    # OPENSSL_VERSION_INFO = (3, 0, 0, 16, 0), which is not the usual
    # (major, minor, fix, patch, status) layout. The string is authoritative.
    m = re.search(r"OpenSSL (\d+)\.(\d+)\.(\d+)", ssl.OPENSSL_VERSION)
    runtime = tuple(int(x) for x in m.groups()) if m else None
    if runtime is None:
        print("   FAIL - cannot parse %r" % ssl.OPENSSL_VERSION)
        return False
    if interp_version is None:
        print("   FAIL - nothing to compare the runtime figure against")
        return False
    if runtime != interp_version:
        print("   FAIL - this script is not running under the reconstructed host:")
        print("          it reports %s, but the archive's libpython carries %s."
              % (vstr(runtime), vstr(interp_version)))
        print("          Run it through py313host (see the docstring).")
        return False
    print("   PASS - the running interpreter reports the version found in the archive")

    # Not everything is wrong here: the defaults are correct, and the report
    # records that as a control that behaved correctly.
    ctx = ssl.create_default_context()
    defaults = {
        "verify_mode = CERT_REQUIRED": ctx.verify_mode == ssl.CERT_REQUIRED,
        "check_hostname = True": ctx.check_hostname is True,
        "minimum_version >= TLS 1.2": ctx.minimum_version >= ssl.TLSVersion.TLSv1_2,
    }
    for label, good in defaults.items():
        print("   %s TLS default: %s" % ("PASS" if good else "FAIL", label))
    return all(defaults.values())


def check_advisories(v30, v35):
    print("\n== C. advisories: shipped versions vs the fixed-version boundaries ==")
    if v30 is None:
        print("   FAIL - no 3.0.x build to evaluate")
        return False
    lag = LATEST_30[2] - v30[2]
    print("   shipped 3.0.x: %s   newest 3.0.x at assessment time: %s   -> %d patch release(s) behind"
          % (vstr(v30), vstr(LATEST_30), lag))
    print()
    print("   %-15s %-9s %-9s %-11s %s" % ("CVE", "severity", "fixed 3.0.x", "3.0.16", "fixed 3.5.x / 3.5.4"))
    in_range = 0
    for cve, sev, _summary, f30, f35 in ADVISORIES:
        hit30 = v30 < f30
        verdict35 = "in range" if (v35 is not None and v35 < f35) else ("fixed" if v35 else "n/a")
        if hit30:
            in_range += 1
        print("   %-15s %-9s %-11s %-11s %s %s" % (cve, sev, vstr(f30),
                                                   "IN RANGE" if hit30 else "fixed",
                                                   vstr(f35), verdict35))
    print()
    print("   %s %d of %d advisories list %s inside their affected range"
          % ("PASS" if in_range == len(ADVISORIES) else "FAIL", in_range, len(ADVISORIES), vstr(v30)))
    print("   %s %s is behind %s (%d patch releases)"
          % ("PASS" if lag > 0 else "FAIL", vstr(v30), vstr(LATEST_30), lag))
    high = [a for a in ADVISORIES if a[1] == "High" and v30 < a[3]]
    if high:
        print("   NOTE - highest-severity item in range: %s (%s)" % (high[0][0], high[0][2]))
    return in_range == len(ADVISORIES) and lag > 0


def main():

    # Run on the reconstructed CPython host when one is available: these checks need
    # the bundled interpreter (armoured modules, 3.13 bytecode, the shipped ssl).
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        import _host
        _host.ensure(__file__)
    except ImportError:
        pass

    extract = find_extract()
    if not extract:
        print("no extraction found - run poc/00-setup.sh first (see poc/README.md)")
        return 2
    print("F-04 focused check - bundled OpenSSL is outdated")
    print("extraction: %s\n" % extract)

    v30, v35, builds_ok = check_builds(extract)
    runtime_ok = check_runtime(v30)
    advisories_ok = check_advisories(v30, v35)

    results = [("builds", builds_ok), ("runtime", runtime_ok), ("advisories", advisories_ok)]
    print("\n== summary ==")
    for label, ok in results:
        print("   %s %s" % ("PASS" if ok else "FAIL", label))
    n = sum(1 for _, ok in results if ok)
    print("   F-04 reproduced: %d/3" % n)
    print("""
   What this shows: the archive carries OpenSSL 3.0.16, five patch releases
   behind the 3.0.x line, and every advisory in the report's table has its
   fixed-version boundary above it - so the whole backlog ships with the tool.
   That backlog is what an outdated component means; it is not an exploit.

   What it does not show: that any of these CVEs is reachable from the CLI. The
   High-severity ones are in CMS/PKCS#12/PKCS#7 parsing and OpenSSL's HTTP
   client; Python's ssl module exposes TLS only, and the CLI does not parse
   those formats through it. No proof-of-concept for a specific CVE is included
   or claimed. The score in the report (Medium, 5.6) reflects that constraint -
   the finding is patch hygiene and a spent security margin.

   Adjust LATEST_30 and the ADVISORIES table if you are reading this much later
   than 2026-10-16: advisory data ages faster than the binary does.""")
    return 0 if n == 3 else 1


if __name__ == "__main__":
    raise SystemExit(main())
