"""Compare every security-relevant bundled version against its advisory range.

Reads the versions the reconstructed runtime actually loads, then evaluates each
published affected-range / fixed-version boundary recorded during the assessment.

    PYTHONHOME=<pyhome> PYTHONPATH=<merged> ./py313host 09-check-advisory-ranges.py
"""
import importlib
import sys

RANGES = [
    # (component, advisory, affected predicate, fixed version)
    ("urllib3", "CVE-2026-97689 (High 8.6, unbounded chunked-size buffering)",
     lambda v: v < (2, 8, 0), "2.8.0"),
    ("urllib3", "CVE-2026-97688 (Med 5.3, Deflate decoder infinite loop)",
     lambda v: (2, 6, 2) <= v < (2, 8, 0), "2.8.0"),
    ("cryptography", "CVE-2026-69249 (High 8.7, exponential path building)",
     lambda v: (42, 0, 0) <= v < (49, 0, 0), "49.0.0"),
    ("cryptography", "CVE-2026-69247 (High 8.2, PKCS#7 Bleichenbacher oracle)",
     lambda v: (44, 0, 0) <= v < (50, 0, 0), "50.0.0"),
    ("cryptography", "CVE-2026-69248 (Med 6.9, wildcard DNS in permittedSubtrees)",
     lambda v: (45, 0, 0) <= v < (49, 0, 0), "49.0.0"),
    ("langgraph-sdk", "CVE-2026-104873 (High 7.6, auth decorators ignore `actions`)",
     lambda v: (0, 1, 45) <= v < (0, 4, 4), "0.4.4"),
    ("aiohttp", "CVE-2026-34513 / -22815 / -34514..-34517",
     lambda v: v < (3, 13, 4), "3.13.4"),
]


def nums(text):
    out = []
    for part in text.split(".")[:3]:
        digits = "".join(c for c in part if c.isdigit())
        out.append(int(digits) if digits else 0)
    return tuple(out + [0] * (3 - len(out)))


def bundled(name):
    """Prefer installed metadata; fall back to the module's own __version__.

    The frozen bundle does not ship a distribution record for every component,
    so a missing dist-info must not be read as "component absent"."""
    try:
        from importlib.metadata import PackageNotFoundError, version

        try:
            return version(name)
        except PackageNotFoundError:
            pass
    except BaseException:
        pass
    try:
        return getattr(importlib.import_module(name.replace("-", "_")), "__version__", None)
    except BaseException:
        return None


def main():
    print("%-16s %-10s %-18s %s" % ("component", "bundled", "in affected range", "advisory"))
    print("-" * 108)
    hits = 0
    for name, advisory, predicate, fixed in RANGES:
        v = bundled(name)
        if v is None:
            print("%-16s %-10s %-18s %s (fixed in %s)" % (name, "-", "UNKNOWN", advisory, fixed))
            continue
        affected = predicate(nums(v))
        hits += affected
        print("%-16s %-10s %-18s %s%s" % (
            name, v, "YES" if affected else "no", advisory,
            "" if affected else "  (fixed in %s)" % fixed))
    print("-" * 108)
    print("bundled components inside a published affected range: %d" % hits)
    return 0


if __name__ == "__main__":
    sys.exit(main())
