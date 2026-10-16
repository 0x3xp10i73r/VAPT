#!/usr/bin/env python3
"""
memscan.py — search a live process's memory for a string (region-by-region).

Used for MANUAL verification of CHK-05 (API key in cleartext process memory,
incl. the ready-to-send 'Authorization: Bearer <key>' form).

Usage:
  sudo python3 memscan.py <pid> <needle> [needle2 ...]

Example (while the stalled scan from MANUAL-VERIFICATION.md is running):
  sudo python3 memscan.py 4242 sk-poc-manual-memkey

Reads /proc/<pid>/maps, then each readable, non-special region from
/proc/<pid>/mem, printing every match offset + a short context snippet.
Run as root (or as a direct ancestor of the target under ptrace_scope=1).

For AUTHORIZED testing only, on systems you control.
"""
import re
import sys


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    pid, needles = sys.argv[1], [n.encode() for n in sys.argv[2:]]
    maps = open("/proc/%s/maps" % pid).read().splitlines()
    mem = open("/proc/%s/mem" % pid, "rb", 0)
    regions = 0
    for line in maps:
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+) \S+ \S+ \S+\s*(.*)", line)
        if not m:
            continue
        lo, hi, perms, path = int(m.group(1), 16), int(m.group(2), 16), m.group(3), m.group(4)
        if "r" not in perms or (path and path.startswith("/dev/")) or "[v" in line:
            continue  # unreadable / device / vdso-vvar
        try:
            mem.seek(lo)
            buf = mem.read(hi - lo)
        except OSError:
            continue
        regions += 1
        for n in needles:
            start = 0
            while True:
                i = buf.find(n, start)
                if i < 0:
                    break
                ctx = buf[max(0, i - 25):i + len(n) + 10]
                clean = "".join(chr(b) if 32 <= b < 127 else "." for b in ctx)
                print("pid %s  0x%x  ...%s..." % (pid, lo + i, clean))
                start = i + 1
    print("scanned %d readable regions in pid %s" % (regions, pid))


if __name__ == "__main__":
    main()
