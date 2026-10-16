"""Dump every string constant and identifier reachable from the protected modules.

All PyArmor-protected product modules import through the runtime that ships
inside the binary, with no licence file and no vendor tooling, so their
function metadata is readable at runtime. This writes a per-module dump plus a
flat list for searching.
"""
import importlib
import io
import dis
import os
import sys
import types
from pathlib import Path

OUT = Path(os.environ.get("ANALYSIS_OUT", "/tmp/vapt/analysis"))
OUT.mkdir(exist_ok=True)
PRODUCT = Path(os.environ.get(
    "SIGNAL_EXTRACT", "/tmp/vapt/signal-pyarmor-linux-x86_64_extracted"))
os.chdir("/tmp/vapt")
sys.setrecursionlimit(30000)

importlib.import_module("numpy")  # warm the numeric stack once

TARGETS = []
for sub in ("", "agents", "prompts", "scans", "utils", "utils/estimator", "tests"):
    d = PRODUCT / sub if sub else PRODUCT
    if not d.is_dir():
        continue
    for f in sorted(d.glob("*.py")):
        if f.name.startswith("__"):
            continue
        TARGETS.append((f"{sub.replace('/', '.')}." if sub else "") + f.stem)

DETAIL = io.StringIO()
FLAT = []
seen = set()
stats = []


def harvest(co, path, depth=0):
    if depth > 14 or id(co) in seen:
        return
    seen.add(id(co))
    for c in co.co_consts:
        if isinstance(c, str) and len(c) > 1:
            FLAT.append((path, "STR", c))
        elif isinstance(c, (bytes, bytearray)):
            try:
                s = c.decode("utf-8")
                if s.isprintable() and len(s) > 3:
                    FLAT.append((path, "BYTES", s))
            except Exception:
                pass
    for n in co.co_names:
        if n and not n.startswith("C_"):
            FLAT.append((path, "NAME", n))
    for c in co.co_consts:
        if hasattr(c, "co_consts"):
            harvest(c, f"{path}.{getattr(c, 'co_name', '?')}", depth + 1)


def harvest_obj(o, path, depth=0):
    if depth > 5:
        return
    if isinstance(o, types.FunctionType):
        for c in (o.__defaults__ or ()):
            if isinstance(c, str) and len(c) > 1:
                FLAT.append((path, "DEFAULT", c))
        harvest(o.__code__, path)
    elif isinstance(o, (staticmethod, classmethod)):
        harvest_obj(o.__func__, path, depth + 1)
    elif isinstance(o, property):
        for f in (o.fget, o.fset, o.fdel):
            harvest_obj(f, path + ".prop", depth + 1)
    elif isinstance(o, type):
        for k, v in vars(o).items():
            harvest_obj(v, f"{path}.{k}", depth + 1)


for name in TARGETS:
    mod = importlib.import_module(name)
    before = len(FLAT)
    for k, v in vars(mod).items():
        harvest_obj(v, f"{name}.{k}")
        if isinstance(v, str) and len(v) > 1:
            FLAT.append((name, "MODULE_ATTR", v))
    stats.append((name, len(FLAT) - before))

for path, kind, value in FLAT:
    DETAIL.write(f"{kind}\t{path}\t{value.replace(chr(10), chr(92) + 'n')}\n")
(OUT / "protected_harvest.tsv").write_text(DETAIL.getvalue(), encoding="utf-8")

print(f"{'module':46s} entries")
print("-" * 60)
for n, c in sorted(stats, key=lambda r: -r[1]):
    print(f"{n:46s} {c}")
print("-" * 60)
print(f"total harvested entries: {len(FLAT)}")
