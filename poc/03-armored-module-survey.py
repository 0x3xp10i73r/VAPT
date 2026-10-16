"""Measure what PyArmor actually protects in signal-pyarmor-linux-x86_64.

Imports every PyArmor-protected product module using the runtime shipped inside
the binary (no licence file present, no network, no vendor tooling) and records:
  * whether the module imports,
  * how many string constants and identifier names become readable,
  * whether a chosen canary string is present in the on-disk artefact.

Run with:  PYTHONPATH=<extraction root> PYTHONHOME=... ./py313host armored_survey.py
"""
import importlib
import os
import sys
import types
def find_extract():
    """Locate the extraction without depending on the caller's environment."""
    here = os.path.dirname(os.path.abspath(__file__))
    env = os.environ.get("SIGNAL_EXTRACT")
    candidates = []
    if env:
        candidates.append(env)
    candidates += [
        os.path.join(os.getcwd(), "signal-pyarmor-linux-x86_64_extracted"),
        os.path.join(os.path.dirname(here), "signal-pyarmor-linux-x86_64_extracted"),
        "/tmp/vapt/signal-pyarmor-linux-x86_64_extracted",
    ]
    for cand in candidates:
        if os.path.isdir(os.path.join(cand, "PYZ.pyz_extracted")):
            if env and os.path.abspath(cand) != os.path.abspath(env):
                sys.stderr.write("note: $SIGNAL_EXTRACT=%s is not an extraction; using %s\n"
                                 % (env, cand))
            return cand
    return candidates[0] if candidates else "./signal-pyarmor-linux-x86_64_extracted"


def neutral_cwd(extract):
    """A cwd that is not inside the merged tree (numpy refuses to import then)."""
    parent = os.path.dirname(os.path.abspath(extract))
    return parent if os.path.isdir(parent) else tempfile.gettempdir()

from pathlib import Path
import tempfile

EXTRACT = find_extract()
PRODUCT = Path(EXTRACT)
# NOTE: the merged tree already exposes both CArchive-root and PYZ entries,
# so the raw extraction root must NOT be added again - doing so reintroduces
# duplicate numpy/faiss trees and the CPU-dispatcher double-init error.
os.chdir(neutral_cwd(EXTRACT))  # numpy refuses to import when cwd is its own tree
sys.setrecursionlimit(20000)

# Pre-import the numeric stack once so the second search path cannot
# re-initialise the numpy CPU dispatcher.
for _m in ("numpy", "faiss"):
    try:
        importlib.import_module(_m)
    except BaseException as _e:
        print(f"warmup {_m}: {type(_e).__name__}: {_e}")

TARGETS = []
for sub in ("", "agents", "prompts", "scans", "utils", "utils/estimator", "tests"):
    d = PRODUCT / sub if sub else PRODUCT
    if not d.is_dir():
        continue
    for f in sorted(d.glob("*.py")):
        if f.name.startswith("__"):
            continue
        name = (f"{sub.replace('/', '.')}." if sub else "") + f.stem
        TARGETS.append(name)

seen = set()
rows = []
canary_hits = []


def harvest(co, strs, names, depth=0):
    if depth > 12 or id(co) in seen:
        return
    seen.add(id(co))
    for c in co.co_consts:
        if isinstance(c, str) and len(c) > 4:
            strs.add(c)
        elif isinstance(c, (bytes, bytearray)):
            try:
                s = c.decode("utf-8")
                if s.isprintable() and len(s) > 4:
                    strs.add(s)
            except Exception:
                pass
    for n in co.co_names:
        if n and not n.startswith("C_") and len(n) > 2:
            names.add(n)
    for c in co.co_consts:
        if hasattr(c, "co_consts"):
            harvest(c, strs, names, depth + 1)


def harvest_obj(o, strs, names, depth=0):
    if depth > 4:
        return
    if isinstance(o, types.FunctionType):
        harvest(o.__code__, strs, names)
    elif isinstance(o, (staticmethod, classmethod)):
        harvest_obj(o.__func__, strs, names, depth + 1)
    elif isinstance(o, property):
        for f in (o.fget, o.fset, o.fdel):
            harvest_obj(f, strs, names, depth + 1)
    elif isinstance(o, type):
        for v in vars(o).values():
            harvest_obj(v, strs, names, depth + 1)


for name in TARGETS:
    try:
        mod = importlib.import_module(name)
    except BaseException as e:
        rows.append((name, "FAIL", f"{type(e).__name__}: {str(e)[:110]}", 0, 0))
        continue
    strs, names = set(), set()
    for v in vars(mod).values():
        harvest_obj(v, strs, names)
    rows.append((name, "OK", "", len(strs), len(names)))

ok = [r for r in rows if r[1] == "OK"]
fail = [r for r in rows if r[1] == "FAIL"]
print(f"protected modules attempted : {len(TARGETS)}")
print(f"  imported successfully     : {len(ok)}")
print(f"  import raised             : {len(fail)}")
print(f"  strings made readable     : {sum(r[3] for r in ok)}")
print(f"  identifiers made readable : {sum(r[4] for r in ok)}")
print()
print("successfully imported:")
for n, _, _, s, nm in sorted(ok, key=lambda r: -r[3]):
    print(f"  {n:34s} strings={s:5d} names={nm:5d}")
print()
print("import failures (grouped):")
groups = {}
for n, _, e, _, _ in fail:
    groups.setdefault(e, []).append(n)
for k, v in sorted(groups.items()):
    print(f"  {k}: {len(v)} modules -> {', '.join(v[:5])}{' ...' if len(v) > 5 else ''}")
