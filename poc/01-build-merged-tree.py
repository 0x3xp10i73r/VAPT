"""Build a merged import tree for the PyInstaller extraction.

PyInstaller splits a package across two locations: binary extension modules
keep their package-relative path at the CArchive root (e.g. numpy/_core/*.so,
faiss/*.so), while the pure-Python modules live inside the extracted PYZ.
Both halves must be visible under one directory for the package to import.

The merge is therefore RECURSIVE: whenever a directory name exists in both
trees, a real directory is created in OUT and both sides are merged into it.
Nothing is ever written into the source tree - every leaf in OUT is a symlink
pointing back at the extraction.
"""
import os
import shutil
from pathlib import Path

X = Path(os.environ.get("SIGNAL_EXTRACT",
    "/tmp/vapt/signal-pyarmor-linux-x86_64_extracted"))
PYZ = X / "PYZ.pyz_extracted"
OUT = Path(os.environ.get("MERGED_OUT", "/tmp/vapt/merged"))


def merge(src_a, src_b, dst):
    """Populate real directory `dst` from the union of `src_a` and `src_b`."""
    dst.mkdir(parents=True, exist_ok=True)
    names = sorted({e.name for e in src_a.iterdir()} | {e.name for e in src_b.iterdir()})
    for name in names:
        a, b = src_a / name, src_b / name
        da, db = a.is_dir() and not a.is_symlink(), b.is_dir() and not b.is_symlink()
        if da and db:
            merge(a, b, dst / name)          # both sides have a directory: recurse
        else:
            leaf = a if a.exists() else b    # otherwise prefer whichever exists
            target = (a if a.exists() else b)
            os.symlink(target, dst / name)


if OUT.exists():
    shutil.rmtree(OUT)
OUT.mkdir()

# The CArchive root also contains PYZ.pyz itself and the extracted PYZ tree;
# skip the latter (it is layered in explicitly) but keep everything else.
root_names = [e for e in sorted(X.iterdir()) if e.name != "PYZ.pyz_extracted"]
for e in root_names:
    src_b = PYZ / e.name
    if e.is_dir() and src_b.is_dir():
        merge(e, src_b, OUT / e.name)
    else:
        os.symlink(e, OUT / e.name)

# PYZ-only entries (no counterpart at the CArchive root)
have = {e.name for e in X.iterdir()}
for e in sorted(PYZ.iterdir()):
    if e.name in have and e.name != "PYZ.pyz_extracted":
        continue
    os.symlink(e, OUT / e.name)

print(f"merged entries at top level: {len(list(OUT.iterdir()))}")
for probe in ("numpy/_core", "numpy/_core/_exceptions.pyc", "numpy/__init__.pyc", "faiss", "tiktoken"):
    p = OUT / probe
    if p.is_dir():
        print(f"  {probe}: dir with {len(list(p.iterdir()))} entries")
    elif p.exists():
        print(f"  {probe}: present ({p.stat().st_size} bytes)")
    else:
        print(f"  {probe}: MISSING")
