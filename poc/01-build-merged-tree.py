"""Build a merged import tree for the PyInstaller extraction.

PyInstaller splits a package across two locations: binary extension modules
keep their package-relative path at the CArchive root (e.g. numpy/_core/*.so,
faiss/*.so), while the pure-Python modules live inside the extracted PYZ.
Both halves must be visible under one directory for the package to import.

The merge is therefore RECURSIVE: whenever a directory name exists in both
trees, a real directory is created in OUT and both sides are merged into it.
Nothing is ever written into the source tree - every leaf in OUT is a link
pointing back at the extraction.

Leaf strategy, in order of preference: symlink, then hard link, then copy.
Symlinks are cheapest and are the default on POSIX; hard links cost no space
and need no privileges on NTFS; a copy is the last resort for filesystems that
support neither (or when MERGE_LINK=copy is set). MERGE_LINK=hardlink forces
the second strategy. The strategy used is printed at the end.

Environment:
    SIGNAL_EXTRACT  extraction directory (default: $SIGNAL_EXTRACT, else
                    ./signal-pyarmor-linux-x86_64_extracted, else next to this script)
    MERGED_OUT      output directory (default: <extraction>/../merged)
    MERGE_LINK      symlink | hardlink | copy
"""
import os
import shutil
import sys
from pathlib import Path


def find_extract():
    """Locate the extraction without depending on the caller's environment."""
    here = Path(__file__).resolve().parent
    if len(sys.argv) > 1:
        return Path(sys.argv[1]).expanduser()
    env = os.environ.get("SIGNAL_EXTRACT")
    if env:
        return Path(env).expanduser()
    candidates = [
        Path.cwd() / "signal-pyarmor-linux-x86_64_extracted",
        here.parent / "signal-pyarmor-linux-x86_64_extracted",       # repo root
        Path("/tmp/vapt/signal-pyarmor-linux-x86_64_extracted"),     # assessment default
    ]
    for cand in candidates:
        if cand.is_dir():
            return cand
    return candidates[0]


X = find_extract()
PYZ = X / "PYZ.pyz_extracted"
OUT = Path(os.environ.get("MERGED_OUT") or (X.parent / "merged")).expanduser()
LINK_MODE = os.environ.get("MERGE_LINK", "").strip().lower() or None
USED = set()


def expose(src, dst):
    """Make `src` visible at `dst` using the best available strategy."""
    if LINK_MODE in (None, "symlink"):
        try:
            os.symlink(src, dst)
            USED.add("symlink")
            return
        except (OSError, NotImplementedError) as exc:
            if LINK_MODE == "symlink":
                raise SystemExit(f"symlink refused by the filesystem: {exc}")
    if LINK_MODE in (None, "hardlink"):
        try:
            os.link(src, dst)
            USED.add("hardlink")
            return
        except (OSError, NotImplementedError) as exc:
            if LINK_MODE == "hardlink":
                raise SystemExit(f"hard link refused by the filesystem: {exc}")
    if src.is_dir():
        shutil.copytree(src, dst, symlinks=True)
    else:
        shutil.copy2(src, dst)
    USED.add("copy")


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
            expose(target, dst / name)


if not X.is_dir():
    raise SystemExit(
        "extraction directory not found: %s\n"
        "\n"
        "Run poc/00-setup.sh first (it creates everything in one step), or point\n"
        "at the directory pyinstxtractor-ng produced, either as an argument:\n"
        "\n"
        "    python3 poc/01-build-merged-tree.py ~/vapt/signal-pyarmor-linux-x86_64_extracted\n"
        "\n"
        "or through the environment:\n"
        "\n"
        "    export SIGNAL_EXTRACT=$HOME/vapt/signal-pyarmor-linux-x86_64_extracted\n"
        % X)

if OUT.exists():
    shutil.rmtree(OUT)
OUT.mkdir(parents=True, exist_ok=True)       # mkdir -p: OUT's parent may not exist

# The CArchive root also contains PYZ.pyz itself and the extracted PYZ tree;
# skip the latter (it is layered in explicitly) but keep everything else.
root_names = [e for e in sorted(X.iterdir()) if e.name != "PYZ.pyz_extracted"]
for e in root_names:
    src_b = PYZ / e.name
    if e.is_dir() and src_b.is_dir():
        merge(e, src_b, OUT / e.name)
    else:
        expose(e, OUT / e.name)

# PYZ-only entries (no counterpart at the CArchive root)
have = {e.name for e in X.iterdir()}
for e in sorted(PYZ.iterdir()):
    if e.name in have and e.name != "PYZ.pyz_extracted":
        continue
    expose(e, OUT / e.name)

print(f"merged entries at top level: {len(list(OUT.iterdir()))}")
print(f"leaf strategy: {', '.join(sorted(USED)) or 'none'}")
for probe in ("numpy/_core", "numpy/_core/_exceptions.pyc", "numpy/__init__.pyc", "faiss", "tiktoken"):
    p = OUT / probe
    if p.is_dir():
        print(f"  {probe}: dir with {len(list(p.iterdir()))} entries")
    elif p.exists():
        print(f"  {probe}: present ({p.stat().st_size} bytes)")
    else:
        print(f"  {probe}: MISSING")
