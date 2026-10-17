"""Locate the reconstructed CPython host built by poc/00-setup.sh.

Several checks have to run on the interpreter that ships inside the binary:
`utils.html_preview` and its peers are armoured, `dis` cannot read 3.13
bytecode from a 3.11 interpreter, and the bundled `ssl` reports the stack that
is actually under test. Running them with a system `python3` therefore fails in
ways that look like bugs in the check.

`ensure()` removes that trap: if a host build is present, the script re-executes
itself on it. If it is not, the script carries on and fails with its own message.

`$WORK` is only defined in the shell that ran 00-setup.sh, and a shell without
it expands `$WORK/py313host` to `/py313host`, so the search also covers the
checkout the script lives in, the current directory, and /tmp/vapt.
"""
import os
import sys

#: set in the child environment so a failed re-exec cannot loop
MARKER = "_POC_HOST_REEXEC"


def find_host():
    """Return (py313host, pyhome, merged, base_library) or None."""
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = []
    if os.environ.get("WORK"):
        candidates.append(os.environ["WORK"])
    candidates += [os.path.dirname(here), os.getcwd(), "/tmp/vapt"]

    for root in candidates:
        host = os.path.join(root, "py313host")
        home = os.path.join(root, "pyhome")
        merged = os.path.join(root, "merged")
        bl = os.path.join(root, "signal-pyarmor-linux-x86_64_extracted",
                          "base_library.zip")
        if (os.path.isfile(host) and os.access(host, os.X_OK)
                and os.path.isdir(home) and os.path.isdir(merged)
                and os.path.isfile(bl)):
            return host, home, merged, bl
    return None


def ensure(script_file, quiet=False):
    """Re-exec `script_file` on the reconstructed host, if one can be found.

    Returns True if the process was replaced (never returns) or False when the
    caller should continue on the current interpreter.
    """
    if os.environ.get(MARKER):
        return False                     # already on the host; do not loop
    found = find_host()
    if not found:
        return False
    host, home, merged, bl = found
    # Already on it? py313host leaves sys.executable empty, so the reliable
    # signal is that PYTHONHOME already points at the host's pyhome.
    if os.path.realpath(os.environ.get("PYTHONHOME") or "") == os.path.realpath(home):
        return False
    env = dict(os.environ)
    env["PYTHONHOME"] = home
    env["PYTHONPATH"] = merged + os.pathsep + bl
    env[MARKER] = "1"
    if not quiet:
        print("running on the reconstructed host (%s)" % host)
        print("   PYTHONHOME=%s" % home)
        print("   PYTHONPATH=%s" % env["PYTHONPATH"])
        print()
        sys.stdout.flush()
    try:
        os.execve(host, [host, os.path.abspath(script_file)] + sys.argv[1:], env)
    except OSError as exc:
        print("could not start %s: %s" % (host, exc))
        return False
    return True
