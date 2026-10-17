"""Disassemble a module (or one function/class inside it) from an extracted .pyc.

Useful because `pockit` - the only package in the artefact that is NOT wrapped in
PyArmor - ships as plain bytecode, so its logic can be read directly. Works with
the system Python 3 for pockit's modules; PyArmor-wrapped product modules can
only be read through the reconstructed 3.13 host (see 02-rebuild-cpython-host.c)
and are covered by 03/04/10.

    python3 12-disassemble-pyc.py pockit/agents/shared_tools.pyc run_shell
    python3 12-disassemble-pyc.py pockit/__main__.pyc

Arguments:
    <pyc path> [name]   name = a function or class to disassemble; omit for the
                        whole module. Relative paths are looked up under
                        $SIGNAL_EXTRACT/PYZ.pyz_extracted/.
"""
import dis
import io
import marshal
import os
import sys


def find_extract():
    """Locate the extraction: argument, $SIGNAL_EXTRACT, cwd, repo root, assessment default."""
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


def no_extract_message(ex):
    return (
        "extraction directory not found: %s\n"
        "\n"
        "Run poc/00-setup.sh first (it creates it), or pass the directory\n"
        "pyinstxtractor-ng produced, either as an argument or through the\n"
        "SIGNAL_EXTRACT environment variable.\n"
        % ex)

EX = find_extract()
PYC_MAGIC_LEN = 16


def load(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    return marshal.loads(raw[PYC_MAGIC_LEN:])


def resolve(arg):
    if os.path.exists(arg):
        return arg
    return os.path.join(EX, "PYZ.pyz_extracted", arg.lstrip("./"))


def main(argv):
    if not argv:
        print(__doc__)
        return 1
    path = resolve(argv[0])
    if not os.path.exists(path):
        if not os.path.isdir(os.path.join(EX, "PYZ.pyz_extracted")):
            print(no_extract_message(EX))
        else:
            print("not found: %s" % path)
            print("hint: paths are looked up under %s/PYZ.pyz_extracted/"
                  % EX)
        return 1
    co = load(path)
    target = None
    if len(argv) > 1:
        want = argv[1]
        stack = [co]
        while stack:
            c = stack.pop()
            if c.co_name == want:
                target = c
                break
            stack.extend(k for k in c.co_consts if hasattr(k, "co_consts"))
        if target is None:
            print("no code object named %r in %s" % (want, path))
            return 1

    name = "%s.%s" % (os.path.basename(path), target.co_name if target else "<module>")
    doc = None
    if target is None:
        for k in co.co_consts:
            if isinstance(k, str) and len(k) > 20:
                doc = k
                break
    print("### %s" % name)
    if doc:
        print("### docstring: %s" % doc.strip()[:400])
    print("### names    : %s" % ((target or co).co_names,))
    print("### varnames : %s" % ((target or co).co_varnames,))
    print("### constants:")
    for k in (target or co).co_consts:
        if not hasattr(k, "co_consts"):
            print("      %r" % (k,))
    print()
    buf = io.StringIO()
    try:
        dis.dis(target if target is not None else co, file=buf)
        print(buf.getvalue())
    except BaseException as exc:
        print("dis failed: %s: %s" % (type(exc).__name__, exc))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
