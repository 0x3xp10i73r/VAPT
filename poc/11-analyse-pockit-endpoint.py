"""Show where PoCKit sends data and which credential it needs (F-15).

PoCKit is the only part of the product that is not Python-bytecode-protected
(33 plain .pyc files under pockit/), so its endpoint constant, its environment
override and the credential each agent reads can be read directly from the
shipped artefact - no code execution required.

    python3 11-analyse-pockit-endpoint.py [extracted-dir]

The optional argument defaults to SIGNAL_EXTRACT or ./signal-pyarmor-linux-x86_64_extracted.
"""
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

EX = sys.argv[1] if len(sys.argv) > 1 else find_extract()
POCKIT = os.path.join(EX, "PYZ.pyz_extracted", "pockit")

if not os.path.isdir(POCKIT):
    raise SystemExit(no_extract_message(EX))

INTERESTING = ("POCKIT_LLM_BASE_URL", "ANTHROPIC_API_KEY", "llm.labs.blackduck",
               "llm.core.blackduck", "claude-opus", "claude-sonnet", "pockit-",
               "Docker", "docker")


def codeobjects(co, out=None):
    if out is None:
        out = []
    out.append(co)
    for const in co.co_consts:
        if hasattr(const, "co_consts"):
            codeobjects(const, out)
    return out


def scan(path, rel):
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        co = marshal.loads(raw[16:])
    except BaseException as exc:
        print("  %-46s unreadable (%s)" % (rel, type(exc).__name__))
        return
    found = set()
    for c in codeobjects(co):
        for const in c.co_consts:
            if isinstance(const, str) and any(t in const for t in INTERESTING):
                if len(const) < 200:
                    found.add(const)
    for item in sorted(found):
        print("  %-46s %s" % (rel, item))


def main():
    if not os.path.isdir(POCKIT):
        print("pockit package not found under %s" % POCKIT)
        return 1
    print("PoCKit modules shipped UNOBFUSCATED (plain .pyc):")
    print()
    print("  %-46s %s" % ("module", "security-relevant constant"))
    print("  " + "-" * 96)
    for root, _dirs, files in os.walk(POCKIT):
        for name in sorted(files):
            if name.endswith(".pyc"):
                scan(os.path.join(root, name),
                     os.path.relpath(os.path.join(root, name), POCKIT))
    print()
    print("Interpretation:")
    print("  - LLM_BASE_URL defaults to https://llm.labs.blackduck.com and is read at")
    print("    import time by pockit/constants.pyc from POCKIT_LLM_BASE_URL.")
    print("  - Every agents/*_agent.pyc _setup_agent reads ANTHROPIC_API_KEY from the")
    print("    environment; none of the Signal --llm-*-key options are consulted.")
    print("  - the PoCKit workflow is gated on a 'docker' executable being on PATH.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
