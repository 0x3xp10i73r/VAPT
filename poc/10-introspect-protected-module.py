"""Show what ordinary introspection returns for a PyArmor-protected module.

Imports protected product modules through the runtime shipped inside the binary
(no licence, no key, no expiry) and prints the module docstring, its classes and
its public callables - including full signatures, defaults and annotations.

    PYTHONHOME=<pyhome> PYTHONPATH=<merged> ./py313host 10-introspect-protected-module.py \
        [module ...]     # default: models error_mapping agent_config_resolution
"""
import importlib
import inspect
import sys

TARGETS = sys.argv[1:] or ["models", "error_mapping", "agent_config_resolution"]


def describe(name):
    print("=" * 74)
    print("MODULE %s" % name)
    print("=" * 74)
    try:
        mod = importlib.import_module(name)
    except BaseException as exc:
        print("  import failed: %s: %s" % (type(exc).__name__, exc))
        return
    doc = (mod.__doc__ or "").strip().replace("\n", " ")
    print("  __file__   : %s" % getattr(mod, "__file__", "?"))
    print("  __doc__    : %s%s" % (doc[:220], "..." if len(doc) > 220 else ""))

    classes = [n for n, o in vars(mod).items()
               if inspect.isclass(o) and getattr(o, "__module__", "") == mod.__name__]
    funcs = [n for n, o in vars(mod).items()
             if inspect.isfunction(o) and getattr(o, "__module__", "") == mod.__name__]
    print("  classes    : %d" % len(classes))
    for c in classes[:12]:
        print("      - %s" % c)
    print("  functions  : %d" % len(funcs))
    for f in funcs[:15]:
        try:
            print("      - %s%s" % (f, inspect.signature(getattr(mod, f))))
        except BaseException:
            print("      - %s" % f)


if __name__ == "__main__":
    for target in TARGETS:
        describe(target)
