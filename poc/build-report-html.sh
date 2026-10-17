#!/usr/bin/env bash
# Build a self-contained HTML version of the report, for reading in a browser or
# attaching to a ticket. Needs node (npx); no network after the first run.
#
#   ./poc/build-report-html.sh                 # -> signal-pyarmor-linux-x86_64-vapt.html
#   ./poc/build-report-html.sh --open          # build, then print the file path
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$HERE")
SRC="$ROOT/signal-pyarmor-linux-x86_64-vapt.md"
OUT="$ROOT/signal-pyarmor-linux-x86_64-vapt.html"
if [ $# -ge 1 ] && [ "$1" != "--open" ]; then OUT="$1"; fi
[ -f "$SRC" ] || { echo "report not found: $SRC" >&2; exit 1; }
command -v npx >/dev/null 2>&1 || { echo "npx not found - install Node, or open the .md in an editor" >&2; exit 2; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/style.css" <<'CSS'
:root{--fg:#1a1a1a;--muted:#5b6470;--line:#e2e6ea;--accent:#0b5cad;--bg:#fff;
      --code-bg:#f6f8fa;--hi:#fff8e1;--hi-line:#f4b400}
@media (prefers-color-scheme:dark){
  :root{--fg:#e6e6e6;--muted:#9aa4b2;--line:#2d333b;--accent:#6cb6ff;--bg:#0d1117;
        --code-bg:#161b22;--hi:#2a2417;--hi-line:#b8860b}
}
*{box-sizing:border-box}
html{font-size:16px}
body{margin:0;background:var(--bg);color:var(--fg);
     font:16px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:60rem;margin:0 auto;padding:3rem 1.5rem 6rem}
h1{font-size:2rem;line-height:1.2;margin:0 0 .5rem;letter-spacing:-.02em}
h2{font-size:1.4rem;margin:2.8rem 0 .9rem;padding-bottom:.35rem;border-bottom:1px solid var(--line)}
h3{font-size:1.12rem;margin:2.2rem 0 .7rem;color:var(--accent)}
h4{font-size:1rem;margin:1.6rem 0 .5rem}
p,li{color:var(--fg)}
a{color:var(--accent)}
table{border-collapse:collapse;width:100%;margin:1.1rem 0;font-size:.9rem;display:block;overflow-x:auto}
th,td{border:1px solid var(--line);padding:.5rem .65rem;text-align:left;vertical-align:top}
th{background:var(--code-bg);font-size:.82rem;text-transform:uppercase;letter-spacing:.03em;color:var(--muted)}
tr:nth-child(even) td{background:color-mix(in srgb,var(--code-bg) 45%,transparent)}
code{background:var(--code-bg);padding:.12em .35em;border-radius:4px;
     font:.88em/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
pre{background:var(--code-bg);border:1px solid var(--line);border-radius:8px;
    padding:1rem 1.1rem;overflow-x:auto;font-size:.84rem;line-height:1.5}
pre code{background:none;padding:0;font-size:1em}
blockquote{margin:1.2rem 0;padding:.8rem 1rem;background:var(--hi);
           border-left:4px solid var(--hi-line);border-radius:4px}
blockquote p{margin:.25rem 0}
hr{border:0;border-top:1px solid var(--line);margin:2.5rem 0}
strong{font-weight:650}
/* keep severity words readable */
td strong{white-space:normal}
@media print{
  body{font-size:10.5pt}
  main{max-width:none;padding:0}
  h2{page-break-after:avoid}
  table,pre,blockquote{page-break-inside:avoid}
  a{color:inherit;text-decoration:none}
  a[href^="http"]::after{content:" (" attr(href) ")";font-size:.8em;color:#555}
}
CSS

cat > "$TMP/template.html" <<'HTML'
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title>
<style>__STYLE__</style>
</head><body><main>
__BODY__
</main></body></html>
HTML

# render markdown -> body fragment, then splice into the template
npx --yes marked@12 -i "$SRC" -o "$TMP/body.html" --no-header-ids 2>/dev/null || \
  npx --yes marked@12 -i "$SRC" -o "$TMP/body.html"

python3 - "$TMP" "$OUT" "$SRC" <<'PY'
import html, pathlib, sys
tmp, out, src = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
body = (tmp / "body.html").read_text()
style = (tmp / "style.css").read_text()
title = next((l.lstrip("# ").strip() for l in src.read_text().splitlines() if l.startswith("# ")),
             src.name)
doc = (tmp / "template.html").read_text()
doc = doc.replace("__TITLE__", html.escape(title)).replace("__STYLE__", style).replace("__BODY__", body)
out.write_text(doc, encoding="utf-8")
print("wrote %s (%d bytes)" % (out, len(doc.encode())))
PY

echo
echo "Open it with:   xdg-open \"$OUT\"      # or just double-click it"
echo "Convert to PDF: open it in a browser and print to PDF (the stylesheet has print rules)."
