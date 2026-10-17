"""Seed the tiktoken cache that every scan needs before its first LLM call.

F-05: the embedding agents fetch
https://openaipublic.blob.core.windows.net/encodings/cl100k_base.tiktoken on
first use. In an egress-restricted environment that fetch fails and the run
reports error_code 63 with the host name in the message - no documented option
moves the URL. The cache is hash-pinned (`sha1(url)` for the file name, and the
contents checked against a digest compiled into tiktoken), so an empty or
hand-written placeholder does not satisfy it.

This script uses whichever tiktoken is importable - run it under the
reconstructed host (poc/02) to use the one shipped in the binary, which needs
no installation on your machine:

    ./py313host poc/seed-tokenizer-cache.py            # -> <extraction>/../tkcache/cached
    ./py313host poc/seed-tokenizer-cache.py /path/to/cache

Then point the scan at the same directory:

    TIKTOKEN_CACHE_DIR=<that directory> ./signal-pyarmor-linux-x86_64 ...

If this machine has no egress to the blob host either, the script prints the
file to fetch elsewhere and its expected SHA-256.
"""
import hashlib
import os
import sys

URL = "https://openaipublic.blob.core.windows.net/encodings/cl100k_base.tiktoken"
FILENAME = hashlib.sha1(URL.encode()).hexdigest()          # 9b5ad71b2ce5302211f9c61530b329a4922fc6a4
SHA256 = "223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7"


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
    return os.path.dirname(os.path.dirname(here))


def fallback(cache_dir):
    print("Fetch the blob on a host that has egress, then copy it here:\n")
    print("    curl -fL -o %s/%s \\" % (cache_dir, FILENAME))
    print("        %s" % URL)
    print("\nVerify it before use:\n")
    print("    sha256sum %s/%s" % (cache_dir, FILENAME))
    print("    # expected: %s" % SHA256)
    print("\nAny other copy of the file works too - the name is sha1(URL) and the")
    print("contents are verified by tiktoken, so a mismatched file is rejected.")


def main():
    cache_dir = (sys.argv[1] if len(sys.argv) > 2
                 else os.environ.get("TIKTOKEN_CACHE_DIR")
                 or (sys.argv[1] if len(sys.argv) > 1 else None))
    if not cache_dir:
        cache_dir = os.path.join(os.path.dirname(os.path.abspath(find_extract())), "tkcache", "cached")
    cache_dir = os.path.abspath(cache_dir)
    os.makedirs(cache_dir, exist_ok=True)
    os.environ["TIKTOKEN_CACHE_DIR"] = cache_dir

    cached = os.path.join(cache_dir, FILENAME)
    if os.path.exists(cached):
        with open(cached, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        print("cache already seeded: %s" % cached)
        print("  sha256 %s%s" % (digest, "" if digest == SHA256 else "   <-- UNEXPECTED"))
        status = "ok" if digest == SHA256 else "wrong"
    else:
        print("cache empty, fetching %s" % URL)
        try:
            import tiktoken
            tiktoken.get_encoding("cl100k_base")
            status = "seeded"
        except ImportError:
            print("\ntiktoken is not importable with this interpreter.")
            print("Run this script through the reconstructed host to use the copy")
            print("shipped in the binary, which fetches the same file:\n")
            print("    ./py313host poc/seed-tokenizer-cache.py        # needs the step 5 exports")
            fallback(cache_dir)
            return 1
        except Exception as exc:                       # noqa: BLE001 - report anything
            print("\nfetch failed: %s: %s" % (type(exc).__name__, exc))
            print("\nThat is F-05 being reproduced, not a broken cache.")
            fallback(cache_dir)
            return 1

        if not os.path.exists(cached):
            print("\ntiktoken reported success but %s is still absent - it may use a" % FILENAME)
            print("different cache directory on this build. Set TIKTOKEN_CACHE_DIR explicitly.")
            fallback(cache_dir)
            return 1
        with open(cached, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        print("  wrote %s (%d bytes)" % (cached, os.path.getsize(cached)))
        print("  sha256 %s%s" % (digest, "" if digest == SHA256 else "   <-- UNEXPECTED"))
        status = "seeded" if digest == SHA256 else "wrong"

    print("\nstatus: %s" % status)
    if status in ("ok", "seeded"):
        # Both are success: the file is present and its digest matched.
        print("export TIKTOKEN_CACHE_DIR=%s" % cache_dir)
        return 0
    if status == "wrong":
        print("The file does not match the expected digest; delete it and re-fetch.")
    print("export TIKTOKEN_CACHE_DIR=%s   # after fetching the blob" % cache_dir)
    return 1


if __name__ == "__main__":
    sys.exit(main())
