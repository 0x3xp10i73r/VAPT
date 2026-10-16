import sys, ssl, zlib, sqlite3, hashlib, platform, importlib
print("python        :", sys.version.replace("\n", " "))
print("compiler      :", platform.python_compiler())
print("ssl           :", ssl.OPENSSL_VERSION)
print("ssl info      :", ssl.OPENSSL_VERSION_INFO)
print("ssl proto     :", ssl.PROTOCOL_TLS_CLIENT)
print("zlib (module) :", zlib.ZLIB_VERSION, "| runtime:", zlib.ZLIB_RUNTIME_VERSION)
print("sqlite3       :", sqlite3.sqlite_version, "| module:", sqlite3.version if hasattr(sqlite3, "version") else "n/a")
print("hashlib       : available;", "md5" in hashlib.algorithms_available, "sha3_256" in hashlib.algorithms_available)
for m in ("numpy", "faiss", "tiktoken", "certifi"):
    try:
        mod = importlib.import_module(m)
        v = getattr(mod, "__version__", None)
        if m == "certifi" and v is None:
            v = getattr(mod, "where", lambda: None)()
        print(f"{m:14s}:", v)
    except BaseException as e:
        print(f"{m:14s}: FAIL {type(e).__name__}: {str(e)[:60]}")
