/*
 * marker.c — LD_PRELOAD proof-of-concept for V-03 / CHK-04
 * (Black Duck Signal 2026.9.0 VAPT — manual verification)
 *
 * A minimal constructor-only shared object: when preloaded, its constructor
 * runs inside the target process before any application code. Signal has no
 * signing/anti-tamper to prevent this.
 *
 * Build:  gcc -shared -fPIC -o marker.so marker.c
 * Run:    LD_PRELOAD=$PWD/marker.so ./signal-pyarmor-linux-x86_64 --version
 * Check:  cat /tmp/LD_PRELOAD_EXECUTED   (marker file written from inside the app)
 *
 * For AUTHORIZED testing only, on systems you control.
 */
#include <stdio.h>

__attribute__((constructor)) static void vapt_marker(void) {
    FILE *f = fopen("/tmp/LD_PRELOAD_EXECUTED", "w");
    if (f) {
        fputs("injected code ran inside signal process\n", f);
        fclose(f);
    }
}
