/* Minimal host that runs a Python 3.13 script using the interpreter library
 * bundled inside the target PyInstaller/BlackDuck Signal binary.
 * Used for controlled static analysis of frozen .pyc modules.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

typedef void (*init_fn)(void);
/* int PyRun_SimpleFileExFlags(FILE *fp, const char *filename, int closeit,
 *                             PyCompilerFlags *flags);
 * Passing a correct 4-argument signature with flags=NULL is required: an
 * underspecified prototype leaves random stack data in the flags pointer,
 * which corrupts parser behaviour. */
typedef int (*run_file_fn)(FILE *, const char *, int, void *);
typedef void (*set_prog_fn)(const wchar_t *);
typedef int (*py_isinit_fn)(void);

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s script.py [args...]\n", argv[0]);
        return 2;
    }

    const char *libpath = getenv("PY313_LIB");
    if (!libpath) libpath = "/tmp/vapt/signal-pyarmor-linux-x86_64_extracted/libpython3.13.so.1.0";

    void *h = dlopen(libpath, RTLD_NOW | RTLD_GLOBAL);
    if (!h) { fprintf(stderr, "dlopen failed: %s\n", dlerror()); return 3; }

    set_prog_fn set_prog = (set_prog_fn)dlsym(h, "Py_SetProgramName");
    init_fn init = (init_fn)dlsym(h, "Py_Initialize");
    run_file_fn run_file = (run_file_fn)dlsym(h, "PyRun_SimpleFileExFlags");
    if (!init || !run_file) { fprintf(stderr, "dlsym failed: %s\n", dlerror()); return 4; }

    if (set_prog) set_prog(L"py313host");

    init();

    FILE *fp = fopen(argv[1], "r");
    if (!fp) { perror("fopen"); return 5; }

    /* Expose the remaining argv to the script via sys.argv */
    int rc = run_file((FILE *)fp, argv[1], 0, NULL);
    return rc;
}
