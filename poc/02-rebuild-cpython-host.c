/* Minimal host that runs a Python 3.13 script using the interpreter library
 * bundled inside the target PyInstaller/BlackDuck Signal binary.
 * Used for controlled static analysis of frozen .pyc modules.
 *
 * The script sees the full command line in sys.argv, so scripts that take
 * arguments (poc/06 --extract, poc/10 <module>, poc/12 <pyc> <function>) work
 * unchanged:
 *
 *     ./py313host script.py arg1 arg2     ->  sys.argv ==
 *                                             ['script.py', 'arg1', 'arg2']
 *
 * Set PY313_VERBOSE=1 to print which libpython3.13 was loaded, and
 * PY313_LIB=/path/to/libpython3.13.so.1.0 to name it explicitly.
 */
#include <dlfcn.h>
#include <glob.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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

/* Locate libpython3.13.so.1.0 inside the extraction.
 *
 * The assessment ran with the extraction at /tmp/vapt, but nobody else does,
 * so the library is searched for rather than assumed:
 *
 *   1. $PY313_LIB
 *   2. $SIGNAL_EXTRACT/libpython3.13.so.1.0
 *   3. <dir of this binary>/[<anything>_extracted/]libpython3.13.so.1.0
 *   4. <parent of that dir>/[<anything>_extracted/]libpython3.13.so.1.0
 *   5. $PWD/[<anything>_extracted/]libpython3.13.so.1.0
 *   6. /tmp/vapt/[<anything>_extracted/]libpython3.13.so.1.0   (assessment default)
 *
 * Returns the path, or NULL if nothing was found; `tried` collects the places
 * that were looked in, for the error message.
 */
#define LEAF "libpython3.13.so.1.0"

static int readable(const char *p) { return p && *p && access(p, R_OK) == 0; }

/* PyRun_SimpleFileExFlags does not populate sys.argv, so do it through the
 * stable C API (PyImport_ImportModule / PyList_New / ...). */
typedef void *(*import_fn)(const char *);
typedef void *(*list_new_fn)(long);
typedef int (*list_set_fn)(void *, long, void *);
typedef void *(*unicode_from_string_fn)(const char *);
typedef int (*set_attr_fn)(void *, const char *, void *);


static int readable(const char *p);

/* Append a location to the "looked in" list, skipping consecutive repeats. */
static void remember(char *tried, size_t tn, const char *fmt, const char *a, const char *b)
{
    char line[PATH_MAX + 64];
    snprintf(line, sizeof(line), fmt, a, b);
    size_t len = strlen(tried);
    char *last = strrchr(tried, '\n');
    if (last && strcmp(last + 6, line) == 0) return;      /* already listed */
    if (len < tn) snprintf(tried + len, tn - len, "\n    %s", line);
}

/* Try <root>/libpython3.13.so.1.0, then <root>/<any>_extracted/libpython3.13.so.1.0
 * as a real glob. A literal '*' never resolves, which is how the first version
 * of this function managed to miss an extraction sitting one level down. */
static const char *try_root(char *out, size_t n, const char *root)
{
    snprintf(out, n, "%s/" LEAF, root);
    if (access(out, R_OK) == 0) return out;

    char pat[PATH_MAX];
    snprintf(pat, sizeof(pat), "%s/*_extracted/" LEAF, root);
    glob_t g;
    if (glob(pat, 0, NULL, &g) == 0) {
        if (g.gl_pathc > 0) {
            snprintf(out, n, "%s", g.gl_pathv[0]);
            globfree(&g);
            return out;
        }
        globfree(&g);
    }
    return NULL;
}

static const char *find_lib(char *out, size_t n, char *tried, size_t tn)
{
    const char *env = getenv("PY313_LIB");
#ifdef PY313_DEFAULT_LIB
    if (PY313_DEFAULT_LIB[0] && access(PY313_DEFAULT_LIB, R_OK) == 0) {
        snprintf(out, n, "%s", PY313_DEFAULT_LIB);
        return out;
    }
    if (PY313_DEFAULT_LIB[0])
        remember(tried, tn, "%s", PY313_DEFAULT_LIB, NULL);
#endif
    if (readable(env)) { snprintf(out, n, "%s", env); return out; }
    if (env) remember(tried, tn, "%s ($PY313_LIB)", env, NULL);

    const char *ex = getenv("SIGNAL_EXTRACT");
    if (ex) {
        if (try_root(out, n, ex)) return out;
        remember(tried, tn, "%s/[" LEAF "]", ex, NULL);
    }

    char exe[PATH_MAX] = "", dirbuf[PATH_MAX - 8] = "", up[PATH_MAX] = "";
    ssize_t got = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (got > 0) {
        exe[got] = '\0';
        snprintf(dirbuf, sizeof(dirbuf), "%s", dirname(exe));
        snprintf(up, sizeof(up), "%s/..", dirbuf);
    }
    const char *roots[] = { dirbuf, up, getenv("PWD"), "/tmp/vapt", NULL };

    for (int i = 0; roots[i]; i++) {
        if (!*roots[i]) continue;
        if (try_root(out, n, roots[i])) return out;
        remember(tried, tn, "%s/[<name>_extracted/]" LEAF, roots[i], NULL);
    }

    /* last resort: any extraction directory under the temporary directories */
    static const char *pats[] = {
        "/tmp/vapt/*/libpython3.13.so.1.0",
        "/tmp/*_extracted/" LEAF,
        "/home/*/*/*_extracted/" LEAF,
        NULL
    };
    for (int i = 0; pats[i]; i++) {
        glob_t g;
        int rc = glob(pats[i], 0, NULL, &g);
        if (rc == 0 && g.gl_pathc > 0) {
            snprintf(out, n, "%s", g.gl_pathv[0]);
            globfree(&g);
            return out;
        }
        if (rc == 0) globfree(&g);
    }
    return NULL;
}

static int set_argv(void *lib, int argc, char **argv)
{
    import_fn import_module = (import_fn)dlsym(lib, "PyImport_ImportModule");
    list_new_fn list_new = (list_new_fn)dlsym(lib, "PyList_New");
    list_set_fn list_set = (list_set_fn)dlsym(lib, "PyList_SetItem");
    unicode_from_string_fn mkstr = (unicode_from_string_fn)dlsym(lib, "PyUnicode_FromString");
    set_attr_fn set_attr = (set_attr_fn)dlsym(lib, "PyObject_SetAttrString");
    if (!import_module || !list_new || !list_set || !mkstr || !set_attr) return -1;

    void *sys = import_module("sys");
    if (!sys) return -1;
    void *list = list_new(argc - 1);
    if (!list) return -1;
    for (int i = 1; i < argc; i++) {
        void *s = mkstr(argv[i]);
        if (!s || list_set(list, i - 1, s) != 0) return -1;   /* steals the ref */
    }
    return set_attr(sys, "argv", list);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s script.py [args...]\n", argv[0]);
        return 2;
    }

    static char libpath[PATH_MAX];
    static char tried[8192] = "";
    if (!find_lib(libpath, sizeof(libpath), tried, sizeof(tried))) {
        fprintf(stderr,
            "libpython3.13.so.1.0 not found. Looked in:%s\n"
            "\n"
            "Run poc/00-setup.sh (it extracts the archive and builds this host),\n"
            "or point at the library directly:\n"
            "    PY313_LIB=/path/to/signal-pyarmor-linux-x86_64_extracted/" LEAF
            " ./py313host script.py\n", tried);
        return 3;
    }

    if (getenv("PY313_VERBOSE")) fprintf(stderr, "py313host: using %s\n", libpath);

    /* Without any path configuration the interpreter starts, cannot find its
     * stdlib and dies with a fatal error that says nothing about the cause. */
    if (!getenv("PYTHONHOME") && !getenv("PYTHONPATH") && !getenv("PY313_QUIET"))
        fprintf(stderr,
            "py313host: warning: neither PYTHONHOME nor PYTHONPATH is set, so the\n"
            "           interpreter has no stdlib and will fail to start. Export the\n"
            "           values printed by poc/00-setup.sh, for example:\n"
            "             export PYTHONHOME=/path/to/pyhome\n"
            "             export PYTHONPATH=/path/to/merged:/path/to/<extract>/base_library.zip\n");


    void *h = dlopen(libpath, RTLD_NOW | RTLD_GLOBAL);
    if (!h) { fprintf(stderr, "dlopen failed: %s (%s)\n", dlerror(), libpath); return 3; }

    set_prog_fn set_prog = (set_prog_fn)dlsym(h, "Py_SetProgramName");
    init_fn init = (init_fn)dlsym(h, "Py_Initialize");
    run_file_fn run_file = (run_file_fn)dlsym(h, "PyRun_SimpleFileExFlags");
    if (!init || !run_file) { fprintf(stderr, "dlsym failed: %s\n", dlerror()); return 4; }

    if (set_prog) set_prog(L"py313host");

    init();

    if (argc > 2 && set_argv(h, argc, argv) != 0)
        fprintf(stderr, "warning: could not populate sys.argv\n");

    FILE *fp = fopen(argv[1], "r");
    if (!fp) { perror("fopen"); return 5; }

    int rc = run_file((FILE *)fp, argv[1], 0, NULL);
    return rc;
}
