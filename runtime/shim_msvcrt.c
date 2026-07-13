/* Plain cdecl implementations of the msvcrt.dll functions winlift supports.
 * Unlike kernel32 (stdcall), msvcrt's C-runtime-style exports use the same
 * caller-cleans-stack convention as normal C, so these need no special
 * calling-convention attribute - default gcc i386 codegen already matches. */
#include "shim_startup.h"
#include "shim_syscall.h"
#include <stdarg.h>

/* ---- data symbols (imported as addresses, not called) ---- */

char **shim_data___initenv;

static int commode_value = 0; /* _IOCOMMIT/_IOTEXT-style default */
static int fmode_value = 0;   /* _O_TEXT default */

/* ---- process/CRT bootstrap ---- */

int shim_msvcrt_getmainargs(int *argc, char ***argv, char ***envp, int do_wildcard, void *startupinfo) {
    (void)do_wildcard;
    (void)startupinfo;
    *argc = shim_argc;
    *argv = shim_argv;
    *envp = shim_envp;
    shim_data___initenv = shim_envp;
    return 0;
}

int *shim_msvcrt_p_commode(void) { return &commode_value; }
int *shim_msvcrt_p_fmode(void) { return &fmode_value; }

/* Newer mingw-w64 CRTs import these as accessor functions rather than
 * directly importing the underlying data symbols (`_iob`, `__initenv`,
 * `_acmdln`) - both forms are kept so winlift works against either CRT
 * generation. */
void *shim_msvcrt_p_iob(void) { return shim_iob; }
char ***shim_msvcrt_p_initenv(void) { return &shim_data___initenv; }

static char *acmdln_value = 0;
char **shim_msvcrt_p_acmdln(void) {
    acmdln_value = shim_cmdline ? shim_cmdline : "";
    return &acmdln_value;
}

/* Single-byte/"C"-locale only (see shim_msvcrt_memcpy et al. above): no byte
 * value is ever a DBCS lead byte, so command-line parsing that consults
 * this always takes the single-byte path. */
int shim_msvcrt_ismbblead(unsigned int c) { (void)c; return 0; }

int shim_msvcrt_atexit(void (*fn)(void)) {
    shim_onexit_register(fn);
    return 0;
}

void shim_msvcrt_set_app_type(int type) { (void)type; }
void shim_msvcrt_setusermatherr(void *handler) { (void)handler; }

void shim_msvcrt_amsg_exit(int code) {
    (void)code;
    static const char msg[] = "runtime error\n";
    shim_syscall3(SYS_write, 2, (long)msg, sizeof(msg) - 1);
    shim_process_exit(255);
}

void shim_msvcrt_cexit(void) {
    shim_run_atexit();
}

/* Walks a NULL-terminated-by-range array of function pointers, calling each
 * non-null entry - used to run C++/CRT static initializers registered
 * between [begin, end). This is genuinely re-executing original PE code
 * (the initializer functions themselves), just via a copied-through call
 * table rather than a re-implementation. */
void shim_msvcrt_initterm(void (**begin)(void), void (**end)(void)) {
    for (void (**p)(void) = begin; p < end; p++) {
        if (*p) (*p)();
    }
}

void *shim_msvcrt_onexit(void (*fn)(void)) {
    shim_onexit_register(fn);
    return (void *)fn;
}

void shim_msvcrt_abort(void) {
    static const char msg[] = "abort()\n";
    shim_syscall3(SYS_write, 2, (long)msg, sizeof(msg) - 1);
    shim_process_exit(3); /* matches real msvcrt abort()'s default exit code */
}

void shim_msvcrt_exit(int code) {
    shim_run_atexit();
    shim_process_exit(code);
}

void *shim_msvcrt_calloc(unsigned long nmemb, unsigned long size) {
    unsigned long total = nmemb * size; /* fixture-scale sizes only: no overflow hardening needed here */
    void *p = shim_heap_alloc(total);
    if (p) {
        char *c = (char *)p;
        for (unsigned long i = 0; i < total; i++) c[i] = 0;
    }
    return p;
}

void *shim_msvcrt_malloc(unsigned long size) { return shim_heap_alloc(size); }
void shim_msvcrt_free(void *p) { shim_heap_free(p); }
void *shim_msvcrt_realloc(void *p, unsigned long size) { return shim_heap_realloc(p, size); }

void *shim_msvcrt_memcpy(void *dst, const void *src, unsigned long n) {
    char *d = (char *)dst;
    const char *s = (const char *)src;
    for (unsigned long i = 0; i < n; i++) d[i] = s[i];
    return dst;
}

unsigned long shim_msvcrt_strlen(const char *s) {
    unsigned long n = 0;
    while (s[n]) n++;
    return n;
}

int shim_msvcrt_strncmp(const char *a, const char *b, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) {
        unsigned char ca = (unsigned char)a[i], cb = (unsigned char)b[i];
        if (ca != cb) return (int)ca - (int)cb;
        if (ca == 0) return 0;
    }
    return 0;
}

void *shim_msvcrt_signal(int sig, void *handler) {
    (void)sig;
    (void)handler; /* not delivering Windows-style signals; accept and ignore */
    return 0; /* SIG_DFL */
}

int shim_msvcrt_vfprintf(void *stream, const char *fmt, va_list ap) {
    char buf[1024];
    int len = shim_vformat(buf, sizeof(buf), fmt, ap);
    int fd = shim_iob_to_fd(stream);
    unsigned long n = len < 0 ? 0 : (unsigned long)len;
    if (n > sizeof(buf) - 1) n = sizeof(buf) - 1;
    unsigned long done = 0;
    while (done < n) {
        long r = shim_syscall3(SYS_write, fd, (long)(buf + done), (long)(n - done));
        if (r <= 0) break;
        done += (unsigned long)r;
    }
    return (int)done;
}

int shim_msvcrt_fprintf(void *stream, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = shim_msvcrt_vfprintf(stream, fmt, ap);
    va_end(ap);
    return r;
}

unsigned long shim_msvcrt_fwrite(const void *ptr, unsigned long size, unsigned long nmemb, void *stream) {
    unsigned long total = size * nmemb;
    int fd = shim_iob_to_fd(stream);
    const char *p = (const char *)ptr;
    unsigned long done = 0;
    while (done < total) {
        long r = shim_syscall3(SYS_write, fd, (long)(p + done), (long)(total - done));
        if (r <= 0) break;
        done += (unsigned long)r;
    }
    return size ? done / size : 0;
}
