#ifndef WINLIFT_SHIM_STARTUP_H
#define WINLIFT_SHIM_STARTUP_H

#include <stdarg.h>

/* Matches the classic mingw-w64/msvcrt `struct _iobuf` layout exactly (8
 * 4-byte fields = 32 bytes on i386). This has to match byte-for-byte: the
 * PE code we copy through unmodified computes `&_iob[N]` via fixed-offset
 * pointer arithmetic baked in at the *original* compile time, so our
 * replacement array must have the same element stride for that arithmetic
 * to still land on the right slot. */
typedef struct {
    char *_ptr;
    int   _cnt;
    char *_base;
    int   _flag;
    int   _file; /* the only field we actually use: 0/1/2 = stdin/stdout/stderr */
    int   _charbuf;
    int   _bufsiz;
    char *_tmpfname;
} shim_iobuf_t;

#define SHIM_IOB_COUNT 20
extern shim_iobuf_t shim_iob[SHIM_IOB_COUNT];

extern int shim_argc;
extern char **shim_argv;
extern char **shim_envp;
extern char *shim_cmdline; /* argv joined with spaces, for GetCommandLineA */

void shim_startup_init(int argc, char **argv, char **envp);

/* Double-null-terminated "VAR=value\0VAR2=value2\0\0" block, built lazily
 * from shim_envp on first call and cached, for GetEnvironmentStrings(A). */
char *shim_env_block(void);

void *shim_heap_alloc(unsigned long size);
void  shim_heap_free(void *p);
void *shim_heap_realloc(void *p, unsigned long size);

/* Resolve a FILE*-shaped pointer (one of &shim_iob[N], or NULL) to a raw fd.
 * Defaults to fd 1 (stdout) for anything we don't recognize rather than
 * crashing, since our scope is "well-behaved CRT-generated I/O calls". */
int shim_iob_to_fd(void *stream);

int shim_vformat(char *buf, unsigned long bufcap, const char *fmt, va_list ap);

void shim_onexit_register(void (*fn)(void));
void shim_run_atexit(void);

void shim_process_exit(int code) __attribute__((noreturn));

#endif /* WINLIFT_SHIM_STARTUP_H */
