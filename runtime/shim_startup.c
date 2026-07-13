#include "shim_startup.h"
#include "shim_syscall.h"
#include <stdarg.h>

shim_iobuf_t shim_iob[SHIM_IOB_COUNT];

int shim_argc;
char **shim_argv;
char **shim_envp;
char *shim_cmdline;

/* ---- fake Windows TEB, reachable via %fs like on real Windows i386 ----
 *
 * MinGW/MSVC-generated CRT startup code (stack-check init, SEH setup) reads
 * fields directly off the Thread Environment Block via fixed %fs-relative
 * offsets (e.g. `mov %fs:0x18, %eax` for the TEB self-pointer) - this is
 * inline in the compiled machine code, bypassing any kernel32 import we
 * could intercept, so simply not resolving it isn't an option: we have to
 * make %fs point at *something* plausible. This mirrors the technique Wine
 * uses on Linux: allocate a GDT entry via set_thread_area(2) pointing at a
 * small buffer we control, and load it into %fs. We only populate the
 * handful of TEB fields the supported fixture corpus actually touches
 * (SEH chain head, stack bounds, self-pointer, TLS pointer slot); other
 * TEB-dependent behavor beyond this scope. */
#define SYS_set_thread_area 243

typedef struct {
    unsigned int entry_number;
    unsigned int base_addr;
    unsigned int limit;
    unsigned int flags; /* seg_32bit=1, limit_in_pages=1, useable=1, rest 0 */
} shim_user_desc_t;

static unsigned char g_teb[4096] __attribute__((aligned(16)));

static void setup_fake_teb(void) {
    unsigned int stack_top;
    __asm__ volatile("mov %%esp, %0" : "=r"(stack_top));

    *(unsigned int *)(g_teb + 0x00) = 0xFFFFFFFFu; /* SEH exception chain: none installed */
    *(unsigned int *)(g_teb + 0x04) = stack_top;   /* NT_TIB.StackBase (approximate) */
    *(unsigned int *)(g_teb + 0x08) = stack_top > 0x100000 ? stack_top - 0x100000 : 0; /* StackLimit (approximate) */
    *(unsigned int *)(g_teb + 0x18) = (unsigned int)(unsigned long)g_teb; /* NT_TIB.Self */
    *(unsigned int *)(g_teb + 0x2C) = 0; /* ThreadLocalStoragePointer: none allocated */

    shim_user_desc_t desc;
    desc.entry_number = 0xFFFFFFFFu; /* ask the kernel to pick a free GDT slot */
    desc.base_addr = (unsigned int)(unsigned long)g_teb;
    desc.limit = 0xFFFFFFFFu;
    desc.flags = 0x51u; /* seg_32bit | limit_in_pages | useable */

    long ret = shim_syscall1(SYS_set_thread_area, (long)&desc);
    if (ret == 0) {
        unsigned short selector = (unsigned short)((desc.entry_number << 3) | 3);
        __asm__ volatile("mov %0, %%fs" : : "r"(selector));
    }
    /* If set_thread_area fails, %fs-relative CRT code will fault - that
     * failure mode is out of scope to recover from further. */
}

/* ---- tiny local string/mem helpers (no libc available) ---- */

static unsigned long local_strlen(const char *s) {
    unsigned long n = 0;
    while (s[n]) n++;
    return n;
}

/* ---- bump allocator over brk ---- */

static char *heap_next = 0;
static char *heap_limit = 0;

void *shim_heap_alloc(unsigned long size) {
    size = (size + 15UL) & ~15UL;
    if (size == 0) size = 16;

    if (heap_next == 0) {
        char *cur = (char *)shim_syscall1(SYS_brk, 0);
        heap_next = cur;
        heap_limit = cur;
    }
    if (heap_next + size > heap_limit) {
        unsigned long need = (unsigned long)((heap_next + size) - heap_limit);
        unsigned long grow = need > 0x100000UL ? need : 0x100000UL;
        char *new_limit = (char *)shim_syscall1(SYS_brk, (long)(heap_limit + grow));
        if (new_limit < heap_limit + grow) return 0; /* brk failed to grow enough */
        heap_limit = new_limit;
    }
    void *p = heap_next;
    heap_next += size;
    return p;
}

void shim_heap_free(void *p) {
    (void)p; /* bump allocator: never actually reclaimed, documented simplification */
}

void *shim_heap_realloc(void *p, unsigned long size) {
    /* We don't track allocation sizes, so realloc always allocates fresh and
     * copies conservatively (up to the new size) - correct but wasteful.
     * Acceptable for the bounded scope this tool targets. */
    void *n = shim_heap_alloc(size);
    if (!n) return 0;
    if (p) {
        unsigned long i;
        for (i = 0; i < size; i++) ((char *)n)[i] = ((char *)p)[i];
    }
    return n;
}

/* ---- FILE* (well, shim_iobuf_t*) -> fd ---- */

int shim_iob_to_fd(void *stream) {
    shim_iobuf_t *s = (shim_iobuf_t *)stream;
    if (s >= &shim_iob[0] && s < &shim_iob[SHIM_IOB_COUNT]) {
        long idx = s - &shim_iob[0];
        if (idx == 0) return 0;
        if (idx == 2) return 2;
        return 1; /* index 1 (stdout) and anything else default to stdout */
    }
    return 1;
}

/* ---- minimal printf-family formatter ---- */

static void out_char(char *buf, unsigned long bufcap, unsigned long *pos, char c) {
    if (*pos < bufcap) buf[*pos] = c;
    (*pos)++;
}

static void out_str(char *buf, unsigned long bufcap, unsigned long *pos, const char *s) {
    while (*s) out_char(buf, bufcap, pos, *s++);
}

static void out_uint(char *buf, unsigned long bufcap, unsigned long *pos, unsigned long v, int base, int upper) {
    char tmp[32];
    int n = 0;
    const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    if (v == 0) {
        tmp[n++] = '0';
    } else {
        while (v > 0) {
            tmp[n++] = digits[v % (unsigned)base];
            v /= (unsigned)base;
        }
    }
    while (n > 0) out_char(buf, bufcap, pos, tmp[--n]);
}

static void out_int(char *buf, unsigned long bufcap, unsigned long *pos, long v) {
    if (v < 0) {
        out_char(buf, bufcap, pos, '-');
        out_uint(buf, bufcap, pos, (unsigned long)(-v), 10, 0);
    } else {
        out_uint(buf, bufcap, pos, (unsigned long)v, 10, 0);
    }
}

int shim_vformat(char *buf, unsigned long bufcap, const char *fmt, va_list ap) {
    unsigned long pos = 0;
    for (const char *p = fmt; *p; p++) {
        if (*p != '%') {
            out_char(buf, bufcap, &pos, *p);
            continue;
        }
        p++;
        int is_long = 0;
        while (*p == 'l') { is_long++; p++; }
        while (*p == '-' || *p == '0' || (*p >= '1' && *p <= '9')) p++; /* skip width/flags, unsupported */
        switch (*p) {
            case 'd': case 'i':
                out_int(buf, bufcap, &pos, is_long ? va_arg(ap, long) : va_arg(ap, int));
                break;
            case 'u':
                out_uint(buf, bufcap, &pos, is_long ? va_arg(ap, unsigned long) : va_arg(ap, unsigned int), 10, 0);
                break;
            case 'x':
                out_uint(buf, bufcap, &pos, is_long ? va_arg(ap, unsigned long) : va_arg(ap, unsigned int), 16, 0);
                break;
            case 'X':
                out_uint(buf, bufcap, &pos, is_long ? va_arg(ap, unsigned long) : va_arg(ap, unsigned int), 16, 1);
                break;
            case 'p':
                out_str(buf, bufcap, &pos, "0x");
                out_uint(buf, bufcap, &pos, (unsigned long)va_arg(ap, void *), 16, 0);
                break;
            case 'c':
                out_char(buf, bufcap, &pos, (char)va_arg(ap, int));
                break;
            case 's': {
                const char *s = va_arg(ap, const char *);
                out_str(buf, bufcap, &pos, s ? s : "(null)");
                break;
            }
            case '%':
                out_char(buf, bufcap, &pos, '%');
                break;
            case '\0':
                p--; /* stray trailing '%', don't overrun */
                break;
            default:
                out_char(buf, bufcap, &pos, '%');
                out_char(buf, bufcap, &pos, *p);
                break;
        }
    }
    if (bufcap > 0) buf[pos < bufcap ? pos : bufcap - 1] = '\0';
    return (int)pos;
}

/* ---- atexit-style callback list, driven by _onexit/exit ---- */

#define MAX_ATEXIT 32
static void (*atexit_fns[MAX_ATEXIT])(void);
static int atexit_count = 0;

void shim_onexit_register(void (*fn)(void)) {
    if (atexit_count < MAX_ATEXIT) atexit_fns[atexit_count++] = fn;
}

void shim_run_atexit(void) {
    while (atexit_count > 0) {
        atexit_count--;
        void (*fn)(void) = atexit_fns[atexit_count];
        if (fn) fn();
    }
}

static char *g_env_block = 0;

char *shim_env_block(void) {
    if (g_env_block) return g_env_block;
    unsigned long total = 1; /* final extra NUL terminating the whole block */
    int n = 0;
    while (shim_envp && shim_envp[n]) {
        total += local_strlen(shim_envp[n]) + 1;
        n++;
    }
    g_env_block = (char *)shim_heap_alloc(total);
    if (!g_env_block) return "";
    unsigned long pos = 0;
    for (int i = 0; i < n; i++) {
        unsigned long l = local_strlen(shim_envp[i]);
        for (unsigned long j = 0; j < l; j++) g_env_block[pos++] = shim_envp[i][j];
        g_env_block[pos++] = '\0';
    }
    g_env_block[pos] = '\0';
    return g_env_block;
}

void shim_process_exit(int code) {
    shim_syscall1(SYS_exit_group, code);
    __builtin_unreachable();
}

/* ---- process bring-up: called from _start before jumping to the PE entry point ---- */

void shim_startup_init(int argc, char **argv, char **envp) {
    setup_fake_teb();

    shim_argc = argc;
    shim_argv = argv;
    shim_envp = envp;

    for (int i = 0; i < SHIM_IOB_COUNT; i++) {
        shim_iob[i]._file = -1;
    }
    shim_iob[0]._file = 0;
    shim_iob[1]._file = 1;
    shim_iob[2]._file = 2;

    /* Build a naive space-joined command line for GetCommandLineA. Args
     * containing spaces are not quoted - documented simplification, real
     * quoting rules are only needed if a fixture actually depends on it. */
    unsigned long total = 1;
    for (int i = 0; i < argc; i++) total += local_strlen(argv[i]) + 1;
    shim_cmdline = (char *)shim_heap_alloc(total);
    if (shim_cmdline) {
        unsigned long pos = 0;
        for (int i = 0; i < argc; i++) {
            if (i > 0) shim_cmdline[pos++] = ' ';
            unsigned long l = local_strlen(argv[i]);
            for (unsigned long j = 0; j < l; j++) shim_cmdline[pos++] = argv[i][j];
        }
        shim_cmdline[pos] = '\0';
    }
}
