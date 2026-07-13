/* Win32-ABI-compatible (stdcall) implementations of the small, enumerable
 * set of kernel32.dll functions winlift supports. Each is declared
 * __attribute__((stdcall)) so gcc emits the `ret N` epilogue matching what
 * PE code calling through the IAT expects (verified against real i386
 * codegen - see the M1c design notes). */
#include "shim_startup.h"
#include "shim_syscall.h"

static unsigned long g_last_error = 0;

void __attribute__((stdcall)) shim_DeleteCriticalSection(void *cs) {
    (void)cs; /* single-threaded: critical sections are no-ops */
}
void __attribute__((stdcall)) shim_InitializeCriticalSection(void *cs) {
    (void)cs;
}
void __attribute__((stdcall)) shim_EnterCriticalSection(void *cs) {
    (void)cs;
}
void __attribute__((stdcall)) shim_LeaveCriticalSection(void *cs) {
    (void)cs;
}

int __attribute__((stdcall)) shim_FreeLibrary(void *hmod) {
    (void)hmod;
    return 1; /* TRUE */
}

unsigned long __attribute__((stdcall)) shim_GetLastError(void) {
    return g_last_error;
}

void __attribute__((stdcall)) shim_SetLastError(unsigned long code) {
    g_last_error = code;
}

/* We don't support dynamic module lookup/loading (see PE_ERR_UNSUPPORTED_*
 * rejection at conversion time for anything that would actually need it):
 * GetModuleHandleA(NULL) returns a fixed sentinel "this module" handle, any
 * named lookup returns NULL rather than fabricating a bogus handle. */
void * __attribute__((stdcall)) shim_GetModuleHandleA(const char *name) {
    if (name == 0) return (void *)0x00400000; /* matches winlift's fixed ImageBase */
    return 0;
}

void * __attribute__((stdcall)) shim_LoadLibraryA(const char *name) {
    (void)name;
    return 0;
}

void * __attribute__((stdcall)) shim_GetProcAddress(void *hmod, const char *name) {
    (void)hmod;
    (void)name;
    return 0; /* unsupported: dynamic export lookup not implemented */
}

void * __attribute__((stdcall)) shim_SetUnhandledExceptionFilter(void *filter) {
    (void)filter; /* SEH not supported; accept and ignore like a no-op previous filter */
    return 0;
}

void __attribute__((stdcall)) shim_Sleep(unsigned long ms) {
    long ts[2];
    ts[0] = (long)(ms / 1000);
    ts[1] = (long)((ms % 1000) * 1000000L);
    shim_syscall2(SYS_nanosleep, (long)ts, 0);
}

/* Single-threaded: a small fixed slot table is enough (no TlsAlloc/SetValue
 * import is present in the supported fixture corpus, so this only needs to
 * satisfy reads of not-yet-set slots). */
#define TLS_SLOTS 64
static void *tls_values[TLS_SLOTS];

void * __attribute__((stdcall)) shim_TlsGetValue(unsigned long idx) {
    if (idx >= TLS_SLOTS) return 0;
    return tls_values[idx];
}

int __attribute__((stdcall)) shim_VirtualProtect(void *addr, unsigned long size,
                                                  unsigned long newprot, unsigned long *oldprot) {
    /* Best-effort: translate the handful of PAGE_* constants CRT startup
     * code typically passes into a POSIX PROT_* mask and call mprotect.
     * Region must be page-aligned per mprotect's own requirement. */
    unsigned long page = (unsigned long)addr & ~0xFFFUL;
    unsigned long extra = (unsigned long)addr - page;
    unsigned long len = (size + extra + 0xFFFUL) & ~0xFFFUL;

    int prot = 0;
    switch (newprot & 0xFF) {
        case 0x01: prot = 0; break;             /* PAGE_NOACCESS */
        case 0x02: prot = 1; break;              /* PAGE_READONLY -> PROT_READ */
        case 0x04: prot = 1 | 2; break;          /* PAGE_READWRITE -> PROT_READ|WRITE */
        case 0x10: prot = 4; break;              /* PAGE_EXECUTE -> PROT_EXEC */
        case 0x20: prot = 4 | 1; break;          /* PAGE_EXECUTE_READ */
        case 0x40: prot = 4 | 1 | 2; break;      /* PAGE_EXECUTE_READWRITE */
        default: prot = 1 | 2; break;
    }
    if (oldprot) *oldprot = 0x04; /* report PAGE_READWRITE; we don't track prior state */
    long r = shim_syscall3(SYS_mprotect, (long)page, (long)len, prot);
    return r == 0 ? 1 : 0;
}

/* MEMORY_BASIC_INFORMATION, PE32 layout (28 bytes): BaseAddress,
 * AllocationBase, AllocationProtect, RegionSize, State, Protect, Type. */
typedef struct {
    void *BaseAddress;
    void *AllocationBase;
    unsigned long AllocationProtect;
    unsigned long RegionSize;
    unsigned long State;
    unsigned long Protect;
    unsigned long Type;
} shim_mbi_t;

unsigned long __attribute__((stdcall)) shim_VirtualQuery(const void *addr, shim_mbi_t *out, unsigned long len) {
    /* Best-effort, not backed by a real /proc/self/maps query: real callers
     * in the supported CRT-startup scope only use this for entropy (e.g.
     * security-cookie init), not to make real placement decisions. */
    if (len < sizeof(shim_mbi_t)) return 0;
    unsigned long page = (unsigned long)addr & ~0xFFFUL;
    out->BaseAddress = (void *)page;
    out->AllocationBase = (void *)page;
    out->AllocationProtect = 0x04; /* PAGE_READWRITE */
    out->RegionSize = 0x1000;
    out->State = 0x1000;   /* MEM_COMMIT */
    out->Protect = 0x04;
    out->Type = 0x20000;   /* MEM_PRIVATE */
    return sizeof(shim_mbi_t);
}

void * __attribute__((stdcall)) shim_GetProcessHeap(void) {
    return (void *)0x1; /* single fixed sentinel heap handle; we only ever have one heap */
}

void * __attribute__((stdcall)) shim_HeapAlloc(void *heap, unsigned long flags, unsigned long size) {
    (void)heap;
    void *p = shim_heap_alloc(size);
    if (p && (flags & 0x8 /* HEAP_ZERO_MEMORY */)) {
        char *c = (char *)p;
        for (unsigned long i = 0; i < size; i++) c[i] = 0;
    }
    return p;
}

int __attribute__((stdcall)) shim_HeapFree(void *heap, unsigned long flags, void *mem) {
    (void)heap;
    (void)flags;
    shim_heap_free(mem);
    return 1;
}

void * __attribute__((stdcall)) shim_HeapReAlloc(void *heap, unsigned long flags, void *mem, unsigned long size) {
    (void)heap;
    void *p = shim_heap_realloc(mem, size);
    if (p && (flags & 0x8)) {
        char *c = (char *)p;
        for (unsigned long i = 0; i < size; i++) c[i] = 0;
    }
    return p;
}

void __attribute__((stdcall)) shim_ExitProcess(unsigned long code) {
    shim_run_atexit();
    shim_process_exit((int)code);
}

char * __attribute__((stdcall)) shim_GetCommandLineA(void) {
    return shim_cmdline ? shim_cmdline : "";
}

char * __attribute__((stdcall)) shim_GetEnvironmentStrings(void) {
    return shim_env_block();
}

int __attribute__((stdcall)) shim_FreeEnvironmentStringsA(char *block) {
    (void)block; /* backed by our own heap, never actually freed - see shim_heap_free */
    return 1;
}

void * __attribute__((stdcall)) shim_GetStdHandle(long which) {
    /* STD_INPUT_HANDLE=-10, STD_OUTPUT_HANDLE=-11, STD_ERROR_HANDLE=-12 */
    if (which == -10) return (void *)1;
    if (which == -11) return (void *)2;
    if (which == -12) return (void *)3;
    return (void *)-1; /* INVALID_HANDLE_VALUE */
}

int __attribute__((stdcall)) shim_CloseHandle(void *h) {
    long fd = (long)h - 1;
    if (fd == 0 || fd == 1 || fd == 2) return 1; /* never really close std handles */
    if (fd > 2) shim_syscall1(SYS_close, fd);
    return 1;
}

int __attribute__((stdcall)) shim_WriteFile(void *h, const void *buf, unsigned long n,
                                             unsigned long *written, void *overlapped) {
    if (overlapped) {
        g_last_error = 87; /* ERROR_INVALID_PARAMETER: async I/O not supported */
        return 0;
    }
    long fd = (long)h - 1;
    if (fd < 0) { g_last_error = 6; return 0; } /* ERROR_INVALID_HANDLE */
    unsigned long done = 0;
    const char *p = (const char *)buf;
    while (done < n) {
        long r = shim_syscall3(SYS_write, fd, (long)(p + done), (long)(n - done));
        if (r <= 0) break;
        done += (unsigned long)r;
    }
    if (written) *written = done;
    return 1;
}

int __attribute__((stdcall)) shim_ReadFile(void *h, void *buf, unsigned long n,
                                            unsigned long *nread, void *overlapped) {
    if (overlapped) {
        g_last_error = 87;
        return 0;
    }
    long fd = (long)h - 1;
    if (fd < 0) { g_last_error = 6; return 0; }
    long r = shim_syscall3(SYS_read, fd, (long)buf, (long)n);
    if (r < 0) { if (nread) *nread = 0; return 0; }
    if (nread) *nread = (unsigned long)r;
    return 1;
}

void * __attribute__((stdcall)) shim_CreateFileA(const char *path, unsigned long access,
                                                  unsigned long share, void *sec,
                                                  unsigned long disposition, unsigned long flags,
                                                  void *template_file) {
    (void)share; (void)sec; (void)flags; (void)template_file;
    int rw = (access & 0x40000000) ? ((access & 0x80000000) ? 2 : 1) : 0; /* GENERIC_WRITE=0x40000000, GENERIC_READ=0x80000000 */
    int posix_flags;
    switch (disposition) {
        case 1: posix_flags = 0x40 | 0x80; break;             /* CREATE_NEW -> O_CREAT|O_EXCL */
        case 2: posix_flags = 0x40 | 0x200; break;             /* CREATE_ALWAYS -> O_CREAT|O_TRUNC */
        case 3: posix_flags = 0; break;                        /* OPEN_EXISTING */
        case 4: posix_flags = 0x40; break;                     /* OPEN_ALWAYS -> O_CREAT */
        case 5: posix_flags = 0x200; break;                    /* TRUNCATE_EXISTING -> O_TRUNC */
        default: posix_flags = 0; break;
    }
    posix_flags |= (rw == 2) ? 2 /* O_RDWR */ : (rw == 1 ? 1 /* O_WRONLY */ : 0 /* O_RDONLY */);

    long fd = shim_syscall3(SYS_open, (long)path, posix_flags, 0644);
    if (fd < 0) { g_last_error = 2; return (void *)-1; } /* ERROR_FILE_NOT_FOUND */
    return (void *)(fd + 1); /* keep 0 free so NULL-handle checks behave */
}
