/* Raw i386 Linux syscalls (int $0x80) - the shim never links against libc,
 * so this is the entire "OS interface" it has. */
#ifndef WINLIFT_SHIM_SYSCALL_H
#define WINLIFT_SHIM_SYSCALL_H

#define SYS_exit        1
#define SYS_read        3
#define SYS_write       4
#define SYS_open        5
#define SYS_close       6
#define SYS_brk         45
#define SYS_mprotect    125
#define SYS_nanosleep   162
#define SYS_exit_group  252

static inline long shim_syscall0(long n) {
    long ret;
    __asm__ volatile("int $0x80" : "=a"(ret) : "a"(n) : "memory");
    return ret;
}
static inline long shim_syscall1(long n, long a) {
    long ret;
    __asm__ volatile("int $0x80" : "=a"(ret) : "a"(n), "b"(a) : "memory");
    return ret;
}
static inline long shim_syscall2(long n, long a, long b) {
    long ret;
    __asm__ volatile("int $0x80" : "=a"(ret) : "a"(n), "b"(a), "c"(b) : "memory");
    return ret;
}
static inline long shim_syscall3(long n, long a, long b, long c) {
    long ret;
    __asm__ volatile("int $0x80" : "=a"(ret) : "a"(n), "b"(a), "c"(b), "d"(c) : "memory");
    return ret;
}
static inline long shim_syscall4(long n, long a, long b, long c, long d) {
    long ret;
    __asm__ volatile("int $0x80" : "=a"(ret) : "a"(n), "b"(a), "c"(b), "d"(c), "S"(d) : "memory");
    return ret;
}

#endif /* WINLIFT_SHIM_SYSCALL_H */
