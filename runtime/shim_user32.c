/* Headless/no-op-backed (stdcall) implementations of a small, enumerable
 * set of user32.dll functions - see include/shim_abi.h for the exact
 * supported list. No real window is ever created or rendered: the goal of
 * this milestone is only that GUI-subsystem binaries convert and run
 * deterministically (see tests/fixtures/gui_messagebox.c and
 * gui_window_lifecycle.c), the same way console I/O is faked via raw
 * syscalls rather than a real console. Real rendering (an X11 backend or
 * similar) is a later milestone. */
#include "shim_startup.h"
#include "shim_syscall.h"

static unsigned long ulen(const char *s) {
    unsigned long n = 0;
    while (s && s[n]) n++;
    return n;
}

static void write_str(const char *s) {
    if (!s) s = "(null)";
    unsigned long n = ulen(s);
    unsigned long done = 0;
    while (done < n) {
        long r = shim_syscall3(SYS_write, 1, (long)(s + done), (long)(n - done));
        if (r <= 0) break;
        done += (unsigned long)r;
    }
}

int __attribute__((stdcall)) shim_MessageBoxA(void *hwnd, const char *text, const char *caption,
                                               unsigned int type) {
    (void)hwnd;
    (void)type;
    write_str("[MessageBoxA] ");
    write_str(caption);
    write_str(": ");
    write_str(text);
    write_str("\n");
    return 1; /* IDOK */
}

unsigned short __attribute__((stdcall)) shim_RegisterClassA(const void *wndclass) {
    (void)wndclass;
    return 1; /* nonzero sentinel atom, so `if (!RegisterClassA(...))` guards pass */
}

void * __attribute__((stdcall)) shim_CreateWindowExA(unsigned long ex_style, const char *class_name,
                                                       const char *window_name, unsigned long style,
                                                       int x, int y, int width, int height,
                                                       void *parent, void *menu, void *instance,
                                                       void *param) {
    (void)ex_style;
    (void)class_name;
    (void)window_name;
    (void)style;
    (void)x;
    (void)y;
    (void)width;
    (void)height;
    (void)parent;
    (void)menu;
    (void)instance;
    (void)param;
    return (void *)0x00010000; /* fixed sentinel HWND, same pattern as GetProcessHeap/GetStdHandle */
}

int __attribute__((stdcall)) shim_ShowWindow(void *hwnd, int cmd_show) {
    (void)hwnd;
    (void)cmd_show;
    return 1;
}

int __attribute__((stdcall)) shim_UpdateWindow(void *hwnd) {
    (void)hwnd;
    return 1;
}

long __attribute__((stdcall)) shim_DefWindowProcA(void *hwnd, unsigned int msg, unsigned long wparam,
                                                    long lparam) {
    (void)hwnd;
    (void)msg;
    (void)wparam;
    (void)lparam;
    return 0;
}

/* MSG is 24 bytes on i386 (HWND, UINT message, WPARAM, LPARAM, DWORD time,
 * POINT pt{LONG x,y}). Always signals loop-exit (returns 0, as if WM_QUIT
 * had been posted) on the very first call: there is no real message source
 * behind a headless shim, so any `while (GetMessage(&msg, ...))` pump in
 * a converted binary must terminate here rather than spin forever. */
int __attribute__((stdcall)) shim_GetMessageA(void *lp_msg, void *hwnd, unsigned int filter_min,
                                                unsigned int filter_max) {
    (void)hwnd;
    (void)filter_min;
    (void)filter_max;
    if (lp_msg) {
        unsigned char *p = (unsigned char *)lp_msg;
        for (int i = 0; i < 24; i++) p[i] = 0;
    }
    return 0;
}

int __attribute__((stdcall)) shim_TranslateMessage(const void *msg) {
    (void)msg;
    return 0;
}

long __attribute__((stdcall)) shim_DispatchMessageA(const void *msg) {
    (void)msg;
    return 0;
}
