#include <windows.h>

/* Exercises argv/GetCommandLineA plumbing without pulling in MinGW's stdio
 * dependency chain (printf/fprintf transitively import wide-char/locale
 * functions well beyond this milestone's scope - see M1c's discovery of
 * that dependency graph). Sums the integer value of argv[1..] and returns
 * it, and separately writes GetCommandLineA()'s result to stdout so the
 * test harness can check both. */

static void write_str(HANDLE h, const char *s) {
    DWORD len = 0;
    while (s[len]) len++;
    DWORD written;
    WriteFile(h, s, len, &written, NULL);
}

static int atoi_simple(const char *s) {
    int v = 0, neg = 0;
    if (*s == '-') { neg = 1; s++; }
    while (*s >= '0' && *s <= '9') v = v * 10 + (*s++ - '0');
    return neg ? -v : v;
}

int main(int argc, char **argv) {
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    write_str(out, "cmdline=");
    write_str(out, GetCommandLineA());
    write_str(out, "\n");

    int sum = 0;
    for (int i = 1; i < argc; i++) sum += atoi_simple(argv[i]);
    return sum;
}
