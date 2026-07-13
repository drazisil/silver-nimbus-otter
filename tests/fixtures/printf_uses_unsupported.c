#include <stdio.h>

/* printf (unlike the WriteFile-based fixtures) pulls in MinGW's wide-char/
 * locale machinery (GetModuleHandleW, IsDBCSLeadByteEx, MultiByteToWideChar,
 * etc. - the exact one varies by mingw-w64 version) - functions outside
 * winlift's supported scope. This fixture exists purely to exercise the
 * "unsupported import" rejection path with a real binary rather than a
 * hand-crafted one. */
int main(void) {
    printf("hello %s\n", "world");
    return 0;
}
