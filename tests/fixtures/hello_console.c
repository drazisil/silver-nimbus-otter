#include <windows.h>

int main(void) {
    const char msg[] = "hello from WriteFile\n";
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written;
    WriteFile(h, msg, sizeof(msg) - 1, &written, NULL);
    return (int)written;
}
