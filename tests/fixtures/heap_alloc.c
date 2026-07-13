#include <windows.h>

int main(void) {
    HANDLE heap = GetProcessHeap();
    int *p = (int *)HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(int) * 10);
    if (!p) return -1;
    int sum = 0;
    for (int i = 0; i < 10; i++) {
        p[i] = i * 2;
        sum += p[i];
    }
    HeapFree(heap, 0, p);
    return sum; /* 0+2+4+...+18 = 90 */
}
