#include <windows.h>

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    WNDCLASSA wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "WinliftM2Window";

    if (!RegisterClassA(&wc)) return 1;

    HWND hwnd = CreateWindowExA(0, "WinliftM2Window", "winlift M2", WS_OVERLAPPEDWINDOW,
                                 CW_USEDEFAULT, CW_USEDEFAULT, 200, 100,
                                 NULL, NULL, hInstance, NULL);
    if (!hwnd) return 2;

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    /* Headless shim always signals loop-exit on the first GetMessage call
     * (see runtime/shim_user32.c) - this proves that termination actually
     * happens rather than hanging, not that any messages were pumped. */
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 88;
}
