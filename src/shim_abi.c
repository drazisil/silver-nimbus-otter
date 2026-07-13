#include "shim_abi.h"

#include <ctype.h>
#include <string.h>

const shim_import_entry_t g_shim_imports[] = {
    /* kernel32.dll */
    {"kernel32.dll", "DeleteCriticalSection", "shim_DeleteCriticalSection", false},
    {"kernel32.dll", "EnterCriticalSection", "shim_EnterCriticalSection", false},
    {"kernel32.dll", "LeaveCriticalSection", "shim_LeaveCriticalSection", false},
    {"kernel32.dll", "InitializeCriticalSection", "shim_InitializeCriticalSection", false},
    {"kernel32.dll", "FreeLibrary", "shim_FreeLibrary", false},
    {"kernel32.dll", "GetLastError", "shim_GetLastError", false},
    {"kernel32.dll", "SetLastError", "shim_SetLastError", false},
    {"kernel32.dll", "GetModuleHandleA", "shim_GetModuleHandleA", false},
    {"kernel32.dll", "LoadLibraryA", "shim_LoadLibraryA", false},
    {"kernel32.dll", "GetProcAddress", "shim_GetProcAddress", false},
    {"kernel32.dll", "SetUnhandledExceptionFilter", "shim_SetUnhandledExceptionFilter", false},
    {"kernel32.dll", "Sleep", "shim_Sleep", false},
    {"kernel32.dll", "TlsGetValue", "shim_TlsGetValue", false},
    {"kernel32.dll", "VirtualProtect", "shim_VirtualProtect", false},
    {"kernel32.dll", "VirtualQuery", "shim_VirtualQuery", false},
    {"kernel32.dll", "ExitProcess", "shim_ExitProcess", false},
    {"kernel32.dll", "GetStdHandle", "shim_GetStdHandle", false},
    {"kernel32.dll", "CloseHandle", "shim_CloseHandle", false},
    {"kernel32.dll", "WriteFile", "shim_WriteFile", false},
    {"kernel32.dll", "ReadFile", "shim_ReadFile", false},
    {"kernel32.dll", "CreateFileA", "shim_CreateFileA", false},
    {"kernel32.dll", "GetProcessHeap", "shim_GetProcessHeap", false},
    {"kernel32.dll", "HeapAlloc", "shim_HeapAlloc", false},
    {"kernel32.dll", "HeapFree", "shim_HeapFree", false},
    {"kernel32.dll", "HeapReAlloc", "shim_HeapReAlloc", false},
    {"kernel32.dll", "GetCommandLineA", "shim_GetCommandLineA", false},
    {"kernel32.dll", "GetEnvironmentStrings", "shim_GetEnvironmentStrings", false},
    {"kernel32.dll", "GetEnvironmentStringsA", "shim_GetEnvironmentStrings", false},
    {"kernel32.dll", "FreeEnvironmentStringsA", "shim_FreeEnvironmentStringsA", false},
    {"kernel32.dll", "GetStartupInfoA", "shim_GetStartupInfoA", false},

    /* msvcrt.dll */
    {"msvcrt.dll", "__getmainargs", "shim_msvcrt_getmainargs", false},
    {"msvcrt.dll", "__initenv", "shim_data___initenv", true},
    {"msvcrt.dll", "__p__commode", "shim_msvcrt_p_commode", false},
    {"msvcrt.dll", "__p__fmode", "shim_msvcrt_p_fmode", false},
    {"msvcrt.dll", "__set_app_type", "shim_msvcrt_set_app_type", false},
    {"msvcrt.dll", "__setusermatherr", "shim_msvcrt_setusermatherr", false},
    {"msvcrt.dll", "_amsg_exit", "shim_msvcrt_amsg_exit", false},
    {"msvcrt.dll", "_cexit", "shim_msvcrt_cexit", false},
    {"msvcrt.dll", "_initterm", "shim_msvcrt_initterm", false},
    {"msvcrt.dll", "_iob", "shim_iob", true},
    {"msvcrt.dll", "_onexit", "shim_msvcrt_onexit", false},
    {"msvcrt.dll", "abort", "shim_msvcrt_abort", false},
    {"msvcrt.dll", "calloc", "shim_msvcrt_calloc", false},
    {"msvcrt.dll", "exit", "shim_msvcrt_exit", false},
    {"msvcrt.dll", "fprintf", "shim_msvcrt_fprintf", false},
    {"msvcrt.dll", "free", "shim_msvcrt_free", false},
    {"msvcrt.dll", "fwrite", "shim_msvcrt_fwrite", false},
    {"msvcrt.dll", "malloc", "shim_msvcrt_malloc", false},
    {"msvcrt.dll", "memcpy", "shim_msvcrt_memcpy", false},
    {"msvcrt.dll", "realloc", "shim_msvcrt_realloc", false},
    {"msvcrt.dll", "signal", "shim_msvcrt_signal", false},
    {"msvcrt.dll", "strlen", "shim_msvcrt_strlen", false},
    {"msvcrt.dll", "strncmp", "shim_msvcrt_strncmp", false},
    {"msvcrt.dll", "vfprintf", "shim_msvcrt_vfprintf", false},
    /* newer mingw-w64 CRTs import these as accessor functions instead of
     * the plain data symbols above - see runtime/shim_msvcrt.c */
    {"msvcrt.dll", "__p__iob", "shim_msvcrt_p_iob", false},
    {"msvcrt.dll", "__p___initenv", "shim_msvcrt_p_initenv", false},
    {"msvcrt.dll", "__p__acmdln", "shim_msvcrt_p_acmdln", false},
    {"msvcrt.dll", "_ismbblead", "shim_msvcrt_ismbblead", false},
    {"msvcrt.dll", "atexit", "shim_msvcrt_atexit", false},

    /* user32.dll - headless/no-op-backed (see runtime/shim_user32.c): no
     * real window is ever created or rendered, this only makes GUI-subsystem
     * binaries convert and run deterministically. */
    {"user32.dll", "MessageBoxA", "shim_MessageBoxA", false},
    {"user32.dll", "RegisterClassA", "shim_RegisterClassA", false},
    {"user32.dll", "CreateWindowExA", "shim_CreateWindowExA", false},
    {"user32.dll", "ShowWindow", "shim_ShowWindow", false},
    {"user32.dll", "UpdateWindow", "shim_UpdateWindow", false},
    {"user32.dll", "DefWindowProcA", "shim_DefWindowProcA", false},
    {"user32.dll", "GetMessageA", "shim_GetMessageA", false},
    {"user32.dll", "TranslateMessage", "shim_TranslateMessage", false},
    {"user32.dll", "DispatchMessageA", "shim_DispatchMessageA", false},
};
const int g_shim_imports_count = sizeof(g_shim_imports) / sizeof(g_shim_imports[0]);

static bool ci_streq(const char *a, const char *b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return false;
        a++;
        b++;
    }
    return *a == *b;
}

const shim_import_entry_t *shim_lookup_import(const char *dll_name, const char *func_name) {
    for (int i = 0; i < g_shim_imports_count; i++) {
        if (ci_streq(g_shim_imports[i].dll_name, dll_name) &&
            strcmp(g_shim_imports[i].func_name, func_name) == 0) {
            return &g_shim_imports[i];
        }
    }
    return NULL;
}
