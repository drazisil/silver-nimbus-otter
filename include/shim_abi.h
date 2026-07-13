/* Host-side (winlift, 64-bit) table of every (dll, function) pair winlift
 * knows how to satisfy, and which symbol in the precompiled shim blob
 * implements it. This is the single source of truth for scope: anything a
 * PE imports that isn't in this table gets a hard rejection (see
 * stub_patch.c) rather than a silent no-op. */
#ifndef WINLIFT_SHIM_ABI_H
#define WINLIFT_SHIM_ABI_H

#include <stdbool.h>

typedef struct {
    const char *dll_name;    /* matched case-insensitively */
    const char *func_name;   /* matched case-sensitively, as PE import names are */
    const char *shim_symbol; /* symbol name to resolve in the compiled shim blob */
    bool is_data;             /* true for imports that are addresses of data (not code) */
} shim_import_entry_t;

extern const shim_import_entry_t g_shim_imports[];
extern const int g_shim_imports_count;

const shim_import_entry_t *shim_lookup_import(const char *dll_name, const char *func_name);

#endif /* WINLIFT_SHIM_ABI_H */
