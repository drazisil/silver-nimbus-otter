#include "import_table.h"

#include <stdio.h>
#include <string.h>

#include "pe_format.h"

static bool read_c_string(const pe_image_t *img, uint32_t rva, char *out, size_t out_cap) {
    /* We don't know the string length up front; probe byte-by-byte via
     * pe_rva_to_ptr(1) since RVA->ptr already bounds-checks the section. */
    size_t i = 0;
    for (; i + 1 < out_cap; i++) {
        const uint8_t *p = pe_rva_to_ptr(img, rva + (uint32_t)i, 1);
        if (!p) return false;
        out[i] = (char)*p;
        if (out[i] == '\0') return true;
    }
    out[out_cap - 1] = '\0';
    return true;
}

static bool parse_one_dll(pe_image_t *img, const pe_import_descriptor_t *desc, pe_error_t *err) {
    if (img->n_imports >= PE_MAX_DLLS) {
        pe_error_set(err, PE_ERR_TOO_MANY_IMPORTS, "malformed PE: too many imported DLLs");
        return false;
    }
    pe_import_dll_t *dll = &img->imports[img->n_imports];
    memset(dll, 0, sizeof(*dll));

    if (!read_c_string(img, desc->Name, dll->dll_name, sizeof(dll->dll_name))) {
        pe_error_set(err, PE_ERR_MALFORMED, "malformed PE: import DLL name RVA out of range");
        return false;
    }

    if (desc->ForwarderChain != 0xFFFFFFFFu && desc->ForwarderChain != 0) {
        pe_error_set(err, PE_ERR_FORWARDED_IMPORT,
                     "unsupported: forwarded imports not supported (dll '%s')", dll->dll_name);
        return false;
    }

    uint32_t thunk_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
    uint32_t iat_rva = desc->FirstThunk;

    for (int i = 0; ; i++) {
        const uint8_t *tp = pe_rva_to_ptr(img, thunk_rva + (uint32_t)i * 4, 4);
        if (!tp) {
            pe_error_set(err, PE_ERR_MALFORMED,
                         "malformed PE: thunk table for '%s' out of range", dll->dll_name);
            return false;
        }
        uint32_t thunk;
        memcpy(&thunk, tp, 4);
        if (thunk == 0) break;

        if (dll->n_funcs >= PE_MAX_FUNCS) {
            pe_error_set(err, PE_ERR_TOO_MANY_IMPORTS,
                         "malformed PE: too many imports from '%s'", dll->dll_name);
            return false;
        }
        pe_import_func_t *fn = &dll->funcs[dll->n_funcs];
        memset(fn, 0, sizeof(*fn));
        fn->iat_rva = iat_rva + (uint32_t)i * 4;

        if (thunk & PE_ORDINAL_FLAG32) {
            fn->by_ordinal = true;
            fn->ordinal = (uint16_t)(thunk & 0xFFFF);
            snprintf(fn->name, sizeof(fn->name), "#%u", fn->ordinal);
            pe_error_set(err, PE_ERR_ORDINAL_IMPORT,
                         "unsupported: import by ordinal not supported (%s ordinal %u) - "
                         "rebuild with default settings which import by name",
                         dll->dll_name, fn->ordinal);
            return false;
        }

        const uint8_t *namep = pe_rva_to_ptr(img, thunk, sizeof(pe_import_by_name_t));
        if (!namep) {
            pe_error_set(err, PE_ERR_MALFORMED,
                         "malformed PE: import-by-name RVA out of range in '%s'", dll->dll_name);
            return false;
        }
        pe_import_by_name_t ibn;
        memcpy(&ibn, namep, sizeof(ibn));
        if (!read_c_string(img, thunk + (uint32_t)sizeof(pe_import_by_name_t), fn->name, sizeof(fn->name))) {
            pe_error_set(err, PE_ERR_MALFORMED,
                         "malformed PE: import function name out of range in '%s'", dll->dll_name);
            return false;
        }

        dll->n_funcs++;
    }

    img->n_imports++;
    return true;
}

bool pe_parse_imports_dir(pe_image_t *img, uint32_t dir_rva, uint32_t dir_size, pe_error_t *err) {
    (void)dir_size;
    if (dir_rva == 0) return true; /* no imports */

    for (int i = 0; ; i++) {
        const uint8_t *p = pe_rva_to_ptr(img, dir_rva + (uint32_t)i * sizeof(pe_import_descriptor_t),
                                          sizeof(pe_import_descriptor_t));
        if (!p) {
            pe_error_set(err, PE_ERR_MALFORMED, "malformed PE: import directory out of range");
            return false;
        }
        pe_import_descriptor_t desc;
        memcpy(&desc, p, sizeof(desc));
        if (desc.OriginalFirstThunk == 0 && desc.TimeDateStamp == 0 &&
            desc.ForwarderChain == 0 && desc.Name == 0 && desc.FirstThunk == 0) {
            break; /* terminator entry */
        }
        if (!parse_one_dll(img, &desc, err)) return false;
    }
    return true;
}

