/* Parsed in-memory PE representation + parser API. */
#ifndef WINLIFT_PE_IMAGE_H
#define WINLIFT_PE_IMAGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "diagnostics.h"

#define PE_MAX_TLS_CALLBACKS 16

typedef struct {
    char     name[9];
    uint32_t rva;
    uint32_t vsize;
    uint32_t file_off;
    uint32_t fsize;
    uint32_t characteristics;
} pe_section_t;

typedef struct {
    char     name[128];
    uint16_t ordinal;
    bool     by_ordinal;
    uint32_t iat_rva;   /* RVA of the IAT slot to patch */
} pe_import_func_t;

typedef struct {
    char     dll_name[64];
    int      n_funcs;
    int      funcs_cap;
    pe_import_func_t *funcs; /* heap-allocated, grown as the thunk table is walked */
} pe_import_dll_t;

typedef struct {
    uint32_t rva; /* only HIGHLOW relocations are kept */
} pe_reloc_t;

typedef struct {
    uint32_t image_base;
    uint32_t entry_point_rva;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint16_t subsystem;
    uint32_t section_alignment;
    uint32_t file_alignment;

    int n_sections;
    pe_section_t *sections; /* heap-allocated, exactly n_sections entries */

    int n_imports;
    int imports_cap;
    pe_import_dll_t *imports; /* heap-allocated, grown as the import directory is walked */

    int n_relocs;
    pe_reloc_t *relocs; /* heap-allocated, n_relocs entries */

    bool has_tls;
    bool tls_has_callbacks;
    int n_tls_callbacks;
    uint32_t tls_callback_rvas[PE_MAX_TLS_CALLBACKS];

    /* raw file image, kept alive for the lifetime of pe_image_t so
     * section data / string lookups can reference it directly. */
    uint8_t *raw;
    size_t   raw_size;
} pe_image_t;

bool pe_image_load(const char *path, pe_image_t *out, pe_error_t *err);
void pe_image_free(pe_image_t *img);
void pe_dump(const pe_image_t *img, FILE *out);

/* Translate an RVA to a pointer into the raw file image, or NULL if the RVA
 * doesn't fall within any known section (or the header region). */
const uint8_t *pe_rva_to_ptr(const pe_image_t *img, uint32_t rva, uint32_t min_len);

#endif /* WINLIFT_PE_IMAGE_H */
