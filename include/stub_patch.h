/* Resolves a pe_image_t's imports against the embedded shim blob, patches
 * IAT slots to point into it, appends the shim's own PT_LOAD segments, and
 * points the final ELF's entry point at the shim's startup code. */
#ifndef WINLIFT_STUB_PATCH_H
#define WINLIFT_STUB_PATCH_H

#include "pe_image.h"
#include "elf_writer.h"

/* img->raw must already be a private, mutable, heap-owned copy (not the
 * original read-only load) - both PE IAT slots and a copy of the shim blob
 * get bytes rewritten in place / referenced by the resulting segments. */
bool stub_patch_apply(pe_image_t *img, elf_image_spec_t *spec, char *errbuf, size_t errbuf_len);

#endif /* WINLIFT_STUB_PATCH_H */
