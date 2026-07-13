/* Bridges pe_image_t -> elf_image_spec_t: maps PE sections onto page-aligned
 * ELF PT_LOAD segments at the PE's own ImageBase (see layout.c for why base
 * relocations don't need to be applied under this strategy). */
#ifndef WINLIFT_LAYOUT_H
#define WINLIFT_LAYOUT_H

#include "pe_image.h"
#include "elf_writer.h"

bool pe_layout_to_elf_spec(const pe_image_t *img, elf_image_spec_t *out_spec,
                            char *errbuf, size_t errbuf_len);

#endif /* WINLIFT_LAYOUT_H */
