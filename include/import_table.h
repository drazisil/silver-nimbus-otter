/* Import directory / base relocation parsing, called from pe_reader.c. */
#ifndef WINLIFT_IMPORT_TABLE_H
#define WINLIFT_IMPORT_TABLE_H

#include "pe_image.h"

bool pe_parse_imports_dir(pe_image_t *img, uint32_t dir_rva, uint32_t dir_size, pe_error_t *err);
bool pe_parse_relocs_dir(pe_image_t *img, uint32_t dir_rva, uint32_t dir_size, pe_error_t *err);
bool pe_parse_tls_dir(pe_image_t *img, uint32_t dir_rva, uint32_t dir_size, pe_error_t *err);

#endif /* WINLIFT_IMPORT_TABLE_H */
