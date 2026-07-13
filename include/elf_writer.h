/* Generic ELF32 ET_EXEC builder. Has no knowledge of PE - callers hand it a
 * flat list of loadable segments (already laid out: page-aligned vaddr/file
 * offsets) plus an entry point, and it emits a valid ELF32 file. */
#ifndef WINLIFT_ELF_WRITER_H
#define WINLIFT_ELF_WRITER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ELF_MAX_SEGMENTS 64

typedef struct {
    uint32_t vaddr;      /* p_vaddr == p_paddr */
    uint32_t flags;      /* PF_R | PF_W | PF_X */
    uint32_t file_offset; /* page-aligned offset in the output file */
    const uint8_t *data; /* filesz bytes to place at file_offset; may be NULL if filesz==0 */
    uint32_t filesz;
    uint32_t memsz;      /* >= filesz; the remainder is zero-filled at load time */
} elf_segment_t;

typedef struct {
    uint32_t entry;
    int n_segments;
    elf_segment_t segments[ELF_MAX_SEGMENTS];
} elf_image_spec_t;

/* Writes spec as a complete ELF32 ET_EXEC/EM_386 file to path. Segments must
 * already be non-overlapping and sorted by file_offset. Returns false and
 * fills errbuf on failure. */
bool elf_write(const char *path, const elf_image_spec_t *spec, char *errbuf, size_t errbuf_len);

#endif /* WINLIFT_ELF_WRITER_H */
