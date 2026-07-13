#include "layout.h"

#include <stdio.h>

#include "elf32_format.h"
#include "pe_format.h"

#define PAGE_SIZE 0x1000u

static uint32_t align_up(uint32_t n, uint32_t a) {
    return (n + a - 1) / a * a;
}

static uint32_t pe_section_flags_to_elf(uint32_t characteristics) {
    uint32_t flags = 0;
    if (characteristics & PE_SCN_MEM_READ) flags |= PF_R;
    if (characteristics & PE_SCN_MEM_WRITE) flags |= PF_W;
    if (characteristics & PE_SCN_MEM_EXECUTE) flags |= PF_X;
    if (flags == 0) flags = PF_R; /* be defensive: never emit a segment with no perms */
    return flags;
}

/* Keeps the PE's own ImageBase as the ELF load address for every section.
 * This is what lets us copy the original x86 code through unmodified: since
 * the code isn't recompiled, any absolute addresses baked into it (jump
 * targets, literal pointers) are only correct if the image loads at exactly
 * the address the compiler/linker assumed. It also means base relocations
 * never need to be applied - they were only ever needed if the loader
 * picked a *different* base than the one they were generated against, and
 * here it never does. (pe_relocs.c still parses them, purely so a future
 * milestone could support rebasing if a preferred base ever conflicts with
 * something on the target system.) */
bool pe_layout_to_elf_spec(const pe_image_t *img, elf_image_spec_t *out_spec,
                            char *errbuf, size_t errbuf_len) {
    if (img->n_sections <= 0 || img->n_sections + 1 > ELF_MAX_SEGMENTS) {
        if (errbuf) snprintf(errbuf, errbuf_len, "unsupported: %d sections (0 or too many)", img->n_sections);
        return false;
    }
    if (img->image_base % PAGE_SIZE != 0) {
        if (errbuf) snprintf(errbuf, errbuf_len, "unsupported: ImageBase 0x%08x is not page-aligned", img->image_base);
        return false;
    }

    out_spec->n_segments = 0;
    out_spec->entry = img->image_base + img->entry_point_rva;

    /* ELF headers occupy file offset 0..phdrs_end (see elf_writer.c); the
     * first segment we emit starts at the next page boundary, which is
     * always >= that since a handful of program headers fit comfortably
     * inside one page. */
    uint32_t cur_file_off = PAGE_SIZE;

    /* Map the PE header region itself (RVA 0..SizeOfHeaders) too, not just
     * the sections: real Windows PE loaders always do this, and CRT startup
     * code sometimes reads its own headers directly (e.g. re-checking the
     * 'MZ'/DOS-header magic at ImageBase as a sanity check) - discovered by
     * hitting exactly that crash against a real MinGW-compiled binary. */
    {
        elf_segment_t *seg = &out_spec->segments[out_spec->n_segments++];
        seg->vaddr = img->image_base;
        seg->flags = PF_R;
        seg->file_offset = cur_file_off;
        seg->filesz = img->size_of_headers;
        seg->memsz = img->size_of_headers;
        seg->data = img->size_of_headers > 0 ? img->raw : NULL;
        cur_file_off = align_up(cur_file_off + seg->filesz, PAGE_SIZE);
    }

    for (int i = 0; i < img->n_sections; i++) {
        const pe_section_t *s = &img->sections[i];

        if (s->rva % PAGE_SIZE != 0) {
            if (errbuf) snprintf(errbuf, errbuf_len,
                                  "unsupported: section '%s' RVA 0x%08x is not page-aligned",
                                  s->name, s->rva);
            return false;
        }

        elf_segment_t *seg = &out_spec->segments[out_spec->n_segments++];
        seg->vaddr = img->image_base + s->rva;
        seg->flags = pe_section_flags_to_elf(s->characteristics);
        seg->file_offset = cur_file_off;
        seg->filesz = s->fsize; /* raw bytes from the PE file, copied as-is */
        seg->memsz = s->vsize > s->fsize ? s->vsize : s->fsize; /* zero-fill tail (e.g. .bss) */
        seg->data = s->fsize > 0 ? (img->raw + s->file_off) : NULL;

        cur_file_off = align_up(cur_file_off + seg->filesz, PAGE_SIZE);
    }

    return true;
}
