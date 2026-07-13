#include "elf_writer.h"

#include <stdio.h>
#include <string.h>

#include "elf32_format.h"

static void seterr(char *errbuf, size_t errbuf_len, const char *msg) {
    if (errbuf && errbuf_len > 0) snprintf(errbuf, errbuf_len, "%s", msg);
}

bool elf_write(const char *path, const elf_image_spec_t *spec, char *errbuf, size_t errbuf_len) {
    if (spec->n_segments <= 0 || spec->n_segments > ELF_MAX_SEGMENTS) {
        seterr(errbuf, errbuf_len, "internal error: bad segment count");
        return false;
    }

    uint32_t phoff = sizeof(elf32_ehdr_t);
    uint32_t phdrs_end = phoff + (uint32_t)spec->n_segments * sizeof(elf32_phdr_t);

    /* Segments are not required to map the ELF/program headers into memory
     * (this is a static, non-PIE ET_EXEC with a hardcoded e_entry - nothing
     * needs to read its own ELF header at runtime), but no segment's file
     * range may overlap the header region we're about to write at the
     * start of the file. */
    for (int i = 0; i < spec->n_segments; i++) {
        if (spec->segments[i].filesz > 0 && spec->segments[i].file_offset < phdrs_end) {
            seterr(errbuf, errbuf_len, "internal error: segment file range overlaps ELF headers");
            return false;
        }
    }

    FILE *f = fopen(path, "wb");
    if (!f) {
        seterr(errbuf, errbuf_len, "cannot open output file for writing");
        return false;
    }

    elf32_ehdr_t eh;
    memset(&eh, 0, sizeof(eh));
    eh.e_ident[0] = ELFMAG0;
    eh.e_ident[1] = ELFMAG1;
    eh.e_ident[2] = ELFMAG2;
    eh.e_ident[3] = ELFMAG3;
    eh.e_ident[4] = ELFCLASS32;
    eh.e_ident[5] = ELFDATA2LSB;
    eh.e_ident[6] = EV_CURRENT;
    eh.e_ident[7] = ELFOSABI_SYSV;
    eh.e_type = ET_EXEC;
    eh.e_machine = EM_386;
    eh.e_version = EV_CURRENT;
    eh.e_entry = spec->entry;
    eh.e_phoff = phoff;
    eh.e_shoff = 0;
    eh.e_flags = 0;
    eh.e_ehsize = sizeof(elf32_ehdr_t);
    eh.e_phentsize = sizeof(elf32_phdr_t);
    eh.e_phnum = (uint16_t)spec->n_segments;
    eh.e_shentsize = 0;
    eh.e_shnum = 0;
    eh.e_shstrndx = 0;

    if (fwrite(&eh, sizeof(eh), 1, f) != 1) goto write_fail;

    for (int i = 0; i < spec->n_segments; i++) {
        const elf_segment_t *s = &spec->segments[i];
        elf32_phdr_t ph;
        ph.p_type = PT_LOAD;
        ph.p_offset = s->file_offset;
        ph.p_vaddr = s->vaddr;
        ph.p_paddr = s->vaddr;
        ph.p_filesz = s->filesz;
        ph.p_memsz = s->memsz;
        ph.p_flags = s->flags;
        ph.p_align = 0x1000;
        if (fwrite(&ph, sizeof(ph), 1, f) != 1) goto write_fail;
    }

    uint32_t cur = phdrs_end;
    for (int i = 0; i < spec->n_segments; i++) {
        const elf_segment_t *s = &spec->segments[i];
        if (s->filesz == 0) continue;
        if (s->file_offset < cur) {
            seterr(errbuf, errbuf_len, "internal error: overlapping segment file ranges");
            fclose(f);
            return false;
        }
        if (s->file_offset > cur) {
            /* pad with zeros up to this segment's file offset */
            static const uint8_t zero_page[0x1000] = {0};
            uint32_t pad = s->file_offset - cur;
            while (pad > 0) {
                uint32_t chunk = pad > sizeof(zero_page) ? (uint32_t)sizeof(zero_page) : pad;
                if (fwrite(zero_page, 1, chunk, f) != chunk) goto write_fail;
                pad -= chunk;
            }
            cur = s->file_offset;
        }
        if (s->data) {
            if (fwrite(s->data, 1, s->filesz, f) != s->filesz) goto write_fail;
        } else {
            seterr(errbuf, errbuf_len, "internal error: segment has filesz but no data");
            fclose(f);
            return false;
        }
        cur += s->filesz;
    }

    fclose(f);
    return true;

write_fail:
    seterr(errbuf, errbuf_len, "short write to output file");
    fclose(f);
    return false;
}
