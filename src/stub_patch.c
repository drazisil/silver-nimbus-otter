#include "stub_patch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elf32_format.h"
#include "shim_abi.h"

#define PAGE_SIZE 0x1000u
#define SHIM_MIN_BASE 0x0F000000u /* must stay clear of any realistic PE ImageBase+SizeOfImage */

extern const unsigned char g_shim_blob[];
extern const unsigned int g_shim_blob_size;

static uint32_t align_up(uint32_t n, uint32_t a) { return (n + a - 1) / a * a; }

static const elf32_ehdr_t *shim_ehdr(void) { return (const elf32_ehdr_t *)g_shim_blob; }

static bool shim_find_symbol(const char *name, uint32_t *out_value) {
    const elf32_ehdr_t *eh = shim_ehdr();
    const elf32_shdr_t *shdrs = (const elf32_shdr_t *)(g_shim_blob + eh->e_shoff);
    for (int i = 0; i < eh->e_shnum; i++) {
        if (shdrs[i].sh_type != SHT_SYMTAB) continue;
        const elf32_sym_t *syms = (const elf32_sym_t *)(g_shim_blob + shdrs[i].sh_offset);
        int n = (int)(shdrs[i].sh_size / sizeof(elf32_sym_t));
        const elf32_shdr_t *strtab = &shdrs[shdrs[i].sh_link];
        const char *strs = (const char *)(g_shim_blob + strtab->sh_offset);
        for (int j = 0; j < n; j++) {
            const char *sym_name = strs + syms[j].st_name;
            if (strcmp(sym_name, name) == 0) {
                *out_value = syms[j].st_value;
                return true;
            }
        }
    }
    return false;
}

/* Writes a little-endian 32-bit value into shim_mutable at the file offset
 * corresponding to the given shim virtual address (found by locating which
 * of the shim's own PT_LOAD segments covers it). */
static bool shim_poke32(uint8_t *shim_mutable, uint32_t vaddr, uint32_t value, char *errbuf, size_t errbuf_len) {
    const elf32_ehdr_t *eh = shim_ehdr();
    const elf32_phdr_t *phdrs = (const elf32_phdr_t *)(g_shim_blob + eh->e_phoff);
    for (int i = 0; i < eh->e_phnum; i++) {
        if (phdrs[i].p_type != PT_LOAD) continue;
        if (vaddr >= phdrs[i].p_vaddr && vaddr + 4 <= phdrs[i].p_vaddr + phdrs[i].p_filesz) {
            uint32_t file_off = phdrs[i].p_offset + (vaddr - phdrs[i].p_vaddr);
            shim_mutable[file_off + 0] = (uint8_t)(value >> 0);
            shim_mutable[file_off + 1] = (uint8_t)(value >> 8);
            shim_mutable[file_off + 2] = (uint8_t)(value >> 16);
            shim_mutable[file_off + 3] = (uint8_t)(value >> 24);
            return true;
        }
    }
    if (errbuf) snprintf(errbuf, errbuf_len, "internal error: shim vaddr 0x%08x not in any shim segment", vaddr);
    return false;
}

/* Casts away const on a pe_rva_to_ptr() result: safe here because callers
 * of stub_patch_apply() are required to have already replaced img->raw with
 * a private, mutable heap copy (see stub_patch.h). */
static uint8_t *mutable_rva_ptr(const pe_image_t *img, uint32_t rva, uint32_t len) {
    return (uint8_t *)pe_rva_to_ptr(img, rva, len);
}

bool stub_patch_apply(pe_image_t *img, elf_image_spec_t *spec, char *errbuf, size_t errbuf_len) {
    if (img->image_base + img->size_of_image > SHIM_MIN_BASE) {
        snprintf(errbuf, errbuf_len,
                 "unsupported: image (base 0x%08x, size 0x%08x) reaches into the shim's reserved "
                 "address range starting at 0x%08x", img->image_base, img->size_of_image, SHIM_MIN_BASE);
        return false;
    }

    /* 1. Resolve and patch every import's IAT slot. */
    for (int i = 0; i < img->n_imports; i++) {
        const pe_import_dll_t *dll = &img->imports[i];
        for (int j = 0; j < dll->n_funcs; j++) {
            const pe_import_func_t *fn = &dll->funcs[j];
            const shim_import_entry_t *entry = shim_lookup_import(dll->dll_name, fn->name);
            if (!entry) {
                snprintf(errbuf, errbuf_len,
                         "unsupported: import '%s!%s' is not implemented by winlift's compatibility shim",
                         dll->dll_name, fn->name);
                return false;
            }
            uint32_t addr;
            if (!shim_find_symbol(entry->shim_symbol, &addr)) {
                snprintf(errbuf, errbuf_len,
                         "internal error: shim symbol '%s' for '%s!%s' missing from shim blob",
                         entry->shim_symbol, dll->dll_name, fn->name);
                return false;
            }
            uint8_t *slot = mutable_rva_ptr(img, fn->iat_rva, 4);
            if (!slot) {
                snprintf(errbuf, errbuf_len, "internal error: IAT slot RVA 0x%08x out of range", fn->iat_rva);
                return false;
            }
            slot[0] = (uint8_t)(addr >> 0);
            slot[1] = (uint8_t)(addr >> 8);
            slot[2] = (uint8_t)(addr >> 16);
            slot[3] = (uint8_t)(addr >> 24);
        }
    }

    /* 2. Make a private, mutable copy of the shim blob (the embedded blob
     * itself is a const array baked into winlift's own binary) so we can
     * poke the per-target PE-entry-point value into it below. */
    uint8_t *shim_mutable = malloc(g_shim_blob_size);
    if (!shim_mutable) {
        snprintf(errbuf, errbuf_len, "out of memory copying shim blob");
        return false;
    }
    memcpy(shim_mutable, g_shim_blob, g_shim_blob_size);

    uint32_t entry_target_addr, start_addr;
    if (!shim_find_symbol("shim_pe_entry_target", &entry_target_addr) ||
        !shim_find_symbol("_start", &start_addr)) {
        snprintf(errbuf, errbuf_len, "internal error: shim blob missing required symbols");
        free(shim_mutable);
        return false;
    }
    uint32_t pe_entry_va = img->image_base + img->entry_point_rva;
    if (!shim_poke32(shim_mutable, entry_target_addr, pe_entry_va, errbuf, errbuf_len)) {
        free(shim_mutable);
        return false;
    }

    /* 3. Append the shim's own PT_LOAD segments (already at fixed,
     * link-time-chosen addresses >= SHIM_MIN_BASE) to the spec, continuing
     * the page-aligned file layout where layout.c left off. */
    uint32_t next_file_off = 0;
    if (spec->n_segments > 0) {
        const elf_segment_t *last = &spec->segments[spec->n_segments - 1];
        next_file_off = align_up(last->file_offset + last->filesz, PAGE_SIZE);
    } else {
        next_file_off = PAGE_SIZE;
    }

    const elf32_ehdr_t *eh = shim_ehdr();
    const elf32_phdr_t *phdrs = (const elf32_phdr_t *)(g_shim_blob + eh->e_phoff);
    for (int i = 0; i < eh->e_phnum; i++) {
        if (phdrs[i].p_type != PT_LOAD) continue;
        if (spec->n_segments >= ELF_MAX_SEGMENTS) {
            snprintf(errbuf, errbuf_len, "internal error: too many segments while embedding shim");
            free(shim_mutable);
            return false;
        }
        elf_segment_t *seg = &spec->segments[spec->n_segments++];
        seg->vaddr = phdrs[i].p_vaddr;
        seg->flags = phdrs[i].p_flags;
        seg->file_offset = next_file_off;
        seg->filesz = phdrs[i].p_filesz;
        seg->memsz = phdrs[i].p_memsz;
        seg->data = phdrs[i].p_filesz > 0 ? (shim_mutable + phdrs[i].p_offset) : NULL;
        next_file_off = align_up(next_file_off + seg->filesz, PAGE_SIZE);
        /* Note: shim_mutable is intentionally leaked for the remaining
         * lifetime of the process - winlift is a short-lived one-shot CLI
         * tool and this buffer must outlive elf_write(), which happens
         * right before exit. */
    }

    /* 4. The ELF's real entry point is the shim's _start, not the PE's -
     * _start initializes shim state, then internally jumps to
     * ImageBase+AddressOfEntryPoint once ready. */
    spec->entry = start_addr;

    return true;
}
