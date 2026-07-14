#include "import_table.h"

#include <stdlib.h>
#include <string.h>

#include "pe_format.h"

bool pe_parse_relocs_dir(pe_image_t *img, uint32_t dir_rva, uint32_t dir_size, pe_error_t *err) {
    if (dir_rva == 0 || dir_size == 0) return true;

    /* Count first so we can allocate exactly once. */
    uint32_t consumed = 0;
    int count = 0;
    while (consumed < dir_size) {
        const uint8_t *bp = pe_rva_to_ptr(img, dir_rva + consumed, sizeof(pe_base_relocation_block_t));
        if (!bp) {
            pe_error_set(err, PE_ERR_MALFORMED, "malformed PE: base relocation block out of range");
            return false;
        }
        pe_base_relocation_block_t blk;
        memcpy(&blk, bp, sizeof(blk));
        if (blk.SizeOfBlock < sizeof(blk)) {
            pe_error_set(err, PE_ERR_MALFORMED, "malformed PE: base relocation block size too small");
            return false;
        }
        count += (int)((blk.SizeOfBlock - sizeof(blk)) / 2);
        consumed += blk.SizeOfBlock;
    }

    if (count == 0) return true;
    img->relocs = malloc((size_t)count * sizeof(pe_reloc_t));
    if (!img->relocs) {
        pe_error_set(err, PE_ERR_MALFORMED, "out of memory parsing relocations");
        return false;
    }

    consumed = 0;
    int idx = 0;
    while (consumed < dir_size) {
        const uint8_t *bp = pe_rva_to_ptr(img, dir_rva + consumed, sizeof(pe_base_relocation_block_t));
        pe_base_relocation_block_t blk;
        memcpy(&blk, bp, sizeof(blk));
        int n_entries = (int)((blk.SizeOfBlock - sizeof(blk)) / 2);
        const uint8_t *entries = pe_rva_to_ptr(img, dir_rva + consumed + sizeof(blk), (uint32_t)n_entries * 2);
        if (!entries) {
            pe_error_set(err, PE_ERR_MALFORMED, "malformed PE: base relocation entries out of range");
            return false;
        }
        for (int i = 0; i < n_entries; i++) {
            uint16_t e;
            memcpy(&e, entries + i * 2, 2);
            uint16_t type = e >> 12;
            uint16_t offset = e & 0x0FFF;
            if (type == PE_REL_BASED_ABSOLUTE) continue; /* padding no-op */
            if (type == PE_REL_BASED_HIGHLOW) {
                img->relocs[idx++].rva = blk.VirtualAddress + offset;
            }
            /* Other relocation types don't occur in i386 PE output; ignore. */
        }
        consumed += blk.SizeOfBlock;
    }
    img->n_relocs = idx;
    return true;
}

bool pe_parse_tls_dir(pe_image_t *img, uint32_t dir_rva, uint32_t dir_size, pe_error_t *err) {
    if (dir_rva == 0 || dir_size == 0) {
        img->has_tls = false;
        return true;
    }
    const uint8_t *p = pe_rva_to_ptr(img, dir_rva, sizeof(pe_tls_directory32_t));
    if (!p) {
        pe_error_set(err, PE_ERR_MALFORMED, "malformed PE: TLS directory out of range");
        return false;
    }
    pe_tls_directory32_t tls;
    memcpy(&tls, p, sizeof(tls));
    img->has_tls = true;
    img->tls_has_callbacks = (tls.AddressOfCallBacks != 0);
    if (!img->tls_has_callbacks) return true;

    /* AddressOfCallBacks points to a VA (not RVA) array of VA function
     * pointers, terminated by a NULL entry. Since we keep ImageBase fixed
     * as the ELF load address (see layout.c), VA == RVA + image_base, so
     * we can resolve and faithfully re-execute these callbacks at process
     * start exactly like the real PE loader would (DLL_PROCESS_ATTACH)
     * rather than rejecting - this callback array is emitted by default by
     * the MinGW-w64 CRT for lazy TLS init, so essentially every real-world
     * binary has one. */
    if (tls.AddressOfCallBacks < img->image_base) {
        pe_error_set(err, PE_ERR_MALFORMED, "malformed PE: TLS AddressOfCallBacks below ImageBase");
        return false;
    }
    uint32_t arr_rva = tls.AddressOfCallBacks - img->image_base;

    for (int i = 0; ; i++) {
        const uint8_t *ep = pe_rva_to_ptr(img, arr_rva + (uint32_t)i * 4, 4);
        if (!ep) {
            pe_error_set(err, PE_ERR_MALFORMED, "malformed PE: TLS callback array out of range");
            return false;
        }
        uint32_t cb_va;
        memcpy(&cb_va, ep, 4);
        if (cb_va == 0) break;
        if (cb_va < img->image_base) {
            pe_error_set(err, PE_ERR_MALFORMED, "malformed PE: TLS callback VA below ImageBase");
            return false;
        }
        if (img->n_tls_callbacks >= PE_MAX_TLS_CALLBACKS) {
            pe_error_set(err, PE_ERR_MALFORMED, "malformed PE: too many TLS callbacks");
            return false;
        }
        img->tls_callback_rvas[img->n_tls_callbacks++] = cb_va - img->image_base;
    }
    return true;
}
