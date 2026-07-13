#include "pe_image.h"

#include <stdio.h>

void pe_dump(const pe_image_t *img, FILE *out) {
    fprintf(out, "ImageBase:        0x%08x\n", img->image_base);
    fprintf(out, "EntryPoint RVA:   0x%08x (VA 0x%08x)\n",
            img->entry_point_rva, img->image_base + img->entry_point_rva);
    fprintf(out, "SizeOfImage:      0x%08x\n", img->size_of_image);
    fprintf(out, "SizeOfHeaders:    0x%08x\n", img->size_of_headers);
    fprintf(out, "Subsystem:        %u (%s)\n", img->subsystem,
            img->subsystem == 3 ? "WINDOWS_CUI" : img->subsystem == 2 ? "WINDOWS_GUI" : "other");
    fprintf(out, "SectionAlignment: 0x%08x\n", img->section_alignment);
    fprintf(out, "FileAlignment:    0x%08x\n", img->file_alignment);
    fprintf(out, "TLS present:      %s (%d callback%s)\n", img->has_tls ? "yes" : "no",
            img->n_tls_callbacks, img->n_tls_callbacks == 1 ? "" : "s");
    fprintf(out, "Base relocations: %d\n", img->n_relocs);

    fprintf(out, "\nSections (%d):\n", img->n_sections);
    fprintf(out, "  %-9s %10s %10s %10s %10s  %s\n", "Name", "RVA", "VSize", "FileOff", "FSize", "Flags");
    for (int i = 0; i < img->n_sections; i++) {
        const pe_section_t *s = &img->sections[i];
        char flags[4] = "---";
        if (s->characteristics & 0x40000000u) flags[0] = 'R';
        if (s->characteristics & 0x80000000u) flags[1] = 'W';
        if (s->characteristics & 0x20000000u) flags[2] = 'X';
        fprintf(out, "  %-9s 0x%08x 0x%08x 0x%08x 0x%08x  %s\n",
                s->name, s->rva, s->vsize, s->file_off, s->fsize, flags);
    }

    fprintf(out, "\nImports (%d DLLs):\n", img->n_imports);
    for (int i = 0; i < img->n_imports; i++) {
        const pe_import_dll_t *dll = &img->imports[i];
        fprintf(out, "  %s (%d functions)\n", dll->dll_name, dll->n_funcs);
        for (int j = 0; j < dll->n_funcs; j++) {
            const pe_import_func_t *fn = &dll->funcs[j];
            fprintf(out, "    %-40s  IAT RVA 0x%08x\n", fn->name, fn->iat_rva);
        }
    }
}
