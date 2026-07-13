#include "pe_image.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pe_format.h"
#include "diagnostics.h"
#include "import_table.h"

static bool read_whole_file(const char *path, uint8_t **out_buf, size_t *out_size, pe_error_t *err) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        pe_error_set(err, PE_ERR_OPEN, "cannot open '%s'", path);
        return false;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        pe_error_set(err, PE_ERR_OPEN, "cannot seek '%s'", path);
        fclose(f);
        return false;
    }
    long size = ftell(f);
    if (size < 0) {
        pe_error_set(err, PE_ERR_OPEN, "cannot determine size of '%s'", path);
        fclose(f);
        return false;
    }
    rewind(f);
    uint8_t *buf = malloc((size_t)size);
    if (!buf) {
        pe_error_set(err, PE_ERR_OPEN, "out of memory reading '%s'", path);
        fclose(f);
        return false;
    }
    if (size > 0 && fread(buf, 1, (size_t)size, f) != (size_t)size) {
        pe_error_set(err, PE_ERR_TRUNCATED, "short read on '%s'", path);
        free(buf);
        fclose(f);
        return false;
    }
    fclose(f);
    *out_buf = buf;
    *out_size = (size_t)size;
    return true;
}

const uint8_t *pe_rva_to_ptr(const pe_image_t *img, uint32_t rva, uint32_t min_len) {
    /* Header region: RVA == file offset for the first SizeOfHeaders bytes. */
    if (rva < img->size_of_headers) {
        if ((uint64_t)rva + min_len > img->size_of_headers) return NULL;
        if ((uint64_t)rva + min_len > img->raw_size) return NULL;
        return img->raw + rva;
    }
    for (int i = 0; i < img->n_sections; i++) {
        const pe_section_t *s = &img->sections[i];
        if (rva >= s->rva && (uint64_t)rva + min_len <= (uint64_t)s->rva + s->vsize) {
            uint32_t within = rva - s->rva;
            if (within >= s->fsize) {
                /* Falls in the zero-filled tail (e.g. .bss) - no raw bytes. */
                return NULL;
            }
            if ((uint64_t)within + min_len > s->fsize) return NULL;
            if ((uint64_t)s->file_off + within + min_len > img->raw_size) return NULL;
            return img->raw + s->file_off + within;
        }
    }
    return NULL;
}

static bool parse_sections(pe_image_t *img, const uint8_t *sec_ptr, int n_sections, pe_error_t *err) {
    if (n_sections < 0 || n_sections > PE_MAX_SECTIONS) {
        pe_error_set(err, PE_ERR_TOO_MANY_SECTIONS,
                     "malformed PE: NumberOfSections=%d out of range", n_sections);
        return false;
    }
    for (int i = 0; i < n_sections; i++) {
        pe_section_header_t sh;
        memcpy(&sh, sec_ptr + (size_t)i * sizeof(sh), sizeof(sh));

        pe_section_t *s = &img->sections[i];
        memcpy(s->name, sh.Name, 8);
        s->name[8] = '\0';
        s->rva = sh.VirtualAddress;
        s->vsize = sh.VirtualSize ? sh.VirtualSize : sh.SizeOfRawData;
        s->file_off = sh.PointerToRawData;
        s->fsize = sh.SizeOfRawData;
        s->characteristics = sh.Characteristics;

        if ((uint64_t)s->file_off + s->fsize > img->raw_size) {
            pe_error_set(err, PE_ERR_MALFORMED,
                         "malformed PE: section '%s' raw data extends past EOF", s->name);
            return false;
        }
    }
    img->n_sections = n_sections;
    return true;
}

bool pe_image_load(const char *path, pe_image_t *out, pe_error_t *err) {
    memset(out, 0, sizeof(*out));

    if (!read_whole_file(path, &out->raw, &out->raw_size, err)) return false;

    if (out->raw_size < sizeof(pe_dos_header_t)) {
        pe_error_set(err, PE_ERR_TRUNCATED, "file too small to contain a DOS header");
        goto fail;
    }

    pe_dos_header_t dos;
    memcpy(&dos, out->raw, sizeof(dos));
    if (dos.e_magic != PE_DOS_MAGIC) {
        pe_error_set(err, PE_ERR_BAD_DOS_MAGIC,
                     "bad DOS header magic 0x%04x (expected 'MZ')", dos.e_magic);
        goto fail;
    }
    if (dos.e_lfanew < 0 || (uint64_t)dos.e_lfanew + 4 > out->raw_size) {
        pe_error_set(err, PE_ERR_MALFORMED, "malformed PE: e_lfanew out of range");
        goto fail;
    }

    uint32_t nt_sig;
    memcpy(&nt_sig, out->raw + dos.e_lfanew, 4);
    if (nt_sig != PE_NT_SIGNATURE) {
        pe_error_set(err, PE_ERR_BAD_NT_SIGNATURE,
                     "bad NT signature 0x%08x (expected \"PE\\0\\0\")", nt_sig);
        goto fail;
    }

    size_t coff_off = (size_t)dos.e_lfanew + 4;
    if (coff_off + sizeof(pe_coff_header_t) > out->raw_size) {
        pe_error_set(err, PE_ERR_TRUNCATED, "file truncated: missing COFF header");
        goto fail;
    }
    pe_coff_header_t coff;
    memcpy(&coff, out->raw + coff_off, sizeof(coff));

    if (coff.Machine != PE_MACHINE_I386) {
        pe_error_set(err, PE_ERR_NOT_I386,
                     "unsupported machine type 0x%04x (only IMAGE_FILE_MACHINE_I386 / 0x014c is supported)",
                     coff.Machine);
        goto fail;
    }
    if (coff.Characteristics & PE_FILE_DLL) {
        pe_error_set(err, PE_ERR_IS_DLL, "unsupported: DLLs not supported, only EXE");
        goto fail;
    }
    if (!(coff.Characteristics & PE_FILE_EXECUTABLE)) {
        pe_error_set(err, PE_ERR_NOT_EXECUTABLE, "unsupported: file is not marked executable");
        goto fail;
    }

    size_t opthdr_off = coff_off + sizeof(pe_coff_header_t);
    if (coff.SizeOfOptionalHeader < sizeof(pe_optional_header32_t) ||
        opthdr_off + sizeof(pe_optional_header32_t) > out->raw_size) {
        pe_error_set(err, PE_ERR_TRUNCATED, "file truncated or optional header too small");
        goto fail;
    }
    pe_optional_header32_t opt;
    memcpy(&opt, out->raw + opthdr_off, sizeof(opt));

    if (opt.Magic == PE_OPTHDR64_MAGIC) {
        pe_error_set(err, PE_ERR_PE32PLUS,
                     "unsupported: 64-bit PE (PE32+) not supported, this tool targets 32-bit PE32 only");
        goto fail;
    }
    if (opt.Magic != PE_OPTHDR32_MAGIC) {
        pe_error_set(err, PE_ERR_BAD_OPTHDR_MAGIC,
                     "unsupported: unrecognized optional header magic 0x%04x", opt.Magic);
        goto fail;
    }
    if (opt.Subsystem != PE_SUBSYSTEM_WINDOWS_CUI && opt.Subsystem != PE_SUBSYSTEM_WINDOWS_GUI) {
        pe_error_set(err, PE_ERR_UNSUPPORTED_SUBSYSTEM,
                     "unsupported: subsystem %u not supported (only Windows console/CUI=3 or GUI=2)",
                     opt.Subsystem);
        goto fail;
    }
    if (opt.NumberOfRvaAndSizes > PE_NUM_DIRECTORIES) {
        pe_error_set(err, PE_ERR_MALFORMED, "malformed PE: NumberOfRvaAndSizes out of range");
        goto fail;
    }
    if (opt.NumberOfRvaAndSizes > PE_DIR_COM_DESCRIPTOR &&
        opt.DataDirectory[PE_DIR_COM_DESCRIPTOR].Size != 0) {
        pe_error_set(err, PE_ERR_HAS_DOTNET, "unsupported: managed (.NET) executables not supported");
        goto fail;
    }
    if (opt.NumberOfRvaAndSizes > PE_DIR_DELAY_IMPORT &&
        opt.DataDirectory[PE_DIR_DELAY_IMPORT].Size != 0) {
        pe_error_set(err, PE_ERR_DELAY_IMPORTS, "unsupported: delay-loaded imports not supported");
        goto fail;
    }

    out->image_base = opt.ImageBase;
    out->entry_point_rva = opt.AddressOfEntryPoint;
    out->size_of_image = opt.SizeOfImage;
    out->size_of_headers = opt.SizeOfHeaders;
    out->subsystem = opt.Subsystem;
    out->section_alignment = opt.SectionAlignment;
    out->file_alignment = opt.FileAlignment;

    if (out->image_base == 0) {
        pe_error_set(err, PE_ERR_IMAGEBASE_CONFLICT, "unsupported: ImageBase is 0");
        goto fail;
    }

    size_t sec_off = opthdr_off + coff.SizeOfOptionalHeader;
    if (sec_off + (size_t)coff.NumberOfSections * sizeof(pe_section_header_t) > out->raw_size) {
        pe_error_set(err, PE_ERR_TRUNCATED, "file truncated: section table extends past EOF");
        goto fail;
    }
    if (!parse_sections(out, out->raw + sec_off, coff.NumberOfSections, err)) goto fail;

    /* Stash the data directory in a place pe_imports.c/pe_relocs.c can reach:
     * we re-derive RVA/size for imports/relocs/tls directly here since
     * pe_image_t doesn't carry the raw directory array. */
    uint32_t import_dir_rva = 0, import_dir_size = 0;
    uint32_t reloc_dir_rva = 0, reloc_dir_size = 0;
    uint32_t tls_dir_rva = 0, tls_dir_size = 0;
    if (opt.NumberOfRvaAndSizes > PE_DIR_IMPORT) {
        import_dir_rva = opt.DataDirectory[PE_DIR_IMPORT].VirtualAddress;
        import_dir_size = opt.DataDirectory[PE_DIR_IMPORT].Size;
    }
    if (opt.NumberOfRvaAndSizes > PE_DIR_BASERELOC) {
        reloc_dir_rva = opt.DataDirectory[PE_DIR_BASERELOC].VirtualAddress;
        reloc_dir_size = opt.DataDirectory[PE_DIR_BASERELOC].Size;
    }
    if (opt.NumberOfRvaAndSizes > PE_DIR_TLS) {
        tls_dir_rva = opt.DataDirectory[PE_DIR_TLS].VirtualAddress;
        tls_dir_size = opt.DataDirectory[PE_DIR_TLS].Size;
    }

    if (!pe_parse_imports_dir(out, import_dir_rva, import_dir_size, err)) goto fail;
    if (!pe_parse_relocs_dir(out, reloc_dir_rva, reloc_dir_size, err)) goto fail;
    if (!pe_parse_tls_dir(out, tls_dir_rva, tls_dir_size, err)) goto fail;

    return true;

fail:
    free(out->raw);
    out->raw = NULL;
    return false;
}

void pe_image_free(pe_image_t *img) {
    if (!img) return;
    free(img->raw);
    free(img->relocs);
    img->raw = NULL;
    img->relocs = NULL;
}
