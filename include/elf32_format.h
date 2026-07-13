/* Minimal ELF32 on-disk structure definitions/constants (just what winlift
 * needs to emit an ET_EXEC, EM_386 executable - not a general ELF library). */
#ifndef WINLIFT_ELF32_FORMAT_H
#define WINLIFT_ELF32_FORMAT_H

#include <stdint.h>

#define ELF_EI_NIDENT 16

#define ELFMAG0 0x7F
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'

#define ELFCLASS32   1
#define ELFDATA2LSB  1
#define EV_CURRENT   1
#define ELFOSABI_SYSV 0

#define ET_EXEC   2
#define EM_386    3

#define PT_LOAD  1
#define PT_PHDR  6

#define PF_X 1
#define PF_W 2
#define PF_R 4

#pragma pack(push, 1)

typedef struct {
    uint8_t  e_ident[ELF_EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} elf32_ehdr_t;

typedef struct {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
} elf32_phdr_t;

typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint32_t sh_flags;
    uint32_t sh_addr;
    uint32_t sh_offset;
    uint32_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint32_t sh_addralign;
    uint32_t sh_entsize;
} elf32_shdr_t;

typedef struct {
    uint32_t st_name;
    uint32_t st_value;
    uint32_t st_size;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
} elf32_sym_t;

#pragma pack(pop)

#define SHT_SYMTAB 2

#endif /* WINLIFT_ELF32_FORMAT_H */
