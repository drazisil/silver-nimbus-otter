/* On-disk PE/COFF structure definitions (32-bit, PE32 only). */
#ifndef WINLIFT_PE_FORMAT_H
#define WINLIFT_PE_FORMAT_H

#include <stdint.h>

#define PE_DOS_MAGIC        0x5A4D    /* "MZ" */
#define PE_NT_SIGNATURE      0x00004550 /* "PE\0\0" */

#define PE_MACHINE_I386      0x014C
#define PE_MACHINE_AMD64     0x8664

#define PE_OPTHDR32_MAGIC    0x010B
#define PE_OPTHDR64_MAGIC    0x020B

#define PE_FILE_DLL          0x2000
#define PE_FILE_EXECUTABLE   0x0002

#define PE_SUBSYSTEM_WINDOWS_GUI 2
#define PE_SUBSYSTEM_WINDOWS_CUI 3

#define PE_SCN_CNT_CODE               0x00000020
#define PE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define PE_SCN_MEM_EXECUTE            0x20000000
#define PE_SCN_MEM_READ               0x40000000
#define PE_SCN_MEM_WRITE              0x80000000

#define PE_DIR_EXPORT      0
#define PE_DIR_IMPORT      1
#define PE_DIR_RESOURCE    2
#define PE_DIR_EXCEPTION   3
#define PE_DIR_SECURITY    4
#define PE_DIR_BASERELOC   5
#define PE_DIR_DEBUG       6
#define PE_DIR_TLS         9
#define PE_DIR_BOUND_IMPORT 11
#define PE_DIR_DELAY_IMPORT 13
#define PE_DIR_COM_DESCRIPTOR 14
#define PE_NUM_DIRECTORIES 16

#define PE_ORDINAL_FLAG32  0x80000000u

#define PE_REL_BASED_ABSOLUTE 0
#define PE_REL_BASED_HIGHLOW  3

#pragma pack(push, 1)

typedef struct {
    uint16_t e_magic;
    uint8_t  e_ignore1[58]; /* fields we don't need */
    int32_t  e_lfanew;
} pe_dos_header_t;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} pe_coff_header_t;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} pe_data_directory_t;

typedef struct {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    pe_data_directory_t DataDirectory[PE_NUM_DIRECTORIES];
} pe_optional_header32_t;

typedef struct {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} pe_section_header_t;

typedef struct {
    uint32_t OriginalFirstThunk; /* RVA to ILT, 0 = use FirstThunk directly */
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;               /* RVA to ASCII DLL name */
    uint32_t FirstThunk;         /* RVA to IAT */
} pe_import_descriptor_t;

typedef struct {
    uint16_t Hint;
    /* char Name[]; -- variable length, null terminated */
} pe_import_by_name_t;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t SizeOfBlock;
    /* uint16_t entries[]; -- (SizeOfBlock - 8) / 2 of them */
} pe_base_relocation_block_t;

typedef struct {
    uint32_t StartAddressOfRawData;
    uint32_t EndAddressOfRawData;
    uint32_t AddressOfIndex;
    uint32_t AddressOfCallBacks;
    uint32_t SizeOfZeroFill;
    uint32_t Characteristics;
} pe_tls_directory32_t;

#pragma pack(pop)

#endif /* WINLIFT_PE_FORMAT_H */
