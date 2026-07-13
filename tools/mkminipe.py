#!/usr/bin/env python3
"""Hand-emit a minimal, valid 32-bit PE32 console EXE with a single .text
section and zero imports/relocations/TLS.

This exists purely to test winlift's container-translation mechanics (PE
section table -> ELF PT_LOAD segments, entry-point wiring) in isolation from
CRT/import handling, which real MinGW/MSVC output always pulls in. Since it
has no imports to satisfy, the "entry point" code is deliberately just a raw
Linux exit syscall (int $0x80) - this file would NOT run on real Windows,
it only exercises winlift's own container plumbing on Linux.
"""
import struct
import sys

IMAGE_BASE = 0x00400000
FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000

# mov eax, 1 ; mov ebx, <exit_code> ; int 0x80   (Linux x86 exit syscall)
def code_bytes(exit_code: int) -> bytes:
    return bytes([0xB8, 0x01, 0x00, 0x00, 0x00]) + \
           bytes([0xBB]) + struct.pack('<I', exit_code) + \
           bytes([0xCD, 0x80])


def align_up(n, a):
    return (n + a - 1) // a * a


def build(exit_code: int) -> bytes:
    code = code_bytes(exit_code)

    dos_header = bytearray(64)
    dos_header[0:2] = b'MZ'
    struct.pack_into('<I', dos_header, 0x3C, 64)  # e_lfanew

    # COFF header
    machine = 0x014C          # IMAGE_FILE_MACHINE_I386
    n_sections = 1
    size_of_opt_hdr = 224     # standard PE32 optional header + 16 data dirs
    characteristics = 0x0002 | 0x0100  # EXECUTABLE_IMAGE | 32BIT_MACHINE
    coff = struct.pack('<HHIIIHH', machine, n_sections, 0, 0, 0, size_of_opt_hdr, characteristics)

    headers_size_raw = 64 + 4 + len(coff) + size_of_opt_hdr + 40 * n_sections
    size_of_headers = align_up(headers_size_raw, FILE_ALIGN)

    text_rva = SECT_ALIGN
    text_file_off = size_of_headers
    text_vsize = len(code)
    text_fsize = align_up(len(code), FILE_ALIGN)
    size_of_image = align_up(text_rva + text_vsize, SECT_ALIGN)

    entry_rva = text_rva  # entry point is the very first byte of .text

    opt = struct.pack(
        '<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII',
        0x010B,            # Magic (PE32)
        1, 0,              # Linker version
        text_fsize,        # SizeOfCode
        0,                 # SizeOfInitializedData
        0,                 # SizeOfUninitializedData
        entry_rva,         # AddressOfEntryPoint
        text_rva,          # BaseOfCode
        0,                 # BaseOfData
        IMAGE_BASE,        # ImageBase
        SECT_ALIGN,        # SectionAlignment
        FILE_ALIGN,        # FileAlignment
        0, 0,              # OS version
        0, 0,              # Image version
        4, 0,              # Subsystem version
        0,                 # Win32VersionValue
        size_of_image,     # SizeOfImage
        size_of_headers,   # SizeOfHeaders
        0,                 # CheckSum
        3,                 # Subsystem (WINDOWS_CUI)
        0,                 # DllCharacteristics
        0x100000, 0x1000,  # StackReserve/Commit
        0x100000, 0x1000,  # HeapReserve/Commit
        0,                 # LoaderFlags
        16,                # NumberOfRvaAndSizes
    )
    opt += b'\x00' * (8 * 16)  # 16 zeroed IMAGE_DATA_DIRECTORY entries

    sect_name = b'.text\x00\x00\x00'
    sect_characteristics = 0x00000020 | 0x20000000 | 0x40000000  # CODE | EXECUTE | READ
    section = struct.pack('<8sIIIIIIHHI', sect_name, text_vsize, text_rva,
                           text_fsize, text_file_off, 0, 0, 0, 0, sect_characteristics)

    header_blob = bytes(dos_header) + b'PE\x00\x00' + coff + opt + section
    header_blob += b'\x00' * (size_of_headers - len(header_blob))

    body = code + b'\x00' * (text_fsize - len(code))

    return header_blob + body


if __name__ == '__main__':
    out_path = sys.argv[1]
    exit_code = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    with open(out_path, 'wb') as f:
        f.write(build(exit_code))
