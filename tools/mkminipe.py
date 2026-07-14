#!/usr/bin/env python3
"""Hand-emit minimal, valid 32-bit PE32 EXEs for testing winlift's parsing
and container-translation mechanics in isolation from CRT/import handling,
which real MinGW/MSVC output always pulls in - and for structural edge cases
(ordinal imports, many imported DLLs) that a real compiler won't produce on
demand.

Three modes (see `if __name__ == '__main__'` below):
  - default: zero imports, just an exit syscall (see `build()`)
  - `ordinal`: one DLL with one ordinal-flagged import, actually called
    through its IAT slot before exiting - proves winlift resolves *and*
    invokes an ordinal import, not just tolerates one while parsing
  - `many_dlls`: N imported DLLs (each with zero functions) to prove
    winlift's import parsing isn't capped at some small fixed DLL count
"""
import struct
import sys

IMAGE_BASE = 0x00400000
FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000
PE_DIR_IMPORT = 1

# mov eax, 1 ; mov ebx, <exit_code> ; int 0x80   (Linux x86 exit syscall)
def exit_code_bytes(exit_code: int) -> bytes:
    return bytes([0xB8, 0x01, 0x00, 0x00, 0x00]) + \
           bytes([0xBB]) + struct.pack('<I', exit_code) + \
           bytes([0xCD, 0x80])


def align_up(n, a):
    return (n + a - 1) // a * a


def _pe_header(text_vsize, text_fsize, entry_rva, subsystem, import_dir_rva, import_dir_size):
    """Builds the DOS/COFF/optional/section headers for a single-section
    (.text, containing code and - if any - import metadata) PE32 image.
    Returns (header_blob, size_of_headers, size_of_image)."""
    dos_header = bytearray(64)
    dos_header[0:2] = b'MZ'
    struct.pack_into('<I', dos_header, 0x3C, 64)  # e_lfanew

    machine = 0x014C          # IMAGE_FILE_MACHINE_I386
    n_sections = 1
    size_of_opt_hdr = 224     # standard PE32 optional header + 16 data dirs
    characteristics = 0x0002 | 0x0100  # EXECUTABLE_IMAGE | 32BIT_MACHINE
    coff = struct.pack('<HHIIIHH', machine, n_sections, 0, 0, 0, size_of_opt_hdr, characteristics)

    headers_size_raw = 64 + 4 + len(coff) + size_of_opt_hdr + 40 * n_sections
    size_of_headers = align_up(headers_size_raw, FILE_ALIGN)

    text_rva = SECT_ALIGN
    text_file_off = size_of_headers
    size_of_image = align_up(text_rva + text_vsize, SECT_ALIGN)

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
        subsystem,         # Subsystem
        0,                 # DllCharacteristics
        0x100000, 0x1000,  # StackReserve/Commit
        0x100000, 0x1000,  # HeapReserve/Commit
        0,                 # LoaderFlags
        16,                # NumberOfRvaAndSizes
    )
    data_dirs = [(0, 0)] * 16
    data_dirs[PE_DIR_IMPORT] = (import_dir_rva, import_dir_size)
    for rva, size in data_dirs:
        opt += struct.pack('<II', rva, size)

    sect_name = b'.text\x00\x00\x00'
    sect_characteristics = 0x00000020 | 0x20000000 | 0x40000000  # CODE | EXECUTE | READ
    section = struct.pack('<8sIIIIIIHHI', sect_name, text_vsize, text_rva,
                           text_fsize, text_file_off, 0, 0, 0, 0, sect_characteristics)

    header_blob = bytes(dos_header) + b'PE\x00\x00' + coff + opt + section
    header_blob += b'\x00' * (size_of_headers - len(header_blob))
    return header_blob, size_of_headers, text_rva


def build(exit_code: int, subsystem: int = 3) -> bytes:
    """Zero imports - tests container-translation mechanics in isolation.
    This file would NOT run on real Windows (the "entry point" is a raw
    Linux exit syscall), it only exercises winlift's own container plumbing
    on Linux."""
    code = exit_code_bytes(exit_code)
    text_fsize = align_up(len(code), FILE_ALIGN)
    # AddressOfEntryPoint is always the first byte of .text (RVA SECT_ALIGN)
    # for every fixture this tool builds.
    header_blob, size_of_headers, _text_rva = _pe_header(
        len(code), text_fsize, entry_rva=SECT_ALIGN, subsystem=subsystem,
        import_dir_rva=0, import_dir_size=0)
    body = code + b'\x00' * (text_fsize - len(code))
    return header_blob + body


def build_with_imports(exit_code: int, dlls, call_first_ordinal: bool = False, subsystem: int = 3) -> bytes:
    """dlls: list of (dll_name: str, ordinals: list[int]) - each DLL is
    emitted with exactly the given ordinal-flagged imports (possibly zero
    of them, which parses as a valid zero-function DLL import). No
    import-by-name entries are ever emitted; this tool only needs to
    synthesize ordinal imports and DLL-count coverage, not named ones (real
    compilers already produce those).

    If call_first_ordinal is True, the entry code calls through the IAT slot
    of dlls[0]'s first ordinal before exiting - proving winlift both
    resolved *and* invoked it, not just tolerated it while parsing. Only
    meaningful (and only intended to be used) when dlls[0] has exactly one
    ordinal.
    """
    tail = exit_code_bytes(exit_code)
    call_len = 6 if call_first_ordinal else 0  # FF 15 <abs32>: call dword ptr [addr]
    code_len = call_len + len(tail)

    n_dlls = len(dlls)
    desc_table_off = code_len
    desc_table_size = (n_dlls + 1) * 20

    name_offsets = []
    pos = desc_table_off + desc_table_size
    for name, _ in dlls:
        name_offsets.append(pos)
        pos += len(name) + 1

    thunk_offsets = []
    for _, ordinals in dlls:
        thunk_offsets.append(pos)
        pos += (len(ordinals) + 1) * 4

    data_end = pos
    text_rva = SECT_ALIGN

    code = b''
    if call_first_ordinal:
        first_thunk_rva = text_rva + thunk_offsets[0]
        call_target_va = IMAGE_BASE + first_thunk_rva
        code += bytes([0xFF, 0x15]) + struct.pack('<I', call_target_va)
    code += tail
    assert len(code) == code_len

    desc_bytes = b''
    for i, (name, _ordinals) in enumerate(dlls):
        name_rva = text_rva + name_offsets[i]
        thunk_rva = text_rva + thunk_offsets[i]
        # OriginalFirstThunk=0 (use FirstThunk directly - no separate ILT),
        # TimeDateStamp=0, ForwarderChain=0, Name, FirstThunk
        desc_bytes += struct.pack('<IIIII', 0, 0, 0, name_rva, thunk_rva)
    desc_bytes += b'\x00' * 20  # terminator descriptor

    name_bytes = b''.join(name.encode('ascii') + b'\x00' for name, _ in dlls)

    thunk_bytes = b''
    for _name, ordinals in dlls:
        for ordv in ordinals:
            thunk_bytes += struct.pack('<I', 0x80000000 | ordv)
        thunk_bytes += struct.pack('<I', 0)  # terminator thunk

    body_data = code + desc_bytes + name_bytes + thunk_bytes
    assert len(body_data) == data_end

    text_fsize = align_up(data_end, FILE_ALIGN)
    header_blob, size_of_headers, _text_rva = _pe_header(
        data_end, text_fsize, entry_rva=text_rva, subsystem=subsystem,
        import_dir_rva=text_rva + desc_table_off, import_dir_size=desc_table_size)
    body = body_data + b'\x00' * (text_fsize - len(body_data))
    return header_blob + body


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'ordinal':
        # mkminipe.py ordinal <out> <exit_code> <dll_name> <ordinal>
        out_path = sys.argv[2]
        exit_code = int(sys.argv[3])
        dll_name = sys.argv[4]
        ordinal = int(sys.argv[5])
        with open(out_path, 'wb') as f:
            f.write(build_with_imports(exit_code, [(dll_name, [ordinal])], call_first_ordinal=True))
    elif len(sys.argv) > 1 and sys.argv[1] == 'many_dlls':
        # mkminipe.py many_dlls <out> <exit_code> <count>
        out_path = sys.argv[2]
        exit_code = int(sys.argv[3])
        count = int(sys.argv[4])
        dlls = [("FAKE%d.dll" % i, []) for i in range(count)]
        with open(out_path, 'wb') as f:
            f.write(build_with_imports(exit_code, dlls, call_first_ordinal=False))
    else:
        out_path = sys.argv[1]
        exit_code = int(sys.argv[2]) if len(sys.argv) > 2 else 0
        subsystem = int(sys.argv[3]) if len(sys.argv) > 3 else 3
        with open(out_path, 'wb') as f:
            f.write(build(exit_code, subsystem))
