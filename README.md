# winlift

Converts 32-bit Windows PE/COFF executables into runnable Linux ELF binaries.

## Scope

`winlift` targets 32-bit PE executables, console (CUI) or GUI subsystem,
that only import from a bounded, enumerable set of
kernel32.dll/msvcrt.dll/user32.dll/comctl32.dll functions - see
`include/shim_abi.h` for the exact supported list. Imports are matched by
name, or - for the one supported ordinal import - by a synthesized
`#<ordinal>` name (see Milestone 3 below); PE parsing itself isn't limited
to MinGW-shaped binaries (arbitrary numbers of imported DLLs, functions, and
base relocations are all handled), but which specific imports are actually
satisfiable is still the bounded, enumerable set in `shim_abi.c` regardless
of which toolchain produced the binary. Anything outside that set (COM,
threads, SEH, delay-loaded imports, unsupported ordinal imports, .NET,
64-bit/PE32+, DLLs) is rejected at conversion time with a specific
diagnostic naming the unsupported feature, rather than silently producing a
broken binary.

The original x86 code is not recompiled: PE and ELF both run the same i386
machine code with a compatible base calling convention, so conversion is
mostly a container-format transcode (PE sections -> ELF `PT_LOAD` segments,
loaded at the PE's own `ImageBase` so no relocations need to be applied)
plus rewriting the Import Address Table so calls that used to resolve into
`kernel32.dll`/`msvcrt.dll` instead call into a small, precompiled
compatibility shim that performs the equivalent operation via raw Linux
syscalls.

## Building

```
make          # builds ./winlift (requires gcc-multilib for the shim, see below)
make test     # builds PE test fixtures with mingw and runs tests/run_tests.sh
```

Building `winlift` itself compiles a small freestanding i386 "shim" runtime
(`runtime/`) and embeds it into the tool, which requires `gcc-multilib`
(`gcc -m32`). Running the test suite additionally requires
`gcc-mingw-w64-i686` (and optionally `gcc-mingw-w64-x86-64`, to build a
PE32+ fixture that exercises the 64-bit rejection path) to build PE test
binaries.

## Usage

```
winlift --dump input.exe          # inspect PE headers/sections/imports
winlift input.exe -o output.elf   # convert; output.elf runs directly on Linux
```

## Status

Milestone 1 (MinGW-static console binaries against the supported
kernel32/msvcrt import set) is implemented and tested end-to-end: real
MinGW-compiled binaries exercising process exit codes, console I/O
(`WriteFile`), heap allocation (`HeapAlloc`/`malloc`), and argv/command-line
plumbing (`GetCommandLineA`) all convert and run correctly. See
`tests/run_tests.sh` for the full test matrix.

Milestone 2 (GUI-subsystem admission + a headless-safe user32 shim) is
implemented and tested end-to-end: real MinGW-compiled `-mwindows` binaries
using `MessageBoxA` and the basic window-creation/message-loop lifecycle
(`RegisterClassA`/`CreateWindowExA`/`ShowWindow`/`GetMessage`/`DispatchMessage`)
convert and run correctly. No real window is ever created or rendered -
`user32.dll` calls are backed by deterministic no-ops (a fixed sentinel
`HWND`, etc.), and the message-pump shim always signals loop-exit
immediately rather than blocking on a real message source, so converted
GUI binaries behave like well-defined batch processes rather than hanging.

Milestone 3 (structural PE-parsing robustness) is implemented and tested
end-to-end: PE sections, imported DLLs, and per-DLL imported functions are
all heap-allocated and grown as parsed rather than capped at small fixed
sizes, and base relocations no longer hit an arbitrary count ceiling below
what the format itself supports - real-world binaries (tested against a
large, genuine 2002 MSVC-linked game client with 19 imported DLLs and ~200K
relocations) are no longer rejected on parsing grounds alone. Ordinal
imports are no longer a blanket rejection either: they're unified into the
same named-import matching `shim_abi.c` already used (via a synthesized
`#<ordinal>` name), with exactly one real, well-known, version-stable case
supported end-to-end - `COMCTL32.dll` ordinal 17 (`InitCommonControls`,
headless no-op). Every other ordinal import is still rejected, the same way
any unrecognized named import is.

Deliberately out of scope for now: real window rendering (an X11 backend or
similar), GDI drawing, keyboard/mouse input, multi-window apps, `gdi32.dll`
broadly, general ordinal-to-name resolution (ordinal meanings are
version-specific; only one well-known case is supported), base-relocation/
rebasing *application* (relocations are parsed and counted but never
applied - still fine as long as the ELF loads at the PE's own preferred
`ImageBase`), Direct3D/DirectSound/DirectInput/other COM-based APIs (a
fundamentally different problem from IAT-patchable imports), threads,
structured exception handling, delay-loaded imports, and .NET.
