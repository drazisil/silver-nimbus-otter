# winlift

Converts 32-bit Windows PE/COFF executables into runnable Linux ELF binaries.

## Scope

`winlift` targets 32-bit, console-mode PE executables built with MinGW
(statically linked) that only import from a bounded, enumerable set of
kernel32.dll and msvcrt.dll functions - see `include/shim_abi.h` for the
exact supported list. Anything outside that set (GUI/user32 apps, COM,
threads, SEH, delay-loaded imports, ordinal imports, .NET, 64-bit/PE32+,
DLLs) is rejected at conversion time with a specific diagnostic naming the
unsupported feature, rather than silently producing a broken binary.

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

Deliberately out of scope for now: base-relocation/rebasing support,
GUI/user32, threads, structured exception handling, delay-loaded imports,
and .NET.
