#!/usr/bin/env bash
# Golden test suite for winlift. Builds PE fixtures with mingw, then exercises
# winlift against them. Extended milestone-by-milestone as ELF conversion and
# more shim functions come online.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WINLIFT="$ROOT/winlift"
FIXTURES="$ROOT/tests/fixtures"

pass=0
fail=0

check() {
    local desc="$1"
    shift
    if "$@"; then
        echo "ok   - $desc"
        pass=$((pass + 1))
    else
        echo "FAIL - $desc"
        fail=$((fail + 1))
    fi
}

"$ROOT/tools/gen_test_exes.sh"

# --- M1a: parser / --dump sanity ---

check "dump hello_exitcode.exe succeeds" \
    bash -c "'$WINLIFT' --dump '$FIXTURES/hello_exitcode.exe' >/tmp/winlift_dump.txt"

check "dump reports KERNEL32.dll import" \
    grep -qi "KERNEL32.dll" /tmp/winlift_dump.txt

check "dump reports entry point" \
    grep -q "EntryPoint RVA" /tmp/winlift_dump.txt

# --- M1b: container translation (zero-import PE -> runnable ELF) ---

check "convert minimal_noimport.exe succeeds" \
    "$WINLIFT" "$FIXTURES/minimal_noimport.exe" -o /tmp/winlift_minimal.elf

check "converted ELF is recognized as i386 ELF executable" \
    bash -c "out=\$(file /tmp/winlift_minimal.elf); echo \"\$out\" | grep -q 'ELF 32-bit LSB executable' && echo \"\$out\" | grep -Eqi '80386|i386'"

/tmp/winlift_minimal.elf
minimal_exit=$?
check "converted ELF runs and exits with the expected code (42)" \
    test "$minimal_exit" -eq 42

# --- M1c: CRT bootstrap shim (real MinGW binary with kernel32/msvcrt imports) ---

check "convert real hello_exitcode.exe succeeds" \
    "$WINLIFT" "$FIXTURES/hello_exitcode.exe" -o /tmp/winlift_hello.elf

"/tmp/winlift_hello.elf"
hello_exit=$?
check "converted real CRT binary runs and exits with the expected code (42)" \
    test "$hello_exit" -eq 42

# --- M1d: console/file I/O (WriteFile/GetStdHandle) ---

check "convert hello_console.exe succeeds" \
    "$WINLIFT" "$FIXTURES/hello_console.exe" -o /tmp/winlift_console.elf

console_out="$(/tmp/winlift_console.elf)"
console_exit=$?
check "converted console binary prints the expected text" \
    test "$console_out" = "hello from WriteFile"

check "converted console binary returns the byte count via exit code (21)" \
    test "$console_exit" -eq 21

# --- M1e: heap (GetProcessHeap/HeapAlloc/HeapFree) ---

check "convert heap_alloc.exe succeeds" \
    "$WINLIFT" "$FIXTURES/heap_alloc.exe" -o /tmp/winlift_heap.elf

/tmp/winlift_heap.elf
heap_exit=$?
check "converted heap binary computes the expected checksum (90)" \
    test "$heap_exit" -eq 90

# --- M1f: argv / GetCommandLineA plumbing ---

check "convert argv_env.exe succeeds" \
    "$WINLIFT" "$FIXTURES/argv_env.exe" -o /tmp/winlift_argv.elf

argv_out="$(/tmp/winlift_argv.elf foo 5 10 15)"
argv_exit=$?
check "converted argv binary reports a GetCommandLineA cmdline containing the args" \
    bash -c "echo \"$argv_out\" | grep -q 'foo 5 10 15'"

check "converted argv binary sums argv[1..] via exit code (30)" \
    test "$argv_exit" -eq 30

# --- M1g: rejection-path hardening ---

check "DLL is rejected" \
    bash -c "! '$WINLIFT' --dump '$FIXTURES/reject_dll.exe' >/tmp/winlift_dll.txt 2>&1"

check "DLL rejection names the reason" \
    grep -qi "DLL" /tmp/winlift_dll.txt

if [ -f "$FIXTURES/reject_pe32plus.exe" ]; then
    check "64-bit (PE32+) is rejected" \
        bash -c "! '$WINLIFT' --dump '$FIXTURES/reject_pe32plus.exe' >/tmp/winlift_64.txt 2>&1"

    check "64-bit rejection names the machine type" \
        grep -qi "machine" /tmp/winlift_64.txt
else
    echo "skip - PE32+ rejection (reject_pe32plus.exe not built; x86_64-w64-mingw32-gcc missing)"
fi

check "unsupported import is rejected by name" \
    bash -c "! '$WINLIFT' '$FIXTURES/printf_uses_unsupported.exe' -o /tmp/winlift_imp.elf >/tmp/winlift_imp.txt 2>&1"

check "unsupported-import rejection names the DLL and function" \
    grep -Eq "unsupported: import '[A-Za-z0-9_.]+![A-Za-z0-9_]+' is not implemented" /tmp/winlift_imp.txt

check "malformed (truncated) input is rejected without crashing" \
    bash -c "head -c 10 '$FIXTURES/hello_exitcode.exe' > /tmp/winlift_truncated.exe && ! '$WINLIFT' --dump /tmp/winlift_truncated.exe >/tmp/winlift_trunc_out.txt 2>&1"

check "no output ELF is written on rejection" \
    bash -c "rm -f /tmp/winlift_should_not_exist.elf; '$WINLIFT' '$FIXTURES/reject_dll.exe' -o /tmp/winlift_should_not_exist.elf >/dev/null 2>&1; [ ! -e /tmp/winlift_should_not_exist.elf ]"

check "unsupported (non-CUI/GUI) subsystem is rejected" \
    bash -c "! '$WINLIFT' --dump '$FIXTURES/reject_native_subsystem.exe' >/tmp/winlift_native.txt 2>&1"

check "unsupported-subsystem rejection names the subsystem" \
    grep -qi "subsystem" /tmp/winlift_native.txt

# --- M2a/M2c: GUI-subsystem admission + headless-safe user32 shim ---
# No real window is ever created or rendered (see runtime/shim_user32.c) -
# these check that a real GUI-subsystem MinGW binary converts and runs
# deterministically, the same golden-test style as the M1 checks above.

check "dump reports WINDOWS_GUI subsystem" \
    bash -c "'$WINLIFT' --dump '$FIXTURES/gui_messagebox.exe' | grep -q 'WINDOWS_GUI'"

check "convert gui_messagebox.exe succeeds" \
    "$WINLIFT" "$FIXTURES/gui_messagebox.exe" -o /tmp/winlift_msgbox.elf

msgbox_out="$(/tmp/winlift_msgbox.elf)"
msgbox_exit=$?
check "converted MessageBoxA binary prints the expected text" \
    test "$msgbox_out" = "[MessageBoxA] hi: hi"

check "converted MessageBoxA binary exits with the expected code (77)" \
    test "$msgbox_exit" -eq 77

check "convert gui_window_lifecycle.exe succeeds" \
    "$WINLIFT" "$FIXTURES/gui_window_lifecycle.exe" -o /tmp/winlift_winlife.elf

# Guarded with `timeout`: a regression that makes the headless GetMessageA
# shim stop signaling loop-exit would otherwise hang the whole test suite.
check "converted window-lifecycle binary terminates and exits with the expected code (88) instead of hanging" \
    bash -c "timeout 5 /tmp/winlift_winlife.elf; test \$? -eq 88"

# --- M3: structural PE-parsing robustness (ordinal imports + no more
# arbitrary fixed-array caps) ---

check "dump reports the ordinal import as #17" \
    bash -c "'$WINLIFT' --dump '$FIXTURES/ordinal_import.exe' | grep -q '#17'"

check "convert ordinal_import.exe succeeds" \
    "$WINLIFT" "$FIXTURES/ordinal_import.exe" -o /tmp/winlift_ordinal.elf

/tmp/winlift_ordinal.elf
ordinal_exit=$?
check "converted ordinal-import binary calls through to shim_InitCommonControls and exits with the expected code (55)" \
    test "$ordinal_exit" -eq 55

check "dump reports all 20 DLLs (past the old PE_MAX_DLLS=16 limit)" \
    bash -c "test \"\$('$WINLIFT' --dump '$FIXTURES/many_dlls.exe' | grep -c '\.dll (')\" -eq 20"

check "convert many_dlls.exe succeeds" \
    "$WINLIFT" "$FIXTURES/many_dlls.exe" -o /tmp/winlift_many.elf

/tmp/winlift_many.elf
many_exit=$?
check "converted many-DLL binary runs and exits with the expected code (66)" \
    test "$many_exit" -eq 66

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
