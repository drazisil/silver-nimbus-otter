#!/usr/bin/env bash
# Builds the PE test fixture corpus used by tests/run_tests.sh, using the
# i686-w64-mingw32 cross-compiler. Fixtures are compiled -static so their
# import set stays limited to kernel32/msvcrt (no extra DLL dependencies).
set -euo pipefail

if ! command -v i686-w64-mingw32-gcc >/dev/null 2>&1; then
    echo "error: i686-w64-mingw32-gcc not found; install gcc-mingw-w64-i686" >&2
    exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURES="$ROOT/tests/fixtures"

# Hand-assembled PE with zero imports, used to test container-translation
# mechanics in isolation from CRT/import handling (see mkminipe.py).
echo "building $FIXTURES/minimal_noimport.exe"
python3 "$ROOT/tools/mkminipe.py" "$FIXTURES/minimal_noimport.exe" 42

# Hand-assembled PE with an unsupported subsystem value (1 = NATIVE, neither
# CUI=3 nor GUI=2), used to keep PE_ERR_UNSUPPORTED_SUBSYSTEM covered now
# that GUI=2 is accepted alongside CUI=3 (see M2).
echo "building $FIXTURES/reject_native_subsystem.exe"
python3 "$ROOT/tools/mkminipe.py" "$FIXTURES/reject_native_subsystem.exe" 0 1

for src in "$FIXTURES"/*.c; do
    [ -e "$src" ] || continue
    case "$(basename "$src")" in
        reject_*.c|gui_*.c) continue ;; # built separately below (need non-default flags)
    esac
    out="${src%.c}.exe"
    echo "building $out"
    i686-w64-mingw32-gcc -O0 -static -o "$out" "$src"
done

# GUI-subsystem fixtures (M2): need -mwindows -luser32, unlike the plain
# console fixtures built by the loop above.
for src in "$FIXTURES"/gui_*.c; do
    [ -e "$src" ] || continue
    out="${src%.c}.exe"
    echo "building $out"
    i686-w64-mingw32-gcc -O0 -mwindows -static -o "$out" "$src" -luser32
done

# Negative-path fixture: DLL, must be rejected by winlift.
echo "building $FIXTURES/reject_dll.exe"
i686-w64-mingw32-gcc -O0 -shared -static -o "$FIXTURES/reject_dll.exe" \
    -Wl,--out-implib,/tmp/winlift_reject_dll.a "$FIXTURES/hello_exitcode.c"
rm -f /tmp/winlift_reject_dll.a

# Negative-path fixture: PE32+ (64-bit), must be rejected by winlift. Skipped
# gracefully if the x86_64 mingw cross-compiler isn't installed, since it's
# a separate package from the i686 one this whole script otherwise needs.
if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    echo "building $FIXTURES/reject_pe32plus.exe"
    x86_64-w64-mingw32-gcc -O0 -static -o "$FIXTURES/reject_pe32plus.exe" "$FIXTURES/hello_exitcode.c"
else
    echo "skipping reject_pe32plus.exe: x86_64-w64-mingw32-gcc not installed" >&2
fi
