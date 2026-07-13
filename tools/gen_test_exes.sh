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

for src in "$FIXTURES"/*.c; do
    [ -e "$src" ] || continue
    case "$(basename "$src")" in
        reject_*.c) continue ;; # negative-path fixtures are built separately below
    esac
    out="${src%.c}.exe"
    echo "building $out"
    i686-w64-mingw32-gcc -O0 -static -o "$out" "$src"
done

# Negative-path fixture: GUI subsystem, must be rejected by winlift.
if [ -f "$FIXTURES/reject_gui.c" ]; then
    echo "building $FIXTURES/reject_gui.exe"
    i686-w64-mingw32-gcc -O0 -mwindows -static -o "$FIXTURES/reject_gui.exe" \
        "$FIXTURES/reject_gui.c" -luser32
fi
