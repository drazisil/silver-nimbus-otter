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

# --- M1g-style negative path (available early since M1a already rejects) ---

check "GUI-subsystem exe is rejected" \
    bash -c "! '$WINLIFT' --dump '$FIXTURES/reject_gui.exe' >/tmp/winlift_gui.txt 2>&1"

check "GUI rejection names the subsystem" \
    grep -qi "GUI subsystem" /tmp/winlift_gui.txt

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
