CC       ?= gcc
CFLAGS   ?= -std=c11 -Wall -Wextra -Wno-unused-parameter -O2 -Iinclude -MMD -MP
LDFLAGS  ?=

SRC := src/main.c src/diagnostics.c src/pe_reader.c src/pe_imports.c src/pe_relocs.c src/pe_dump.c \
       src/elf_writer.c src/layout.c src/shim_abi.c src/stub_patch.c src/shim_blob.c
OBJ := $(SRC:.c=.o)
DEP := $(SRC:.c=.d)
BIN := winlift

# --- shim runtime (freestanding i386 ELF code, embedded into winlift) ---
RUNTIME_CFLAGS := -m32 -nostdlib -ffreestanding -fno-pic -fno-pie -fno-stack-protector \
                   -Wall -Wextra -Iruntime -O2
RUNTIME_C_SRC  := runtime/shim_startup.c runtime/shim_kernel32.c runtime/shim_msvcrt.c runtime/shim_user32.c runtime/shim_comctl32.c
RUNTIME_OBJ    := runtime/shim_entry.o $(RUNTIME_C_SRC:.c=.o)

.PHONY: all clean test check-mingw check-m32

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

-include $(DEP)

runtime/shim_entry.o: runtime/shim_entry.S
	$(CC) $(RUNTIME_CFLAGS) -c -o $@ $<

runtime/%.o: runtime/%.c
	$(CC) $(RUNTIME_CFLAGS) -c -o $@ $<

runtime/shim.elf: $(RUNTIME_OBJ)
	$(CC) -m32 -nostdlib -static -ffreestanding -fno-pic -fno-pie \
		-Wl,-Ttext=0x0F000000 -Wl,--build-id=none -Wl,-e,_start \
		-o $@ $(RUNTIME_OBJ)

src/shim_blob.c: runtime/shim.elf tools/gen_shim_blob.py
	python3 tools/gen_shim_blob.py runtime/shim.elf src/shim_blob.c

check-m32:
	@echo 'int main(void){return 0;}' | $(CC) -m32 -xc -o /dev/null - >/dev/null 2>&1 || { \
		echo "error: gcc -m32 not available; install gcc-multilib" >&2; exit 1; }

check-mingw:
	@command -v i686-w64-mingw32-gcc >/dev/null 2>&1 || { \
		echo "error: i686-w64-mingw32-gcc not found; install gcc-mingw-w64-i686" >&2; exit 1; }

test: all check-mingw
	@./tests/run_tests.sh

clean:
	rm -f $(OBJ) $(DEP) $(BIN) $(RUNTIME_OBJ) runtime/shim.elf src/shim_blob.c
