CC       ?= gcc
CFLAGS   ?= -std=c11 -Wall -Wextra -Wno-unused-parameter -O2 -Iinclude -MMD -MP
LDFLAGS  ?=

SRC := src/main.c src/diagnostics.c src/pe_reader.c src/pe_imports.c src/pe_relocs.c src/pe_dump.c \
       src/elf_writer.c src/layout.c
OBJ := $(SRC:.c=.o)
DEP := $(SRC:.c=.d)
BIN := winlift

.PHONY: all clean test check-mingw

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

-include $(DEP)

check-mingw:
	@command -v i686-w64-mingw32-gcc >/dev/null 2>&1 || { \
		echo "error: i686-w64-mingw32-gcc not found; install gcc-mingw-w64-i686" >&2; exit 1; }

test: all check-mingw
	@./tests/run_tests.sh

clean:
	rm -f $(OBJ) $(DEP) $(BIN)
