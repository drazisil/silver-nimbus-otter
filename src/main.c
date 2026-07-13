#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "pe_image.h"
#include "layout.h"
#include "elf_writer.h"

static void usage(const char *prog) {
    fprintf(stderr,
            "usage: %s --dump <input.exe>\n"
            "       %s <input.exe> -o <output.elf>\n",
            prog, prog);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }

    bool dump_mode = false;
    const char *input = NULL;
    const char *output = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--dump") == 0) {
            dump_mode = true;
        } else if (strcmp(argv[i], "-o") == 0) {
            if (i + 1 >= argc) {
                usage(argv[0]);
                return 2;
            }
            output = argv[++i];
        } else if (!input) {
            input = argv[i];
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    if (!input) {
        usage(argv[0]);
        return 2;
    }

    pe_image_t img;
    pe_error_t err;
    if (!pe_image_load(input, &img, &err)) {
        fprintf(stderr, "winlift: %s\n", err.message);
        return 1;
    }

    if (dump_mode) {
        pe_dump(&img, stdout);
        pe_image_free(&img);
        return 0;
    }

    if (!output) {
        fprintf(stderr, "winlift: -o <output.elf> is required to convert\n");
        pe_image_free(&img);
        return 2;
    }

    elf_image_spec_t spec;
    char elferr[256];
    if (!pe_layout_to_elf_spec(&img, &spec, elferr, sizeof(elferr))) {
        fprintf(stderr, "winlift: %s\n", elferr);
        pe_image_free(&img);
        return 1;
    }
    if (!elf_write(output, &spec, elferr, sizeof(elferr))) {
        fprintf(stderr, "winlift: %s\n", elferr);
        pe_image_free(&img);
        return 1;
    }
    chmod(output, 0755);

    pe_image_free(&img);
    return 0;
}
