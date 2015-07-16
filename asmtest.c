#include <stdio.h>

#include "libso.h"

static GElf_Half get_elf_machine(void)
{
    return EM_386;
}

int main(int argc, char *argv[])
{
    SoCtx_t *ctx;

    if (argc < 2) {
        fprintf(stderr, "no output file specified\n");
        return 1;
    }

    GElf_Half machine;
    if ((machine = get_elf_machine()) == EM_NONE) {
        fprintf(stderr, "could not detect elf machine\n");
        return 1;
    }

    if (!(ctx = so_begin(argv[1], machine))) {
        fprintf(stderr, "cannot create so context\n");
        return 1;
    }

    so_end(ctx);
    return 0;
}



/*
 * vim:ts=8:sw=4:sts=4:et
 */
