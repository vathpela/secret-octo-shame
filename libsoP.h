#ifndef LIBSO_LIBSOP_H
#define LIBSO_LIBSOP_H 1

#include "libso.h"

#include <gelf.h>
#include <libelf.h>
#include <elfutils/libebl.h>
#include <elfutils/libasm.h>

#include <stdio.h>

struct so_ctx_s {
    const char *path;
    GElf_Half machine;
    Ebl *ebl;
    AsmCtx_t *asmctx;
    Elf *elf;
    Elf32_Ehdr *ehdr;
    AsmScn_t *text;
    AsmScn_t *data;
};

#endif /* LIBSO_LIBSOP_H */
/*
 * vim:ts=8:sw=4:sts=4:et
 */
