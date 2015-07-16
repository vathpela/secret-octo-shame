#define _GNU_SOURCE 1

#include "libsoP.h"

#include <stdlib.h>

struct So_Elf_Scn {
    const char *name;
    GElf_Word type;
    GElf_Xword flags;
    int alignment;
};

static struct So_Elf_Scn scn_templates[] = {
#if 0
    { ".gnu.hash",      SHT_GNU_HASH, SHF_ALLOC, 4 },
    { ".dynsym",        SHT_DYNSYM, SHF_ALLOC, 4 },
    { ".dynstr",        SHT_STRTAB, SHF_ALLOC, 1 },
    { ".gnu.version",   SHT_GNU_versym, SHF_ALLOC, 2 },
    { ".gnu.version_r", SHT_GNU_verneed, SHF_ALLOC, 4 },
    { ".rel.dyn",       SHT_REL, SHF_ALLOC, 4 },
    { ".rel.plt",       SHT_REL, SHF_ALLOC, 4 },
#endif
    { ".init",          SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 4 },
    { ".plt",           SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 4 },
    { ".text",          SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 16 },
    { ".fini",          SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 4 },
    { ".eh_frame",      SHT_PROGBITS, SHF_ALLOC, 4 },
    { ".ctors",         SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, 4 },
    { ".dtors",         SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, 4 },
    { ".jcr",           SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, 4 },
    { ".data.rel.ro",   SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, 4 },
#if 0
    { ".dynamic",       SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE, 4 },
#endif
    { ".got",           SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, 4 },
    { ".got.plt",       SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, 4 },
    { ".data",          SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, 32 },
    { ".bss",           SHT_NOBITS, SHF_ALLOC | SHF_WRITE, 4 },
    { ".comment",       SHT_PROGBITS, 0, 1 },
    { ".debug_aranges", SHT_PROGBITS, 0, 1 },
    { ".debug_pubnames",SHT_PROGBITS, 0, 1 },
    { ".debug_info",    SHT_PROGBITS, 0, 1 },
    { ".debug_abbrev",  SHT_PROGBITS, 0, 1 },
    { ".debug_line",    SHT_PROGBITS, 0, 1 },
    { ".debug_frame",   SHT_PROGBITS, 0, 4 },
    { ".debug_loc",     SHT_PROGBITS, 0, 1 },
#if 0
    { ".shstrtab",      SHT_STRTAB, 0, 1 },
    { ".symtab",        SHT_SYMTAB, 0, 4 },
    { ".strtab",        SHT_STRTAB, 0, 1 },
#endif
    { "", SHT_NULL, 0 }
};

SoCtx_t *so_begin(const char *path, GElf_Half machine)
{
    elf_version(EV_CURRENT);

    SoCtx_t *ctx;
    if (!(ctx = calloc(1, sizeof (*ctx))))
        return NULL;

    ctx->path = path;
    if (!(ctx->ebl = ebl_openbackend_machine(machine))) {
ebl_err:
        so_end(ctx);
        return NULL;
    }

    if (!(ctx->asmctx = asm_begin(ctx->path, ctx->ebl, false)))
        goto ebl_err;

    if (!(ctx->elf = asm_getelf(ctx->asmctx))) {
err:
        asm_abort(ctx->asmctx);
        ctx->asmctx = NULL;
        goto ebl_err;
    }

    if (!(ctx->ehdr = elf32_getehdr(ctx->elf)))
        goto err;

    ctx->ehdr->e_type = ET_DYN;

    struct So_Elf_Scn *tmpl;
    for (tmpl = &scn_templates[0]; tmpl->type != SHT_NULL; tmpl++) {
        AsmScn_t *as;

        if (!(as =asm_newscn(ctx->asmctx, tmpl->name, tmpl->type, tmpl->flags)))
            goto err;
        asm_align(as, tmpl->alignment);
    }

    return ctx;
}

void so_end(SoCtx_t *ctx)
{
    if (ctx) {
        if (ctx->asmctx)
            asm_end(ctx->asmctx);
        if (ctx->ebl)
            ebl_closebackend(ctx->ebl);
        free(ctx);
    }
}

/*
 * vim:ts=8:sw=4:sts=4:et
 */
