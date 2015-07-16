#ifndef LIBSO_LIBSO_H
#define LIBSO_LIBSO_H 1

#include <gelf.h>

typedef struct so_ctx_s SoCtx_t;

extern SoCtx_t *so_begin(const char *path, GElf_Half machine);
extern void so_end(SoCtx_t * ctx);

#endif /* LIBSO_LIBSO_H */
