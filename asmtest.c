#include <err.h>
#include <stdio.h>

#include "libso.h"

static GElf_Half get_elf_machine(void)
{
	return EM_386;
}

int main(int argc, char *argv[])
{
	SoCtx_t *ctx;

	if (argc < 2)
		errx(1, "No ouptut file specified");

	GElf_Half machine;
	if ((machine = get_elf_machine()) == EM_NONE)
		errx(1, "Could not detect ELF machine type");

	if (!(ctx = so_begin(argv[1], machine)))
		errx(1, "Could not create context for DSO");

	so_end(ctx);
	return 0;
}
