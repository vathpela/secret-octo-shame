#include <dlfcn.h>
#include <elfutils/libebl.h>
#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdio.h>
#include <nlist.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct GElf_SymX {
	GElf_Sym sym;
	Elf32_Word xndx;
	char *where;
} GElf_SymX;

int main(int argc, char *argv[])
{
	void *h;
	int fd;
	Elf *elf;
	struct nlist symbols[1024];
	GElf_Word symsec_type = SHT_DYNSYM;
	GElf_Ehdr ehdr_mem;
	GElf_Ehdr *ehdr;
	Elf_Scn *scn = NULL;
	int n;
	int i;

	if (argc < 2)
		return 1;

	if (!(fd = open(argv[1], O_RDONLY)))
		err(1, "Could not open \"%s\"", argv[1]);

	elf_version(EV_CURRENT);

	if ((elf = elf_begin(fd, ELF_C_READ_MMAP, NULL)) == NULL)
		errx(1, "Cannot get elf descriptor for %s: %s", argv[1],
		     elf_errmsg(-1));

	if (elf_kind(elf) != ELF_K_ELF) {
		elf_end(elf);
		close(fd);
		errx(1, "\"%s\" is not an elf file", argv[1]);
	}

	ehdr = gelf_getehdr(elf, &ehdr_mem);

	if (symsec_type == SHT_DYNSYM && ehdr->e_type != ET_EXEC &&
	    ehdr->e_type != ET_DYN) {
		close(fd);
		elf_end(elf);
		errx(1, "\"%s\" is not a dynamic shared object", argv[1]);
	}

	Ebl *ebl;

	if (!(ebl = ebl_openbackend(elf)))
		errx(1, "Could not open ebl backend");

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		GElf_Shdr shdr_mem;
		GElf_Shdr *shdr = gelf_getshdr(scn, &shdr_mem);
		size_t shstrndx;

		if (symsec_type != shdr->sh_type)
			continue;

		if (elf_getshdrstrndx(elf, &shstrndx) < 0)
			errx(1, "elf_getshstrndx() failed");

		size_t size = shdr->sh_size;
		size_t entsize = shdr->sh_entsize;
		size_t nentries = size / (entsize ? : 1);

		if (entsize != gelf_fsize(elf, ELF_T_SYM, 1, ehdr->e_version))
			errx(1, "ELF is malformed.");

		GElf_SymX *sym_mem;

		sym_mem = (GElf_SymX *) malloc(nentries * sizeof(GElf_SymX));
		Elf_Data *data = elf_getdata(scn, NULL);
		if (data == NULL)
			errx(1, "elf_getdata() failed");

		size_t nentries_used = 0;
		for (size_t cnt = 0; cnt < nentries; ++cnt) {
			GElf_Sym *sym;

			sym = gelf_getsymshndx(data, NULL, cnt,
					       &sym_mem[nentries_used].sym,
					       &sym_mem[nentries_used].xndx);
			if (sym == NULL)
				errx(1, "sym was NULL");

			if (sym->st_shndx != SHN_UNDEF)
				continue;

			const char *symstr = elf_strptr(elf, shdr->sh_link,
							sym->st_name);
			if (symstr == NULL || symstr[0] == '\0')
				continue;

			nentries_used++;

			printf("symbol is %s\n", symstr);
		}
	}

	ebl_closebackend(ebl);
	elf_end(elf);
	close(fd);

	return 0;
	n = nlist(argv[1], &symbols[0]);
	printf("n is %d\n", n);
	for (i = 0; i < 1024; i++) {
		if (symbols[i].n_name == NULL)
			break;
		printf("%s %ld %d %d\n", symbols[i].n_name, symbols[i].n_value,
		       symbols[i].n_type, symbols[i].n_sclass);
	}

	h = dlopen(argv[1], RTLD_LAZY);
	if (!h)
		errx(1, "cannot open '%s': %s", argv[1], dlerror());

	elf_end(elf);
	return 0;
}
