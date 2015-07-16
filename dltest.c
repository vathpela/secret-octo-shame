#include <dlfcn.h>
#include <gelf.h>
#include <libelf.h>
#include <stdio.h>
#include <nlist.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <elfutils/libebl.h>

typedef struct GElf_SymX
{
	GElf_Sym sym;
	Elf32_Word xndx;
	char *where;
} GElf_SymX;


int main(int argc, char *argv[]) {
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

	if (!(fd = open(argv[1], O_RDONLY))) {
		perror("open");
		return 1;
	}

	elf_version (EV_CURRENT);

	if ((elf = elf_begin(fd, ELF_C_READ_MMAP, NULL)) == NULL) {
		printf("cannot get elf descriptor for %s: %s\n", argv[1],
			elf_errmsg(-1));
		return 1;
	}

	if (elf_kind(elf) != ELF_K_ELF) {
		elf_end(elf);
		close(fd);
		printf("this isn't an elf file\n");
		return 1;
	}

	ehdr = gelf_getehdr(elf, &ehdr_mem);

	if (symsec_type == SHT_DYNSYM && ehdr->e_type != ET_EXEC &&
			ehdr->e_type != ET_DYN) {
		close(fd);
		elf_end(elf);
		printf("this isn't dynamic\n");
		return 1;
	}

	Ebl *ebl;

	if (!(ebl = ebl_openbackend(elf))) {
		printf("couldn't open backend\n");
		return 1;
	}

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		GElf_Shdr shdr_mem;
		GElf_Shdr *shdr = gelf_getshdr (scn, &shdr_mem);
		size_t shstrndx;

		if (symsec_type != shdr->sh_type)
			continue;

		if (elf_getshdrstrndx (elf, &shstrndx) < 0) {
			printf("elf_getshstrndx() failed\n");
			return 1;
		}

		size_t size = shdr->sh_size;
		size_t entsize = shdr->sh_entsize;
		size_t nentries = size / (entsize ?: 1);

		if (entsize != gelf_fsize (elf, ELF_T_SYM, 1, ehdr->e_version)) {
			printf("elf is malformed\n");
			return 1;
		}


		GElf_SymX *sym_mem;

		sym_mem = (GElf_SymX *) malloc(nentries * sizeof (GElf_SymX));
		Elf_Data *data = elf_getdata (scn, NULL);
		if (data == NULL) {
			printf("elf_getdata failed\n");
			return 1;
		}

		size_t nentries_used = 0;
		for (size_t cnt = 0; cnt < nentries; ++cnt) {
			GElf_Sym *sym = gelf_getsymshndx(data, NULL, cnt,
				&sym_mem[nentries_used].sym,
				&sym_mem[nentries_used].xndx);

			if (sym == NULL) {
				printf("sym was NULL\n");
				return 1;
			}

			if (sym->st_shndx != SHN_UNDEF)
				continue;

			const char *symstr = elf_strptr(elf, shdr->sh_link,
					sym->st_name);
			if (symstr == NULL || symstr[0] == '\0')
				continue;

			nentries_used ++;

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
	if (!h) {
		printf("cannot open '%s': %s\n", argv[1], dlerror());
		return 1;
	}

	elf_end(elf);
	return 0;
}
