#include <dlfcn.h>
#include <gelf.h>
#include <libelf.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <nlist.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <elfutils/libebl.h>
#include <elfutils/libasm.h>

#include <glib.h>

struct creator {
	const char *path;
	int fd;
	Elf *elf;
	GElf_Ehdr *ehdr;
	GElf_Ehdr ehdr_mem;
	size_t sns;
	Elf *oldelf;

	int dynidx;

	int hashidx;
	Elf64_Addr hashaddr;
	int strtabidx;
	Elf64_Addr strtabaddr;
	int symtabidx;
	Elf64_Addr symtabaddr;
	int relaidx;
	Elf64_Addr relaaddr;
	int relidx;
	Elf64_Addr reladdr;
	int gnuhashidx;
	Elf64_Addr gnuhashaddr;
};
static struct creator creator;


static void fixup_dynamic(void);
static void creator_destroy(int do_unlink)
{
	if (do_unlink) {
		if (creator.elf)
			elf_end(creator.elf);
		if (creator.fd >= 0)
			close(creator.fd);
		if (creator.path)
			unlink(creator.path);
	} else {
		if (creator.elf) {
			elf_update(creator.elf, ELF_C_WRITE_MMAP);
			elf_end(creator.elf);
		}
		if (creator.fd >= 0)
			close(creator.fd);
	}
	memset(&creator, '\0', sizeof(creator));
	creator.dynidx = -1;
	creator.hashidx = -1;
	creator.strtabidx = -1;
	creator.symtabidx = -1;
	creator.relaidx = -1;
	creator.relidx = -1;
	creator.gnuhashidx = -1;
}

int creator_begin(char *path, Elf *elf) {
	GElf_Ehdr ehdr_mem, *ehdr;
	GElf_Half machine;

	memset(&creator, '\0', sizeof(creator));
	creator_destroy(0);

	creator.dynidx = -1;
	creator.hashidx = -1;
	creator.strtabidx = -1;
	creator.symtabidx = -1;
	creator.relaidx = -1;
	creator.relidx = -1;
	creator.gnuhashidx = -1;

	creator.path = path;
	creator.oldelf = elf;

	ehdr = gelf_getehdr(elf, &ehdr_mem);
	machine = ehdr->e_machine;

	if ((creator.fd = open(path, O_RDWR|O_CREAT|O_TRUNC, 0755)) < 0) {
err:
		creator_destroy(1);
		return -1;
	}

	if (!(creator.elf = elf_begin(creator.fd, ELF_C_WRITE_MMAP, elf)))
		goto err;

	gelf_newehdr(creator.elf, gelf_getclass(elf));
	gelf_update_ehdr(creator.elf, ehdr);

	if (!(creator.ehdr = gelf_getehdr(creator.elf, &creator.ehdr_mem)))
		goto err;

	return 0;
}

static void creator_copy_scn(Elf *elf, Elf_Scn *scn, GElf_Shdr *shdr)
{
	Elf_Scn *newscn;
	Elf_Data *indata, *outdata;
	GElf_Shdr shdr_mem, *newshdr;

	creator.sns++;

	newscn = elf_newscn(creator.elf);
	newshdr = gelf_getshdr(newscn, &shdr_mem);

	memmove(newshdr, shdr, sizeof(*newshdr));
	switch (newshdr->sh_type) {
	case SHT_DYNAMIC:
		creator.dynidx = creator.sns;
		break;
	case SHT_HASH:
		creator.hashidx = creator.sns;
		creator.hashaddr = newshdr->sh_offset;
		break;
	case SHT_STRTAB:
		creator.strtabidx = creator.sns;
		creator.strtabaddr = newshdr->sh_offset;
		break;
	case SHT_SYMTAB:
		creator.symtabidx = creator.sns;
		creator.symtabaddr = newshdr->sh_offset;
		break;
	case SHT_RELA:
		creator.relaidx = creator.sns;
		creator.relaaddr = newshdr->sh_offset;
		break;
	case SHT_REL:
		creator.relidx = creator.sns;
		creator.reladdr = newshdr->sh_offset;
		break;
	case SHT_GNU_HASH:
		creator.gnuhashidx = creator.sns;
		creator.gnuhashaddr = newshdr->sh_offset;
		break;
	}

	gelf_update_shdr(newscn, newshdr);

	indata = NULL;
	while ((indata = elf_getdata(scn, indata)) != NULL) { 
		outdata = elf_newdata(newscn);
		*outdata = *indata;
	}
}

GElf_Dyn *get_dyn_by_tag(Elf_Data *dyndata, GElf_Shdr *dynshdr,
			Elf64_Sxword d_tag, GElf_Dyn *mem, size_t *idx)
{
	size_t cnt;
	for (cnt = 1; cnt < dynshdr->sh_size / dynshdr->sh_entsize; cnt++) {
		GElf_Dyn *dyn;

		dyn = gelf_getdyn(dyndata, cnt, mem);

		if (dyn == NULL)
			break;

		if (dyn->d_tag == d_tag) {
			*idx = cnt;
			return dyn;
		}
	}
	return NULL;
}

static void remove_dyn(Elf_Scn *scn, Elf_Data *dyndata, GElf_Shdr *dynshdr, size_t idx)
{
	size_t cnt;
	for (cnt = idx; cnt < dynshdr->sh_size / dynshdr->sh_entsize; cnt++) {
		GElf_Dyn *dyn, dyn_mem;

		if (cnt+1 == dynshdr->sh_size / dynshdr->sh_entsize) {
			memset(&dyn_mem, '\0', sizeof(dyn_mem));
			gelf_update_dyn(dyndata, cnt, &dyn_mem);
			break;
		}

		dyn = gelf_getdyn(dyndata, cnt+1, &dyn_mem);
		gelf_update_dyn(dyndata, cnt, dyn);
	}
	dynshdr->sh_size--;
	gelf_update_shdr(scn, dynshdr);
}

static void fixup_dynamic(void)
{
	Elf_Scn *dynscn = NULL;
	GElf_Shdr *dynshdr = NULL, dynshdr_mem;
	Elf_Data *dyndata;

	if (creator.dynidx < 0)
		return;
	dynscn = elf_getscn(creator.elf, creator.dynidx);
        dynshdr = gelf_getshdr(dynscn, &dynshdr_mem);
	dyndata = elf_getdata (dynscn, NULL);

	Elf_Scn *scn = NULL;

	GElf_Shdr *hash = NULL, hash_mem;
	if (creator.hashidx >= 0) {
		scn = elf_getscn(creator.elf, creator.hashidx);
		hash = gelf_getshdr(scn, &hash_mem);
	}

	GElf_Shdr *strtab = NULL, strtab_mem;
	if (creator.strtabidx >= 0) {
		scn = elf_getscn(creator.elf, creator.strtabidx);
		strtab = gelf_getshdr(scn, &strtab_mem);
	}

	GElf_Shdr *symtab = NULL, symtab_mem;
	if (creator.symtabidx >= 0) {
		scn = elf_getscn(creator.elf, creator.symtabidx);
		symtab = gelf_getshdr(scn, &symtab_mem);
	}

	GElf_Shdr *rela = NULL, rela_mem;
	if (creator.relaidx >= 0) {
		scn = elf_getscn(creator.elf, creator.relaidx);
		rela = gelf_getshdr(scn, &rela_mem);
	}

	GElf_Shdr *rel = NULL, rel_mem;
	if (creator.relidx >= 0) {
		scn = elf_getscn(creator.elf, creator.relidx);
		rel = gelf_getshdr(scn, &rel_mem);
	}

	GElf_Shdr *gnuhash = NULL, gnuhash_mem;
	if (creator.gnuhashidx >= 0) {
		scn = elf_getscn(creator.elf, creator.gnuhashidx);
		gnuhash = gelf_getshdr(scn, &gnuhash_mem);
	}

	GElf_Dyn *dyn, dyn_mem;
	size_t idx;

	dyn = get_dyn_by_tag(dyndata, dynshdr, DT_HASH, &dyn_mem, &idx);
	if (dyn) {
		if (hash) {
			dyn->d_un.d_ptr = creator.hashaddr;
			gelf_update_dyn(dyndata, idx, dyn);
		} else {
			remove_dyn(dynscn, dyndata, dynshdr, idx);
		}
	}

	dyn = get_dyn_by_tag(dyndata, dynshdr, DT_STRTAB, &dyn_mem, &idx);
	if (dyn) {
		if (strtab) {
			dyn->d_un.d_ptr = creator.strtabaddr;
			gelf_update_dyn(dyndata, idx, dyn);
		} else {
			remove_dyn(dynscn, dyndata, dynshdr, idx);
		}
	}

	dyn = get_dyn_by_tag(dyndata, dynshdr, DT_SYMTAB, &dyn_mem, &idx);
	if (dyn) {
		if (symtab) {
			dyn->d_un.d_ptr = creator.symtabaddr;
			gelf_update_dyn(dyndata, idx, dyn);
		} else {
			remove_dyn(dynscn, dyndata, dynshdr, idx);
		}
	}

	dyn = get_dyn_by_tag(dyndata, dynshdr, DT_RELA, &dyn_mem, &idx);
	if (dyn) {
		if (rela) {
			dyn->d_un.d_ptr = creator.relaaddr;
			gelf_update_dyn(dyndata, idx, dyn);
		} else {
			remove_dyn(dynscn, dyndata, dynshdr, idx);
			dyn = get_dyn_by_tag(dyndata, dynshdr, DT_RELASZ, &dyn_mem, &idx);
			if (dyn) {
				dyn->d_un.d_val = 0;
				gelf_update_dyn(dyndata, idx, dyn);
			}
		}
	}

	dyn = get_dyn_by_tag(dyndata, dynshdr, DT_REL, &dyn_mem, &idx);
	if (dyn) {
		if (rel) {
			dyn->d_un.d_ptr = creator.reladdr;
			gelf_update_dyn(dyndata, idx, dyn);
		} else {
			remove_dyn(dynscn, dyndata, dynshdr, idx);
			dyn = get_dyn_by_tag(dyndata, dynshdr, DT_RELSZ, &dyn_mem, &idx);
			if (dyn) {
				dyn->d_un.d_val = 0;
				gelf_update_dyn(dyndata, idx, dyn);
			}
		}
	}

	dyn = get_dyn_by_tag(dyndata, dynshdr, DT_GNU_HASH, &dyn_mem, &idx);
	if (dyn) {
		if (gnuhash) {
			dyn->d_un.d_ptr = creator.gnuhashaddr;
			gelf_update_dyn(dyndata, idx, dyn);
		} else {
			remove_dyn(dynscn, dyndata, dynshdr, idx);
		}
	}
}

void creator_end(void)
{
	GElf_Phdr phdr_mem, *phdr;
	int m,n;

	for (m = 0; (phdr = gelf_getphdr(creator.oldelf, m, &phdr_mem)) != NULL; m++)
		/* XXX this should check if an entry is needed */;
	
	gelf_newphdr(creator.elf, m);

	for (n = 0; n < m; n++) {
		phdr = gelf_getphdr(creator.oldelf, n, &phdr_mem);
		gelf_update_phdr(creator.elf, n, phdr);
	}

	fixup_dynamic();

	creator_destroy(0);
}

static void bogus_destructor(gpointer data)
{
	;
}

static int should_copy_scn(Elf *elf, GElf_Shdr *shdr, GHashTable *scns)
{
	char *name;
	size_t shstrndx;

	if (elf_getshdrstrndx(elf, &shstrndx) < 0)
		return 0;
	name = elf_strptr(elf, shstrndx, shdr->sh_name);
	if (name == NULL)
		return 0;

	if (g_hash_table_lookup(scns, name) == NULL)
		return 0;
	return 1;
}

int main(int argc, char *argv[])
{
	int n;
	GHashTable *sections;
	char *infile = NULL, *outfile = NULL;
	int fd;
	Elf *elf;
	Elf_Scn *scn;
	int copy_all_sections = 0;

	sections = g_hash_table_new_full(g_str_hash, g_str_equal,
					bogus_destructor, bogus_destructor);
	for (n = 1; n < argc; n++) {
		if (!strcmp(argv[n], "-a")) {
			copy_all_sections = 1;
		} else if (!strcmp(argv[n], "-s")) {
			if (n == argc-1) {
				fprintf(stderr, "Missing argument to -s\n");
				return -1;
			}
			n++;
			g_hash_table_insert(sections, argv[n], (void *)1);
			continue;
		} else if (!strcmp(argv[n], "-o")) {
			if (n == argc-1) {
				fprintf(stderr, "Missing argument to -o\n");
				return -1;
			}
			n++;
			outfile = argv[n];
			continue;
		} else if (!strcmp(argv[n], "-?") || !strcmp(argv[n],"--usage")) {
			printf("usage: pjoc -s section 0 [[-s section1] ... -s sectionN] -o outfile infile\n");
			return 0;
		} else if (n == argc-1) {
			infile = argv[n];
		} else {
			fprintf(stderr, "usage: pjoc -s section 0 [[-s section1] ... -s sectionN] -o outfile infile\n");
			return 1;
		}
	}
	if (!infile || !outfile) {
		fprintf(stderr, "usage: pjoc -s section 0 [[-s section1] ... -s sectionN] -o outfile infile\n");
		return 1;
	}

	if (!(fd = open(infile, O_RDONLY))) {
		fprintf(stderr, "Could not open \"%s\" for reading: %m\n", infile);
		return 1;
	}

	elf_version(EV_CURRENT);

	if ((elf = elf_begin(fd, ELF_C_READ_MMAP_PRIVATE, NULL)) == NULL) {
		fprintf(stderr, "cannot get elf descriptor for \"%s\": %s\n",
				infile, elf_errmsg(-1));
		close(fd);
		return 1;
	}

	if (elf_kind(elf) != ELF_K_ELF) {
		fprintf(stderr, "\"%s\" is not an ELF file\n", infile);
err:
		elf_end(elf);
		close(fd);
		return 1;
	}

	if (creator_begin(outfile, elf) < 0) {
		fprintf(stderr, "could not initialize ELF creator\n");
		goto err;
	}

	scn = NULL;
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		GElf_Shdr shdr_mem, *shdr;

		shdr = gelf_getshdr(scn, &shdr_mem);
		if (shdr == NULL)
			continue;

		if (!should_copy_scn(elf, shdr, sections) && !copy_all_sections)
			continue;

		creator_copy_scn(elf, scn, shdr);
	}
	creator_end();
	return 0;
}
