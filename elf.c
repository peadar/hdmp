#include <sys/types.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/procfs.h>
#include "queue.h"
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <link.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include "myelf.h"

/*
 * Culled from System V Application Binary Interface
 */
static unsigned long
elfhash(const char *name)
{
    unsigned long h = 0, g;
    while (*name != '\0') {
            h = (h << 4) + *name++;
            if ((g = h & 0xf0000000) != 0)
                    h ^= g >> 24;
            h &= ~g;
    }
    return (h);
}

static int
sortFuncTab(const void *a, const void *b)
{
    const struct FunctionInfo *l, *r;
    l = *(const struct FunctionInfo **)a;
    r = *(const struct FunctionInfo **)b;
    if (l->elfSym->st_value < r->elfSym->st_value)
        return -1;
    if (l->elfSym->st_value == r->elfSym->st_value)
        return 0;
    return 1;
}

static int
findFunction(const void *a, const void *b)
{
    const struct FunctionInfo *fi = *(struct FunctionInfo **)b;
    Elf_Addr addr = (Elf_Addr)a;
    if (fi->elfSym->st_value > addr)
        return -1;
    if (fi->elfSym->st_value + fi->elfSym->st_size <= addr)
        return 1;
    return 0;
}

/*
 * Parse out an ELF file into an ElfObject structure.
 * XXX: We probably don't use all the information we parse, and can probably
 * pear this down a bit.
 */
int
elf32LoadObjectFile(const char *fileName, struct ElfObject *obj)
{
    FILE *file;
    if ((file = fopen(fileName, "r")) == 0) {
            fprintf(stderr, "unable to open executable '%s': %s\n", fileName, strerror(errno));
            return (-1);
    }
    int rc = elf32LoadObject(file, obj);
    if (rc == 0) {
        obj->fileName = strdup(fileName);
        obj->baseName = strrchr(obj->fileName, '/');
        obj->baseName = obj->baseName ? obj->baseName + 1 : obj->fileName;
    } else {
        fclose(file);
    }
    return rc;
}

int
elf32UnloadObjectFile(struct ElfObject *obj)
{
    int rc = elf32UnloadObject(obj);
    fclose(obj->file);
    free(obj->fileName);
    return rc;
}

int
elf32LoadObject(FILE *file, struct ElfObject *obj)
{
    int i;
    Elf_Ehdr *eHdr;
    struct Section *sHdrs;
    struct Segment *pHdrs;
    struct Section *section;

    memset(obj, 0, sizeof *obj);

    obj->file = file;

    eHdr = &obj->elfHeader;
    int rc = fread(eHdr, sizeof *eHdr, 1, file);
    /* Validate the ELF header */
    if (rc != 1
            || !IS_ELF(obj->elfHeader)
            || eHdr->e_ident[EI_CLASS] != ELFCLASS32
            || eHdr->e_ident[EI_VERSION] > EV_CURRENT) {
        fprintf(stderr, "not an ELF image");
        return (-1);
    }

    obj->programHeaders = pHdrs = malloc(sizeof(struct Segment) * eHdr->e_phnum);
    obj->mappedData = 0;

    off_t off;

    for (off = eHdr->e_phoff, i = 0; i < eHdr->e_phnum; i++) {
        struct Segment *seg = &pHdrs[i];
        seg->data = 0;
        Elf_Phdr *phdr = &seg->phdr;
        fseeko(obj->file, off, SEEK_SET);
        ssize_t rc = fread(phdr, sizeof *phdr, 1, file);
        if (rc != 1)
            abort();
        switch (pHdrs[i].phdr.p_type) {
        case PT_INTERP:
                obj->interpreterName = elf32MapSegment(obj, seg);
                break;
        case PT_DYNAMIC:
                obj->dynamic = &pHdrs[i];
                break;
        }
        off += eHdr->e_phentsize;
    }

    obj->sectionHeaders = sHdrs = malloc(sizeof(struct Section) * eHdr->e_shnum);

    for (off = eHdr->e_shoff, i = 0; i < eHdr->e_shnum; i++) {
        fseeko(file, off, SEEK_SET);
        sHdrs[i].data = 0;
        ssize_t rc = fread(&sHdrs[i].shdr, sizeof (Elf_Shdr), 1, file);
        if (rc != 1)
            abort();
        off += eHdr->e_shentsize;
    }

    int ssi = eHdr->e_shstrndx;
    obj->sectionStrings = ssi != SHN_UNDEF ?  elf32MapSection(obj, &sHdrs[ssi]) : 0;

    if (elf32FindSectionByName(obj, ".stab", &section) != -1) {
        obj->stabs = elf32MapSection(obj, section);
        obj->stabCount = section->shdr.sh_size / sizeof (struct stab);
        if (section->shdr.sh_link)
            obj->stabStrings = elf32MapSection(obj, &sHdrs[section->shdr.sh_link]);
        else if (elf32FindSectionByName(obj, ".stabstr", &section) != -1)
            obj->stabStrings = elf32MapSection(obj, section);
        else
            obj->stabStrings = 0;
    } else {
        obj->stabs = 0;
        obj->stabCount = 0;
    }
    elf32ProcessFunctions(obj);
    return (0);
}

/*
 * Locate a symbol in an ELF image.
 */
int
elf32FindSymbolByName(struct ElfObject *o, const char *name,
                    const Elf_Sym **symp, const char **namep)
{
    struct Section *shdrs, *hash, *syms;
    const char *symStrings;
    const Elf_Sym *sym;
    Elf_Word nbucket;
    Elf_Word nchain;
    Elf_Word i;

    const Elf_Word *buckets;
    const Elf_Word *chains;
    const Elf_Word *hashData;
    unsigned long hashv;

    shdrs = o->sectionHeaders;

    /* First, search the hashed symbols in .dynsym.  */
    if (elf32FindSectionByName(o, ".hash", &hash) != -1) {
        syms = &shdrs[hash->shdr.sh_link];

        hashData = elf32MapSection(o, hash);
        sym = elf32MapSection(o, syms);
        symStrings = elf32MapSection(o, &shdrs[syms->shdr.sh_link]);

        nbucket = hashData[0];
        nchain = hashData[1];
        buckets = hashData + 2;
        chains = buckets + nbucket;
        hashv = elfhash(name) % nbucket;
        for (i = buckets[hashv]; i != STN_UNDEF; i = chains[i])
            if (strcmp(symStrings + sym[i].st_name, name) == 0) {
                *symp = sym + i;
                if (namep)
                    *namep = symStrings + sym[i].st_name;
                return (0);
            }
    } else if (elf32FindSectionByName(o, ".dynsym", &syms) != -1) {
        /* No ".hash", but have ".dynsym": do linear search */
        if (elf32LinearSymSearch(o, syms, name, symp, namep) != -1) {
            return (0);
        }
    }

    /* Do a linear search of ".symtab" if present */
    if (elf32FindSectionByName(o, ".symtab", &syms) != -1 &&
        elf32LinearSymSearch(o, syms, name, symp, namep) != -1) {
            return (0);
    }

    return -1;
}


void
elf32SymbolIterate(struct ElfObject *o, symiterfunc_t cb, void *state)
{
    struct Section *hdr;
    if (elf32FindSectionByName(o, ".dynsym", &hdr) != -1)
        elf32SymbolIterateSection(o, hdr, cb, state);
    if (elf32FindSectionByName(o, ".symtab", &hdr) != -1)
        elf32SymbolIterateSection(o, hdr, cb, state);
}

void
elf32SymbolIterateSection(struct ElfObject *o, struct Section *section, symiterfunc_t cb, void *state)
{
    struct Section *shdrs;
    const char *symStrings;
    const Elf_Sym *sym;
    int symCount, i;
    shdrs = o->sectionHeaders;

    sym = elf32MapSection(o, section);
    symStrings = elf32MapSection(o, &shdrs[section->shdr.sh_link]);

    symCount = section->shdr.sh_size / sizeof (Elf_Sym);
    for (i = 0; i < symCount; i++)
        cb(state, o, section, sym + i, symStrings + sym[i].st_name);
}

/*
 * Given an Elf32 object, find a particular section.
 */
int
elf32FindSectionByName(struct ElfObject *obj, const char *name, struct Section **shdrp)
{
    int i;

    for (i = 0; i < obj->elfHeader.e_shnum; i++)
        if (strcmp(obj->sectionHeaders[i].shdr.sh_name + obj->sectionStrings, name) == 0) {
            *shdrp = &obj->sectionHeaders[i];
            return (i);
        }
    return (-1);
}

int
elf32LinearSymSearch(struct ElfObject *o, struct Section *section,
                    const char *name, const Elf_Sym **symp,
                    const char **namep)
{
    struct Section *shdrs;
    const char *symStrings;
    const Elf_Sym *sym;
    int symCount, i;
    shdrs = o->sectionHeaders;
    sym = elf32MapSection(o, section);
    symStrings = elf32MapSection(o, &shdrs[section->shdr.sh_link]);
    symCount = section->shdr.sh_size / sizeof (Elf_Sym);
    for (i = 0; i < symCount; i++) {
        if (!strcmp(symStrings + sym[i].st_name, name)) {
            if (namep)
                *namep = symStrings + sym->st_name;
            *symp = sym + i;
            return (i);
        }
    }
    return (-1);
}

void
elf32ProcessFunctions(struct ElfObject *obj)
{
    struct FunctionInfo *si;
    int section;
    const struct stab *lineNumbers = 0, *function = 0, *args = 0;
    const Elf_Sym *sym;

    struct Section *symtab, *shdrs;
    static char *symsections[] = {
        ".dynsym",
        ".symtab",
        0
    };
    int stringOffset = 0, nextStringOffset = 0, i, j, fileSp = 0;
    int symCount, funcCount = 0, funcTabSize = 0;
    const char *symStrings;
    struct FunctionInfo **funcTab = 0, *funcInfo;

    const char *fileStack[128];
    fileStack[0] = 0;
    obj->functionTable = 0;
    obj->functionTableLength = 0;


    /* Run through the ELF symbol tables, locating all the functions */
    shdrs = obj->sectionHeaders;
    for (i = 0; symsections[i]; i++) {
        if (elf32FindSectionByName(obj, symsections[i], &symtab) == -1)
                continue;

        symStrings = elf32MapSection(obj, &shdrs[symtab->shdr.sh_link]);
        sym = elf32MapSection(obj, symtab);
        symCount = symtab->shdr.sh_size / sizeof(Elf_Sym);

        for (j = 0; j < symCount; j++) {
            if (ELF32_ST_TYPE(sym[j].st_info) != STT_FUNC)
                continue;
            section = sym[j].st_shndx;
            if (section >= obj->elfHeader.e_shnum || (shdrs[section].shdr.sh_flags & SHF_ALLOC) == 0)
                continue;
            if (funcCount == funcTabSize) {
                funcTabSize += 1024;
                funcTabSize = funcTabSize + funcTabSize / 2;
                funcTab = realloc(funcTab, sizeof (*funcTab) *
                    funcTabSize);
            }
            funcTab[funcCount++] = funcInfo = malloc(sizeof *funcInfo);
            funcInfo->elfSym = sym + j;
            funcInfo->elfName = symStrings + sym[j].st_name;
            funcInfo->stabStringOffset = 0;
            funcInfo->fileName = 0;
            funcInfo->function = 0;
            funcInfo->args = 0;
            funcInfo->lineNumbers = 0;
        }
    }

    if (!funcCount)
        return;

    /* Sort the functions by address */
    qsort(funcTab, funcCount, sizeof *funcTab, sortFuncTab);

    /* Remove duplicates */

    for (i = 1, j = 0; i < funcCount; i++) {
            if (funcTab[i]->elfSym->st_value !=
                funcTab[j]->elfSym->st_value)
                    funcTab[++j] = funcTab[i];
            else
                    free(funcTab[i]);
    }
    obj->functionTableLength = j + 1;
    obj->functionTable = funcTab;

    for (i = 0; i < obj->stabCount; i++) {
            const struct stab *stab = obj->stabs + i;

            switch (stab->n_type) {
            case N_UNDF:
                    stringOffset += nextStringOffset;
                    nextStringOffset = stab->n_value;
                    break;
            case N_SO:
                    fileSp = 0;
                    fileStack[0] = stab->n_strx + obj->stabStrings + stringOffset;
                    break;

            case N_SOL:
                    fileStack[fileSp] = stab->n_strx + obj->stabStrings + stringOffset;
                    break;

            case N_BINCL:
                    assert(fileSp < 128);
                    fileStack[++fileSp] = stab->n_strx + obj->stabStrings + stringOffset;
                    break;

            case N_EINCL:
                    --fileSp;
                    assert(fileSp >= 0);
                    break;

            case N_PSYM:
                    if (!args)
                            args = stab;
                    break;

            case N_SLINE:
                    if (!lineNumbers)
                            lineNumbers = stab;
                    break;

            case N_FUN:
                    if (stab->n_strx == 0 ||
                        *(obj->stabStrings + stringOffset +
                        stab->n_strx) == 0) {
                            /* End of a function: fill in funcinfo */
                            if (elf32FindFunction(obj, function->n_value,
                                &si) != -1) {
                                    si->stabStringOffset = stringOffset;
                                    si->fileName = fileStack[fileSp];
                                    si->function = function;
                                    si->args = args;
                                    si->lineNumbers = lineNumbers;
                            }
                    } else if (!function || function->n_value !=
                        stab->n_value) {
                            args = lineNumbers = 0;
                            function = stab;
                    }
                    break;
            }
    }
}

int
elf32FindFunction(struct ElfObject *obj, Elf_Addr loc,
    struct FunctionInfo **f)
{
    void *p;
    if (obj->functionTable == 0)
        return -1;
    p = bsearch((const void *)loc, obj->functionTable,
            obj->functionTableLength, sizeof *obj->functionTable, findFunction);
    if (!p)
        return -1;
    *f = *(struct FunctionInfo **)p;
    return 0;
}

/*
 * Free any resources assoiated with an ElfObject
 */
int
elf32UnloadObject(struct ElfObject *obj)
{
    int i;
    for (i = 0; i < obj->functionTableLength; i++)
        free(obj->functionTable[i]);
    for (i = 0; i < obj->elfHeader.e_phnum; i++)
        free(obj->programHeaders[i].data);
    for (i = 0; i < obj->elfHeader.e_shnum; i++)
        if (obj->sectionHeaders[i].owns)
            free(obj->sectionHeaders[i].data);
    free(obj->programHeaders);
    free(obj->sectionHeaders);
    free(obj->functionTable);
    fprintf(stderr, "mapped data: %lu\n", obj->mappedData);
    return (0);
}

/*
 * Debug output of the contents of an ELF32 section
 */
void
elf32DumpSection(FILE *f, struct ElfObject *obj, struct Section *hdr,
			int indent)
{
    const Elf_Sym * sym, *esym;
    int i;
    const char *symStrings, *padding = pad(indent);

    static const char *sectionTypeNames[] = {
            "SHT_NULL",
            "SHT_PROGBITS",
            "SHT_SYMTAB",
            "SHT_STRTAB",
            "SHT_RELA",
            "SHT_HASH",
            "SHT_DYNAMIC",
            "SHT_NOTE",
            "SHT_NOBITS",
            "SHT_REL",
            "SHT_SHLIB",
            "SHT_DYNSYM",
    };

    fprintf(f, "%sname= %s\n"
        "%stype= %d (%s)\n"
        "%sflags= %xH (%s%s%s)\n"
        "%saddress= %xH\n"
        "%soffset= %d (%xH)\n"
        "%ssize= %d (%xH)\n"
        "%slink= %d (%xH)\n"
        "%sinfo= %d (%xH)\n" ,
        padding, obj->sectionStrings + hdr->shdr.sh_name,
        padding, hdr->shdr.sh_type, hdr->shdr.sh_type <= SHT_DYNSYM ?
        sectionTypeNames[hdr->shdr.sh_type] : "unknown",
        padding,
        hdr->shdr.sh_flags,
        hdr->shdr.sh_flags & SHF_WRITE ? "write " : "",
        hdr->shdr.sh_flags & SHF_ALLOC ? "alloc " : "",
        hdr->shdr.sh_flags & SHF_EXECINSTR ? "instructions " : "",
        padding, hdr->shdr.sh_addr,
        padding, hdr->shdr.sh_offset, hdr->shdr.sh_offset,
        padding, hdr->shdr.sh_size, hdr->shdr.sh_size,
        padding, hdr->shdr.sh_link, hdr->shdr.sh_link,
        padding, hdr->shdr.sh_info, hdr->shdr.sh_info);

    switch (hdr->shdr.sh_type) {
    case SHT_SYMTAB:
    case SHT_DYNSYM:
            symStrings = elf32MapSection(obj, &obj->sectionHeaders[hdr->shdr.sh_link]);
            sym = elf32MapSection(obj, hdr);
            esym = (const Elf_Sym *) ((char *)sym + hdr->shdr.sh_size);

            for (i = 0; sym < esym; i++) {
                printf("%ssymbol %d:\n", padding, i);
                elf32DumpSymbol(f, sym, symStrings, indent + 4);
                sym++;
            }
            break;
    }
}

/*
 * Debug output of an ELF32 program segment
 */
void
elf32DumpProgramSegment(FILE *f, struct ElfObject *obj, const Elf_Phdr *hdr,
			int indent)
{
    const char *padding = pad(indent);
    static const char *segmentTypeNames[] = {
            "PT_NULL",
            "PT_LOAD",
            "PT_DYNAMIC",
            "PT_INTERP",
            "PT_NOTE",
            "PT_SHLIB",
            "PT_PHDR"
    };

    fprintf(f, "%stype = %xH (%s)\n"
        "%soffset = %xH (%d)\n"
        "%svirtual address = %xH (%d)\n"
        "%sphysical address = %xH (%d)\n"
        "%sfile size = %xH (%d)\n"
        "%smemory size = %xH (%d)\n"
        "%sflags = %xH (%s %s %s)\n"
        "%salignment = %xH (%d)\n",
        padding, hdr->p_type,
        hdr->p_type <= PT_PHDR ? segmentTypeNames[hdr->p_type] : "unknown",
        padding, hdr->p_offset, hdr->p_offset,
        padding, hdr->p_vaddr, hdr->p_vaddr,
        padding, hdr->p_paddr, hdr->p_paddr,
        padding, hdr->p_filesz, hdr->p_filesz,
        padding, hdr->p_memsz, hdr->p_memsz,
        padding, hdr->p_flags,
        hdr->p_flags & PF_R ? "PF_R" : "",
        hdr->p_flags & PF_W ? "PF_W" : "",
        hdr->p_flags & PF_X ? "PF_X" : "",
        padding, hdr->p_align, hdr->p_align);

}

/*
 * Debug output of an Elf32 symbol.
 */
void
elf32DumpSymbol(FILE *f, const Elf_Sym * sym, const char *strings, int indent)
{
	static const char *bindingNames[] = {
		"STB_LOCAL",
		"STB_GLOBAL",
		"STB_WEAK",
		"unknown3",
		"unknown4",
		"unknown5",
		"unknown6",
		"unknown7",
		"unknown8",
		"unknown9",
		"unknowna",
		"unknownb",
		"unknownc",
		"STB_LOPROC",
		"STB_LOPROC + 1",
		"STB_HIPROC + 1",
	};

	static const char *typeNames[] = {
		"STT_NOTYPE",
		"STT_OBJECT",
		"STT_FUNC",
		"STT_SECTION",
		"STT_FILE",
		"STT_5",
		"STT_6",
		"STT_7",
		"STT_8",
		"STT_9",
		"STT_A",
		"STT_B",
		"STT_C",
		"STT_LOPROC",
		"STT_LOPROC + 1",
		"STT_HIPROC"
	};

	const char *padding = pad(indent);

	fprintf(f,
	    "%sname = %s\n"
	    "%svalue = %d (%xH)\n"
	    "%ssize = %d (%xH)\n"
	    "%sinfo = %d (%xH)\n"
	    "%sbinding = %s\n"
	    "%stype = %s\n"
	    "%sother = %d (%xH)\n"
	    "%sshndx = %d (%xH)\n",
	    padding, sym->st_name ? strings + sym->st_name : "(unnamed)",
	    padding, sym->st_value, sym->st_value,
	    padding, sym->st_size, sym->st_size,
	    padding, sym->st_info, sym->st_info,
	    pad(indent + 4), bindingNames[sym->st_info >> 4],
	    pad(indent + 4), typeNames[sym->st_info & 0xf],
	    padding, sym->st_other, sym->st_other,
	    padding, sym->st_shndx, sym->st_shndx);
}

/*
 * Debug output of an ELF32 dynamic item
 */

void
elf32DumpDynamic(FILE *f, const Elf_Dyn *dyn, int indent)
{
	const char *padding = pad(indent);
	static const char *tagNames[] = {
	    "DT_NULL",
	    "DT_NEEDED",
	    "DT_PLTRELSZ",
	    "DT_PLTGOT",
	    "DT_HASH",
	    "DT_STRTAB",
	    "DT_SYMTAB",
	    "DT_RELA",
	    "DT_RELASZ",
	    "DT_RELAENT",
	    "DT_STRSZ",
	    "DT_SYMENT",
	    "DT_INIT",
	    "DT_FINI",
	    "DT_SONAME",
	    "DT_RPATH",
	    "DT_SYMBOLIC",
	    "DT_REL",
	    "DT_RELSZ",
	    "DT_RELENT",
	    "DT_PLTREL",
	    "DT_DEBUG",
	    "DT_TEXTREL",
	    "DT_JMPREL",
	    "DT_BIND_NOW"
	};
#ifndef DT_COUNT
#define DT_COUNT (sizeof tagNames / sizeof tagNames[0])
#endif
	fprintf(f, "%stag: %d (%s)\n", padding, dyn->d_tag,
	    dyn->d_tag >= 0 && dyn->d_tag <= DT_COUNT ?
	    tagNames[dyn->d_tag] : "(unknown)");
	fprintf(f, "%sword/addr: %d (%x)\n",
	    padding, dyn->d_un.d_val, dyn->d_un.d_val);
}


/*
 * Debug output of an ELF32 object.
 */

static const char *
stabType(enum StabType t)
{
	switch (t) {
	case N_UNDF: return "N_UNDF";
	case N_ABS: return "N_ABS";
	case N_ABS_EXT: return "N_ABS_EXT";
	case N_TEXT: return "N_TEXT";
	case N_TEXT_EXT: return "N_TEXT_EXT";
	case N_DATA: return "N_DATA";
	case N_DATA_EXT: return "N_DATA_EXT";
	case N_BSS: return "N_BSS";
	case N_BSS_EXT: return "N_BSS_EXT";
	case N_FN_SEQ: return "N_FN_SEQ";
	case N_INDR: return "N_INDR";
	case N_COMM: return "N_COMM";
	case N_SETA: return "N_SETA";
	case N_SETA_EXT: return "N_SETA_EXT";
	case N_SETT: return "N_SETT";
	case N_SETT_EXT: return "N_SETT_EXT";
	case N_SETD: return "N_SETD";
	case N_SETD_EXT: return "N_SETD_EXT";
	case N_SETB: return "N_SETB";
	case N_SETB_EXT: return "N_SETB_EXT";
	case N_SETV: return "N_SETV";
	case N_SETV_EXT: return "N_SETV_EXT";
	case N_WARNING: return "N_WARNING";
	case N_FN: return "N_FN";
	case N_GSYM: return "N_GSYM";
	case N_FNAME: return "N_FNAME";
	case N_FUN: return "N_FUN";
	case N_STSYM: return "N_STSYM";
	case N_LCSYM: return "N_LCSYM";
	case N_MAIN: return "N_MAIN";
	case N_PC: return "N_PC";
	case N_NSYMS: return "N_NSYMS";
	case N_NOMAP: return "N_NOMAP";
	case N_OBJ: return "N_OBJ";
	case N_OPT: return "N_OPT";
	case N_RSYM: return "N_RSYM";
	case N_M2C: return "N_M2C";
	case N_SLINE: return "N_SLINE";
	case N_DSLINE: return "N_DSLINE";
	case N_BSLINE: return "N_BSLINE";
	case N_DEFD: return "N_DEFD";
	case N_FLINE: return "N_FLINE";
	case N_EHDECL: return "N_EHDECL";
	case N_CATCH: return "N_CATCH";
	case N_SSYM: return "N_SSYM";
	case N_ENDM: return "N_ENDM";
	case N_SO: return "N_SO";
	case N_LSYM: return "N_LSYM";
	case N_BINCL: return "N_BINCL";
	case N_SOL: return "N_SOL";
	case N_PSYM: return "N_PSYM";
	case N_EINCL: return "N_EINCL";
	case N_ENTRY: return "N_ENTRY";
	case N_LBRAC: return "N_LBRAC";
	case N_EXCL: return "N_EXCL";
	case N_SCOPE: return "N_SCOPE";
	case N_RBRAC: return "N_RBRAC";
	case N_BCOMM: return "N_BCOMM";
	case N_ECOMM: return "N_ECOMM";
	case N_ECOML: return "N_ECOML";
	case N_WITH: return "N_WITH";
	case N_NBTEXT: return "N_NBTEXT";
	case N_NBDATA: return "N_NBDATA";
	case N_NBBSS: return "N_NBBSS";
	case N_NBSTS: return "N_NBSTS";
	case N_NBLCS: return "N_NBLCS";
	default: return "unknown";
	}
}

void
elf32DumpObject(FILE *f, struct ElfObject *obj, int indent)
{
	int brand;
	int i;
	static const char *typeNames[] = {
		"ET_NONE",
		"ET_REL",
		"ET_EXEC",
		"ET_DYN",
		"ET_CORE"
	};
	static const char *abiNames[] = {
	    "SYSV/NONE",
	    "HP-UX",
	    "NetBSD",
	    "Linux",
	    "Hurd",
	    "86Open",
	    "Solaris",
	    "Monterey",
	    "Irix",
	    "FreeBSD",
	    "Tru64",
	    "Modesto",
	    "OpenBSD"
	};
	const Elf_Ehdr *ehdr = &obj->elfHeader;
	const Elf_Dyn *dyn, *edyn;

	const char *padding = pad(indent);

	brand = ehdr->e_ident[EI_OSABI];

	fprintf(f, "%sType= %s\n", padding, typeNames[ehdr->e_type]);
	fprintf(f, "%sEntrypoint= %x\n", padding, ehdr->e_entry);
	fprintf(f, "%sExetype= %d (%s)\n", padding, brand,
		brand >= 0  && brand <= sizeof abiNames / sizeof abiNames[0] ?
		abiNames[brand] : "unknown");

        for (i = 1; i < obj->elfHeader.e_shnum; i++) {
            fprintf(f, "%ssection %d:\n", padding, i);
            elf32DumpSection(f, obj, &obj->sectionHeaders[i], indent + 4);
        }

        for (i = 0; i < obj->elfHeader.e_phnum; i++) {
            fprintf(f, "%ssegment %d:\n", padding, i);
            elf32DumpProgramSegment(f, obj, &obj->programHeaders[i].phdr, indent + 4);
        }

        if (obj->dynamic) {
            dyn = elf32MapSegment(obj, obj->dynamic);
            edyn = (const Elf_Dyn *) ((char *)dyn + obj->dynamic->phdr.p_filesz);
            while (dyn < edyn) {
                printf("%sdynamic entry\n", padding - 4);
                elf32DumpDynamic(f, dyn, indent + 8);
                dyn++;
            }
        }
	if (obj->interpreterName)
            fprintf(f, "%sinterpreter %s\n", padding, obj->interpreterName);

        if (obj->stabs) {
            const struct stab *stab;
            int i;
            int stringOffset = 0;
            int nextStringOffset = 0;
            printf("%sstabs:\n", padding);
            for (i = 0; i < obj->stabCount; i++) {
                    stab = obj->stabs + i;
                    printf("%sstab %d\n", pad(indent + 4), i);
                    printf("%stype %s(%d)\n", pad(indent + 8), stabType(stab->n_type), stab->n_type);
                    printf("%svalue %ld %lxh\n", pad(indent + 8), (long)stab->n_value, (long)stab->n_value);
                    printf("%sstring \"%s\" %s\n", pad(indent + 8), obj->stabStrings + stringOffset + stab->n_strx, stab->n_strx ? "" : "(not-present)");
                    printf("%sdesc %d\n", pad(indent + 8), stab->n_desc);
                    printf("%sother %d\n", pad(indent + 8), stab->n_other);
                    if (stab->n_type == N_UNDF) {
                            stringOffset += nextStringOffset;
                            nextStringOffset = stab->n_value;
                    }
            }
        }
}

/*
 * Helps for pretty-printing
 */
const char *
pad(int size)
{
	static const char paddingChars[] = "                                                                                ";
	if (size > sizeof paddingChars - 1)
		size = sizeof paddingChars - 1;
	return (paddingChars + sizeof paddingChars - 1 - size);
}

void
hexdump(FILE *f, int indent, const char *p, int len)
{
    const unsigned char *cp = (const unsigned char *)p;
    char hex[16 * 3 + 1], *hp, ascii[16 + 1], *ap;
    int i, c;

    while (len) {
        hp = hex;
        ap = ascii;
        for (i = 0; len && i < 16; i++) {
            c = *cp++;
            len--;
            hp += sprintf(hp, "%02x ", c);
            *ap++ = c < 127 && c >= 32 ? c : '.';
        }
        *ap = 0;
        fprintf(f, "%s%-48s |%-16s|\n", pad(indent), hex, ascii);
    }
}

/*
 * Find the mapped object within which "addr" lies
 */
int
elf32FindObject(struct ElfObject *objlist, Elf_Addr addr, struct ElfObject **objp)
{
    const Elf_Phdr *phdr;
    Elf_Addr segAddr;
    int i;

    for (; objlist; objlist = objlist->next) {
        for (i = 0; i < objlist->elfHeader.e_phnum; i++) {
            phdr = &objlist->programHeaders[i].phdr;
            segAddr = phdr->p_vaddr + objlist->baseAddr;
            if (addr >= segAddr && addr < segAddr + phdr->p_memsz) {
                *objp = objlist;
                return (0);
            }
        }
    }
    return (-1);
}

void *
loadData(struct ElfObject *obj, off_t offset, size_t count)
{
    void *p;
    p = malloc(count);
    obj->mappedData += count;
    fseeko(obj->file, offset, SEEK_SET);
    int countIn = fread(p, 1, count, obj->file);
    if (countIn != count) {
        free(p);
        return 0;
    } else {
        return p;
    }
}

void *
elf32MapSegment(struct ElfObject *obj, struct Segment *segment)
{
    if (segment->data)
        return segment->data;
    segment->data = loadData(obj, segment->phdr.p_offset, segment->phdr.p_filesz);
    return segment->data;
}

void *
elf32MapSection(struct ElfObject *obj, struct Section *section)
{
    if (section->data)
        return section->data;

    // Find what segment this section is in.
    Elf_Addr secStart = section->shdr.sh_offset;
    Elf_Addr secEnd = secStart + section->shdr.sh_size;
    size_t i;

    for (i = 0; i < obj->elfHeader.e_phnum; i++) {
        struct Segment *seg = &obj->programHeaders[i];
        Elf_Phdr *phdr = &seg->phdr;
        if (phdr->p_offset <= secStart && secEnd <= phdr->p_offset + phdr->p_filesz) {
            section->owns = 0;
            return section->data = elf32MapSegment(obj, seg) + secStart - phdr->p_offset;
        }
    }

    section->data = loadData(obj, section->shdr.sh_offset, section->shdr.sh_size);
    section->owns = 1;
    return section->data;
}
