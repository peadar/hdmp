struct FunctionInfo {
    const Elf32_Sym *elfSym;
    const char *elfName;
    int stabStringOffset;
    const struct stab *lineNumbers;
    const struct stab *function;
    const struct stab *args;
    const struct stab *locals;
    const char *fileName;
    void *udat;
};

struct Segment {
    Elf32_Phdr phdr;
    void *data; // data == 0 => non-mapped segment.
};

struct Section {
    Elf32_Shdr shdr;
    void *data; // data == 0 => non-mapped segment.
    int owns; // this section owns its own data (not contained in a segment)
};

struct ElfObject {
        FILE *file;
        struct ElfObject *next;

	Elf32_Ehdr elfHeader;

	Elf32_Addr	baseAddr; /* For loaded objects */
	char		*fileName;
	char		*baseName;
	struct Segment *programHeaders;
	struct Section *sectionHeaders;
        struct Segment *dynamic;
	const char	*sectionStrings;
	const char	*interpreterName;
	const char	*stabStrings;
        const struct stab *stabs;
        int stabCount;
        struct FunctionInfo **functionTable;
        int functionTableLength;
        void *udat;
        unsigned long mappedData;
};

struct stab {
	unsigned long n_strx;
	unsigned char n_type;
	unsigned char n_other;
	unsigned short n_desc;
	unsigned long n_value;
};

enum StabType {
    N_UNDF = 0x0,
    N_ABS = 0x2,
    N_ABS_EXT = 0x3,
    N_TEXT = 0x4,
    N_TEXT_EXT = 0x5,
    N_DATA = 0x6,
    N_DATA_EXT = 0x7,
    N_BSS = 0x8,
    N_BSS_EXT = 0x9,
    N_FN_SEQ = 0x0c,
    N_INDR = 0x0a,
    N_COMM = 0x12,
    N_SETA = 0x14,
    N_SETA_EXT = 0x15,
    N_SETT = 0x16,
    N_SETT_EXT = 0x17,
    N_SETD = 0x18,
    N_SETD_EXT = 0x19,
    N_SETB = 0x1a,
    N_SETB_EXT = 0x1b,
    N_SETV = 0x1c,
    N_SETV_EXT = 0x1d,
    N_WARNING = 0x1e,
    N_FN = 0x1f,
    N_GSYM = 0x20,
    N_FNAME = 0x22,
    N_FUN = 0x24,
    N_STSYM = 0x26,
    N_LCSYM = 0x28,
    N_MAIN = 0x2a,
    n_ROSYM = 0x2c,
    N_PC = 0x30,
    N_NSYMS = 0x32,
    N_NOMAP = 0x34,
    N_OBJ = 0x38,
    N_OPT = 0x3c,
    N_RSYM = 0x40,
    N_M2C = 0x42,
    N_SLINE = 0x44,
    N_DSLINE = 0x46,
    N_BSLINE = 0x48,
    N_DEFD = 0x4a,
    N_FLINE = 0x4c,
    N_EHDECL = 0x50,
    N_CATCH = 0x54,
    N_SSYM = 0x60,
    N_ENDM = 0x62,
    N_SO = 0x64,
    N_LSYM = 0x80,
    N_BINCL = 0x82,
    N_SOL = 0x84,
    N_PSYM = 0xa0,
    N_EINCL = 0xa2,
    N_ENTRY = 0xa4,
    N_LBRAC = 0xc0,
    N_EXCL = 0xc2,
    N_SCOPE = 0xc4,
    N_RBRAC = 0xe0,
    N_BCOMM = 0xe2,
    N_ECOMM = 0xe4,
    N_ECOML = 0xe8,
    N_WITH = 0xea,
    N_NBTEXT = 0xf0,
    N_NBDATA = 0xf2,
    N_NBBSS = 0xf4,
    N_NBSTS = 0xf6,
    N_NBLCS = 0xf8
};


int elf32LoadObjectFile(const char *fileName, struct ElfObject *obj);
int elf32LoadObject(FILE *f, struct ElfObject *obj);

typedef void (*symiterfunc_t)(void *, const struct ElfObject *, struct Section *, const Elf32_Sym *, const char *);
void elf32SymbolIterate(struct ElfObject *o, symiterfunc_t cb, void *state);
void elf32SymbolIterateSection(struct ElfObject *o, struct Section *, symiterfunc_t cb, void *state);

int elf32FindSymbolByName(struct ElfObject *o, const char *name, const Elf32_Sym **symp, const char **namep);
int elf32FindSectionByName(struct ElfObject *obj, const char *name, struct Section **shdrp);
int elf32LinearSymSearch(struct ElfObject *o, struct Section *hdr, const char *name, const Elf32_Sym **symp, const char **namep);
void elf32ProcessFunctions(struct ElfObject *obj);
int elf32FindFunction(struct ElfObject *obj, Elf32_Addr loc, struct FunctionInfo **f);
int elf32UnloadObject(struct ElfObject *obj);
int elf32UnloadObjectFile(struct ElfObject *obj);
void elf32DumpSection(FILE *f, struct ElfObject *obj, struct Section *hdr, int indent);
void elf32DumpProgramSegment(FILE *f, struct ElfObject *obj, const Elf32_Phdr *hdr, int indent);
void elf32DumpSymbol(FILE *f, const Elf32_Sym * sym, const char *strings, int indent);
void elf32DumpDynamic(FILE *f, const Elf32_Dyn *dyn, int indent);
int elf32FindSymbolByName(struct ElfObject *o, const char *name, const Elf32_Sym **symp, const char **namep);
int elf32FindObject(struct ElfObject *list, Elf32_Addr addr, struct ElfObject **objp);
void elf32DumpObject(FILE *f, struct ElfObject *obj, int indent);

void *elf32MapSegment(struct ElfObject *, struct Segment *);
void *elf32MapSection(struct ElfObject *, struct Section *);

const char *pad(int size);
void hexdump(FILE *f, int indent, const char *p, int len);

#ifndef IS_ELF
#define IS_ELF(hdr) \
	((hdr).e_ident[0] == ELFMAG0 && \
	(hdr).e_ident[1] == ELFMAG1 && \
	(hdr).e_ident[2] == ELFMAG2 && \
	(hdr).e_ident[3] == ELFMAG3)
#endif
#ifndef EI_OSABI
#define EI_OSABI 7
#endif
