#include <sys/types.h>
#include <array>
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
#include "elfinfo.h"
#include "procinfo.h"

#include "heap.h"

struct ListedSymbol {
    Elf_Sym sym;
    const ElfObject *obj;
    std::string name;
    ListedSymbol()
    {
    }
};

std::list<ListedSymbol> excludeList;
std::list<ListedSymbol> includeList;
std::list<ListedSymbol> vtables;

static void printBlocks(struct Process *proc
        , struct memdesc_list *list
        , enum memstate
        , int, int *, int *, int *, int *);
static int  usage(void);
static void printStack(struct Process *proc, struct stackframe *stack);
static const char *gLibPrefix = "";

static int
globmatchR(const char *pattern, const char *name)
{
    for (;; name++) {
        switch (*pattern) {
        case '*':
            // if the rest of the name matches the bit of pattern after '*', 
            for (;;) {
                ++name;
                if (globmatchR(pattern + 1, name))
                    return 1;
                if (*name == 0) // exhuasted name without finding a match
                    return 0;
            }
        default:
            if (*name != *pattern)
                return 0;
        }
        if (*pattern++ == 0)
            return 1;
    }
}

static int
globmatch(std::string pattern, std::string name)
{
    return globmatchR(pattern.c_str(), name.c_str());
}

static void
getSymbolWildcard(Process &proc, std::list<ListedSymbol> list, std::string lib, std::string func)
{
    static std::array<const char *, 2> sections = { ".dynsym", ".symtab" };
    for (auto obj : proc.objectList) { // for each object
        if (globmatch(lib, obj->io.describe())) { // if the object name matches
            for (auto section : sections) { // for each symbol-containing section
                Elf_Shdr *hdr = obj->findSectionByName(section);
                if (hdr) {
                    for (auto info : SymbolSection(obj, hdr)) { // for each symbol in that section
                        if (info.first.st_value != 0 && globmatch(func, info.second)) { // if tha name matches
                            ListedSymbol lsym;
                            lsym.obj = obj;
                            lsym.name = info.second;
                            lsym.sym = info.first;
                            list.push_back(lsym);
                        }
                    }
                }
            }
        }
    }
}

void
getSymbolList(Process &proc, std::list<ListedSymbol> &list, const char *filename)
{
    FILE *f = fopen(filename, "r");
    char *func;
    char lib[1024];
    int lineNumber;
    char *p;

    if (!f) {
        fprintf(stderr, "cannot open symbol list file %s\n", filename);
        return;
    }

    for (lineNumber = 1; fgets(lib, sizeof lib, f) != 0; lineNumber++) {
        if (*lib == '#')
            continue;
        func = strchr(lib, ':');
        if (!func) {
            printf("syntax error in symbol list at line %d", lineNumber);
            continue;
        }
        *func++ = 0;
        if ((p = strchr(func, '\n')) != 0)
            *p = 0;
        /* Now find the library, and the symbol */

        getSymbolWildcard(proc, list, lib, func);
    }
    fclose(f);
}

static int
onList(struct Process *proc, Elf_Addr addr, std::list<ListedSymbol *> &list)
{
    for (auto item : list) {
        Elf_Addr symStart = item->obj->base + item->sym.st_value;
        if (symStart <= addr && symStart + item->sym.st_size > addr)
            return 1;
    }
    return 0;
}

struct Symcounter {
    Elf_Addr addr;
    const char *name;
    unsigned count;
    struct ListedSymbol *sym;
};

int
sortSymcountAddr(const void *lv, const void *rv)
{
    struct Symcounter *l = (struct Symcounter *)lv;
    struct Symcounter *r = (struct Symcounter *)rv;
    return l->addr - r->addr;
}

int
findSymByAddr(const void *keyv,  const void *valuev)
{
    Elf_Addr key = *(uint32_t *)keyv;
    struct Symcounter *value = (struct Symcounter *)valuev;
    return key - value->addr;
}

union val {
    char char_[4];
    unsigned int int_;
};

static const char *virtpattern = "_ZTV*"; /* wildcard for all vtbls */

struct hdbg_info info;
int
main(int argc, char **argv)
{
    Elf_Word listAddr;
    const Elf_Sym *sym;
    struct ElfObject *obj;
    const char *includeListName = 0, *excludeListName = 0;
    int dovirts = 0, dovirtprint = 0;
    int c, dataLen = 0, badBlocks, excludedBlocks, totalBytes, totalBlocks;
        struct ListedSymbol *s;

    while ((c = getopt(argc, argv, "p:e:i:d:D:v:V:")) != -1) {
        switch (c) {
        case 'e':
            excludeListName = optarg;
            break;
        case 'i':
            includeListName = optarg;
            break;
        case 'p':
            gLibPrefix = optarg;
            break;
        case 'd':
            dataLen = atoi(optarg);
            if (dataLen == 0)
                dataLen = 4096;
            break;

        case 'V':
            dovirtprint = 1;
        case 'v':
            if (strcmp(optarg, ".") != 0)
                virtpattern = optarg;
            dovirts = 1;
            break;
        default:
            return usage();
        }
    }

    if (argc - optind != 2 || excludeListName && includeListName)
        return usage();

    FileReader exeFile(argv[optind]);
    FileReader coreFile(argv[optind +1]);
    CoreProcess proc(exeFile, coreFile);

    if (excludeListName)
        getSymbolList(proc, excludeList, excludeListName);
    else if (includeListName)
        getSymbolList(proc, includeList, includeListName);

    if (dovirts) {
        size_t vtcount = 0;
        int i;
        size_t got;
        union val val;

        struct Symcounter *table, *found;
        getSymbolWildcard(proc, vtables, "*", virtpattern);

        for (s = vtables; s; s = s->next)
            vtcount++;

        if (vtcount == 0) {
            fprintf(stderr, "no vtbls\n");
            exit(0);
        }

        table = malloc(sizeof *table * vtcount);
        for (s = vtables, i = 0; i < vtcount; ++i, s = s->next) {
            table[i].count = 0;
            table[i].name = s->name;
            table[i].addr = s->sym->st_value + s->obj->baseAddr + 8; // the + 8 seems to be what goes into the object...
            table[i].sym = s;
        }

        /* sort the table by address. */
        qsort(table, vtcount, sizeof *table, sortSymcountAddr);

        val.int_ = 0;
            int c;
            struct ElfObject *core = proc->coreImage;
            for (i = 0; i < core->elfHeader.e_phnum; i++) {
                off_t readCount;
                struct Segment *seg = &core->programHeaders[i];
                Elf_Phdr *hdr = &seg->phdr;
                if (hdr->p_type != PT_LOAD)
                    continue;
                fseeko(core->file, hdr->p_offset, SEEK_SET);
                for (readCount = 0; readCount < hdr->p_filesz; readCount += 4) {
                    c = fread(val.char_, 4, 1, core->file);
                    if (c != 1)
                        abort();
                    found = bsearch(&val.int_, table, vtcount, sizeof *table, findSymByAddr);
                    if (found) {
                        found->count++;
                        got++;
                        if (dovirtprint) {
                            fprintf(stdout, "%s at 0x%lx\n", found->name, (long unsigned int)(hdr->p_vaddr + readCount));
                        }
                    }
                }
            }
            for (s = vtables, i = 0; i < vtcount; ++i, s = s->next)
                if (table[i].count)
                    fprintf(stdout, "%d %s %x\n", table[i].count, table[i].name, table[i].addr);
    }

    for (obj = proc->objectList; obj; obj = obj->next)
        if (elf32FindSymbolByName(obj, "hdbg", &sym, 0) != -1)
            break;

    if (!obj) {
        procFree(proc);
        fprintf(stderr, "heap.so was not loaded for process\n");
                exit(-1);
    }

    listAddr = obj->baseAddr + sym->st_value;
    procReadMem(proc, &info, listAddr, sizeof info);
    printf("Allocator usage statistics:\n\n");
    printf("Calls to malloc:   %8d\n", info.stats.malloc_calls);
    printf("Calls to free:     %8d\n", info.stats.free_calls);
    printf("Calls to calloc:   %8d\n", info.stats.calloc_calls);
    printf("Calls to realloc:  %8d\n\n", info.stats.realloc_calls);

    printf("Loaded Shared Libraries:\n");
    for (obj = proc->objectList; obj; obj = obj->next)
        printf("%-20s -> %s @ %p\n", obj->baseName, obj->fileName, (void *)obj->baseAddr);

    printf("\nStack at termination:\n");
    printStack(proc, info.crashstack);

    printf("\nCurrently allocated memory:\n");
    printBlocks(proc, &info.heap, mem_allocated, dataLen, &totalBytes, &totalBlocks, &badBlocks, &excludedBlocks);

    printf("\n%d bytes allocated in %d blocks (max %d). "
        "%d blocks damaged, %d excluded from dump\n", totalBytes, totalBlocks,
        info.stats.maxmem, badBlocks, excludedBlocks);
    printf("\nRecently freed memory:\n");
    printBlocks(proc, &info.freelist, mem_free, dataLen, &totalBytes, &totalBlocks, &badBlocks, &excludedBlocks);
    printf("\n%d bytes free in %d blocks. "
        "%d blocks damaged, %d excluded from dump\n", totalBytes, totalBlocks, badBlocks, excludedBlocks);
    procFree(proc);
    return 0;
}

static void
printStack(struct Process *proc, struct stackframe *stack)
{
    struct FunctionInfo *stab;
    struct ElfObject *obj;

    int i;
    for (i = 0; i < info.maxframes; i++) {
        const char *fileName;
        Elf_Word off = 0;
        int j;
        struct stackframe *frame = stack + i;
        Elf_Addr funcAddr = (Elf_Addr)frame->ip;
        const struct stab *line;
        const struct stab *args;
        char *colon;

        if (funcAddr == 0)
            return;

        stab = 0;
        if (elf32FindObject(proc->objectList, funcAddr, &obj) != -1) {
            fileName = obj->baseName;
            elf32FindFunction(obj, funcAddr - obj->baseAddr, &stab);
        } else {
            obj = 0;
        }

        fileName = "unknown file";
        if (stab) {
            const struct stab *nextLine;
            off = funcAddr - obj->baseAddr -
                stab->elfSym->st_value;
            for (line = nextLine = stab->lineNumbers; line && nextLine->n_type != N_FUN; nextLine++) {
                if (nextLine->n_type == N_SLINE && nextLine->n_value <= off)
                line = nextLine;
            }
            args = stab->args;
            if (stab->fileName)
                fileName = stab->fileName;
        } else {
            off = 0;
            line = 0;
            args = 0;
        }

        printf("    %-16s %08x %s(",
            obj ? obj->baseName : "????????", funcAddr,
            stab ? stab->elfName : "????????");

        for (j = 0;; j++) {
            int nameLen;
            if (args) {
                const char *argName =
                obj->stabStrings +
                stab->stabStringOffset +
                args[j].n_strx;
                colon = strchr(argName, ':');
                nameLen = colon ? colon - argName :
                strlen(argName);
                printf("%.*s=", nameLen, argName);
            }

            printf("%p", frame->args[j]);
            if (j > DBGH_FRAMEARGS ||
            args && args[j + 1].n_type != N_PSYM)
                break;
            printf(", ");
        }
        printf(") + 0x%x %s:", off, fileName);
        if (line)
            printf("%d\n", line->n_desc);
        else
            printf("no line number\n");
    }
}

static void
printBlocks(struct Process *proc, struct memdesc_list *list, enum memstate state, int dataLen, int *totalBytes, int *totalBlocks, int *badBlocks, int *excluded)
{
    int i, bad;
    struct memdesc *hdr;
    char *dataBuf;
    size_t hdrsize;

    Elf_Addr addr;
    if (dataLen)
        dataBuf = malloc(dataLen);
    else
        dataBuf = 0;

    *badBlocks = *excluded = *totalBlocks = *totalBytes = 0;

    hdrsize = sizeof *hdr + info.maxframes * sizeof (struct stackframe);
    hdr = malloc(hdrsize);

    for (*totalBlocks = *totalBytes = 0, addr = (Elf_Addr)list->tqh_first;
        addr;
        addr = (Elf_Addr)hdr->node.tqe_next) {
        enum memstate headState, tailState;

        procReadMem(proc, hdr, addr, hdrsize);
        procReadMem(proc, &headState, (Elf_Addr)(&hdr->data->state), sizeof headState);
        procReadMem(proc, &tailState, (Elf_Addr)(hdr->data + 1) + hdr->len, sizeof headState);

        ++*totalBlocks;
        *totalBytes += hdr->len;

        bad = tailState != state || headState != state;
        if (!bad && (excludeList || includeList)) {
            Elf_Addr funcAddr = 0;
            for (i = 0; i < info.maxframes; i++) {
                struct stackframe *frame = hdr->stack + i;
                funcAddr = (Elf_Addr)frame->ip;
                if (!funcAddr || (excludeList && onList(proc,
                    funcAddr, excludeList)) || includeList &&
                    !onList(proc, funcAddr, includeList))
                    break;
            }
            if (excludeList && funcAddr || includeList && !funcAddr) {
                ++*excluded;
                continue;
            }
        }

        printf("\nptr=%p\tlen=%d\tserial=%ld\tdesc=%p\t%s%s\n",
            (caddr_t)(hdr->data + 1),
            hdr->len,
            hdr->serial,
            (void *)(intptr_t)addr,
            headState == state ? "" : " *BADHEAD*",
            tailState == state ?  "" : " *BADTAIL*");
        *badBlocks += bad;

        if (dataLen) {
            int dumpLen = hdr->len < dataLen ? hdr->len : dataLen;
            procReadMem(proc, dataBuf, addr, dumpLen);
            printf("    first %d bytes:\n", dumpLen);
            hexdump(stdout, 16, dataBuf, dumpLen);
        }

        printStack(proc, hdr->stack);
    }
    if (dataLen)
        free(dataBuf);
    free(hdr);
}

static int
usage(void)
{
fprintf(stderr, "usage: hdmp [options] <executable> <core>"
    "\n\t[-e <file>  ] exclude stack traces that include symbols in <file>"
    "\n\t[-i <file>  ] include only stack traces that include symbols in <file>"
    "\n\t[-p <prefix>] prepend to file names of shared libraries when opening"
    "\n\t[-d <size>  ] show first size bytes of allocate memory block in output"
"\n");
    return (EX_USAGE);
}

/*
 * Create a description of a process. Attempt to get:
 *   A description of the executable object.
 *   A description of any loaded objects from the run-time linker.
 *   A stack trace for each thread we find, as well as the currently
 *   running thread.
 */
static int
procOpen(const char *exeName, const char *coreFile, struct Process **procp)
{
    struct Process *proc;

    proc = malloc(sizeof(*proc));
    proc->objectList = NULL;
    proc->coreImage = NULL;
    proc->mem = -1;

    /*
     * Get access to the address space via /proc, or the core image
     */
    if (procSetupMem(proc, coreFile) != 0) {
        procFree(proc);
        return (-1);
    }

    /*
     * read executable image
     */
    proc->execImage = malloc(sizeof (struct ElfObject));
    if (elf32LoadObjectFile(exeName, proc->execImage)) {
                free(proc->execImage);
                proc->execImage = 0;
        procFree(proc);
        return (-1);
    }
    procLoadSharedObjects(proc);
    procAddElfObject(proc, proc->execImage, 0);
    *procp = proc;
    return (0);
}

/*
 * Read data from the target's address space.
 */
static int
procReadMem(struct Process *proc, void *ptr, Elf_Addr remoteAddr, size_t size)
{
    if (!proc->coreImage) {
        if (pread(proc->mem, ptr, size, remoteAddr) == size)
            return 0;
        return -1;
    } else {
        struct ElfObject *obj, *nextObj;
        for (obj = proc->coreImage; obj; obj = nextObj) {
            size_t i;
            off_t objectOffset = remoteAddr - obj->baseAddr;
            for (i = 0; i < obj->elfHeader.e_phnum; i++) {
                struct Segment *seg = &obj->programHeaders[i];
                Elf_Phdr *hdr = &seg->phdr;
                if (hdr->p_type == PT_LOAD && hdr->p_vaddr <= objectOffset
                        && hdr->p_vaddr + hdr->p_filesz > objectOffset) {
                    fseeko(obj->file, hdr->p_offset + (objectOffset - hdr->p_vaddr), SEEK_SET);
                    if (fread(ptr, size, 1, obj->file) != 1)
                        abort();
                    return 0;
                }
            }
            if (obj == proc->coreImage)
                nextObj = proc->objectList;
            else
                nextObj = obj->next;
        }
        return (-1);
    }
}

/*
 * Add ELF object description into process.
 */
static void
procAddElfObject(struct Process *proc, struct ElfObject *obj, Elf_Addr base)
{
    obj->next = proc->objectList;
    obj->baseAddr = base;
    proc->objectList = obj;
}

/*
 * Grovel through the rtld's internals to find any shared libraries.
 */
static void
procLoadSharedObjects(struct Process *proc)
{
    struct r_debug rDebug;
    struct link_map map;
    Elf_Addr mapAddr, lAddr, r_debug_addr;
    char path[PATH_MAX];
    int prefixLen;
    struct ElfObject *obj;


    if ((r_debug_addr = procFindRDebugAddr(proc)) == 0)
        return;

    if (procReadMem(proc, &rDebug, r_debug_addr, sizeof(rDebug)) != 0)
        return;

    prefixLen = strlen(gLibPrefix);
    strcpy(path, gLibPrefix);
    path[prefixLen] = 0;

    for (mapAddr = (Elf_Addr)rDebug.r_map; mapAddr;
        mapAddr = (Elf_Addr)map.l_next) {

        if (procReadMem(proc, &map, mapAddr, sizeof(map)) != 0)
            continue;

        /* Read the path to the file */
        if (procReadMem(proc, path + prefixLen, (Elf_Addr)map.l_name,
            PATH_MAX - prefixLen) || path[prefixLen] == '\0') {
            fprintf(stderr, "cannot get library name @ %p\n", (void *)(intptr_t)map.l_addr);
            continue;
        }

        /*
         * Load the object into memory, but avoid loading the
         * executable again.
         * The executable is loaded at the start of memory, so any
         * object with a load address lower than the executable's
         * entry point is either broken, or is the executable.
         */
        lAddr = (Elf_Addr)map.l_addr;
        //if (lAddr <= proc->execImage->elfHeader->e_entry)
        //  continue;

                obj = malloc(sizeof *obj);
        if (elf32LoadObjectFile(path, obj) &&
            (prefixLen == 0 || elf32LoadObjectFile(path + prefixLen, obj)))
            continue;
        procAddElfObject(proc, obj, lAddr);
    }
}

/*
 * Grab various bits of information from the run-time linker.
 */
static Elf_Addr
procFindRDebugAddr(struct Process *proc)
{
    struct ElfObject *obj;
    Elf_Dyn dyno;
    const Elf_Dyn *dynp;
    Elf_Addr dyn;

    obj = proc->execImage;
    /* Find DT_DEBUG in the process's dynamic section. */
    if (obj->dynamic) {
        const char *data = elf32MapSegment(obj, obj->dynamic);
        for (dyn = 0; dyn < obj->dynamic->phdr.p_filesz; dyn += sizeof(Elf_Dyn)) {
            dynp = (const Elf_Dyn *)(data + dyn);
            if (dynp->d_tag == DT_DEBUG &&
                        procReadMem(proc, &dyno, obj->dynamic->phdr.p_vaddr + dyn, sizeof(dyno)) == 0)
                return dyno.d_un.d_ptr;
        }
    }
    return (0);
}

/*
 * Setup what we need to read from the process memory (or core file)
 */
static int
procSetupMem(struct Process *proc, const char *core)
{
    struct ElfObject *obj = proc->coreImage = malloc(sizeof *proc->coreImage);
    if (elf32LoadObjectFile(core, obj)) {
        free(obj);
        proc->coreImage = 0;
        return -1;
    }

    off_t furthest = 0;
    int i;
    for (i = 0; i < obj->elfHeader.e_phnum; i++) {
        off_t readCount;
        struct Segment *seg = &obj->programHeaders[i];
        Elf_Phdr *hdr = &seg->phdr;
        if (hdr->p_type != PT_LOAD)
            continue;
        if (hdr->p_offset + hdr->p_filesz > furthest)
            furthest = hdr->p_offset + hdr->p_filesz;
    }
    fprintf(stderr, "(core %s should be at least %ld bytes)\n", core, (long)furthest);

    return 0;
}

/*
 * Free any resources associated with a Process
 */
static void
procFree(struct Process *proc)
{
    procFreeObjects(proc);
    if (proc->mem != -1)
        close(proc->mem);
    if (proc->coreImage) {
        elf32UnloadObjectFile(proc->coreImage);
                free(proc->coreImage);
        }
    free(proc);
}

/*
 * Release the loaded ELF objects
 */
static void
procFreeObjects(struct Process *proc)
{
    struct ElfObject *obj, *nextObj;

    for (obj = proc->objectList; obj; obj = nextObj) {
        nextObj = obj->next;
        elf32UnloadObjectFile(obj);
                free(obj);
    }
}

