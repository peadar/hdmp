#include <sys/time.h>
#include <assert.h>
#include <pthread.h>
#include <ucontext.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <link.h>
#include <elf.h>
#include <setjmp.h>

#include "myelf.h"

typedef unsigned long ADDR;

struct callsite;

#define MAXFRAMES 256

struct frame {
    ADDR ip;
    struct ElfObject *obj;
    struct FunctionInfo *function;
};

struct threadcontext {
    jmp_buf jb;
    ADDR bp;
    ADDR ip;
    ADDR sp;
    size_t frameCount;
    struct frame stack[MAXFRAMES];
};

struct function {
    struct ElfObject *o;
    const char *name;
    ADDR start;
    ADDR end;
    struct callsite *callSites; // points between start and end where this functions calls others.
    int toCount;
    int mark;
};

struct callsite {
    /*
     * functions called from here (should be a very short list),
     * for most cases, it'll be a single destination. For virtual functions
     * and pointer-to-function dispatch, it'll still be quite limited.
     */
    struct function **calls;
    int callCount;
    int callMax;
    struct function *within;
    struct callsite *next; /* list linkage for siblings. */
    ADDR ip;
    int fromCount;
};

static struct callsite *bottom;
static struct ElfObject *elf;
static pthread_key_t tls;
static sigset_t sigs;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct function **functions;
static int functionCount;
static int functionMax;
static struct sigaction oldsigsegv;
extern struct r_debug _r_debug;

static void showSite(FILE *file, struct callsite *site, int indent);
static void showFunction(FILE *file, struct function *func, int indent, ADDR);

static void
updateObjects()
{
    struct link_map *map;
    pthread_mutex_lock(&lock);
    for (map = _r_debug.r_map; map; map = map->l_next) {
        struct ElfObject *o;
        for (o = elf;; o = o->next) {
            int rc;
            if (o == 0)  {
                if (map->l_name[0] != 0) {
                    struct ElfObject *o;
                    o = malloc(sizeof *o);
                    fprintf(stderr, "loading %s at %x descr=%p\n", map->l_name, map->l_addr, o);
                    rc = elf32LoadObjectFile(map->l_name, o);
                    if (rc != 0) {
                        fprintf(stderr, "failed\n");
                    } else {
                        o->next = elf;
                        o->baseAddr = map->l_addr;
                        o->udat = map;
                        elf = o;
                        fprintf(stderr, "... done\n");
                    }
                }
                break;
            }
            if (o->udat == map)
                break;
        }
    }
    pthread_mutex_unlock(&lock);
}

static int
cmpFuncIP(const void *a, const void *b)
{
    ADDR addr = (ADDR)a;

    const struct function *func = *(const struct function **)b;

    if (addr < func->start)
        return -1;
    if (addr > func->end)
        return +1;
    return 0;
}

static int
sortFunctions(const void *a, const void *b)
{
    const struct function *lhs = *(const struct function **)a;
    const struct function *rhs = *(const struct function **)b;
    if (lhs->start < rhs->start)
        return -1;
    if (lhs->start > rhs->start)
        return +1;
    return 0;
}

static struct callsite *
newSite(ADDR ip)
{
    struct callsite *site = malloc(sizeof (struct callsite));
    site->ip = ip;
    site->calls = malloc(sizeof site->calls[0] * 8);
    site->callCount = 0;
    site->callMax = 8;
    site->next = 0;
    site->fromCount = 0;
    return site;
}

static struct function *
newFunction(struct ElfObject *obj, const char *name, ADDR start, ADDR end) 
{
    struct function *func = malloc(sizeof (struct function));
    func->name = strdup(name);
    func->start = start;
    func->end = end;
    func->o = obj;
    func->callSites = 0;
    func->toCount = 0;
    func->mark = 0;
    return func;
}

static void
sigsegv(int sig, siginfo_t *info, void *uc_v)
{
    struct threadcontext *ctx = pthread_getspecific(tls);
    ucontext_t *uc = (ucontext_t *)uc_v;
    mcontext_t *mc = &uc->uc_mcontext;

    if (ctx == 0) {
        fprintf(stderr, "fault at %x: no context\n", mc->gregs[REG_EIP]);
        raise(SIGTRAP); // this'll generally dump core, and not get interfered with by java.
    }
    fprintf(stderr, "recover from fault at %x: %lx/%lx\n", mc->gregs[REG_EIP], ctx->ip, ctx->bp);
    longjmp(ctx->jb, 1);
}

static void
sigprof(int sig, siginfo_t *info, void *uc_v)
{
    ucontext_t *uc = (ucontext_t *)uc_v;
    mcontext_t *mc = &uc->uc_mcontext;

    struct threadcontext context;
    int i;
    ADDR newBp, newIp;

    memset(&context, 0, sizeof context);
    assert(pthread_getspecific(tls) == 0);

    context.bp = mc->gregs[REG_EBP];
    context.ip = mc->gregs[REG_EIP];
    context.sp = mc->gregs[REG_ESP];

    updateObjects();

    pthread_setspecific(tls, &context);
    if (setjmp(context.jb) == 0) {
        for (context.frameCount = 0; context.frameCount < MAXFRAMES; ++context.frameCount) {
            struct frame *frame = &context.stack[context.frameCount];

            frame->ip = context.ip;

            // Some sanity checking...
            if (context.bp < 0x80000)
                break;

            // We can't find the current instruction pointer in any object. (Java optimiser tends to do this at a time when we can't use our segv handler to recover)
            if (elf32FindObject(elf, context.ip, &frame->obj) != 0)
                break;

            if (elf32FindFunction(frame->obj, context.ip - frame->obj->baseAddr, &frame->function) != 0)
                frame->function = 0;

            newBp = ((ADDR *)context.bp)[0];
            if (newBp <= context.bp)
                break;
            newIp = ((ADDR *)context.bp)[1];
            if (newIp == 0)
                break;
            context.ip = newIp;
            context.bp = newBp;
        }
    }
    pthread_setspecific(tls, 0);

    struct callsite *calledfrom = bottom;
    if (context.frameCount == 0)
        return;

    for (i = context.frameCount - 1;  ; --i) {
        struct callsite *site, **sitep;
        struct function *function, **functionp;
        struct frame *frame;
        ADDR ip;
        int j;

        frame = &context.stack[i];

        /*
         * Find the function for this IP.
         */
        functionp = (struct function **)bsearch((void *)frame->ip, functions, functionCount, sizeof functions[0], cmpFuncIP);

        if (functionp == 0) {
            /* New function: add to our table. */
            if (functionCount == functionMax) {
                functionMax *= 2;
                functionMax += 128;
                functions = realloc(functions, sizeof functions[0] * functionMax);
            }

            if (frame->function) {
                ADDR start = frame->function->elfSym->st_value + frame->obj->baseAddr;
                ADDR end = start + frame->function->elfSym->st_size;
                const char *name = frame->function->elfName;
                function = newFunction(frame->obj, name, start, end);
            } else {
                function = newFunction(frame->obj, "_unknown_", frame->ip, frame->ip + 1);
            }
            functions[functionCount++] = function;
            qsort(functions, functionCount, sizeof functions[0], sortFunctions);
        } else {
            function = *functionp;
        }

        // Make sure this function is on the list of those called from the call site.
        for (j = 0;; j++) {
            if (j == calledfrom->callCount) {
                // This function hasn't been called from this site before.
                if (calledfrom->callMax == calledfrom->callCount) {
                    calledfrom->callMax *= 2;
                    calledfrom->calls = realloc(calledfrom->calls, sizeof calledfrom->calls[0] * calledfrom->callMax);
                }
                calledfrom->calls[calledfrom->callCount++] = function;
                break;
            }
            if (calledfrom->calls[j] == function)
                break;
        }

        function->toCount++;

        // Don't create a callsite for the top frame: the jump from here was the asynch jump into the sigprof handler
        if (i == 0)
            break;

        // Find or create a callsite out of this function at this IP.
        for (sitep = &function->callSites;; sitep = &site->next) {
            site = *sitep;
            if (site == 0) {
                site = *sitep = newSite(ip);
                break;
            } else if (site->ip == ip) {
                break;
            }
        }

        site->fromCount++;
        calledfrom = site;
    }
}

static int id = 1;
static void
showFunction(FILE *file, struct function *func, int indent, ADDR from)
{
    if (func->mark) {
        fprintf(file, "\t%s already seen at %d\n", func->name, func->mark);
        return;
    }
    func->mark = id++;
    fprintf(file, "%8d %8d %8lx->%8lx %s%s %s\n",
            func->mark,
            func->toCount,
            from,
            func->start,
            pad(indent),
            func->name, 
            func->o ? func->o->fileName : "<none>");

    struct callsite *cur, *done = 0;
    while (func->callSites) {
        struct callsite **highestp, **prevp = &func->callSites;
        for (highestp = 0; *prevp; prevp = &cur->next) {
            cur = *prevp;
            if (highestp == 0 || cur->fromCount > (*highestp)->fromCount)
                highestp = prevp;
        }
        cur = *highestp;
        *highestp = cur->next; // Remove highest from site list.
        cur->next = done; // add to done list
        showSite(file, cur, indent + 2);
    }
    func->callSites = done;
}

static void
showSite(FILE *file, struct callsite *site, int indent)
{
    int j;
    for (j = 0; j < site->callCount; j++)
        showFunction(file, site->calls[j], indent, site->ip);
}

static void
profinit()
{
    struct itimerval it, oldit;
    struct sigaction act;

    fprintf(stderr, "initialize profiling...\n");

    bottom = newSite(0);

    struct link_map *map;
    map = _r_debug.r_map;
    elf = malloc(sizeof *elf);
    const char *exec = getenv("AOUT");
    int rc = elf32LoadObjectFile(exec, elf);
    if (rc != 0)
        fprintf(stderr, "cannot load elf object");
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGPROF);
    sigprocmask(SIG_BLOCK, &sigs, 0);

    memset(&it, 0, sizeof it);
    it.it_interval.tv_sec = 0;
    it.it_interval.tv_usec = 1000;
    it.it_value = it.it_interval;

    setitimer(ITIMER_PROF, &it, &oldit);
    act.sa_sigaction = sigprof;
    sigemptyset(&act.sa_mask);
    sigaddset(&act.sa_mask, SIGPROF);
    act.sa_flags = SA_SIGINFO;
    sigaction(SIGPROF, &act, 0);

    act.sa_sigaction = sigsegv;
    sigaction(SIGSEGV, &act, &oldsigsegv);

    rc = pthread_key_create(&tls, 0);
    if (rc != 0)
        abort();
    sigprocmask(SIG_UNBLOCK, &sigs, 0);
}

static int
proffini()
{
    signal(SIGSEGV, SIG_DFL);
    sigprocmask(SIG_BLOCK, &sigs, 0); // Stop profiling timer.
    FILE *f = fopen("pmeprof", "w");
    showSite(f, bottom, 0);
    fclose(f);
    return 0;
}

void
_init()
{
    profinit();
}

void
_fini()
{
    fprintf(stderr, "complete profiling...\n");
    proffini();
}
