#include <sys/time.h>
#include <ucontext.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <link.h>
#include <elf.h>

#include "myelf.h"

static int a();
static int b();
static int c();
static int d();
static int e();

typedef unsigned long ADDR;

struct callsite;

struct function {
    struct function *next;
    struct ElfObject *o;
    struct FunctionInfo *info;
    struct callsite *callSites; // points between start and end where this functions calls others.
    int toCount;
};

struct callsite {
    /*
     * functions called from here (should be a very short list),
     * for most cases, it'll be a single destination. For virtual functions
     * and pointer-to-function dispatch, it'll still be quite limited.
     */
    struct function *calls;
    /* list linkage for siblings. */
    struct callsite *next;
    ADDR ip;
    int fromCount;
};

struct callsite bottom;

extern struct r_debug _r_debug;

#define MAXFRAMES 256

struct ElfObject *elf;

static void showSite(FILE *file, struct callsite *site, int indent);
static void showFunction(FILE *file, struct function *func, int indent, ADDR);

static void
updateObjects()
{
    struct link_map *map;
    for (map = _r_debug.r_map; map; map = map->l_next) {
        struct ElfObject *o;
        for (o = elf;; o = o->next) {
            int rc;
            if (o == 0)  {
                if (map->l_addr != 0) {
                    struct ElfObject *o;
                    o = malloc(sizeof *o);
                    rc = elf32LoadObjectFile(map->l_name, o);
                    if (rc != 0) {
                        fprintf(stderr, "failed to load object\n");
                    } else {
                        o->next = elf;
                        o->baseAddr = map->l_addr;
                        elf = o;
                        fprintf(stderr, "loaded %s at %p descr=%p\n", map->l_name, (void *)(intptr_t)map->l_addr, o);
                    }
                }
                break;
            }
            if (o->baseAddr == map->l_addr)
                break;
        }
    }
}

static struct callsite *
newSite(ADDR ip)
{
    struct callsite *site = malloc(sizeof (struct callsite));
    site->ip = ip;
    site->calls = 0;
    site->next = 0;
    site->fromCount = 0;
    return site;
}

static struct function *
newFunction(struct ElfObject *obj, struct FunctionInfo *info)
{
    struct function *func = malloc(sizeof (struct function));
    func->info = info;
    func->o = obj;
    func->callSites = 0;
    func->next = 0;
    func->toCount = 0;
    return func;
}

static int done;
static void
sigint(int sig)
{
    done = 1;
}

static void
sigprof(int sig, siginfo_t *info, void *uc_v)
{
    ucontext_t *uc = (ucontext_t *)uc_v;
    ADDR stacktrace[MAXFRAMES];
    int frameCount, i;

    mcontext_t *mc = &uc->uc_mcontext;

    ADDR bp, ip, newBp, newIp;
    bp = mc->gregs[REG_EBP];
    ip = mc->gregs[REG_EIP];

    updateObjects();

    for (frameCount = 0; frameCount < MAXFRAMES; ++frameCount) {
        stacktrace[frameCount] = ip;
        newBp = ((ADDR *)bp)[0];
        if (!newBp || newBp <= bp)
            break;
        newIp = ((ADDR *)bp)[1];
	if (!newIp)
	    break;
        ip = newIp;
        bp = newBp;

    }

    struct callsite *context = &bottom;
    for (i = frameCount - 1;  ; --i) {
        struct callsite *site, **sitep;
        struct function *function, **functionp;

        ip = stacktrace[i];

        struct ElfObject *o;
        struct FunctionInfo *info;
        if (elf32FindObject(elf, ip, &o) != 0 || elf32FindFunction(o, ip - o->baseAddr, &info) != 0) {
            o = 0;
            info = 0;
        }

        // From the previous callsite, find a call to this function.
        for (functionp = &context->calls;; functionp = &function->next) {
            function = *functionp;
            if (function == 0) {
                *functionp = function = newFunction(o, info);
                break;
            } else if (function->info == info) {
                break;
            }
        }

        function->toCount++;

        // Don't create a callsite for the top frame: it's a sampled "real" IP, not a call to a function.
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
        context = site;
    }
}

static int
a()
{
    double f = random();
    f /= RAND_MAX;

    if (f < 0.1)
        return b();
    if (f < 0.5)
        return c();
    if (f < 0.95)
        return d();
    return e();
}

static int
b()
{
    return a();
}

static int
c()
{
    return 3;
}

static int
d()
{
    return c();
}

static int
e()
{
    return a();
}


static void showSite(FILE *file, struct callsite *site, int indent);
static void
showFunction(FILE *file, struct function *func, int indent, ADDR from)
{
    struct callsite *site;
    fprintf(file,
            "%8d%s%s %p %s\n",
            func->toCount,
            pad(indent),
            func->info ? func->info->elfName : "<unknown>",
            (void *)(intptr_t)(func->info ? func->info->elfSym->st_value : 0),
            func->o ? func->o->fileName : "<none>");
    for (site = func->callSites; site; site = site->next)
        showSite(file, site, indent + 2);
}

static void
showSite(FILE *file, struct callsite *site, int indent)
{
    struct function *callee;
    if (site->calls) {
        for (callee = site->calls; callee; callee = callee->next)
            showFunction(file, callee, indent + 2, site->ip);
    }
}

int
main(int argc, char *argv[])
{
    struct itimerval it, oldit;

    struct sigaction act;
    sigset_t sigs;

    struct link_map *map;
    map = _r_debug.r_map;

    elf = malloc(sizeof *elf);
    int rc = elf32LoadObjectFile(argv[0], elf);
    if (rc != 0)
        fprintf(stderr, "cannot load elf object");
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGPROF);

    sigprocmask(SIG_BLOCK, &sigs, 0);

    memset(&it, 0, sizeof it);
    it.it_interval.tv_sec = 0;
    it.it_interval.tv_usec = 10000;
    it.it_value = it.it_interval;

    setitimer(ITIMER_PROF, &it, &oldit);
    act.sa_sigaction = sigprof;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_SIGINFO;
    sigaction(SIGPROF, &act, 0);

    sigprocmask(SIG_UNBLOCK, &sigs, 0);

    signal(SIGINT, sigint);

    while (!done)
	a();
    sigprocmask(SIG_BLOCK, &sigs, 0);

    showSite(stderr, &bottom, 0);
    abort();
    return 0;
}
