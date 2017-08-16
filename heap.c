
/*
 * Wrapper for "malloc" that records stack information in a block header
 */

#include <signal.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <setjmp.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <link.h>
#include <stdarg.h>
#include <pthread.h>
#include "queue.h"
#include "heap.h"

#include <dlfcn.h>

typedef void *(*malloc_t)(size_t);
typedef void (*free_t)(void *);
typedef void *(*calloc_t)(size_t, size_t);
typedef void *(*realloc_t)(void *, size_t);

#include <assert.h>
#include <sys/types.h>

static void assertheap(void);
static void getstacktrace(struct stackframe *ents, int max_ents);
static void sanity_freenode(struct memdesc *hdr);

#define VALLOC_MAX 1024
static int valloc_count;
static int dovalloc;
static void *valloc_tab[VALLOC_MAX];
static void *buffer_malloc(size_t amount);

struct hdbg_info hdbg;
extern char **environ;
static void *libc_handle = RTLD_NEXT;
pthread_mutex_t heap_lock;
pthread_mutex_t descriptors_lock;
static int startup = 2;

static void
die(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    getstacktrace(hdbg.crashstack, CRASHFRAMES);
    fprintf(stderr, "hdmp: ");
    vfprintf(stderr, msg, args);
    fprintf(stderr, "\n");
    va_end(args);
    abort();
}

static void
dieOnExit()
{
    die("normal termination: generating core");
}

static inline void
LOCK(pthread_mutex_t *lock)
{
    int rc;
    if ((rc = pthread_mutex_lock(lock)) != 0)
        die("lock failed: %s", strerror(rc));
}

static inline void
UNLOCK(pthread_mutex_t *lock)
{
    int rc;
    if ((rc = pthread_mutex_unlock(lock)) != 0)
        die("unlock failed: %s", strerror(rc));
}

static inline void
fill(unsigned char *base, int len, unsigned long filler)
{
    if (!hdbg.doFill)
        return;
    const unsigned char *pad = (const unsigned char *)&filler;
    int i;
    for (i = 0; i < len; i++)
	base[i] = pad[i%4];
}

static malloc_t real_malloc;
static free_t real_free;
static realloc_t real_realloc;
static calloc_t real_calloc;
static malloc_t real_valloc;
static void *signalTrampoline;

static inline struct memdesc *
alloc_hdr()
{
    struct memdesc *desc;
    LOCK(&descriptors_lock);
    if (TAILQ_EMPTY(&hdbg.descriptors)) {
        UNLOCK(&descriptors_lock);
        desc = real_malloc(sizeof (struct memdesc) + sizeof (struct stackframe) * hdbg.maxframes);
    } else {
        desc = TAILQ_FIRST(&hdbg.descriptors);
        TAILQ_REMOVE(&hdbg.descriptors, desc, node);
        UNLOCK(&descriptors_lock);
    }
    return desc;
}

static void
free_hdr(struct memdesc *hdr)
{
    sanity_freenode(hdr);
    LOCK(&descriptors_lock);
    TAILQ_INSERT_TAIL(&hdbg.descriptors, hdr, node);
    UNLOCK(&descriptors_lock);
}

static void
set_state(struct memdesc *hdr, enum memstate state)
{
    size_t i;
    char *p = (char *)(hdr->data + 1) + hdr->len;
    char *q = (char *)&state;

    q = (char *)&state;
    for (i = 0; i < sizeof state; i++)
        p[i] = q[i];
    hdr->data->state = state;
}

static enum memstate
get_state(struct memdesc *hdr)
{
    size_t i;
    enum memstate state;

    char *p = (char *)(hdr->data + 1) + hdr->len;
    char *q = (char *)&state;

    for (i = 0; i < sizeof state; i++)
	q[i] = p[i];

    if (state != hdr->data->state)
        die("head state != tail state. memory over/underrun");

    return state;
}

static void
sanity_freenode(struct memdesc *hdr)
{
    int i;
    if (get_state(hdr) != mem_free)
        die("free memory isn't");
    if (hdbg.doFill) {
        for (i = 0; i < hdr->len / 4; i++)
            if (((unsigned long *)(hdr->data + 1))[i] != 0xdeaddead)
                die("free memory modified");
    }
}

static char malloc_headroom[1024 * 64];
static int malloc_total = 0;

static void *
buffer_malloc(size_t amount)
{
    // Only use buffer_malloc before we can use proper malloc...
    if (!startup)
        die("unexpected buffer_malloc()");

    // round up to 4-byte aligned value.
    amount = (amount + 3) & ~3;

    // space in buffer?
    if (amount + malloc_total >= sizeof malloc_headroom)
        die("out of buffer space during initialisation");

    // consume and return that much of the malloc_headroom
    char *p = malloc_headroom + malloc_total;
    malloc_total += amount;
    return p;
}

static void
buffer_free(void *_)
{
}

static void
dbg_init()
{
    char **pp;

    if (startup != 2)
	return;

    startup = 1;

    /* Use our fixed buffer until we are truly up and running. */
    real_malloc = buffer_malloc;
    real_free = buffer_free;

    hdbg.stats.malloc_calls = 0;

    hdbg.level = 1;

    for (pp = environ; *pp; pp++) {
	static const char hdmp_level[] = "HDMP_LEVEL=";
	if (strncmp(*pp, hdmp_level, sizeof hdmp_level - 1) == 0)
	    hdbg.level = atoi((*pp) + sizeof hdmp_level - 1);
    }

    hdbg.freelistmax = 1024;
    hdbg.doFill = hdbg.level >= 2;
    hdbg.maxframes = DBGH_STACKFRAMES;

    for (pp = environ; *pp; pp++) {
	static const char hdmp_freelistsize[] = "HDMP_FREELISTSIZE=";
	static const char hdmp_stackdepth[] = "HDMP_STACKDEPTH=";
	static const char hdmp_fill[] = "HDMP_FILL=";
	if (strncmp(*pp, hdmp_freelistsize, sizeof hdmp_freelistsize - 1) == 0)
	    hdbg.freelistmax = atoi((*pp) + sizeof hdmp_freelistsize - 1);
	else if (strncmp(*pp, hdmp_fill, sizeof hdmp_fill - 1) == 0)
	    hdbg.doFill = atoi((*pp) + sizeof hdmp_fill - 1);
	else if (strncmp(*pp, hdmp_stackdepth, sizeof hdmp_stackdepth - 1) == 0)
	    hdbg.maxframes = atoi((*pp) + sizeof hdmp_stackdepth - 1);
    }

    TAILQ_INIT(&hdbg.heap);
    TAILQ_INIT(&hdbg.freelist);
    TAILQ_INIT(&hdbg.descriptors);

    pthread_mutex_init(&descriptors_lock, 0);
    pthread_mutex_init(&heap_lock, 0);

    // Make sure we can lock/unlock mutexes without recursing on malloc (i.e., while startup != 0)
    LOCK(&descriptors_lock);
    UNLOCK(&descriptors_lock);
    LOCK(&heap_lock);
    UNLOCK(&heap_lock);

    real_valloc = (malloc_t) dlsym(libc_handle, "valloc");
    real_realloc = (realloc_t) dlsym(libc_handle, "realloc");
    real_calloc = (calloc_t) dlsym(libc_handle, "calloc");
    real_free = (free_t) dlsym(libc_handle, "free");
    real_malloc = (malloc_t) dlsym(libc_handle, "malloc");
    startup = 0;
}

void
hdmpInit()
{
    dbg_init();
    atexit(dieOnExit);
    fprintf(stderr, "heap debugger enabled: use hdmp <executable> <core> to examine post-mortem output\n");
    fprintf(stderr, "debug level=%d, stack frames=%d,  freelist size=%d, fill memory? %d, buffer memory used=%d\n", 
        hdbg.level,
        (int)hdbg.maxframes,
        hdbg.freelistmax,
        hdbg.doFill,
        malloc_total);
}

void *
valloc(size_t size)
{
    dbg_init();
    if (!hdbg.level || startup)
	return (real_malloc(size));
    if (hdbg.level >= 2)
	assertheap();
    void *p = real_valloc(size);

    LOCK(&heap_lock);
    dovalloc = 1;
    if (valloc_count == VALLOC_MAX) {
        UNLOCK(&heap_lock);
        die("too many valloc calls");
    }
    valloc_tab[valloc_count++] = p;
    UNLOCK(&heap_lock);

    return p;
}

void *
malloc(size_t size)
{
    struct memdesc *hdr;
    struct guard *guard;
    void *v;

    dbg_init();
    if (!hdbg.level || startup)
	return (real_malloc(size));

    if (hdbg.level >= 2)
	assertheap();

    /* Space for guard at the start, memstate at the end, and size in between */
    guard = real_malloc(sizeof *guard + size + sizeof (enum memstate));
    hdr = guard->desc = alloc_hdr();
    hdr->data = guard;
    hdr->len = size;
    set_state(hdr, mem_allocated);
    getstacktrace(hdr->stack, hdbg.maxframes);

    LOCK(&heap_lock);
    hdr->serial = hdbg.serial++;
    hdbg.stats.alloc_total += size;
    hdbg.stats.malloc_calls++;
    if (hdbg.stats.alloc_total > hdbg.stats.maxmem)
	hdbg.stats.maxmem = hdbg.stats.alloc_total;
    TAILQ_INSERT_HEAD(&hdbg.heap, hdr, node);
    UNLOCK(&heap_lock);
    v = guard + 1;
    fill(v, size, 0xbaadf00d);
    return v;
}

static inline int
headroom(const void *p)
{
    return ((const char *)p >= malloc_headroom && (const char *)p < malloc_headroom + sizeof malloc_headroom);
}

void
free(void *p)
{
    struct memdesc  *hdr;
    struct guard *guard;
    if (p == 0)
        return;

    if (!hdbg.level || startup) {
	if (!headroom(p))
	    real_free(p);
	return;
    }

    if (hdbg.level >= 2)
        assertheap();

    int i;
    if (dovalloc) { // at least one call to valloc has happend. Sigh.
        char vallocmsg[] = "warning: free of valloc'd mem shunted to free()\n";
        LOCK(&heap_lock);
        for (i = 0; i < valloc_count; i++) {
            if (valloc_tab[i] == p) {
                real_free(valloc_tab[i]);
                write(2, vallocmsg, sizeof vallocmsg - 1);
                valloc_tab[i] = valloc_tab[--valloc_count];
                UNLOCK(&heap_lock);
                return;
            }
        }
        UNLOCK(&heap_lock);
    }

    guard = (struct guard *)p - 1;
    hdr = guard->desc;

    if (get_state(hdr) != mem_allocated)
        die("free() passed non-allocated memory");
    if (hdr->data != guard)
        die("internal integrity error");

    getstacktrace(hdr->stack, hdbg.maxframes);
    fill((unsigned char *)(hdr->data + 1), hdr->len, 0xdeaddead);
    set_state(hdr, mem_free);

    LOCK(&heap_lock);

    hdbg.stats.free_calls++;
    hdbg.stats.alloc_total -= hdr->len;
    TAILQ_REMOVE(&hdbg.heap, hdr, node);

    TAILQ_INSERT_HEAD(&hdbg.freelist, hdr, node);
    if (hdbg.freelistsize == hdbg.freelistmax) {
        hdr = TAILQ_LAST(&hdbg.freelist, memdesc_list);
        TAILQ_REMOVE(&hdbg.freelist, hdr, node);
    } else {
        hdbg.freelistsize++;
        hdr = 0;
    }
    UNLOCK(&heap_lock);

    if (hdr) {
        void *p = hdr->data;
        free_hdr(hdr);
        if (!headroom(p))
            real_free(p);
    }
}

void *
realloc(void *p, size_t size)
{
    char *p2;
    struct memdesc *oldhdr;
    struct guard *guard;

    dbg_init();

    hdbg.stats.realloc_calls++;

    if (!hdbg.level)
	return real_realloc(p, size);
    if (hdbg.level >= 2)
	assertheap();
    if (p) {
        guard = (struct guard *)p - 1;
        oldhdr = guard->desc;
        if (oldhdr->len > size)
            return p;
    }
    p2 = malloc(size);
    if (p2 && p) {
        memcpy(p2, p, oldhdr->len < size ? oldhdr->len : size);
        free(p);
    }
    return p2;
}

void *
calloc(size_t numelem, size_t size)
{
    void *p;
    hdbg.stats.calloc_calls++;
    size *= numelem;
    p = malloc(size);
    memset(p, 0, size);
    return p;
}

static void
assertheap()
{
    struct memdesc *hdr;
    int count;

    if (!hdbg.level || startup)
	return;

    LOCK(&heap_lock);
    TAILQ_FOREACH(hdr, &hdbg.heap, node)
        if (get_state(hdr) != mem_allocated)
            die("allocated memory isn't");
    count = 0;
    TAILQ_FOREACH(hdr, &hdbg.freelist, node) {
        sanity_freenode(hdr);
        if (count++ > 64)
            break;
    }
    UNLOCK(&heap_lock);
}

static void
getstacktrace(struct stackframe *ents, int max_ents)
{
    /* XXX XXX XXX. Major hackery. */
    int i;
    struct stackframe *sf;
    caddr_t ip;

#if defined(__FreeBSD__) || defined(__linux__)
    caddr_t **bp, **newBp;
    jmp_buf j;
    _setjmp(j);
#if defined(__FreeBSD__)
    bp = (caddr_t **)j->_jb[3];
    ip = (caddr_t)j->_jb[0];
#elif defined(__linux__)
    bp = (caddr_t **)j->__jmpbuf[3];
#elif defined(__sparc__)
#endif

    while (--max_ents) {
	sf = ents++;
	newBp = (caddr_t **)bp[0];
	if (!newBp || newBp <= bp) /* Make sure we are making progress. */
	    break;
	ip = (caddr_t)bp[1];
	if (!ip || ip == (caddr_t)0xbaadf00d || ip == signalTrampoline)
	    break;
	if (abs(newBp - bp) > 65536)
	    break; // Huge stack frame or new bp is higher in memory than old
	bp = newBp;
	sf->ip = ip;
	for (i = 0; i < DBGH_FRAMEARGS; i++)
	    sf->args[i] = bp[i + 2];
    }
#elif defined(SunOS)
#ifdef __sparc__
    struct {
	caddr_t *locals[8];
	caddr_t *input[8];
    } *frame;

    /*
     * Really evil hackery: We need to make sure all the register windows
     * are flushed out to memory: otherwise, we have no portable way of
     * doing a backtrace. We assume that there is at most 8 windows.
     * This probably brings the CPU to its knees.
     */

    winflush(&frame, &ip);

    while (max_ents-- && frame) {
	sf = ents++;
	sf->ip = ip;
	for (i = 0; i < DBGH_FRAMEARGS; i++)
	    sf->args[i] = frame->input[i];
	ip = (void *)frame->input[7];
	frame = (void *)frame->input[6];
    }
#endif
#else
#error "Don't know how to get EBP on this OS"
#endif
    ents->ip = 0;
}
