/* $Id: heap.h,v 1.5.2.1 2002/05/31 15:40:03 petere Exp $ */

#ifndef heap_h_guard
#define heap_h_guard

enum memstate {
    mem_allocated =  (int)0xa5a5a5a5,
    mem_free = (int)0x5a5a5a5a
};

#define DBGH_STACKFRAMES 10
#define DBGH_FRAMEARGS 4

struct memdesc;

TAILQ_HEAD(memdesc_list, memdesc);
typedef TAILQ_ENTRY(memdesc) memdesc_node;

struct stackframe {
    caddr_t ip;
    caddr_t *args[DBGH_FRAMEARGS];
};

/*
 * Each block of memory is preceded by a "guard", and followed by a simple "memstate"
 * The memdesc structure pointed to by the guard is separated so any overruns are
 * less likely to eat into the state information
 */

struct guard {
    struct memdesc *desc;
    enum memstate state;
};

/*
 * Contains information about an allocated block of memory.
 */
struct memdesc {
    memdesc_node node; /* Links to allocated, recently free, or unused descriptor list */
    unsigned long serial; /* Incrementing serial number for alloc/free operation */
    int len; /* User-requested length of allocated block. */
    struct guard *data; /* Points to data for this descriptor */
    struct stackframe stack[1];
};

struct stats {
    int alloc_total;
    int maxmem;
    int malloc_calls;
    int free_calls;
    int calloc_calls;
    int realloc_calls;
};

/* This is the structure the post-processing tool grovels for. */
#define CRASHFRAMES 512
struct hdbg_info {
    struct memdesc_list heap; /* Active memory */
    struct memdesc_list freelist; /* Free memory */
    struct memdesc_list descriptors; /* Free memdescs */
    int freelistmax;
    int freelistsize;
    struct stats stats;
    int level;
    unsigned long serial;
    int doFill;
    size_t maxframes;
    struct stackframe crashstack[CRASHFRAMES];
};
#endif
