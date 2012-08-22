ELF_BITS ?= 32

ifeq ($(ELF_BITS),32)
CFLAGS += -m32
endif

CFLAGS += -I. -g -fpic -Wall -Wno-parentheses \
    -D_LARGEFILE_SOURCE \
    -D_FILE_OFFSET_BITS=64 \
    -D_GNU_SOURCE \
    -DELF_BITS=$(ELF_BITS)
CC=gcc

TARGETS=heap.so hdmp it prof.so
all: $(TARGETS)

heap.so: heap.o init.o
	$(CXX) -shared -o $@ heap.o init.o -ldl 

prof.so: prof.o elf.o
	$(CC) -nostdlib -shared -o $@ prof.o elf.o -ldl -lc -lpthread

hdmp: hdmp.o elf.o
	$(CC) -g -o $@ hdmp.o elf.o

it: it.o elf.o
	$(CC) -g -o $@ it.o elf.o

clean:
	rm -f core* *.core *.o $(TARGETS) tags
