ELF_BITS ?= 64

ifeq ($(ELF_BITS),32)
COMFLAGS += -m32
LDFLAGS += -m32
endif

COMFLAGS += -I../pstack -g -fpic -Wall -Wno-parentheses \
    -D_LARGEFILE_SOURCE \
    -D_FILE_OFFSET_BITS=64 \
    -D_GNU_SOURCE \
    -DELF_BITS=$(ELF_BITS)

LDFLAGS += -g

CC=gcc
CFLAGS += $(COMFLAGS)
CXXFLAGS += $(COMFLAGS) -std=c++0x

TARGETS=heap.so hdmp it prof.so
all: $(TARGETS)

heap.so: heap.o init.o
	$(CXX) $(LDFLAGS) -shared -o $@ heap.o init.o -ldl 

prof.so: prof.o elf.o
	$(CC) $(LDFLAGS) -nostdlib -shared -o $@ prof.o elf.o -ldl -lc -lpthread

hdmp: hdmp.o elf.o
	$(CC) $(LDFLAGS) -o $@ hdmp.o elf.o

it: it.o elf.o
	$(CC) $(LDFLAGS) -o $@ it.o elf.o

clean:
	rm -f core* *.core *.o $(TARGETS) tags
