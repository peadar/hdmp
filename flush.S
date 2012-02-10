
winflush:
start:
    save %sp, -0x40, %sp
    save %sp, -0x40, %sp
    save %sp, -0x40, %sp
    save %sp, -0x40, %sp
    save %sp, -0x40, %sp
    save %sp, -0x40, %sp
    save %sp, -0x40, %sp
    save %sp, -0x40, %sp
    save %sp, -0x40, %sp
    save %sp, -0x40, %sp
    save %sp, -0x40, %sp
    save %sp, -0x40, %sp
    save %sp, -0x40, %sp
    save %sp, -0x40, %sp
    save %sp, -0x40, %sp
    save %sp, -0x40, %sp
    restore %g0, %g0, %g0
    restore %g0, %g0, %g0
    restore %g0, %g0, %g0
    restore %g0, %g0, %g0
    restore %g0, %g0, %g0
    restore %g0, %g0, %g0
    restore %g0, %g0, %g0
    restore %g0, %g0, %g0
    restore %g0, %g0, %g0
    restore %g0, %g0, %g0
    restore %g0, %g0, %g0
    restore %g0, %g0, %g0
    restore %g0, %g0, %g0
    restore %g0, %g0, %g0
    restore %g0, %g0, %g0
    restore %g0, %g0, %g0
    st %i6, [%o0]
    retl
    st %i7, [%o1]
.globl winflush
.size winflush,(.-start)
.type winflush,#function
