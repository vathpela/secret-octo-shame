include Make.rules
include Make.defaults

TARGETS=scncopy dso.so dltest libso.so asmtest

scncopy : scncopy.c
scncopy : LIBS=dl elf asm
scncopy : PKGS=glib-2.0
scncopy : CFLAGS+=-I/usr/include/elfutils/

dltest : dltest.c
dltest : LIBS=dl ebl elf asm

asmtest : asmtest.c libso.so
asmtest : LDFLAGS+=-L. -Wl,-rpath=$(shell pwd)
asmtest : LIBS=so dl asm ebl elf

libso.so : libso.c
libso.so : CFLAGS+=-I/usr/include/elfutils/

dso.so : dso.c

all : $(TARGETS)

clean :
	rm -vf *.o *.so $(TARGETS)

test : asmtest dltest
	@rm -f asm.so
	LD_LIBRARY_PATH=$(shell echo $$PWD) ./asmtest asm.so

.PHONY : clean test all
