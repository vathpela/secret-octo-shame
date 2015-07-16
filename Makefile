CC=gcc
CFLAGS=-Wall -Werror -g2 -O0 --std=gnu99 -I/usr/include/elfutils/ -fPIC
SOFLAGS=--shared
TARGETS=scncopy dso.so dltest libso.so asmtest

all : $(TARGETS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

scncopy : scncopy.c
	$(CC) $(CFLAGS) -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include  -lglib-2.0 -o $@ $^ -ldl -lelf -lasm

dltest : dltest.o
	$(CC) $(CFLAGS) -o $@ $^ -ldl -lebl -lelf

asmtest : asmtest.o
	$(CC) $(CFLAGS) -o $@ $^ -L. -Wl,-rpath=$(shell pwd) -lso -ldl -lasm -lebl -lelf

%.so: %.o
	$(CC) $(CFLAGS) $(SOFLAGS) -o $@ $^


clean :
	rm -vf *.o *.so $(TARGETS)

test : asmtest dltest
	@rm -f asm.so
	LD_LIBRARY_PATH=$(shell echo $$PWD) ./asmtest asm.so

.PHONY : clean test all
