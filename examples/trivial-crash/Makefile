ifeq ($(OS),Windows_NT)
	CLEANCMD=del fuzz.exe, fuzz.exp, fuzz.lib, fuzz.pdb, fuzz-afl.exe, afl-llvm-rt.o.o, fuzz.o, main.o
else
	CLEANCMD=rm -rf fuzz.exe fuzz.exp fuzz.lib fuzz.pdb fuzz-afl.exe afl-llvm-rt.o.o fuzz.o main.o
endif

CC=clang
OBJS=fuzz.c

all: fuzz.exe

fuzz.exe: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@

.PHONY: clean

clean:
	$(CLEANCMD)
