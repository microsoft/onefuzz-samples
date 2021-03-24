DLL=CalendarLib.dll
CXX=clang++

.PHONY: all clean test

CPPFLAGS=-g3 -fsanitize=address,fuzzer

SOURCES=$(wildcard *.cpp)
OBJS=$(SOURCES:.cpp=.o)
PDB=$(DLL:.dll=.pdb)
LIB=$(DLL:.lib=.lib)

all: $(DLL)

%.dll: $(OBJS)
	$(CXX) $(CPPFLAGS) -shared -o $@ $^
