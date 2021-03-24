EXE=CalendarReader.exe
CXX=clang++

.PHONY: all clean test

CPPFLAGS=-g3 -fsanitize=address,fuzzer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

SOURCES=$(wildcard *.cpp)
OBJS=$(SOURCES:.cpp=.o)
PDB=$(DLL:.dll=.pdb)
LIB=$(DLL:.lib=.lib)

all: $(EXE)

%.exe: $(OBJS)
	$(CXX) $(CPPFLAGS) -o $@ $^ -L../calendar-lib -lCalendarLib
