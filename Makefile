CC		:= gcc
CFLAGS	+= -Wall -Wextra -g -pedantic -O0

BIN		:= bin
SRC		:= src
INCLUDE	:= include
LIB		:= lib

LIBRARIES	:= -lnetfilter_conntrack

ifneq ($(strip $(NCURSES)),)
CFLAGS      += -DENABLE_NCURSES
LIBRARIES   += -l:libncurses.so.5 -l:libtinfo.so.5
endif

EXECUTABLE	:= nftop
SOURCEDIRS	:= $(shell find $(SRC) -type d)
INCLUDEDIRS	:= $(shell find $(INCLUDE) -type d)
LIBDIRS		:= $(shell find $(LIB) -type d)

CINCLUDES	:= $(patsubst %,-I%, $(INCLUDEDIRS:%/=%))
CLIBS		:= $(patsubst %,-L%, $(LIBDIRS:%/=%))

SOURCES		:= $(wildcard $(patsubst %,%/*.c, $(SOURCEDIRS)))
OBJECTS		:= $(SOURCES:.c=.o)

TESTS		:= $(wildcard $(patsubst %,%/*.c, tests))

all: $(BIN)/$(EXECUTABLE)

.PHONY: clean debug
clean:
	-$(RM) $(BIN)/$(EXECUTABLE)
	-$(RM) $(BIN)/dump
	-$(RM) tests/dump.o
	-$(RM) $(OBJECTS)

debug: CFLAGS += -DDEBUG -ggdb3
debug: $(BIN)/$(EXECUTABLE)

dump: $(BIN)/dump
	$(info    SOURCES: $(SOURCES) OBJECTS: $(OBJECTS) INCLUDES: $(CINCLUDES))

$(BIN)/dump: tests/dump.o
	$(info    SOURCES: $(SOURCES) OBJECTS: $(OBJECTS) INCLUDES: $(CINCLUDES))
	$(CC) $(CFLAGS) $(CINCLUDES) $(CLIBS) $^ -o $@ $(LIBRARIES)

run: all
	./$(BIN)/$(EXECUTABLE)

$(BIN)/$(EXECUTABLE): $(OBJECTS)
	$(info    SOURCES: $(SOURCES) OBJECTS: $(OBJECTS) INCLUDES: $(CINCLUDES))
	$(info    CLIBS: $(CLIBS) $(LIBRARIES))
	$(info    CFLAGS: $(CFLAGS))
	$(CC) $(CFLAGS) $(CINCLUDES) $(CLIBS) $^ -o $@ $(LIBRARIES)
