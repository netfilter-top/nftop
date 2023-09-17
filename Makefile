CC		:= gcc
CFLAGS	+= -Wall -Wextra -pedantic -O3
CPPFLAGS += -D __FILENAME__='"$(subst $(PWD)/,,$(abspath $<))"'

BIN		:= $(PWD)/build/bin
SRC		:= $(PWD)/src

LIBRARIES	:= -lnetfilter_conntrack

ifeq ($(strip $(PREFIX)),)
    PREFIX := /usr
endif

ifneq ($(strip $(NCURSES)),)
CFLAGS      += -DENABLE_NCURSES
LIBRARIES   += -l:libncurses.so.5 -l:libtinfo.so.5
endif

EXECUTABLE	:= nftop

SOURCES		:= $(wildcard $(patsubst %,%/*.c, $(SRC)))
OBJECTS		:= $(SOURCES:.c=.o)

TESTS		:= $(wildcard $(patsubst %,%/*.c, tests))
TESTS_OBJ	:= $(TESTS:.c=.o)

all: $(BIN)/$(EXECUTABLE)

.ONESHELL:
.PHONY: clean debug install deb-pkg
clean:
	-$(RM) -r build/*
	-$(RM) $(TESTS_OBJ)
	-$(RM) $(OBJECTS)
	-$(RM) -r debian/nftop
	-$(RM) debian/nftop.debhelper.log
	-$(RM) debian/nftop.substvars
	-$(RM) debian/files
	-$(RM) debian/debhelper-build-stamp
	-$(RM) -r build/packages

debug: CFLAGS += -DDEBUG -g -ggdb3 -pg -O0
debug: $(BIN)/$(EXECUTABLE)

dump: $(BIN)/dump
	$(info    SOURCES: $(TESTS) OBJECTS: $(TESTS_OBJ) INCLUDES: $(CINCLUDES))

$(BIN)/dump: tests/dump.o
	$(info    SOURCES: $(TESTS) OBJECTS: $(TESTS_OBJ) INCLUDES: $(CINCLUDES))
	$(CC) $(CFLAGS) $(CINCLUDES) $(CLIBS) $^ -o $@ $(LIBRARIES)

dump_only: $(BIN)/dump_only
	$(info    SOURCES: $(TESTS) OBJECTS: $(TESTS_OBJ) INCLUDES: $(CINCLUDES))

$(BIN)/dump_only: tests/dump_only.o
	$(info    SOURCES: $(TESTS) OBJECTS: $(TESTS_OBJ) INCLUDES: $(CINCLUDES))
	$(CC) $(CFLAGS) $(CINCLUDES) $(CLIBS) $^ -o $@ $(LIBRARIES)

query_route: $(BIN)/query_route
	$(info    SOURCES: $(TESTS) OBJECTS: $(TESTS_OBJ) INCLUDES: $(CINCLUDES))

$(BIN)/query_route: tests/query_route.o
	$(info    SOURCES: $(TESTS) OBJECTS: $(TESTS_OBJ) INCLUDES: $(CINCLUDES))
	$(CC) $(CFLAGS) $(CINCLUDES) $(CLIBS) $^ -o $@ $(LIBRARIES)


run: all
	$(BIN)/$(EXECUTABLE)

$(BIN)/$(EXECUTABLE): $(OBJECTS)
	$(info  PREFIX: $(PREFIX)
	SOURCES: $(SOURCES) OBJECTS: $(OBJECTS) INCLUDES: $(CINCLUDES)
	CLIBS: $(CLIBS) $(LIBRARIES)
	CFLAGS: $(CFLAGS))
	install -d -D $(BIN)
	$(CC) $(CFLAGS) $(CINCLUDES) $(CLIBS) $^ -o $@ $(LIBRARIES)
	gzip -c $(SRC)/nftop.8 > $(BIN)/nftop.8.gz

install: $(BIN)/$(EXECUTABLE)
	install -d $(DESTDIR)$(PREFIX)/share/man/man8
	install -d $(DESTDIR)$(PREFIX)/sbin
	install $(BIN)/nftop.8.gz $(DESTDIR)$(PREFIX)/share/man/man8/
	install --strip $(BIN)/$(EXECUTABLE) $(DESTDIR)$(PREFIX)/sbin/

uninstall:
	-$(RM) $(DESTDIR)$(PREFIX)/share/man/man8/nftop.8.gz
	-$(RM) $(DESTDIR)$(PREFIX)/sbin/nftop

deb-pkg:
	install -D -d build/packages
	ln -s $(PWD)/Makefile build/packages/
	ln -s $(PWD)/src build/packages/
	ln -s $(PWD)/build/bin build/packages/
	ln -s $(PWD)/debian build/packages/
	cd build/packages
	PREFIX=$(PREFIX) dpkg-buildpackage -rfakeroot -uc -B