CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow
CPPFLAGS = -Isrc

SRC     = src/entry.c src/format.c src/analyse.c
OBJ     = $(SRC:.c=.o)
BIN     = logsift
TESTBIN = run_tests

PREFIX ?= /usr/local

.PHONY: all test clean install uninstall

all: $(BIN)

$(BIN): $(OBJ) src/main.o
	$(CC) $(CFLAGS) -o $@ $^

$(TESTBIN): $(OBJ) tests/test_logsift.o
	$(CC) $(CFLAGS) -o $@ $^

tests/test_logsift.o: tests/test_logsift.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -Itests -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

test: $(TESTBIN)
	./$(TESTBIN)

install: $(BIN)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BIN)

clean:
	rm -f $(OBJ) src/main.o tests/test_logsift.o $(BIN) $(TESTBIN)
