AR = ar rcu
CC += -std=c99
LUA = lua
RANLIB = ranlib

LIBS += -lm
CFLAGS += -Wall -Wextra -pedantic -Werror -g
CPPFLAGS += -Isrc
LDFLAGS = -g

RESEARCH_A = libreasearch.a
RESEARCH_O = src/context.o

ALL_O = $(LIB_O) src/main/schema.o
ALL_T = $(RESEARCH_A) bin/schema
ALL_A = $(RESEARCH_A)

.PHONY: all
all: $(ALL_T)

$(RESEARCH_A): $(RESEARCH_O)
	$(AR) $@ $(RESEARCH_O)
	$(RANLIB) $@

bin/schema: src/main/schema.o $(RESEARCH_A)
	$(CC) -o $@ $^ $(LIBS) $(LDFLAGS)

.PHONY: clean
clean:
	$(RM) $(ALL_T) $(ALL_O)

.PHONY: check
check: bin/schema tests/schema.lua
	$(LUA) tests/schema.lua

src/context.o: src/context.c src/context.h
