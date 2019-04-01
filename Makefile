
CC += -std=c99
CFLAGS += -Wall -Wextra -pedantic -Werror -g
CPPFLAGS += -Ilib
LUA = lua
LIBS += -lm

schema: src/schema.o lib/context.o
	$(CC) -o $@ $^ $(LIBS) $(LDFLAGS)

lib/context.o: lib/context.c lib/context.h
#	$(CC) $(CFLAGS) -o $@ $(CPPCLAGS)

clean:
	$(RM) schema lib/context.o src/schema.o

check: schema tests/schema.lua
	$(LUA) tests/schema.lua

.PHONY: clean check
