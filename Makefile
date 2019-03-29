
CC += -std=c99
CFLAGS += -Wall -Wextra -pedantic -Werror -g
LUA = lua
LIBS += -lm

schema: src/schema.o
	$(CC) -o $@ $< $(LIBS) $(LDFLAGS)

clean:
	$(RM) schema src/schema.o

check: schema tests/schema.lua
	$(LUA) tests/schema.lua

.PHONY: clean check
