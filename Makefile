AR = ar rcu
CC += -std=c99
RANLIB = ranlib

LIBS += -lm
CFLAGS += -Wall -Wextra -pedantic -Werror -g
CPPFLAGS += -Isrc -Ilib/lua-5.3.5/src
LDFLAGS = -g

RESEARCH_A = src/libreasearch.a
RESEARCH_O = src/context.o src/text.o

LUASRC = lib/lua-5.3.5/src
LUA_CPPFLAGS = -DLUA_USE_READLINE
LUA_LIBS = -lreadline
LUA_A = $(LUASRC)/liblua.a
LUA_CORE_O = $(LUASRC)/lapi.o $(LUASRC)/lcode.o $(LUASRC)/lctype.o \
			 $(LUASRC)/ldebug.o $(LUASRC)/ldo.o $(LUASRC)/ldump.o \
			 $(LUASRC)/lfunc.o $(LUASRC)/lgc.o $(LUASRC)/llex.o \
			 $(LUASRC)/lmem.o $(LUASRC)/lobject.o $(LUASRC)/lopcodes.o \
			 $(LUASRC)/lparser.o $(LUASRC)/lstate.o $(LUASRC)/lstring.o \
			 $(LUASRC)/ltable.o $(LUASRC)/ltm.o $(LUASRC)/lundump.o \
			 $(LUASRC)/lvm.o $(LUASRC)/lzio.o
LUA_LIB_O =	$(LUASRC)/lauxlib.o $(LUASRC)/lbaselib.o $(LUASRC)/lbitlib.o \
			$(LUASRC)/lcorolib.o $(LUASRC)/ldblib.o $(LUASRC)/liolib.o \
			$(LUASRC)/lmathlib.o $(LUASRC)/loslib.o $(LUASRC)/lstrlib.o \
			$(LUASRC)/ltablib.o $(LUASRC)/lutf8lib.o $(LUASRC)/loadlib.o
LUA_EXT_O = ext/lua/linit.o ext/lua/lresearch.o ext/lua/text.o
LUA_BASE_O = $(LUA_CORE_O) $(LUA_LIB_O) $(LUA_EXT_O)
LUA = bin/lua

ALL_O = $(LIB_O) $(LUA_BASE_O) $(LUASRC)/lua.o src/main/schema.o
ALL_T = $(RESEARCH_A) bin/lua bin/schema
ALL_A = $(RESEARCH_A) $(LUA_A)

.PHONY: all
all: $(ALL_T)

$(RESEARCH_A): $(RESEARCH_O)
	$(AR) $@ $(RESEARCH_O)
	$(RANLIB) $@

$(LUA_A): $(LUA_BASE_O)
	$(AR) $@ $(LUA_BASE_O)
	$(RANLIB) $@

bin/lua: $(LUASRC)/lua.o $(LUA_A) $(RESEARCH_A)
	$(CC) -o $@ $(LDFLAGS) $^ $(LIBS) $(LUA_LIBS)

$(LUASRC)/lua.o: $(LUASRC)/lua.c
	$(CC) -c -o $@ $(CPPFLAGS) $(LUA_CPPFLAGS) $(CFLAGS) $<

bin/schema: src/main/schema.o $(RESEARCH_A)
	$(CC) -o $@ $(LDFLAGS) $^ $(LIBS)

.PHONY: clean
clean:
	$(RM) $(ALL_T) $(ALL_O)

.PHONY: check
check:
	$(LUA) tests/all.lua

src/context.o: src/context.c src/context.h
src/text.o: src/text.c src/text.h

ext/lua/lreasearch.o: ext/lua/lresearch.c src/lresearch.h
ext/lua/text.o: ext/lua/text.c src/research.h
