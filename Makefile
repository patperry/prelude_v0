AR = ar rcu
CC += -std=c99
MKDIR_P = mkdir -p
RANLIB = ranlib

LIBS += -lm -lssl -lcrypto
CFLAGS += -Wall -Wextra -pedantic -Werror -g
CPPFLAGS += -Isrc -I/usr/local/opt/libressl/include
LDFLAGS += -g -L/usr/local/opt/libressl/lib

LIBRARY_A = src/library.a
LIBRARY_O = src/array.o src/async.o src/char.o src/context.o src/dns.o \
			src/log.o src/memory.o src/socket.o src/text.o src/textalloc.o \
			src/textbuild.o src/textiter.o src/tls.o

LUASRC = lib/lua-5.3.5/src
LUA_CPPFLAGS = -DLUA_USE_READLINE -I$(LUASRC)
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
			$(LUASRC)/ltablib.o $(LUASRC)/lutf8lib.o $(LUASRC)/loadlib.o \
			ext/lua/linit.o
LUA_EXT_O = ext/lua/lprelude.o ext/lua/text.o
LUA_BASE_O = $(LUA_CORE_O) $(LUA_LIB_O) $(LUA_EXT_O)
LUA = bin/lua

ALL_O = $(LIBRARY_O) $(LUA_BASE_O) $(LUASRC)/lua.o src/main/schema.o
ALL_T = $(LIBRARY_A) bin/lua bin/download bin/schema
ALL_A = $(LIBRARY_A) $(LUA_A)

.PHONY: all
all: $(ALL_T)

$(LIBRARY_A): $(LIBRARY_O)
	$(AR) $@ $(LIBRARY_O)
	$(RANLIB) $@

$(LUA_A): $(LUA_BASE_O)
	$(AR) $@ $(LUA_BASE_O)
	$(RANLIB) $@

bin/lua: $(LUASRC)/lua.o $(LUA_A) $(LIBRARY_A)
	$(MKDIR_P) bin && $(CC) $(LDFLAGS) -o $@ $^ $(LIBS) $(LUA_LIBS)

bin/download: src/main/download.o $(LIBRARY_A)
	$(MKDIR_P) bin && $(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

bin/schema: src/main/schema.o $(LIBRARY_A)
	$(MKDIR_P) bin && $(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

src/%.o : src/%.c src/prelude.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(LUASRC)/%.o : $(LUASRC)/%.c
	$(CC) $(CPPFLAGS) $(LUA_CPPFLAGS) $(CFLAGS) -c -o $@ $<

ext/lua/%.o : ext/lua/%.c ext/lua/lprelude.h src/prelude.h
	$(CC) $(CPPFLAGS) $(LUA_CPPFLAGS) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	$(RM) $(ALL_T) $(ALL_O)

.PHONY: check
check: $(LUA) tests/all.lua tests/text.lua
	$(LUA) tests/all.lua
