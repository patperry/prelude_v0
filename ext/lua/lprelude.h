#ifndef LPRELUDE_H
#define LPRELUDE_H

#include "lua.h"
#include "lauxlib.h"

#include "prelude.h"

int luaopen_text(lua_State *L);
void luaopen_prelude(lua_State *L);

Context *lprelude_open(lua_State *L);
void lprelude_close(lua_State *L, Context *ctx);

#endif /* LPRELUDE_H */
