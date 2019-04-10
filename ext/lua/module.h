#ifndef LUA_MODULE_H
#define LUA_MODULE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "context.h"
#include "text.h"

#include "lua.h"

int luaopen_text(lua_State *L);

void lmodule_init(lua_State *L);
void lmodule_deinit(lua_State *L);

Context *lmodule_open(lua_State *L);
void lmodule_close(lua_State *L, Context *ctx);

#endif /* LUA_MODULE_H */
