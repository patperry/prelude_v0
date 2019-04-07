#ifndef LRESEARCH_H
#define LRESEARCH_H

#include "lua.h"
#include "research.h"

int luaopen_text(lua_State *L);

void lresearch_open(lua_State *L);
Context *lresearch_context(lua_State *L);
void lresearch_close(lua_State *L);

#endif /* LRESEARCH_H */
