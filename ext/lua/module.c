#include "module.h"
#include "lua.h"
#include "lauxlib.h"

static int gc(lua_State *L);

static const char ContextKey = 'k';

static const struct luaL_Reg context_m[] = {
    {"__gc", gc},
    {NULL, NULL}
};


static const luaL_Reg module_libs[] = {
    {"text", luaopen_text},
    {NULL, NULL}
};


void lmodule_init(lua_State *L)
{
    const luaL_Reg *lib;

    luaL_newmetatable(L, "context");
    luaL_setfuncs(L, context_m, 0);

    lua_pushlightuserdata(L, (void *)&ContextKey);

    Context *ctx = lua_newuserdata(L, sizeof(*ctx));
    context_init(ctx, NULL, NULL, NULL, NULL);

    lua_pushvalue(L, -3);
    lua_setmetatable(L, -2);

    lua_settable(L, LUA_REGISTRYINDEX);
    lua_pop(L, 1);

    for (lib = module_libs; lib->func; lib++) {
        luaL_requiref(L, lib->name, lib->func, 1);
        lua_pop(L, 1);
    }
}


Context *lmodule_open(lua_State *L)
{
    lua_pushlightuserdata(L, (void *)&ContextKey);
    lua_gettable(L, LUA_REGISTRYINDEX);
    Context *ctx = lua_touserdata(L, -1);
    lua_pop(L, 1);
    return ctx;
}


void lmodule_close(lua_State *L, Context *ctx)
{
    if (context_error(ctx)) {
        lua_pushstring(L, context_message(ctx));
        context_recover(ctx);
        lua_error(L);
    }
}


int gc(lua_State *L)
{
    Context *ctx = lua_touserdata(L, 1);
    context_deinit(ctx);
    return 0;
}
