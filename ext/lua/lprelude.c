#include "lprelude.h"


static int gc(lua_State *L);

typedef struct {
    lua_Alloc alloc_func;
    void *data;
} Alloc;


static const char ALLOC_KEY = 'k';
static const char CONTEXT_KEY = 'k';

static const struct luaL_Reg context_m[] = {
    {"__gc", gc},
    {NULL, NULL}
};

static const luaL_Reg module_libs[] = {
    {"text", luaopen_text},
    {NULL, NULL}
};

// override the lua allocator with the prelude default for testing
static void *l_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
    (void)ud;
    return default_alloc(ptr, osize, nsize, NULL);
}

static void *alloc_func(void *buf, size_t old_size, size_t new_size, void *data)
{
    Alloc *alloc = data;
    return (alloc->alloc_func)(alloc->data, buf, old_size, new_size);
}

void luaopen_prelude(lua_State *L)
{
    const luaL_Reg *lib;

    lua_setallocf(L, l_alloc, NULL); // for testing
    lua_pushlightuserdata(L, (void *)&ALLOC_KEY);
    Alloc *alloc = lua_newuserdata(L, sizeof(*alloc));
    alloc->alloc_func = lua_getallocf(L, &alloc->data);
    lua_settable(L, LUA_REGISTRYINDEX);

    luaL_newmetatable(L, "context");
    luaL_setfuncs(L, context_m, 0);

    lua_pushlightuserdata(L, (void *)&CONTEXT_KEY);

    Context *ctx = lua_newuserdata(L, sizeof(*ctx));
    context_init(ctx, alloc_func, alloc, NULL, NULL);

    lua_pushvalue(L, -3);
    lua_setmetatable(L, -2);

    lua_settable(L, LUA_REGISTRYINDEX);
    lua_pop(L, 1);

    for (lib = module_libs; lib->func; lib++) {
        luaL_requiref(L, lib->name, lib->func, 1);
        lua_pop(L, 1);
    }
}


Context *lprelude_open(lua_State *L)
{
    lua_pushlightuserdata(L, (void *)&CONTEXT_KEY);
    lua_gettable(L, LUA_REGISTRYINDEX);
    Context *ctx = lua_touserdata(L, -1);
    lua_pop(L, 1);
    return ctx;
}


void lprelude_close(lua_State *L, Context *ctx)
{
    if (ctx->error) {
        lua_pushstring(L, ctx->message);
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
