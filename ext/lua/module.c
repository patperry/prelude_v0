#include "module.h"
#include "lua.h"
#include "lauxlib.h"


static Context context;


static const luaL_Reg module_libs[] = {
    {"text", luaopen_text},
    {NULL, NULL}
};


void lmodule_init(lua_State *L)
{
    const luaL_Reg *lib;
    
    context_init(&context, NULL, NULL, NULL, NULL);

    for (lib = module_libs; lib->func; lib++) {
        luaL_requiref(L, lib->name, lib->func, 1);
        lua_pop(L, 1);
    }
}


Context *lmodule_context(lua_State *L)
{
    (void)L;
    return &context;
}


void lmodule_deinit(lua_State *L)
{
    (void)L;
    context_deinit(&context);
}
