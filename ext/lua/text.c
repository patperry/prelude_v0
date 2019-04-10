#include "lua.h"
#include "lauxlib.h"
#include "module.h"

static int char_(lua_State *L)
{
    int i, n = lua_gettop(L);
    for (i = 1; i <= n; i++) {
        lua_Integer code = luaL_checkinteger(L, i);
        (void)code;
    }
    lua_pushstring(L, "xxx");
    return 1;
}


static int decode(lua_State *L)
{
    size_t len;
    const char *input = luaL_checklstring(L, 1, &len);
    const char *mode = luaL_optstring(L, 2, "n");
    TextViewType flags = TEXT_VIEW_VALIDATE;

    switch (mode[0]) {
    case 'n':
        break;

    case 'u':
        flags |= TEXT_VIEW_UNESCAPE;
        break;

    default:
        luaL_argcheck(L, 0, 2, "invalid format");
        break;
    }

    Context *ctx = lmodule_context(L);
    Text *text = lua_newuserdata(L, sizeof(*text));
    Error error = text_view(ctx, text, flags, (const uint8_t *)input, len);

    switch (error) {
    case ERROR_NONE:
        luaL_getmetatable(L, "text");
        lua_setmetatable(L, -2);
        return 1;

    case ERROR_VALUE:
        lua_pushboolean(L, 0);
        lua_pushstring(L, context_message(ctx));
        context_recover(ctx);
        return 2;

    default:
        lua_pushstring(L, context_message(ctx));
        context_recover(ctx);
        lua_error(L);
        return 0;
    }
}


static int eq(lua_State *L)
{
    Context *ctx = lmodule_context(L);
    const Text *text1 = luaL_checkudata(L, 1, "text");
    const Text *text2 = luaL_checkudata(L, 2, "text");
    bool eq = text_eq(ctx, text1, text2);
    lua_pushboolean(L, (int)eq);
    return 1;
}


static int tostring(lua_State *L)
{
    const Text *text = luaL_checkudata(L, 1, "text");
    lua_pushlstring(L, (const char *)text->bytes, text->size);
    return 1;
}


static const struct luaL_Reg textlib_f[] = {
    {"char", char_},
    {"decode", decode},
    {NULL, NULL}
};

static const struct luaL_Reg textlib_m[] = {
    {"__eq", eq},
    {"__tostring", tostring},
    {NULL, NULL}
};


int luaopen_text(lua_State *L)
{
    luaL_newmetatable(L, "text");
    luaL_setfuncs(L, textlib_m, 0);
    luaL_newlib(L, textlib_f);
    return 1;
}
