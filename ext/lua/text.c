#include "lua.h"
#include "lauxlib.h"
#include "module.h"


void pushtext(lua_State *L, const Text *text)
{
    Context *ctx = lmodule_open(L);
    TextObj *obj = lua_newuserdata(L, sizeof(*obj));
    luaL_getmetatable(L, "text");
    lua_setmetatable(L, -2);
    textobj_init(ctx, obj, text);
    lmodule_close(L, ctx);
}


static int char_(lua_State *L)
{
    Context *ctx = lmodule_open(L);
    int i, n = lua_gettop(L);
    TextBuild build;

    textbuild_init(ctx, &build);

    for (i = 1; i <= n; i++) {
        lua_Integer code = luaL_checkinteger(L, i);
        if (code > CHAR32_MAX || code < 0) {
            luaL_error(L, "argument %d is outside code point range", i);
        }
        textbuild_char(ctx, &build, code);
    }
    Text text = textbuild_get(ctx, &build);
    pushtext(L, &text);
    textbuild_deinit(ctx, &build);
    lmodule_close(L, ctx);
    return 1;
}


static int codepoint(lua_State *L)
{
    Context *ctx = lmodule_open(L);
    const Text *text = luaL_checkudata(L, 1, "text");
    lua_Integer i = luaL_optinteger(L, 2, 1);
    lua_Integer j = luaL_optinteger(L, 3, i);
    lua_Integer pos = 1;
    int nret = 0;

    if (i < 0 || j < 0) {
        lua_Integer n = (lua_Integer)text_len(ctx, text);
        if (i < 0) {
            i = (n + i) + 1;
        }
        if (j < 0) {
            j = (n + j) + 1;
        }
    }

    TextIter it;
    textiter_init(ctx, &it, text);

    while (pos < i) {
        if (textiter_advance(ctx, &it)) {
            pos++;
        } else {
            goto out;
        }
    }

    while (pos <= j) {
        lua_pushinteger(L, (lua_Integer)it.current);
        nret++; // no overflow since text size <= INT32_MAX
        if (textiter_advance(ctx, &it)) {
            pos++;
        } else {
            goto out;
        }
    }
out:
    textiter_deinit(ctx, &it);
    lmodule_close(L, ctx);
    return nret;
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

    Context *ctx = lmodule_open(L);
    Text text;
    Error error = text_view(ctx, &text, flags, (const uint8_t *)input, len);
    int nret;

    switch (error) {
    case ERROR_NONE:
        pushtext(L, &text);
        nret = 1;
        break;

    case ERROR_VALUE:
        lua_pushboolean(L, 0);
        lua_pushstring(L, context_message(ctx));
        context_recover(ctx);
        nret = 2;
        break;

    default:
        nret = 0;
        break;
    }

    lmodule_close(L, ctx);
    return nret;
}


static int eq(lua_State *L)
{
    Context *ctx = lmodule_open(L);
    const Text *text1 = luaL_checkudata(L, 1, "text");
    const Text *text2 = luaL_checkudata(L, 2, "text");
    bool eq = text_eq(ctx, text1, text2);
    lua_pushboolean(L, (int)eq);
    lmodule_close(L, ctx);
    return 1;
}


static int len(lua_State *L)
{
    Context *ctx = lmodule_open(L);
    const Text *text = luaL_checkudata(L, 1, "text");
    int32_t len = text_len(ctx, text);
    lua_pushinteger(L, (lua_Integer)len);
    lmodule_close(L, ctx);
    return 1;
}


static int tostring(lua_State *L)
{
    const Text *text = luaL_checkudata(L, 1, "text");
    lua_pushlstring(L, (const char *)text->bytes, text->size);
    return 1;
}


static int gc(lua_State *L)
{
    Context *ctx = lmodule_open(L);
    TextObj *obj = lua_touserdata(L, 1);
    textobj_deinit(ctx, obj);
    lmodule_close(L, ctx);
    return 0;
}



static const struct luaL_Reg textlib_f[] = {
    {"char", char_},
    {"codepoint", codepoint},
    {"decode", decode},
    {NULL, NULL}
};


static const struct luaL_Reg textlib_m[] = {
    {"__eq", eq},
    {"__gc", gc},
    {"__len", len},
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
