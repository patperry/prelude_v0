#include "research.h"
#include "lua.h"
#include "lauxlib.h"
#include "lresearch.h"

static int validate(lua_State *L)
{
    size_t len;
    const char *input = luaL_checklstring(L, 1, &len);
    Context *ctx = lresearch_context(L);
    TextViewType flags = TEXT_VIEW_VALIDATE;
    Text text;
    Error error = text_view(ctx, &text, flags, (const uint8_t *)input, len);

    switch (error) {
    case ERROR_NONE:
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

static const struct luaL_Reg textlib[] = {
    {"validate", validate},
    {NULL, NULL}
};

int luaopen_text(lua_State *L)
{
    luaL_newlib(L, textlib);
    return 1;
}
