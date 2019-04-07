#include "lresearch.h"

static Context context;

void lresearch_open(lua_State *L)
{
    (void)L;
    context_init(&context, NULL, NULL, NULL, NULL);
}

Context *lresearch_context(lua_State *L)
{
    (void)L;
    return &context;
}

void lresearch_close(lua_State *L)
{
    (void)L;
    context_deinit(&context);
}
