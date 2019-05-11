
#include "lprelude.h"


static int connect(lua_State *L)
{
    Context *ctx = lprelude_open(L);
    size_t len;
    const char *host = luaL_checklstring(L, 1, &len);
    const char *service = luaL_optstring(L, 2, NULL);

    Socket *sock = lua_newuserdata(L, sizeof(*sock));
    memory_clear(ctx, sock, sizeof(*sock));
    luaL_getmetatable(L, "socket");
    lua_setmetatable(L, -2);

    (void)host;
    (void)service;
    
    lprelude_close(L, ctx);
    return 1;
}


static int send(lua_State *L)
{
    (void)L;
    return 1;
}


static int receive(lua_State *L)
{
    (void)L;
    return 1;
}


static const struct luaL_Reg socketlib_f[] = {
    {"connect", connect},
    {NULL, NULL}
};


static const struct luaL_Reg socketlib_m[] = {
    {"send", send},
    {"receive", receive},
    {NULL, NULL}
};


int luaopen_socket(lua_State *L)
{
    luaL_newmetatable(L, "socket");
    luaL_setfuncs(L, socketlib_m, 0);
    luaL_newlib(L, socketlib_f);
    return 1;
}
