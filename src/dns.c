#define _POSIX_C_SOURCE 200112L
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "prelude.h"

static bool getaddrinfo_blocked(Context *ctx, Task *task);


void getaddrinfo_init(Context *ctx, GetAddrInfo *req, const char *node,
                      const char *service, const struct addrinfo *hints)
{
    memory_clear(ctx, req, sizeof(*req));
    req->task._blocked = getaddrinfo_blocked;
    req->node = node;
    req->service = service;
    req->hints = hints;
}


void getaddrinfo_deinit(Context *ctx, GetAddrInfo *req)
{
    (void)ctx;

    if (req->result) {
        freeaddrinfo(req->result);
    }
}


bool getaddrinfo_blocked(Context *ctx, Task *task)
{
    if (ctx->error)
        return false;

    GetAddrInfo *req = (GetAddrInfo *)task;
    int status = getaddrinfo(req->node, req->service, req->hints, &req->result);

    if (status) {
        context_panic(ctx, ERROR_OS, "failed getting address information: %s",
                      gai_strerror(status));
    }

    return false;
}
