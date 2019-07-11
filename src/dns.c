#define _POSIX_C_SOURCE 200112L
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "prelude.h"

static bool getaddrinfo_blocked(Context *ctx, Task *task);


void getaddrinfo_init(Context *ctx, GetAddrInfo *req, const char *node,
                      const char *service, SocketType type, IpType family,
                      int flags)
{
    memory_clear(ctx, req, sizeof(*req));
    req->task._blocked = getaddrinfo_blocked;
    req->node = node;
    req->service = service;
    req->type = type;
    req->family = family;
    req->flags = flags;
}


void getaddrinfo_deinit(Context *ctx, GetAddrInfo *req)
{
    (void)ctx;

    struct addrinfo *ai = req->_ai;
    if (ai) {
        freeaddrinfo(ai);
    }
}


bool getaddrinfo_blocked(Context *ctx, Task *task)
{
    if (ctx->error)
        return false;

    GetAddrInfo *req = (GetAddrInfo *)task;
    struct addrinfo hints = {0};

    switch (req->type) {
    case SOCKET_TCP:
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        break;
    case SOCKET_UDP:
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
        break;
    default:
        break;
    }

    switch (req->family) {
    case IP_V4:
        hints.ai_family = PF_INET;
        break;
    case IP_V6:
        hints.ai_family = PF_INET6;
        break;
    default:
        break;
    }

    struct addrinfo *ai;
    int status = getaddrinfo(req->node, req->service, &hints, &ai);
    req->_ai = ai;

    if (status) {
        context_panic(ctx, ERROR_OS, "failed getting address information: %s",
                      gai_strerror(status));
    }

    req->result._ai_next = ai;
    if (!addrinfoiter_advance(ctx, &req->result)) {
        context_panic(ctx, ERROR_OS, "failed getting address information");
    }

    return false;
}


bool addrinfoiter_advance(Context *ctx, AddrInfoIter *it)
{
    (void)ctx;
    const struct addrinfo *ai = it->_ai_next;
    if (!ai)
        return false;

    bool invalid = false;

    memset(&it->current, 0, sizeof(it->current));
    if (ai->ai_family == PF_INET) {
        const struct sockaddr_in *addr = (struct sockaddr_in *)ai->ai_addr;
        it->current.addr.type = IP_V4;
        it->current.addr.value.v4.port = ntohs(addr->sin_port);
        memcpy(&it->current.addr.value.v4.ip.bytes,
               &addr->sin_addr.s_addr,
               sizeof(it->current.addr.value.v4.ip.bytes));
    } else if (ai->ai_family == PF_INET6) {
        const struct sockaddr_in6 *addr = (struct sockaddr_in6 *)ai->ai_addr;
        it->current.addr.type = IP_V6;
        it->current.addr.value.v6.port = ntohs(addr->sin6_port);
        it->current.addr.value.v6.flowinfo = addr->sin6_flowinfo;
        it->current.addr.value.v6.scope_id = addr->sin6_scope_id;
        memcpy(&it->current.addr.value.v6.ip.bytes,
               &addr->sin6_addr.s6_addr,
               sizeof(it->current.addr.value.v6.ip.bytes));
    } else {
        invalid = true;
    }

    switch (ai->ai_socktype) {
    case SOCK_STREAM:
        it->current.type = SOCKET_TCP;
        break;
    case SOCK_DGRAM:
        it->current.type = SOCKET_UDP;
        break;
    default:
        invalid = true;
        break;
    }

    it->current.canonname = ai->ai_canonname;
    it->_ai_next = ai->ai_next;

    if (invalid) {
        return addrinfoiter_advance(ctx, it);
    } else {
        return true;
    }
}
