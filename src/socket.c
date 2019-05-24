#include <assert.h>
#include <errno.h>
#include <string.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "prelude.h"

static bool socketconnect_blocked(Context *ctx, Task *task);
static bool socketshutdown_blocked(Context *ctx, Task *task);


void socket_init(Context *ctx, Socket *sock, int domain, int type,
                 int protocol)
{
    if (ctx->error) {
        sock->fd = -1;
        return;
    }

    sock->fd = socket(domain, type, protocol);
    if (sock->fd < 0) {
        int status = errno;
        context_panic(ctx, error_code(status),
                      "failed opening socket: %s", strerror(status));
    }

    int flags = fcntl(sock->fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(sock->fd, F_SETFL, flags | O_NONBLOCK); // ignore error
    }
}


void socket_deinit(Context *ctx, Socket *sock)
{
    (void)ctx;
    if (sock->fd >= 0)
        close(sock->fd);
}


void socketconnect_init(Context *ctx, SocketConnect *req, Socket *socket,
                        const struct sockaddr *address, int address_len)
{
    assert(address_len >= 0);
    (void)ctx;
    memset(req, 0, sizeof(*req));
    req->task._blocked = socketconnect_blocked;
    req->socket = socket;
    req->address = address;
    req->address_len = address_len;
    req->started = false;
}


void socketconnect_deinit(Context *ctx, SocketConnect *conn)
{
    (void)ctx;
    (void)conn;
}


bool socketconnect_blocked(Context *ctx, Task *task)
{
    if (ctx->error)
        return false;

    SocketConnect *req = (SocketConnect *)task;

    if (connect(req->socket->fd, req->address,
                (socklen_t)req->address_len) < 0) {
        int status = errno;

        if (!req->started) {
            if (status == EINPROGRESS) {
                req->task.block.type = BLOCK_IO;
                req->task.block.job.io.fd = req->socket->fd;
                req->task.block.job.io.flags = IO_WRITE;
                req->started = true;
                return true;
            }
        } else if (status == EALREADY || status == EINTR) {
            return true;
        } else if (status == EISCONN) {
            goto exit;
        }

        assert(status);
        context_code(ctx, status);
        context_panic(ctx, ctx->error, "failed connecting to peer: %s",
                      ctx->message);
    }

exit:
    req->task.block.type = BLOCK_NONE;
    return false;
}


void socketshutdown_init(Context *ctx, SocketShutdown *req, Socket *socket,
                         int how)
{
    memset(req, 0, sizeof(*req));
    if (ctx->error)
        return;

    req->task._blocked = socketshutdown_blocked;
    req->socket = socket;
    req->how = how;
}


void socketshutdown_deinit(Context *ctx, SocketShutdown *req)
{
    (void)ctx;
    (void)req;
}


bool socketshutdown_blocked(Context *ctx, Task *task)
{
    if (ctx->error)
        return false;

    SocketShutdown *req = (SocketShutdown *)task;
    if (shutdown(req->socket->fd, req->how) < 0) {
        int status = errno;
        if (status != ENOTCONN) { // peer closed the connection
            assert(status);
            context_code(ctx, status);
            context_panic(ctx, ctx->error,
                          "failed shutting down connection to peer: %s",
                          ctx->message);
        }
    }

    return false;
}
