#include <assert.h>
#include <errno.h>
#include <string.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include "prelude.h"

static bool tcpconnect_blocked(Context *ctx, Task *task);
static bool tcpshutdown_blocked(Context *ctx, Task *task);
static bool tcpread_blocked(Context *ctx, Task *task);

static void tcpread_init(Context *ctx, Read *req, void *stream, void *buffer,
                         int length);
static void tcpread_reset(Context *ctx, Read *req, void *buffer, int length);
static void tcpread_deinit(Context *ctx, Read *req);

static StreamType TcpStreamImpl = {
    tcpread_init,
    tcpread_reset,
    tcpread_deinit
};


void tcp_init(Context *ctx, Tcp *tcp, int domain)
{
    memory_clear(ctx, tcp, sizeof(*tcp));
    tcp->stream.type = &TcpStreamImpl;
    tcp->fd = -1;

    if (ctx->error) {
        return;
    }

    tcp->fd = socket(domain, SOCK_STREAM, IPPROTO_TCP);
    if (tcp->fd < 0) {
        int status = errno;
        context_panic(ctx, error_code(status),
                      "failed opening tcp: %s", strerror(status));
    }

    int flags = fcntl(tcp->fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(tcp->fd, F_SETFL, flags | O_NONBLOCK); // ignore error
    }
}


void tcp_deinit(Context *ctx, Tcp *tcp)
{
    (void)ctx;
    if (tcp->fd >= 0)
        close(tcp->fd);
}


void tcpconnect_init(Context *ctx, TcpConnect *req, Tcp *tcp,
                     const struct sockaddr *address, int address_len)
{
    assert(address_len >= 0);
    (void)ctx;
    memset(req, 0, sizeof(*req));
    req->task._blocked = tcpconnect_blocked;
    req->tcp = tcp;
    req->address = address;
    req->address_len = address_len;
    req->started = false;
}


void tcpconnect_deinit(Context *ctx, TcpConnect *conn)
{
    (void)ctx;
    (void)conn;
}


bool tcpconnect_blocked(Context *ctx, Task *task)
{
    if (ctx->error)
        return false;

    TcpConnect *req = (TcpConnect *)task;

    if (connect(req->tcp->fd, req->address,
                (socklen_t)req->address_len) < 0) {
        int status = errno;

        if (!req->started) {
            if (status == EINPROGRESS) {
                req->task.block.type = BLOCK_IO;
                req->task.block.job.io.fd = req->tcp->fd;
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


void tcpshutdown_init(Context *ctx, TcpShutdown *req, Tcp *tcp,
                         int how)
{
    memset(req, 0, sizeof(*req));
    if (ctx->error)
        return;

    req->task._blocked = tcpshutdown_blocked;
    req->tcp = tcp;
    req->how = how;
}


void tcpshutdown_deinit(Context *ctx, TcpShutdown *req)
{
    (void)ctx;
    (void)req;
}


bool tcpshutdown_blocked(Context *ctx, Task *task)
{
    if (ctx->error)
        return false;

    TcpShutdown *req = (TcpShutdown *)task;
    if (shutdown(req->tcp->fd, req->how) < 0) {
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


void tcpread_init(Context *ctx, Read *req, void *stream,
                  void *buffer, int length)
{
    assert(length >= 0);

    memory_clear(ctx, req, sizeof(*req));
    req->stream = stream;
    if (ctx->error)
        return;

    req->task._blocked = tcpread_blocked;
    tcpread_reset(ctx, req, buffer, length);
}


void tcpread_reset(Context *ctx, Read *req, void *buffer, int length)
{
    assert(length >= 0);

    if (ctx->error)
        return;

    Stream *stream = req->stream;
    req->stream = stream;
    req->buffer = buffer;
    req->length = length;
    req->nread = 0;
}


void tcpread_deinit(Context *ctx, Read *req)
{
    (void)ctx;
    (void)req;
}


bool tcpread_blocked(Context *ctx, Task *task)
{
    if (ctx->error)
        return false;

    Read *req = (Read *)task;
    Tcp *tcp = container_of(req->stream, Tcp, stream);

    if (req->length == 0) {
        return false;
    }

    int nrecv = (int)recv(tcp->fd, req->buffer, (size_t)req->length, 0);

    if (nrecv < 0) {
        int status = errno;
        if (status == EAGAIN || status == EWOULDBLOCK || status == EINTR) {
            req->task.block.type = BLOCK_IO;
            req->task.block.job.io.fd = tcp->fd;
            req->task.block.job.io.flags = IO_READ;
            return true;
        } else {
            assert(status);
            context_code(ctx, status);
            context_panic(ctx, ctx->error,
                          "failed receiving data: %s", ctx->message);
        }
    } else if (nrecv == 0) {
        context_panic(ctx, ERROR_OS,
                      "failed receiving data: connection reset by peer");
    } else {
        req->nread = nrecv;
    }

    req->task.block.type = BLOCK_NONE;
    return false;
}
