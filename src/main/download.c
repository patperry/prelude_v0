#define _POSIX_C_SOURCE 200112L
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "prelude.h"

// https://people.eecs.berkeley.edu/~sangjin/2012/12/21/epoll-vs-kqueue.html

#define BUFFER_LEN 4096



int64_t clock_usec(clockid_t clock_id)
{
    struct timespec tp;
    clock_gettime(clock_id, &tp);
    return (int64_t)tp.tv_sec * 1000 * 1000 + tp.tv_nsec / 1000;
}


/*
 * epoll
 * -----
 * EPOLLIN read
 * EPOLLOUT wrtie
 * EPOLLRDHUP peer shut down writing half of connection
 * EPOLLPRI exceptional condition (POLLPRI)
 * EPOLLHUP hang up
 *
 * kqueue
 * ------
 * EVFILT_READ
 * EVFILT_EXCEPT
 * EVFILT_WRITE
 * EVFILT_VNODE
 * EVFILT_PROC
 * EVFILT_SIGNAL
 * EVFILT_MACHPORT
 * EVFILT_TIMER
 */



typedef enum {
    HTTPGET_START = 0,
    HTTPGET_GETADDR,
    HTTPGET_OPEN,
    HTTPGET_CONNECT,
    HTTPGET_STARTTLS,
    HTTPGET_SEND,
    HTTPGET_RECV,
    HTTPGET_FINISH
} HttpGetState;



typedef struct {
    Task task;
    HttpGetState state;
    const char *host;
    const char *target;
    TlsContext *tls;

    struct addrinfo hints;
    GetAddrInfo getaddr;
    Socket sock;
    bool has_sock;
    SockConnect conn;
    SockStartTls starttls;
    SockSend send;
    HttpRecv recv;
    SockShutdown shutdown;

    void *buffer;
    uint8_t *data;

    size_t buffer_len;
    size_t data_len;
    size_t data_max;
} HttpGet;


static bool httpget_start(Context *ctx, HttpGet *req)
{
    if (ctx->error)
        return false;

    log_debug(ctx, "getting address information for host %s", req->host);
    getaddrinfo_init(ctx, &req->getaddr, req->host, "https",
                     SOCKET_TCP, IP_NONE, 0);

    log_debug(ctx, "getaddr started");
    req->state = HTTPGET_GETADDR;
    return false;
}


static bool httpget_getaddr_blocked(Context *ctx, HttpGet *req)
{
    if (ctx->error)
        return false;

    if (task_blocked(ctx, &req->getaddr.task)) {
        req->task.block = req->getaddr.task.block;
        return true;
    }

    log_debug(ctx, "getaddr finished");
    log_debug(ctx, "open started");
    req->state = HTTPGET_OPEN;
    return false;
}


static bool httpget_open_blocked(Context *ctx, HttpGet *req)
{
    if (ctx->error) {
        log_debug(ctx, "error");
        return false;
    }

    req->has_sock = false;
    const AddrInfo *ai = NULL;

    while (!req->has_sock  && addrinfoiter_advance(ctx, &req->getaddr.result)) {
        log_debug(ctx, "trying next address");
        ai = &req->getaddr.result.current;
        socket_init(ctx, &req->sock, ai->type, ai->addr.type);
        if (ctx->error) {
            socket_deinit(ctx, &req->sock);
        } else {
            req->has_sock = true;
        }
    }

    if (!req->has_sock) {
        if (ctx->error) {
            context_panic(ctx, ctx->error, "failed connecting to host: %s",
                          ctx->message);
        } else {
            context_panic(ctx, ERROR_OS, "failed connecting to host");
        }
        return false;
    }

    log_debug(ctx, "about to connect");
    sockconnect_init(ctx, &req->conn, &req->sock, &ai->addr);

    log_debug(ctx, "open finished");
    log_debug(ctx, "connect started");
    req->state = HTTPGET_CONNECT;
    return false;
}


static bool httpget_connect_blocked(Context *ctx, HttpGet *req)
{
    if (ctx->error)
        return false;

    if (task_blocked(ctx, &req->conn.task)) {
        req->task.block = req->conn.task.block;
        return true;
    }

    if (ctx->error) {
        context_recover(ctx);
        sockconnect_deinit(ctx, &req->conn);
        socket_deinit(ctx, &req->sock);
        req->has_sock = false;
        req->state = HTTPGET_OPEN;
        return false;
    }

    sockstarttls_init(ctx, &req->starttls, &req->sock, req->tls,
                     TLSMETHOD_CLIENT);

    log_debug(ctx, "connect finished");
    log_debug(ctx, "starttls started");
    req->state = HTTPGET_STARTTLS;
    return false;
}


static bool httpget_starttls_blocked(Context *ctx, HttpGet *req)
{
    if (ctx->error)
        return false;

    if (task_blocked(ctx, &req->starttls.task)) {
        req->task.block = req->starttls.task.block;
        return true;
    }

    if (ctx->error) {
        context_panic(ctx, ctx->error, "failed starting TLS session: %s",
                      ctx->message);
        return false;
    }

    // send request
    const char *format = "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n";
    size_t buffer_len =
        (size_t)snprintf(NULL, 0, format, req->target, req->host) + 1;

    req->buffer = memory_alloc(ctx, buffer_len);
    if (ctx->error)
        return false;

    req->buffer_len = buffer_len;
    snprintf(req->buffer, req->buffer_len, format, req->target, req->host);
    log_debug(ctx, "sending message: |\n%s", req->buffer);
    socksend_init(ctx, &req->send, &req->sock, req->buffer,
               (int)strlen(req->buffer));

    log_debug(ctx, "starttls finished");
    log_debug(ctx, "send started");
    req->state = HTTPGET_SEND;
    return false;
}


static bool httpget_send_blocked(Context *ctx, HttpGet *req)
{
    log_debug(ctx, "waiting on send");

    if (ctx->error)
        return false;

    if (task_blocked(ctx, &req->send.task)) {
        req->task.block = req->send.task.block;
        return true;
    }

    httprecv_init(ctx, &req->recv, &req->sock);

    log_debug(ctx, "send finished");
    log_debug(ctx, "recv started");
    req->state = HTTPGET_RECV;
    return false;
}


static bool httpget_recv_blocked(Context *ctx, HttpGet *req)
{
    log_debug(ctx, "waiting on recv");

    if (ctx->error)
        return false;

    if (task_blocked(ctx, &req->recv.task)) {
        req->task.block = req->recv.task.block;
        return true;
    }

    log_debug(ctx, "recv finished");
    req->state = HTTPGET_FINISH;
    return false;
}



bool httpget_blocked(Context *ctx, Task *task)
{
    HttpGet *req = (HttpGet *)task;

    while (true) {
        if (ctx->error)
            return false;

        bool (*action)(Context *, HttpGet *);

        switch (req->state) {
        case HTTPGET_START:
            action = httpget_start;
            break;

        case HTTPGET_GETADDR:
            action = httpget_getaddr_blocked;
            break;

        case HTTPGET_OPEN:
            action = httpget_open_blocked;
            break;

        case HTTPGET_CONNECT:
            action = httpget_connect_blocked;
            break;

        case HTTPGET_STARTTLS:
            action = httpget_starttls_blocked;
            break;

        case HTTPGET_SEND:
            action = httpget_send_blocked;
            break;

        case HTTPGET_RECV:
            action = httpget_recv_blocked;
            break;

        case HTTPGET_FINISH:
            return false;
        }

        if (action(ctx, req))
            return true;
    }
}


void httpget_init(Context *ctx, HttpGet *req, const char *host,
                  const char *target, TlsContext *tls)
{
    memset(req, 0, sizeof(*req));
    if (ctx->error)
        return;

    req->state = HTTPGET_START;
    req->host = host;
    req->target = target;
    req->task.block.type = BLOCK_NONE;
    req->task._blocked = httpget_blocked;
    req->tls = tls;
}


void httpget_deinit(Context *ctx, HttpGet *req)
{
    switch (req->state) {
    case HTTPGET_FINISH:
    case HTTPGET_RECV:
        httprecv_deinit(ctx, &req->recv);
        /* fall through */

    case HTTPGET_SEND:
        socksend_deinit(ctx, &req->send);
        /* fall through */

    case HTTPGET_STARTTLS:
        sockstarttls_deinit(ctx, &req->starttls);
        /* fall through */

    case HTTPGET_CONNECT:
        sockconnect_deinit(ctx, &req->conn);
        /* fall through */

    case HTTPGET_OPEN:
        if (req->has_sock)
            socket_deinit(ctx, &req->sock);
        /* fall through */

    case HTTPGET_GETADDR:
        getaddrinfo_deinit(ctx, &req->getaddr);
        /* fall through */

    case HTTPGET_START:
        break;
    }

    free(req->buffer);
}


int main(int argc, const char **argv)
{
    (void)argc;
    (void)argv;
    int status = EXIT_SUCCESS;

    // int64_t start = clock_usec(CLOCK_MONOTONIC_RAW);
    // int64_t deadline = start + 15 * 1000 * 1000; // 15s
    Context ctx;
    context_init(&ctx, NULL, NULL, NULL, NULL);

    TlsContext tls;
    tlscontext_init(&ctx, &tls, TLSPROTO_TLS, TLSMETHOD_CLIENT);

    HttpGet req;
    //httpget_init(&ctx, &req, "www.unicode.org",
    //             "/Public/12.0.0/ucd/UnicodeData.txt");
    httpget_init(&ctx, &req, "www.openssl.org", "/index.html", &tls);

    task_await(&ctx, &req.task);
    if (ctx.error)
        goto exit;

    log_debug(&ctx, "start: `%s`", req.recv.start);
    size_t i, n = req.recv.header_count;
    for (i = 0; i < n; i++) {
        log_debug(&ctx, "header: `%s`: `%s`",
                  req.recv.headers[i].key, req.recv.headers[i].value);
    }

    log_debug(&ctx, "content-length: %zu", req.recv.content_length);

    while (httprecv_advance(&ctx, &req.recv)) {
        task_await(&ctx, &req.recv.current.task);
        log_debug(&ctx, "read %d bytes", (int)req.recv.current.data_len);
        printf("----------------------------------------\n");
        printf("%.*s", (int)req.recv.current.data_len,
               (char *)req.recv.current.data);
        printf("\n----------------------------------------\n");
    }

    // TODO: shutdown

exit:
    if (ctx.error) {
        fprintf(stderr, "error: %s\n", ctx.message);
        status = EXIT_FAILURE;
    }

    httpget_deinit(&ctx, &req);
    tlscontext_deinit(&ctx, &tls);
    context_deinit(&ctx);

    return status;
}
