#include <assert.h>
#include <errno.h>
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


// https://people.eecs.berkeley.edu/~sangjin/2012/12/21/epoll-vs-kqueue.html


typedef enum {
    ERROR_NONE = 0,
    ERROR_MEMORY,
    ERROR_OS,
    ERROR_TIMEOUT,
} Error;


int error_code(int errnum)
{
    switch (errnum) {
    case 0:
        return 0;
    case ENOMEM:
        return ERROR_MEMORY;
    default:
        return ERROR_OS;
    }
}


int64_t clock_usec(clockid_t clock_id)
{
    struct timespec tp;
    clock_gettime(clock_id, &tp);
    return (int64_t)tp.tv_sec * 1000 * 1000 + tp.tv_nsec / 1000;
}


#define CONTEXT_BUFFER_MAX 1024

typedef struct {
    Error err;

    char _buffer0[CONTEXT_BUFFER_MAX];
    char _buffer1[CONTEXT_BUFFER_MAX];
    int _active;
} Context;

void context_init(Context *ctx)
{
    ctx->err = ERROR_NONE;
    ctx->_buffer1[0] = '\0';
    ctx->_active = 0;
}

void context_deinit(Context *ctx)
{
    (void)ctx;
}

const char *context_message(Context *ctx)
{
    return (ctx->_active) ? ctx->_buffer1 : ctx->_buffer0;
}

void context_recover(Context *ctx)
{
    ctx->err = 0;
    ctx->_buffer0[0] = '\0';
    ctx->_buffer1[0] = '\0';
}

Error context_panic(Context *ctx, Error err, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    char *buffer = (ctx->_active) ? ctx->_buffer0 : ctx->_buffer1;
    vsnprintf(buffer, sizeof(ctx->_buffer0), format, args);
    va_end(args);
    ctx->_active = ctx->_active ? 0 : 1;
    ctx->err = err;
    return err;
}


Error context_code(Context *ctx, int errnum)
{
    int err = error_code(errnum);

    if (err) {
        context_panic(ctx, err, strerror(errnum));
    } else {
        context_recover(ctx);
    }

    return err;
}


typedef enum {
    IO_READ = 1 << 0,
    IO_WRITE = 1 << 1
} IOFlag;

typedef struct {
    int fd;
    IOFlag flags;
} BlockIO;

typedef struct {
    int millis;
} BlockTimer;

typedef enum {
    BLOCK_NONE = 0,
    BLOCK_IO,
    BLOCK_TIMER
} BlockType;

typedef struct {
    union {
        BlockIO io;
        BlockTimer timer;
    } job;
    BlockType type;
} Block;

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


typedef struct Task {
    Block block;
    bool (*_blocked)(Context *ctx, struct Task *task, Error *perr);
} Task;


bool task_blocked(Context *ctx, Task *task, Error *perr)
{
    if (*perr)
        return false;

    return (task->_blocked)(ctx, task, perr);
}


static void await_io(Context *ctx, BlockIO *block, Error *perr)
{
    if (*perr)
        return;

    struct pollfd fds[1];
    fds[0].fd = block->fd;
    fds[0].events = 0;

    printf("calling poll...\n");

    if (block->flags & IO_READ) {
        fds[0].events |= POLLIN;
    }
    if (block->flags & IO_WRITE) {
        fds[0].events |= POLLOUT;
    }
    fds[0].revents = 0;

    assert(!errno);
    if (poll(fds, 1, -1) < 0) {
        printf("failure :(\n");
        *perr = context_code(ctx, errno);
        errno = 0;
    }

    assert(!errno);
    printf("success!\n");
}


static void await_timer(Context *ctx, BlockTimer *block, Error *perr)
{
    if (*perr)
        return;

    assert(!errno);
    if (poll(NULL, 0, block->millis) < 0) {
        int status = errno;
        errno = 0;
        *perr = context_code(ctx, status);
    }
}


bool task_advance(Context *ctx, Task *task, Error *perr)
{
    if (*perr)
        return false;

    if (!task_blocked(ctx, task, perr)) {
        return false;
    }

    printf("blocked. waiting...\n");
    switch (task->block.type) {
    case BLOCK_NONE:
        break;
    case BLOCK_IO:
        await_io(ctx, &task->block.job.io, perr);
        break;
    case BLOCK_TIMER:
        await_timer(ctx, &task->block.job.timer, perr);
        break;
    }

    return true;
}


void task_await(Context *ctx, Task *task, Error *perr)
{
    if (*perr)
        return;

    while (task_advance(ctx, task, perr)) {
        // pass
    }
}


typedef struct {
    Task task;
    const char *node;
    const char *service;
    const struct addrinfo *hints;
    struct addrinfo *result;
    int err;
} GetAddrInfo;


bool getaddrinfo_blocked(Context *ctx, Task *task, Error *perr)
{
    assert(!errno);

    if (*perr)
        return false;

    GetAddrInfo *req = (GetAddrInfo *)task;
    int err = getaddrinfo(req->node, req->service, req->hints, &req->result);

    if (err) {
        *perr = context_panic(ctx, ERROR_OS, gai_strerror(err));
    }
    errno = 0; // getaddrinfo sets it

    assert(!errno);
    return false;
}


void getaddrinfo_init(Context *ctx, GetAddrInfo *req, const char *node,
                      const char *service, const struct addrinfo *hints)
{
    (void)ctx;
    memset(req, 0, sizeof(*req));
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


typedef struct {
    Task task;
    int sockfd;
    const struct sockaddr *address;
    socklen_t address_len;
    bool started;
} SockConnect;


bool sockconnect_blocked(Context *ctx, Task *task, Error *perr)
{
    assert(!errno);

    if (*perr)
        return false;

    SockConnect *req = (SockConnect *)task;

    printf("calling connect\n");
    if (connect(req->sockfd, req->address, req->address_len) < 0) {
        int status = errno;
        errno = 0;

        if (!req->started && status == EINPROGRESS) {
            req->task.block.type = BLOCK_IO;
            req->task.block.job.io.fd = req->sockfd;
            req->task.block.job.io.flags = IO_WRITE;
            req->started = true;
            return true;
        } else if (req->started && status == EALREADY) {
            return true;
        } else if (req->started && status == EISCONN) {
            // pass
        } else {
            *perr = context_code(ctx, status);
        }
    }

    req->task.block.type = BLOCK_NONE;
    assert(!errno);
    return false;
}


void sockconnect_init(Context *ctx, SockConnect *req, int sockfd,
                      const struct sockaddr *address, socklen_t address_len)
{
    (void)ctx;
    memset(req, 0, sizeof(*req));
    req->task._blocked = sockconnect_blocked;
    req->sockfd = sockfd;
    req->address = address;
    req->address_len = address_len;
    req->started = false;
}

void sockconnect_deinit(Context *ctx, SockConnect *conn)
{
    (void)ctx;
    (void)conn;
}

typedef struct {
    Task task;
    int sockfd;
    const void *buffer;
    size_t length;
    int flags;
    size_t nsend;
} SockSend;


bool socksend_blocked(Context *ctx, Task *task, Error *perr)
{
    if (*perr)
        return false;

    SockSend *req = (SockSend *)task;
    const void *buffer = (const char *)req->buffer + req->nsend;
    size_t length = req->length - req->nsend;

    if (length == 0) {
        return false;
    }

    ssize_t nsend = send(req->sockfd, buffer, length, req->flags);

    if (nsend < 0) {
        int status = errno;
        errno = 0;
        if (status == EAGAIN || status == EWOULDBLOCK) {
            req->task.block.type = BLOCK_IO;
            req->task.block.job.io.fd = req->sockfd;
            req->task.block.job.io.flags = IO_WRITE;
            return true;
        } else {
            *perr = context_code(ctx, status);
        }
    } else {
        req->nsend += (size_t)nsend;
        if (req->nsend < req->length) {
            return true;
        }
    }

    req->task.block.type = BLOCK_NONE;
    return false;
}


void socksend_init(Context *ctx, SockSend *req, int sockfd,
                   const void *buffer, size_t length, int flags)
{
    (void)ctx;
    memset(req, 0, sizeof(*req));
    req->task._blocked = socksend_blocked;
    req->sockfd = sockfd;
    req->buffer = buffer;
    req->length = length;
    req->flags = flags;
    req->nsend = 0;
}

void socksend_deinit(Context *ctx, SockSend *req)
{
    (void)ctx;
    (void)req;
}

typedef struct {
    Task task;
    int sockfd;
    void *buffer;
    size_t length;
    int flags;
    size_t nrecv;
} SockRecv;


bool sockrecv_blocked(Context *ctx, Task *task, Error *perr)
{
    if (*perr)
        return false;

    SockRecv *req = (SockRecv *)task;
    void *buffer = (char *)req->buffer + req->nrecv;
    size_t length = req->length - req->nrecv;

    if (length == 0) {
        return false;
    }

    ssize_t nrecv = recv(req->sockfd, buffer, length, req->flags);

    if (nrecv < 0) {
        int status = errno;
        errno = 0;
        if (status == EAGAIN || status == EWOULDBLOCK) {
            req->task.block.type = BLOCK_IO;
            req->task.block.job.io.fd = req->sockfd;
            req->task.block.job.io.flags = IO_READ;
            return true;
        } else {
            *perr = context_code(ctx, status);
        }
    } else {
        req->nrecv += (size_t)nrecv;
        if (req->nrecv > 0 && req->nrecv < req->length) {
            return true;
        }
    }

    req->task.block.type = BLOCK_NONE;
    return false;
}


void sockrecv_init(Context *ctx, SockRecv *req, int sockfd,
                   void *buffer, size_t length, int flags)
{
    (void)ctx;
    memset(req, 0, sizeof(*req));
    req->task._blocked = sockrecv_blocked;
    req->sockfd = sockfd;
    req->buffer = buffer;
    req->length = length;
    req->flags = flags;
    req->nrecv = 0;
}


void sockrecv_deinit(Context *ctx, SockRecv *req)
{
    (void)ctx;
    (void)req;
}


void sockrecv_reset(Context *ctx, SockRecv *req, void *buffer, size_t length,
                    int flags)
{
    (void)ctx;
    req->buffer = buffer;
    req->length = length;
    req->flags = flags;
    req->nrecv = 0;
}


typedef struct {
    Task task;
    int sockfd;
    int how;
} SockShutdown;


bool sockshutdown_blocked(Context *ctx, Task *task, Error *perr)
{
    if (*perr)
        return false;

    SockShutdown *req = (SockShutdown *)task;
    assert(!errno);
    if (shutdown(req->sockfd, req->how) < 0) {
        int status = errno;
        errno = 0;
        if (status != ENOTCONN) { // peer closed the connection
            *perr = context_code(ctx, status);
        }
    }
    assert(!errno);
    return false;
}


void sockshutdown_init(Context *ctx, SockShutdown *req, int sockfd, int how)
{
    (void)ctx;
    memset(req, 0, sizeof(*req));
    req->task._blocked = sockshutdown_blocked;
    req->sockfd = sockfd;
    req->how = how;
}


void sockshutdown_deinit(Context *ctx, SockShutdown *req)
{
    (void)ctx;
    (void)req;
}


typedef enum {
    HTTPGET_INIT = 0,
    HTTPGET_GETADDR,
    HTTPGET_OPEN,
    HTTPGET_CONNECT,
    HTTPGET_SEND,
    HTTPGET_RECV,
    HTTPGET_SHUTDOWN,
    HTTPGET_EXIT
} HttpGetState;


typedef struct {
    Task task;
    HttpGetState state;
    const char *host;
    const char *resource;

    GetAddrInfo getaddr;
    const struct addrinfo *addrinfo;
    int sockfd;
    SockConnect conn;
    SockSend send;
    SockRecv recv;
    SockShutdown shutdown;

    char buffer[4096];
    const char *content;
    struct {
        const char *key;
        const char *value;
    } header;
} HttpGet;


bool httpget_blocked(Context *ctx, Task *task, Error *perr)
{
    if (*perr)
        return false;

    HttpGet *req = (HttpGet *)task;

    switch (req->state) {
    case HTTPGET_INIT:
        goto init;
    case HTTPGET_GETADDR:
        goto getaddr;
    case HTTPGET_OPEN:
        goto open;
    case HTTPGET_CONNECT:
        goto connect;
    case HTTPGET_SEND:
        goto send;
    case HTTPGET_RECV:
        goto recv;
    case HTTPGET_SHUTDOWN:
        goto shutdown;
    case HTTPGET_EXIT:
        goto exit;
    }

init:
    {
        struct addrinfo hints = {0};
        hints.ai_flags = PF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        getaddrinfo_init(ctx, &req->getaddr, req->host, "http", &hints);
        req->state = HTTPGET_GETADDR;
    }

getaddr:
    printf("getaddr started\n");

    if (task_blocked(ctx, &req->getaddr.task, perr)) {
        task->block = req->getaddr.task.block;
        return true;
    }

    if (*perr) {
        context_panic(ctx, *perr,
            "failed getting host address information: %s",
            context_message(ctx));
        return false;
    }

    req->addrinfo = req->getaddr.result;
    req->state = HTTPGET_OPEN;

    printf("getaddr finished\n");
open:
    assert(!errno);
    printf("open started\n");
    assert(req->addrinfo);
    req->sockfd = -1;

    while (req->sockfd < 0 && req->addrinfo) {
        const struct addrinfo *ai = req->addrinfo;

        assert(!errno);
        req->sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (req->sockfd >= 0) {
            break;
        }

        req->addrinfo = req->addrinfo->ai_next;
    }

    if (req->sockfd < 0) {
        int status = errno;
        errno = 0;
        *perr = context_panic(ctx, error_code(status),
            "failed opening socket: %s", strerror(status));
    }
    assert(!errno);

    int flags = fcntl(req->sockfd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(req->sockfd, F_SETFL, flags | O_NONBLOCK); // ignore error
        errno = 0;
    }
    assert(!errno);

    sockconnect_init(ctx, &req->conn, req->sockfd, req->addrinfo->ai_addr,
                     req->addrinfo->ai_addrlen);
    req->state = HTTPGET_CONNECT;

    printf("open finished\n");
connect:
    printf("connect started\n");

    if (task_blocked(ctx, &req->conn.task, perr)) {
        task->block = req->conn.task.block;
        return true;
    }

    if (*perr) {
        req->addrinfo = req->addrinfo->ai_next;
        if (req->addrinfo) {
            sockconnect_deinit(ctx, &req->conn);
            close(req->sockfd);
            req->state = HTTPGET_OPEN;
            goto open;
        }

        context_panic(ctx, *perr,
            "failed connecting to host: %s",
            context_message(ctx));
        return false;
    }

    sprintf(req->buffer, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n",
            req->resource, req->host);

    socksend_init(ctx, &req->send, req->sockfd, req->buffer,
                  strlen(req->buffer), 0);
    req->state = HTTPGET_SEND;

    printf("connect finished\n");
send:
    printf("send started\n");

    if (task_blocked(ctx, &req->send.task, perr)) {
        task->block = req->send.task.block;
        return true;
    }

    if (*perr) {
        context_panic(ctx, *perr,
            "failed sending to host: %s",
            context_message(ctx));
        return false;
    }

    sockrecv_init(ctx, &req->recv, req->sockfd, req->buffer,
                  sizeof(req->buffer), 0);
    req->state = HTTPGET_RECV;

    printf("send finished\n");
recv:
    printf("recv started\n");

    if (task_blocked(ctx, &req->recv.task, perr)) {
        task->block = req->recv.task.block;
        if (req->recv.nrecv > 0) {
            printf("read %d bytes:\n", (int)req->recv.nrecv);
            printf("----------------------------------------\n");
            printf("%.*s", (int)req->recv.nrecv, (char *)req->buffer);
            printf("\n----------------------------------------\n");

            sockrecv_reset(ctx, &req->recv,
                           req->buffer, sizeof(req->buffer), 0);
        }
        return true;
    }

    if (*perr) {
        context_panic(ctx, *perr,
            "failed receiving from host: %s",
            context_message(ctx));
        return false;
    }

    if (req->recv.nrecv > 0) {
        printf("read %d bytes:\n", (int)req->recv.nrecv);
        printf("----------------------------------------\n");
        printf("%.*s", (int)req->recv.nrecv, (char *)req->buffer);
        printf("\n----------------------------------------\n");
        sockrecv_reset(ctx, &req->recv, req->buffer, sizeof(req->buffer), 0);
        goto recv;
    }

    sockshutdown_init(ctx, &req->shutdown, req->sockfd, SHUT_RDWR);
    req->state = HTTPGET_SHUTDOWN;

    printf("recv finished\n");
shutdown:
    printf("shutdown started\n");
    if (task_blocked(ctx, &req->shutdown.task, perr)) {
        task->block = req->shutdown.task.block;
        return true;
    }

    if (*perr) {
        context_panic(ctx, *perr,
            "failed shutting down connection to host: %s",
            context_message(ctx));
        return false;
    }

    printf("shutdown finished\n");
    req->state = HTTPGET_EXIT;
    task->block.type = BLOCK_NONE;

exit:
    return false;
}


void httpget_init(Context *ctx, HttpGet *req, const char *host,
                  const char *resource)
{
    (void)ctx;

    req->state = HTTPGET_INIT;
    req->host = host;
    req->resource = resource;
    req->task.block.type = BLOCK_NONE;
    req->task._blocked = httpget_blocked;
}


void httpget_deinit(Context *ctx, HttpGet *req)
{
    switch (req->state) {
    case HTTPGET_EXIT:
    case HTTPGET_SHUTDOWN:
        sockshutdown_deinit(ctx, &req->shutdown);

    case HTTPGET_RECV:
        sockrecv_deinit(ctx, &req->recv);

    case HTTPGET_SEND:
        socksend_deinit(ctx, &req->send);

    case HTTPGET_CONNECT:
        sockconnect_deinit(ctx, &req->conn);

    case HTTPGET_OPEN:
        if (req->sockfd >= 0)
            close(req->sockfd);

    case HTTPGET_GETADDR:
        getaddrinfo_deinit(ctx, &req->getaddr);

    case HTTPGET_INIT:
        break;
    }
}


bool httpget_header(Context *ctx, HttpGet *req, Error *perr)
{
    if (*perr)
        return false;
    (void)ctx;
    (void)req;
    return false;
}


bool httpget_content(Context *ctx, HttpGet *req, Error *perr)
{
    if (*perr)
        return false;
    (void)ctx;
    (void)req;
    return false;
}


int main(int argc, const char **argv)
{
    (void)argc;
    (void)argv;

    // int64_t start = clock_usec(CLOCK_MONOTONIC_RAW);
    // int64_t deadline = start + 15 * 1000 * 1000; // 15s
    Error err = 0;

    Context ctx;
    context_init(&ctx);

    HttpGet req;
    httpget_init(&ctx, &req, "www.unicode.org",
                 "/Public/12.0.0/ucd/UnicodeData.txt");

    while (!err && !req.content) {
        while (httpget_header(&ctx, &req, &err)) {
            printf("%s: %s\n", req.header.key, req.header.value);
        }

        task_advance(&ctx, &req.task, &err);
    }

    while (!err && req.content) {
        while (httpget_content(&ctx, &req, &err)) {
            printf("%s", req.content);
        }
        task_advance(&ctx, &req.task, &err);
    }

    if (err) {
        fprintf(stderr, "error: %s", context_message(&ctx));
    }

    httpget_deinit(&ctx, &req);
    context_deinit(&ctx);

    return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
