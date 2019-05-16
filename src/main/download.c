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
} TaskIO;

typedef struct {
    int timeout_millis;
} TaskTimer;

typedef enum {
    TASK_NONE = 0,
    TASK_IO,
    TASK_TIMER
} TaskType;

typedef struct {
    union {
        TaskIO io;
        TaskTimer timer;
    } job;
    TaskType type;
} TaskCurrent;

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
    TaskCurrent current;
    bool (*_advance)(Context *ctx, struct Task *task, Error *perr);
} Task;


bool task_advance(Context *ctx, Task *task, Error *perr)
{
    return (task->_advance)(ctx, task, perr);
}


void task_await_io(Context *ctx, TaskIO *task, Error *perr)
{
    struct pollfd fds[1];
    fds[0].fd = task->fd;
    fds[0].events = 0;

    if (task->flags & IO_READ) {
        fds[0].events |= POLLIN | POLLPRI;
    }
    if (task->flags & IO_WRITE) {
        fds[0].events |= POLLOUT | POLLWRBAND;
    }
    fds[0].revents = 0;

    if (poll(fds, 1, -1) < 0) {
        // TODO: message
        *perr = context_code(ctx, errno);
        errno = 0;
    }
}


void task_await_timer(Context *ctx, TaskTimer *task, Error *perr)
{
    if (poll(NULL, 0, task->timeout_millis) < 0) {
        *perr = context_code(ctx, errno);
        errno = 0;
    }
}


void task_await(Context *ctx, Task *task, Error *perr)
{
    while (task_advance(ctx, task, perr)) {
        switch (task->current.type) {
        case TASK_NONE:
            break;
        case TASK_IO:
            task_await_io(ctx, &task->current.job.io, perr);
            break;
        case TASK_TIMER:
            task_await_timer(ctx, &task->current.job.timer, perr);
            break;
        }
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


bool getaddrinfo_advance(Context *ctx, Task *task, Error *perr)
{
    GetAddrInfo *req = (GetAddrInfo *)task;
    int err = getaddrinfo(req->node, req->service, req->hints, &req->result);

    if (err) {
        err = context_panic(ctx, ERROR_OS, gai_strerror(err));
    }

    *perr = err;
    return false;
}


void getaddrinfo_init(Context *ctx, GetAddrInfo *req, const char *node,
                      const char *service, const struct addrinfo *hints)
{
    memset(req, 0, sizeof(*req));
    req->task._advance = getaddrinfo_advance;
    req->node = node;
    req->service = service;
    req->hints = hints;
}


void getaddrinfo_deinit(Context *ctx, GetAddrInfo *req)
{
    if (req->result) {
        freeaddrinfo(req->result);
    }
}


typedef struct {
    Task task;
} SockConnect;


bool sockconnect_advance(Context *ctx, Task *task, Error *perr)
{
    SockConnect *req = (SockConnect *)task;
    return false;
}


void sockconnect_init(Context *ctx, SockConnect *req, int sockfd,
                      const struct sockaddr *address, socklen_t address_len)
{
    memset(req, 0, sizeof(*req));
    req->task._advance = sockconnect_advance;
}

void sockconnect_deinit(Context *ctx, SockConnect *conn)
{
    (void)ctx;
    (void)conn;
}

typedef struct {
    Task task;
} SockSend;

void socksend_init(Context *ctx, SockSend *req, int sockfd,
                   const void *buffer, size_t length, int flags)
{
}

void socksend_deinit(Context *ctx, SockSend *req)
{
}

typedef enum {
    HTTPGET_INIT = 0,
    HTTPGET_GETADDR,
    HTTPGET_OPEN,
    HTTPGET_CONNECT,
    HTTPGET_SEND
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
} HttpGet;


bool httpget_advance(Context *ctx, Task *task, Error *perr)
{
    HttpGet *req = (HttpGet *)task;

    switch (req->state) {
    case HTTPGET_INIT:
        break;
    case HTTPGET_GETADDR:
        goto getaddr;
    case HTTPGET_OPEN:
        goto open;
    case HTTPGET_CONNECT:
        goto connect;
    case HTTPGET_SEND:
        goto send;
    }

    struct addrinfo hints = {0};
    hints.ai_flags = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    getaddrinfo_init(ctx, &req->getaddr, req->host, "http", &hints);
    req->state = HTTPGET_GETADDR;

getaddr:
    if (task_advance(ctx, &req->getaddr.task, perr)) {
        task->current = req->getaddr.task.current;
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

open:
    assert(req->addrinfo);
    req->sockfd = -1;

    while (req->sockfd < 0 && req->addrinfo) {
        const struct addrinfo *ai = req->addrinfo;

        req->sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (req->sockfd >= 0)
            break;

        int flags = fcntl(req->sockfd, F_GETFL, 0);
        if (flags >= 0) {
            fcntl(req->sockfd, F_SETFL, flags | O_NONBLOCK); // ignore error
        }

        req->addrinfo = req->addrinfo->ai_next;
    }

    if (req->sockfd < 0) {
        *perr = context_panic(ctx, error_code(errno),
            "failed opening socket: %s", strerror(errno));
        errno = 0;
    }

    sockconnect_init(ctx, &req->conn, req->sockfd, req->addrinfo->ai_addr,
                     req->addrinfo->ai_addrlen);
    req->state = HTTPGET_CONNECT;

connect:
    if (task_advance(ctx, &req->conn.task, perr)) {
        task->current = req->conn.task.current;
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

    req->state = HTTPGET_SEND;

    socksend_init(ctx, &req->send, req->sockfd, NULL, 0, 0);
send:

    task->current.type = TASK_NONE;
    return false;
}


void httpget_init(Context *ctx, HttpGet *req, const char *host,
                  const char *resource)
{
    req->state = HTTPGET_INIT;
    req->host = host;
    req->resource = resource;
    req->task.current.type = TASK_NONE;
    req->task._advance = httpget_advance;
}

void httpget_deinit(Context *ctx, HttpGet *req)
{
    switch (req->state) {
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


int main(int argc, const char **argv)
{
    (void)argc;
    (void)argv;

    int64_t start = clock_usec(CLOCK_MONOTONIC_RAW);
    int64_t deadline = start + 15 * 1000 * 1000; // 15s
    Error err = 0;

    Context ctx;
    context_init(&ctx);

    HttpGet req;
    httpget_init(&ctx, &req, "www.unicode.org",
                 "/Public/12.0.0/ucd/UnicodeData.txt");
    task_await(&ctx, &req.task, &err);
    if (err) {
        fprintf(stderr, "error: %s", context_message(&ctx));
        return EXIT_FAILURE;
    }

    httpget_deinit(&ctx, &req);

    return err ? EXIT_FAILURE : EXIT_SUCCESS;

    /*

    Error err = ERROR_NONE;

    const char *host = ;
    const char *service = "http";
    Context ctx;
    Socket sock;
    bool has_sock = false;
    int32_t deadline = 60 * 1000;

    task_await(&ctx, &lookup.task, deadline, &err);
    if (err)
        goto hostlookup_fail;

    while (!has_sock && hostlookup_advance(&ctx, &lookup, &err)) {
        socket_init(&ctx, &sock, look.family, look.comm, lookup.proto, &err);
        if (err)
            continue;

        SocketConnect req;
        socket_connect(&ctx, &req, &sock, &look.addr);
        task_await(&ctx, &req.task, deadline, &err);

        if (err) {
            socket_deinit(&ctx, &sock);
            err = context_recover(&ctx);
        } else {
            has_sock = true;
        }
    }

    if (!has_sock) { // lookup failed or could not connect to an address
        goto connect_fail;
    }

    // http://www.unicode.org/Public/12.0.0/data/ucd/UnicodeData.txt
    const char *message = 
        "GET /Public/12.0.0/ucd/UnicodeData.txt HTTP/1.1\r\n"
        "Host: www.unicode.org\r\n"
        "\r\n";

    SocketWrite write;
    socket_write(&ctx, &write, &sock, message, strlen(message), 0);
    task_await(&ctx, &write.task, deadline, &err);
    if (err) {
        goto write_fail;
    }

    char response[4096];
    memset(response, 0, sizeof(response));
    int total = sizeof(response)-1;
    int received = 0;
    int bytes = 0;

    do {
        SocketRead read;
        socket_read(&ctx, &read, &sock, response, total, 0, &bytes);
        task_await(&ctx, &read.task, deadline, &err);
        if (err) {
            goto read_fail;
        }

        printf("%s", response);
        memset(response, 0, sizeof(response));
        printf("bytes = %d\n", bytes);
    } while (bytes > 0);

    SocketShutdown shutdown;
    socket_shutdown(&ctx, &shutdown, &sock);
    task_await(&ctx, &shutdown.task, deadline, &err);
    if (err) {
        goto shutdown_fail;
    }

shutdown_fail:
read_fail:
write_fail:
    socket_deinit(&sock);
connect_fail:
hostlookup_fail:
    hostlookup_deinit(&lookup);
    context_deinit(&ctx);
    return err;
    */
}
