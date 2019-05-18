#include <assert.h>
#include <ctype.h>
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

#define BUFFER_MIN 4096

typedef enum {
    ERROR_NONE = 0,
    ERROR_MEMORY,
    ERROR_VALUE,
    ERROR_OVERFLOW,
    ERROR_OS,
    ERROR_TIMEOUT,
} Error;


int error_code(int errnum)
{
    switch (errnum) {
    case 0:
        return 0;
    case EINVAL:
        return ERROR_VALUE;
    case ENOMEM:
        return ERROR_MEMORY;
    case EOVERFLOW:
        return ERROR_OVERFLOW;
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
    char _buffer0[CONTEXT_BUFFER_MAX];
    char _buffer1[CONTEXT_BUFFER_MAX];
    int _active;
} Context;

void context_clear(Context *ctx)
{
    ctx->_buffer0[0] = '\0';
    ctx->_buffer1[0] = '\0';
    ctx->_active = 0;
}

void context_init(Context *ctx)
{
    context_clear(ctx);
}

void context_deinit(Context *ctx)
{
    (void)ctx;
}

const char *context_message(Context *ctx)
{
    return (ctx->_active) ? ctx->_buffer1 : ctx->_buffer0;
}


Error context_panic(Context *ctx, Error err, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    char *buffer = (ctx->_active) ? ctx->_buffer0 : ctx->_buffer1;
    vsnprintf(buffer, sizeof(ctx->_buffer0), format, args);
    va_end(args);
    ctx->_active = ctx->_active ? 0 : 1;
    return err;
}


Error context_code(Context *ctx, int errnum)
{
    int err = error_code(errnum);

    if (err) {
        context_panic(ctx, err, strerror(errnum));
    } else {
        context_clear(ctx);
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

    if (block->flags & IO_READ) {
        fds[0].events |= POLLIN;
    }
    if (block->flags & IO_WRITE) {
        fds[0].events |= POLLOUT;
    }
    fds[0].revents = 0;

    assert(!errno);
    if (poll(fds, 1, -1) < 0) {
        *perr = context_code(ctx, errno);
        errno = 0;
    }

    assert(!errno);
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

    if (req->length == 0) {
        return false;
    }

    ssize_t nrecv = recv(req->sockfd, req->buffer, req->length, req->flags);

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
    } else if (nrecv == 0) {
        *perr = context_panic(ctx, ERROR_OS, "connection reset by peer");
    } else {
        req->nrecv = (size_t)nrecv;
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
    HTTPGET_META,
    HTTPGET_BODY,
    HTTPGET_SHUTDOWN,
    HTTPGET_EXIT
} HttpGetState;


typedef struct {
    const char *key;
    const char *value;
} HttpHeader;


typedef struct {
    Task task;
    HttpGetState state;
    const char *host;
    const char *target;

    GetAddrInfo getaddr;
    const struct addrinfo *addrinfo;
    int sockfd;
    SockConnect conn;
    SockSend send;
    SockRecv recv;
    SockShutdown shutdown;

    const char *status;
    size_t status_len;

    HttpHeader *headers;
    size_t header_count;
    size_t header_capacity;

    void *buffer;
    uint8_t *data;

    size_t buffer_len;
    size_t data_len;
    size_t data_max;
} HttpGet;


static void httpget_grow_buffer(Context *ctx, HttpGet *req, Error *perr)
{
    if (*perr)
        return;

    size_t old_buffer_len = req->buffer_len;
    char *old_buffer = req->buffer;
    size_t new_buffer_len = old_buffer_len * 2; // overflow?
    char *new_buffer = realloc(old_buffer, new_buffer_len);

    if (!new_buffer) {
        errno = 0;
        *perr = context_panic(ctx, ERROR_MEMORY,
            "failed allocating %zu bytes", new_buffer_len);
        return;
    }

    req->buffer = new_buffer;
    req->buffer_len = new_buffer_len;
    req->data = (uint8_t *)new_buffer + (req->data - (uint8_t *)old_buffer);
    req->data_max += new_buffer_len - old_buffer_len;

    if (req->status) {
        req->status = new_buffer + (req->status - old_buffer);
    }

    size_t i, n = req->header_count;
    for (i = 0; i < n; i++) {
        HttpHeader *header = &req->headers[i];
        header->key = new_buffer + (header->key - old_buffer);
        header->value = new_buffer + (header->value - old_buffer);
    }
}


static void httpget_grow_headers(Context *ctx, HttpGet *req, Error *perr)
{
    if (*perr)
        return;

    size_t old_max = req->header_capacity;
    size_t new_max = old_max * 2;
    if (new_max == 0) {
        new_max = 32;
    }
    HttpHeader *old_headers = req->headers;
    size_t size = new_max * sizeof(*old_headers);
    HttpHeader *new_headers = realloc(old_headers, size);

    if (!new_headers) {
        errno = 0;
        *perr = context_panic(ctx, ERROR_MEMORY,
            "failed allocating %zu bytes", size);
        return;
    }

    req->headers = new_headers;
    req->header_capacity = new_max;
}


static void assert_ascii(Context *ctx, const uint8_t *str, size_t str_len,
                         Error *perr)
{
    if (*perr)
        return;

    uint8_t ch;
    const uint8_t *ptr = str;
    const uint8_t *end = str + str_len;

    for (ptr = str; ptr < end; ptr++) {
        ch = *ptr;
        if (ch == 0 || ch > 0x7F) {
            *perr = context_panic(ctx, ERROR_VALUE,
                "invalid ASCII code byte 0x%02x in position %zu:"
                " value not between 0x01 and 0x7f",
                (unsigned)ch, (size_t)(ptr - str));
            break;
        }
    }
}


static void httpget_set_status(Context *ctx, HttpGet *req, uint8_t *line,
                               size_t line_len, Error *perr)
{
    if (*perr)
        return;

    assert_ascii(ctx, line, line_len, perr);
    if (*perr) {
        context_panic(ctx, *perr, "invalid HTTP status line: %s",
                      context_message(ctx));
        return;
    }
    req->status = (char *)line;
}


static void httpget_add_header(Context *ctx, HttpGet *req, uint8_t *line,
                               size_t line_len, Error *perr)
{
    if (*perr)
        return;

    if (req->header_count == req->header_capacity) {
        httpget_grow_headers(ctx, req, perr);
        if (*perr)
            return;
    }

    size_t i = req->header_count;

    assert_ascii(ctx, line, line_len, perr);
    if (*perr) {
        context_panic(ctx, *perr,
            "invalid HTTP header line in position %zu: %s",
            i + 1,
            context_message(ctx));
        return;
    }

    char *key = (char *)line;
    char *colon = strstr(key, ":");
    if (!colon) {
        *perr = context_panic(ctx, ERROR_VALUE,
            "invalid HTTP header line in position %zu: %s",
            i + 1,
            "missing colon (:)");
    }
    *colon = '\0';
    char *value = colon + 1;
    char *end = (char *)line + line_len;

    while (value < end && isspace(*value)) {
        value++;
    }

    while (value < end && isspace(end[-1])) {
        end--;
    }

    *end = '\0';
    req->headers[i].key = key;
    req->headers[i].value = value;
    req->header_count = i + 1;
}


bool httpget_blocked(Context *ctx, Task *task, Error *perr)
{
    struct addrinfo hints;

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
    case HTTPGET_META:
        goto meta;
    case HTTPGET_BODY:
        goto body;
    case HTTPGET_SHUTDOWN:
        goto shutdown;
    case HTTPGET_EXIT:
        goto exit;
    }

init:
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    getaddrinfo_init(ctx, &req->getaddr, req->host, "http", &hints);

    printf("getaddr started\n");
    req->state = HTTPGET_GETADDR;
getaddr:
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

    printf("getaddr finished\n");
    printf("open started\n");
    req->state = HTTPGET_OPEN;
open:
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

    printf("open finished\n");
    printf("connect started\n");
    req->state = HTTPGET_CONNECT;
connect:

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

    // send request
    const char *format = "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n";
    {
        size_t buffer_len =
            (size_t)snprintf(NULL, 0, format, req->target, req->host) + 1;
        if (buffer_len < BUFFER_MIN)
            buffer_len = BUFFER_MIN;

        req->buffer = malloc(buffer_len);
        if (!req->buffer) {
            *perr = context_panic(ctx, ERROR_MEMORY,
                "failed allocating %d bytes", buffer_len);
            return false;
        }
        req->buffer_len = buffer_len;
    }

    snprintf(req->buffer, req->buffer_len, format, req->target, req->host);
    socksend_init(ctx, &req->send, req->sockfd, req->buffer,
                  strlen(req->buffer), 0);

    printf("connect finished\n");
    printf("send started\n");
    req->state = HTTPGET_SEND;
send:

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

    req->data = req->buffer;
    req->data_len = 0;
    req->data_max = req->buffer_len;

    sockrecv_init(ctx, &req->recv, req->sockfd, req->data, req->data_max, 0);

    printf("send finished\n");
    printf("meta started\n");
    req->state = HTTPGET_META;

meta:
    if (task_blocked(ctx, &req->recv.task, perr)) {
        task->block = req->recv.task.block;
        return true;
    }

    if (*perr) {
        context_panic(ctx, *perr,
            "failed receiving status from host: %s",
            context_message(ctx));
        return false;
    }

    assert(req->recv.nrecv > 0);

    req->data_len += req->recv.nrecv;
    uint8_t *line_end;
    bool empty_line = false;

    while ((line_end = memmem(req->data, req->data_len, "\r\n", 2))) {
        *line_end = '\0';
        uint8_t *line = req->data;
        size_t line_len = line_end - line;
        size_t line_size = line_len + 2;

        req->data += line_size;
        req->data_len -= line_size;
        req->data_max -= line_size;

        if (line_len == 0) { // end of headers
            empty_line = true;
            break;
        } else if (!req->status) { // status
            httpget_set_status(ctx, req, line, line_len, perr);
            if (*perr)
                return false;
            printf("status: `%s`\n", req->status);
        } else {
            httpget_add_header(ctx, req, line, line_len, perr);
            if (*perr)
                return false;
            printf("header: `%s`: `%s`\n",
                   req->headers[req->header_count - 1].key,
                   req->headers[req->header_count - 1].value);
        }
    }

    if (req->data_max - req->data_len < BUFFER_MIN) {
        printf("growing buffer\n");
        httpget_grow_buffer(ctx, req, perr);
        if (*perr)
            return false;
    }

    sockrecv_reset(ctx, &req->recv, req->data + req->data_len,
                   req->data_max - req->data_len, 0);

    if (!empty_line)
        goto meta;

    printf("meta finished\n");
    printf("body started\n");
    req->state = HTTPGET_BODY;
body:
    exit(0);
    printf("body finished\n");

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
        goto body;
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
                  const char *target)
{
    (void)ctx;

    req->state = HTTPGET_INIT;
    req->host = host;
    req->target = target;
    req->task.block.type = BLOCK_NONE;
    req->task._blocked = httpget_blocked;
}


void httpget_deinit(Context *ctx, HttpGet *req)
{
    switch (req->state) {
    case HTTPGET_EXIT:
    case HTTPGET_SHUTDOWN:
        sockshutdown_deinit(ctx, &req->shutdown);

    case HTTPGET_BODY:
    case HTTPGET_META:
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

    free(req->buffer);
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

    task_await(&ctx, &req.task, &err);
    if (err)
        goto exit;

    printf("Status: `%s`\n", req.status);
    // headers

    /*
    while (httpget_advance(&ctx, &req, &err)) {
        task_await(&ctx, &req.current.task, &err);
        if (err)
            goto exit;
        // body
    }
    */

exit:
    if (err) {
        fprintf(stderr, "error: %s", context_message(&ctx));
    }

    httpget_deinit(&ctx, &req);
    context_deinit(&ctx);

    return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
