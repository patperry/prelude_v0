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




/*
typedef struct {
    int (*_read) (Context *ctx, Stream *stream, void *buffer, int length);
    int (*_write) (Context *ctx, Stream *stream, void *buffer, int length);
} Stream;


typedef struct {
    Task task;
    void *buffer;
    int length;
    int nread;
} StreamRead;


void streamread_init(Context *ctx, StreamRead *read, Stream *stream,
                     void *buffer, int length)
{
}


typedef struct {
    Stream *base;
} SocketStream;
*/


typedef struct {
    Task task;
    const char *node;
    const char *service;
    const struct addrinfo *hints;
    struct addrinfo *result;
} GetAddrInfo;


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


bool sockconnect_blocked(Context *ctx, Task *task)
{
    if (ctx->error)
        return false;

    SockConnect *req = (SockConnect *)task;

    if (connect(req->sockfd, req->address, req->address_len) < 0) {
        int status = errno;

        if (!req->started) {
            if (status == EINPROGRESS) {
                req->task.block.type = BLOCK_IO;
                req->task.block.job.io.fd = req->sockfd;
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


bool socksend_blocked(Context *ctx, Task *task)
{
    if (ctx->error)
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
        if (status == EAGAIN || status == EWOULDBLOCK || status == EINTR) {
            req->task.block.type = BLOCK_IO;
            req->task.block.job.io.fd = req->sockfd;
            req->task.block.job.io.flags = IO_WRITE;
            return true;
        } else {
            assert(status);
            context_code(ctx, status);
            context_panic(ctx, ctx->error,
                          "failed sending data: %s", ctx->message);
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
    memset(req, 0, sizeof(*req));
    if (ctx->error)
        return;

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


bool sockrecv_blocked(Context *ctx, Task *task)
{
    if (ctx->error)
        return false;

    SockRecv *req = (SockRecv *)task;

    if (req->length == 0) {
        return false;
    }

    ssize_t nrecv = recv(req->sockfd, req->buffer, req->length, req->flags);

    if (nrecv < 0) {
        int status = errno;
        if (status == EAGAIN || status == EWOULDBLOCK || status == EINTR) {
            req->task.block.type = BLOCK_IO;
            req->task.block.job.io.fd = req->sockfd;
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
        req->nrecv = (size_t)nrecv;
    }

    req->task.block.type = BLOCK_NONE;
    return false;
}


void sockrecv_reinit(Context *ctx, SockRecv *req, int sockfd, void *buffer,
                     size_t length, int flags)
{
    if (ctx->error)
        return;

    req->sockfd = sockfd;
    req->buffer = buffer;
    req->length = length;
    req->flags = flags;
    req->nrecv = 0;
}


void sockrecv_init(Context *ctx, SockRecv *req, int sockfd,
                   void *buffer, size_t length, int flags)
{
    memset(req, 0, sizeof(*req));
    if (ctx->error)
        return;

    req->task._blocked = sockrecv_blocked;
    sockrecv_reinit(ctx, req, sockfd, buffer, length, flags);
}


void sockrecv_deinit(Context *ctx, SockRecv *req)
{
    (void)ctx;
    (void)req;
}


typedef struct {
    Task task;
    int sockfd;
    int how;
} SockShutdown;


bool sockshutdown_blocked(Context *ctx, Task *task)
{
    if (ctx->error)
        return false;

    SockShutdown *req = (SockShutdown *)task;
    if (shutdown(req->sockfd, req->how) < 0) {
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


void sockshutdown_init(Context *ctx, SockShutdown *req, int sockfd, int how)
{
    memset(req, 0, sizeof(*req));
    if (ctx->error)
        return;

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
    HTTPGET_START = 0,
    HTTPGET_GETADDR,
    HTTPGET_OPEN,
    HTTPGET_CONNECT,
    HTTPGET_SEND,
    HTTPGET_META,
    HTTPGET_FINISH
} HttpGetState;


typedef struct {
    const char *key;
    const char *value;
} HttpHeader;


typedef struct {
    Task task;
    uint8_t *data;
    size_t data_len;
} HttpBody;


typedef struct {
    Task task;
    HttpGetState state;
    const char *host;
    const char *target;
    struct addrinfo hints;

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

    size_t content_length;
    size_t content_read;
    bool content_started;

    HttpBody current;

    void *buffer;
    uint8_t *data;

    size_t buffer_len;
    size_t data_len;
    size_t data_max;

} HttpGet;


static void httpget_grow_buffer(Context *ctx, HttpGet *req, size_t add)
{
    if (ctx->error || add == 0)
        return;

    char *old_buffer = req->buffer;
    size_t old_buffer_len = req->buffer_len;
    size_t new_buffer_len;

    if (old_buffer_len / 2 > SIZE_MAX || old_buffer_len > SIZE_MAX - add) {
        context_panic(ctx, ERROR_OVERFLOW,
                      "buffer size exceeds maximum (%zu)", SIZE_MAX);
        return;
    }
   
    if (add > old_buffer_len) {
        new_buffer_len = old_buffer_len + add;
    } else {
        new_buffer_len = 2 * old_buffer_len;
    }

    if (new_buffer_len <= 32) {
        new_buffer_len = 32;
    }

    req->buffer = memory_realloc(ctx, req->buffer, req->buffer_len,
                                 new_buffer_len);
    if (ctx->error)
        return;

    char *new_buffer = req->buffer;
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


static void httpget_grow_headers(Context *ctx, HttpGet *req, size_t add)
{
    if (ctx->error || add == 0)
        return;

    size_t old_max = req->header_capacity;
    if (old_max / 2 > SIZE_MAX || old_max > SIZE_MAX - add) {
        context_panic(ctx, ERROR_OVERFLOW,
                      "header count exceeds maximum (%zu)", SIZE_MAX);
        return;
    }
    
    size_t new_max;
    if (add > old_max) {
        new_max = old_max + add;
    } else {
        new_max = old_max * 2;
    }

    if (new_max <= 32) {
        new_max = 32;
    }

    size_t old_size = old_max * sizeof(*req->headers);
    size_t new_size = new_max * sizeof(*req->headers);
    req->headers = memory_realloc(ctx, req->headers, old_size, new_size);
    if (ctx->error)
        return;

    req->header_capacity = new_max;
}


static void assert_ascii(Context *ctx, const uint8_t *str, size_t str_len)
{
    if (ctx->error)
        return;

    uint8_t ch;
    const uint8_t *ptr = str;
    const uint8_t *end = str + str_len;

    for (ptr = str; ptr < end; ptr++) {
        ch = *ptr;
        if (ch == 0 || ch > 0x7F) {
            context_panic(ctx, ERROR_VALUE,
                          "invalid ASCII code byte 0x%02x in position %zu:"
                          " value not between 0x01 and 0x7f",
                          (unsigned)ch, (size_t)(ptr - str));
            break;
        }
    }
}


static void httpget_set_status(Context *ctx, HttpGet *req, uint8_t *line,
                               size_t line_len)
{
    if (ctx->error)
        return;

    assert_ascii(ctx, line, line_len);
    if (ctx->error) {
        context_panic(ctx, ctx->error, "failed parsing HTTP status line: %s",
                      ctx->message);
        return;
    }
    req->status = (char *)line;
}


static void httpget_add_header(Context *ctx, HttpGet *req, uint8_t *line,
                               size_t line_len)
{
    if (ctx->error)
        return;

    if (req->header_count == req->header_capacity) {
        httpget_grow_headers(ctx, req, 1);
        if (ctx->error)
            return;
    }

    size_t i = req->header_count;

    assert_ascii(ctx, line, line_len);
    if (ctx->error) {
        context_panic(ctx, ERROR_VALUE,
            "failed parsing HTTP header line in position %zu: %s",
            i + 1, ctx->message);
        return;
    }

    char *key = (char *)line;
    char *colon = strstr(key, ":");
    if (!colon) {
        context_panic(ctx, ERROR_VALUE,
                      "failed parsing HTTP header line in position %zu: %s",
                      i + 1, "missing colon (:)");
        return;
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


static bool httpget_start(Context *ctx, HttpGet *req)
{
    if (ctx->error)
        return false;

    memset(&req->hints, 0, sizeof(req->hints));
    req->hints.ai_flags = PF_UNSPEC;
    req->hints.ai_socktype = SOCK_STREAM;
    req->hints.ai_protocol = IPPROTO_TCP;
    getaddrinfo_init(ctx, &req->getaddr, req->host, "http", &req->hints);

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

    req->addrinfo = req->getaddr.result;

    log_debug(ctx, "getaddr finished");
    log_debug(ctx, "open started");
    req->state = HTTPGET_OPEN;
    return false;
}


static bool httpget_open_blocked(Context *ctx, HttpGet *req)
{
    if (ctx->error)
        return false;

    assert(req->addrinfo);
    req->sockfd = -1;

    while (req->sockfd < 0 && req->addrinfo) {
        const struct addrinfo *ai = req->addrinfo;

        req->sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (req->sockfd >= 0) {
            break;
        }

        req->addrinfo = req->addrinfo->ai_next;
    }

    if (req->sockfd < 0) {
        int status = errno;
        context_panic(ctx, error_code(status),
                      "failed opening socket: %s", strerror(status));
        return false;
    }

    int flags = fcntl(req->sockfd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(req->sockfd, F_SETFL, flags | O_NONBLOCK); // ignore error
    }

    sockconnect_init(ctx, &req->conn, req->sockfd, req->addrinfo->ai_addr,
                     req->addrinfo->ai_addrlen);

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
        req->addrinfo = req->addrinfo->ai_next;

        if (req->addrinfo) {
            context_recover(ctx);
            sockconnect_deinit(ctx, &req->conn);
            close(req->sockfd);
            req->state = HTTPGET_OPEN;
        } else {
            context_panic(ctx, ctx->error, "failed connecting to host: %s",
                          ctx->message);
        }

        return false;
    }

    // send request
    const char *format = "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n";
    size_t buffer_len =
        (size_t)snprintf(NULL, 0, format, req->target, req->host) + 1;

    if (buffer_len < BUFFER_LEN)
        buffer_len = BUFFER_LEN;

    httpget_grow_buffer(ctx, req, buffer_len);
    if (ctx->error)
        return false;

    snprintf(req->buffer, req->buffer_len, format, req->target, req->host);
    socksend_init(ctx, &req->send, req->sockfd, req->buffer,
                  strlen(req->buffer), 0);

    log_debug(ctx, "connect finished");
    log_debug(ctx, "send started");
    req->state = HTTPGET_SEND;
    return false;
}


static bool httpget_send_blocked(Context *ctx, HttpGet *req)
{
    if (ctx->error)
        return false;

    if (task_blocked(ctx, &req->send.task)) {
        req->task.block = req->send.task.block;
        return true;
    }

    req->data = req->buffer;
    req->data_len = 0;
    req->data_max = req->buffer_len;

    assert(req->data_max >= BUFFER_LEN);
    sockrecv_init(ctx, &req->recv, req->sockfd, req->data, BUFFER_LEN, 0);

    log_debug(ctx, "send finished");
    log_debug(ctx, "meta started");
    req->state = HTTPGET_META;
    return false;
}


static bool httpget_meta_blocked(Context *ctx, HttpGet *req)
{
    if (ctx->error)
        return false;

    if (task_blocked(ctx, &req->recv.task)) {
        req->task.block = req->recv.task.block;
        return true;
    }

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
            httpget_set_status(ctx, req, line, line_len);
        } else {
            httpget_add_header(ctx, req, line, line_len);
        }
    }

    if (empty_line) {
        req->state = HTTPGET_FINISH;
        log_debug(ctx, "meta finished");
    } else {
        size_t empty = req->data_max - req->data_len; 
        if (empty < BUFFER_LEN) {
            httpget_grow_buffer(ctx, req, BUFFER_LEN - empty);
        }

        sockrecv_reinit(ctx, &req->recv, req->sockfd,
                        req->data + req->data_len, BUFFER_LEN, 0);
    }

    return false;
}


static bool httpbody_blocked(Context *ctx, Task *task)
{
    if (ctx->error)
        return false;

    HttpBody *body = (HttpBody *)task;
    HttpGet *req = container_of(body, HttpGet, current);

    Task *work;
    if (req->content_read < req->content_length) {
        work = &req->recv.task;
    } else {
        work = &req->shutdown.task;
    }

    if (task_blocked(ctx, work)) {
        body->task.block = work->block;
        return true;
    }

    body->task.block.type = BLOCK_NONE;
    return false;
}


static void httpbody_init(Context *ctx, HttpBody *body)
{
    memset(body, 0, sizeof(*body));
    if (ctx->error)
        return;
    body->task._blocked = httpbody_blocked;
}


static void httpbody_deinit(Context *ctx, HttpBody *body)
{
    (void)ctx;
    (void)body;
}


bool httpget_advance(Context *ctx, HttpGet *req)
{
    if (ctx->error)
        return false;

    assert(req->state == HTTPGET_FINISH);

    size_t tail_len = req->content_length - req->content_read;
    if (tail_len == 0)
        return false;

    size_t data_len;

    if (!req->content_started) {
        req->current.data = req->data;
        data_len = req->data_len;
    } else {
        req->current.data = req->recv.buffer;
        data_len = req->recv.nrecv;
    }

    if (data_len > tail_len) {
        data_len = tail_len;
    }
    req->current.data_len = data_len;
    req->content_read += data_len;

    tail_len = req->content_length - req->content_read;

    if (tail_len) {
        void *buffer;
        void *tail = req->data + (req->data_max - BUFFER_LEN);
        if (!req->content_started || req->recv.buffer < tail) {
            buffer = tail;
        } else {
            buffer = req->data;
        }
        size_t buffer_len = tail_len > BUFFER_LEN ? BUFFER_LEN : tail_len;
        sockrecv_reinit(ctx, &req->recv, req->sockfd, buffer, buffer_len, 0);
    } else {
        sockshutdown_init(ctx, &req->shutdown, req->sockfd, SHUT_RDWR);
    }

    req->content_started = true;
    return true;
}


static void httpget_finish(Context *ctx, HttpGet *req)
{
    if (ctx->error)
        return;

    req->task.block.type = BLOCK_NONE;

    if (!req->status) {
        context_panic(ctx, ERROR_VALUE, "missing HTTP status line");
        return;
    }

    bool has_content_length = false;
    size_t i, n = req->header_count;
    const HttpHeader *header;

    for (i = 0; i < n; i++) {
        header = &req->headers[i];
        if (strcmp(header->key, "Content-Length") == 0) {
            has_content_length = true;
            break;
        }
    }

    if (!has_content_length) {
        context_panic(ctx, ERROR_VALUE, "missing HTTP `Content-Length` header");
        return;
    }

    char *end;
    errno = 0;
    intmax_t content_length = strtoimax(header->value, &end, 10);

    if (*end != '\0' || content_length < 0) {
        context_panic(ctx, ERROR_VALUE,
                      "invalid HTTP `Content-Length` value: `%s`",
                      header->value);
    } else if (errno == ERANGE) {
        context_panic(ctx, ERROR_OVERFLOW,
                      "HTTP `Content-Length` value `%s`"
                      " exceeds maximum (%"PRIdMAX")",
                      header->value, (intmax_t)INTMAX_MAX);
    } else {
        assert(SIZE_MAX >= INTMAX_MAX);
        req->content_length = (size_t)content_length;
        httpbody_init(ctx, &req->current);
    }

    size_t required = BUFFER_LEN;
    if (req->data_len <= BUFFER_LEN) {
        required += (BUFFER_LEN - req->data_len);
    }

    size_t available = req->data_max - req->data_len;
    if (available < required) {
        httpget_grow_buffer(ctx, req, required - available);
    }
}


bool httpget_blocked(Context *ctx, Task *task)
{
    if (ctx->error)
        return false;

    HttpGet *req = (HttpGet *)task;

    while (true) {
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

        case HTTPGET_SEND:
            action = httpget_send_blocked;
            break;

        case HTTPGET_META:
            action = httpget_meta_blocked;
            break;

        case HTTPGET_FINISH:
            httpget_finish(ctx, req);
            return false;
        }

        if (action(ctx, req))
            return true;
    }
}


void httpget_init(Context *ctx, HttpGet *req, const char *host,
                  const char *target)
{
    memset(req, 0, sizeof(*req));
    if (ctx->error)
        return;

    req->state = HTTPGET_START;
    req->host = host;
    req->target = target;
    req->task.block.type = BLOCK_NONE;
    req->task._blocked = httpget_blocked;
}


void httpget_deinit(Context *ctx, HttpGet *req)
{
    switch (req->state) {
    case HTTPGET_FINISH:
        httpbody_deinit(ctx, &req->current);

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

    HttpGet req;
    httpget_init(&ctx, &req, "www.unicode.org",
                 "/Public/12.0.0/ucd/UnicodeData.txt");

    task_await(&ctx, &req.task);
    if (ctx.error)
        goto exit;

    log_debug(&ctx, "status: `%s`", req.status);
    size_t i, n = req.header_count;
    for (i = 0; i < n; i++) {
        log_debug(&ctx, "header: `%s`: `%s`",
                  req.headers[i].key, req.headers[i].value);
    }

    log_debug(&ctx, "content-length: %zu", req.content_length);

    while (httpget_advance(&ctx, &req)) {
        task_await(&ctx, &req.current.task);
        log_debug(&ctx, "read %d bytes", (int)req.current.data_len);
        printf("----------------------------------------\n");
        printf("%.*s", (int)req.current.data_len, (char *)req.current.data);
        printf("\n----------------------------------------\n");
    }

exit:
    if (ctx.error) {
        fprintf(stderr, "error: %s\n", ctx.message);
        status = EXIT_FAILURE;
    }

    httpget_deinit(&ctx, &req);
    context_deinit(&ctx);

    return status;
}
