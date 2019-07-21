#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include "prelude.h"

#define BUFFER_LEN 4096

typedef enum {
    META_HEADER,
    META_TRAILER
} MetaType;

static bool httprecv_blocked(Context *ctx, Task *task);
static void httprecv_set_start(Context *ctx, HttpRecv *req, uint8_t *line,
                               int line_len);
static void httprecv_add_meta(Context *ctx, HttpRecv *req,
                              MetaType type, uint8_t *line, int line_len);
static void httprecv_end_header(Context *ctx, HttpRecv *req);


static void httprecv_grow_metas(Context *ctx, HttpRecv *req, int add);
static void httprecv_grow_buffer(Context *ctx, HttpRecv *req, size_t add);

static void httpcontent_init(Context *ctx, HttpContent *content);
static void httpcontent_deinit(Context *ctx, HttpContent *content);
static bool httpcontent_blocked(Context *ctx, Task *task);



static void assert_ascii(Context *ctx, const uint8_t *str, int str_len);


void httprecv_init(Context *ctx, HttpRecv *req, Socket *sock)
{
    memset(req, 0, sizeof(*req));
    if (ctx->error)
        return;

    req->buffer = memory_alloc(ctx, BUFFER_LEN);
    if (ctx->error)
        return;

    req->buffer_len = BUFFER_LEN;
    req->data = req->buffer;
    req->data_len = 0;
    req->data_max = req->buffer_len;

    sockrecv_init(ctx, &req->recv, sock, req->data, BUFFER_LEN);
    req->task.block.type = BLOCK_NONE;
    req->task._blocked = httprecv_blocked;
}


void httprecv_deinit(Context *ctx, HttpRecv *req)
{
    httpcontent_deinit(ctx, &req->current);
    sockrecv_deinit(ctx, &req->recv);
    memory_free(ctx, req->buffer, req->buffer_len);
}


bool httprecv_blocked(Context *ctx, Task *task)
{
    log_debug(ctx, "waiting on httprecv");

    if (ctx->error)
        return false;

    HttpRecv *req = (HttpRecv *)task;
    if (task_blocked(ctx, &req->recv.task)) {
        log_debug(ctx, "socket recv is blocked");
        req->task.block = req->recv.task.block;
        log_debug(ctx, "httprecv requires %s on fd %d",
                  req->task.block.job.io.flags == IO_READ ? "read"
                  : req->task.block.job.io.flags == IO_WRITE ? "write"
                  : "void", req->task.block.job.io.fd);
        return true;
    }
    log_debug(ctx, "socket recv completed");

    req->data_len += req->recv.nrecv;

    uint8_t *line_end;
    bool empty_line = false;

    while ((line_end = memory_find(ctx, req->data, req->data_len, "\r\n", 2))) {
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
        } else if (!req->start) { // start line
            httprecv_set_start(ctx, req, line, line_len);
        } else {
            httprecv_add_meta(ctx, req, META_HEADER, line, line_len);
        }
    }

    if (empty_line) {
        log_debug(ctx, "header finished");
        httprecv_end_header(ctx, req);
    } else {
        size_t empty = req->data_max - req->data_len;
        if (empty < BUFFER_LEN) {
            httprecv_grow_buffer(ctx, req, BUFFER_LEN - empty);
        }

        log_debug(ctx, "resetting recv");
        sockrecv_reset(ctx, &req->recv, req->data + req->data_len, BUFFER_LEN);
    }

    return false;
}


void httprecv_end_header(Context *ctx, HttpRecv *req)
{
    if (ctx->error)
        return;

    req->task.block.type = BLOCK_NONE;

    if (!req->start) {
        context_panic(ctx, ERROR_VALUE, "missing HTTP start line");
        return;
    }

    const char *content_length_str = NULL;
    int i, n = req->header_count;
    const HttpMeta *header;

    for (i = 0; i < n; i++) {
        header = &req->headers[i];
        if (strcmp(header->key, "Content-Length") == 0) {
            content_length_str = header->value;
            break;
        }
    }

    if (!content_length_str) {
        // TODO: handle Transfer-Encoding: chunked
        content_length_str = "0";
    }

    char *end;
    errno = 0;
    intmax_t content_length = strtoimax(content_length_str, &end, 10);

    if (*end != '\0' || content_length < 0) {
        context_panic(ctx, ERROR_VALUE,
                      "invalid HTTP `Content-Length` value: `%s`",
                      header->value);
    } else if (errno == ERANGE || content_length > INT64_MAX) {
        context_panic(ctx, ERROR_OVERFLOW,
                      "HTTP `Content-Length` value `%s`"
                      " exceeds maximum (%"PRId64")",
                      header->value, INT64_MAX);
    } else {
        req->content_length = (int64_t)content_length;
        httpcontent_init(ctx, &req->current);
    }

    size_t required = BUFFER_LEN;
    if (req->data_len <= BUFFER_LEN) {
        required += (BUFFER_LEN - req->data_len);
    }

    size_t available = req->data_max - req->data_len;
    if (available < required) {
        httprecv_grow_buffer(ctx, req, required - available);
    }
}


void httpcontent_init(Context *ctx, HttpContent *content)
{
    memset(content, 0, sizeof(*content));
    if (ctx->error)
        return;
    content->task._blocked = httpcontent_blocked;
}


void httpcontent_deinit(Context *ctx, HttpContent *content)
{
    (void)ctx;
    (void)content;
}


bool httpcontent_blocked(Context *ctx, Task *task)
{
    if (ctx->error)
        return false;

    HttpContent *content = (HttpContent *)task;
    HttpRecv *req = container_of(content, HttpRecv, current);

    Task *work;
    if (req->content_read < req->content_length) {
        work = &req->recv.task;
    } else {
        work = NULL;
    }

    if (work && task_blocked(ctx, work)) {
        content->task.block = work->block;
        return true;
    }

    content->task.block.type = BLOCK_NONE;
    return false;
}


bool httprecv_advance(Context *ctx, HttpRecv *req)
{
    if (ctx->error)
        return false;

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
        sockrecv_reset(ctx, &req->recv, buffer, buffer_len);
    }

    req->content_started = true;
    return true;
}


void httprecv_set_start(Context *ctx, HttpRecv *req, uint8_t *line,
                         int line_len)
{
    if (ctx->error)
        return;

    assert_ascii(ctx, line, line_len);
    if (ctx->error) {
        context_panic(ctx, ctx->error, "failed parsing HTTP start line: %s",
                      ctx->message);
        return;
    }
    req->start = (char *)line;
    req->start_len = line_len;
}


void httprecv_add_meta(Context *ctx, HttpRecv *req, MetaType type,
                       uint8_t *line, int line_len)
{
    if (ctx->error)
        return;

    if (req->meta_count == req->meta_capacity) {
        httprecv_grow_metas(ctx, req, 1);
        if (ctx->error)
            return;
    }

    int i;
    const char *desc;

    switch (type) {
    case META_HEADER:
        i = req->header_count;
        desc = "header";
        break;

    case META_TRAILER:
        i = req->trailer_count;
        desc = "trailer";
        break;

    default:
        assert(0);
    }

    assert_ascii(ctx, line, line_len);
    if (ctx->error) {
        context_panic(ctx, ERROR_VALUE,
            "failed parsing HTTP %s line in position %d: %s",
            desc, i + 1, ctx->message);
        return;
    }

    char *key = (char *)line;
    char *colon = strstr(key, ":");
    if (!colon) {
        context_panic(ctx, ERROR_VALUE,
                      "failed parsing HTTP %s line in position %d: %s",
                      desc, i + 1, "missing colon (:)");
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

    switch (type) {
    case META_HEADER:
        req->headers[i].key = key;
        req->headers[i].value = value;
        req->header_count = i + 1;
        break;

    case META_TRAILER:
        req->trailers[i].key = key;
        req->trailers[i].value = value;
        req->trailer_count = i + 1;
        break;

    default:
        assert(0);
    }

    req->meta_count++;
}


void httprecv_grow_metas(Context *ctx, HttpRecv *req, int add)
{
    if (ctx->error || add <= 0)
        return;

    int old_max = req->meta_capacity;
    if (old_max / 2 > INT_MAX || old_max > INT_MAX - add) {
        context_panic(ctx, ERROR_OVERFLOW,
                      "meta count exceeds maximum (%d)", INT_MAX);
        return;
    }

    int new_max;
    if (add > old_max) {
        new_max = old_max + add;
    } else {
        new_max = old_max * 2;
    }

    if (new_max <= 32) {
        new_max = 32;
    }

    size_t old_size = old_max * sizeof(*req->metas);
    size_t new_size = new_max * sizeof(*req->metas);
    req->metas = memory_realloc(ctx, req->metas, old_size, new_size);
    if (ctx->error)
        return;
    req->headers = req->metas;
    req->trailers = req->headers + req->header_count;
    req->meta_capacity = new_max;
}


void httprecv_grow_buffer(Context *ctx, HttpRecv *req, size_t add)
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

    if (req->start) {
        req->start = new_buffer + (req->start - old_buffer);
    }

    int i, n = req->meta_count;
    for (i = 0; i < n; i++) {
        HttpMeta *meta = &req->metas[i];
        meta->key = new_buffer + (meta->key - old_buffer);
        meta->value = new_buffer + (meta->value - old_buffer);
    }
}


void assert_ascii(Context *ctx, const uint8_t *str, int str_len)
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
