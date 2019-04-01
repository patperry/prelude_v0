#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include "context.h"

static void context_log(context *ctx, enum log_type log, const char *format,
                        va_list args);

static void *alloc_default(void *buf, size_t old_size, size_t new_size,
                           void *data);

static void log_default(enum log_type log, const char *message, void *data);


void context_init(context *ctx, alloc_func alloc, void *alloc_data,
                  log_func log, void *log_data)
{
    memset(ctx, 0, sizeof(*ctx));

    if (alloc) {
        ctx->alloc = alloc;
        ctx->alloc_data = alloc_data;
    } else {
        ctx->alloc = &alloc_default;
    }

    if (log) {
        ctx->log = log;
        ctx->log_data = log_data;
    } else {
        ctx->log = &log_default;
    }
}


void context_deinit(struct context *ctx)
{
    (void)ctx;
}


void context_panic(context *ctx, enum error_type error,
                   const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vsnprintf(ctx->buffer, sizeof(ctx->buffer), format, args);
    va_end(args);
    ctx->error = error;
}


void context_recover(context *ctx)
{
    ctx->error = 0;
}


int context_status(context *ctx)
{
    return ctx->error;
}


const char *context_message(context *ctx)
{
    if (!ctx->error)
        return NULL;
    return ctx->buffer;
}


void *context_alloc(context *ctx, size_t size)
{
    return context_realloc(ctx, NULL, 0, size);
}


void context_free(context *ctx, void *buf, size_t size)
{
    context_realloc(ctx, buf, size, 0);
}


void *context_realloc(context *ctx, void *buf, size_t old_size,
                      size_t new_size)
{
    buf = (ctx->alloc)(buf, old_size, new_size, ctx->alloc_data);
    if (!buf && new_size) {
        context_panic(ctx, ERROR_NOMEM, "failed allocating %zu bytes",
                      new_size);
    }
    return buf;
}


void context_debug(context *ctx, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    context_log(ctx, LOG_DEBUG, format, args);
    va_end(args);
}


void context_info(context *ctx, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    context_log(ctx, LOG_INFO, format, args);
    va_end(args);
}


void context_log(context *ctx, enum log_type log, const char *format,
                 va_list args)
{
    if (!ctx->error) {
        vsnprintf(ctx->buffer, sizeof(ctx->buffer), format, args);
        (ctx->log)(log, ctx->buffer, ctx->log_data);
    }
}


void *alloc_default(void *buf, size_t old_size, size_t new_size, void *data)
{
    (void)old_size;
    (void)data;

    if (new_size == 0) {
        free(buf);
        return NULL;
    }

    void *new_buf = realloc(buf, new_size);

    if (!new_buf && old_size >= new_size) { // shrink failed
        return buf;
    } else {
        return new_buf;
    }
}


void log_default(enum log_type log, const char *message, void *data)
{
    (void)data;

    if (log == LOG_INFO) {
        fprintf(stdout, "%s\n", message);
        fflush(stdout);
    } else {
        time_t clock;
        struct tm tm;

        time(&clock);
        gmtime_r(&clock, &tm);

        fprintf(stderr, "%d-%02d-%02d %02d:%02d:%02d [DEBUG] %s\n",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec,
                message);
        fflush(stderr);
    }
}
