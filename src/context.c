#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "prelude.h"


Error error_code(int errnum)
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


void *default_alloc(void *buf, size_t old_size, size_t new_size, void *data)
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


void default_log(LogType log, const char *message, void *data)
{
    (void)data;

    if (log == LOG_INFO) {
        fprintf(stdout, "%s\n", message);
        fflush(stdout);
    } else if (log == LOG_DEBUG) {
        time_t clock;
        struct tm tm;

        time(&clock);
        tm = *gmtime(&clock); // TODO: replace with reentrant version

        fprintf(stderr, "%d-%02d-%02d %02d:%02d:%02d [DEBUG] %s\n",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec,
                message);
        fflush(stderr);
    }
}


void context_init(Context *ctx, AllocFunc alloc, void *alloc_data,
                  LogFunc log, void *log_data)
{
    memset(ctx, 0, sizeof(*ctx));

    if (alloc) {
        ctx->_alloc = alloc;
        ctx->_alloc_data = alloc_data;
    } else {
        ctx->_alloc = &default_alloc;
    }

    if (log) {
        ctx->_log = log;
        ctx->_log_data = log_data;
    } else {
        ctx->_log = &default_log;
    }
}


void context_deinit(Context *ctx)
{
    (void)ctx;
}


void context_panic(Context *ctx, Error error, const char *format, ...)
{
    char *message = (ctx->message == ctx->_buffer0 ?
                     ctx->_buffer1 :
                     ctx->_buffer0);

    va_list args;
    va_start(args, format);
    vsnprintf(message, CONTEXT_MESSAGE_MAX, format, args);
    va_end(args);

    ctx->message = message;
    ctx->error = error;
}


void context_recover(Context *ctx)
{
    ctx->error = ERROR_NONE;
    ctx->message = NULL;
}


void context_code(Context *ctx, int errnum)
{
    int error = error_code(errnum);
    if (error) {
        context_panic(ctx, error, "%s", strerror(errnum));
    } else {
        context_recover(ctx);
    }
}
