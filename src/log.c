#include <stdarg.h>
#include <stdio.h>
#include "prelude.h"

static void vlog(Context *ctx, LogType log, const char *format, va_list args);


void log_debug(Context *ctx, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vlog(ctx, LOG_DEBUG, format, args);
    va_end(args);
}


void log_info(Context *ctx, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vlog(ctx, LOG_INFO, format, args);
    va_end(args);
}


void vlog(Context *ctx, LogType log, const char *format, va_list args)
{
    if (!ctx->error) {
        vsnprintf(ctx->buffer, sizeof(ctx->buffer), format, args);
        (ctx->log)(log, ctx->buffer, ctx->log_data);
    }
}
