#ifndef CONTEXT_H
#define CONTEXT_H

#define CONTEXT_BUFFER_MAX 1024

typedef enum {
    ERROR_NONE = 0,
    ERROR_MEMORY,
    ERROR_OVERFLOW,
    ERROR_VALUE,
} Error;

typedef enum {
    LOG_NONE = 0,
    LOG_DEBUG,
    LOG_INFO
} Log;

typedef void* (*AllocFunc)(void *buf, size_t old_size, size_t new_size,
                            void *data);

typedef void (*LogFunc)(Log log, const char *message, void *data);

typedef struct {
    char buffer[CONTEXT_BUFFER_MAX];
    AllocFunc alloc;
    LogFunc log;
    void *alloc_data;
    void *log_data;
    Error error;
} Context;

void context_init(Context *ctx, AllocFunc alloc, void *alloc_data,
                  LogFunc log, void *log_data);
void context_deinit(Context *ctx);

/* errors */
Error context_panic(Context *ctx, Error error, const char *format, ...)
    __attribute__ ((format (printf, 3, 4)));
void context_recover(Context *ctx);
Error context_error(Context *ctx);
const char *context_message(Context *ctx);

/* memory */
void *context_alloc(Context *ctx, size_t size);
void *context_realloc(Context *ctx, void *buf, size_t old_size,
                      size_t new_size);
void context_free(Context *ctx, void *buf, size_t size);

/* logging */
void context_debug(Context *ctx, const char *format, ...)
    __attribute__ ((format (printf, 2, 3)));
void context_info(Context *ctx, const char *format, ...)
    __attribute__ ((format (printf, 2, 3)));

#endif /* CONTEXT_H */
