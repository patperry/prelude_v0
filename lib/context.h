#ifndef CONTEXT_H
#define CONTEXT_H

#define CONTEXT_BUFFER_MAX 1024

enum error_type {
    ERROR_NONE = 0,
    ERROR_NOMEM
};

enum log_type {
    LOG_DEBUG = 0,
    LOG_INFO
};

typedef void* (*alloc_func)(void *buf, size_t old_size, size_t new_size,
                            void *data);

typedef void (*log_func)(enum log_type log, const char *message, void *data);

typedef struct context {
    char buffer[CONTEXT_BUFFER_MAX];
    alloc_func alloc;
    log_func log;
    void *alloc_data;
    void *log_data;
    enum error_type error;
} context;

void context_init(context *ctx, alloc_func alloc, void *alloc_data,
                  log_func log, void *log_data);
void context_deinit(context *ctx);

/* errors */
void context_panic(context *ctx, enum error_type error, const char *format, ...)
    __attribute__ ((format (printf, 3, 4)));
void context_recover(context *ctx);
enum error_type context_status(context *ctx);
const char *context_message(context *ctx);

/* memory */
void *context_alloc(context *ctx, size_t size);
void *context_realloc(context *ctx, void *buf, size_t old_size,
                      size_t new_size);
void context_free(context *ctx, void *buf, size_t size);

/* logging */
void context_debug(context *ctx, const char *format, ...)
    __attribute__ ((format (printf, 2, 3)));
void context_info(context *ctx, const char *format, ...)
    __attribute__ ((format (printf, 2, 3)));

#endif /* CONTEXT_H */
