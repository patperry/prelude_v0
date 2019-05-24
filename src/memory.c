#include <string.h>
#include "prelude.h"


void *memory_alloc(Context *ctx, size_t size)
{
    return memory_realloc(ctx, NULL, 0, size);
}


void memory_free(Context *ctx, void *buf, size_t size)
{
    // Can't call memory_realloc because it aborts on error
    (ctx->_alloc)(buf, size, 0, ctx->_alloc_data);
}


void *memory_realloc(Context *ctx, void *buf, size_t old_size, size_t new_size)
{
    if (ctx->error)
        return buf;

    void *new_buf = (ctx->_alloc)(buf, old_size, new_size, ctx->_alloc_data);
    if (!new_buf && new_size) {
        context_panic(ctx, ERROR_MEMORY, "failed allocating %zu bytes",
                      new_size);
        return buf;
    }
    return new_buf;
}


void memory_clear(Context *ctx, void *buf, size_t size)
{
    (void)ctx;
    memset(buf, 0, size);
}


bool memory_equal(Context *ctx, const void *buf1, const void *buf2,
                  size_t size)
{
    (void)ctx;
    return !memcmp(buf1, buf2, size);
}


void memory_copy(Context *ctx, void *buf, const void *src, size_t size)
{
    (void)ctx;
    memcpy(buf, src, size);
}
