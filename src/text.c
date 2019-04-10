#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "context.h"
#include "text.h"


Error text_view(Context *ctx, Text *text, TextViewType flags,
                const uint8_t *bytes, size_t size)
{
    if (size > (size_t)INT32_MAX) {
        return context_panic(ctx, ERROR_OVERFLOW, "text size (%zu bytes)"
                             " exceeds maximum (%"PRId32" bytes)",
                             size, INT32_MAX);
    }

    text->bytes = bytes;
    text->unescape = (flags & TEXT_VIEW_UNESCAPE) ? 1 : 0;
    text->size = size;
    return ERROR_NONE;
}


int32_t text_len(Context *ctx, const Text *text)
{
    int32_t len = 0;
    TextIter it;

    text_iter_init(ctx, &it, text);
    while (text_iter_advance(ctx, &it)) {
        len++;
    }
    text_iter_deinit(ctx, &it);

    return len;
}


bool text_eq(Context *ctx, const Text *text1, const Text *text2)
{
    (void)ctx;
    (void)text1;
    (void)text2;
    return false;
}


void text_iter_init(Context *ctx, TextIter *it, const Text *text)
{
    (void)ctx;
    (void)it;
    (void)text;
}


void text_iter_deinit(Context *ctx, TextIter *it)
{
    (void)ctx;
    (void)it;
}


bool text_iter_advance(Context *ctx, TextIter *it)
{
    (void)ctx;
    (void)it;
    return false;
}
