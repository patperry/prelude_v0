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


bool text_eq(Context *ctx, const Text *text1, const Text *text2)
{
    (void)ctx;
    (void)text1;
    (void)text2;
    return false;
}
