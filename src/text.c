#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "context.h"
#include "buffer.h"
#include "text.h"


Error textbuild_reserve(Context *ctx, TextBuild *build, int32_t extra)
{
    void *bytes = build->bytes;
    Error err = buffer_reserve(ctx, &bytes, sizeof(*build->bytes),
                               &build->capacity, build->count, extra);
    if (!err) {
        build->bytes = bytes;
    }
    return err;
}


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

    textiter_init(ctx, &it, text);
    while (textiter_advance(ctx, &it)) {
        len++;
    }
    textiter_deinit(ctx, &it);

    return len;
}


bool text_eq(Context *ctx, const Text *text1, const Text *text2)
{
    (void)ctx;
    (void)text1;
    (void)text2;
    return false;
}


void textiter_init(Context *ctx, TextIter *it, const Text *text)
{
    (void)ctx;
    (void)it;
    (void)text;
}


void textiter_deinit(Context *ctx, TextIter *it)
{
    (void)ctx;
    (void)it;
}


bool textiter_advance(Context *ctx, TextIter *it)
{
    (void)ctx;
    (void)it;
    return false;
}


void textbuild_init(Context *ctx, TextBuild *build)
{
    (void)ctx;
    memset(build, 0, sizeof(*build));
}


void textbuild_clear(Context *ctx, TextBuild *build)
{
    (void)ctx;
    build->count = 0;
}


void textbuild_deinit(Context *ctx, TextBuild *build)
{
    context_free(ctx, build->bytes, build->count * sizeof(*build->bytes));
}


void textbuild_char(Context *ctx, TextBuild *build, Char32 code)
{
    int32_t extra = UTF8_COUNT(code);

    if (textbuild_reserve(ctx, build, extra))
        return;

    uint8_t *end = build->bytes + build->count;
    utf8_encode(ctx, code, &end);
    build->count += extra;
}


// http://www.fileformat.info/info/unicode/utf8.htm
void utf8_encode(Context *ctx, Char32 code, uint8_t **pptr)
{
    (void)ctx;
    uint8_t *ptr = *pptr;

    assert(code >= 0);
    uint32_t x = (uint32_t)code;

    if (x <= 0x7F) {
		*ptr++ = (uint8_t)x;
	} else if (x <= 0x07FF) {
		*ptr++ = (uint8_t)(0xC0 | (x >> 6));
		*ptr++ = (uint8_t)(0x80 | (x & 0x3F));
	} else if (x <= 0xFFFF) {
		*ptr++ = (uint8_t)(0xE0 | (x >> 12));
		*ptr++ = (uint8_t)(0x80 | ((x >> 6) & 0x3F));
		*ptr++ = (uint8_t)(0x80 | (x & 0x3F));
	} else {
		*ptr++ = (uint8_t)(0xF0 | (x >> 18));
		*ptr++ = (uint8_t)(0x80 | ((x >> 12) & 0x3F));
		*ptr++ = (uint8_t)(0x80 | ((x >> 6) & 0x3F));
		*ptr++ = (uint8_t)(0x80 | (x & 0x3F));
	}

    *pptr = ptr;
}
