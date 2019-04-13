#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "context.h"
#include "buffer.h"
#include "text.h"


void textobj_init(Context *ctx, TextObj *obj, const Text *text)
{
    size_t size = (size_t)text->size * sizeof(*text->bytes);
    memset(obj, 0, sizeof(*obj));
    obj->text.bytes = context_alloc(ctx, size);
    if (obj->text.bytes) {
        obj->text.unescape = text->unescape;
        obj->text.size = text->size;
    }
}


void textobj_deinit(Context *ctx, TextObj *obj)
{
    context_free(ctx, (void *)obj->text.bytes,
                 obj->text.size * sizeof(*obj->text.bytes));
}


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
    text->unescape = (flags & TEXTVIEW_UNESCAPE) ? 1 : 0;
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
    if (text1 == text2) {
        return true;
    } else if (text1->bytes == text2->bytes
            && text1->unescape == text2->unescape
            && text1->size == text2->size) {
        return true;
    } else if (text1->size == text2->size
            && !text1->unescape && !text2->unescape) {
        return memcmp(text1->bytes, text2->bytes,
                      text1->size * sizeof(*text1->bytes)) == 0;
    }
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


Text textbuild_get(Context *ctx, TextBuild *build)
{
    (void)ctx;
    Text text;
    text.bytes = build->bytes;
    text.unescape = 0;
    text.size = (unsigned int)build->count;
    return text;
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
