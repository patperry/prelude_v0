#include <inttypes.h>
#include <string.h>

#include "prelude.h"


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
    memset(text, 0, sizeof(*text));

    if (size > (size_t)INT32_MAX) {
        return context_panic(ctx, ERROR_OVERFLOW, "text size (%zu bytes)"
                             " exceeds maximum (%"PRId32" bytes)",
                             size, INT32_MAX);
    }

    Error err = ERROR_NONE;
    const uint8_t *ptr = bytes;
    const uint8_t *end = ptr + size;
    bool unescape = false;
    uint8_t ch;

    if (flags & TEXTVIEW_UNESCAPE) {
        while (ptr != end) {
            ch = *ptr++;
            if (ch == '\\') {
                unescape = true;

                if ((err = char_scan_escape(ctx, &ptr, end))) {
                    goto out;
                }
            } else if (ch & 0x80) {
                ptr--;
                if ((err = char_scan(ctx, &ptr, end))) {
                    goto out;
                }
            }
        }
    } else {
        while (ptr != end) {
            ch = *ptr++;
            if (ch & 0x80) {
                ptr--;
                if ((err = char_scan(ctx, &ptr, end))) {
                    goto out;
                }
            }
        }
    }

out:
    if (!err) {
        text->bytes = bytes;
        text->unescape = (unsigned int)unescape;
        text->size = size;
    }
    return err;
}


int32_t text_length(Context *ctx, const Text *text)
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


bool text_equal(Context *ctx, const Text *text1, const Text *text2)
{
    (void)ctx;
    if (text1 == text2) {
        return true;
    } else if (!text1->unescape && !text2->unescape) {
        if (text1->size != text2->size) {
            return false;
        } else if (text1->bytes == text2->bytes) {
            return true;
        } else {
            return !memcmp(text1->bytes, text2->bytes,
                           text1->size * sizeof(*text1->bytes));
        }
    }

    TextIter it1, it2;
    textiter_init(ctx, &it1, text1);
    textiter_init(ctx, &it2, text1);
    bool ret;

    while (textiter_advance(ctx, &it1)) {
        if (!textiter_advance(ctx, &it2)) {
            ret = false;
            goto out;
        } else if (it1.current != it2.current) {
            ret = false;
            goto out;
        }
    }

    if (textiter_advance(ctx, &it2)) {
        ret = false;
        goto out;
    }

    ret = true;
out:
    textiter_deinit(ctx, &it2);
    textiter_deinit(ctx, &it1);
    return ret;
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
    int32_t extra = CHAR32_UTF8_COUNT(code);

    if (textbuild_reserve(ctx, build, extra))
        return;

    uint8_t *end = build->bytes + build->count;
    char_encode(ctx, code, &end);
    build->count += extra;
}
