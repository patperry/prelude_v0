#include "prelude.h"


Error text_view(Context *ctx, Text *text, TextViewType flags,
                const uint8_t *bytes, size_t size)
{
    memory_clear(ctx, text, sizeof(*text));

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
    if (text1 == text2) {
        return true;
    } else if (!text1->unescape && !text2->unescape) {
        if (text1->size != text2->size) {
            return false;
        } else if (text1->bytes == text2->bytes) {
            return true;
        } else {
            return memory_equal(ctx, text1->bytes, text2->bytes,
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
