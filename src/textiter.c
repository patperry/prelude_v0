#include "prelude.h"


void textiter_init(Context *ctx, TextIter *it, const Text *text)
{
    (void)ctx;

    it->ptr = text->bytes;
    it->end = text->bytes + text->size;
    it->unescape = (bool)text->unescape;
    it->current = CHAR32_NONE;
}


void textiter_deinit(Context *ctx, TextIter *it)
{
    (void)ctx;
    (void)it;
}


bool textiter_advance(Context *ctx, TextIter *it)
{
    if (it->ptr == it->end) {
        it->current = CHAR32_NONE;
        return false;
    }

    const uint8_t *ptr = it->ptr;
    Char32 code = (Char32)*ptr++;
    if (code == '\\' && it->unescape) {
        code = char_decode_escape(ctx, &ptr);
    } else if (code > CHAR8_MAX) {
        ptr--;
        code = char_decode_utf8(ctx, &ptr);
    }
    it->ptr = ptr;
    it->current = code;
    return true;
}
