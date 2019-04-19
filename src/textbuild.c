#include "prelude.h"


static void textbuild_reserve(Context *ctx, TextBuild *build, int32_t extra,
                              Error *perr)
{
    void *bytes = build->bytes;
    array_reserve(ctx, &bytes, sizeof(*build->bytes), &build->capacity,
                  build->count, extra, perr);
    if (!*perr) {
        build->bytes = bytes;
    }
}


void textbuild_init(Context *ctx, TextBuild *build)
{
    memory_clear(ctx, build, sizeof(*build));
}


void textbuild_clear(Context *ctx, TextBuild *build)
{
    (void)ctx;
    build->count = 0;
}


void textbuild_deinit(Context *ctx, TextBuild *build)
{
    memory_free(ctx, build->bytes, build->count * sizeof(*build->bytes));
}


Text textbuild_get(Context *ctx, TextBuild *build)
{
    Text text;

    memory_clear(ctx, &text, sizeof(text));

    if (!context_error(ctx)) {
        text.bytes = build->bytes;
        text.unescape = 0;
        text.size = (unsigned int)build->count;
    }

    return text;
}


void textbuild_text(Context *ctx, TextBuild *build, const Text *text)
{
    if (context_error(ctx))
        return;

    TextIter it;
    textiter_init(ctx, &it, text);
    while (textiter_advance(ctx, &it)) {
        textbuild_char(ctx, build, it.current);
    }
    textiter_deinit(ctx, &it);
}


void textbuild_char(Context *ctx, TextBuild *build, Char32 code)
{
    if (context_error(ctx))
        return;

    int32_t extra = CHAR32_UTF8_COUNT(code);
    Error err = ERROR_NONE;

    textbuild_reserve(ctx, build, extra, &err);
    if (err)
        return;

    uint8_t *end = build->bytes + build->count;
    char_encode_utf8(ctx, code, &end);
    build->count += extra;
}
