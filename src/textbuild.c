#include "prelude.h"


static void textbuild_reserve(Context *ctx, TextBuild *build, int32_t extra)
{
    if (ctx->error)
        return;

    void *bytes = build->bytes;
    array_reserve(ctx, &bytes, sizeof(*build->bytes), &build->capacity,
                  build->count, extra);
    if (ctx->error)
        return;
    build->bytes = bytes;
}


void textbuild_init(Context *ctx, TextBuild *build)
{
    memory_clear(ctx, build, sizeof(*build));
}


void textbuild_clear(Context *ctx, TextBuild *build)
{
    if (ctx->error)
        return;
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

    if (!ctx->error) {
        text.bytes = build->bytes;
        text.unescape = 0;
        text.size = (unsigned int)build->count;
    }

    return text;
}


void textbuild_text(Context *ctx, TextBuild *build, const Text *text)
{
    if (ctx->error)
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
    if (ctx->error)
        return;

    int32_t extra = CHAR32_UTF8_COUNT(code);

    textbuild_reserve(ctx, build, extra);
    if (ctx->error)
        return;

    uint8_t *end = build->bytes + build->count;
    char_encode_utf8(ctx, code, &end);
    build->count += extra;
}
