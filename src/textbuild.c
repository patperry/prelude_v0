#include "prelude.h"


static Error textbuild_reserve(Context *ctx, TextBuild *build, int32_t extra)
{
    void *bytes = build->bytes;
    Error err = array_reserve(ctx, &bytes, sizeof(*build->bytes),
                              &build->capacity, build->count, extra);
    if (!err) {
        build->bytes = bytes;
    }
    return err;
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
