#include "prelude.h"

void textalloc_init(Context *ctx, TextAlloc *obj, const Text *text)
{
    memory_clear(ctx, obj, sizeof(*obj));
    size_t size = (size_t)text->size * sizeof(*text->bytes);
    obj->text.bytes = memory_alloc(ctx, size);
    if (obj->text.bytes) {
        obj->text.unescape = text->unescape;
        obj->text.size = text->size;
    }
}


void textalloc_deinit(Context *ctx, TextAlloc *obj)
{
    memory_free(ctx, (void *)obj->text.bytes,
                 obj->text.size * sizeof(*obj->text.bytes));
}
