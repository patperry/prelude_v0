
#include <stddef.h>
#include <stdio.h>
#include "prelude.h"

int main(int argc, const char **argv)
{
    (void)argc;
    (void)argv;
    Context ctx;
    context_init(&ctx, NULL, NULL, NULL, NULL);
    context_debug(&ctx, "Hello, world!");
    printf("{\"a\": \"Int\", \"b\": \"Real\"}\n");
    context_deinit(&ctx);
    return 0;
}
