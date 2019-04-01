
#include <stddef.h>
#include <stdio.h>
#include "context.h"

int main(int argc, const char **argv)
{
    (void)argc;
    (void)argv;
    context ctx;
    context_init(&ctx, NULL, NULL, NULL, NULL);
    context_debug(&ctx, "Hello, world!");
    printf("{\"a\": \"Int\", \"b\": \"Real\"}\n");
    context_deinit(&ctx);
    return 0;
}
