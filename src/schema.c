
#include <stdio.h>

#define UNUSED(x) (void)x

int main(int argc, const char **argv)
{
    UNUSED(argc);
    UNUSED(argv);
    printf("{\"a\": \"Int\", \"b\": \"Real\"}\n");
    return 0;
}
