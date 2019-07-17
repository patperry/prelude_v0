#include <stdlib.h>
#include <stdio.h>

#include "prelude.h"

// https://www.freecodecamp.org/news/how-to-get-https-working-on-your-local-development-environment-in-5-minutes-7af615770eec/

int main(int argc, const char **argv)
{
    (void)argc;
    (void)argv;
    int status = EXIT_SUCCESS;

    Context ctx;
    context_init(&ctx, NULL, NULL, NULL, NULL);

    Socket sock;
    socket_init(&ctx, &sock, SOCKET_TCP, IP_V4);

    SocketAddr addr;
    addr.type = IP_V4;
    addr.value.v4.ip = IPADDRV4_LOOPBACK_INIT;
    addr.value.v4.port = 31337;

    socket_bind(&ctx, &sock, &addr);
    socket_listen(&ctx, &sock, 128);

    SockAccept accept;
    sockaccept_init(&ctx, &accept, &sock);
    task_await(&ctx, &accept.task);

    SockRecv recv;
    char buffer[1024];
    sockrecv_init(&ctx, &recv, &accept.peer_sock, buffer, 1023);
    task_await(&ctx, &recv.task);

    buffer[recv.nrecv] = '\0';
    printf("%s", buffer);

    if (ctx.error) {
        fprintf(stderr, "error: %s\n", ctx.message);
        status = EXIT_FAILURE;
    }

    sockrecv_deinit(&ctx, &recv);
    sockaccept_deinit(&ctx, &accept);
    socket_deinit(&ctx, &sock);
    context_deinit(&ctx);
    return status;
}
