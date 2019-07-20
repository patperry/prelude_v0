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

    HttpRecv recv;
    httprecv_init(&ctx, &recv, &accept.peer_sock);
    task_await(&ctx, &recv.task);

    log_debug(&ctx, "start: `%s`", recv.start);
    size_t i, n = recv.header_count;
    for (i = 0; i < n; i++) {
        log_debug(&ctx, "header: `%s`: `%s`",
                  recv.headers[i].key, recv.headers[i].value);
    }

    while (httprecv_advance(&ctx, &recv)) {
        task_await(&ctx, &recv.current.task);
        log_debug(&ctx, "read %d bytes", (int)recv.current.data_len);
        printf("----------------------------------------\n");
        printf("%.*s", (int)recv.current.data_len,
               (char *)recv.current.data);
        printf("\n----------------------------------------\n");
    }

    SockShutdown peer_shutdown;
    sockshutdown_init(&ctx, &peer_shutdown, &accept.peer_sock);
    task_await(&ctx, &peer_shutdown.task);

    SockShutdown shutdown;
    sockshutdown_init(&ctx, &shutdown, &sock);
    task_await(&ctx, &shutdown.task);

    if (ctx.error) {
        fprintf(stderr, "error: %s\n", ctx.message);
        status = EXIT_FAILURE;
    }

    httprecv_deinit(&ctx, &recv);
    sockaccept_deinit(&ctx, &accept);
    socket_deinit(&ctx, &sock);
    context_deinit(&ctx);
    return status;
}
