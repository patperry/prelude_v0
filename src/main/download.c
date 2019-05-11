#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "prelude.h"

int main(int argc, const char **argv)
{
    (void)argc;
    (void)argv;

    Error err = ERROR_NONE;

    const char *host = "www.unicode.org";
    const char *service = "http";
    Context ctx;
    HostLookup look;
    Socket sock;
    bool has_sock = false;
    Task task;

    context_init(&ctx);
    hostlookup_init(&ctx, &look, host, service, SOCKET_FAMILY_NONE,
                    SOCKET_COMM_STREAM, SOCKET_PROTO_TCP);

    while (!has_sock && hostlookup_advance(&ctx, &look, &err)) {
        socket_init(&ctx, &sock, look.family, look.comm, lookup.proto, &err);
        socket_connect(&ctx, &sock, &look.addr, &task, &err);
        task_await(&ctx, task, timeout_ms, &err);

        if (err) {
            socket_deinit(&ctx, &sock);
            err = context_recover(&ctx);
        } else {
            has_sock = true;
        }
    }

    if (!has_sock) { // lookup failed or could not connect to an address
        goto connect_fail;
    }

    // http://www.unicode.org/Public/12.0.0/data/ucd/UnicodeData.txt
    const char *message = 
        "GET /Public/12.0.0/ucd/UnicodeData.txt HTTP/1.1\r\n"
        "Host: www.unicode.org\r\n"
        "\r\n";

    socket_send(&ctx, &sock, message, strlen(message), 0, &task, &err);
    task_await(&ctx, task, timeout_ms, &err);
    if (err) {
        goto send_fail;
    }

    char response[4096];
    memset(response, 0, sizeof(response));
    int total = sizeof(response)-1;
    int received = 0;
    int bytes = 0;

    do {
        socket_receive(&ctx, &sock, response, total, 0, &task, &bytes, &err);
        task_await(&ctx, task, timeout_ms, &err);
        if (err) {
            goto receive_fail;
        }

        printf("%s", response);
        memset(response, 0, sizeof(response));
        printf("bytes = %d\n", bytes);
    } while (bytes > 0);

    socket_disconnect(&ctx, &sock);

receive_fail:
send_fail:
    socket_deinit(&sock);
connect_fail:
    hostlookup_deinit(&lookup);
    context_deinit(&ctx);
    return err;
}
