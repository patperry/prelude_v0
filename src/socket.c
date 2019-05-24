#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#include "prelude.h"


void socket_init(Context *ctx, Socket *sock, int domain, int type,
                 int protocol)
{
    if (ctx->error) {
        sock->fd = -1;
        return;
    }

    sock->fd = socket(domain, type, protocol);
    if (sock->fd < 0) {
        int status = errno;
        context_panic(ctx, error_code(status),
                      "failed opening socket: %s", strerror(status));
    }

    int flags = fcntl(sock->fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(sock->fd, F_SETFL, flags | O_NONBLOCK); // ignore error
    }
}


void socket_deinit(Context *ctx, Socket *sock)
{
    (void)ctx;
    if (sock->fd >= 0)
        close(sock->fd);
}
