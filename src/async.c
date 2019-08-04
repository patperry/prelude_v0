#include <errno.h>
#include <poll.h>

#include "prelude.h"

static void await_io(Context *ctx, BlockIO *block);
static void await_timer(Context *ctx, BlockTimer *block);


bool taskpart_blocked(Context *ctx, TaskPart *taskpart)
{
    if (ctx->error)
        return false;

    return (taskpart->_blocked)(ctx, taskpart);
}


bool taskpart_advance(Context *ctx, TaskPart *taskpart)
{
    if (ctx->error)
        return false;

    if (!taskpart_blocked(ctx, taskpart)) {
        return false;
    }

    log_debug(ctx, "blocked. waiting...");
    switch (taskpart->block.type) {
    case BLOCK_NONE:
        break;
    case BLOCK_IO:
        await_io(ctx, &taskpart->block.job.io);
        break;
    case BLOCK_TIMER:
        await_timer(ctx, &taskpart->block.job.timer);
        break;
    }

    return true;
}


void taskpart_await(Context *ctx, TaskPart *taskpart)
{
    if (ctx->error)
        return;

    while (taskpart_advance(ctx, taskpart)) {
        // pass
    }
}


void await_io(Context *ctx, BlockIO *block)
{
    if (ctx->error)
        return;

    log_debug(ctx, "awaiting %s on fd %d",
              block->flags == IO_READ ? "read"
              : block->flags == IO_WRITE ? "write"
              : block->flags == (IO_READ | IO_WRITE) ? "read or write"
              : "nothing", block->fd);

    struct pollfd fds[1];
    fds[0].fd = block->fd;
    fds[0].events = 0;

    if (block->flags & IO_READ) {
        fds[0].events |= POLLIN;
    }
    if (block->flags & IO_WRITE) {
        fds[0].events |= POLLOUT;
    }
    fds[0].revents = 0;

    if (poll(fds, 1, -1) < 0) {
        context_code(ctx, errno);
    }
}


void await_timer(Context *ctx, BlockTimer *block)
{
    if (ctx->error)
        return;

    if (poll(NULL, 0, block->millis) < 0) {
        int status = errno;
        context_code(ctx, status);
    }
}
