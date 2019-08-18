#define _POSIX_C_SOURCE 200112L // getaddrinfo
#define _XOPEN_SOURCE // ucontext
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>

#include <fcntl.h>

#if defined(__APPLE__) || defined(__FreeBSD__)
# define USE_KQUEUE
#endif

#if defined(__linux__)
# define USE_EPOLL
#endif

#ifdef USE_KQUEUE
# include <sys/types.h>
# include <sys/event.h>
# include <sys/time.h>
#endif

#ifdef USE_EPOLL
# include <sys/epoll.h>
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>

typedef enum {
    None = -1,
    False = 0,
    True = 1
} Bool;

typedef int Int;
#define Int_None INT_MIN
#define Int_Min (INT_MIN + 1)
#define Int_Max INT_MAX

typedef char *Error;
#define Error_None NULL

typedef struct Global Global;
typedef struct Context Context;
typedef struct ContextQueue ContextQueue;


void Error_Setup(Context *ctx, Error *err, const char *fmt, ...)
{
    // TODO
    (void)ctx;
    (void)err;
    (void)fmt;
}


void Error_Teardown(Context *ctx, Error *err)
{
    // TODO
    (void)ctx;
    (void)err;
}


typedef enum {
    IO_None = 0,
    IO_Read,
    IO_Write
} IOType;


struct ContextQueue {
    Context *head;
    Context *tail;
};

typedef struct BlockQueue {
    Int fd;
    Int len;
} BlockQueue;

typedef enum {
    Block_None = 0,
    Block_IO
} BlockType;

typedef struct BlockIO {
    Int fd;
    IOType type;
} BlockIO;

// BlockTimer; kqueue: EVFILT_TIMER / epoll: timerfd_create

typedef struct Block {
    BlockType type;
    union {
        BlockIO io;
    } value;
    void *data;
} Block;

void BlockQueue_Setup(BlockQueue *queue);
void BlockQueue_Teardown(BlockQueue *queue);
Bool BlockQueue_Dequeue(BlockQueue *queue, void **data);
void BlockQueue_EnqueueIO(BlockQueue *queue, const BlockIO *item,
                            void *data);


#if defined(USE_KQUEUE)

void BlockQueue_Setup(BlockQueue *queue)
{
    queue->fd = kqueue();
    if (queue->fd == -1) {
        abort(); // check errno
    }
    queue->len = 0;
}


void BlockQueue_Teardown(BlockQueue *queue)
{
    close(queue->fd);
}


Bool BlockQueue_Dequeue(BlockQueue *queue, void **data)
{
    if (!queue->len) {
        *data = NULL;
        return False;
    }

    struct kevent event;
    int ret;
    ret = kevent(queue->fd, NULL, 0, &event, 1, NULL);
    if (ret == -1) {
        abort(); // failure
    }
    assert(ret == 1);
    queue->len--;

    *data = event.udata;
    return True;
}


void BlockQueue_EnqueueIO(BlockQueue *queue, const BlockIO *item, void *data)
{
    int fd = (int)item->fd;
    IOType type = item->type;
    int filter, ret;

    switch (type) {
    case IO_None:
        return;
    case IO_Read:
        filter = EVFILT_READ;
        break;
    case IO_Write:
        filter = EVFILT_WRITE;
        break;
    }

    struct kevent event;
    EV_SET(&event, fd, filter, EV_ADD | EV_ONESHOT, 0, 0, data);

    ret = kevent(queue->fd, &event, 1, NULL, 0, NULL);
    if (ret == -1) {
        abort(); // failure
    }
    queue->len++;
}

#elif defined(USE_EPOLL)

void BlockQueue_Setup(BlockQueue *queue)
{
    queue->fd = epoll_create(1);
    if (queue->fd == -1) {
        abort(); // check errno
    }
    queue->len = 0;
}


void BlockQueue_Teardown(BlockQueue *queue)
{
    close(queue->fd);
}


Bool BlockQueue_Dequeue(BlockQueue *queue, void **data)
{
    if (!queue->len) {
        *data = NULL;
        return False;
    }

    struct epoll_event event;
    int ret;
    ret = epoll_wait(queue->fd, &event, 1, -1);
    if (ret == -1) {
        abort(); // failure
    }
    assert(ret == 1);
    queue->len--;
    *data = event.data.ptr;
    return True;
}


void BlockQueue_EnqueueIO(BlockQueue *queue, const EventIO *item, void *data)
{
    int fd = (int)item->fd;
    IOType type = item->type;
    uint32_t events;

    switch (type) {
    case IO_None:
        return;
    case IO_Read:
        events = EPOLLIN;
        break;
    case IO_Write:
        events = EPOLLOUT;
        break;
    }

    struct epoll_event event;
    event.events = events | EPOLLONESHOT;
    event.data.ptr = data;

    int ret = epoll_ctl(queue->fd, EPOLL_CTL_MOD, fd, &event);
    // With epoll, ONESHOT disables the fd, not deletes it like kqueue does.
    //
    // The common case is repeated polls on the same file descriptor,
    // so try MOD before ADD. This is simpler than keeping track of
    // whether we have added the descriptor already ourselves...

    if (ret == -1 && errno == ENOENT) {
        ret = epoll_ctl(queue->fd, EPOLL_CTL_ADD, fd, &event);
        // ...If MOD fails, try ADD.
    }

    if (ret == -1) {
        abort(); // failure
    }

    queue->len++;
}

#endif


void BlockQueue_Enqueue(BlockQueue *queue, const Block *item)
{
    switch (item->type) {
    case Block_None:
        break;
    case Block_IO:
        BlockQueue_EnqueueIO(queue, &item->value.io, item->data);
        break;
    }
}


struct Global {
    BlockQueue event_queue;
    ContextQueue context_queue;
};

typedef struct Defer {
    void (*action)(Context *ctx, void *arg);
    void *arg;
} Defer;

typedef struct DeferStack {
    Defer *items;
    Int len;
    Int cap;
} DeferStack;

struct Context {
    ucontext_t uc;
    Global *global;
    Context *next;
    Context *prev;
    DeferStack deferred;
    Error panic;
};

void DeferStack_Push(Context *ctx, DeferStack *stack, const Defer *item)
{
    // TODO
}

Bool DeferStack_Pop(Context *ctx, DeferStack *stack, Defer *item)
{
    if (!stack->len) {
        return False;
    }
    stack->len--;
    *item = stack->items[stack->len];
    return True;
}


void ContextQueue_Enqueue(Context *ctx, ContextQueue *queue, Context *item)
{
    (void)ctx;

    fprintf(stderr, "> enqueue(%p, %p) { head: %p; tail %p }\n",
            queue, item, queue->head, queue->tail);

    item->prev = queue->tail;
    item->next = NULL;

    if (queue->tail) {
        queue->tail->next = item;
    } else {
        queue->head = item;
    }
    queue->tail = item;

    fprintf(stderr, "< enqueue(%p, %p) { head: %p; tail %p }\n",
            queue, item, queue->head, queue->tail);
}


void ContextQueue_Steal(Context *ctx, ContextQueue *queue, ContextQueue *other)
{
    (void)ctx;

    if (!other->head) {
        return;
    } else if (!queue->tail) {
        *queue = *other;
    } else {
        queue->tail->next = other->head;
        other->head->prev = queue->tail;
        queue->tail = other->tail;
    }
    other->head = NULL;
    other->tail = NULL;
}


Context *ContextQueue_Dequeue(Context *ctx, ContextQueue *queue)
{
    (void)ctx;

    fprintf(stderr, "> dequeue(%p) { head: %p; tail %p }\n",
            queue, queue->head, queue->tail);

    Context *item = queue->head;
    if (!item) {
        fprintf(stderr, "< dequeue(%p) = NULL { head: %p; tail %p }\n",
                queue, queue->head, queue->tail);
        return NULL;
    }

    queue->head = item->next;
    if (item->next) {
        item->next->prev = NULL;
        item->next = NULL;
    } else {
        queue->tail = NULL;
    }

    fprintf(stderr, "< dequeue(%p) = %p { head: %p; tail %p }\n",
            queue, item, queue->head, queue->tail);

    return item;
}


void Global_Setup(Global *global)
{
    *global = (Global){0};
    BlockQueue_Setup(&global->event_queue);
}


void Global_Teardown(Global *global)
{
    BlockQueue_Teardown(&global->event_queue);
}


void Context_Setup(Context *ctx)
{
    *ctx = (Context){0};
    ctx->global = malloc(sizeof(*ctx->global));
    if (!ctx->global) {
        abort();
    }
    Global_Setup(ctx->global);
}

void Context_Close(Context *ctx, int frame);

void Context_Teardown(Context *ctx)
{
    Context_Close(ctx, 0);
    Global_Teardown(ctx->global);
    free(ctx->global);
}


void Context_Enqueue(Context *ctx, Context *item)
{
    ContextQueue_Enqueue(ctx, &ctx->global->context_queue, item);
}


Context *Context_Dequeue(Context *ctx)
{
    Context *item = ContextQueue_Dequeue(ctx, &ctx->global->context_queue);

    if (!item) {
        void *data;
        if (!BlockQueue_Dequeue(&ctx->global->event_queue, &data)) {
            return NULL;
        }
        item = data;
    }

    return item;
}


void Context_Yield(Context *ctx)
{
    fprintf(stderr, "> context_yield(%p)\n", ctx);
    Context *item = Context_Dequeue(ctx);

    if (!item) {
        fprintf(stderr, "deadlock\n");
        abort(); // deadlock
    } else if (item != ctx) {
        fprintf(stderr, "< context_yield(%p) to %p\n", ctx, item);
        if (swapcontext(&ctx->uc, &item->uc) < 0) {
            abort(); // failed allocating memory
        }
    }
}


Int Context_Open(Context *ctx)
{
    return ctx->deferred.len;
}


void Context_Close(Context *ctx, Int frame)
{
    assert(ctx->deferred.len >= frame);
    while (ctx->deferred.len != frame) {
        Defer defer;
        DeferStack_Pop(ctx, &ctx->deferred, &defer);
        defer.action(ctx, defer.arg);
    }
}


Error Context_Recover(Context *ctx)
{
    Error panic = ctx->panic;
    if (panic) {
        ctx->panic = Error_None;
    }
    return panic;
}


void Context_Panic(Context *ctx, const char *fmt, ...)
{
    Context_Close(ctx, 0);
    if (ctx->panic) { // not recovered
        fprintf(stderr, "panic: %s\n", ctx->panic);
        abort();
    } else {
        // TODO: exit if no other coroutines?
        Context_Yield(ctx);
    }
}


void Context_Defer(Context *ctx, void (*action)(Context *ctx, void *arg),
                   void *arg)
{
    Defer defer = {.action = action, .arg = arg};
    DeferStack_Push(ctx, &ctx->deferred, &defer);
}



typedef struct Task {
    Context context;
    void *stack;
    size_t stack_size;
    void (*action)(Context *ctx, void *state, Error *err);
    void *state;
    Error err;
    Bool running;
    ContextQueue waiting;
} Task;


void Task_Setup(Context *ctx, Task *task, size_t stack_size)
{
    *task = (Task){0};
    task->context = *ctx;

    if (getcontext(&task->context.uc) < 0) {
        abort();
    }

    task->stack = malloc(stack_size);
    if (!task->stack) {
        abort();
    }
    task->stack_size = stack_size;

    task->context.uc.uc_stack.ss_sp = task->stack;
    task->context.uc.uc_stack.ss_size = task->stack_size;
}


void Task_Teardown(Context *ctx, void *arg)
{
    (void)ctx;
    Task *task = arg;
    free(task->stack);
}


static void taskstart(uint32_t y, uint32_t x)
{
	uint64_t z = (uint64_t)x << 32;
    z |= y;
    
    Task *task = (Task *)z;
    Context *ctx = &task->context;

    task->running = True;
    task->action(ctx, task->state, &task->err);
    task->running = False;
    ContextQueue_Steal(ctx, &ctx->global->context_queue, &task->waiting);
    Context_Yield(ctx);
}


void Task_Run(Context *ctx, Task *task,
              void (*action)(Context *ctx, void *state, Error *err),
              void *state)
{
    assert(!task->running);

    task->action = action;
    task->state = state;
    task->err = Error_None;

	uint64_t z = (uint64_t)task;
	uint32_t y = (uint32_t)z;
	uint32_t x = z >> 32;
    
    makecontext(&task->context.uc, (void (*)(void))taskstart, 2, y, x);
    Context_Enqueue(ctx, &task->context);
}


void Task_Await(Context *ctx, Task *task, Error *err)
{
    ContextQueue_Enqueue(ctx, &task->waiting, ctx);
    Context_Yield(ctx);
    *err = task->err;
}


void Context_UnblockIO(Context *ctx, Int fd, IOType type)
{
    BlockIO event = { .fd = fd, .type = type };
    BlockQueue_EnqueueIO(&ctx->global->event_queue, &event, ctx);
    Context_Yield(ctx);
}

typedef struct Socket {
    Int fd;
} Socket;

void Socket_Setup(Context *ctx, Socket *sock, int domain, int type,
                  int protocol, Error *err)
{
    *sock = (Socket){0};
    *err = Error_None;

    int fd = socket(domain, type, protocol);
    if (fd < 0) {
        Error_Setup(ctx, err, "failed allocating socket: %s",
                    strerror(errno));
    } else if (fd > Int_Max) {
        Context_Panic(ctx, "file descriptor exceeds maximum (%d)", Int_Max);
    } else {
        assert(fd != 0);
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
        sock->fd = fd;
    }
}


void Socket_Teardown(Context *ctx, void *arg)
{
    Socket *sock = arg;
    if (sock->fd) {
        close(sock->fd);
    }
}


void download(Context *ctx, void *state, Error *err)
{
    Int frame = Context_Open(ctx);

    const char *hostname = "www.unicode.org";
    // http://www.unicode.org/Public/12.0.0/data/ucd/UnicodeData.txt
    const char *message = 
        "GET /Public/12.0.0/ucd/UnicodeData.txt HTTP/1.0\r\n"
        "Host: www.unicode.org\r\n"
        "\r\n";

    struct addrinfo *res, *res0;
    struct addrinfo hints = {0};
    int ret;

    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if ((ret = getaddrinfo(hostname, "http", &hints, &res0))) {
        Error_Setup(ctx, err, "failed getting host address: %s",
                    gai_strerror(ret));
        goto Exit;
    }

    assert(res0);

    Socket sock;
    Bool has_sock = False;

    for (res = res0; res; res = res->ai_next) {
        Socket_Setup(ctx, &sock, res->ai_family, res->ai_socktype,
                     res->ai_protocol, err);
        if (*err) {
            if (!res->ai_next) {
                break;
            }
            Error_Teardown(ctx, err);
            continue;
        }

        if (connect(sock.fd, res->ai_addr, res->ai_addrlen) < 0
                && errno != EINPROGRESS) {
            Socket_Teardown(ctx, &sock);
            if (!res->ai_next) {
                Error_Setup(ctx, err, "failed connecting to host: %s",
                            strerror(errno));
                break;
            }
            continue;
        }

        Context_Defer(ctx, Socket_Teardown, &sock);
        Context_UnblockIO(ctx, sock.fd, IO_Write); // TODO: this could fail
        has_sock = True;
        break; // success
    }

    if (!has_sock) {
        assert(*err);
        goto Exit;
    }

    const char *buf = message;
    Int buf_len = (Int)strlen(message);
    Int nsend = 0;

    while (buf_len > 0) {
        while ((nsend = send(sock.fd, buf, buf_len, 0)) < 0
                    && errno == EAGAIN) {
            Context_UnblockIO(ctx, sock.fd, IO_Write);
        }
        if (nsend < 0) {
            printf("ERROR writing to socket\n");
            goto Exit;
        } else if (nsend == 0) {
            printf("partial write");
        } else {
            buf += nsend;
            buf_len -= nsend;
        }
    }

    char response[4096] = {0};
    Int total = sizeof(response)-1;
    Int bytes = 0;
    do {
        while ((bytes = recv(sock.fd, response, total, 0)) < 0
                    && errno == EAGAIN) {
            Context_UnblockIO(ctx, sock.fd, IO_Read);
        }
        if (bytes < 0) {
            printf("ERROR reading response from socket\n");
            goto Exit;
        }
        //printf("%s", response);
        memset(response, 0, sizeof(response));
        printf("bytes = %d\n", bytes);
    } while (bytes > 0);

    freeaddrinfo(res0);
    shutdown(sock.fd, 2); // 0 = stop recv; 1 = stop send; 2 = stop both
Exit:
    Context_Close(ctx, frame);
}


int main(int argc, const char **argv)
{
    (void)argc;
    (void)argv;

    Error err = Error_None;

    Context ctx;
    Context_Setup(&ctx);

    Task task;
    Task_Setup(&ctx, &task, 64 * 1024);
    Context_Defer(&ctx, Task_Teardown, &task);

    Task_Run(&ctx, &task, download, NULL);
    Task_Await(&ctx, &task, &err);

    if (err) {
        printf("error: %s\n", err);
        Error_Teardown(&ctx, &err);
    }

    Context_Teardown(&ctx);

    return EXIT_SUCCESS;
}
