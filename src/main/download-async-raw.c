#define _POSIX_C_SOURCE 200112L // getaddrinfo
#define _XOPEN_SOURCE // ucontext
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
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
    IO_None = 0,
    IO_Read,
    IO_Write
} IOType;

typedef struct Global Global;
typedef struct Context Context;
typedef struct ContextQueue ContextQueue;

struct ContextQueue {
    Context *head;
    Context *tail;
};

typedef struct BlockQueue {
    int handle;
    int count;
} BlockQueue;

typedef enum {
    Block_None = 0,
    Block_IO
} BlockType;

typedef struct BlockIO {
    int fd;
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
bool BlockQueue_Dequeue(BlockQueue *queue, void **data);
void BlockQueue_EnqueueIO(BlockQueue *queue, const BlockIO *item,
                            void *data);


#if defined(USE_KQUEUE)

void BlockQueue_Setup(BlockQueue *queue)
{
    queue->handle = kqueue();
    if (queue->handle == -1) {
        abort(); // check errno
    }
    queue->count = 0;
}


void BlockQueue_Teardown(BlockQueue *queue)
{
    close(queue->handle);
}


bool BlockQueue_Dequeue(BlockQueue *queue, void **data)
{
    if (!queue->count) {
        *data = NULL;
        return false;
    }

    struct kevent event;
    int ret;
    ret = kevent(queue->handle, NULL, 0, &event, 1, NULL);
    if (ret == -1) {
        abort(); // failure
    }
    assert(ret == 1);
    queue->count--;

    *data = event.udata;
    return true;
}


void BlockQueue_EnqueueIO(BlockQueue *queue, const BlockIO *item,
                            void *data)
{
    int fd = item->fd;
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

    ret = kevent(queue->handle, &event, 1, NULL, 0, NULL);
    if (ret == -1) {
        abort(); // failure
    }
    queue->count++;
}

#elif defined(USE_EPOLL)

void BlockQueue_Setup(BlockQueue *queue)
{
    queue->handle = epoll_create(1);
    if (queue->handle == -1) {
        abort(); // check errno
    }
    queue->count = 0;
}


void BlockQueue_Teardown(BlockQueue *queue)
{
    close(queue->handle);
}


bool BlockQueue_Dequeue(BlockQueue *queue, void **data)
{
    if (!queue->count) {
        *data = NULL;
        return false;
    }

    struct epoll_event event;
    int ret;
    ret = epoll_wait(queue->handle, &event, 1, -1);
    if (ret == -1) {
        abort(); // failure
    }
    assert(ret == 1);
    queue->count--;
    *data = event.data.ptr;
    return true;
}


void BlockQueue_EnqueueIO(BlockQueue *queue, const EventIO *item, void *data)
{
    int fd = item->fd;
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

    int ret = epoll_ctl(queue->handle, EPOLL_CTL_MOD, fd, &event);
    // With epoll, ONESHOT disables the fd, not deletes it like kqueue does.
    //
    // The common case is repeated polls on the same file descriptor,
    // so try MOD before ADD. This is simpler than keeping track of
    // whether we have added the descriptor already ourselves...

    if (ret == -1 && errno == ENOENT) {
        ret = epoll_ctl(queue->handle, EPOLL_CTL_ADD, fd, &event);
        // ...If MOD fails, try ADD.
    }

    if (ret == -1) {
        abort(); // failure
    }

    queue->count++;
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

struct Context {
    ucontext_t uc;
    Global *global;
    Context *next;
    Context *prev;
};


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
    memset(global, 0, sizeof(*global));
    BlockQueue_Setup(&global->event_queue);
}


void Global_Teardown(Global *global)
{
    BlockQueue_Teardown(&global->event_queue);
}


void Context_Setup(Context *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->global = malloc(sizeof(*ctx->global));
    if (!ctx->global) {
        abort();
    }
    Global_Setup(ctx->global);
}


void Context_Teardown(Context *ctx)
{
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


typedef struct Task {
    Context context;
    void *stack;
    size_t stack_size;
    void (*action)(Context *ctx, void *state);
    void *state;
    bool running;
    ContextQueue waiting;
} Task;


void Task_Setup(Context *ctx, Task *task, size_t stack_size)
{
    memset(task, 0, sizeof(*task));

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


void Task_Teardown(Context *ctx, Task *task)
{
    (void)ctx;
    free(task->stack);
}


static void taskstart(uint32_t y, uint32_t x)
{
	uint64_t z = (uint64_t)x << 32;
    z |= y;
    
    Task *task = (Task *)z;
    Context *ctx = &task->context;

    task->running = true;
    task->action(ctx, task->state);
    task->running = false;
    ContextQueue_Steal(ctx, &ctx->global->context_queue, &task->waiting);
    Context_Yield(ctx);
}


void Task_Run(Context *ctx, Task *task,
              void (*action)(Context *ctx, void *state), void *state)
{
    assert(!task->running);

    task->action = action;
    task->state = state;

	uint64_t z = (uint64_t)task;
	uint32_t y = (uint32_t)z;
	uint32_t x = z >> 32;
    
    makecontext(&task->context.uc, (void (*)(void))taskstart, 2, y, x);
    Context_Enqueue(ctx, &task->context);
}


void Task_Await(Context *ctx, Task *task)
{
    ContextQueue_Enqueue(ctx, &task->waiting, ctx);
    Context_Yield(ctx);
}


void Context_UnblockIO(Context *ctx, int fd, IOType type)
{
    BlockIO event = { .fd = fd, .type = type };
    BlockQueue_EnqueueIO(&ctx->global->event_queue, &event, ctx);
    Context_Yield(ctx);
}


void download(Context *ctx, void *state)
{
    (void)state;

    int err = 0;
    const char *hostname = "www.unicode.org";
    // http://www.unicode.org/Public/12.0.0/data/ucd/UnicodeData.txt
    const char *message = 
        "GET /Public/12.0.0/ucd/UnicodeData.txt HTTP/1.0\r\n"
        "Host: www.unicode.org\r\n"
        "\r\n";

    struct addrinfo *res, *res0;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if ((err = getaddrinfo(hostname, "http", &hints, &res0))) {
        printf("ERROR %s\n", gai_strerror(err));
        return;
    }

    int sockfd = -1;
    for (res = res0; res; res = res->ai_next) {
        sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sockfd < 0) {
            // socket failed
            continue;
        }
        fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK);

        if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0
                && errno != EINPROGRESS) {
            // connect failed
            close(sockfd);
            sockfd = -1;
            continue;
        }

        Context_UnblockIO(ctx, sockfd, IO_Write);

        printf("success!\n");
        break; // success
    }

    const char *buf = message;
    int buf_len = (int)strlen(message);
    int nsend = 0;

    while (buf_len > 0) {
        while ((nsend = send(sockfd, buf, buf_len, 0)) < 0
                    && errno == EAGAIN) {
            Context_UnblockIO(ctx, sockfd, IO_Write);
        }
        if (nsend < 0) {
            printf("ERROR writing to socket\n");
            return;
        } else if (nsend == 0) {
            printf("partial write");
        } else {
            buf += nsend;
            buf_len -= nsend;
        }
    }

    char response[4096];
    memset(response, 0, sizeof(response));
    int total = sizeof(response)-1;
    int bytes = 0;
    do {
        while ((bytes = recv(sockfd, response, total, 0)) < 0
                    && errno == EAGAIN) {
            Context_UnblockIO(ctx, sockfd, IO_Read);
        }
        if (bytes < 0) {
            printf("ERROR reading response from socket\n");
            return;
        }
        //printf("%s", response);
        memset(response, 0, sizeof(response));
        printf("bytes = %d\n", bytes);
    } while (bytes > 0);

    freeaddrinfo(res0);
    shutdown(sockfd, 2); // 0 = stop recv; 1 = stop send; 2 = stop both
    close(sockfd);

}


int main(int argc, const char **argv)
{
    (void)argc;
    (void)argv;

    Context ctx;
    Context_Setup(&ctx);

    Task task;
    Task_Setup(&ctx, &task, 64 * 1024);
    Task_Run(&ctx, &task, download, NULL);
    Task_Await(&ctx, &task);

    Task_Teardown(&ctx, &task);
    Context_Teardown(&ctx);

    return EXIT_SUCCESS;
}
