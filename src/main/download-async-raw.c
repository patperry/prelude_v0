#define _XOPEN_SOURCE
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>

#include <poll.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

typedef struct Block Block;

typedef enum {
    IO_NONE = 0,
    IO_READ,
    IO_WRITE
} IOType;

typedef struct Global Global;
typedef struct Context Context;
typedef struct ContextQueue ContextQueue;

struct ContextQueue {
    Context *head;
    Context *tail;
};

struct Global {
    int event_queue;
    int event_queue_count;
    ContextQueue context_queue;
};

struct Context {
    ucontext_t uc;
    Global *global;
    Context *next;
    Context *prev;
};


void contextqueue_enqueue(Context *ctx, ContextQueue *queue, Context *item)
{

    item->prev = queue->tail;
    item->next = NULL;
    queue->tail->next = item;
    queue->tail = item;
}


void contextqueue_steal(Context *ctx, ContextQueue *queue, ContextQueue *other)
{
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


Context *contextqueue_dequeue(Context *ctx, ContextQueue *queue)
{
    Context *item = queue->head;
    if (!item) {
        return NULL;
    }

    queue->head = item->next;
    if (item->next) {
        item->next->prev = NULL;
        item->next = NULL;
    } else {
        queue->tail = NULL;
    }

    return item;
}


void global_init(Global *global)
{
    memset(global, 0, sizeof(*global));
    global->event_queue = kqueue();
    if (global->event_queue < -1) {
        abort(); // check errno
    }
}


void global_deinit(Global *global)
{
    close(global->event_queue);
}


void context_init(Context *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->global = malloc(sizeof(*ctx->global));
    if (!ctx->global) {
        abort();
    }
    global_init(ctx->global);
}


void context_deinit(Context *ctx)
{
    global_deinit(ctx->global);
    free(ctx->global);
}


void context_enqueue(Context *ctx, Context *item)
{
    contextqueue_enqueue(ctx, &ctx->global->context_queue, item);
}


Context *context_dequeue(Context *ctx)
{
    Context *item = contextqueue_dequeue(ctx, &ctx->global->context_queue);

    if (!item) {
        if (!ctx->global->event_queue_count) {
            return NULL;
        }
        struct	kevent tevent;
        int ret;
        ret = kevent(ctx->global->event_queue, NULL, 0, &tevent, 1, NULL);
        if (ret == -1) {
            abort(); // failure
        }
        assert(ret == 1);
        ctx->global->event_queue_count--;
        item = tevent.udata;
    }

    return item;
}


void context_yield(Context *ctx)
{
    Context *item = context_dequeue(ctx);

    if (!item) {
        abort(); // deadlock
    } else if (item != ctx) {
        if (swapcontext(&ctx->uc, &item->uc) < 0) {
            abort(); // failed allocating memory
        }
    }
}


typedef struct Task {
    Context context;
    void *stack;
    size_t stack_size;
    void (*action)(void *state);
    void *state;
    bool running;
    ContextQueue waiting;
} Task;


void task_init(Context *ctx, Task *task, size_t stack_size)
{
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


void task_deinit(Context *ctx, Task *task)
{
    free(task->stack);
}


static void taskstart(uint32_t y, uint32_t x)
{
	uint64_t z = (uint64_t)x << 32;
    z |= y;
    
    Task *task = (Task *)z;
    task->running = true;
    task->action(task->state);
    task->running = false;
    Context *ctx = &task->context;
    contextqueue_steal(ctx, &ctx->global->context_queue, &task->waiting);
    context_yield(ctx);
}


void task_run(Context *ctx, Task *task, void (*action)(void *state),
              void *state)
{
    assert(!task->running);

    task->action = action;
    task->state = state;

	uint64_t z = (uint64_t)task;
	uint32_t y = (uint32_t)z;
	uint32_t x = z >> 32;
    
    makecontext(&task->context.uc, taskstart, 2, y, x);
    context_enqueue(ctx, &task->context);
}


void task_await(Context *ctx, Task *task)
{
    contextqueue_enqueue(ctx, &task->waiting, ctx);
    context_yield(ctx);
}


void unblock_io(Context *ctx, int fd, IOType type)
{
    int filter, ret;

    switch (type) {
    case IO_NONE:
        return;
    case IO_READ:
        filter = EVFILT_READ;
        break;
    case IO_WRITE:
        filter = EVFILT_WRITE;
        break;
    }

    struct	kevent event;
    EV_SET(&event, fd, filter, EV_ADD | EV_ONESHOT, 0, 0, ctx);

    ret = kevent(ctx->global->event_queue, &event, 1, NULL, 0, NULL);
    if (ret == -1) {
        abort(); // failure
    }
    ctx->global->event_queue_count++;
    context_yield(ctx);
}


int main(int argc, const char **argv)
{
    (void)argc;
    (void)argv;

    int err = 0;
    const char *hostname = "www.unicode.org";
    // http://www.unicode.org/Public/12.0.0/data/ucd/UnicodeData.txt
    const char *message = 
        "GET /Public/12.0.0/ucd/UnicodeData.txt HTTP/1.1\r\n"
        "Host: www.unicode.org\r\n"
        "\r\n";

    struct addrinfo *res, *res0;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if ((err = getaddrinfo(hostname, "http", &hints, &res0))) {
        printf("error %s", gai_strerror(err));
        // error
    }

    int sockfd = -1;
    for (res = res0; res; res = res->ai_next) {
        sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sockfd < 0) {
            // socket failed
            continue;
        }

        if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
            // connect failed
            close(sockfd);
            sockfd = -1;
            continue;
        }

        printf("success!\n");
        break; // success
    }

    send(sockfd, message, strlen(message), 0);

    char response[4096];
    memset(response, 0, sizeof(response));
    int total = sizeof(response)-1;
    int bytes = 0;
    do {
        bytes = recv(sockfd, response, total, 0);
        if (bytes < 0)
            printf("ERROR reading response from socket");
        printf("%s", response);
        memset(response, 0, sizeof(response));
        printf("bytes = %d\n", bytes);
    } while (bytes > 0);

    freeaddrinfo(res0);
    shutdown(sockfd, 2); // 0 = stop recv; 1 = stop send; 2 = stop both
    close(sockfd);

    return 0;
}
