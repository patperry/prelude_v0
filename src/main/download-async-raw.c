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

typedef struct EventQueue {
    int handle;
    int count;
} EventQueue;

typedef enum {
    EVENT_NONE = 0,
    EVENT_IO,
} EventType;

typedef struct EventIO {
    int fd;
    IOType type;
} EventIO;

typedef struct Event {
    EventType type;
    union {
        EventIO io;
    } value;
    void *udata;
} Event;

void eventqueue_init(EventQueue *queue);
void eventqueue_deinit(EventQueue *queue);
bool eventqueue_dequeue(EventQueue *queue, void **udata);
void eventqueue_enqueue_io(EventQueue *queue, const EventIO *item, void *udata);


#if defined(USE_KQUEUE)

void eventqueue_init(EventQueue *queue)
{
    queue->handle = kqueue();
    if (queue->handle == -1) {
        abort(); // check errno
    }
    queue->count = 0;
}


void eventqueue_deinit(EventQueue *queue)
{
    close(queue->handle);
}


bool eventqueue_dequeue(EventQueue *queue, void **udata)
{
    if (!queue->count) {
        *udata = NULL;
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

    *udata = event.udata;
    return true;
}


void eventqueue_enqueue_io(EventQueue *queue, const EventIO *item, void *udata)
{
    int fd = item->fd;
    IOType type = item->type;
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

    struct kevent event;
    EV_SET(&event, fd, filter, EV_ADD | EV_ONESHOT, 0, 0, udata);

    ret = kevent(queue->handle, &event, 1, NULL, 0, NULL);
    if (ret == -1) {
        abort(); // failure
    }
    queue->count++;
}

#elif defined(USE_EPOLL)

void eventqueue_init(EventQueue *queue)
{
    queue->handle = epoll_create(1);
    if (queue->handle == -1) {
        abort(); // check errno
    }
    queue->count = 0;
}


void eventqueue_deinit(EventQueue *queue)
{
    close(queue->handle);
}


bool eventqueue_dequeue(EventQueue *queue, void **udata)
{
    if (!queue->count) {
        *udata = NULL;
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
    *udata = event.data.ptr;
    return true;
}


void eventqueue_enqueue_io(EventQueue *queue, const EventIO *item, void *udata)
{
    int fd = item->fd;
    IOType type = item->type;
    uint32_t events;

    switch (type) {
    case IO_NONE:
        return;
    case IO_READ:
        events = EPOLLIN;
        break;
    case IO_WRITE:
        events = EPOLLOUT;
        break;
    }

    struct epoll_event event;
    event.events = events | EPOLLONESHOT;
    event.data.ptr = udata;

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


void eventqueue_enqueue(EventQueue *queue, const Event *item)
{
    switch (item->type) {
    case EVENT_NONE:
        break;
    case EVENT_IO:
        eventqueue_enqueue_io(queue, &item->value.io, item->udata);
        break;
    }
}


struct Global {
    EventQueue event_queue;
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


void contextqueue_steal(Context *ctx, ContextQueue *queue, ContextQueue *other)
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


Context *contextqueue_dequeue(Context *ctx, ContextQueue *queue)
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


void global_init(Global *global)
{
    memset(global, 0, sizeof(*global));
    eventqueue_init(&global->event_queue);
}


void global_deinit(Global *global)
{
    eventqueue_deinit(&global->event_queue);
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
        void *udata;
        if (!eventqueue_dequeue(&ctx->global->event_queue, &udata)) {
            return NULL;
        }
        item = udata;
    }

    return item;
}


void context_yield(Context *ctx)
{
    fprintf(stderr, "> context_yield(%p)\n", ctx);
    Context *item = context_dequeue(ctx);

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


void task_init(Context *ctx, Task *task, size_t stack_size)
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


void task_deinit(Context *ctx, Task *task)
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
    contextqueue_steal(ctx, &ctx->global->context_queue, &task->waiting);
    context_yield(ctx);
}


void task_run(Context *ctx, Task *task,
              void (*action)(Context *ctx, void *state), void *state)
{
    assert(!task->running);

    task->action = action;
    task->state = state;

	uint64_t z = (uint64_t)task;
	uint32_t y = (uint32_t)z;
	uint32_t x = z >> 32;
    
    makecontext(&task->context.uc, (void (*)(void))taskstart, 2, y, x);
    context_enqueue(ctx, &task->context);
}


void task_await(Context *ctx, Task *task)
{
    contextqueue_enqueue(ctx, &task->waiting, ctx);
    context_yield(ctx);
}


void unblock_io(Context *ctx, int fd, IOType type)
{
    EventIO event = { .fd = fd, .type = type };
    eventqueue_enqueue_io(&ctx->global->event_queue, &event, ctx);
    context_yield(ctx);
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

        unblock_io(ctx, sockfd, IO_WRITE);

        printf("success!\n");
        break; // success
    }

    const char *buf = message;
    int buf_len = (int)strlen(message);
    int nsend = 0;

    while (buf_len > 0) {
        while ((nsend = send(sockfd, buf, buf_len, 0)) < 0
                    && errno == EAGAIN) {
            unblock_io(ctx, sockfd, IO_WRITE);
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
            unblock_io(ctx, sockfd, IO_READ);
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
    context_init(&ctx);

    Task task;
    task_init(&ctx, &task, 64 * 1024);
    task_run(&ctx, &task, download, NULL);
    task_await(&ctx, &task);

    //download(&ctx, NULL);
    task_deinit(&ctx, &task);
    context_deinit(&ctx);

    return EXIT_SUCCESS;
}
