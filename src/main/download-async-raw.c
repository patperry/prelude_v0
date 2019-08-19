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

typedef size_t Size;
#define Size_None 0
#define Size_Max SIZE_MAX

typedef char *Error;
#define Error_None NULL

typedef struct Runtime Runtime;
typedef struct Task Task;
typedef struct TaskQueue TaskQueue;

void Panic(const char *fmt, ...);
#define Assert(x) assert(x) /* TODO: replace with Panic */

void Defer(void (*func)(void *arg), void *arg);
void Trap(void (*func)(void *arg), void *arg);

void *Alloc(Size n);
void *Realloc(void *ptr, Size from, Size to);
void Free(void *ptr, Size n);

typedef struct Memory {
    void *ptr;
    Size size;
} Memory;

void Memory_Setup(Memory *mem, Size size) {
    mem->ptr = Alloc(size);
    mem->size = size;
}

void Memory_Teardown(void *arg) {
    Memory *mem = arg;
    Free(mem->ptr, mem->size);
}

enum {
    Array_Init = 32
};


Int Array_NextCap(Size elt, Int cap, Int buf) {
    Assert(cap >= 0);
    Assert(buf >= 0);

    if (elt == 0 || buf == 0) {
        return cap;
    }

    if (cap > Int_Max - buf) {
        Panic("required array capacity exceeds maximum (%d)", Int_Max);
        return Int_None;
    }

    Int min = cap + buf;
    if ((Size)min > Size_Max / elt) {
        Panic("required array capacity exceeds maximum (%zu)", Size_Max / elt);
        return Int_None;
    }

    if (cap == 0) {
        cap = Array_Init;
    }

    while (cap < min) {
        if (cap > Int_Max / 2) {
            return min;
        }
        cap *= 2;
    }

    if ((Size)cap > Size_Max / elt) {
        return min;
    }

    return cap;
}


void *Array_Grow(void *ptr, Size elt, Int *cap, Int buf) {
    Int n = *cap;
    Int n1 = Array_NextCap(elt, n, buf);
    void *ptr1 = Realloc(ptr, elt * n, elt * n1);
    *cap = n1;
    return ptr1;
}


void *Alloc(Size n) {
    return Realloc(NULL, 0, n);
}

void Free(void *ptr, Size n) {
    Realloc(ptr, n, 0);
}

void *Realloc(void *ptr, Size from, Size to) {
    if (to == 0) {
        free(ptr);
        return NULL;
    }

    ptr = realloc(ptr, to);
    if (!ptr) {
        Panic("failed allocating %zu bytes", to);
    }

    return ptr;
}

void Error_Setup(Error *err, const char *fmt, ...) {
    // TODO
    (void)err;
    (void)fmt;
}


void Error_Teardown(Error *err)
{
    // TODO
    (void)err;
}


typedef enum {
    IO_None = 0,
    IO_Read,
    IO_Write
} IOType;


struct TaskQueue {
    Task *head;
    Task *tail;
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
        Panic("failed setting up kqueue: %s", strerror(errno));
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
        Panic("failed removing event from kqueue: %s", strerror(errno));
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
        Panic("failed adding event to kqueue: %s", strerror(errno));
    }
    queue->len++;
}

#elif defined(USE_EPOLL)

void BlockQueue_Setup(BlockQueue *queue)
{
    queue->fd = epoll_create(1);
    if (queue->fd == -1) {
        Panic("failed setting up epoll: %s", strerror(errno));
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
        Panic("failed waiting for epoll event: %s", strerror(errno));
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
        Panic("failed adding epoll event: %s", strerror(errno));
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


struct Runtime {
    BlockQueue event_queue;
    TaskQueue task_queue;
    Task *current_task;
};


typedef struct Finalizer {
    void (*func)(void *arg);
    void *arg;
    Bool trap;
} Finalizer;

typedef struct FinalizerStack {
    Finalizer *items;
    Int len;
    Int cap;
} FinalizerStack;

typedef struct IntStack {
    Int *items;
    Int len;
    Int cap;
} IntStack;


typedef struct Task {
    ucontext_t uc;

    void *stack;
    Size stack_cap;

    void (*action)(void *state, Error *err);
    void *state;

    FinalizerStack finalizers;
    IntStack opens;
    Error panic;
    Error err;

    Bool running;
    TaskQueue waiting;
    Task *next;
    Task *prev;
} Task;


static Runtime runtime;
static Task main_task;

void FinalizerStack_Setup(FinalizerStack *stack)
{
    *stack = (FinalizerStack){0};
}

void FinalizerStack_Teardown(void *arg)
{
    FinalizerStack *stack = arg;
    Free(stack->items, stack->cap * sizeof(*stack->items));
}

void FinalizerStack_Reserve(FinalizerStack *stack, Int n)
{
    Assert(n >= 0);
    Int buf = n - (stack->cap - stack->len);
    if (buf > 0) {
        stack->items = Array_Grow(stack->items, sizeof(*stack->items),
                                  &stack->cap, buf);
    }
}

void FinalizerStack_Push(FinalizerStack *stack, Finalizer item)
{
    FinalizerStack_Reserve(stack, 1);
    stack->items[stack->len++] = item;
}

Bool FinalizerStack_Pop(FinalizerStack *stack, Finalizer *item)
{
    if (!stack->len) {
        return False;
    }
    stack->len--;
    *item = stack->items[stack->len];
    return True;
}

void IntStack_Setup(IntStack *stack)
{
    *stack = (IntStack){0};
}

void IntStack_Teardown(void *arg)
{
    IntStack *stack = arg;
    Free(stack->items, stack->cap * sizeof(*stack->items));
}

void IntStack_Reserve(IntStack *stack, Int n)
{
    Assert(n >= 0);
    Int buf = n - (stack->cap - stack->len);
    if (buf > 0) {
        stack->items = Array_Grow(stack->items, sizeof(*stack->items),
                                  &stack->cap, buf);
    }
}

void IntStack_Push(IntStack *stack, Int item)
{
    IntStack_Reserve(stack, 1);
    stack->items[stack->len++] = item;
}

Bool IntStack_Pop(IntStack *stack, Int *item)
{
    if (!stack->len) {
        return False;
    }
    stack->len--;
    *item = stack->items[stack->len];
    return True;
}

void TaskQueue_Enqueue(TaskQueue *queue, Task *item)
{
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


void TaskQueue_Steal(TaskQueue *queue, TaskQueue *other)
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


Task *TaskQueue_Dequeue(TaskQueue *queue)
{
    fprintf(stderr, "> dequeue(%p) { head: %p; tail %p }\n",
            queue, queue->head, queue->tail);

    Task *item = queue->head;
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


void Initialize(void)
{
    runtime = (Runtime){0};
    BlockQueue_Setup(&runtime.event_queue);
    runtime.current_task = &main_task;
}


void Finalize(void)
{
    BlockQueue_Teardown(&runtime.event_queue);
}


void Close(void);


static void Schedule(Task *task)
{
    TaskQueue_Enqueue(&runtime.task_queue, task);
}


void Yield(void)
{
    fprintf(stderr, "> Yield(%p)\n", runtime.current_task);

    Task *task = TaskQueue_Dequeue(&runtime.task_queue);

    if (!task) {
        void *data;
        if (BlockQueue_Dequeue(&runtime.event_queue, &data)) {
            task = data;
        }
    }

    if (!task) {
        Panic("deadlock: no tasks waiting");
    }

    Task *current = runtime.current_task;
    if (task != current) {
        fprintf(stderr, "< context_yield(%p) to %p\n", current, task);
        runtime.current_task = task;
        int ret = swapcontext(&current->uc, &task->uc);
        if (ret < 0) {
            runtime.current_task = current;
            Panic("failed yielding to task:"
                  " insufficient stack space (%zu bytes)",
                  task->stack_cap);
        }
        assert(runtime.current_task == current);
    }
}


void Open(void) {
    Int open = runtime.current_task->finalizers.len;
    IntStack_Push(&runtime.current_task->opens, open);
}


void Close(void) {
    Assert(runtime.current_task->opens.len);

    FinalizerStack *finalizers = &runtime.current_task->finalizers;

    Int open;
    IntStack_Pop(&runtime.current_task->opens, &open);
    
    Assert(runtime.current_task->finalizers.len >= open);
    while (finalizers->len != open) {
        Finalizer action;
        FinalizerStack_Pop(finalizers, &action);
        if (!action.trap) {
            action.func(action.arg);
        }
    }
}


Error Recover(void)
{
    Error panic = runtime.current_task->panic;
    if (panic) {
        runtime.current_task->panic = Error_None;
    }
    return panic;
}


void Panic(const char *fmt, ...)
{
    FinalizerStack *finalizers = &runtime.current_task->finalizers;
    
    while (finalizers->len != 0) {
        Finalizer action;
        FinalizerStack_Pop(finalizers, &action);
        action.func(action.arg);
    }
    
    Error panic = runtime.current_task->panic;
    if (panic) { // not recovered
        fprintf(stderr, "panic: %s\n", panic);
        abort();
    } else {
        // TODO: exit if no other coroutines?
        Yield();
    }
}


void Defer(void (*func)(void *arg), void *arg) {
    Finalizer action = {.func = func, .arg = arg, .trap = False};
    FinalizerStack_Push(&runtime.current_task->finalizers, action);
    FinalizerStack_Reserve(&runtime.current_task->finalizers, 1);
}


void Trap(void (*func)(void *arg), void *arg) {
    Finalizer action = {.func = func, .arg = arg, .trap = True};
    FinalizerStack_Push(&runtime.current_task->finalizers, action);
    FinalizerStack_Reserve(&runtime.current_task->finalizers, 1);
}


void Task_Setup(Task *task, Size stack_cap)
{
    Open();

    *task = (Task){0};

    if (getcontext(&task->uc) < 0) {
        Panic("failed getting thread context: %s", strerror(errno));
    }

    Memory stack;
    Memory_Setup(&stack, stack_cap);
    Trap(Memory_Teardown, &stack);

    task->stack = stack.ptr;
    task->stack_cap = stack_cap;
    task->uc.uc_stack.ss_sp = task->stack;
    task->uc.uc_stack.ss_size = task->stack_cap;

    FinalizerStack_Setup(&task->finalizers);
    Trap(FinalizerStack_Teardown, &task->finalizers);

    IntStack_Setup(&task->opens);
    Trap(IntStack_Teardown, &task->opens);

    FinalizerStack_Reserve(&task->finalizers, 1);

    Close();
}


void Task_Teardown(void *arg)
{
    Task *task = arg;
    IntStack_Teardown(&task->opens);
    FinalizerStack_Teardown(&task->finalizers);
    Free(task->stack, task->stack_cap);
}


static void task_run(uint32_t y, uint32_t x)
{
	uint64_t z = (uint64_t)x << 32;
    z |= y;
    
    Task *task = (Task *)z;

    task->running = True;
    task->action(task->state, &task->err);
    task->running = False;
    TaskQueue_Steal(&runtime.task_queue, &task->waiting);
    Yield();
}


void Task_Run(Task *task, void (*action)(void *state, Error *err),
              void *state)
{
    assert(!task->running);

    task->action = action;
    task->state = state;
    task->err = Error_None;

	uint64_t z = (uint64_t)task;
	uint32_t y = (uint32_t)z;
	uint32_t x = z >> 32;
    
    makecontext(&task->uc, (void (*)(void))task_run, 2, y, x);
    Schedule(task);
}


void Task_Await(Task *task, Error *err)
{
    TaskQueue_Enqueue(&task->waiting, task);
    Yield();
    *err = task->err;
}


void UnblockIO(Int fd, IOType type)
{
    BlockIO event = {.fd = fd, .type = type};
    BlockQueue_EnqueueIO(&runtime.event_queue, &event, runtime.current_task);
    Yield();
}

typedef struct Socket {
    Int fd;
} Socket;

void Socket_Setup(Socket *sock, int domain, int type, int protocol,
                  Error *err) {
    *sock = (Socket){0};
    *err = Error_None;

    int fd = socket(domain, type, protocol);
    if (fd < 0) {
        Error_Setup(err, "failed allocating socket: %s", strerror(errno));
    } else {
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
        sock->fd = fd;
    }
}


void Socket_Teardown(void *arg) {
    Socket *sock = arg;
    close(sock->fd);
}


void download(void *state, Error *err) {
    Open();

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
        Error_Setup(err, "failed getting host address: %s",
                    gai_strerror(ret));
        goto Exit;
    }

    assert(res0);

    Socket sock;
    Bool has_sock = False;

    for (res = res0; res; res = res->ai_next) {
        Socket_Setup(&sock, res->ai_family, res->ai_socktype,
                     res->ai_protocol, err);
        if (*err) {
            if (!res->ai_next) {
                break;
            }
            Error_Teardown(err);
            continue;
        }

        if (connect(sock.fd, res->ai_addr, res->ai_addrlen) < 0
                && errno != EINPROGRESS) {
            Socket_Teardown(&sock);
            if (!res->ai_next) {
                Error_Setup(err, "failed connecting to host: %s",
                            strerror(errno));
                break;
            }
            continue;
        }

        Defer(Socket_Teardown, &sock);
        UnblockIO(sock.fd, IO_Write); // TODO: this could fail
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
            UnblockIO(sock.fd, IO_Write);
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
            UnblockIO(sock.fd, IO_Read);
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
    Close();
    (void)state;
}


int main(int argc, const char **argv)
{
    (void)argc;
    (void)argv;

    Error err = Error_None;
    Initialize();
    Open();

    Task task;
    Task_Setup(&task, 64 * 1024);
    Defer(Task_Teardown, &task);

    Task_Run(&task, download, NULL);
    Task_Await(&task, &err);

    if (err) {
        printf("error: %s\n", err);
        Error_Teardown(&err);
    }

    Close();
    Finalize();

    return EXIT_SUCCESS;
}
