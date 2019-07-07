#include <assert.h>
#include <errno.h>
#include <string.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "prelude.h"

static int ssl_filetype(TlsFileType type);
static void context_ssl_panic(Context *ctx, const char *format, ...)
    __attribute__ ((format (printf, 2, 3)));

static bool sockconnect_blocked(Context *ctx, Task *task);
static bool sockshutdown_blocked(Context *ctx, Task *task);
static bool sockread_blocked(Context *ctx, Task *task);
static bool sockreadtls_blocked(Context *ctx, Task *task);
static bool sockwrite_blocked(Context *ctx, Task *task);
static bool sockwritetls_blocked(Context *ctx, Task *task);
static bool sockstarttls_blocked(Context *ctx, Task *task);

static void sockread_init(Context *ctx, Read *req, void *stream, void *buffer,
                         int length);
static void sockread_reset(Context *ctx, Read *req, void *buffer, int length);
static void sockread_deinit(Context *ctx, Read *req);

static void sockwrite_init(Context *ctx, Write *req, void *stream, void *buffer,
                          int length);
static void sockwrite_reset(Context *ctx, Write *req, void *buffer, int length);
static void sockwrite_deinit(Context *ctx, Write *req);

static bool OpenSSL_Initialized = false; // TODO: thread safe?

static StreamType SockStreamImpl = {
    sockread_init,
    sockread_reset,
    sockread_deinit,
    sockwrite_init,
    sockwrite_reset,
    sockwrite_deinit
};


void context_ssl_panic(Context *ctx, const char *format, ...)
{
    unsigned long err = ERR_get_error();
    ERR_clear_error();

    char ssl_msg[256];
    ERR_error_string_n(err, ssl_msg, sizeof(ssl_msg));

    char buffer[CONTEXT_MESSAGE_MAX];
    va_list ap;
    va_start(ap, format);
    vsnprintf(buffer, sizeof(buffer), format, ap);
    va_end(ap);

    context_panic(ctx, ERROR_OS, "%s: %s", buffer, ssl_msg);
}


int ssl_filetype(TlsFileType type)
{
    switch (type) {
    case TLSFILE_ASN1:
        return SSL_FILETYPE_ASN1;
    case TLSFILE_PEM:
        return SSL_FILETYPE_PEM;
    default:
        assert(0);
        return -1;
    }
}


void tlscontext_init(Context *ctx, TlsContext *tls, TlsProto proto,
                     TlsMethod method)
{
    memory_clear(ctx, tls, sizeof(*tls));
    if (ctx->error)
        return;

    tls->proto = proto;
    tls->method = method;
    if (!tls->proto)
        return;

    if (!OpenSSL_Initialized) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        OpenSSL_Initialized = true;
    }

    const SSL_METHOD *ssl_method;
    if (proto == TLSPROTO_DTLS) {
        switch (method) {
        case TLSMETHOD_NONE:
            ssl_method = DTLS_method();
            break;
        case TLSMETHOD_SERVER:
            ssl_method = DTLS_server_method();
            break;
        case TLSMETHOD_CLIENT:
            ssl_method = DTLS_client_method();
            break;
        }
    } else {
        switch (method) {
        case TLSMETHOD_NONE:
            ssl_method = TLS_method();
            break;
        case TLSMETHOD_SERVER:
            ssl_method = TLS_server_method();
            break;
        case TLSMETHOD_CLIENT:
            ssl_method = TLS_client_method();
            break;
        }
    }

    SSL_CTX *ssl_ctx = SSL_CTX_new(ssl_method);
    if (!ssl_ctx) {
        context_ssl_panic(ctx, "failed opening TLS context");
        return;
    }

    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    tls->_ssl_ctx = ssl_ctx;
}


void tlscontext_deinit(Context *ctx, TlsContext *tls)
{
    (void)ctx;
    if (tls->_ssl_ctx)
        SSL_CTX_free(tls->_ssl_ctx);
}


void tlscontext_certificate_file(Context *ctx, TlsContext *tls,  
                                 const char *file, TlsFileType type)
{
    if (ctx->error)
        return;

    SSL_CTX *ssl_ctx = tls->_ssl_ctx;
    int ssl_type = ssl_filetype(type); 
    if (!SSL_CTX_use_certificate_file(ssl_ctx, file, ssl_type)) {
        context_ssl_panic(ctx, "failed loading certificate file \"%s\"",
                          file);
        return;
    }
}


void tlscontext_privatekey_file(Context *ctx, TlsContext *tls,  
                                const char *file, TlsFileType type)
{
    if (ctx->error)
        return;

    SSL_CTX *ssl_ctx = tls->_ssl_ctx;
    int ssl_type = ssl_filetype(type); 
    if (!SSL_CTX_use_PrivateKey_file(ssl_ctx, file, ssl_type)) {
        context_ssl_panic(ctx, "failed loading private key file \"%s\"",
                          file);
        return;
    }

    // TODO: SSL_CTX_check_private_key next?
}



void socket_init(Context *ctx, Socket *sock, SocketType type, int family)
{
    memory_clear(ctx, sock, sizeof(*sock));
    sock->type = type;
    sock->stream.type = &SockStreamImpl;
    sock->fd = -1;
    sock->tls = NULL;

    if (ctx->error) {
        return;
    }

    int socket_type;
    int protocol;

    switch (type) {
    case SOCKET_TCP:
        socket_type = SOCK_STREAM;
        protocol = IPPROTO_TCP;
        break;

    case SOCKET_UDP:
        socket_type = SOCK_DGRAM;
        protocol = IPPROTO_UDP;
        break;

    default:
        return;
    }

    sock->fd = socket(family, socket_type, protocol);
    if (sock->fd < 0) {
        int status = errno;
        context_panic(ctx, error_code(status),
                      "failed opening sock: %s", strerror(status));
    }

    int flags = fcntl(sock->fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(sock->fd, F_SETFL, flags | O_NONBLOCK); // ignore error
    }
}


void socket_deinit(Context *ctx, Socket *sock)
{
    (void)ctx;

    if (sock->_ssl)
        SSL_free(sock->_ssl);

    if (sock->fd >= 0)
        close(sock->fd);
}


void sockconnect_init(Context *ctx, SockConnect *req, Socket *sock,
                     const struct sockaddr *address, int address_len)
{
    assert(address_len >= 0);
    memory_clear(ctx, req, sizeof(*req));
    req->task._blocked = sockconnect_blocked;
    req->sock = sock;
    req->address = address;
    req->address_len = address_len;
    req->started = false;
}


void sockconnect_deinit(Context *ctx, SockConnect *req)
{
    (void)ctx;
    (void)req;
}


bool sockconnect_blocked(Context *ctx, Task *task)
{
    if (ctx->error)
        return false;

    SockConnect *req = (SockConnect *)task;

    if (connect(req->sock->fd, req->address,
                (socklen_t)req->address_len) < 0) {
        int status = errno;

        if (!req->started) {
            if (status == EINPROGRESS) {
                req->task.block.type = BLOCK_IO;
                req->task.block.job.io.fd = req->sock->fd;
                req->task.block.job.io.flags = IO_WRITE;
                req->started = true;
                return true;
            }
        } else if (status == EALREADY || status == EINTR) {
            return true;
        } else if (status == EISCONN) {
            goto exit;
        }

        assert(status);
        context_code(ctx, status);
        context_panic(ctx, ctx->error, "failed connecting to peer: %s",
                      ctx->message);
    }

exit:
    req->task.block.type = BLOCK_NONE;
    return false;
}


void sockshutdown_init(Context *ctx, SockShutdown *req, Socket *sock)
{
    memset(req, 0, sizeof(*req));
    if (ctx->error)
        return;

    req->task._blocked = sockshutdown_blocked;
    req->sock = sock;
}


void sockshutdown_deinit(Context *ctx, SockShutdown *req)
{
    (void)ctx;
    (void)req;
}


bool sockshutdown_blocked(Context *ctx, Task *task)
{
    if (ctx->error)
        return false;

    SockShutdown *req = (SockShutdown *)task;
    Socket *sock = req->sock;

    if (sock->_ssl) {
        SSL *ssl = sock->_ssl;

        log_debug(ctx, "sending TLS close notify");
        int ret = SSL_shutdown(ssl);

        if (ret < 0) {
            int status = SSL_get_error(ssl, ret);
            switch (status) {
            case SSL_ERROR_WANT_READ:
                log_debug(ctx, "TLS close notify requires read");
                req->task.block.type = BLOCK_IO;
                req->task.block.job.io.fd = sock->fd;
                req->task.block.job.io.flags = IO_READ;
                return true;

            case SSL_ERROR_WANT_WRITE:
                log_debug(ctx, "TLS close notify requires write");
                req->task.block.type = BLOCK_IO;
                req->task.block.job.io.fd = sock->fd;
                req->task.block.job.io.flags = IO_WRITE;
                return true;

            default:
                log_debug(ctx, "TLS close notify failed");
                context_ssl_panic(ctx, "failed closing TLS session");
                req->task.block.type = BLOCK_NONE;
                return false;
            }
        } else {
            log_debug(ctx, "TLS close notify sent");
            SSL_free(ssl);
            sock->_ssl = NULL;
        }
    }

    if (shutdown(req->sock->fd, SHUT_RDWR) < 0) {
        int status = errno;
        if (status != ENOTCONN) { // peer closed the connection
            assert(status);
            context_code(ctx, status);
            context_panic(ctx, ctx->error,
                          "failed shutting down connection to peer: %s",
                          ctx->message);
        }
    }

    return false;
}


void sockread_init(Context *ctx, Read *req, void *stream,
                  void *buffer, int length)
{
    assert(length >= 0);

    memory_clear(ctx, req, sizeof(*req));
    req->stream = stream;
    if (ctx->error)
        return;

    Socket *sock = container_of(req->stream, Socket, stream);

    if (sock->_ssl) {
        log_debug(ctx, "reading encrypted");
        req->task._blocked = sockreadtls_blocked;
    } else {
        log_debug(ctx, "reading unencrypted");
        req->task._blocked = sockread_blocked;
    }
    sockread_reset(ctx, req, buffer, length);
}


void sockread_reset(Context *ctx, Read *req, void *buffer, int length)
{
    assert(length >= 0);

    if (ctx->error)
        return;

    req->buffer = buffer;
    req->length = length;
    req->nread = 0;
}


void sockread_deinit(Context *ctx, Read *req)
{
    (void)ctx;
    (void)req;
}


void sockwrite_init(Context *ctx, Write *req, void *stream,
                   void *buffer, int length)
{
    memset(req, 0, sizeof(*req));
    req->stream = stream;
    if (ctx->error)
        return;

    Socket *sock = container_of(req->stream, Socket, stream);
    
    if (sock->_ssl) {
        log_debug(ctx, "writing encrypted");
        req->task._blocked = sockwritetls_blocked;
    } else {
        log_debug(ctx, "writing unencrypted");
        req->task._blocked = sockwrite_blocked;
    }
    sockwrite_reset(ctx, req, buffer, length);
}


void sockwrite_reset(Context *ctx, Write *req, void *buffer, int length)
{
    assert(length >= 0);

    if (ctx->error)
        return;

    req->buffer = buffer;
    req->length = length;
    req->nwrite = 0;
}


void sockwrite_deinit(Context *ctx, Write *req)
{
    (void)ctx;
    (void)req;
}


bool sockread_blocked(Context *ctx, Task *task)
{
    if (ctx->error)
        return false;

    Read *req = (Read *)task;
    Socket *sock = container_of(req->stream, Socket, stream);

    if (req->length == 0) {
        return false;
    }

    int nrecv = (int)recv(sock->fd, req->buffer, (size_t)req->length, 0);

    if (nrecv < 0) {
        int status = errno;
        if (status == EAGAIN || status == EWOULDBLOCK || status == EINTR) {
            req->task.block.type = BLOCK_IO;
            req->task.block.job.io.fd = sock->fd;
            req->task.block.job.io.flags = IO_READ;
            return true;
        } else {
            assert(status);
            context_code(ctx, status);
            context_panic(ctx, ctx->error,
                          "failed receiving data: %s", ctx->message);
        }
    } else if (nrecv == 0) {
        context_panic(ctx, ERROR_OS,
                      "failed receiving data: connection reset by peer");
    } else {
        req->nread = nrecv;
    }

    req->task.block.type = BLOCK_NONE;
    return false;
}


bool sockreadtls_blocked(Context *ctx, Task *task)
{
    if (ctx->error)
        return false;

    Read *req = (Read *)task;
    Socket *sock = container_of(req->stream, Socket, stream);
    SSL *ssl = sock->_ssl;

    if (req->length == 0) {
        return false;
    }

    int nrecv = SSL_read(ssl, req->buffer, req->length);

    if (nrecv <= 0) {
        int status = SSL_get_error(ssl, nrecv);
        switch (status) {
        case SSL_ERROR_WANT_READ:
            log_debug(ctx, "TLS-encrypted read requires read");
            req->task.block.type = BLOCK_IO;
            req->task.block.job.io.fd = sock->fd;
            req->task.block.job.io.flags = IO_READ;
            return true;

        case SSL_ERROR_WANT_WRITE:
            log_debug(ctx, "TLS-encrypted read requires write");
            req->task.block.type = BLOCK_IO;
            req->task.block.job.io.fd = sock->fd;
            req->task.block.job.io.flags = IO_WRITE;
            return true;

        default:
            log_debug(ctx, "TLS-encrypted read failed");
            context_ssl_panic(ctx, "failed reading data");
            req->task.block.type = BLOCK_NONE;
            return false;
        }
    } else {
        log_debug(ctx, "TLS-encrypted read got %d bytes", nrecv);
        req->nread = nrecv;
    }

    req->task.block.type = BLOCK_NONE;
    return false;
}


bool sockwrite_blocked(Context *ctx, Task *task)
{
    if (ctx->error)
        return false;

    Write *req = (Write *)task;
    Socket *sock = container_of(req->stream, Socket, stream);
    
    const void *buffer = (const char *)req->buffer + req->nwrite;
    int length = req->length - req->nwrite;

    if (length == 0) {
        return false;
    }

    int nsend = (int)send(sock->fd, buffer, (size_t)length, 0);

    if (nsend < 0) {
        int status = errno;
        if (status == EAGAIN || status == EWOULDBLOCK || status == EINTR) {
            req->task.block.type = BLOCK_IO;
            req->task.block.job.io.fd = sock->fd;
            req->task.block.job.io.flags = IO_WRITE;
            return true;
        } else {
            assert(status);
            context_code(ctx, status);
            context_panic(ctx, ctx->error,
                          "failed sending data: %s", ctx->message);
        }
    } else {
        req->nwrite += nsend;
        if (req->nwrite < req->length) {
            return true;
        }
    }

    req->task.block.type = BLOCK_NONE;
    return false;
}


bool sockwritetls_blocked(Context *ctx, Task *task)
{
    if (ctx->error)
        return false;

    Write *req = (Write *)task;
    Socket *sock = container_of(req->stream, Socket, stream);
    SSL *ssl = sock->_ssl;
    
    const void *buffer = (const char *)req->buffer + req->nwrite;
    int length = req->length - req->nwrite;

    if (length == 0) {
        return false;
    }

    int nsend = (int)SSL_write(ssl, buffer, length);

    if (nsend <= 0) {
        int status = SSL_get_error(ssl, nsend);
        switch (status) {
        case SSL_ERROR_WANT_READ:
            log_debug(ctx, "TLS-encrypted write requires read");
            req->task.block.type = BLOCK_IO;
            req->task.block.job.io.fd = sock->fd;
            req->task.block.job.io.flags = IO_READ;
            return true;

        case SSL_ERROR_WANT_WRITE:
            log_debug(ctx, "TLS-encrypted write requires write");
            req->task.block.type = BLOCK_IO;
            req->task.block.job.io.fd = sock->fd;
            req->task.block.job.io.flags = IO_WRITE;
            return true;

        default:
            log_debug(ctx, "TLS-encrypted write failed");
            context_ssl_panic(ctx, "failed sending data");
            req->task.block.type = BLOCK_NONE;
            return false;
        }
    } else {
        log_debug(ctx, "TLS-encrypted write wrote %d bytes", nsend);
        req->nwrite += nsend;
        if (req->nwrite < req->length) {
            return true;
        }
    }

    req->task.block.type = BLOCK_NONE;
    return false;
}


void sockstarttls_init(Context *ctx, SockStartTls *req, Socket *sock,
                      TlsContext *tls, TlsMethod method)
{
    memory_clear(ctx, req, sizeof(*req));
    req->task._blocked = sockstarttls_blocked;
    req->sock = sock;
    req->tls = tls;
    req->method = method;
}


void sockstarttls_deinit(Context *ctx, SockStartTls *req)
{
    (void)ctx;
    (void)req;
}


bool sockstarttls_blocked(Context *ctx, Task *task)
{
    if (ctx->error)
        return false;

    SockStartTls *req = (SockStartTls *)task;
    Socket *sock = req->sock;
    SSL *ssl = sock->_ssl;

    if (!ssl) {
        log_debug(ctx, "creating new SSL");
        ssl = SSL_new(req->tls->_ssl_ctx); // TODO: error check
        sock->_ssl = ssl;

        SSL_set_fd(ssl, sock->fd); // TODO: error check

        switch (req->method) {
        case TLSMETHOD_SERVER:
            SSL_set_accept_state(ssl);
            break;

        case TLSMETHOD_CLIENT:
            SSL_set_connect_state(ssl);
            break;

        case TLSMETHOD_NONE:
            return false;
        }
        // TODO: error check
    }

    log_debug(ctx, "continuing TLS handshake");

    int ret = SSL_do_handshake(ssl);
    int status = SSL_get_error(ssl, ret);

    switch (status) {
    case SSL_ERROR_NONE:
        log_debug(ctx, "TLS handshake completed");
        sock->tls = req->tls;
        req->task.block.type = BLOCK_NONE;
        return false;

    case SSL_ERROR_WANT_READ:
        log_debug(ctx, "TLS handshake requires read");
        req->task.block.type = BLOCK_IO;
        req->task.block.job.io.fd = sock->fd;
        req->task.block.job.io.flags = IO_READ;
        return true;

    case SSL_ERROR_WANT_WRITE:
        log_debug(ctx, "TLS handshake requires write");
        req->task.block.type = BLOCK_IO;
        req->task.block.job.io.fd = sock->fd;
        req->task.block.job.io.flags = IO_WRITE;
        return true;

    default:
        log_debug(ctx, "TLS handshake failed");
        context_ssl_panic(ctx, "failed performing TLS handshake");
        req->task.block.type = BLOCK_NONE;
        return false;
    }
}
