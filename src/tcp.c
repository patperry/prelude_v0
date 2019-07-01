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

static bool tcpconnect_blocked(Context *ctx, Task *task);
static bool tcpshutdown_blocked(Context *ctx, Task *task);
static bool tcpread_blocked(Context *ctx, Task *task);
static bool tcpwrite_blocked(Context *ctx, Task *task);
static bool tcpstarttls_blocked(Context *ctx, Task *task);

static void tcpread_init(Context *ctx, Read *req, void *stream, void *buffer,
                         int length);
static void tcpread_reset(Context *ctx, Read *req, void *buffer, int length);
static void tcpread_deinit(Context *ctx, Read *req);

static void tcpwrite_init(Context *ctx, Write *req, void *stream, void *buffer,
                          int length);
static void tcpwrite_reset(Context *ctx, Write *req, void *buffer, int length);
static void tcpwrite_deinit(Context *ctx, Write *req);

static bool OpenSSL_Initialized = false; // TODO: thread safe?

static StreamType TcpStreamImpl = {
    tcpread_init,
    tcpread_reset,
    tcpread_deinit,
    tcpwrite_init,
    tcpwrite_reset,
    tcpwrite_deinit
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


void tlscontext_init(Context *ctx, TlsContext *tls, TlsMethod method)
{
    memory_clear(ctx, tls, sizeof(*tls));
    if (ctx->error)
        return;

    if (!OpenSSL_Initialized) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        OpenSSL_Initialized = true;
    }

    const SSL_METHOD *ssl_method;
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



void tcp_init(Context *ctx, Tcp *tcp, int domain)
{
    memory_clear(ctx, tcp, sizeof(*tcp));
    tcp->stream.type = &TcpStreamImpl;
    tcp->fd = -1;
    tcp->tls = NULL;

    if (ctx->error) {
        return;
    }

    tcp->fd = socket(domain, SOCK_STREAM, IPPROTO_TCP);
    if (tcp->fd < 0) {
        int status = errno;
        context_panic(ctx, error_code(status),
                      "failed opening tcp: %s", strerror(status));
    }

    int flags = fcntl(tcp->fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(tcp->fd, F_SETFL, flags | O_NONBLOCK); // ignore error
    }
}


void tcp_deinit(Context *ctx, Tcp *tcp)
{
    (void)ctx;
    if (tcp->fd >= 0)
        close(tcp->fd);
}


void tcpconnect_init(Context *ctx, TcpConnect *req, Tcp *tcp,
                     const struct sockaddr *address, int address_len)
{
    assert(address_len >= 0);
    memory_clear(ctx, req, sizeof(*req));
    req->task._blocked = tcpconnect_blocked;
    req->tcp = tcp;
    req->address = address;
    req->address_len = address_len;
    req->started = false;
}


void tcpconnect_deinit(Context *ctx, TcpConnect *req)
{
    (void)ctx;
    (void)req;
}


bool tcpconnect_blocked(Context *ctx, Task *task)
{
    if (ctx->error)
        return false;

    TcpConnect *req = (TcpConnect *)task;

    if (connect(req->tcp->fd, req->address,
                (socklen_t)req->address_len) < 0) {
        int status = errno;

        if (!req->started) {
            if (status == EINPROGRESS) {
                req->task.block.type = BLOCK_IO;
                req->task.block.job.io.fd = req->tcp->fd;
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


void tcpshutdown_init(Context *ctx, TcpShutdown *req, Tcp *tcp,
                         int how)
{
    memset(req, 0, sizeof(*req));
    if (ctx->error)
        return;

    req->task._blocked = tcpshutdown_blocked;
    req->tcp = tcp;
    req->how = how;
}


void tcpshutdown_deinit(Context *ctx, TcpShutdown *req)
{
    (void)ctx;
    (void)req;
}


bool tcpshutdown_blocked(Context *ctx, Task *task)
{
    if (ctx->error)
        return false;

    TcpShutdown *req = (TcpShutdown *)task;
    if (shutdown(req->tcp->fd, req->how) < 0) {
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


void tcpread_init(Context *ctx, Read *req, void *stream,
                  void *buffer, int length)
{
    assert(length >= 0);

    memory_clear(ctx, req, sizeof(*req));
    req->stream = stream;
    if (ctx->error)
        return;

    req->task._blocked = tcpread_blocked;
    tcpread_reset(ctx, req, buffer, length);
}


void tcpread_reset(Context *ctx, Read *req, void *buffer, int length)
{
    assert(length >= 0);

    if (ctx->error)
        return;

    req->buffer = buffer;
    req->length = length;
    req->nread = 0;
}


void tcpread_deinit(Context *ctx, Read *req)
{
    (void)ctx;
    (void)req;
}


void tcpwrite_init(Context *ctx, Write *req, void *stream,
                   void *buffer, int length)
{
    memset(req, 0, sizeof(*req));
    req->stream = stream;
    if (ctx->error)
        return;

    req->task._blocked = tcpwrite_blocked;
    tcpwrite_reset(ctx, req, buffer, length);
}


void tcpwrite_reset(Context *ctx, Write *req, void *buffer, int length)
{
    assert(length >= 0);

    if (ctx->error)
        return;

    req->buffer = buffer;
    req->length = length;
    req->nwrite = 0;
}


void tcpwrite_deinit(Context *ctx, Write *req)
{
    (void)ctx;
    (void)req;
}


bool tcpread_blocked(Context *ctx, Task *task)
{
    if (ctx->error)
        return false;

    Read *req = (Read *)task;
    Tcp *tcp = container_of(req->stream, Tcp, stream);

    if (req->length == 0) {
        return false;
    }

    int nrecv = (int)recv(tcp->fd, req->buffer, (size_t)req->length, 0);

    if (nrecv < 0) {
        int status = errno;
        if (status == EAGAIN || status == EWOULDBLOCK || status == EINTR) {
            req->task.block.type = BLOCK_IO;
            req->task.block.job.io.fd = tcp->fd;
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


bool tcpwrite_blocked(Context *ctx, Task *task)
{
    if (ctx->error)
        return false;

    Write *req = (Write *)task;
    Tcp *tcp = container_of(req->stream, Tcp, stream);
    
    const void *buffer = (const char *)req->buffer + req->nwrite;
    int length = req->length - req->nwrite;

    if (length == 0) {
        return false;
    }

    int nsend = (int)send(tcp->fd, buffer, (size_t)length, 0);

    if (nsend < 0) {
        int status = errno;
        if (status == EAGAIN || status == EWOULDBLOCK || status == EINTR) {
            req->task.block.type = BLOCK_IO;
            req->task.block.job.io.fd = tcp->fd;
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


void tcpstarttls_init(Context *ctx, TcpStartTls *req, Tcp *tcp,
                      TlsContext *tls, TlsMethod method)
{
    memory_clear(ctx, req, sizeof(*req));
    req->task._blocked = tcpstarttls_blocked;
    req->tcp = tcp;
    req->tls = tls;
    req->method = method;
}


void tcpstarttls_deinit(Context *ctx, TcpStartTls *req)
{
    (void)ctx;
    (void)req;
}


bool tcpstarttls_blocked(Context *ctx, Task *task)
{
    if (ctx->error)
        return false;

    TcpStartTls *req = (TcpStartTls *)task;
    Tcp *tcp = req->tcp;
    SSL *ssl = tcp->_ssl;
    if (!ssl) {
        log_debug(ctx, "creating new SSL");
        ssl = SSL_new(req->tls->_ssl_ctx); // TODO: error check
        SSL_set_fd(ssl, tcp->fd); // TODO: error check
        tcp->_ssl = ssl;
    }

    log_debug(ctx, "starting SSL handshake");

    int ret = SSL_do_handshake(ssl);
    int status = SSL_get_error(ssl, ret);

    switch (status) {
    case SSL_ERROR_NONE:
        log_debug(ctx, "SSL handshake completed");
        req->task.block.type = BLOCK_NONE;
        return false;

    case SSL_ERROR_WANT_READ:
        log_debug(ctx, "SSL handshake requires read");
        req->task.block.type = BLOCK_IO;
        req->task.block.job.io.fd = tcp->fd;
        req->task.block.job.io.flags = IO_READ;
        return true;

    case SSL_ERROR_WANT_WRITE:
        log_debug(ctx, "SSL handshake requires write");
        req->task.block.type = BLOCK_IO;
        req->task.block.job.io.fd = tcp->fd;
        req->task.block.job.io.flags = IO_WRITE;
        return true;

    default:
        log_debug(ctx, "SSL handshake failed");
        context_ssl_panic(ctx, "failed performing TLS handshake");
        req->task.block.type = BLOCK_NONE;
        return false;
    }
}
