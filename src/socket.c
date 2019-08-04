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

static void socketaddr_encode(const SocketAddr *addr,
                              struct sockaddr_storage *dst,
                              socklen_t *address_len);

static bool sockconnect_blocked(Context *ctx, TaskPart *taskpart);
static bool sockaccept_blocked(Context *ctx, TaskPart *taskpart);
static bool sockshutdown_blocked(Context *ctx, TaskPart *taskpart);
static bool sockrecv_blocked(Context *ctx, TaskPart *taskpart);
static bool sockrecvtls_blocked(Context *ctx, TaskPart *taskpart);
static bool socksend_blocked(Context *ctx, TaskPart *taskpart);
static bool socksendtls_blocked(Context *ctx, TaskPart *taskpart);
static bool sockstarttls_blocked(Context *ctx, TaskPart *taskpart);


static bool OpenSSL_Initialized = false; // TODO: thread safe?


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



void socket_init(Context *ctx, Socket *sock, SocketType type,
                 IpType family)
{
    memory_clear(ctx, sock, sizeof(*sock));
    sock->fd = -1;
    sock->tls = NULL;

    if (ctx->error) {
        return;
    }

    sock->type = type;
    sock->family = family;

    int socket_family;
    int socket_type;
    int protocol;

    switch (family) {
    case IP_V4:
        socket_family = PF_INET;
        break;

    case IP_V6:
        socket_family = PF_INET6;
        break;

    default:
        return;
    }

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

    sock->fd = socket(socket_family, socket_type, protocol);
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


void socket_bind(Context *ctx, Socket *sock, SocketAddr *addr)
{
    if (ctx->error)
        return;

    struct sockaddr_storage sa;
    socklen_t sa_len;
    socketaddr_encode(addr, &sa, &sa_len);

    int ret = bind(sock->fd, (const struct sockaddr *)&sa, sa_len);

    if (ret) {
        context_panic(ctx, ERROR_OS, "failed binding socket to address");
    }
}


void socket_listen(Context *ctx, Socket *sock, int backlog)
{
    if (ctx->error)
        return;

    int ret = listen(sock->fd, backlog);
    if (ret) {
        context_panic(ctx, ERROR_OS, "failed listening on socket");
    }
}


void sockconnect_init(Context *ctx, SockConnect *req, Socket *sock,
                      const SocketAddr *addr)
{
    assert(addr->type == sock->family);
    memory_clear(ctx, req, sizeof(*req));
    req->taskpart._blocked = sockconnect_blocked;
    req->sock = sock;
    req->addr = addr;
    req->started = false;
}


void sockconnect_deinit(Context *ctx, SockConnect *req)
{
    (void)ctx;
    (void)req;
}

static void socketaddrv4_encode(const SocketAddrV4 *addr,
                                struct sockaddr_in *dst)
{
    dst->sin_family = AF_INET;
    dst->sin_port = htons(addr->port);
    memcpy(&dst->sin_addr.s_addr, addr->ip.bytes, sizeof(addr->ip.bytes));
}

static void socketaddrv6_encode(const SocketAddrV6 *addr,
                                struct sockaddr_in6 *dst)
{
    dst->sin6_family = AF_INET6;
    dst->sin6_port = htons(addr->port);
    dst->sin6_flowinfo = addr->flowinfo;
    dst->sin6_scope_id = addr->scope_id;
    memcpy(&dst->sin6_addr.s6_addr, addr->ip.bytes, sizeof(addr->ip.bytes));
}

static void socketaddr_encode(const SocketAddr *addr,
                              struct sockaddr_storage *dst,
                              socklen_t *address_len)
{
    switch (addr->type) {
    case IP_V4:
        socketaddrv4_encode(&addr->value.v4, (struct sockaddr_in *)dst);
        *address_len = sizeof(struct sockaddr_in);
        break;

    case IP_V6:
        socketaddrv6_encode(&addr->value.v6, (struct sockaddr_in6 *)dst);
        *address_len = sizeof(struct sockaddr_in6);
        break;

    default:
        break;
    }
}

bool sockconnect_blocked(Context *ctx, TaskPart *taskpart)
{
    if (ctx->error)
        return false;

    SockConnect *req = (SockConnect *)taskpart;
    struct sockaddr_storage addr;
    socklen_t addr_len;

    socketaddr_encode(req->addr, &addr, &addr_len);

    if (connect(req->sock->fd, (struct sockaddr *)&addr, addr_len) < 0) {
        int status = errno;

        if (!req->started) {
            if (status == EINPROGRESS) {
                req->taskpart.block.type = BLOCK_IO;
                req->taskpart.block.job.io.fd = req->sock->fd;
                req->taskpart.block.job.io.flags = IO_WRITE;
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
    req->taskpart.block.type = BLOCK_NONE;
    return false;
}


void sockaccept_init(Context *ctx, SockAccept *req, Socket *sock)
{
    memory_clear(ctx, req, sizeof(*req));
    req->taskpart._blocked = sockaccept_blocked;
    req->sock = sock;
    req->peer_sock.fd = -1;
}


void sockaccept_deinit(Context *ctx, SockAccept *req)
{
    socket_deinit(ctx, &req->peer_sock);
}


bool sockaccept_blocked(Context *ctx, TaskPart *taskpart)
{
    if (ctx->error)
        return false;

    SockAccept *req = (SockAccept *)taskpart;
    Socket *sock = req->sock;
    struct sockaddr_storage sa;
    socklen_t sa_len;

    int fd = accept(sock->fd, (struct sockaddr *)&sa, &sa_len);
    if (fd < 0) {
        int status = errno;
        if (status != EWOULDBLOCK) {
            assert(status);
            context_code(ctx, status);
            context_panic(ctx, ctx->error,
                          "failed accepting connection: %s",
                          ctx->message);
            return false;
        } else {
            req->taskpart.block.type = BLOCK_IO;
            req->taskpart.block.job.io.fd = sock->fd;
            req->taskpart.block.job.io.flags = IO_READ;
            return true;
        }
    }

    req->peer_sock.type = sock->type;
    req->peer_sock.family = sock->family;
    req->peer_sock.fd = fd;
    return false;
}


void sockshutdown_init(Context *ctx, SockShutdown *req, Socket *sock)
{
    memset(req, 0, sizeof(*req));
    if (ctx->error)
        return;

    req->taskpart._blocked = sockshutdown_blocked;
    req->sock = sock;
}


void sockshutdown_deinit(Context *ctx, SockShutdown *req)
{
    (void)ctx;
    (void)req;
}


bool sockshutdown_blocked(Context *ctx, TaskPart *taskpart)
{
    if (ctx->error)
        return false;

    SockShutdown *req = (SockShutdown *)taskpart;
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
                req->taskpart.block.type = BLOCK_IO;
                req->taskpart.block.job.io.fd = sock->fd;
                req->taskpart.block.job.io.flags = IO_READ;
                return true;

            case SSL_ERROR_WANT_WRITE:
                log_debug(ctx, "TLS close notify requires write");
                req->taskpart.block.type = BLOCK_IO;
                req->taskpart.block.job.io.fd = sock->fd;
                req->taskpart.block.job.io.flags = IO_WRITE;
                return true;

            default:
                log_debug(ctx, "TLS close notify failed");
                context_ssl_panic(ctx, "failed closing TLS session");
                req->taskpart.block.type = BLOCK_NONE;
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


void sockrecv_init(Context *ctx, SockRecv *req, Socket *sock,
                  void *buffer, int length)
{
    assert(length >= 0);

    memory_clear(ctx, req, sizeof(*req));
    req->sock = sock;
    if (ctx->error)
        return;

    if (sock->_ssl) {
        log_debug(ctx, "reading encrypted");
        req->taskpart._blocked = sockrecvtls_blocked;
    } else {
        log_debug(ctx, "reading unencrypted");
        req->taskpart._blocked = sockrecv_blocked;
    }
    sockrecv_reset(ctx, req, buffer, length);
}


void sockrecv_reset(Context *ctx, SockRecv *req, void *buffer, int length)
{
    assert(length >= 0);

    if (ctx->error)
        return;

    req->buffer = buffer;
    req->length = length;
    req->nrecv = 0;
}


void sockrecv_deinit(Context *ctx, SockRecv *req)
{
    (void)ctx;
    (void)req;
}


void socksend_init(Context *ctx, SockSend *req, Socket *sock,
                   void *buffer, int length)
{
    memset(req, 0, sizeof(*req));
    req->sock = sock;
    if (ctx->error)
        return;
    
    if (sock->_ssl) {
        log_debug(ctx, "writing encrypted");
        req->taskpart._blocked = socksendtls_blocked;
    } else {
        log_debug(ctx, "writing unencrypted");
        req->taskpart._blocked = socksend_blocked;
    }
    socksend_reset(ctx, req, buffer, length);
}


void socksend_reset(Context *ctx, SockSend *req, void *buffer, int length)
{
    assert(length >= 0);

    if (ctx->error)
        return;

    req->buffer = buffer;
    req->length = length;
    req->nsend = 0;
}


void socksend_deinit(Context *ctx, SockSend *req)
{
    (void)ctx;
    (void)req;
}


bool sockrecv_blocked(Context *ctx, TaskPart *taskpart)
{
    if (ctx->error)
        return false;

    SockRecv *req = (SockRecv *)taskpart;
    Socket *sock = req->sock;

    if (req->length == 0) {
        return false;
    }

    int nrecv = (int)recv(sock->fd, req->buffer, (size_t)req->length, 0);

    if (nrecv < 0) {
        int status = errno;
        if (status == EAGAIN || status == EWOULDBLOCK || status == EINTR) {
            req->taskpart.block.type = BLOCK_IO;
            req->taskpart.block.job.io.fd = sock->fd;
            req->taskpart.block.job.io.flags = IO_READ;
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
        req->nrecv = nrecv;
    }

    req->taskpart.block.type = BLOCK_NONE;
    return false;
}


bool sockrecvtls_blocked(Context *ctx, TaskPart *taskpart)
{
    log_debug(ctx, "waiting on recvtls");

    if (ctx->error)
        return false;

    SockRecv *req = (SockRecv *)taskpart;
    Socket *sock = req->sock;
    SSL *ssl = sock->_ssl;

    if (req->length == 0) {
        return false;
    }

    int nrecv = SSL_read(ssl, req->buffer, req->length);

    if (nrecv <= 0) {
        int status = SSL_get_error(ssl, nrecv);
        switch (status) {
        case SSL_ERROR_WANT_READ:
            log_debug(ctx, "TLS-encrypted read requires read on fd %d",
                      sock->fd);
            req->taskpart.block.type = BLOCK_IO;
            req->taskpart.block.job.io.fd = sock->fd;
            req->taskpart.block.job.io.flags = IO_READ;
            return true;

        case SSL_ERROR_WANT_WRITE:
            log_debug(ctx, "TLS-encrypted read requires write");
            req->taskpart.block.type = BLOCK_IO;
            req->taskpart.block.job.io.fd = sock->fd;
            req->taskpart.block.job.io.flags = IO_WRITE;
            return true;

        default:
            log_debug(ctx, "TLS-encrypted read failed");
            context_ssl_panic(ctx, "failed reading data");
            req->taskpart.block.type = BLOCK_NONE;
            return false;
        }
    } else {
        log_debug(ctx, "TLS-encrypted read got %d bytes", nrecv);
        req->nrecv = nrecv;
    }

    req->taskpart.block.type = BLOCK_NONE;
    return false;
}


bool socksend_blocked(Context *ctx, TaskPart *taskpart)
{
    if (ctx->error)
        return false;

    SockSend *req = (SockSend *)taskpart;
    Socket *sock = req->sock;
    
    const void *buffer = (const char *)req->buffer + req->nsend;
    int length = req->length - req->nsend;

    if (length == 0) {
        return false;
    }

    int nsend = (int)send(sock->fd, buffer, (size_t)length, 0);

    if (nsend < 0) {
        int status = errno;
        if (status == EAGAIN || status == EWOULDBLOCK || status == EINTR) {
            req->taskpart.block.type = BLOCK_IO;
            req->taskpart.block.job.io.fd = sock->fd;
            req->taskpart.block.job.io.flags = IO_WRITE;
            return true;
        } else {
            assert(status);
            context_code(ctx, status);
            context_panic(ctx, ctx->error,
                          "failed sending data: %s", ctx->message);
        }
    } else {
        req->nsend += nsend;
        if (req->nsend < req->length) {
            return true;
        }
    }

    req->taskpart.block.type = BLOCK_NONE;
    return false;
}


bool socksendtls_blocked(Context *ctx, TaskPart *taskpart)
{
    if (ctx->error)
        return false;

    SockSend *req = (SockSend *)taskpart;
    Socket *sock = req->sock;
    SSL *ssl = sock->_ssl;
    
    const void *buffer = (const char *)req->buffer + req->nsend;
    int length = req->length - req->nsend;

    if (length == 0) {
        return false;
    }

    int nsend = (int)SSL_write(ssl, buffer, length);

    if (nsend <= 0) {
        int status = SSL_get_error(ssl, nsend);
        switch (status) {
        case SSL_ERROR_WANT_READ:
            log_debug(ctx, "TLS-encrypted write requires read");
            req->taskpart.block.type = BLOCK_IO;
            req->taskpart.block.job.io.fd = sock->fd;
            req->taskpart.block.job.io.flags = IO_READ;
            return true;

        case SSL_ERROR_WANT_WRITE:
            log_debug(ctx, "TLS-encrypted write requires write");
            req->taskpart.block.type = BLOCK_IO;
            req->taskpart.block.job.io.fd = sock->fd;
            req->taskpart.block.job.io.flags = IO_WRITE;
            return true;

        default:
            log_debug(ctx, "TLS-encrypted write failed");
            context_ssl_panic(ctx, "failed sending data");
            req->taskpart.block.type = BLOCK_NONE;
            return false;
        }
    } else {
        log_debug(ctx, "TLS-encrypted write wrote %d bytes", nsend);
        req->nsend += nsend;
        if (req->nsend < req->length) {
            return true;
        }
    }

    req->taskpart.block.type = BLOCK_NONE;
    return false;
}


void sockstarttls_init(Context *ctx, SockStartTls *req, Socket *sock,
                      TlsContext *tls, TlsMethod method)
{
    memory_clear(ctx, req, sizeof(*req));
    req->taskpart._blocked = sockstarttls_blocked;
    req->sock = sock;
    req->tls = tls;
    req->method = method;
}


void sockstarttls_deinit(Context *ctx, SockStartTls *req)
{
    (void)ctx;
    (void)req;
}


bool sockstarttls_blocked(Context *ctx, TaskPart *taskpart)
{
    if (ctx->error)
        return false;

    SockStartTls *req = (SockStartTls *)taskpart;
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
        req->taskpart.block.type = BLOCK_NONE;
        return false;

    case SSL_ERROR_WANT_READ:
        log_debug(ctx, "TLS handshake requires read");
        req->taskpart.block.type = BLOCK_IO;
        req->taskpart.block.job.io.fd = sock->fd;
        req->taskpart.block.job.io.flags = IO_READ;
        return true;

    case SSL_ERROR_WANT_WRITE:
        log_debug(ctx, "TLS handshake requires write");
        req->taskpart.block.type = BLOCK_IO;
        req->taskpart.block.job.io.fd = sock->fd;
        req->taskpart.block.job.io.flags = IO_WRITE;
        return true;

    default:
        log_debug(ctx, "TLS handshake failed");
        context_ssl_panic(ctx, "failed performing TLS handshake");
        req->taskpart.block.type = BLOCK_NONE;
        return false;
    }
}
