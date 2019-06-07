#include <assert.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "prelude.h"

static int ssl_filetype(TlsFileType type);

static void context_ssl_panic(Context *ctx, const char *format, ...)
    __attribute__ ((format (printf, 2, 3)));

static bool Initialized; // TODO: thread safe?


void tlscontext_init(Context *ctx, TlsContext *tls, TlsMethod method)
{
    memory_clear(ctx, tls, sizeof(*tls));
    if (ctx->error)
        return;

    if (!Initialized) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        Initialized = true;
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
