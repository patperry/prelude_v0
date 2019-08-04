#ifndef PRELUDE_H
#define PRELUDE_H

/**
 * \file prelude.h
 *
 * Data environment.
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* https://stackoverflow.com/a/10269766/6233565 */
#define container_of(ptr, type, member) \
    ((type *) (void *)((char *)(void *)(ptr) - offsetof(type, member)))


/**
 * \defgroup context Session context
 * @{
 */

#define CONTEXT_MESSAGE_MAX 1024

typedef enum {
    ERROR_NONE = 0,
    ERROR_MEMORY,
    ERROR_OVERFLOW,
    ERROR_VALUE,
    ERROR_OS
} Error;

Error error_code(int errnum);


typedef enum {
    LOG_NONE = 0,
    LOG_DEBUG,
    LOG_INFO
} LogType;

typedef void* (*AllocFunc)(void *buf, size_t old_size, size_t new_size,
                           void *data);

typedef void (*LogFunc)(LogType log, const char *message, void *data);

typedef struct {
    Error error;
    const char *message;

    AllocFunc _alloc;
    LogFunc _log;
    void *_alloc_data;
    void *_log_data;
    char _buffer0[CONTEXT_MESSAGE_MAX];
    char _buffer1[CONTEXT_MESSAGE_MAX];
} Context;

void *default_alloc(void *buf, size_t old_size, size_t new_size, void *data);
void default_log(LogType log, const char *message, void *data);

void context_init(Context *ctx, AllocFunc alloc, void *alloc_data,
                  LogFunc log, void *log_data);
void context_deinit(Context *ctx);

void context_panic(Context *ctx, Error error, const char *format, ...)
    __attribute__ ((format (printf, 3, 4)));
void context_recover(Context *ctx);
void context_code(Context *ctx, int errnum);


/**@}*/

/**
 * \defgroup log Logging
 * @{
 */

void log_debug(Context *ctx, const char *format, ...)
    __attribute__ ((format (printf, 2, 3)));
void log_info(Context *ctx, const char *format, ...)
    __attribute__ ((format (printf, 2, 3)));

/**@}*/

/**
 * \defgroup memory Memory
 * @{
 */

/* memory */
void *memory_alloc(Context *ctx, size_t size);
void *memory_realloc(Context *ctx, void *buf, size_t old_size,
                     size_t new_size);
void memory_free(Context *ctx, void *buf, size_t size);

void memory_clear(Context *ctx, void *buf, size_t size);
bool memory_equal(Context *ctx, const void *buf1, const void *buf2,
                  size_t size);

void *memory_find(Context *ctx, const void *buf, size_t buf_len,
                  const void *search, size_t search_len);

void memory_copy(Context *ctx, void *buf, const void *src, size_t size);

/**@}*/

/**
 * \defgroup async Asynchronous Operations
 * @{
 */

typedef enum {
    IO_READ = 1 << 0,
    IO_WRITE = 1 << 1
} IOFlag;

typedef struct {
    int fd;
    IOFlag flags;
} BlockIO;

typedef struct {
    int millis;
} BlockTimer;

typedef enum {
    BLOCK_NONE = 0,
    BLOCK_IO,
    BLOCK_TIMER
} BlockType;

typedef struct {
    union {
        BlockIO io;
        BlockTimer timer;
    } job;
    BlockType type;
} Block;


typedef struct TaskPart {
    Block block;
    bool (*_blocked)(Context *ctx, struct TaskPart *taskpart);
} TaskPart;

bool taskpart_blocked(Context *ctx, TaskPart *taskpart);
bool taskpart_advance(Context *ctx, TaskPart *taskpart);
void taskpart_await(Context *ctx, TaskPart *taskpart);

/**@}*/

/**
 * \defgroup array Dynamic Array
 * @{
 */

void array_reserve(Context *ctx, void **pbase, size_t width,
                   int32_t *pcapacity, int32_t count, int32_t extra);

/**@}*/

/**
 * \defgroup char Character (Unicode)
 * @{
 */

/**
 * ASCII character code unit
 */
typedef int8_t Char8;

#define CHAR8_NONE -1
#define CHAR8_MAX 0x7F

/**
 * Unicode code unit (UTF-32)
 */
typedef int32_t Char32;

#define CHAR32_NONE -1
#define CHAR32_MAX 0x10FFFF

/** Number of code units in the UTF-8 encoding of a code point. */
#define CHAR32_UTF8_COUNT(u) \
    ((u) <= 0x7F    ? 1 : \
     (u) <= 0x07FF  ? 2 : \
     (u) <= 0xFFFF  ? 3 : 4)

/** Indicates whether a 16-bit code unit is a UTF-16 high surrogate.
 *  High surrogates are in the range 0xD800 `(1101 1000 0000 0000)`
 *  to 0xDBFF `(1101 1011 1111 1111)`. */
#define CHAR32_ISHIGH(x) (((x) & 0xFC00) == 0xD800)

/** Indicates whether a 16-bit code unit is a UTF-16 low surrogate.
 *  Low surrogates are in the range 0xDC00 `(1101 1100 0000 0000)`
 *  to 0xDFFF `(1101 1111 1111 1111)`. */
#define CHAR32_ISLOW(x) (((x) & 0xFC00) == 0xDC00)

/** Given the high and low UTF-16 surrogates, compute the unicode codepoint. */
#define CHAR32_DECODE_HIGHLOW(h, l) \
	(((((h) & 0x3FF) << 10) | ((l) & 0x3FF)) + 0x10000)

/**
 * Scan over the first code point in a UTF-8 buffer, updating `*pptr` to
 * point past the encoded code point.
 *
 * Fails with ERROR_VALUE for invalid UTF-8.
 */
const uint8_t *char_scan_utf8(Context *ctx, const uint8_t *ptr,
                              const uint8_t *end);

/**
 * Scan a JSON-style backslash (\\) escape.
 *
 * Fails with ERROR_VALUE for invalid UTF-8 or invalid escape code.
 */
const uint8_t *char_scan_escape(Context *ctx, const uint8_t *ptr,
                                const uint8_t *end);

/**
 * Decode the first code point from a UTF-8 character buffer, without
 * validating the input.
 */ 
Char32 char_decode_utf8(Context *ctx, const uint8_t **pptr);

/**
 * Decode a JSON-style backslash (\\) escape, without validating the input.
 */
Char32 char_decode_escape(Context *ctx, const uint8_t **pptr);

/**
 * Encode a code point into UTF-8. Writes `UTF8_LEN(code)` bytes and
 * updates `pptr`.
 */
void char_encode_utf8(Context *ctx, Char32 code, uint8_t **pptr);

/**
 * Character width type.
 */
typedef enum {
    CHARWIDTH_NONE = 0,    /**< Control and other */
    CHARWIDTH_IGNORABLE,   /**< Default ignorable */
    CHARWIDTH_MARK,        /**< Zero-width mark or format */
    CHARWIDTH_NARROW,      /**< Most western alphabets */
    CHARWIDTH_AMBIGUOUS,   /**< Width depends on context */
    CHARWIDTH_WIDE,        /**< Most ideographs */
    CHARWIDTH_EMOJI        /**< Emoji presentation */
} CharWidthType;

/**
 * Width of a code point, from the East Asian Width table and
 * the Emoji data.
 */
CharWidthType char_width(Context *ctx, Char32 code);

/**
 * Whether a code point is a default ignorable character.
 */
bool char_isignorable(Context *ctx, Char32 code);

/**
 * Unicode character decomposition and case mappings.
 *
 * Compatibility mappings are defined in
 * [UAX #44 Sec. 5.7.3 Character Decomposition Maps]
 * (http://www.unicode.org/reports/tr44/#Character_Decomposition_Mappings).
 *
 * Case folding mappings are defined in *TR44* Sec. 5.6.
 */
typedef enum {
	CHARMAP_DECOMP = 0,            /**< normal decompositions (for NFD) */
	CHARMAP_FONT = (1 << 0),       /**< font variant */
	CHARMAP_NOBREAK = (1 << 1),    /**< no-break version of space or hyphen */
	CHARMAP_INITIAL = (1 << 2),    /**< initial presentation form (Arabic) */
	CHARMAP_MEDIAL = (1 << 3),     /**< medial presentation form (Arabic) */
	CHARMAP_FINAL = (1 << 4),      /**< final presentation form (Arabic) */
	CHARMAP_ISOLATED = (1 << 5),   /**< isolated presentation form (Arabic) */
	CHARMAP_CIRCLE = (1 << 6),     /**< encircled form */
	CHARMAP_SUPER = (1 << 7),      /**< superscript form */
	CHARMAP_SUB = (1 << 8),        /**< subscript form */
	CHARMAP_VERTICAL = (1 << 9),   /**< vertical layout presentation form */
	CHARMAP_WIDE = (1 << 10),      /**< wide (or zenkaku) compat */
	CHARMAP_NARROW = (1 << 11),    /**< narrow (or hankaku) compat */
	CHARMAP_SMALL = (1 << 12),     /**< small variant form (CNS compat) */
	CHARMAP_SQUARE = (1 << 13),    /**< CJK squared font variant */
	CHARMAP_FRACTION = (1 << 14),  /**< vulgar fraction form */
	CHARMAP_UNSPECIFIED = (1 << 15),/**< unspecified compatibility */
	CHARMAP_COMPAT = ((1 << 16) - 1),/**< all compatibility maps (for NFKD) */

	CHARMAP_RMDI = (1 << 16),      /**< remove default ignorables */
	CHARMAP_CASEFOLD = (1 << 17)   /**< perform full case folding */
} CharMapType;

/**
 * Maximum size (in code points) of a single code point's decomposition.
 *
 * From *TR44* Sec. 5.7.3: "Compatibility mappings are guaranteed to be no
 * longer than 18 characters, although most consist of just a few characters."
 */
#define CHAR_MAP_MAX 18

/**
 * Apply decomposition and/or casefold mapping to a code point,
 * writing the output to the specified buffer, and return a pointer past
 * the output. The output will be at most #CHAR_MAP_MAX code points.
 */
void char_map(Context *ctx, CharMapType type, Char32 code, Char32 **pbuf);

/**
 * Apply the canonical ordering algorithm to put an array of code points
 * into normal order. See *Unicode* Sec 3.11 and *TR44* Sec. 5.7.4.
 */
void chars_order(Context *ctx, Char32 *codes, int count);

/**
 * Apply the canonical composition algorithm to put an array of
 * canonically-ordered Unicode code points into composed form. This
 * shrinks or preserves the number of code points.
 */
void chars_compose(Context *ctx, Char32 *codes, int *pcount);

/**@}*/


/**
 * \defgroup text Text (character sequences)
 * @{
 */

typedef struct {
    const uint8_t *bytes;
    unsigned int unescape : 1;
    unsigned int size     : 31;
} Text;

typedef enum {
	TEXTVIEW_UTF8 = 0,
	TEXTVIEW_UNESCAPE = (1 << 0)
} TextViewType;

void text_view(Context *ctx, Text *text, TextViewType flags,
               const uint8_t *bytes, size_t size);

bool text_equal(Context *ctx, const Text *text1, const Text *text2);
int32_t text_length(Context *ctx, const Text *text);

typedef struct {
    Text text;
} TextAlloc;

void textalloc_init(Context *ctx, TextAlloc *obj, const Text *text);
void textalloc_deinit(Context *ctx, TextAlloc *obj);

/**
 * Iterator over the decoded UTF-32 code points in a text.
 */
typedef struct {
	const uint8_t *ptr;
	const uint8_t *end;
	bool unescape;
	Char32 current;
} TextIter;

void textiter_init(Context *ctx, TextIter *it, const Text *text);
void textiter_copy(Context *ctx, TextIter *it, const TextIter *src);
void textiter_deinit(Context *ctx, TextIter *it);

bool textiter_advance(Context *ctx, TextIter *it);

/**
 * Text building buffer.
 */
typedef struct {
    uint8_t *bytes;
    int32_t count;
    int32_t capacity;
} TextBuild;

void textbuild_init(Context *ctx, TextBuild *build);
void textbuild_clear(Context *ctx, TextBuild *build);
void textbuild_deinit(Context *ctx, TextBuild *build);

void textbuild_text(Context *ctx, TextBuild *build, const Text *text);
void textbuild_char(Context *ctx, TextBuild *build, Char32 code);
Text textbuild_get(Context *ctx, TextBuild *build);


typedef struct {
    Text text;
    Char8 ascii_map[CHAR8_MAX + 1];
    Char32 *buffer;
    int32_t capacity;
    CharMapType type;
} TextMap;

/**@}*/

/**
 * \defgroup stream Streams (duplex communication channels)
 */

/* OpenSSL https://stackoverflow.com/a/16328115/6233565 */
/* https://nachtimwald.com/2014/10/06/client-side-session-cache-in-openssl/ */
/* https://nachtimwald.com/2014/10/05/server-side-session-cache-in-openssl/ */


/**@}*/

/**
 * \defgroup tls Transport Layer Security
 */

typedef enum {
    TLSFILE_NONE = 0,
    TLSFILE_PEM,
    TLSFILE_ASN1
} TlsFileType;

typedef enum {
    TLSPROTO_NONE = 0,
    TLSPROTO_DTLS,
    TLSPROTO_TLS
} TlsProto;

typedef enum {
    TLSMETHOD_NONE = 0,
    TLSMETHOD_SERVER,
    TLSMETHOD_CLIENT
} TlsMethod;

typedef struct {
    TlsProto proto;
    TlsMethod method;
    void *_ssl_ctx;
} TlsContext;

void tlscontext_init(Context *ctx, TlsContext *tls, TlsProto proto,
                     TlsMethod method);
void tlscontext_deinit(Context *ctx, TlsContext *tls);
void tlscontext_certificate_file(Context *ctx, TlsContext *tls,
                                 const char *file, TlsFileType type);
void tlscontext_privatekey_file(Context *ctx, TlsContext *tls,
                                const char *file, TlsFileType type);

/**@}*/

/**
 * \defgroup sockets
 */

typedef enum {
    SOCKET_NONE = 0,
    SOCKET_TCP,
    SOCKET_UDP
} SocketType;

typedef enum {
    IP_NONE = 0,
    IP_V4,
    IP_V6
} IpType;

typedef struct {
    uint8_t bytes[4];
} IpAddrV4;

#define IPADDRV4_ANY_INIT \
    (IpAddrV4) { \
        { 0x00, 0x00, 0x00, 0x00 } \
    }

#define IPADDRV4_LOOPBACK_INIT \
    (IpAddrV4) { \
        { 0x7f, 0x00, 0x00, 0x01 } \
    }

typedef struct {
    uint8_t bytes[16];
} IpAddrV6;

#define IPADDRV6_ANY_INIT \
    (IpAddrV6) { \
        { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } \
    }

#define IPADDRV6_LOOPBACK_INIT \
    (IpAddrV6) { \
        { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } \
    }

typedef struct {
    IpType type;
    union {
        IpAddrV4 v4;
        IpAddrV6 v6;
    } value;
} IpAddr;

typedef struct {
    IpAddrV4 ip;
    uint16_t port;
} SocketAddrV4;

typedef struct {
    IpAddrV6 ip;
    uint16_t port;
    uint32_t flowinfo;
    uint32_t scope_id;
} SocketAddrV6;

typedef struct {
    IpType type;
    union {
        SocketAddrV4 v4;
        SocketAddrV6 v6;
    } value;
} SocketAddr;

typedef struct {
    SocketType type;
    IpType family;
    int fd;
    TlsContext *tls;
    void *_ssl;
} Socket;

void socket_init(Context *ctx, Socket *sock, SocketType type, IpType family);
void socket_deinit(Context *ctx, Socket *sock);

/* TODO: setsockopt SO_REUSEADDR */
void socket_bind(Context *ctx, Socket *sock, SocketAddr *addr);
void socket_listen(Context *ctx, Socket *sock, int backlog);


typedef struct {
    TaskPart taskpart;
    Socket *sock;
    const SocketAddr *addr;
    bool started;
} SockConnect;

void sockconnect_init(Context *ctx, SockConnect *req, Socket *sock,
                      const SocketAddr *addr);
void sockconnect_deinit(Context *ctx, SockConnect *conn);


typedef struct {
    TaskPart taskpart;
    Socket *sock;
    Socket peer_sock;
    SocketAddr peer_address;
} SockAccept;

void sockaccept_init(Context *ctx, SockAccept *req, Socket *sock);
void sockaccept_deinit(Context *ctx, SockAccept *req);


typedef struct {
    TaskPart taskpart;
    Socket *sock;
} SockShutdown;

void sockshutdown_init(Context *ctx, SockShutdown *req, Socket *sock);
void sockshutdown_deinit(Context *ctx, SockShutdown *req);

typedef struct {
    TaskPart taskpart;
    Socket *sock;
    TlsContext *tls;
    TlsMethod method;
} SockStartTls;

void sockstarttls_init(Context *ctx, SockStartTls *req, Socket *sock,
                       TlsContext *tls, TlsMethod method);
void sockstarttls_deinit(Context *ctx, SockStartTls *req);

typedef struct {
    TaskPart taskpart;
    Socket *sock;
} SockStopTls;

void sockstoptls_init(Context *ctx, SockStopTls *req, Socket *sock);
void sockstoptls_deinit(Context *ctx, SockStopTls *req);

typedef struct {
    TaskPart taskpart;
    Socket *sock;
    void *buffer;
    int length;
    int nrecv;
} SockRecv;

void sockrecv_init(Context *ctx, SockRecv *req, Socket *sock, void *buffer,
                   int length);
void sockrecv_reset(Context *ctx, SockRecv *req, void *buffer, int length);
void sockrecv_deinit(Context *ctx, SockRecv *req);

typedef struct {
    TaskPart taskpart;
    Socket *sock;
    void *buffer;
    int length;
    int nsend;
} SockSend;

void socksend_init(Context *ctx, SockSend *req, Socket *sock, void *buffer,
                   int length);
void socksend_reset(Context *ctx, SockSend *req, void *buffer, int length);
void socksend_deinit(Context *ctx, SockSend *req);


/**@}*/

/**
 * \defgroup dns DNS utilities
 */

typedef struct {
    SocketType type;
    SocketAddr addr;
    const char *canonname;
} AddrInfo;

typedef struct {
    AddrInfo current;
    const void *_ai_next;
} AddrInfoIter;

bool addrinfoiter_advance(Context *ctx, AddrInfoIter *it);

typedef struct {
    TaskPart taskpart;
    AddrInfoIter result;
    const char *node;
    const char *service;
    SocketType type;
    IpType family;
    int flags;
    void *_ai;
} GetAddrInfo;

void getaddrinfo_init(Context *ctx, GetAddrInfo *req, const char *node,
                      const char *service, SocketType type, IpType family,
                      int flags);
void getaddrinfo_deinit(Context *ctx, GetAddrInfo *req);

/**@}*/

#define HTTP_HEADER_BYTES_MAX (1 << 20)

typedef struct {
    const char *key;
    const char *value;
} HttpMeta;

typedef struct {
    TaskPart taskpart;
    uint8_t *data;
    int data_len;
} HttpContent;

typedef struct {
    TaskPart taskpart;
    SockRecv recv;

    const char *start;
    int start_len;

    HttpMeta *metas;
    int meta_count;
    int meta_capacity;

    HttpMeta *headers;
    int header_count;

    HttpMeta *trailers;
    int trailer_count;

    int64_t content_length;
    int64_t content_read;
    bool content_started;

    HttpContent current;

    void *buffer;
    uint8_t *data;

    size_t buffer_len;
    size_t data_len;
    size_t data_max;
} HttpRecv;

void httprecv_init(Context *ctx, HttpRecv *req, Socket *sock);
/* void httprecv_reset(Context *ctx, HttpRecv *req, Socket *sock); */
void httprecv_deinit(Context *ctx, HttpRecv *req);
bool httprecv_advance(Context *ctx, HttpRecv *req);

#endif /* PRELUDE_H */
