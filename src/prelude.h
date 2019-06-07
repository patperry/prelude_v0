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


typedef struct Task {
    Block block;
    bool (*_blocked)(Context *ctx, struct Task *task);
} Task;

bool task_blocked(Context *ctx, Task *task);
bool task_advance(Context *ctx, Task *task);
void task_await(Context *ctx, Task *task);

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
typedef struct {
    int _dummy;
} Stream;


typedef struct {
    Task task;
    Stream *stream;
    void *buffer;
    int length;
    int nread;
} Read;

void read_init(Context *ctx, Read *req, Stream *stream,
               void *buffer, int length);
void read_reinit(Context *ctx, Read *req, Stream *stream,
                 void *buffer, int length);
void read_deinit(Context *ctx, Read *req);


/**@}*/

/**
 * \defgroup tcp TCP Streams
 */

typedef struct {
    Stream stream;
    int fd;
} Tcp;

void tcp_init(Context *ctx, Tcp *tcp, int domain);
void tcp_deinit(Context *ctx, Tcp *sock);


typedef struct {
    Task task;
    Tcp *tcp;
    const struct sockaddr *address;
    int address_len;
    bool started;
} TcpConnect;

void tcpconnect_init(Context *ctx, TcpConnect *req, Tcp *tcp,
                     const struct sockaddr *address, int address_len);
void tcpconnect_deinit(Context *ctx, TcpConnect *conn);


typedef struct {
    Task task;
    Tcp *tcp;
    int how;
} TcpShutdown;

void tcpshutdown_init(Context *ctx, TcpShutdown *req, Tcp *tcp,
                      int how);
void tcpshutdown_deinit(Context *ctx, TcpShutdown *req);

/**@}*/

/**
 * \defgroup tls Transport Layer Security
 */

typedef enum {
    TLSFILE_PEM,
    TLSFILE_ASN1
} TlsFileType;

typedef enum {
    TLSMETHOD_NONE = 0,
    TLSMETHOD_SERVER,
    TLSMETHOD_CLIENT
} TlsMethod;

typedef struct {
    void *_ssl_ctx;
} TlsContext;

void tlscontext_init(Context *ctx, TlsContext *tls, TlsMethod method);
void tlscontext_deinit(Context *ctx, TlsContext *tls);
void tlscontext_certificate_file(Context *ctx, TlsContext *tls,  
                                 const char *file, TlsFileType type);
void tlscontext_privatekey_file(Context *ctx, TlsContext *tls,  
                                const char *file, TlsFileType type);



/**
 * \defgroup dns DNS utilities
 */

struct addrinfo;

typedef struct {
    Task task;
    const char *node;
    const char *service;
    const struct addrinfo *hints;
    struct addrinfo *result;
} GetAddrInfo;

void getaddrinfo_init(Context *ctx, GetAddrInfo *req, const char *node,
                      const char *service, const struct addrinfo *hints);
void getaddrinfo_deinit(Context *ctx, GetAddrInfo *req);

/**@}*/

#endif /* PRELUDE_H */
