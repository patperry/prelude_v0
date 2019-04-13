#ifndef PRELUDE_H
#define PRELUDE_H

/**
 * \file prelude.h
 *
 * Data environment.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * \defgroup context Session context
 * @{
 */

#define CONTEXT_BUFFER_MAX 1024

typedef enum {
    ERROR_NONE = 0,
    ERROR_MEMORY,
    ERROR_OVERFLOW,
    ERROR_VALUE,
} Error;

typedef enum {
    LOG_NONE = 0,
    LOG_DEBUG,
    LOG_INFO
} Log;

typedef void* (*AllocFunc)(void *buf, size_t old_size, size_t new_size,
                            void *data);

typedef void (*LogFunc)(Log log, const char *message, void *data);

typedef struct {
    char buffer[CONTEXT_BUFFER_MAX];
    AllocFunc alloc;
    LogFunc log;
    void *alloc_data;
    void *log_data;
    Error error;
} Context;

void context_init(Context *ctx, AllocFunc alloc, void *alloc_data,
                  LogFunc log, void *log_data);
void context_deinit(Context *ctx);

/* errors */
Error context_panic(Context *ctx, Error error, const char *format, ...)
    __attribute__ ((format (printf, 3, 4)));
void context_recover(Context *ctx);
Error context_error(Context *ctx);
const char *context_message(Context *ctx);

/* memory */
void *context_alloc(Context *ctx, size_t size);
void *context_realloc(Context *ctx, void *buf, size_t old_size,
                      size_t new_size);
void context_free(Context *ctx, void *buf, size_t size);

/* logging */
void context_debug(Context *ctx, const char *format, ...)
    __attribute__ ((format (printf, 2, 3)));
void context_info(Context *ctx, const char *format, ...)
    __attribute__ ((format (printf, 2, 3)));

/**@}*/

/**
 * \defgroup buffer Memory buffer
 * @{
 */

Error buffer_reserve(Context *ctx, void **pbuf, size_t width,
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
#define UTF8_COUNT(u) \
    ((u) <= 0x7F    ? 1 : \
     (u) <= 0x07FF  ? 2 : \
     (u) <= 0xFFFF  ? 3 : 4)

/**
 * Scan over the first code point in a UTF-8 buffer, updating `*pptr` to
 * point past the encoded code point.
 *
 * Returns ERROR_VALUE for invalid UTF-8.
 */
Error char_scan(Context *ctx, const uint8_t **pptr, const uint8_t *end);

/**
 * Decode the first code point from a UTF-8 character buffer, without
 * validating the input.
 */ 
Char32 char_decode(Context *ctx, const uint8_t *pptr);

/**
 * Encode a code point into UTF-8. Writes `UTF8_LEN(code)` bytes and
 * updates `pptr`.
 */
void char_encode(Context *ctx, Char32 code, uint8_t **pptr);

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
	TEXTVIEW_VALIDATE = 0,
	TEXTVIEW_TRUST = (1 << 0),
	TEXTVIEW_UNESCAPE = (1 << 1)
} TextViewType;

Error text_view(Context *ctx, Text *text, TextViewType flags,
                const uint8_t *bytes, size_t size);

bool text_eq(Context *ctx, const Text *text1, const Text *text2);
int32_t text_len(Context *ctx, const Text *text);

typedef struct {
    Text text;
} TextObj;

void textobj_init(Context *ctx, TextObj *obj, const Text *text);
void textobj_deinit(Context *ctx, TextObj *obj);

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

Text textbuild_get(Context *ctx, TextBuild *build);
void textbuild_char(Context *ctx, TextBuild *build, Char32 code);

typedef struct {
    Text text;
    Char8 ascii_map[CHAR8_MAX + 1];
    Char32 *buffer;
    int32_t capacity;
    CharMapType type;
} TextMap;

/**@}*/

#endif /* PRELUDE_H */
