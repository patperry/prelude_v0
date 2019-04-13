#ifndef TEXT_H
#define TEXT_H

/**
 * \defgroup rune Unicode code points (runes)
 * @{
 */

/**
 * Unicode code unit (ASCII, UTF-32)
 */
typedef int8_t Char8;
typedef int32_t Char32;

#define CHAR32_NONE -1
#define CHAR32_MAX 0x10FFFF

#define CHAR8_MAX 0x7F

/**
 * Unicode character width type.
 */
typedef enum {
    CHAR_WIDTH_NONE = 0,    /**< Control and other */
    CHAR_WIDTH_IGNORABLE,   /**< Default ignorable */
    CHAR_WIDTH_MARK,        /**< Zero-width mark or format */
    CHAR_WIDTH_NARROW,      /**< Most western alphabets */
    CHAR_WIDTH_AMBIGUOUS,   /**< Width depends on context */
    CHAR_WIDTH_WIDE,        /**< Most ideographs */
    CHAR_WIDTH_EMOJI        /**< Emoji presentation */
} CharWidthType;

/**
 * Get the width of a code point, using the East Asian Width table and
 * the Emoji data.
 */
CharWidthType char_width(Context *ctx, Char32 code);

/**
 * Whether a code point is a default ignorable character.
 */
bool char_isignorable(Context *ctx, Char32 code);

/**@}*/

/**
 * \defgroup normalize Normalization
 * @{
 */

/**
 * Unicode character decomposition and case folding mappings.
 *
 * Compatibility mappings are defined in
 * [UAX #44 Sec. 5.7.3 Character Decomposition Maps]
 * (http://www.unicode.org/reports/tr44/#Character_Decomposition_Mappings).
 *
 * Case folding mappings are defined in *TR44* Sec. 5.6.
 */
typedef enum {
	CHAR_MAP_DECOMP = 0,            /**< normalization (for NFD) */
	CHAR_MAP_FONT = (1 << 0),       /**< font variant */
	CHAR_MAP_NOBREAK = (1 << 1),    /**< no-break version of space or hyphen */
	CHAR_MAP_INITIAL = (1 << 2),    /**< initial presentation form (Arabic) */
	CHAR_MAP_MEDIAL = (1 << 3),     /**< medial presentation form (Arabic) */
	CHAR_MAP_FINAL = (1 << 4),      /**< final presentation form (Arabic) */
	CHAR_MAP_ISOLATED = (1 << 5),   /**< isolated presentation form (Arabic) */
	CHAR_MAP_CIRCLE = (1 << 6),     /**< encircled form */
	CHAR_MAP_SUPER = (1 << 7),      /**< superscript form */
	CHAR_MAP_SUB = (1 << 8),        /**< subscript form */
	CHAR_MAP_VERTICAL = (1 << 9),   /**< vertical layout presentation form */
	CHAR_MAP_WIDE = (1 << 10),      /**< wide (or zenkaku) compat */
	CHAR_MAP_NARROW = (1 << 11),    /**< narrow (or hankaku) compat */
	CHAR_MAP_SMALL = (1 << 12),     /**< small variant form (CNS compat) */
	CHAR_MAP_SQUARE = (1 << 13),    /**< CJK squared font variant */
	CHAR_MAP_FRACTION = (1 << 14),  /**< vulgar fraction form */
	CHAR_MAP_UNSPECIFIED = (1 << 15),/**< unspecified compatibility */
	CHAR_MAP_COMPAT = ((1 << 16) - 1),/**< all compatibility maps (for NFKD) */

	CHAR_MAP_RMDI = (1 << 16),      /**< remove default ignorables */
	CHAR_MAP_CASEFOLD = (1 << 17)   /**< perform full case folding */
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



typedef struct {
    const uint8_t *bytes;
    unsigned int unescape : 1;
    unsigned int size     : 31;
} Text;

typedef struct {
    Text text;
} TextObj;


void textobj_init(Context *ctx, TextObj *obj, const Text *text);
void textobj_deinit(Context *ctx, TextObj *obj);


typedef enum {
	TEXT_VIEW_VALIDATE = 0,
	TEXT_VIEW_TRUST = (1 << 0),
	TEXT_VIEW_UNESCAPE = (1 << 1)
} TextViewType;

Error text_view(Context *ctx, Text *text, TextViewType flags,
                const uint8_t *bytes, size_t size);

bool text_eq(Context *ctx, const Text *text1, const Text *text2);
int32_t text_len(Context *ctx, const Text *text);


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

/**
 * Text encoding.
 */

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
Error utf8_scan(Context *ctx, const uint8_t **pptr, const uint8_t *end);

/**
 * Decode the first code point from a UTF-8 character buffer, without
 * validating the input.
 */ 
Char32 utf8_decode(Context *ctx, const uint8_t *pptr);

/**
 * Encode a code point into UTF-8. Writes `UTF8_LEN(code)` bytes and
 * updates `pptr`.
 */
void utf8_encode(Context *ctx, Char32 code, uint8_t **pptr);

#endif /* TEXT_H */
