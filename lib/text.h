#ifndef TEXT_H
#define TEXT_H

/**
 * \defgroup rune Unicode code points (runes)
 * @{
 */

/**
 * Unicode code unit (ASCII, UTF-16, UTF-32)
 */
typedef int_least8_t Char8;
typedef int_least16_t Char16;
typedef int_least32_t Char32;

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
 * Whether a codepoint is a default ignorable character.
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
 * Maximum size (in codepoints) of a single code point's decomposition.
 *
 * From *TR44* Sec. 5.7.3: "Compatibility mappings are guaranteed to be no
 * longer than 18 characters, although most consist of just a few characters."
 */
#define CHAR_MAP_MAX 18

/**
 * Apply decomposition and/or casefold mapping to a codepoint,
 * writing the output to the specified buffer, and return a pointer past
 * the output. The output will be at most #CHAR_MAP_MAX codepoints.
 */
Char32 *char_map(Context *ctx, CharMapType type, Char code, Char *output);

/**
 * Apply the canonical ordering algorithm to put an array of codepoints
 * into normal order. See *Unicode* Sec 3.11 and *TR44* Sec. 5.7.4.
 */
void chars_order(Context *ctx, Char32 *codes, int count);

/**
 * Apply the canonical composition algorithm to put an array of
 * canonically-ordered Unicode codepoints into composed form. This
 * shrinks or preserves the rune count.
 */
void chars_compose(Context *ctx, Char32 *codes, int *pcount);

/**@}*/



typedef struct {
    unsigned char *bytes;
    unsigned int unescape : 1;
    unsigned int size     : 31;
} Text;

typedef enum {
	TEXT_VIEW_VALIDATE = 0,
	TEXT_VIEW_TRUST = (1 << 0),
	TEXT_VIEW_UNESCAPE = (1 << 1)
} TextViewType;

Error text_view(Context *ctx, Text *text, TextViewType flags,
                unsigned char *bytes, int size);



/**
 * An iterator over the decoded UTF-32 codepoingt in a text.
 */
typedef struct {
	const unsigned char *ptr;
	const unsigned char *end;
	bool unescape;
	Char32 current;
} TextIter;

void text_iter_init(Context *ctx, TextIter *it, const Text *text);
void text_iter_copy(Context *ctx, TextIter *it, const TextIter *src);
void text_iter_deinit(Context *ctx, TextIter *it);

bool text_iter_advance(Context *ctx, TextIter *it);


typedef struct {
    Text text;
    Char8 ascii_map[CHAR8_MAX + 1];
    Char32 *buffer;
    int capacity;
    CharMapType type;
} TextMap;


#endif /* TEXT_H */
