#include <assert.h>
#include <ctype.h>

#include "prelude.h"

/* http://stackoverflow.com/a/11986885 */
#define hextoi(ch) ((ch > '9') ? (ch &~ 0x20) - 'A' + 10 : (ch - '0'))

/*
  Source:
   http://www.unicode.org/versions/Unicode7.0.0/UnicodeStandard-7.0.pdf
   page 124, 3.9 "Unicode Encoding Forms", "UTF-8"

  Table 3-7. Well-Formed UTF-8 Byte Sequences
  -----------------------------------------------------------------------------
  |  Code Points        | First Byte | Second Byte | Third Byte | Fourth Byte |
  |  U+0000..U+007F     |     00..7F |             |            |             |
  |  U+0080..U+07FF     |     C2..DF |      80..BF |            |             |
  |  U+0800..U+0FFF     |         E0 |      A0..BF |     80..BF |             |
  |  U+1000..U+CFFF     |     E1..EC |      80..BF |     80..BF |             |
  |  U+D000..U+D7FF     |         ED |      80..9F |     80..BF |             |
  |  U+E000..U+FFFF     |     EE..EF |      80..BF |     80..BF |             |
  |  U+10000..U+3FFFF   |         F0 |      90..BF |     80..BF |      80..BF |
  |  U+40000..U+FFFFF   |     F1..F3 |      80..BF |     80..BF |      80..BF |
  |  U+100000..U+10FFFF |         F4 |      80..8F |     80..BF |      80..BF |
  -----------------------------------------------------------------------------

  (table taken from https://github.com/JulienPalard/is_utf8 )
*/


const uint8_t *char_scan_utf8(Context *ctx, const uint8_t *ptr,
                              const uint8_t *end)
{
    if (ctx->error)
        return ptr;

    uint_fast8_t ch, ch1;
    unsigned nc;

    assert(ptr < end);

    /* First byte
     * ----------
     *
     * 1-byte sequence:
     * 00: 0000 0000
     * 7F: 0111 1111
     * (ch1 & 0x80 == 0)
     *
     * Invalid:
     * 80: 1000 0000
     * BF: 1011 1111
     * C0: 1100 0000
     * C1: 1100 0001
     * (ch & 0xF0 == 0x80 || ch == 0xC0 || ch == 0xC1)
     *
     * 2-byte sequence:
     * C2: 1100 0010
     * DF: 1101 1111
     * (ch & 0xE0 == 0xC0 && ch > 0xC1)
     *
     * 3-byte sequence
     * E0: 1110 0000
     * EF: 1110 1111
     * (ch & 0xF0 == E0)
     *
     * 4-byte sequence:
     * F0: 1111 0000
     * F4: 1111 0100
     * (ch & 0xFC == 0xF0 || ch == 0xF4)
     */

    ch1 = *ptr++;

    if ((ch1 & 0x80) == 0) {
        goto success;
    } else if ((ch1 & 0xC0) == 0x80) {
        goto inval_lead;
    } else if ((ch1 & 0xE0) == 0xC0) {
        if (ch1 == 0xC0 || ch1 == 0xC1) {
            goto inval_lead;
        }
        nc = 1;
    } else if ((ch1 & 0xF0) == 0xE0) {
        nc = 2;
    } else if ((ch1 & 0xFC) == 0xF0 || ch1 == 0xF4) {
        nc = 3;
    } else {
        // expecting bytes in the following ranges: 00..7F C2..F4
        goto inval_lead;
    }

    // ensure string is long enough
    if (ptr + nc > end) {
        // expecting another continuation byte
        goto inval_incomplete;
    }

    /* First Continuation byte
     * -----------
     * X  + 80..BF:
     * 80: 1000 0000
     * BF: 1011 1111
     * (ch & 0xC0 == 0x80)
     *
     * E0 + A0..BF:
     * A0: 1010 0000
     * BF: 1011 1111
     * (ch & 0xE0 == 0xA0)
     *
     * ED + 80..9F:
     * 80: 1000 0000
     * 9F: 1001 1111
     * (ch & 0xE0 == 0x80)
     *
     * F0 + 90..BF:
     * 90: 1001 0000
     * BF: 1011 1111
     * (ch & 0xF0 == 0x90 || ch & 0xE0 == A0)
     *
     */

    // validate the first continuation byte
    ch = *ptr++;
    switch (ch1) {
    case 0xE0:
        if ((ch & 0xE0) != 0xA0) {
            // expecting a byte between A0 and BF
            goto inval_cont;
        }
        break;
    case 0xED:
        if ((ch & 0xE0) != 0x80) {
            // expecting a byte between A0 and 9F
            goto inval_cont;
        }
        break;
    case 0xF0:
        if ((ch & 0xE0) != 0xA0 && (ch & 0xF0) != 0x90) {
            // expecting a byte between 90 and BF
            goto inval_cont;
        }
        break;
    case 0xF4:
        if ((ch & 0xF0) != 0x80) {
            // expecting a byte between 80 and 8F
            goto inval_cont;
        }
        break;
    default:
        if ((ch & 0xC0) != 0x80) {
            // expecting a byte between 80 and BF
            goto inval_cont;
        }
        break;
    }
    nc--;

    // validate the trailing continuation bytes
    while (nc-- > 0) {
        ch = *ptr++;
        if ((ch & 0xC0) != 0x80) {
            // expecting a byte between 80 and BF
            goto inval_cont;
        }
    }

success:
    goto out;

inval_incomplete:
    context_panic(ctx, ERROR_VALUE, "not enough continuation bytes"
                  " after leading byte (0x%02X)", (unsigned)ch1);
    goto error;

inval_lead:
    context_panic(ctx, ERROR_VALUE, "invalid leading byte (0x%02X)",
                  (unsigned)ch1);
    goto error;

inval_cont:
    context_panic(ctx, ERROR_VALUE, "leading byte 0x%02X followed by"
                  " invalid continuation byte (0x%02X)",
                  (unsigned)ch1, (unsigned)ch);
    goto error;

error:
    ptr--;

out:
    return ptr;
}


static const uint8_t *char_scan_uescape(Context *ctx, const uint8_t *ptr,
                                        const uint8_t *end)
{
    if (ctx->error)
        return ptr;

    const uint8_t *input = ptr;
    int32_t code, low;
    uint_fast8_t ch;
    unsigned i;

    if (ptr + 4 > end) {
        goto error_inval_incomplete;
    }

    code = 0;
    for (i = 0; i < 4; i++) {
        ch = *ptr++;
        if (!isxdigit(ch)) {
            goto error_inval_hex;
        }
        code = (code << 4) + hextoi(ch);
    }

    if (CHAR32_ISHIGH(code)) {
        if (ptr + 6 > end || ptr[0] != '\\' || ptr[1] != 'u') {
            goto error_inval_nolow;
        }
        ptr += 2;
        input = ptr;

        low = 0;
        for (i = 0; i < 4; i++) {
            ch = *ptr++;
            if (!isxdigit(ch)) {
                goto error_inval_hex;
            }
            low = (low << 4) + hextoi(ch);
        }
        if (!CHAR32_ISLOW(low)) {
            ptr -= 6;
            goto error_inval_low;
        }
    } else if (CHAR32_ISLOW(code)) {
        goto error_inval_nohigh;
    }
    goto out;

error_inval_incomplete:
    context_panic(ctx, ERROR_VALUE, "incomplete escape code (\\u%.*s)",
                  (int)(end - input), input);
    goto out;

error_inval_hex:
    context_panic(ctx, ERROR_VALUE,
                  "invalid hex value in escape code (\\u%.*s)",
                  4, input);
    goto out;

error_inval_nolow:
    context_panic(ctx, ERROR_VALUE, "missing UTF-16 low surrogate"
                  " after high surrogate escape code (\\u%.*s)",
                  4, input);
    goto out;

error_inval_low:
    context_panic(ctx, ERROR_VALUE,
                  "invalid UTF-16 low surrogate (\\u%.*s)"
                  " after high surrogate escape code (\\u%.*s)",
                  4, input, 4, input - 6);
    goto out;

error_inval_nohigh:
    context_panic(ctx, ERROR_VALUE, "missing UTF-16 high surrogate"
                  " before low surrogate escape code (\\u%.*s)",
                  4, input);
    goto out;

out:
    return ptr;
}


const uint8_t *char_scan_escape(Context *ctx, const uint8_t *ptr,
                                const uint8_t *end)
{
    if (ctx->error)
        return ptr;

    uint_fast8_t ch;

    if (ptr == end) {
        goto error_incomplete;
    }

    ch = *ptr++;

    switch (ch) {
    case '"':
    case '\\':
    case '/':
    case 'b':
    case 'f':
    case 'n':
    case 'r':
    case 't':
        break;
    case 'u':
        ptr = char_scan_uescape(ctx, ptr, end);
        if (ctx->error) {
            goto out;
        }
        break;
    default:
        goto error_inval;
    }

    goto out;

error_incomplete:
    context_panic(ctx, ERROR_VALUE, "incomplete escape code (\\)");
    goto out;

error_inval:
    context_panic(ctx, ERROR_VALUE, "invalid escape code (\\%c)", ch);
    goto out;

out:
    return ptr;
}


Char32 char_decode_utf8(Context *ctx, const uint8_t **pptr)
{
    if (ctx->error)
        return CHAR32_NONE;

    const uint8_t *ptr = *pptr;
    Char32 code;
    uint_fast8_t ch;
    unsigned nc;

    ch = *ptr++;
    if (!(ch & 0x80)) {
        code = ch;
        nc = 0;
    } else if (!(ch & 0x20)) {
        code = ch & 0x1F;
        nc = 1;
    } else if (!(ch & 0x10)) {
        code = ch & 0x0F;
        nc = 2;
    } else {
        code = ch & 0x07;
        nc = 3;
    }

    while (nc-- > 0) {
        ch = *ptr++;
        code = (code << 6) + (ch & 0x3F);
    }

    *pptr = ptr;
    return code;
}


static Char32 char_decode_uescape(Context *ctx, const uint8_t **pptr)
{
    if (ctx->error)
        return CHAR32_NONE;

    const uint8_t *ptr = *pptr;
    Char32 code;
    uint_fast16_t low;
    uint_fast8_t ch;
    unsigned i;

    code = 0;
    for (i = 0; i < 4; i++) {
        ch = *ptr++;
        code = (code << 4) + hextoi(ch);
    }

    if (CHAR32_ISHIGH(code)) {
        // skip over \u
        ptr += 2;

        low = 0;
        for (i = 0; i < 4; i++) {
            ch = *ptr++;
            low = (uint_fast16_t)(low << 4) + hextoi(ch);
        }

        code = CHAR32_DECODE_HIGHLOW(code, low);
    }

    *pptr = ptr;
    return code;
}


Char32 char_decode_escape(Context *ctx, const uint8_t **pptr)
{
    if (ctx->error)
        return CHAR32_NONE;

    const uint8_t *ptr = *pptr;
    Char32 code = (Char32)*ptr++;

    switch (code) {
    case 'b':
        code = '\b';
        break;
    case 'f':
        code = '\f';
        break;
    case 'n':
        code = '\n';
        break;
    case 'r':
        code = '\r';
        break;
    case 't':
        code = '\t';
        break;
    case 'u':
        *pptr = ptr;
        return char_decode_uescape(ctx, pptr);
    default:
        break;
    }

    *pptr = ptr;
    return code;
}


// http://www.fileformat.info/info/unicode/utf8.htm
void char_encode_utf8(Context *ctx, Char32 code, uint8_t **pptr)
{
    if (ctx->error)
        return;

    uint8_t *ptr = *pptr;

    assert(code >= 0);
    uint32_t x = (uint32_t)code;

    if (x <= 0x7F) {
        *ptr++ = (uint8_t)x;
    } else if (x <= 0x07FF) {
        *ptr++ = (uint8_t)(0xC0 | (x >> 6));
        *ptr++ = (uint8_t)(0x80 | (x & 0x3F));
    } else if (x <= 0xFFFF) {
        *ptr++ = (uint8_t)(0xE0 | (x >> 12));
        *ptr++ = (uint8_t)(0x80 | ((x >> 6) & 0x3F));
        *ptr++ = (uint8_t)(0x80 | (x & 0x3F));
    } else {
        *ptr++ = (uint8_t)(0xF0 | (x >> 18));
        *ptr++ = (uint8_t)(0x80 | ((x >> 12) & 0x3F));
        *ptr++ = (uint8_t)(0x80 | ((x >> 6) & 0x3F));
        *ptr++ = (uint8_t)(0x80 | (x & 0x3F));
    }

    *pptr = ptr;
}
