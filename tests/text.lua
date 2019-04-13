
-- valid text
assert(text.decode("hello world"))
assert(text.decode("B\xC5\x93uf Bourguignon"))

-- invalid text
assert(not text.decode("invalid utf-8 \xBF"))
assert(not text.decode("invalid utf-8 \xC2\x7F"))

-- valid escaped text
assert(text.unescape("hello world"))
assert(text.unescape("escape: \\n\\r\\t"))
assert(text.unescape("unicode escape: \\u0034"))
assert(text.unescape("surrogate pair: \\uD834\\uDD1E"))
assert(text.unescape("B\\u0153uf Bourguignon"))

-- invalid escaped text
assert(not text.unescape("invalid utf-8 \xBF"))
assert(not text.unescape("invalid utf-8 \xC2\x7F"))
assert(not text.unescape("invalid escape \\a"))
assert(not text.unescape("missing escape \\"))
assert(not text.unescape("ends early \\u007"))
assert(not text.unescape("non-hex value \\u0G7F"))
assert(not text.unescape("\\uD800 high surrogate"))
assert(not text.unescape("\\uDBFF high surrogate"))
assert(not text.unescape("\\uD800\\uDC0G invalid hex"))
assert(not text.unescape("\\uDC00 low surrogate"))
assert(not text.unescape("\\uDFFF low surrogate"))
assert(not text.unescape("\\uD84 incomplete"))
assert(not text.unescape("\\uD804\\u2603 invalid low"))

-- equality
x = text.decode("x")
assert(x == x)
assert(text.decode("x") == text.decode("x"))
assert(text.decode("") == text.char())
assert(text.decode("hello") == text.char(0x68, 0x65, 0x6c, 0x6c, 0x6f))
assert(text.unescape("hello\\nworld") == text.decode("hello\nworld"))
