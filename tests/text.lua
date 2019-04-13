

x = text.decode("x")
assert(x == x)
assert(text.decode("x") == text.decode("x"))
assert(text.decode("hello") == text.char(0x68, 0x65, 0x6c, 0x6c, 0x6f))

-- valid text
assert(text.decode("hello world"))
assert(text.unescape("escape: \\n\\r\\t"))
assert(text.unescape("unicode escape: \\u0034"))
assert(text.unescape("surrogate pair: \\uD834\\uDD1E"))
assert(text.unescape("B\\u0153uf Bourguignon"))

-- invalid text
assert(not text.decode("invalid utf-8 \xBF"))
