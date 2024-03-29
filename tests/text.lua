-- valid text
assert(text.decode("hello world"))
assert(text.decode("B\xC5\x93uf Bourguignon"))

-- invalid text
assert(not text.decode("invalid utf-8 \xBF"))
assert(not text.decode("invalid utf-8 \xC2\x7F"))
assert(not text.decode("\xF0\xA4\xAD"))

-- valid 1-byte
assert(text.decode("\x00"))
assert(text.decode("\x01"))
assert(text.decode("\x7E"))
assert(text.decode("\x7F"))

-- invalid 1-byte
assert(not text.decode("\x80"))
assert(not text.decode("\xBF"))
assert(not text.decode("\xC0"))
assert(not text.decode("\xE0"))
assert(not text.decode("\xF0"))
assert(not text.decode("\xF8"))
assert(not text.decode("\xFC"))
assert(not text.decode("\xFE"))
assert(not text.decode("\xFF"))

-- valid 2-byte
assert(text.decode("\xC2\x80"))
assert(text.decode("\xC2\xBF"))
assert(text.decode("\xDF\x80"))
assert(text.decode("\xDF\xBF"))

-- invalid 2-byte: valid first, invalid second
assert(not text.decode("\xC2\x00"))
assert(not text.decode("\xC2\x7F"))
assert(not text.decode("\xDF\x00"))
assert(not text.decode("\xDF\x7F"))

-- invalid 2-byte: too short
assert(not text.decode("\xE0\x80"))
assert(not text.decode("\xE0\xA0"))
assert(not text.decode("\xE1\x80"))
assert(not text.decode("\xEC\x80"))
assert(not text.decode("\xEE\x80"))
assert(not text.decode("\xED\x80"))
assert(not text.decode("\xEF\x80"))
assert(not text.decode("\xF0\x80"))
assert(not text.decode("\xF0\x90"))
assert(not text.decode("\xF1\x80"))
assert(not text.decode("\xF4\x80"))

-- valid 3-byte
assert(text.decode("\xE0\xA0\x80"))
assert(text.decode("\xE0\xA0\xBF"))
assert(text.decode("\xE0\xBF\x80"))
assert(text.decode("\xE0\xBF\xBF"))
assert(text.decode("\xE1\x80\x80"))
assert(text.decode("\xE1\x80\xBF"))
assert(text.decode("\xE1\xBF\x80"))
assert(text.decode("\xE1\xBF\xBF"))
assert(text.decode("\xEC\x80\x80"))
assert(text.decode("\xEC\x80\xBF"))
assert(text.decode("\xEC\xBF\x80"))
assert(text.decode("\xEC\xBF\xBF"))
assert(text.decode("\xED\x80\x80"))
assert(text.decode("\xED\x80\xBF"))
assert(text.decode("\xED\x9F\x80"))
assert(text.decode("\xED\x9F\xBF"))

-- invalid 3-byte
assert(not text.decode("\xE0\x80\x80"))
assert(not text.decode("\xE0\x80\xBF"))
assert(not text.decode("\xE0\x9F\x80"))
assert(not text.decode("\xE0\x9F\xBF"))
assert(not text.decode("\xED\xA0\x80"))
assert(not text.decode("\xED\xA0\xBF"))
assert(not text.decode("\xED\xBF\x80"))
assert(not text.decode("\xED\xBF\xBF"))

-- valid 4-byte
assert(text.decode("\xF0\x90\x80\x80"))
assert(text.decode("\xF0\x90\x80\xBF"))
assert(text.decode("\xF0\x90\xBF\x80"))
assert(text.decode("\xF0\x90\xBF\xBF"))
assert(text.decode("\xF0\xBF\x80\x80"))
assert(text.decode("\xF0\xBF\x80\xBF"))
assert(text.decode("\xF0\xBF\xBF\x80"))
assert(text.decode("\xF0\xBF\xBF\xBF"))
assert(text.decode("\xF1\x80\x80\x80"))
assert(text.decode("\xF1\x80\x80\xBF"))
assert(text.decode("\xF1\x80\xBF\x80"))
assert(text.decode("\xF1\x80\xBF\xBF"))
assert(text.decode("\xF1\xBF\x80\x80"))
assert(text.decode("\xF1\xBF\x80\xBF"))
assert(text.decode("\xF1\xBF\xBF\x80"))
assert(text.decode("\xF1\xBF\xBF\xBF"))
assert(text.decode("\xF3\x80\x80\x80"))
assert(text.decode("\xF3\x80\x80\xBF"))
assert(text.decode("\xF3\x80\xBF\x80"))
assert(text.decode("\xF3\x80\xBF\xBF"))
assert(text.decode("\xF3\xBF\x80\x80"))
assert(text.decode("\xF3\xBF\x80\xBF"))
assert(text.decode("\xF3\xBF\xBF\x80"))
assert(text.decode("\xF3\xBF\xBF\xBF"))
assert(text.decode("\xF4\x80\x80\x80"))
assert(text.decode("\xF4\x80\x80\xBF"))
assert(text.decode("\xF4\x80\xBF\x80"))
assert(text.decode("\xF4\x80\xBF\xBF"))
assert(text.decode("\xF4\x8F\x80\x80"))
assert(text.decode("\xF4\x8F\x80\xBF"))
assert(text.decode("\xF4\x8F\xBF\x80"))
assert(text.decode("\xF4\x8F\xBF\xBF"))

-- invalid 4-byte
assert(not text.decode("\xF0\x80\x80\x80"))
assert(not text.decode("\xF0\x8F\x80\x80"))
assert(not text.decode("\xF4\x90\x80\x80"))
assert(not text.decode("\xF4\xBF\x80\x80"))
assert(not text.decode("\xF5\x80\x80\x80"))
assert(not text.decode("\xFF\x80\x80\x80"))
assert(not text.decode("\xF4\x80\x80\x7F"))

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

-- unescaping
assert(text.unescape("\\\\") == text.decode("\\"))
assert(text.unescape("\\/") == text.decode("/"))
assert(text.unescape("\\\"") == text.decode("\""))
assert(text.unescape("\\b") == text.decode("\b"))
assert(text.unescape("\\f") == text.decode("\f"))
assert(text.unescape("\\n") == text.decode("\n"))
assert(text.unescape("\\r") == text.decode("\r"))
assert(text.unescape("\\t") == text.decode("\t"))
assert(text.unescape("\\u2603") == text.decode("\xE2\x98\x83"))
assert(text.unescape("\\u0024") == text.decode("\x24"))
assert(text.unescape("\\uD801\\uDC37") == text.decode("\xF0\x90\x90\xB7"))
assert(text.unescape("\\uD852\\uDF62") == text.decode("\xF0\xA4\xAD\xA2"))

-- tostring
assert(tostring(text.unescape("\\n")) == "\n")

-- equality
x = text.decode("x")
assert(x == x)
assert(text.decode("") == text.char())
assert(text.decode("x") == text.decode("x"))
assert(text.decode("hello") ~= text.decode("hell"))
assert(text.decode("hell") ~= text.decode("hello"))
assert(text.decode("hello") ~= text.decode("hell_"))
assert(text.decode("hello") == text.char(0x68, 0x65, 0x6c, 0x6c, 0x6f))
assert(text.unescape("hello\\nworld") == text.decode("hello\nworld"))
assert(text.unescape("hello\\nworld") ~= text.decode("hello\\nworld"))

-- encode-decode round trip
for code=1,0xFFFF,0xFF do -- U+0000..U+FFFF
  assert(text.codepoint(text.char(code)) == code)
end

for _, code in pairs({
    0x10000, 0x10001, 0x3FFFE, 0x3FFFF,     --  U+10000..U+3FFFF
	0x40000, 0x40001, 0xFFFFE, 0xFFFFF,     --  U+40000..U+FFFFF
	0x100000, 0x100001, 0x10FFFE, 0x10FFFF  -- U+100000..U+10FFFF
    }) do
  assert(text.codepoint(text.char(code)) == code)
end
