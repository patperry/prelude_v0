
function valid(x, mode)
    return text.decode(x, mode)
end

assert(text.decode("hello") == text.char(0x68, 0x65, 0x6c, 0x6c, 0x6f))

-- valid text
assert(valid("hello world"))
assert(valid("escape: \\n\\r\\t", "u"))
assert(valid("unicode escape: \\u0034", "u"))
assert(valid("surrogate pair: \\uD834\\uDD1E", "u"))
assert(valid("B\\u0153uf Bourguignon", "u"))

-- invalid text
assert(not valid("invalid utf-8 \xBF"))
