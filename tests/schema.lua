
tests = {
    {
        source = [[
            {"a": 1, "b": 7.2}
        ]],
        schema = '{"a": "Int", "b": "Real"}'
    },
    {
        source = [[
            {"a": 1, "b": 7.2}
            {"a": 1.0, "b": 7.2}
        ]],
        schema = '{"a": "Real", "b": "Real"}'
    },
}

function get_schema(source)
    local filename = os.tmpname()

    local file = assert(io.open(filename, "w"))
    assert(file:write(source))
    file:close()

    local stream = io.popen("./schema " .. filename)
    local output = stream:read("a")
    stream:close()

    os.remove(filename)
    return output
end

fail_count = 0

for _, test in ipairs(tests) do
    schema = get_schema(test.source)
    if schema ~= test.schema .. "\n" then
        print("source:\n" .. test.source)
        print("expected: " .. test.schema)
        print("actual:   " .. schema)
        fail_count = fail_count + 1
    end
end

if fail_count > 0 then
    print(fail_count .. " tests failed")
    os.exit(false)
end
