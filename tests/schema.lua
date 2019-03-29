
test = {
    source = [[
        {"a": 1, "b": 7.2}
    ]],
    schema = '{"a": "Int", "b": "Real"}'
}

function get_schema(source)
    filename = os.tmpname()

    file = assert(io.open(filename, "w"))
    assert(file:write(source))
    file:close()

    stream = io.popen("./schema " .. filename)
    output = stream:read("a")
    stream:close()

    os.remove(filename)
    return output
end

schema = get_schema(test.source)
if schema ~= test.schema .. "\n" then
    print("source: " .. test.source)
    print("expected: " .. test.schema)
    print("actual:   " .. schema)
    os.exit(false)
end
