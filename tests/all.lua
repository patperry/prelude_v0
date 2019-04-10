
function run (filename)
  print('# ' .. filename)
  return dofile(filename)
end

run('tests/text.lua')
