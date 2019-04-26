
hostname = "www.unicode.org"
resource = "/Public/12.0.0/ucd/UnicodeData.txt"
port = 80 -- http

sock = socket.connect(hostname, port)
sock:send(
  "GET " .. resource .. " HTTP/1.1\r\n"
  .. "Host: " .. hostname .. "\r\n"
  .. "\r\n"
  )

chunksize = 4096
chunk = sock:receive(chunksize)
