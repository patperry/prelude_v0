
host= "www.unicode.org"
resource = "/Public/12.0.0/ucd/UnicodeData.txt"
service = "http"

sock = socket.connect(host, service)
sock:send(
  "GET " .. resource .. " HTTP/1.1\r\n"
  .. "Host: " .. hostname .. "\r\n"
  .. "\r\n"
  )

chunksize = 4096
chunk = sock:receive(chunksize)
