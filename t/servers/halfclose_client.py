# SPDX-License-Identifier: GPL-2.0-only
#
# Test client that exercises a client-side half-close.
#
# Usage: halfclose_client.py <host> <port> <path> <outfile>
#
# It connects, sends a small HTTP/1.0 request, shuts down its write side
# (SHUT_WR) while leaving its read side open, then reads the whole response
# and writes the response body to <outfile>. A proxy must not tear the
# connection down when it observes the client's write-side EOF; it must keep
# delivering the response until the target is done.

import socket
import sys


def main():
    host = sys.argv[1]
    port = int(sys.argv[2])
    path = sys.argv[3]
    outfile = sys.argv[4]

    s = socket.create_connection((host, port), timeout=15)
    s.settimeout(15)
    s.sendall(("GET %s HTTP/1.0\r\nHost: x\r\n\r\n" % path).encode())
    s.shutdown(socket.SHUT_WR)

    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    s.close()

    sep = data.find(b"\r\n\r\n")
    body = data[sep + 4:] if sep >= 0 else data
    with open(outfile, "wb") as f:
        f.write(body)


if __name__ == "__main__":
    main()
