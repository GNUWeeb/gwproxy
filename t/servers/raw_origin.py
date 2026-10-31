#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# An origin that saves the exact bytes of each request it is sent, header and
# Content-Length body, so a test can compare what the proxy forwarded byte for
# byte. Request N (from 1) goes to <dir>/req.N; then the origin answers 200.
#
# Usage: raw_origin.py <port> <dir>
import socket, sys, threading

port = int(sys.argv[1])
outdir = sys.argv[2]
lock = threading.Lock()
count = [0]


def handle(c):
    buf = b''
    try:
        c.settimeout(10)
        while b'\r\n\r\n' not in buf:
            chunk = c.recv(4096)
            if not chunk:
                return
            buf += chunk
        head = buf.split(b'\r\n\r\n', 1)[0].decode('latin-1')
        clen = 0
        for line in head.split('\r\n')[1:]:
            name, _, val = line.partition(':')
            if name.strip().lower() == 'content-length':
                clen = int(val.strip())
        want = len(head) + 4 + clen
        while len(buf) < want:
            chunk = c.recv(4096)
            if not chunk:
                break
            buf += chunk
        with lock:
            count[0] += 1
            n = count[0]
        with open('%s/req.%d' % (outdir, n), 'wb') as f:
            f.write(buf)
        c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n'
                  b'Connection: close\r\n\r\nok')
    except OSError:
        pass
    finally:
        c.close()


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', port))
s.listen(64)
while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
