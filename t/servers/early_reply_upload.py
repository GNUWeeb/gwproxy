# SPDX-License-Identifier: GPL-2.0-only
#
# An upload that the origin answers before reading it, for t/0221: the origin
# reads the request header, answers 413 and closes. The body is still unread,
# so its close() resets the connection, right behind the reply. The reply must
# reach the client every time.
#
# Usage: early_reply_upload.py <proxy_port> [<rounds>]
#
# The origin runs here, on a port of its own; each round sends an
# absolute-form POST of a 200 KB body through the proxy (--as-http=1).
# Prints "ok", or what went wrong.

import socket
import sys
import threading

TIMEOUT = 30
REPLY = (b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 4\r\n"
         b"Connection: close\r\n\r\nbig!")
BODY = b"x" * 200000


def origin(ls):
    while True:
        try:
            c, _ = ls.accept()
        except OSError:
            return
        try:
            c.settimeout(TIMEOUT)
            req = b""
            while b"\r\n\r\n" not in req:
                d = c.recv(4096)
                if not d:
                    break
                req += d
            c.sendall(REPLY)
        except OSError:
            pass
        c.close()


def upload(c, data):
    try:
        c.sendall(data)
    except OSError:
        pass		# refused before the end: the reply is still there


def main():
    pport = int(sys.argv[1])
    rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 40
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(16)
    oport = ls.getsockname()[1]
    threading.Thread(target=origin, args=(ls,), daemon=True).start()

    req = (b"POST http://127.0.0.1:%d/up HTTP/1.1\r\nHost: x\r\n"
           b"Content-Length: %d\r\n\r\n" % (oport, len(BODY))) + BODY
    bad = {}
    for _ in range(rounds):
        c = socket.create_connection(("127.0.0.1", pport), timeout=TIMEOUT)
        t = threading.Thread(target=upload, args=(c, req), daemon=True)
        t.start()
        got = b""
        try:
            while True:
                d = c.recv(65536)
                if not d:
                    break
                got += d
        except OSError:
            pass		# the reset that follows the reply
        t.join(TIMEOUT)
        c.close()
        head = got.split(b"\r\n", 1)[0]
        if not (head.startswith(b"HTTP/1.1 413") and got.endswith(b"big!")):
            k = repr(head) if got else "empty reply"
            bad[k] = bad.get(k, 0) + 1
    ls.close()
    if bad:
        print("of %d rounds: %s" % (rounds, ", ".join(
            "%s %d" % (k, n) for k, n in sorted(bad.items()))))
    else:
        print("ok")


if __name__ == "__main__":
    main()
