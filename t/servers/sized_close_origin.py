# SPDX-License-Identifier: GPL-2.0-only
#
# sized_close_origin.py <port>: an origin that reads one line holding a byte
# count N from each client, writes N bytes back at once and then half-closes
# (SHUT_WR). It keeps reading until the peer closes, so the connection only
# ends from the client side. Lets a test put a FIN right behind a known
# amount of data.

import socket
import sys
import threading


def handle(c):
    try:
        line = b""
        while not line.endswith(b"\n"):
            d = c.recv(64)
            if not d:
                return
            line += d
        c.sendall(b"y" * int(line))
        c.shutdown(socket.SHUT_WR)
        while c.recv(65536):
            pass
    except (OSError, ValueError):
        pass
    finally:
        c.close()


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", int(sys.argv[1])))
    s.listen(16)
    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
