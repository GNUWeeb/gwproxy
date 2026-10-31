#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Stop gwproxy in the middle of freeing its connection pairs and check that
# every pair it has freed by then is really gone.
#
# Usage: shutdown_stall.py <gwproxy> <proxy-port> <origin-port> <fifo>
#                          [gwproxy args...]
#
# The proxy logs to <fifo>, a pipe shrunk to one page. Once the clients are
# connected and the log is drained, the pipe gets a filler that leaves room
# for only a few log lines, and the proxy is sent SIGTERM. Its log writes
# then block on the full pipe partway through the "Closing connection pair"
# lines, which shutdown prints for each pair just before freeing it. With
# the proxy held there, every pair whose line made it into the pipe has had
# its buffers freed and its sockets closed, so each of those clients must
# see its connection closed. A client that does not means the proxy's end of
# it is still alive: an event loop still holds a request on the socket, and
# a recv completing then writes into the freed buffer.
#
# Prints "OK <n>" (n = pairs checked) on success; anything else is a failure.

import fcntl
import os
import re
import signal
import socket
import subprocess
import sys
import termios
import threading
import time

F_SETPIPE_SZ = 1031
NR_CLIENTS = 6
ROOM = 400	# bytes of the page left for log lines once the filler is in


def fionread(fd):
    buf = fcntl.ioctl(fd, termios.FIONREAD, b"\0\0\0\0")
    return int.from_bytes(buf, sys.byteorder)


def read_avail(fd):
    out = b""
    while True:
        try:
            b = os.read(fd, 65536)
        except BlockingIOError:
            return out
        if not b:
            return out
        out += b


def main():
    gwp, pport, oport, fifo = (sys.argv[1], int(sys.argv[2]),
                               int(sys.argv[3]), sys.argv[4])
    extra = sys.argv[5:]

    origin = socket.socket()
    origin.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    origin.bind(("127.0.0.1", oport))
    origin.listen(64)
    held = []

    def accept_loop():
        while True:
            try:
                c, _ = origin.accept()
            except OSError:
                return
            held.append(c)

    threading.Thread(target=accept_loop, daemon=True).start()

    rfd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
    wfd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
    fcntl.fcntl(rfd, F_SETPIPE_SZ, 4096)

    log = b""
    proc = subprocess.Popen([gwp, "--bind=127.0.0.1:%d" % pport,
                             "--target=127.0.0.1:%d" % oport,
                             "--nr-workers=1", "--log-level=3",
                             "--log-file=" + fifo, "--acl-allow-all"] + extra,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.STDOUT)
    clients = []
    try:
        for _ in range(100):
            log += read_avail(rfd)
            try:
                socket.create_connection(("127.0.0.1", pport), 1).close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            print("proxy did not listen")
            return 1

        for _ in range(NR_CLIENTS):
            clients.append(socket.create_connection(("127.0.0.1", pport), 5))

        # Wait until the proxy has connected every client to the origin,
        # then for the log to go quiet, and leave the pipe empty.
        for _ in range(200):
            log += read_avail(rfd)
            if len(held) >= NR_CLIENTS:
                break
            time.sleep(0.02)
        quiet = 0
        while quiet < 5:
            time.sleep(0.05)
            b = read_avail(rfd)
            log += b
            quiet = 0 if b else quiet + 1

        os.write(wfd, b"#" * (4096 - ROOM - 1) + b"\n")
        os.kill(proc.pid, signal.SIGTERM)

        # Wait for the proxy to block on the full pipe.
        last, stable = -1, 0
        while stable < 10:
            if proc.poll() is not None:
                print("proxy exited without blocking on its log; "
                      "the filler left too much room")
                return 1
            n = fionread(rfd)
            stable = stable + 1 if n == last else 0
            last = n
            time.sleep(0.05)

        # Read all but the last byte: a page fully read is released, and
        # that would let the proxy go on.
        stalled = os.read(rfd, last - 1)
        log += stalled
        closed = re.findall(rb"Closing connection pair \(.*?ca=127\.0\.0\.1:(\d+),",
                            stalled)
        if not closed:
            print("no pair was freed before the proxy blocked")
            return 1

        by_port = {c.getsockname()[1]: c for c in clients}
        alive = []
        for port in closed:
            c = by_port.get(int(port))
            if c is None:
                continue
            c.settimeout(2)
            try:
                while c.recv(4096):
                    pass
            except socket.timeout:
                alive.append(int(port))
            except OSError:
                pass	# reset: closed as well
        if alive:
            print("client(s) %s still connected after the proxy freed their "
                  "pairs" % alive)
            return 1

        # Let the proxy finish.
        os.close(wfd)
        wfd = -1
        deadline = time.time() + 10
        while proc.poll() is None and time.time() < deadline:
            log += read_avail(rfd)
            time.sleep(0.02)
        if proc.poll() is None:
            print("proxy did not exit")
            return 1
        log += read_avail(rfd)
        if proc.returncode != 0:
            print("proxy exited with status %d" % proc.returncode)
            return 1
        if b"Sanitizer" in log:
            print("sanitizer report in the proxy log")
            return 1
        print("OK %d" % len(closed))
        return 0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        with open(fifo + ".log", "wb") as f:
            f.write(log + read_avail(rfd))
        os.close(rfd)
        if wfd >= 0:
            os.close(wfd)


if __name__ == "__main__":
    sys.exit(main())
