# SPDX-License-Identifier: GPL-2.0-only
#
# Whether a TLS client that floods the proxy with data it drops keeps the
# proxy's worker from serving anyone else.
#
# Usage: tls_flood_ping.py <mode> <proxy_port> <secs>
#
# Flooders, in processes of their own, each open a TLS connection to the
# proxy and get it to drop what they send:
#   udp   SOCKS5 UDP ASSOCIATE, then data on its control connection;
#   http  a forwarding request for a name the proxy's DNS server holds back
#         (hold<n>.example), then data behind it.
# Meanwhile a plain SOCKS5 client tunnels to an echo server through the same
# proxy, which must run a single worker, and sends it a byte every PING_GAP
# seconds, for <secs> seconds of flooding.
#
# Prints "ok", or what went wrong and the round trips seen. Exits 77 if the
# flooders cannot keep up a flood at all, in which case nothing is measured.
#
# A ping waits behind whatever the worker does in one go. When that is only
# what one read of the socket brings in, a ping takes well under a
# millisecond on an idle host and some milliseconds on a loaded one, and the
# client spends nearly all its time between pings. When the worker keeps
# reading a flooder's socket for as long as there is data, it can stay there
# for up to a second or two at a time, and the client spends most of its
# time waiting for an answer. What share of the time it waits tells the two
# apart, and a few pings that a loaded host happened to delay do not move it
# much.

import os
import socket
import ssl
import statistics
import struct
import subprocess
import sys
import threading
import time

FLOODERS = 2
PING_GAP = 0.02
MAX_WAITING = 0.5       # the share of the time the client may wait
CHUNK = 256 << 10


def flooder(mode, port, n):
    raw = socket.create_connection(("127.0.0.1", port))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(raw, server_hostname="localhost")
    if mode == "udp":
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 greeting refused")
        s.sendall(b"\x05\x03\x00\x01\0\0\0\0\0\0")
        rep = s.recv(10)
        if len(rep) != 10 or rep[1] != 0:
            raise RuntimeError("UDP ASSOCIATE got %r" % rep)
    else:
        host = b"hold%d.example" % n
        s.sendall(b"GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n" % (host, host))
    print("ready", flush=True)
    secs = float(sys.stdin.readline())
    chunk = b"z" * CHUNK
    sent = 0
    end = time.monotonic() + secs
    while time.monotonic() < end:
        s.sendall(chunk)
        sent += len(chunk)
    print("sent %d" % sent, flush=True)
    # Until told to go: closing would end the flood's state in the proxy.
    sys.stdin.readline()


def echo_server():
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)

    def run():
        c, _ = ls.accept()
        while True:
            d = c.recv(4096)
            if not d:
                return
            c.sendall(d)

    threading.Thread(target=run, daemon=True).start()
    return ls.getsockname()[1]


def socks5_connect(port, dport):
    b = socket.create_connection(("127.0.0.1", port))
    b.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    b.sendall(b"\x05\x01\x00")
    if b.recv(2) != b"\x05\x00":
        raise RuntimeError("SOCKS5 greeting refused")
    b.sendall(b"\x05\x01\x00\x01\x7f\0\0\x01" + struct.pack(">H", dport))
    rep = b""
    while len(rep) < 10:
        d = b.recv(10 - len(rep))
        if not d:
            raise RuntimeError("no reply to CONNECT")
        rep += d
    if rep[1] != 0:
        raise RuntimeError("CONNECT got REP %d" % rep[1])
    return b


def ping(b, secs):
    """Returns the round trips, and how long it took to make them."""
    rtts = []
    b.settimeout(60)
    start = time.monotonic()
    end = start + secs
    while time.monotonic() < end:
        t = time.monotonic()
        b.sendall(b"p")
        if b.recv(1) != b"p":
            raise RuntimeError("echo lost")
        rtts.append(time.monotonic() - t)
        time.sleep(PING_GAP)
    return rtts, time.monotonic() - start


def main():
    mode, port, secs = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
    b = socks5_connect(port, echo_server())
    ping(b, 0.2)
    floods = []
    try:
        for n in range(FLOODERS):
            f = subprocess.Popen([sys.executable, __file__, "flood", mode,
                                  str(port), str(n)], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, text=True)
            floods.append(f)
            if f.stdout.readline().strip() != "ready":
                raise RuntimeError("flooder %d did not get going" % n)
        for f in floods:
            f.stdin.write("%s\n" % secs)
            f.stdin.flush()
        rtts, took = ping(b, secs)
        sent = 0
        for f in floods:
            line = f.stdout.readline().split()
            if len(line) != 2 or line[0] != "sent":
                raise RuntimeError("a flooder failed")
            sent += int(line[1])
    finally:
        for f in floods:
            try:
                f.stdin.write("\n")
                f.stdin.flush()
            except OSError:
                pass
            f.wait(30)
    if sent < FLOODERS * CHUNK * 4:
        print("the flooders sent only %d bytes" % sent)
        sys.exit(77)
    waiting = sum(rtts) / took
    what = ("%d pings in %.1f s, waiting %.0f%% of the time, median %.1f ms,"
            " max %.1f ms, %d MiB flooded" % (
                len(rtts), took, waiting * 100,
                statistics.median(rtts) * 1e3, max(rtts) * 1e3, sent >> 20))
    if waiting > MAX_WAITING:
        print("worker held up: " + what)
    else:
        print("ok")
        print(what, file=sys.stderr)


if __name__ == "__main__":
    if sys.argv[1] == "flood":
        flooder(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
    else:
        try:
            main()
        except (RuntimeError, OSError) as e:
            print(repr(e))
