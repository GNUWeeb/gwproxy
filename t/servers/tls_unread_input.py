# SPDX-License-Identifier: GPL-2.0-only
#
# TLS client for t/0123: sends ciphertext the proxy has no use for and watches
# what that does to the proxy's memory.
#
# Usage: tls_unread_input.py <scenario> <proxy_port> <proxy_pid>
#
# Scenarios:
#   closenotify
#       Send a close_notify, alone or behind the start of a request, then
#       flood the connection with junk: the proxy must hang up, and must not
#       keep what it was sent. Then the same with a client that goes silent:
#       the proxy must still hang up. A close_notify behind a complete request
#       must not stop the request being served.
#   dropped
#       Send a complete bodyless forwarding request to an origin that answers
#       only at the end of the client's stream, then many small records and a
#       close_notify, without closing. The proxy drops those records, and must
#       neither keep them nor stop at the first one: the origin must see the
#       end of the stream, and the client must get the answer.
#
# Prints "ok" on success, or what went wrong.

import socket
import ssl
import sys
import threading

FLOOD = 64 << 20        # bytes to send
MAX_GROWTH = 32 << 20   # how much of it the proxy may hold on to


def vm_hwm(pid):
    with open("/proc/%d/status" % pid) as f:
        for line in f:
            if line.startswith("VmHWM:"):
                return int(line.split()[1]) << 10
    raise RuntimeError("no VmHWM")


class Client:
    def __init__(self, port):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.inb, self.outb = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.o = ctx.wrap_bio(self.inb, self.outb)
        self.s = socket.create_connection(("127.0.0.1", port), timeout=30)
        while True:
            try:
                self.o.do_handshake()
                break
            except ssl.SSLWantReadError:
                self.flush()
                self.inb.write(self.s.recv(65536))
        self.flush()

    def flush(self):
        d = self.outb.read()
        if d:
            self.s.sendall(d)

    def close_notify(self):
        try:
            self.o.unwrap()
        except ssl.SSLWantReadError:
            pass
        self.flush()

    def read_until_eof(self):
        """What the proxy sent until it hung up; None if it did not."""
        got = b""
        while True:
            try:
                d = self.s.recv(65536)
            except socket.timeout:
                return None
            except ConnectionError:
                return got
            if not d:
                return got
            self.inb.write(d)
            while True:
                try:
                    p = self.o.read(65536)
                except (ssl.SSLWantReadError, ssl.SSLZeroReturnError):
                    break
                if not p:
                    break
                got += p

    def close(self):
        self.s.close()


def flood_after_close_notify(port, pid, start):
    c = Client(port)
    if start:
        c.o.write(start)
    c.close_notify()
    before = vm_hwm(pid)
    junk = b"\x17" * 65536
    sent = 0
    try:
        while sent < FLOOD:
            c.s.sendall(junk)
            sent += len(junk)
    except socket.timeout:
        return "send stalled instead of the proxy hanging up"
    except ConnectionError:
        pass
    c.close()
    grown = vm_hwm(pid) - before
    if grown > MAX_GROWTH:
        return "proxy memory grew by %d MiB" % (grown >> 20)
    if sent >= FLOOD:
        return "proxy took %d MiB without hanging up" % (sent >> 20)
    return None


def silent_after_close_notify(port, start):
    c = Client(port)
    if start:
        c.o.write(start)
    c.close_notify()
    got = c.read_until_eof()
    c.close()
    if got is None:
        return "proxy did not hang up"
    return None


def served_after_close_notify(port):
    # The origin answers once it has seen the end of the request.
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    ls.settimeout(30)
    res = []

    def origin():
        try:
            o, _ = ls.accept()
            o.settimeout(30)
            data = b""
            while True:
                d = o.recv(65536)
                if not d:
                    break
                data += d
            res.append(data)
            o.sendall(b"answer")
            o.close()
        except OSError as e:
            res.append(repr(e).encode())

    t = threading.Thread(target=origin)
    t.start()
    c = Client(port)
    c.o.write(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: x\r\n\r\n"
              % ls.getsockname()[1])
    c.o.write(b"early")
    c.close_notify()
    got = c.read_until_eof()
    c.close()
    t.join()
    ls.close()
    if got is None or not got.endswith(b"answer") or b" 200 " not in got:
        return "request behind a close_notify not served: %r" % (got,)
    if res != [b"early"]:
        return "origin got %r" % (res,)
    return None


def closenotify(port, pid):
    starts = [b"", b"CONNECT 127.0.0.1", b"\x05"]
    for start in starts:
        err = flood_after_close_notify(port, pid, start)
        if err:
            return "flood after %r: %s" % (start, err)
    for start in starts:
        err = silent_after_close_notify(port, start)
        if err:
            return "silence after %r: %s" % (start, err)
    return served_after_close_notify(port)


def dropped(port, pid):
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    ls.settimeout(30)
    forwarding = threading.Event()
    res = []

    def origin():
        try:
            o, _ = ls.accept()
            o.settimeout(60)
            data = b""
            while b"\r\n\r\n" not in data:
                d = o.recv(65536)
                if not d:
                    break
                data += d
            forwarding.set()
            while True:
                d = o.recv(65536)
                if not d:
                    break
                data += d
            res.append(data)
            o.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n"
                      b"Connection: close\r\n\r\nanswer")
            o.close()
        except OSError as e:
            res.append(repr(e).encode())
        forwarding.set()

    t = threading.Thread(target=origin)
    t.start()
    c = Client(port)
    host = b"127.0.0.1:%d" % ls.getsockname()[1]
    c.o.write(b"GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n" % (host, host))
    c.flush()
    err = None
    if not forwarding.wait(30):
        err = "origin got no request"
    before = vm_hwm(pid)
    sent = 0
    record = b"x" * 256
    try:
        while not err and sent < FLOOD:
            for _ in range(2000):
                c.o.write(record)
            d = c.outb.read()
            c.s.sendall(d)
            sent += len(d)
    except OSError as e:
        err = "sending: %r" % (e,)
    if err is None:
        grown = vm_hwm(pid) - before
        if grown > MAX_GROWTH:
            err = "proxy memory grew by %d MiB" % (grown >> 20)
    if err is None:
        c.close_notify()
        got = c.read_until_eof()
        if got is None or not got.endswith(b"answer"):
            err = "client got %r" % (got,)
    c.close()
    t.join()
    ls.close()
    if err is None and b"xxx" in res[0]:
        err = "origin got dropped bytes"
    return err


def main():
    scenario, port, pid = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    err = {"closenotify": closenotify, "dropped": dropped}[scenario](port, pid)
    print(err or "ok")


if __name__ == "__main__":
    main()
