# SPDX-License-Identifier: GPL-2.0-only
#
# TLS 1.3 client for t/0124 that asks for KeyUpdates, each of which makes the
# proxy's TLS engine produce a record of its own. Python's ssl module cannot
# send one, so this drives the OpenSSL library directly through ctypes.
#
# Usage: tls_keyupdate_client.py <scenario> <proxy_port> <proxy_pid>
#
# A scenario looks at the proxy's peak memory, so it needs a proxy of its own:
# what another one made it use would hide what this one does.
#
# Scenarios:
#   answer
#       Ask for two KeyUpdates before sending a request, then again on an
#       established CONNECT tunnel to an origin that stays silent. No other
#       traffic is going on, and yet the answer must come, both times.
#   noread
#       On such a tunnel, keep asking and sending a byte each time, without
#       reading. The proxy must stop reading the client rather than queue its
#       answers without limit: the client's sending must come to a stop while
#       the proxy's memory stays flat. Then read everything: the tunnel must
#       go on, and the origin must get every byte.
#   burst
#       The same, with a large send buffer and nearly nothing but KeyUpdates
#       in it, so that one read by the proxy makes its engine queue more than
#       the limit. The proxy has to get that out too once the client reads,
#       as it stays held up until then.
#   strand
#       Much the same with more data in it, on a tunnel with small buffers to
#       an origin that keeps talking, so that its traffic may be what gets the
#       client's reading going again, and then stop sending and only read. The
#       origin must get every byte with nothing more from the client to bring
#       the last of them along. Run on a proxy started with small buffers.
#   udp
#       On the control connection of a SOCKS5 UDP association: what the proxy's
#       engine has to say there must also come through, and must not pile up
#       when the client asks for it without reading.
#   shut
#       The origin finishes sending, which ends the proxy's sending to the
#       client, and goes on reading. Keep asking and sending a byte each time:
#       with nowhere to send its answers to, the proxy must not hold on to
#       them, and the origin must still get every byte.
#
# Prints "ok" on success, or what went wrong. Exits 77 if the OpenSSL library
# cannot be used this way.

import ctypes
import ctypes.util
import random
import select
import socket
import sys
import threading
import time

MAX_GROWTH = 8 << 20    # how much the proxy's memory may grow
STALL_SECS = 3          # no progress for this long: the client has been stopped
# Answers that are kept make the proxy grow by 1.5 MiB or more over these, counted
# from where the proxy has handled SHUT_SETTLE of them: a sanitizer's quarantine
# has filled up by then, and it takes about 1 MiB itself.
SHUT_UPDATES = 128 << 10
SHUT_SETTLE = 32 << 10
SHUT_GROWTH = 1 << 20
SHUT_STALL = 30         # the origin got nothing for this long: it is stuck
BURST_SNDBUF = 256 << 10  # one read gets the engine past its limit with less
BURST_RUN = 20          # OpenSSL allows 32 KeyUpdates without data in between
STRAND_ROUNDS = 3       # it depends on timing: this makes it show nearly always
STRAND_RCVBUF = 64 << 10  # much less and TCP crawls on persist timers
STRAND_SNDBUF = 128 << 10
STRAND_DATA = b"x" * 64
STRAND_TALK = b"p" * 200
STRAND_STALL = 30       # the origin got nothing for this long: it is stuck
STRAND_MSS = 8192       # what the client sends in, see strand_round()

SSL_ERROR_WANT_READ = 2
SSL_ERROR_WANT_WRITE = 3
SSL_CTRL_SET_MIN_PROTO_VERSION = 123
TLS1_3_VERSION = 0x0304
SSL_KEY_UPDATE_REQUESTED = 1


def load_libssl():
    names = ["libssl.so.3", "libssl.so.1.1", ctypes.util.find_library("ssl")]
    for name in names:
        if not name:
            continue
        try:
            lib = ctypes.CDLL(name)
            lib.SSL_key_update
            break
        except (OSError, AttributeError):
            continue
    else:
        print("no usable libssl")
        sys.exit(77)
    vp, ci, cl = ctypes.c_void_p, ctypes.c_int, ctypes.c_long
    for name, res, args in (
        ("TLS_client_method", vp, []),
        ("SSL_CTX_new", vp, [vp]),
        ("SSL_CTX_ctrl", cl, [vp, ci, cl, vp]),
        ("SSL_new", vp, [vp]),
        ("SSL_set_fd", ci, [vp, ci]),
        ("SSL_connect", ci, [vp]),
        ("SSL_key_update", ci, [vp, ci]),
        ("SSL_do_handshake", ci, [vp]),
        ("SSL_write", ci, [vp, ctypes.c_char_p, ci]),
        ("SSL_read", ci, [vp, vp, ci]),
        ("SSL_get_error", ci, [vp, ci]),
    ):
        f = getattr(lib, name)
        f.restype, f.argtypes = res, args
    return lib


LIB = load_libssl()


def vm_hwm(pid):
    with open("/proc/%d/status" % pid) as f:
        for line in f:
            if line.startswith("VmHWM:"):
                return int(line.split()[1]) << 10
    raise RuntimeError("no VmHWM")


def check_growth(pid, before, limit, count, what):
    grew = vm_hwm(pid) - before
    if grew > limit:
        raise RuntimeError("proxy memory grew by %d MiB after %d %s" % (
            grew >> 20, count, what))


class Client:
    def __init__(self, port, rcvbuf=0, mss=0):
        self.s = socket.socket()
        if mss:
            self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, mss)
        if rcvbuf:
            self.s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
            self.s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, rcvbuf)
        # Blocking, as OpenSSL expects it; the test's timeout covers a hang.
        self.s.connect(("127.0.0.1", port))
        ctx = LIB.SSL_CTX_new(LIB.TLS_client_method())
        LIB.SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_3_VERSION,
                         None)
        self.ssl = LIB.SSL_new(ctx)
        LIB.SSL_set_fd(self.ssl, self.s.fileno())
        if LIB.SSL_connect(self.ssl) != 1:
            raise RuntimeError("TLS handshake failed")
        self.buf = ctypes.create_string_buffer(65536)

    def write(self, data):
        if LIB.SSL_write(self.ssl, data, len(data)) != len(data):
            raise RuntimeError("SSL_write failed")

    def read_some(self):
        """Read what there is; b"" if nothing (non-blocking socket)."""
        n = LIB.SSL_read(self.ssl, self.buf, len(self.buf))
        if n > 0:
            return self.buf.raw[:n]
        e = LIB.SSL_get_error(self.ssl, n)
        if e == SSL_ERROR_WANT_READ or e == SSL_ERROR_WANT_WRITE:
            return b""
        raise RuntimeError("SSL_read failed: %d" % e)

    def key_update(self):
        if LIB.SSL_key_update(self.ssl, SSL_KEY_UPDATE_REQUESTED) != 1:
            raise RuntimeError("SSL_key_update failed")

    def drain(self, secs):
        """Non-blocking socket: read until nothing has come for @secs."""
        got = b""
        while select.select([self.s], [], [], secs)[0]:
            d = self.read_some()
            got += d
        return got

    def wire_idle(self, secs):
        """Whether no bytes are waiting on the socket for @secs."""
        return not select.select([self.s], [], [], secs)[0]


class Sink:
    """Reads what it gets, counts it and never sends a thing."""

    def __init__(self, shut=False):
        self.shut = shut
        self.ls = socket.socket()
        self.ls.bind(("127.0.0.1", 0))
        self.ls.listen(1)
        self.ls.settimeout(30)
        self.port = self.ls.getsockname()[1]
        self.count = 0
        t = threading.Thread(target=self.run, daemon=True)
        t.start()

    def run(self):
        c, _ = self.ls.accept()
        if self.shut:
            c.shutdown(socket.SHUT_WR)
        try:
            while True:
                d = c.recv(65536)
                if not d:
                    break
                self.count += len(d)
        except ConnectionResetError:
            # The client went without a close_notify: the proxy says so.
            pass


class Talker(Sink):
    """A Sink that keeps sending a little until told to stop or cut off."""

    def __init__(self):
        self.stop = False
        super().__init__()

    def talk(self, c):
        try:
            while not self.stop:
                c.send(STRAND_TALK)
                time.sleep(0.0005)
        except OSError:
            pass

    def run(self):
        c, _ = self.ls.accept()
        threading.Thread(target=self.talk, args=(c,), daemon=True).start()
        try:
            while True:
                d = c.recv(65536)
                if not d:
                    break
                self.count += len(d)
        except OSError:
            pass


def connect_tunnel(c, sink):
    c.write(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: x\r\n\r\n" % sink.port)
    got = b""
    while b"\r\n\r\n" not in got:
        d = c.read_some()
        if not d:
            raise RuntimeError("no reply to CONNECT")
        got += d
    if b" 200 " not in got:
        raise RuntimeError("CONNECT got %r" % got)


def expect_answer(c, what):
    # Tickets from the handshake are read by now: only an answer can come.
    # The engine answers a KeyUpdate when it gets to its next message.
    c.s.setblocking(False)
    c.drain(1)
    for _ in range(2):
        if LIB.SSL_key_update(c.ssl, SSL_KEY_UPDATE_REQUESTED) != 1:
            return "SSL_key_update failed"
        # Sends it, on a socket that has the room for it.
        LIB.SSL_do_handshake(c.ssl)
    if c.wire_idle(20):
        return "no answer to a KeyUpdate %s" % what
    if not c.s.recv(1, socket.MSG_PEEK):
        return "proxy hung up instead of answering a KeyUpdate %s" % what
    return None


def answer(port, pid):
    sink = Sink()
    c = Client(port)
    err = expect_answer(c, "before the request")
    if err:
        return err
    c.drain(1)
    c.s.setblocking(True)
    connect_tunnel(c, sink)
    return expect_answer(c, "on a tunnel")


def flood_unread(c, pid):
    """Ask and send until the proxy stops reading. Returns the bytes sent and
    the result of the SSL_write() left unfinished."""
    c.s.setblocking(False)
    time.sleep(0.2)
    before = vm_hwm(pid)
    sent = 0
    update = True
    last = time.monotonic()
    while time.monotonic() - last < STALL_SECS:
        if update:
            c.key_update()
            update = False
        n = LIB.SSL_write(c.ssl, b"x", 1)
        if n == 1:
            sent += 1
            update = True
            last = time.monotonic()
        elif LIB.SSL_get_error(c.ssl, n) == SSL_ERROR_WANT_WRITE:
            select.select([], [c.s], [], 0.1)
        else:
            raise RuntimeError("SSL_write failed")
        if sent % 4096 == 0:
            check_growth(pid, before, MAX_GROWTH, sent, "KeyUpdates")
    check_growth(pid, before, MAX_GROWTH, sent, "KeyUpdates")
    return sent, n


def noread(port, pid):
    sink = Sink()
    c = Client(port, rcvbuf=4096)
    connect_tunnel(c, sink)
    sent, n = flood_unread(c, pid)

    # Read again, and all must get going. This has no use for what it reads,
    # and SSL_read() would not get to the socket with a KeyUpdate of ours
    # stuck on its way out, so take it raw and finish that write.
    deadline = time.monotonic() + 60
    while n != 1 or sink.count < sent + 1:
        if time.monotonic() > deadline:
            return "tunnel did not resume: origin got %d of %d bytes" % (
                sink.count, sent + 1)
        try:
            if not c.s.recv(65536):
                return "proxy hung up"
        except BlockingIOError:
            select.select([c.s], [], [], 0.1)
        if n != 1:
            n = LIB.SSL_write(c.ssl, b"x", 1)
            if n != 1 and LIB.SSL_get_error(c.ssl, n) != SSL_ERROR_WANT_WRITE:
                return "SSL_write failed"
    return None


def udp(port, pid):
    # Much less and the answers to read below crawl through the tiny window.
    c = Client(port, rcvbuf=STRAND_RCVBUF)
    c.write(b"\x05\x01\x00")
    if c.read_some() != b"\x05\x00":
        return "SOCKS5 greeting refused"
    c.write(b"\x05\x03\x00\x01\0\0\0\0\0\0")
    rep = c.read_some()
    if len(rep) != 10 or rep[1] != 0:
        return "UDP ASSOCIATE got %r" % rep
    err = expect_answer(c, "on a UDP association")
    if err:
        return err
    c.drain(1)
    n = flood_unread(c, pid)[1]

    # Read again, and the proxy must take what the client still has to send.
    deadline = time.monotonic() + 90
    while n != 1:
        if time.monotonic() > deadline:
            return "association did not resume"
        try:
            if not c.s.recv(65536):
                return "proxy hung up"
        except BlockingIOError:
            select.select([c.s], [], [], 0.1)
        n = LIB.SSL_write(c.ssl, b"x", 1)
        if n != 1 and LIB.SSL_get_error(c.ssl, n) != SSL_ERROR_WANT_WRITE:
            return "SSL_write failed"
    return None


def burst(port, pid):
    sink = Sink()
    c = Client(port, rcvbuf=4096)
    connect_tunnel(c, sink)
    c.s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, BURST_SNDBUF)
    c.s.setblocking(False)

    def push(is_data):
        r = (LIB.SSL_write(c.ssl, b"x", 1) if is_data
             else LIB.SSL_do_handshake(c.ssl))
        if r == 1:
            return True
        if LIB.SSL_get_error(c.ssl, r) != SSL_ERROR_WANT_WRITE:
            raise RuntimeError("could not send to the proxy")
        return False

    before = vm_hwm(pid)
    pushed = sent = 0
    is_data = False
    c.key_update()
    last = time.monotonic()
    while time.monotonic() - last < STALL_SECS:
        if not push(is_data):
            select.select([], [c.s], [], 0.1)
            continue
        sent += is_data
        pushed += 1
        is_data = pushed % BURST_RUN == 0
        if not is_data:
            c.key_update()
        last = time.monotonic()
        if pushed % 4096 == 0:
            check_growth(pid, before, MAX_GROWTH, pushed, "messages")
    check_growth(pid, before, MAX_GROWTH, pushed, "messages")

    # As in noread: take it raw, and finish the message that got stuck.
    deadline = time.monotonic() + 60
    stuck = True
    while stuck or sink.count < sent:
        if time.monotonic() > deadline:
            return "tunnel did not resume: origin got %d of %d bytes" % (
                sink.count, sent)
        try:
            if not c.s.recv(65536):
                return "proxy hung up"
        except BlockingIOError:
            select.select([c.s], [], [], 0.1)
        if stuck and push(is_data):
            stuck = False
            sent += is_data
    return None


def stall_state(pid, c, sink, sent, stuck):
    """What a stalled round looks like, for the test's log: where the bytes
    the origin is short of could be, and what the proxy is waiting on."""
    import os
    import subprocess

    out = ["origin got %d of %d bytes, stuck message %s" %
           (sink.count, sent, "still unsent" if stuck else "sent")]
    try:
        r = subprocess.run(["ss", "-tnmiep"], capture_output=True, text=True,
                           timeout=5).stdout.splitlines()
        for i, l in enumerate(r):
            if "pid=%s," % pid in l:
                out += ["  ss " + x.strip() for x in r[i:i + 2]]
    except (OSError, subprocess.SubprocessError):
        out.append("  ss: not available")
    fds = "/proc/%s/fd" % pid
    try:
        for fd in sorted(os.listdir(fds), key=int):
            try:
                if os.readlink("%s/%s" % (fds, fd)) != "anon_inode:[io_uring]":
                    continue
                with open("/proc/%s/fdinfo/%s" % (pid, fd)) as f:
                    out += ["  io_uring fd %s: %s" % (fd, l.rstrip())
                            for l in f.read().splitlines()[:200]]
            except OSError:
                pass
    except OSError:
        out.append("  /proc/%s: gone" % pid)
    try:
        ti = c.s.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 256)
        out.append("  client tcp_info %d bytes: %s" % (len(ti), ti[:104].hex()))
    except OSError:
        pass
    return "\n".join(out)


def strand_round(port, pid):
    sink = Talker()
    # Its receive buffer is left to the kernel. Set, it cannot grow, and a
    # segment the window let in is dropped once it is full; the proxy takes
    # that for a loss and retransmits on a timer that doubles each time,
    # into a window that stays closed for as long as the flood below goes
    # on. When the reading starts, nothing comes until that timer runs out,
    # which can be longer than STRAND_STALL, and the proxy, holding back
    # while its answers are not taken, reads nothing from the client
    # either. Left alone, the buffer grows instead, and only the window
    # holds the proxy up, which reopens as soon as the client reads.
    #
    # Its segments are kept small, as on any real network. On the loopback
    # they can be as large as half the most the proxy ever offered, and
    # once the flood has queued them up that large, the window the proxy
    # offers later may stay below one of them: the client then sends only
    # when its zero-window probe timer runs out, and every segment of the
    # origin's talk that the proxy passes on puts that timer off again. On
    # CI that kept the client from sending anything for the whole 100 s,
    # with the proxy waiting for it, nothing of its own queued, and an
    # empty receive queue.
    c = Client(port, mss=STRAND_MSS)
    connect_tunnel(c, sink)
    c.s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, STRAND_SNDBUF)
    c.s.setblocking(False)

    def push(is_data):
        r = (LIB.SSL_write(c.ssl, STRAND_DATA, len(STRAND_DATA)) if is_data
             else LIB.SSL_do_handshake(c.ssl))
        if r > 0:
            return True
        if LIB.SSL_get_error(c.ssl, r) not in (SSL_ERROR_WANT_WRITE,
                                               SSL_ERROR_WANT_READ):
            raise RuntimeError("could not send to the proxy")
        return False

    before = vm_hwm(pid)
    pushed = sent = 0
    is_data = False
    c.key_update()
    last = time.monotonic()
    while time.monotonic() - last < 1:
        if not push(is_data):
            select.select([], [c.s], [], 0.05)
            continue
        sent += len(STRAND_DATA) if is_data else 0
        pushed += 1
        is_data = pushed % BURST_RUN == 0
        if not is_data:
            c.key_update()
        last = time.monotonic()
        if pushed % 4096 == 0:
            check_growth(pid, before, MAX_GROWTH, pushed, "messages")

    # In small, uneven steps, for the origin to get in between. Once the
    # message that got stuck is out the client sends nothing more, so what
    # the origin is short of by then is what the proxy took and sat on.
    stuck = True
    seen = -1
    start = time.monotonic()
    rd, sink0, sent0 = 0, sink.count, sent
    deadline = time.monotonic() + 100
    moved = time.monotonic()
    err = None
    while stuck or sink.count < sent:
        now = time.monotonic()
        if sink.count != seen:
            seen = sink.count
            moved = now
        if now > deadline or (not stuck and now - moved > STRAND_STALL):
            err = "tunnel did not resume: origin got %d of %d bytes" % (
                sink.count, sent)
            err += ("\n  %s after %.1f s of reading, %.1f s since the origin"
                    " last got data; client read %d bytes; at the start of"
                    " reading the origin had %d of %d; proxy pid %d" % (
                        "deadline" if now > deadline else "stall",
                        now - start, now - moved, rd, sink0, sent0, pid))
            err += "\n" + stall_state(pid, c, sink, sent, stuck)
            break
        try:
            d = c.s.recv(random.choice((256, 512, 1024, 4096)))
            if not d:
                err = "proxy hung up"
                break
            rd += len(d)
        except BlockingIOError:
            pass
        time.sleep(random.choice((0, 0.0002, 0.001)))
        if stuck and push(is_data):
            stuck = False
            sent += len(STRAND_DATA) if is_data else 0
    sink.stop = True
    c.s.close()
    return err


def strand(port, pid):
    for i in range(STRAND_ROUNDS):
        err = strand_round(port, pid)
        if err:
            return "round %d of %d: %s" % (i + 1, STRAND_ROUNDS, err)
    return None


def shut(port, pid):
    sink = Sink(shut=True)
    c = Client(port)
    connect_tunnel(c, sink)
    # Until the proxy's close_notify and FIN, so that all it has is sent.
    while True:
        n = LIB.SSL_read(c.ssl, c.buf, len(c.buf))
        if n <= 0:
            break

    # Each KeyUpdate goes with a byte, so what the origin got is how many of
    # them the proxy has handled. The client can be far ahead of that: the
    # sockets hold tens of thousands of them, and a proxy slowed down by load
    # may have handled only a few thousand by the time SHUT_SETTLE are sent.
    # Count from the proxy's progress, and look again once it is done.
    before = None

    def settled():
        nonlocal before
        if before is None and sink.count >= SHUT_SETTLE:
            before = vm_hwm(pid)
        return before is not None

    sent = 0
    while sent < SHUT_UPDATES:
        c.key_update()
        c.write(b"x")
        sent += 1
        if sent % 1024 == 0 and settled() and sent % 4096 == 0:
            check_growth(pid, before, SHUT_GROWTH, sink.count,
                         "KeyUpdates handled")
    # The proxy may still have most of them to handle, at its own pace: give
    # up only once it has stopped.
    seen, moved = -1, time.monotonic()
    while sink.count < sent:
        if sink.count != seen:
            seen, moved = sink.count, time.monotonic()
        elif time.monotonic() - moved > SHUT_STALL:
            return "origin got %d of %d bytes" % (sink.count, sent)
        settled()
        time.sleep(0.01)
    settled()
    check_growth(pid, before, SHUT_GROWTH, sent, "KeyUpdates")
    return None


def main():
    scenario, port, pid = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    try:
        err = {"answer": answer, "noread": noread, "burst": burst,
               "strand": strand, "shut": shut, "udp": udp}[scenario](port, pid)
    except (RuntimeError, OSError) as e:
        err = repr(e)
    print(err or "ok")


if __name__ == "__main__":
    main()
