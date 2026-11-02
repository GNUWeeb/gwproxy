# SPDX-License-Identifier: GPL-2.0-only
#
# TLS client for t/0136: ends its stream in various ways and looks at what the
# origin behind the proxy makes of it.
#
# Usage: tls_cut_client.py <proxy_port> [<proxy_pid> [<connect_timeout>]]
#
# With a pid, stops that proxy in the middle of an upload instead, which is no
# end of the client's either. With its --connect-timeout as well, has it give up
# on a connect the kernel has finished but it has not been told about yet.
#
# Each scenario tunnels to an origin of its own through CONNECT. An end the
# client meant must reach the origin as an EOF, and one it did not as a reset.
# So must one that comes while the proxy is still connecting to the origin, which
# goes through SOCKS5 to have the request and what follows it in a single segment.
#
# Prints "ok" on success, or what went wrong.

import os
import signal
import socket
import ssl
import struct
import sys
import threading
import time

TIMEOUT = 60
# Two records, 16384 bytes and the rest.
PAYLOAD = b"A" * 30000
FIRST_RECORD = 16384


class Origin:
    def __init__(self):
        self.ls = socket.socket()
        self.ls.bind(("127.0.0.1", 0))
        self.ls.listen(1)
        self.ls.settimeout(TIMEOUT)
        self.port = self.ls.getsockname()[1]
        self.nr = 0
        self.end = None
        self.cond = threading.Condition()
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        end = "timeout"
        try:
            c, _ = self.ls.accept()
            c.settimeout(TIMEOUT)
            while True:
                d = c.recv(65536)
                if not d:
                    end = "eof"
                    break
                with self.cond:
                    self.nr += len(d)
                    self.cond.notify_all()
            c.close()
        except ConnectionResetError:
            end = "reset"
        except OSError as e:
            end = repr(e)
        with self.cond:
            self.end = end
            self.cond.notify_all()

    def wait_nr(self, nr):
        """Wait until the origin has that much, or has seen the end."""
        with self.cond:
            self.cond.wait_for(lambda: self.nr >= nr or self.end, TIMEOUT)

    def result(self):
        self.thread.join()
        self.ls.close()
        return self.nr, self.end


class Client:
    def __init__(self, port, origin_port, maxver):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.maximum_version = maxver
        self.inb, self.outb = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.o = ctx.wrap_bio(self.inb, self.outb)
        self.s = socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT)
        self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        while True:
            try:
                self.o.do_handshake()
                break
            except ssl.SSLWantReadError:
                self.flush()
                self.inb.write(self.s.recv(65536))
        self.flush()
        if origin_port is None:
            return
        self.o.write(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: x\r\n\r\n"
                     % origin_port)
        self.flush()
        got = b""
        while b"\r\n\r\n" not in got:
            d = self.s.recv(65536)
            if not d:
                raise RuntimeError("proxy hung up ahead of its reply")
            self.inb.write(d)
            try:
                while True:
                    got += self.o.read(65536)
            except ssl.SSLWantReadError:
                pass
        if b" 200 " not in got:
            raise RuntimeError("proxy said %r" % got)

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

    def close(self):
        self.s.close()


def clean(c, o):
    c.o.write(PAYLOAD)
    c.close_notify()
    return len(PAYLOAD), "eof"


def clean_fin(c, o):
    c.o.write(PAYLOAD)
    c.close_notify()
    c.s.shutdown(socket.SHUT_WR)
    return len(PAYLOAD), "eof"


def bare_fin(c, o):
    # No telling this one from a client that does not bother: it stays an EOF.
    c.o.write(PAYLOAD)
    c.flush()
    o.wait_nr(len(PAYLOAD))
    c.s.shutdown(socket.SHUT_WR)
    return len(PAYLOAD), "eof"


def cut_header(c, o):
    c.o.write(PAYLOAD)
    d = c.outb.read()
    c.s.sendall(d)
    o.wait_nr(len(PAYLOAD))
    c.o.write(b"more")
    c.s.sendall(c.outb.read()[:3])
    c.s.shutdown(socket.SHUT_WR)
    return len(PAYLOAD), "reset"


def cut_after_header(c, o):
    # The engine takes the whole header and has nothing left but its wait.
    c.o.write(PAYLOAD)
    c.flush()
    o.wait_nr(len(PAYLOAD))
    c.o.write(b"more")
    c.s.sendall(c.outb.read()[:5])
    time.sleep(0.2)
    c.s.shutdown(socket.SHUT_WR)
    return len(PAYLOAD), "reset"


def cut_record(c, o):
    c.o.write(PAYLOAD)
    c.s.sendall(c.outb.read()[:-5])
    o.wait_nr(FIRST_RECORD)
    c.s.shutdown(socket.SHUT_WR)
    return FIRST_RECORD, "reset"


def bad_record(c, o):
    c.o.write(PAYLOAD)
    c.flush()
    o.wait_nr(len(PAYLOAD))
    c.s.sendall(b"\x17\x03\x03\x00\x40" + b"\xaa" * 64)
    return len(PAYLOAD), "reset"


def fatal_alert(c, o):
    c.o.write(PAYLOAD)
    c.flush()
    o.wait_nr(len(PAYLOAD))
    # A record that fails to verify has the client's engine send a real one.
    c.inb.write(b"\x17\x03\x03\x00\x20" + b"\0" * 32)
    try:
        c.o.read(16)
    except ssl.SSLError:
        pass
    c.flush()
    return len(PAYLOAD), "reset"


def tcp_reset(c, o):
    c.o.write(PAYLOAD)
    c.flush()
    o.wait_nr(len(PAYLOAD))
    c.s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    c.s.close()
    return len(PAYLOAD), "reset"


SCENARIOS = [clean, clean_fin, bare_fin, cut_header, cut_after_header,
             cut_record, bad_record, fatal_alert, tcp_reset]


def stop_proxy(port, pid):
    o = Origin()
    c = Client(port, o.port, ssl.TLSVersion.TLSv1_3)
    c.o.write(PAYLOAD)
    c.flush()
    o.wait_nr(len(PAYLOAD))
    os.kill(pid, signal.SIGTERM)
    got = o.result()
    c.close()
    if got != (len(PAYLOAD), "reset"):
        print("stop_proxy: origin got %d bytes and %s" % got)
        return 1
    print("ok")
    return 0


def socks5_handshake(port, maxver):
    """A client past the handshake, and a stream to send its request on."""
    c = Client(port, None, maxver)
    c.o.write(b"\x05\x01\x00")
    c.flush()
    got = b""
    while len(got) < 2:
        c.inb.write(c.s.recv(65536))
        try:
            got += c.o.read(2)
        except ssl.SSLWantReadError:
            pass
    return c


def socks5_request(c, origin_port):
    c.o.write(b"\x05\x01\x00\x01\x7f\x00\x00\x01"
              + struct.pack(">H", origin_port))
    return c.outb.read()


def connecting_reset(port, maxver):
    # The request's connect is under way when the reset arrives.
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    c = socks5_handshake(port, maxver)
    c.s.sendall(socks5_request(c, ls.getsockname()[1]))
    c.s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    c.close()
    return ls, None


def connecting_bad_record(port, maxver):
    # A record that does not verify behind the request and data for the target.
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    c = socks5_handshake(port, maxver)
    d = socks5_request(c, ls.getsockname()[1])
    c.o.write(b"A" * 100)
    c.s.sendall(d + c.outb.read() + b"\x17\x03\x03\x00\x40" + b"\xaa" * 64)
    return ls, c


def connecting_end(ls, c):
    """How the target's connection ended, if there came to be one."""
    if c:
        # The pair is gone when the client's socket says so.
        try:
            while c.s.recv(65536):
                pass
        except OSError:
            pass
        c.close()
    # Nothing to wait for if the proxy never got to connect, so not for long.
    ls.settimeout(1)
    try:
        s, _ = ls.accept()
    except socket.timeout:
        return "no connection"
    finally:
        ls.close()
    return target_end(s)


def target_end(s):
    s.settimeout(TIMEOUT)
    try:
        while s.recv(65536):
            pass
        return "eof"
    except ConnectionResetError:
        return "reset"
    finally:
        s.close()


def connecting(port):
    # Whether the proxy connects at all depends on the race, but what the target
    # gets to see of it must not be an end of stream. The reset goes against a
    # race, so it gets a few tries.
    for maxver in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
        for f, nr in ((connecting_reset, 10), (connecting_bad_record, 2)):
            for _ in range(nr):
                end = connecting_end(*f(port, maxver))
                if end == "eof":
                    print("%s, max %s: origin got an eof"
                          % (f.__name__, maxver.name))
                    return 1
    return 0


def syn_sent_to(port):
    with open("/proc/net/tcp") as f:
        for line in f.readlines()[1:]:
            x = line.split()
            if x[3] == "02" and x[2].endswith(":%04X" % port):
                return True
    return False


def all_stopped(pid):
    for t in os.listdir("/proc/%d/task" % pid):
        with open("/proc/%d/task/%s/stat" % (pid, t)) as f:
            if f.read().rsplit(")", 1)[1].split()[0] != "T":
                return False
    return True


def wait_for(cond):
    end = time.monotonic() + TIMEOUT
    while not cond():
        if time.monotonic() > end:
            raise RuntimeError("timed out on %s" % cond)
        time.sleep(0.001)


def timed_out_connected_once(port, pid, connect_timeout):
    """
    Have the proxy find its connect timeout expired ahead of the connect that
    has by then succeeded, so it drops the attempt with the target on the other
    end. A full accept queue holds the connect back, which the kernel retries on
    its own, and a stopped proxy sees both events only once they have happened,
    in that order. Returns how the target's connection ended, or None if the
    timeout beat the stop on a slow machine and the try says nothing.
    """
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    lport = ls.getsockname()[1]
    ls.settimeout(TIMEOUT)
    fill = [socket.create_connection(("127.0.0.1", lport)) for _ in range(2)]
    c = socks5_handshake(port, ssl.TLSVersion.TLSv1_3)
    c.s.sendall(socks5_request(c, lport))
    try:
        wait_for(lambda: syn_sent_to(lport))
    except RuntimeError:
        # Stalled past the proxy's connect timeout: the attempt is gone.
        c.close()
        for f in fill:
            f.close()
        ls.close()
        return None
    os.kill(pid, signal.SIGSTOP)
    s = None
    try:
        wait_for(lambda: all_stopped(pid))
        if syn_sent_to(lport):
            time.sleep(connect_timeout + 0.5)
            for _ in fill:
                ls.accept()[0].close()
            s, _ = ls.accept()
    finally:
        os.kill(pid, signal.SIGCONT)
    # If the proxy took it as connected after all, the reset ends it just as well.
    c.s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    c.close()
    for f in fill:
        f.close()
    ls.close()
    return target_end(s) if s else None


def timed_out_connected(port, pid, connect_timeout):
    for _ in range(5):
        end = timed_out_connected_once(port, pid, connect_timeout)
        if end:
            if end != "reset":
                print("origin got %s" % end)
                return 1
            break
    print("ok")
    return 0


def main():
    port = int(sys.argv[1])
    if len(sys.argv) > 3:
        return timed_out_connected(port, int(sys.argv[2]), int(sys.argv[3]))
    if len(sys.argv) > 2:
        return stop_proxy(port, int(sys.argv[2]))
    for maxver in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
        for f in SCENARIOS:
            o = Origin()
            c = Client(port, o.port, maxver)
            nr, end = f(c, o)
            got = o.result()
            c.close()
            if got != (nr, end):
                print("%s, max %s: origin got %d bytes and %s, not %d and %s"
                      % (f.__name__, maxver.name, got[0], got[1], nr, end))
                return 1
    if connecting(port):
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
