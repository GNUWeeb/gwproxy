#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# SOCKS5 client that sends its greeting, the RFC 1929 credentials (with
# --user/--pass) and a CONNECT in a single write, over TLS with --tls, and
# then reads everything the proxy sends until it closes the connection.
# Prints what it got as hex, then "EOF" for a clean close, "RST" for a reset
# or "TIMEOUT" when the proxy kept the connection open for --wait seconds.
#
# Usage: socks5_pipelined_reply.py <proxy_port> <atyp:1|3|4> <dst> <dst_port>
#        [--user U --pass P] [--tls] [--wait SEC] [--read-delay SEC]
#
# --read-delay sleeps after the write, before the first read, so the proxy
# has answered by then whatever it is going to answer.

import socket
import ssl
import struct
import sys
import time


def main():
    port, atyp, dst, dport = (int(sys.argv[1]), int(sys.argv[2]),
                              sys.argv[3], int(sys.argv[4]))
    args = sys.argv[5:]

    def opt(name, conv, dflt):
        return conv(args[args.index(name) + 1]) if name in args else dflt

    user = opt("--user", str.encode, None)
    pw = opt("--pass", str.encode, b"")
    wait = opt("--wait", float, 10.0)
    delay = opt("--read-delay", float, 0.0)

    out = b"\x05\x01\x02" if user is not None else b"\x05\x01\x00"
    if user is not None:
        out += b"\x01" + bytes([len(user)]) + user + bytes([len(pw)]) + pw
    if atyp == 1:
        addr = socket.inet_aton(dst)
    elif atyp == 4:
        addr = socket.inet_pton(socket.AF_INET6, dst)
    else:
        addr = bytes([len(dst)]) + dst.encode()
    out += b"\x05\x01\x00" + bytes([atyp]) + addr + struct.pack(">H", dport)

    s = socket.create_connection(("127.0.0.1", port), timeout=wait)
    if "--tls" in args:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s)
    s.sendall(out)
    if delay:
        time.sleep(delay)

    got, end = b"", "TIMEOUT"
    deadline = time.monotonic() + wait
    try:
        while time.monotonic() < deadline:
            s.settimeout(max(deadline - time.monotonic(), 0.01))
            try:
                d = s.recv(4096)
            except ssl.SSLError as e:
                # A TLS peer that closes without close_notify.
                end = "EOF" if "EOF" in str(e) else "TLSERR"
                break
            if not d:
                end = "EOF"
                break
            got += d
    except socket.timeout:
        pass
    except ConnectionResetError:
        end = "RST"
    print(got.hex(), end)


if __name__ == "__main__":
    main()
