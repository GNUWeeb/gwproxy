#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A forwarding HTTP proxy names itself in the Via header of what it forwards
# (RFC 9110 Section 7.6.3): the request to the origin and the origin's final
# response to the client each get "Via: <version> gwproxy", with the version
# of HTTP the message was received with, at the end of a Via already there.
# A CONNECT tunnel carries bytes, not messages, and is left alone. On every
# available event loop.

. "$(dirname "$0")/lib.sh"
require python3

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-http=1 --event-loop="$loop" \
		--nr-workers=1
	out="$(timeout 60 python3 - "$pp" <<'PY' 2>&1
import socket, sys

proxy = ("127.0.0.1", int(sys.argv[1]))
ls = socket.socket()
ls.bind(("127.0.0.1", 0))
ls.listen(1)
ls.settimeout(20)
op = ls.getsockname()[1]
bad = []


def read_hdr(s):
    got = b""
    while b"\r\n\r\n" not in got:
        d = s.recv(4096)
        if not d:
            break
        got += d
    return got


def via(hdr):
    return [l.split(b":", 1)[1].strip() for l in hdr.split(b"\r\n")[1:]
            if l.lower().startswith(b"via:")]


def exchange(name, req, res, want_req, want_res, connect=False):
    c = socket.create_connection(proxy, timeout=20)
    if connect:
        c.sendall(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\n"
                  b"Host: 127.0.0.1:%d\r\n\r\n" % (op, op))
        o, _ = ls.accept()
        r = read_hdr(c)
        if not r.startswith(b"HTTP/1.1 200"):
            bad.append("%s: CONNECT reply %r" % (name, r[:40]))
            return
    c.sendall(req)
    if not connect:
        o, _ = ls.accept()
    o.settimeout(20)
    got = read_hdr(o)
    if via(got) != want_req:
        bad.append("%s: origin saw Via %r, want %r" % (name, via(got),
                                                        want_req))
    o.sendall(res)
    o.close()
    back = b""
    while True:
        d = c.recv(65536)
        if not d:
            break
        back += d
    c.close()
    if not back.endswith(b"\r\n\r\nok"):
        bad.append("%s: client got %r" % (name, back[:200]))
        return
    hdrs = back[:-2].split(b"\r\n\r\n")[:-1]
    if via(hdrs[-1]) != want_res:
        bad.append("%s: client saw Via %r, want %r" % (name, via(hdrs[-1]),
                                                        want_res))
    for h in hdrs[:-1]:
        if via(h):
            bad.append("%s: interim response got Via %r" % (name, via(h)))


url = b"http://127.0.0.1:%d/" % op
exchange("plain",
         b"GET " + url + b" HTTP/1.1\r\nHost: x\r\n\r\n",
         b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
         [b"1.1 gwproxy"], [b"1.1 gwproxy"])
exchange("appended",
         b"GET " + url + b" HTTP/1.0\r\nVia: 1.1 client\r\n\r\n",
         b"HTTP/1.0 200 OK\r\nVia: 1.1 up\r\nContent-Length: 2\r\n\r\nok",
         [b"1.1 client, 1.0 gwproxy"], [b"1.1 up, 1.0 gwproxy"])
# An interim response passes as it came; the final one gets the Via.
exchange("interim",
         b"GET " + url + b" HTTP/1.1\r\n\r\n",
         b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n"
         b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
         [b"1.1 gwproxy"], [b"1.1 gwproxy"])
exchange("connect",
         b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
         b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
         [], [], connect=True)
if bad:
    print("\n".join(bad))
    sys.exit(1)
PY
)" || fail "[$loop] $out"
	kill "$GWP_PID" 2>/dev/null
done

pass
