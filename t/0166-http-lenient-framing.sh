#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Request framing that a strict origin and a lenient one could read apart is
# refused with 400 before anything reaches the origin: a chunk extension off
# the RFC 9112 Section 7.1.1 grammar (an unterminated quoted-string, an empty
# extension), a Content-Length beyond a signed 64-bit integer, and a field
# name that is a framing or hop-by-hop field with '_' for '-', which a
# CGI-style origin maps to the same variable. What is valid still goes through
# byte for byte: well-formed extensions, a body of many GiB announced by its
# Content-Length, and ordinary names with underscores.

. "$(dirname "$0")/lib.sh"
require python3

cat >"$WORK/drive.py" <<'EOF'
import socket, sys, threading, time

port = int(sys.argv[1])
lock = threading.Lock()
got, conns = [], [0]


def framed(buf):
    """Whether @buf holds a whole request, by the rules of a plain origin.
    A body announced as larger than sent ends with the marker END, as the
    test never sends the many GiB it announces."""
    head, sep, rest = buf.partition(b'\r\n\r\n')
    if not sep:
        return False
    for line in head.split(b'\r\n')[1:]:
        name, _, val = line.partition(b':')
        if name.lower() == b'content-length':
            return len(rest) >= int(val) or rest.endswith(b'END')
        if name.lower() == b'transfer-encoding':
            # The last chunk may carry extensions too.
            return rest.endswith(b'\r\n\r\n')
    return True


def origin_conn(c):
    buf = b''
    c.settimeout(10)
    try:
        while not framed(buf):
            d = c.recv(65536)
            if not d:
                break
            buf += d
        c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n'
                  b'Connection: close\r\n\r\nok')
        # Anything behind the request would be a request of the client's.
        c.settimeout(0.2)
        while True:
            d = c.recv(65536)
            if not d:
                break
            buf += d
    except (OSError, ValueError):
        pass
    c.close()
    with lock:
        got.append(buf)


def origin():
    while True:
        c, _ = ls.accept()
        with lock:
            conns[0] += 1
        threading.Thread(target=origin_conn, args=(c,), daemon=True).start()


ls = socket.socket()
ls.bind(('127.0.0.1', 0))
ls.listen(64)
oport = ls.getsockname()[1]
threading.Thread(target=origin, daemon=True).start()
auth = b'127.0.0.1:%d' % oport
errors = 0


def xact(req):
    """Send @req, return the reply's status line, or CLOSED if there is none."""
    s = socket.create_connection(('127.0.0.1', port))
    s.settimeout(20)
    r = b''
    try:
        s.sendall(req)
        while True:
            d = s.recv(4096)
            if not d:
                break
            r += d
    except OSError:
        pass
    s.close()
    return r.split(b'\r\n', 1)[0].decode('latin-1') or 'CLOSED'


def wait_got(n):
    for _ in range(1000):
        with lock:
            if len(got) >= n:
                return True
        time.sleep(0.02)
    return False


def fail(name, msg):
    global errors
    errors += 1
    print('%s: %s' % (name, msg))


def req(lines, tail=b''):
    return (b'POST http://%s/ HTTP/1.1\r\n' % auth +
            b''.join(l + b'\r\n' for l in lines) + b'\r\n' + tail)


def out(lines, tail=b''):
    return (b'POST / HTTP/1.1\r\nHost: %s\r\n' % auth +
            b''.join(l + b'\r\n' for l in lines) +
            b'Connection: close\r\n\r\n' + tail)


def ok(name, data, want):
    """@data is accepted and the origin gets exactly @want."""
    with lock:
        n = len(got)
    st = xact(data)
    if not st.startswith('HTTP/1.1 200 '):
        return fail(name, 'got %r, want 200' % st)
    if not wait_got(n + 1):
        return fail(name, 'the origin saw no request')
    with lock:
        seen = got[n]
    if seen != want:
        fail(name, 'origin got %r, want %r' % (seen, want))


def bad(name, data):
    """@data gets a 400, and the origin hears nothing of it."""
    with lock:
        n = conns[0]
    st = xact(data)
    if not st.startswith('HTTP/1.1 400 '):
        fail(name, 'got %r, want 400' % st)
    with lock:
        if conns[0] != n:
            fail(name, 'reached the origin')


evil = b'GET http://evil/ HTTP/1.1\r\nHost: evil\r\n\r\n'
TE = b'Transfer-Encoding: chunked'

# Chunk extensions: what the grammar allows goes through unchanged...
for ext in (b';a', b';a=b', b' ; a = b', b';a="q \\" ;\\\\";b=""',
            b';a=1;b;c="x\xa0"', b'\t;a\t=\t"\t"'):
    body = b'5' + ext + b'\r\nhello\r\n0' + ext + b'\r\n\r\n'
    ok('extension %r' % ext, req([TE], body + evil), out([TE], body))

# ... and what it does not is refused, with nothing passed on.
for ext in (b';', b';;a', b';a;', b'; ', b';=b', b';a=', b';a==b', b';a b',
            b';a=b c', b';a ', b';a=b ', b';a="b" ', b';a="b"c', b';a(b)',
            b';a=b,c', b';a="', b';a="b\\"', b';a="b\\', b';a="b\x01"',
            b';a\xa0', b';a="\x7f"'):
    bad('extension %r' % ext,
        req([TE], b'5' + ext + b'\r\nhello\r\n0\r\n\r\n'))
# The case the review found: a quoted-string left open, which an origin that
# reads it on past the line end takes as eating the next chunk.
bad('unterminated quoted-string',
    req([TE], b'35;a="\r\n' + b'x' * 0x35 + b'\r\n0\r\n\r\n' + evil))
bad('empty extension on the last chunk', req([TE], b'0;\r\n\r\n' + evil))

# Content-Length: up to the largest signed 64-bit value, which an origin
# reading it as an off_t still holds; one more is refused, as are signs and
# white space inside the digits.
for v in (b'5368709120', b'9223372036854775807', b'09223372036854775807'):
    ok('Content-Length %r' % v,
       req([b'Content-Length: ' + v], b'body-END'),
       out([b'Content-Length: ' + v], b'body-END'))
for v in (b'9223372036854775808', b'18446744073709551615',
          b'18446744073709551616', b'99999999999999999999', b'+4', b'-4',
          b'4 4', b'4\t4', b'4,4', b'0x4', b'4.0'):
    bad('Content-Length %r' % v,
        req([b'Content-Length: ' + v], b'body' + evil))

# A field name that is one of the fields read or dropped here, spelt with
# '_' for '-', is refused in any case and wherever the '_' is...
for n in (b'Content_Length', b'content_length', b'CONTENT_LENGTH',
          b'Transfer_Encoding', b'transfer_encoding', b'Proxy_Connection',
          b'Keep_Alive', b'Proxy_Authorization', b'Proxy_Authenticate'):
    bad('field %r' % n, req([n + b': 4', b'Content-Length: 4'], b'body'))
    bad('field %r alone' % n, req([n + b': 4'], b'body' + evil))
bad('Transfer_Encoding next to chunked',
    req([b'Transfer_Encoding: chunked', TE], b'0\r\n\r\n'))

# ... but other names with underscores, and these names spelt right, are not.
lines = [b'X_Custom_Header: 1', b'Content_Type: text/plain', b'Max_Forwards: 2',
         b'Accept_Language: x', b'my_header_: y', b'_: z', b'Content__Length: 1',
         b'Content-Length_: 1', b'Content_Lengthx: 1', b'Content-Length: 4']
ok('ordinary underscores', req(lines, b'body' + evil), out(lines, b'body'))

sys.exit(1 if errors else 0)
EOF

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-http=1 --event-loop="$loop" --nr-workers=1
	rc=0
	timeout 150 python3 "$WORK/drive.py" "$pp" \
		>"$WORK/drive.$loop.out" 2>&1 || rc=$?
	kill "$GWP_PID" 2>/dev/null
	if [ "$rc" != 0 ]; then
		sed 's/^/# /' "$WORK/drive.$loop.out" >&2
		fail "[$loop] lenient request framing (rc=$rc)"
	fi
done

pass
