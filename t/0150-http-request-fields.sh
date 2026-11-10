#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Which request fields the proxy lets through, and what stays refused. A field
# value may hold obs-text (bytes 0x80-0xff), passed on unchanged, and a field
# not defined to appear once may be repeated. None of that may open the way to
# request smuggling: a framing field the proxy cannot read exactly as a number
# or as "chunked" is refused, whatever bytes surround it, and so is a byte that
# some peer could take for a line end or for part of a field name: each with a
# 400. Whatever is
# accepted is compared byte for byte with what reaches the origin, which sees
# that one request and nothing behind it.

. "$(dirname "$0")/lib.sh"
require python3

printf 'user:pass\n' >"$WORK/auth"

cat >"$WORK/drive.py" <<'EOF'
import socket, sys, threading, time

port, aport = int(sys.argv[1]), int(sys.argv[2])
lock = threading.Lock()
got, conns = [], [0]


def framed(buf):
    """Whether @buf holds a whole request, by the rules of a plain origin."""
    head, sep, rest = buf.partition(b'\r\n\r\n')
    if not sep:
        return False
    for line in head.split(b'\r\n')[1:]:
        name, _, val = line.partition(b':')
        if name.lower() == b'content-length':
            return len(rest) >= int(val)
        if name.lower() == b'transfer-encoding':
            return rest.endswith(b'0\r\n\r\n')
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


def xact(p, req):
    """Send @req, return the reply's status line, or CLOSED if there is none."""
    s = socket.create_connection(('127.0.0.1', p))
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


def req(lines, tail=b'', method=b'GET', p=b''):
    return (b'%s http://%s/ HTTP/1.1\r\n' % (method, auth) +
            b''.join(l + b'\r\n' for l in lines) + b'\r\n' + tail + p)


def out(lines, tail=b'', method=b'GET'):
    return (b'%s / HTTP/1.1\r\nHost: %s\r\n' % (method, auth) +
            b''.join(l + b'\r\n' for l in lines) +
            b'Connection: close\r\n\r\n' + tail)


def ok(name, data, want, p=None):
    """@data is accepted and the origin gets exactly @want."""
    with lock:
        n = len(got)
    st = xact(p or port, data)
    if not st.startswith('HTTP/1.1 200 '):
        return fail(name, 'got %r, want 200' % st)
    if not wait_got(n + 1):
        return fail(name, 'the origin saw no request')
    with lock:
        seen = got[n]
    if seen != want:
        fail(name, 'origin got %r, want %r' % (seen, want))


def no(name, data, want, p=None):
    """@data gets status @want, and the origin hears nothing of it."""
    with lock:
        n = conns[0]
    st = xact(p or port, data)
    if not st.startswith(want):
        fail(name, 'got %r, want %r' % (st, want))
    with lock:
        if conns[0] != n:
            fail(name, 'reached the origin')


def connect_ok(name, lines):
    """A CONNECT with these fields tunnels, and they go no further."""
    with lock:
        n = len(got)
    s = socket.create_connection(('127.0.0.1', port))
    s.settimeout(20)
    s.sendall(b'CONNECT %s HTTP/1.1\r\n' % auth +
              b''.join(l + b'\r\n' for l in lines) + b'\r\n')
    r = b''
    try:
        while b'\r\n\r\n' not in r:
            d = s.recv(4096)
            if not d:
                break
            r += d
        if r != b'HTTP/1.1 200 OK\r\n\r\n':
            s.close()
            return fail(name, 'got %r' % r)
        s.sendall(b'ping\r\n\r\n')
        while s.recv(4096):
            pass
    except OSError as e:
        fail(name, repr(e))
    s.close()
    if not wait_got(n + 1):
        return fail(name, 'the origin saw nothing')
    with lock:
        seen = got[n]
    if seen != b'ping\r\n\r\n':
        fail(name, 'origin got %r' % seen)


BAD = 'HTTP/1.1 400 '

# obs-text is passed on unchanged, wherever it is in the value.
for v in (b'caf\xc3\xa9', b'caf\xe9', b'a\x80b', b'a\xffb', b'\x80', b'\xff',
          b'\xc2\xa0x\xc2\x85', b'a\t\xa0 b'):
    ok('obs-text %r' % v, req([b'X-Name: ' + v]), out([b'X-Name: ' + v]))
    connect_ok('CONNECT obs-text %r' % v, [b'X-Name: ' + v])
ok('obs-text in a merged list', req([b'Accept: \xc3\xa9', b'Accept: b']),
   out([b'Accept: \xc3\xa9, b']))

# ... and the framing is the framing: the body goes on, what follows does not.
evil = b'GET http://evil/ HTTP/1.1\r\nHost: evil\r\n\r\n'
ok('obs-text, Content-Length body',
   req([b'X-N: \xff', b'Content-Length: 4'], b'body' + evil, b'POST'),
   out([b'X-N: \xff', b'Content-Length: 4'], b'body', b'POST'))
ok('obs-text, chunked body',
   req([b'X-N: \xa0', b'Transfer-Encoding: chunked'],
       b'4\r\nbody\r\n0\r\n\r\n' + evil, b'POST'),
   out([b'X-N: \xa0', b'Transfer-Encoding: chunked'],
       b'4\r\nbody\r\n0\r\n\r\n', b'POST'))

# A framing field that is not exactly what it should be is refused. Bytes that
# some peer may strip as white space or fold to something else count as well.
for v in (b'4\xa0', b'\xa04', b'4\x85', b'\xc2\xa04', b'4\xc2\x85', b'\xef\xbb\xbf4'):
    no('Content-Length %r' % v,
       req([b'Content-Length: ' + v], b'body' + evil, b'POST'), BAD)
for v in (b'chunked\xa0', b'\xa0chunked', b'chunked\x85', b'\xc2\xa0chunked',
          b'chunke\xc4\x8f', b'ch\xc5\xabnked'):
    no('Transfer-Encoding %r' % v,
       req([b'Transfer-Encoding: ' + v], b'0\r\n\r\n' + evil, b'POST'), BAD)
no('Connection naming a framing field, after obs-text',
   req([b'Connection: \xa0, Content-Length', b'Content-Length: 4'], b'body',
       b'POST'), BAD)

# Field names are tokens, and only the value may hold these bytes.
for l in (b'Content-Length\xa0: 4', b'\xa0Content-Length: 4',
          b'Transfer-Encoding\x85: chunked', b'X-\xc3\xa9: 1', b'\xff: 1'):
    no('name %r' % l, req([l], b'body', b'POST'), BAD)

# Nor does a control byte get in by standing next to one of them.
for v in (b'\xc3\x00', b'\x00\xc3', b'a\x01\xff', b'\xff\x7f', b'\xa0\x1f',
          b'\xc3\rContent-Length: 0', b'\xa0\rX: 1'):
    no('control byte in %r' % v, req([b'X-N: ' + v]), BAD)
# A line folded behind obs-text, which an origin could read as its own field.
no('obs-fold', req([b'X-N: \xa0', b' Content-Length: 0']), BAD)

# It is not a credential, and must not be taken for part of one.
ok('good credentials, obs-text elsewhere',
   req([b'Proxy-Authorization: Basic dXNlcjpwYXNz', b'X-N: \xff']),
   out([b'X-N: \xff']), aport)
for v in (b'Basic \xc3\xa9', b'\xff', b'Basic dXNlcjpwYXNz\xa0',
          b'Basic \xa0dXNlcjpwYXNz'):
    no('credentials %r' % v, req([b'Proxy-Authorization: ' + v]),
       'HTTP/1.1 407 ', aport)

# A repeated field that is neither singular nor a known list keeps its lines:
# same spelling, same order, the fields around it where they were.
for name in (b'X-Forwarded-For', b'Forwarded', b'Content-Language', b'X-A',
             b'Set-Cookie', b'Via-Extension'):
    lines = [name + b': 1', b'X-Other: y', name.lower() + b': 2',
             name + b': \xc3\xa9, 3']
    ok('repeated %r' % name, req(lines), out(lines))
    connect_ok('CONNECT repeated %r' % name, lines)

# That changes nothing about where the request ends.
ok('repeated, Content-Length body',
   req([b'X-A: 1', b'Content-Length: 4', b'X-A: 2'], b'body' + evil, b'POST'),
   out([b'X-A: 1', b'Content-Length: 4', b'X-A: 2'], b'body', b'POST'))
ok('repeated, chunked body',
   req([b'X-A: 1', b'Transfer-Encoding: chunked', b'X-A: 2'],
       b'0\r\n\r\n' + evil, b'POST'),
   out([b'X-A: 1', b'Transfer-Encoding: chunked', b'X-A: 2'], b'0\r\n\r\n',
       b'POST'))
ok('no body, something behind the header',
   req([b'X-A: 1', b'X-A: 2'], evil), out([b'X-A: 1', b'X-A: 2']))

# Hop-by-hop and Connection-listed fields go, every line of them.
ok('repeated hop-by-hop',
   req([b'Keep-Alive: 1', b'X-A: 1', b'keep-alive: 2', b'Proxy-Connection: a',
        b'Proxy-Connection: b']), out([b'X-A: 1']))
ok('repeated, named by Connection',
   req([b'X-Drop: 1', b'Connection: x-drop', b'x-drop: 2', b'X-A: 1',
        b'X-DROP: 3']), out([b'X-A: 1']))
ok('Transfer-Encoding with an empty line',
   req([b'Transfer-Encoding:', b'Transfer-Encoding: chunked'],
       b'0\r\n\r\n', b'POST'),
   out([b'Transfer-Encoding: chunked'], b'0\r\n\r\n', b'POST'))

# Two of a field that delimits or routes the request: never, whatever they say.
CL = b'Content-Length'
for a, b in ((b'4', b'4'), (b'4', b'0'), (b'0', b'4'), (b'', b'4'), (b'4', b'')):
    for n2 in (CL, CL.lower(), CL.upper()):
        no('two Content-Length %r %r' % (a, b),
           req([CL + b': ' + a, n2 + b': ' + b], b'body' + evil, b'POST'), BAD)
no('Content-Length apart', req([CL + b': 4', b'X-A: 1', b'X-A: 2', CL + b': 4'],
                               b'body', b'POST'), BAD)
TE = b'Transfer-Encoding'
for a, b in ((b'chunked', b'chunked'), (b'chunked', b'identity'),
             (b'identity', b'chunked'), (b'gzip', b'chunked'),
             (b'', b'')):
    no('two Transfer-Encoding %r %r' % (a, b),
       req([TE + b': ' + a, TE.lower() + b': ' + b], b'0\r\n\r\n' + evil,
           b'POST'), BAD)
no('both framing fields',
   req([TE + b': chunked', CL + b': 4', b'X-A: 1', b'X-A: 2'], b'body', b'POST'),
   BAD)
no('Connection lines adding up to a framing field',
   req([b'Connection: x', b'Connection: Content-Length', CL + b': 4'],
       b'body', b'POST'), BAD)
no('two Host', req([b'Host: a', b'hOST: b']), BAD)

# The rest of the fields defined to appear once stay refused as well, and on a
# CONNECT too.
for n in (b'Authorization', CL, b'Content-Location', b'Content-Range',
          b'Content-Type', b'Cookie', b'Date', b'Expect', b'From', b'Host',
          b'If-Modified-Since', b'If-Range', b'If-Unmodified-Since',
          b'Max-Forwards', b'Origin', b'Proxy-Authorization', b'Referer',
          b'User-Agent'):
    no('two %r' % n, req([n + b': 1', n.lower() + b': 1']), BAD)
    no('CONNECT two %r' % n,
       b'CONNECT %s HTTP/1.1\r\n%s: 1\r\n%s: 1\r\n\r\n' %
       (auth, n, n.lower()), BAD)

# Which credentials count is never up for interpretation.
good = b'Proxy-Authorization: Basic dXNlcjpwYXNz'
no('credentials twice', req([good, good]), BAD, aport)
no('good credentials after bad',
   req([b'Proxy-Authorization: Basic eDp5', good]), BAD, aport)

sys.exit(1 if errors else 0)
EOF

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-http=1 --event-loop="$loop" --nr-workers=1
	pid1="$GWP_PID"
	ap="$(pick_port)"
	gwp_start "127.0.0.1:$ap" --as-http=1 --event-loop="$loop" \
		--nr-workers=1 --auth-file="$WORK/auth"
	rc=0
	timeout 150 python3 "$WORK/drive.py" "$pp" "$ap" \
		>"$WORK/drive.$loop.out" 2>&1 || rc=$?
	kill "$pid1" "$GWP_PID" 2>/dev/null
	if [ "$rc" != 0 ]; then
		sed 's/^/# /' "$WORK/drive.$loop.out" >&2
		fail "[$loop] request fields (rc=$rc)"
	fi
done

pass
