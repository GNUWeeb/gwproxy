#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A request that is recognisably HTTP, a method token and a space, is
# answered rather than dropped without a word when it cannot be served:
# "400 Bad Request" for a malformed request line or field line (obs-fold and
# white space before the colon among them, RFC 9112 Section 5) and for a
# target without a usable authority, "501 Not Implemented" for origin-form,
# asterisk-form and other schemes than http://, "505 HTTP Version Not
# Supported" for HTTP/2 and later. None of them reaches the origin. One empty
# line before the request line is skipped (RFC 9112 Section 2.2), and an
# HTTP/1.x request above 1.1 is served as HTTP/1.1 (RFC 9110 Section 2.5).

. "$(dirname "$0")/lib.sh"
require python3

cat >"$WORK/drive.py" <<'EOF'
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[2])
import http_check as hc

port = int(sys.argv[1])
o = hc.Origin()
auth = b'127.0.0.1:%d' % o.port
errors = 0


def fail(name, msg):
    global errors
    errors += 1
    print('%s: %s' % (name, msg))


def no(name, data, want):
    n = o.count()
    st = hc.status(hc.xact(port, data))
    if not st.startswith(want):
        fail(name, 'got %r, want %r' % (st, want))
    if o.count() != n:
        fail(name, 'reached the origin')


def ok(name, data, want):
    n = o.nr_reqs()
    st = hc.status(hc.xact(port, data))
    if not st.startswith('HTTP/1.1 200 '):
        return fail(name, 'got %r, want 200' % st)
    got = o.wait(n + 1)
    if got != want:
        fail(name, 'origin got %r, want %r' % (got, want))


BAD, NI, VER = 'HTTP/1.1 400 ', 'HTTP/1.1 501 ', 'HTTP/1.1 505 '
u = b'http://%s/' % auth
for name, req, want in (
        ('obs-fold', b'GET %s HTTP/1.1\r\nX: a\r\n  b\r\n\r\n' % u, BAD),
        ('space before colon', b'GET %s HTTP/1.1\r\nHost : x\r\n\r\n' % u,
         BAD),
        ('control byte in a value', b'GET %s HTTP/1.1\r\nX: a\x01\r\n\r\n' % u,
         BAD),
        ('lone CR in a value', b'GET %s HTTP/1.1\r\nX: a\rb\r\n\r\n' % u, BAD),
        ('obs-text in a name', b'GET %s HTTP/1.1\r\nX\xff: 1\r\n\r\n' % u, BAD),
        ('two spaces', b'GET  %s HTTP/1.1\r\n\r\n' % u, BAD),
        ('no version', b'GET %s\r\n\r\n' % u, BAD),
        ('HTTP/1.10', b'GET %s HTTP/1.10\r\n\r\n' % u, BAD),
        ('neither form', b'GET foo HTTP/1.1\r\n\r\n', BAD),
        ('empty port', b'GET http://127.0.0.1:/ HTTP/1.1\r\n\r\n', BAD),
        ('empty host', b'GET http://:80/ HTTP/1.1\r\n\r\n', BAD),
        ('no authority', b'GET http:/// HTTP/1.1\r\n\r\n', BAD),
        ('userinfo only', b'GET http://u@/ HTTP/1.1\r\n\r\n', BAD),
        ('CONNECT without a port', b'CONNECT 127.0.0.1 HTTP/1.1\r\n\r\n', BAD),
        ('CONNECT empty port', b'CONNECT 127.0.0.1: HTTP/1.1\r\n\r\n', BAD),
        ('CONNECT [::1]', b'CONNECT [::1] HTTP/1.1\r\n\r\n', BAD),
        ('two empty lines', b'\r\n\r\nGET %s HTTP/1.1\r\n\r\n' % u, 'CLOSED'),
        ('origin-form', b'GET / HTTP/1.1\r\nHost: %s\r\n\r\n' % auth, NI),
        ('https://', b'GET https://%s/ HTTP/1.1\r\n\r\n' % auth, NI),
        ('OPTIONS *', b'OPTIONS * HTTP/1.1\r\nHost: %s\r\n\r\n' % auth, NI),
        ('HTTP/2 preface', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n', VER),
        ('HTTP/2.0', b'GET %s HTTP/2.0\r\n\r\n' % u, VER),
        ('HTTP/3.0', b'CONNECT %s HTTP/3.0\r\n\r\n' % auth, VER)):
    no(name, req, want)

ok('HTTP/1.2', b'GET %s HTTP/1.2\r\n\r\n' % u,
   b'GET / HTTP/1.1\r\nHost: %s\r\nVia: 1.1 gwproxy\r\n'
   b'Connection: close\r\n\r\n' % auth)
ok('leading CRLF', b'\r\nGET %s HTTP/1.1\r\n\r\n' % u,
   b'GET / HTTP/1.1\r\nHost: %s\r\nVia: 1.1 gwproxy\r\n'
   b'Connection: close\r\n\r\n' % auth)
ok('leading LF', b'\nGET %s HTTP/1.0\r\n\r\n' % u,
   b'GET / HTTP/1.0\r\nHost: %s\r\nVia: 1.0 gwproxy\r\n'
   b'Connection: close\r\n\r\n' % auth)

sys.exit(1 if errors else 0)
EOF

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	for modes in "--as-http=1" "--as-socks5=1 --as-http=1"; do
		pp="$(pick_port)"
		# shellcheck disable=SC2086
		gwp_start "127.0.0.1:$pp" $modes --event-loop="$loop" \
			--nr-workers=1
		rc=0
		timeout 120 python3 "$WORK/drive.py" "$pp" "$SERVERS_DIR" \
			>"$WORK/drive.out" 2>&1 || rc=$?
		kill "$GWP_PID" 2>/dev/null
		if [ "$rc" != 0 ]; then
			sed 's/^/# /' "$WORK/drive.out" >&2
			fail "[$loop $modes] request errors (rc=$rc)"
		fi
	done
done

pass
