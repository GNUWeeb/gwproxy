#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# TRACE and OPTIONS are hop-limited (RFC 9110 Section 7.6.2): with
# "Max-Forwards: 0" the proxy answers them as their final recipient instead
# of forwarding them, OPTIONS with a 200, TRACE with a 501, and with a larger
# value they reach the origin with one less. A value that is not a number is
# refused. Other methods keep the field as it is. An OPTIONS request for a URI
# with an empty path and no query asks about the server as a whole, and
# reaches the origin as "OPTIONS *" (RFC 9112 Section 3.2.4).

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


def local(name, req, want):
    n = o.count()
    r = hc.xact(port, req)
    if not r.startswith(want.encode()) or not r.endswith(b'\r\n\r\n'):
        fail(name, 'got %r, want %r' % (r, want))
    if o.count() != n:
        fail(name, 'reached the origin')


def fwd(name, req, want):
    n = o.nr_reqs()
    r = hc.xact(port, req)
    if not r.startswith(b'HTTP/1.1 200 OK\r\n') or not r.endswith(b'ok'):
        return fail(name, 'got %r' % r)
    got = o.wait(n + 1)
    if got != want:
        fail(name, 'origin got %r, want %r' % (got, want))


u = b'http://%s/x' % auth
local('TRACE at 0', b'TRACE %s HTTP/1.1\r\nMax-Forwards: 0\r\n\r\n' % u,
      'HTTP/1.1 501 ')
local('OPTIONS at 0', b'OPTIONS %s HTTP/1.1\r\nMax-Forwards: 0\r\n\r\n' % u,
      'HTTP/1.1 200 ')
local('OPTIONS * at 0', b'OPTIONS http://%s HTTP/1.1\r\nmax-forwards: 00\r\n'
      b'\r\n' % auth, 'HTTP/1.1 200 ')
local('not a number', b'TRACE %s HTTP/1.1\r\nMax-Forwards: 1x\r\n\r\n' % u,
      'HTTP/1.1 400 ')
fwd('TRACE at 3', b'TRACE %s HTTP/1.1\r\nMax-Forwards: 3\r\n\r\n' % u,
    b'TRACE /x HTTP/1.1\r\nHost: %s\r\nMax-Forwards: 2\r\n'
    b'Via: 1.1 gwproxy\r\nConnection: close\r\n\r\n' % auth)
fwd('OPTIONS at 1', b'OPTIONS %s HTTP/1.1\r\nMax-Forwards: 1\r\n\r\n' % u,
    b'OPTIONS /x HTTP/1.1\r\nHost: %s\r\nMax-Forwards: 0\r\n'
    b'Via: 1.1 gwproxy\r\nConnection: close\r\n\r\n' % auth)
fwd('GET at 0', b'GET %s HTTP/1.1\r\nMax-Forwards: 0\r\n\r\n' % u,
    b'GET /x HTTP/1.1\r\nHost: %s\r\nMax-Forwards: 0\r\n'
    b'Via: 1.1 gwproxy\r\nConnection: close\r\n\r\n' % auth)
fwd('OPTIONS, empty path', b'OPTIONS http://%s HTTP/1.1\r\n\r\n' % auth,
    b'OPTIONS * HTTP/1.1\r\nHost: %s\r\nVia: 1.1 gwproxy\r\n'
    b'Connection: close\r\n\r\n' % auth)
fwd('OPTIONS, empty path and a query',
    b'OPTIONS http://%s?q HTTP/1.1\r\n\r\n' % auth,
    b'OPTIONS /?q HTTP/1.1\r\nHost: %s\r\nVia: 1.1 gwproxy\r\n'
    b'Connection: close\r\n\r\n' % auth)

sys.exit(1 if errors else 0)
EOF

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-http=1 --event-loop="$loop" \
		--nr-workers=1
	rc=0
	timeout 120 python3 "$WORK/drive.py" "$pp" "$SERVERS_DIR" \
		>"$WORK/drive.out" 2>&1 || rc=$?
	kill "$GWP_PID" 2>/dev/null
	if [ "$rc" != 0 ]; then
		sed 's/^/# /' "$WORK/drive.out" >&2
		fail "[$loop] Max-Forwards (rc=$rc)"
	fi
done

pass
