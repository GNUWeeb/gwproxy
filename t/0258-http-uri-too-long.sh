#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A request-target too long to take is answered "414 URI Too Long" (RFC 9112
# Section 3), not "431 Request Header Fields Too Large": past the 16384-byte
# header limit, and past a small --client-buf-size while the request line is
# still incomplete, for a forwarding request and a CONNECT alike. A header
# that is too large only for its fields still gets the 431.

. "$(dirname "$0")/lib.sh"
require python3

cat >"$WORK/drive.py" <<'EOF'
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[3])
import http_check as hc

port, small = int(sys.argv[1]), int(sys.argv[2])
o = hc.Origin()
auth = b'127.0.0.1:%d' % o.port
errors = 0
URI, HDR = 'HTTP/1.1 414 URI Too Long', \
    'HTTP/1.1 431 Request Header Fields Too Large'


def no(name, p, data, want):
    global errors
    n = o.count()
    st = hc.status(hc.xact(p, data))
    if st != want:
        errors += 1
        print('%s: got %r, want %r' % (name, st, want))
    if o.count() != n:
        errors += 1
        print('%s: reached the origin' % name)


long_uri = b'GET http://%s/%s HTTP/1.1\r\n\r\n' % (auth, b'a' * 20000)
long_auth = b'CONNECT %s:443 HTTP/1.1\r\n\r\n' % (b'a' * 20000)
fields = b'GET http://%s/ HTTP/1.1\r\n%s\r\n' % (
    auth, b''.join(b'X-%d: v\r\n' % i for i in range(129)))
long_val = b'GET http://%s/ HTTP/1.1\r\nX: %s\r\n\r\n' % (auth, b'v' * 17000)

no('20000-byte URI', port, long_uri, URI)
no('20000-byte CONNECT authority', port, long_auth, URI)
no('129 field lines', port, fields, HDR)
no('17000-byte value', port, long_val, HDR)
# The request line alone fills a 256-byte client buffer.
no('URI over the buffer', small,
   b'GET http://%s/%s HTTP/1.1\r\n\r\n' % (auth, b'a' * 400), URI)
no('CONNECT over the buffer', small,
   b'CONNECT %s:443 HTTP/1.1\r\n\r\n' % (b'a' * 400), URI)
no('field over the buffer', small,
   b'GET http://%s/ HTTP/1.1\r\nX: %s\r\n\r\n' % (auth, b'v' * 400), HDR)

sys.exit(1 if errors else 0)
EOF

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-http=1 --event-loop="$loop" \
		--nr-workers=1
	pid1="$GWP_PID"
	sp="$(pick_port)"
	gwp_start "127.0.0.1:$sp" --as-http=1 --event-loop="$loop" \
		--nr-workers=1 --client-buf-size=256
	rc=0
	timeout 120 python3 "$WORK/drive.py" "$pp" "$sp" "$SERVERS_DIR" \
		>"$WORK/drive.out" 2>&1 || rc=$?
	kill "$pid1" "$GWP_PID" 2>/dev/null
	if [ "$rc" != 0 ]; then
		sed 's/^/# /' "$WORK/drive.out" >&2
		fail "[$loop] request line limits (rc=$rc)"
	fi
done

pass
