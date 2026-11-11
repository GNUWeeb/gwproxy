#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The framing of an origin's response is checked before the client relies on
# it (RFC 9112 Section 6.3): with Transfer-Encoding present, Content-Length is
# dropped; a Content-Length that does not name one length (two that differ,
# a list of differing values, not a number) gets "502 Bad Gateway" instead of
# the response; one named more than once goes on once. A Transfer-Encoding
# that does not end in chunked is valid and leaves the body to the close.

. "$(dirname "$0")/lib.sh"
require python3

cat >"$WORK/drive.py" <<'EOF'
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[2])
import http_check as hc

port = int(sys.argv[1])
errors = 0
CC = (b'Via: 1.1 gwproxy\r\nConnection: close\r\n'
      b'Proxy-Connection: close\r\n\r\n')

for name, res, want in (
        ('CL and chunked',
         b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked'
         b'\r\n\r\n2\r\nok\r\n0\r\n\r\n',
         b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n' + CC +
         b'2\r\nok\r\n0\r\n\r\n'),
        ('two CL', b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n'
         b'Content-Length: 7\r\n\r\nhello', None),
        ('CL list', b'HTTP/1.1 200 OK\r\nContent-Length: 5, 7\r\n\r\nhello',
         None),
        ('CL abc', b'HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\nhello',
         None),
        ('same CL twice', b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n'
         b'Content-Length: 2, 2\r\n\r\nok',
         b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n' + CC + b'ok'),
        ('TE gzip', b'HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nzz',
         b'HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n' + CC + b'zz')):
    o = hc.Origin(res)
    r = hc.xact(port, b'GET http://127.0.0.1:%d/ HTTP/1.1\r\n\r\n' % o.port)
    if want is None:
        if hc.status(r) != 'HTTP/1.1 502 Bad Gateway':
            errors += 1
            print('%s: got %r, want 502' % (name, r))
    elif r != want:
        errors += 1
        print('%s: got %r, want %r' % (name, r, want))

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
		fail "[$loop] response framing (rc=$rc)"
	fi
done

pass
