#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A forwarding request may use any method token, not only the methods of RFC
# 9110: WebDAV's PROPFIND, MKCOL and REPORT, SSDP's M-SEARCH, or one spelt in
# lowercase (method names are case-sensitive, so "get" is a method of its own
# that the origin judges). The method reaches the origin spelt as the client
# sent it, the body framed as for any other method, and the origin's answer
# comes back. CONNECT keeps its meaning.

. "$(dirname "$0")/lib.sh"
require python3

cat >"$WORK/drive.py" <<'EOF'
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[2])
import http_check as hc

port = int(sys.argv[1])
o = hc.Origin(b'HTTP/1.1 207 Multi-Status\r\nContent-Length: 5\r\n\r\nmulti')
auth = b'127.0.0.1:%d' % o.port
errors = 0
evil = b'GET http://evil/ HTTP/1.1\r\nHost: evil\r\n\r\n'

for m, fields, body in (
        (b'PROPFIND', b'Depth: 1\r\nContent-Length: 7\r\n', b'<a></a>'),
        (b'MKCOL', b'', b''),
        (b'REPORT', b'Transfer-Encoding: chunked\r\n', b'3\r\nabc\r\n0\r\n\r\n'),
        (b'M-SEARCH', b'Man: "ssdp:discover"\r\n', b''),
        (b'get', b'', b''),
        (b'X_Y.Z~1', b'', b'')):
    n = o.nr_reqs()
    r = hc.xact(port, b'%s http://%s/dav/x?y HTTP/1.1\r\n%s\r\n%s%s' %
                (m, auth, fields, body, evil))
    want = (b'%s /dav/x?y HTTP/1.1\r\nHost: %s\r\n%sVia: 1.1 gwproxy\r\n'
            b'Connection: close\r\n\r\n%s' % (m, auth, fields, body))
    if not r.startswith(b'HTTP/1.1 207 Multi-Status\r\n') or \
            not r.endswith(b'\r\n\r\nmulti'):
        errors += 1
        print('%r: got %r' % (m, r[:80]))
        continue
    got = o.wait(n + 1)
    if got != want:
        errors += 1
        print('%r: origin got %r, want %r' % (m, got, want))

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
			fail "[$loop $modes] extension methods (rc=$rc)"
		fi
	done
done

pass
