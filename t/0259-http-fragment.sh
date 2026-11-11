#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A fragment is never part of a request-target (RFC 9112 Section 3.2.1):
# forwarding "GET http://h/p?q#f" sends "GET /p?q" to the origin, the
# fragment cut off as clients do before they send a URI, and a fragment right
# after the authority leaves the empty path, "/". The authority still ends at
# the '#', so "http://h#@other/" goes to h.

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

for target, path in ((b'/p?q#f', b'/p?q'), (b'/p#f?g/h', b'/p'),
                     (b'/p#', b'/p'), (b'#f', b'/'), (b'?q#f', b'/?q'),
                     (b'#@192.0.2.1:9/x', b'/')):
    n = o.nr_reqs()
    st = hc.status(hc.xact(port, b'GET http://%s%s HTTP/1.1\r\n\r\n' %
                           (auth, target)))
    if not st.startswith('HTTP/1.1 200 '):
        errors += 1
        print('%r: got %r' % (target, st))
        continue
    got = o.wait(n + 1)
    want = (b'GET %s HTTP/1.1\r\nHost: %s\r\nVia: 1.1 gwproxy\r\n'
            b'Connection: close\r\n\r\n' %
            (path, auth))
    if got != want:
        errors += 1
        print('%r: origin got %r, want %r' % (target, got, want))

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
		fail "[$loop] fragments (rc=$rc)"
	fi
done

pass
