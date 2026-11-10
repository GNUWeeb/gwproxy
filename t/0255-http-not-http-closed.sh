#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A client whose first bytes cannot start an HTTP request line is closed at
# once, on an HTTP-only listener and on a combined SOCKS5 + HTTP one alike,
# rather than when a line end happens to arrive or --protocol-timeout ends the
# wait: a SOCKS4 request, SOCKS5 on an HTTP-only port and binary bytes carry no
# line end at all. A request line starts with a method token and the white
# space after it; bytes that may still become one keep waiting.

. "$(dirname "$0")/lib.sh"
require python3

cat >"$WORK/drive.py" <<'EOF'
import socket, sys, time

port, socks5 = int(sys.argv[1]), sys.argv[2] == '1'
errors = 0


def eof_after(data, limit):
    """Send @data; return the seconds until EOF or reset, None if none
    within @limit."""
    s = socket.create_connection(('127.0.0.1', port))
    s.settimeout(limit)
    t0 = time.monotonic()
    try:
        s.sendall(data)
        while True:
            d = s.recv(4096)
            if not d:
                break
            # Nothing is ever said to bytes that are not HTTP.
            return 'reply %r' % d[:40]
    except socket.timeout:
        return None
    except OSError:
        pass
    finally:
        s.close()
    return time.monotonic() - t0


def closed(name, data):
    global errors
    t = eof_after(data, 5)
    if t is None or isinstance(t, str) or t > 3:
        errors += 1
        print('%s: want a close at once, got %r' % (name, t))


def held(name, data):
    global errors
    t = eof_after(data, 1.5)
    if t is not None:
        errors += 1
        print('%s: want it held, got %r' % (name, t))


closed('SOCKS4 CONNECT', b'\x04\x01\x00\x50\x7f\x00\x00\x01\x00')
closed('SOCKS4a CONNECT', b'\x04\x01\x00\x50\x00\x00\x00\x01u\x00host\x00')
closed('16 NULs', b'\x00' * 16)
closed('binary', b'\xff\xfe\xfd')
closed('TLS record header', b'\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03')
closed('control byte in the method', b'GET\x01')
closed('space first', b' GET http://h/')
if not socks5:
    closed('SOCKS5 greeting', b'\x05\x01\x00')

held('method only', b'GET')
held('lowercase method', b'get / HTTP/1.1')
held('request line, no line end', b'GET http://127.0.0.1:1/ HTTP/1.1')

sys.exit(1 if errors else 0)
EOF

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	for modes in "--as-http=1" "--as-socks5=1 --as-http=1"; do
		pp="$(pick_port)"
		# shellcheck disable=SC2086
		gwp_start "127.0.0.1:$pp" $modes --event-loop="$loop" \
			--nr-workers=1 --protocol-timeout=10
		s5=0
		[ "${modes#--as-socks5}" != "$modes" ] && s5=1
		rc=0
		timeout 120 python3 "$WORK/drive.py" "$pp" "$s5" \
			>"$WORK/drive.out" 2>&1 || rc=$?
		kill "$GWP_PID" 2>/dev/null
		if [ "$rc" != 0 ]; then
			sed 's/^/# /' "$WORK/drive.out" >&2
			fail "[$loop $modes] not-HTTP input (rc=$rc)"
		fi
	done
done

pass
