#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# HTTP 502: when the origin cannot be reached the proxy must answer, not just
# hang up. A bare FIN leaves the client reporting a transport error it cannot
# explain, and is indistinguishable from the proxy crashing. RFC 9110 s15.6.3
# calls for 502 Bad Gateway.
#
# Covered on every available event loop: a refused target in forward mode and
# through CONNECT, and a name that does not resolve. A successful fetch is the
# control, so a proxy answering 502 to everything could not pass.

. "$(dirname "$0")/lib.sh"
require curl
require python3

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 1024
start_httpd "$hp" "$WORK" "1.1"

# A port with nothing listening: connect() is refused rather than timing out.
closed_port
closed="$CLOSED_PORT"

# Status line the proxy returns for a CONNECT. curl cannot report the status of
# a failed CONNECT tunnel (it is not the final response), so this reads the wire
# directly. The request is built in python: command substitution would eat the
# trailing newlines and the header block would never terminate.
# NOTE: <<- strips leading tabs, so the python below indents with spaces.
raw_status() {				# $1=proxy_port $2=target_authority
	python3 - "$1" "$2" <<-'PY'
	import socket, sys
	port, authority = int(sys.argv[1]), sys.argv[2]
	req = 'CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n' % (authority, authority)
	s = socket.create_connection(('127.0.0.1', port))
	s.settimeout(10)
	s.sendall(req.encode())
	buf = b''
	try:
	    while b'\r\n' not in buf:
	        chunk = s.recv(4096)
	        if not chunk:
	            break
	        buf += chunk
	except socket.timeout:
	    pass
	if not buf:
	    print('NOREPLY')
	else:
	    print(buf.split(b'\r\n', 1)[0].decode('latin-1'))
	PY
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-http=1 --event-loop="$loop" --nr-workers=2

	# Control: a reachable origin still succeeds.
	code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 \
		-x "http://127.0.0.1:$pp" "http://127.0.0.1:$hp/payload.bin")"
	[ "$code" = 200 ] \
		|| fail "[$loop] forward to a live origin got $code (want 200)"

	# Forward mode, target refuses the connection.
	code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 \
		-x "http://127.0.0.1:$pp" "http://127.0.0.1:$closed/x")"
	[ "$code" = 502 ] \
		|| fail "[$loop] forward to a refused origin got $code (want 502)"

	# Forward mode, name does not resolve (.invalid is reserved, RFC 2606).
	code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 \
		-x "http://127.0.0.1:$pp" "http://no-such-host.invalid/x")"
	[ "$code" = 502 ] \
		|| fail "[$loop] forward to an unresolvable name got $code (want 502)"

	# CONNECT to a refused target: the tunnel request itself is answered.
	st="$(raw_status "$pp" "127.0.0.1:$closed")"
	case "$st" in
	"HTTP/1.1 502"*)	;;
	NOREPLY)	fail "[$loop] CONNECT to a refused target got no reply at all" ;;
	*)		fail "[$loop] CONNECT to a refused target got '$st' (want 502)" ;;
	esac

	# A port that is not one is the client's mistake, not the origin's:
	# 400, and nothing is looked up. Service names are not ports either.
	for auth in "localhost:99999" "localhost:http" "localhost:+80"; do
		st="$(raw_status "$pp" "$auth")"
		case "$st" in
		"HTTP/1.1 400"*)	;;
		*)	fail "[$loop] CONNECT $auth got '$st' (want 400)" ;;
		esac
	done

	kill "$GWP_PID" 2>/dev/null
done

pass
