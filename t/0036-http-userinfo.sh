#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Userinfo in an absolute-form request target (RFC 3986 Section 3.2): the
# userinfo runs to the LAST '@' and is not part of the host. Getting this wrong
# is not just a parsing nicety -- scanning for the port separator before
# dropping the userinfo splits "A:B@C" on the colon INSIDE the userinfo, so the
# proxy connects to the attacker-chosen "A" while the authority still reads as
# "C" to anything inspecting the URL.
#
# Checked here:
#   (a) a URL carrying userinfo reaches the right origin, and the userinfo is
#       not leaked to it in the Host header;
#   (b) "REAL:PORT@decoy" resolves to the decoy -- the authority -- not to the
#       host hidden in the userinfo. Asserted against the destination the proxy
#       actually asked its upstream for, because that is the observable that
#       the disguise attacks; a socks5h upstream is used since that path takes
#       the hostname straight from this parse.

. "$(dirname "$0")/lib.sh"
require python3

# Origin that records the Host header it was sent.
op="$(pick_port)"
hlog="$WORK/host.log"
python3 "$SERVERS_DIR/header_origin.py" "$op" "$hlog" Host \
	>"$WORK/header_origin.log" 2>&1 &
_PIDS+=("$!")
wait_listen "$op" "$!" || fail "header origin did not listen on $op"

# Send one raw absolute-form request through the proxy, print the status line.
# NOTE: <<- strips leading tabs, so the python below indents with spaces.
fetch() {				# $1=proxy_port $2=url
	python3 - "$1" "$2" <<-'PY'
	import socket, sys
	port, url = int(sys.argv[1]), sys.argv[2]
	req = ('GET %s HTTP/1.1\r\nHost: placeholder\r\n'
	       'Connection: close\r\n\r\n' % url)
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
	print(buf.split(b'\r\n', 1)[0].decode('latin-1') if buf else 'NOREPLY')
	PY
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	# (a) Userinfo is accepted and discarded, not treated as the host.
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-http=1 --event-loop="$loop" --nr-workers=2

	for creds in "user:pw@" "user@" ""; do
		: >"$hlog"
		st="$(fetch "$pp" "http://${creds}127.0.0.1:$op/x")"
		[ "$st" = "HTTP/1.1 200 OK" ] \
			|| fail "[$loop] http://${creds}127.0.0.1:$op/x got '$st' (want 200)"
		got="$(head -1 "$hlog")"
		[ "$got" = "127.0.0.1:$op" ] \
			|| fail "[$loop] origin saw Host '$got' for '${creds}' (want 127.0.0.1:$op, no userinfo)"
	done
	kill "$GWP_PID" 2>/dev/null

	# (b) The disguise: "REAL:PORT@decoy" must resolve to the decoy. The
	#     recording upstream reports the destination it was handed, which
	#     is what the URL is trying to misrepresent.
	rp="$(pick_port)"
	rlog="$WORK/rec.$loop.log"
	: >"$rlog"
	python3 "$SERVERS_DIR/recording_proxy.py" socks5 127.0.0.1 "$rp" "$rlog" \
		>"$WORK/rec.$loop.err" 2>&1 &
	_PIDS+=("$!")
	wait_listen "$rp" "$!" || fail "recording upstream did not listen"

	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-http=1 --event-loop="$loop" \
		--upstream-proxy="socks5h://127.0.0.1:$rp"

	# decoy.invalid never resolves, so the upstream cannot complete the
	# request -- irrelevant here: what matters is which destination it was
	# asked for. A pass must not depend on the fetch succeeding.
	fetch "$fp" "http://127.0.0.1:$op@decoy.invalid/x" >/dev/null
	got="$(head -1 "$rlog")"
	case "$got" in
	"atyp=3 addr=decoy.invalid port=80")
		;;
	"atyp=3 addr=127.0.0.1 port=$op")
		fail "[$loop] userinfo disguised the target: upstream was sent to the userinfo host" ;;
	*)
		fail "[$loop] upstream was asked for '$got' (want decoy.invalid:80)" ;;
	esac
	kill "$GWP_PID" 2>/dev/null
done

pass
