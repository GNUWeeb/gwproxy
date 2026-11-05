#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# However a handshake with the upstream proxy goes wrong, a client with a
# request outstanding must be told, not just hung up on: a malformed reply, a
# hangup or a reset get a SOCKS5 client REP 0x01 and an HTTP client a 502, as
# a SOCKS5 upstream's refused CONNECT gets REP 0x05 and a 502. An HTTP
# upstream's 403 says nothing about the destination, so it gets REP 0x01 too
# (t/0174 has the other statuses). A plain forwarding client has no reply to
# wait for, and must get no bytes at all. Every case ends at once rather than
# at a timeout. The log names whose fault each failure is: a refused CONNECT
# the destination's, garbage the upstream's, a 403 nobody's.

. "$(dirname "$0")/lib.sh"
require python3

fault="$WORK/fault"
: >"$fault"

# probe <port> <socks5|http|plain> <fault>...: for each fault in turn, tell the
# upstream, make a request, and print "<fault> <bytes>": everything received
# until the proxy closes, as hex ("-" for nothing), or OPEN when it does not
# close in time. A reset counts as a close: what matters is the bytes before it.
probe()
{
	python3 - "$fault" "$@" <<-'PY'
	import socket, sys
	fault_file, port, front = sys.argv[1], int(sys.argv[2]), sys.argv[3]
	def one():
	    c = socket.create_connection(("127.0.0.1", port))
	    c.settimeout(30)
	    if front == "socks5":
	        c.sendall(b"\x05\x01\x00")
	        if c.recv(2) != b"\x05\x00":
	            return "BADGREETING"
	        c.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50")
	    elif front == "http":
	        c.sendall(b"CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: 127.0.0.1:80\r\n\r\n")
	    got = b""
	    try:
	        while True:
	            d = c.recv(4096)
	            if not d:
	                break
	            got += d
	    except socket.timeout:
	        return "OPEN"
	    except ConnectionResetError:
	        pass
	    return got.hex() or "-"
	for f in sys.argv[4:]:
	    with open(fault_file, "w") as o:
	        o.write(f)
	    print(f, one(), flush=True)
	PY
}

# check <label> <front> <rep> <hex bytes>: <rep> is the expected SOCKS5 REP for
# a SOCKS5 front; an HTTP front always expects a 502, a plain one no bytes.
check()
{
	local label="$1" front="$2" rep="$3" got="$4"

	diag "$label: $got"
	case "$front" in
	socks5)
		case "$got" in
		05"$rep"00????????????*) ;;
		*) fail "$label: expected REP 0x$rep alone, got $got" ;;
		esac
		[ "${#got}" = 20 ] || fail "$label: expected REP 0x$rep alone, got $got"
		;;
	http)
		case "$got" in
		485454502f312e3120353032*) ;;	# "HTTP/1.1 502"
		*) fail "$label: expected a 502, got $got" ;;
		esac
		;;
	plain)
		[ "$got" = - ] || fail "$label: expected no bytes, got $got"
		;;
	esac
}

# logged <label> <log> <text>: the proxy's log has a line containing <text>.
logged()
{
	grep -qF -- "$3" "$2" || fail "$1: no log line with: $3"
}

s5_up="$(pick_port)"
python3 "$SERVERS_DIR/upstream_faults.py" socks5 "$s5_up" "$fault" \
	>"$WORK/up.s5.log" 2>&1 &
_PIDS+=("$!")
wait_listen "$s5_up" "$!" || fail "SOCKS5 upstream did not start on $s5_up"

http_up="$(pick_port)"
python3 "$SERVERS_DIR/upstream_faults.py" http "$http_up" "$fault" \
	>"$WORK/up.http.log" 2>&1 &
_PIDS+=("$!")
wait_listen "$http_up" "$!" || fail "HTTP upstream did not start on $http_up"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	# One proxy takes both protocols: a SOCKS5 and an HTTP client each.
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --as-http=1 --event-loop="$loop" \
		--nr-workers=1 --upstream-proxy="socks5://127.0.0.1:$s5_up"
	for front in socks5 http; do
		while read -r f got; do
			rep=01
			[ "$f" = refuse ] && rep=05
			check "[$loop] $front, socks5 upstream, $f" "$front" "$rep" "$got"
		done < <(probe "$pp" "$front" refuse bad_method_ver bad_ver bad_atyp \
			       close_greeting close_connect partial_close rst_connect)
	done
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
	log="$WORK/gwp.$pp.log"
	logged "[$loop] socks5 upstream" "$log" \
		"Upstream SOCKS5 CONNECT failed (rep=0x05, class=destination,"
	logged "[$loop] socks5 upstream" "$log" \
		"Upstream proxy sent a malformed reply (class=upstream,"

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --as-http=1 --event-loop="$loop" \
		--nr-workers=1 --upstream-proxy="http://127.0.0.1:$http_up"
	for front in socks5 http; do
		while read -r f got; do
			check "[$loop] $front, http upstream, $f" "$front" 01 "$got"
		done < <(probe "$pp" "$front" refuse bad_reply bad_status close_connect \
			       partial_close rst_connect)
	done
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
	log="$WORK/gwp.$pp.log"
	logged "[$loop] http upstream" "$log" \
		"Upstream HTTP CONNECT failed (status=403, class=neutral,"
	logged "[$loop] http upstream" "$log" \
		"Upstream proxy sent a malformed reply (class=upstream,"

	# A plain forwarding client is owed nothing, and gets nothing.
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --target=127.0.0.1:80 --event-loop="$loop" \
		--nr-workers=1 --upstream-proxy="socks5://127.0.0.1:$s5_up"
	while read -r f got; do
		check "[$loop] plain, socks5 upstream, $f" plain 01 "$got"
	done < <(probe "$pp" plain bad_ver close_connect rst_connect)
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
done

pass
