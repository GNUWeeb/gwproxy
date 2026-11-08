#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# What a client is told when a SOCKS5 upstream turns its CONNECT down, or
# cannot be reached at all. Only REP 0x03 to 0x06 say the destination could
# not be reached, and only those reach a SOCKS5 client as they are; an HTTP
# client gets a 504 for 0x06 (TTL expired) and a 502 for the rest. Every
# other REP (0x01, 0x02, 0x07, 0x08, an unassigned 0x09) is the chain's
# failure, not the destination's: REP 0x01 and a 502. The log keeps each
# REP's failure class, as the passive health counts it. An upstream whose
# port refuses the connection is the chain's failure too, through a
# socks5:// and an http:// upstream alike: REP 0x01 and a 502, where a
# SOCKS5 client used to hear 0x05 (connection refused) as if the destination
# had refused. On both event loops.

. "$(dirname "$0")/lib.sh"
require python3

fault="$WORK/fault"
: >"$fault"

# probe <port> <socks5|http> <fault>...: for each fault in turn, tell the
# upstream, make a CONNECT, and print "<fault> <answer>": the SOCKS5 reply as
# "REP=0xNN", or the HTTP status code, or CLOSED.
probe()
{
	timeout 120 python3 - "$fault" "$@" <<-'PY'
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
	    else:
	        c.sendall(b"CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: 127.0.0.1:80\r\n\r\n")
	    got = b""
	    try:
	        while True:
	            d = c.recv(4096)
	            if not d:
	                break
	            got += d
	    except (socket.timeout, ConnectionResetError):
	        pass
	    c.close()
	    if front == "socks5":
	        return "REP=0x%02x" % got[1] if len(got) >= 2 else "CLOSED"
	    parts = got.split(b"\r\n", 1)[0].split()
	    return parts[1].decode() if len(parts) > 1 else "CLOSED"
	for f in sys.argv[4:]:
	    with open(fault_file, "w") as o:
	        o.write(f)
	    print(f, one(), flush=True)
	PY
}

# want <socks5|http> <fault>: the answer the client must get.
want()
{
	case "$1:$2" in
	socks5:rep_0[3456]) echo "REP=0x${2#rep_}" ;;
	socks5:*) echo REP=0x01 ;;
	http:rep_06) echo 504 ;;
	http:*) echo 502 ;;
	esac
}

# class <fault>: the failure class the log must give the upstream's REP.
class()
{
	case "$1" in
	rep_0[12]) echo neutral ;;
	rep_0[3456]) echo destination ;;
	*) echo upstream ;;
	esac
}

# check <label> <port> <nr> <fault>...: each fault's answer, to a SOCKS5 and
# an HTTP client.
check()
{
	local label="$1" port="$2" nr="$3" front f got n w
	shift 3

	for front in socks5 http; do
		n=0
		while read -r f got; do
			n=$((n + 1))
			w="$(want "$front" "$f")"
			[ "$got" = "$w" ] ||
				fail "$label: $front client, $f: got $got, want $w"
		done < <(probe "$port" "$front" "$@")
		[ "$n" = "$nr" ] ||
			fail "$label: $front client: $n of $nr probes ran"
	done
}

up="$(pick_port)"
python3 "$SERVERS_DIR/upstream_faults.py" socks5 "$up" "$fault" \
	>"$WORK/up.log" 2>&1 &
_PIDS+=("$!")
wait_listen "$up" "$!" || fail "the SOCKS5 upstream did not start on $up"
closed_port
dead="$CLOSED_PORT"

reps="rep_01 rep_02 rep_03 rep_04 rep_05 rep_06 rep_07 rep_08 rep_09"
for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --as-http=1 --event-loop="$loop" \
		--nr-workers=1 --upstream-proxy="socks5://127.0.0.1:$up"
	check "[$loop] socks5 upstream" "$pp" 9 $reps
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
	log="$WORK/gwp.$pp.log"
	for f in $reps; do
		s="rep=0x${f#rep_}, class=$(class "$f"),"
		grep -qF -- "Upstream SOCKS5 CONNECT failed ($s" "$log" || {
			sed 's/^/# gwp: /' "$log" >&2
			fail "[$loop] no log line with: $s"
		}
	done

	# A refused upstream: the fault is not asked, the connect fails.
	for scheme in socks5 http; do
		pp="$(pick_port)"
		gwp_start "127.0.0.1:$pp" --as-socks5=1 --as-http=1 \
			--event-loop="$loop" --nr-workers=1 \
			--upstream-proxy="$scheme://127.0.0.1:$dead"
		check "[$loop] refused $scheme upstream" "$pp" 1 refused
		kill "$GWP_PID" 2>/dev/null
		wait "$GWP_PID" 2>/dev/null
	done
done

pass
