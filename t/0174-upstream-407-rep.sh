#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# What a client is told when an HTTP CONNECT upstream turns its CONNECT down.
# Only a 502 or a 504 says the destination could not be reached, and only
# those reach a SOCKS5 client as REP 0x05 (connection refused). A 407 means
# the upstream refused our credentials, the chain's failure and not the
# destination's: REP 0x01, as for every other status (403, 500, 503). An HTTP
# client gets a 502 in every case. The log keeps whose fault each one is: the
# upstream's for the 407, as its passive health counts it. Through an http://
# upstream for each status, and through an https:// one, with OpenSSL, for a
# real 407 to wrong credentials, on both event loops.

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

# The SOCKS5 reply each fault must give; an HTTP client always gets 502.
want_rep()
{
	case "$1" in
	bad_gateway|status_504) echo REP=0x05 ;;
	*) echo REP=0x01 ;;
	esac
}

# logged <label> <log> <text>: the proxy's log holds <text>.
logged()
{
	grep -qF -- "$3" "$2" || {
		sed 's/^/# gwp: /' "$2" >&2
		fail "$1: no log line with: $3"
	}
}

up="$(pick_port)"
python3 "$SERVERS_DIR/upstream_faults.py" http "$up" "$fault" \
	>"$WORK/up.log" 2>&1 &
_PIDS+=("$!")
wait_listen "$up" "$!" || fail "the HTTP upstream did not start on $up"

faults="auth_required refuse status_500 status_503 bad_gateway status_504"
for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --as-http=1 --event-loop="$loop" \
		--nr-workers=1 --upstream-proxy="http://u:p@127.0.0.1:$up"
	n=0
	while read -r f got; do
		n=$((n + 1))
		w="$(want_rep "$f")"
		[ "$got" = "$w" ] ||
			fail "[$loop] socks5 client, upstream $f: got $got, want $w"
	done < <(probe "$pp" socks5 $faults)
	[ "$n" = 6 ] || fail "[$loop] socks5 client: $n of 6 probes ran"
	n=0
	while read -r f got; do
		n=$((n + 1))
		[ "$got" = 502 ] ||
			fail "[$loop] http client, upstream $f: got $got, want 502"
	done < <(probe "$pp" http $faults)
	[ "$n" = 6 ] || fail "[$loop] http client: $n of 6 probes ran"
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
	log="$WORK/gwp.$pp.log"
	for s in "407, class=upstream" "403, class=neutral" \
		 "500, class=neutral" "503, class=neutral" \
		 "502, class=destination" "504, class=destination"; do
		logged "[$loop]" "$log" "Upstream HTTP CONNECT failed (status=$s,"
	done
done

# An https:// upstream that answers 407 to the wrong credentials.
"$GWPROXY" --help 2>&1 | grep -q -- --upstream-ca-file ||
	pass "no OpenSSL: the https:// upstream case did not run"
command -v openssl >/dev/null 2>&1 ||
	pass "no openssl: the https:// upstream case did not run"

ossl()
{
	openssl "$@" >>"$WORK/openssl.log" 2>&1 || {
		sed 's/^/# openssl: /' "$WORK/openssl.log" >&2
		fail "openssl could not make the test certificates"
	}
}
newkey="-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes"
ossl req -x509 $newkey -keyout "$WORK/ca.key" -out "$WORK/ca.pem" \
	-days 2 -subj "/CN=gwproxy test ca"
ossl req -new $newkey -keyout "$WORK/up.key" -out "$WORK/up.csr" \
	-subj "/CN=localhost"
printf 'subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\n' \
	>"$WORK/up.ext"
ossl x509 -req -in "$WORK/up.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" \
	-set_serial "$RANDOM" -days 2 -extfile "$WORK/up.ext" -out "$WORK/up.pem"

tp="$(pick_port)"
python3 "$SERVERS_DIR/tls_upstream.py" server "$WORK/up.pem" "$WORK/up.key" \
	"$tp" "$WORK/tls.log" "up:s3cr3t" >"$WORK/tls.out" 2>&1 &
_PIDS+=("$!")
wait_listen "$tp" "$!" || {
	sed 's/^/# up: /' "$WORK/tls.out" >&2
	fail "the TLS upstream did not start on $tp"
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	for pw in s3cr3t wrong; do
		pp="$(pick_port)"
		gwp_start "127.0.0.1:$pp" --as-socks5=1 --as-http=1 \
			--event-loop="$loop" --nr-workers=1 \
			--upstream-proxy="https://up:$pw@localhost:$tp" \
			--upstream-ca-file="$WORK/ca.pem"
		got="$(timeout 60 python3 "$SERVERS_DIR/tls_upstream.py" \
			socks5-rep "$pp" 2>&1)"
		w=rep=0x01
		[ "$pw" = s3cr3t ] && w=rep=0x00
		[ "$got" = "$w" ] ||
			fail "[$loop https $pw] socks5 client: got '$got', want $w"
		if [ "$pw" = wrong ]; then
			got="$(timeout 60 python3 - "$pp" <<-'PY'
			import socket, sys
			c = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
			c.settimeout(30)
			c.sendall(b"CONNECT echo.invalid:7 HTTP/1.1\r\nHost: echo.invalid:7\r\n\r\n")
			r = b""
			try:
			    while True:
			        d = c.recv(4096)
			        if not d:
			            break
			        r += d
			except OSError:
			    pass
			p = r.split(b"\r\n", 1)[0].split()
			print(p[1].decode() if len(p) > 1 else "CLOSED")
			PY
			)"
			[ "$got" = 502 ] ||
				fail "[$loop https] http client: got '$got', want 502"
		fi
		kill "$GWP_PID" 2>/dev/null
		wait "$GWP_PID" 2>/dev/null
		[ "$pw" = wrong ] &&
			logged "[$loop https]" "$WORK/gwp.$pp.log" \
				"Upstream HTTP CONNECT failed (status=407, class=upstream,"
	done
done
grep -q s3cr3t "$WORK"/gwp.*.log && fail "a password was logged"

pass
