#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Behaviour the two event loops must share, checked on each of them:
#
#   (1) the TCP options apply to the accepted client socket, not only to the
#       target one: with --tcp-keepalive and a short --tcp-keepidle, the
#       client-side socket carries that keepalive timer;
#   (2) an HTTPS-proxy client gets a TLS close_notify before the FIN, so a
#       response whose body runs until the connection closes ends cleanly
#       instead of looking truncated (curl fails such a read with "unexpected
#       eof" otherwise). Needs a build with --use-openssl;
#   (3) a client that fails the handshake gets its error reply and is then
#       disconnected at once, not left open until --protocol-timeout.

. "$(dirname "$0")/lib.sh"
require curl
require python3
require ss

op="$(pick_port)"
python3 "$SERVERS_DIR/close_origin.py" "$op" >"$WORK/origin.log" 2>&1 &
_PIDS+=("$!")
wait_listen "$op" "$!" || fail "close-delimited origin did not start on $op"

have_tls=0
if "$GWPROXY" --help 2>&1 | grep -q -- --tls-cert && command -v openssl >/dev/null &&
   curl --help all 2>/dev/null | grep -q -- --proxy-insecure &&
   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 \
	-subj '/CN=localhost' >/dev/null 2>&1; then
	have_tls=1
else
	echo "# no TLS support here: skipping the close_notify check"
fi

printf 'alice:secret\n' >"$WORK/auth"

gwp_stop()
{
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
	return 0
}

# keepalive_secs <local_port>: the keepalive timer of the established socket
# bound to <local_port> (the proxy's end of a client connection), in whole
# seconds, or nothing when it has none. Only the number is trusted: iproute2
# versions disagree on the unit they print after it ("6sec", "6.412ms" for
# the same 6.4 seconds), and a sub-minute idle is all this test sets.
keepalive_secs()
{
	ss -tnoH state established "( sport = :$1 )" 2>/dev/null |
		sed -n 's/.*timer:(keepalive,\([0-9.]*\)\([a-z]*\),.*/\1 \2/p' |
		head -1 | awk '{ print int(($2 == "min") ? $1 * 60 : $1) }'
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	# (1) Client-side TCP options. A plain forwarder to the origin; the
	#     client holds its connection open while ss inspects the proxy's
	#     end of it.
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --target="127.0.0.1:$op" --event-loop="$loop" \
		--tcp-keepalive=1 --tcp-keepidle=7
	python3 -c 'import socket, sys, time
c = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
time.sleep(3)' "$pp" &
	cpid=$!
	ka=""
	for _ in $(seq 1 20); do
		ka="$(keepalive_secs "$pp")"
		[ -n "$ka" ] && break
		sleep 0.1
	done
	wait "$cpid" 2>/dev/null
	gwp_stop
	[ -n "$ka" ] || \
		fail "[$loop] the accepted client socket has no keepalive timer"
	[ "$ka" -le 7 ] || \
		fail "[$loop] client keepalive timer is ${ka}s, not --tcp-keepidle=7"

	# (2) TLS close_notify. Forward through the TLS-terminating proxy to an
	#     origin whose body is delimited by the close.
	if [ "$have_tls" = 1 ]; then
		pp="$(pick_port)"
		gwp_start "127.0.0.1:$pp" --as-http=1 --event-loop="$loop" \
			--tls-cert="$WORK/cert.pem" --tls-key="$WORK/key.pem"
		for i in 1 2 3; do
			err="$(curl -sS --max-time 10 --proxy-insecure \
				-x "https://127.0.0.1:$pp" "http://127.0.0.1:$op/x" \
				-o "$WORK/tls.$loop.$i" 2>&1)" || \
				fail "[$loop] TLS client saw the close-delimited body as truncated: $err"
			[ "$(wc -c <"$WORK/tls.$loop.$i")" = 1408 ] || \
				fail "[$loop] close-delimited body came back $(wc -c <"$WORK/tls.$loop.$i") bytes, want 1408"
		done
		gwp_stop
	fi

	# (3) Prompt close after an error reply. A request without credentials
	#     to a proxy that wants them gets a 407; the connection must close
	#     right after, well before the 10s protocol timeout.
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-http=1 --event-loop="$loop" \
		--auth-file="$WORK/auth" --protocol-timeout=10
	res="$(python3 -c 'import socket, sys, time
c = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
c.settimeout(9)
t = time.time()
c.sendall(b"GET http://127.0.0.1:1/ HTTP/1.1\r\nHost: x\r\n\r\n")
d = b""
try:
    while True:
        b = c.recv(4096)
        if not b:
            break
        d += b
    print("%s %.1f" % (d.split(b" ")[1].decode() if d else "-", time.time() - t))
except socket.timeout:
    print("%s open" % (d.split(b" ")[1].decode() if d else "-"))' "$pp")"
	gwp_stop
	set -- $res
	[ "$1" = 407 ] || fail "[$loop] expected a 407 reply, got '$res'"
	[ "$2" != open ] || \
		fail "[$loop] the connection stayed open after the 407 reply"
	python3 -c 'import sys; sys.exit(0 if float(sys.argv[1]) < 3.0 else 1)' "$2" || \
		fail "[$loop] the connection closed only ${2}s after the 407 reply"
done

pass
