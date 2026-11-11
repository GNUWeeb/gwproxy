#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# An upstream proxy that hangs up while the handshake with it is held for
# the client's reply. A SOCKS5 client that sends its greeting and CONNECT
# in one go is answered with the method reply as the connect to the
# upstream starts; when that reply's send comes up short, the handshake
# waits until the rest is out, watching the upstream only for a hangup.
# An upstream that hangs up then, with no server left to retry on, is a
# failure of the chain like a hangup during the handshake: the client must
# get the rest of its method reply and then REP 0x01, as on io_uring,
# not a bare close. Through a single upstream, and through a pool of two
# that both hang up (the retry is held as well).
#
# The short send is made with a seccomp filter that fails every 2-byte
# sendto() with EAGAIN, so the method reply "05 00" stays pending until
# the failure reply goes out with it. io_uring's sends do not go through
# the filter: there the hangup is met by the handshake itself, which
# answers REP 0x01 already, and is checked for the same answer.

. "$(dirname "$0")/lib.sh"
require python3
require_opt "--upstream-proxy"

real="$GWPROXY"
wrap="$WORK/gwproxy-short-send"
printf '#!/bin/sh\nexec python3 "%s" 2 "%s" "$@"\n' \
	"$SERVERS_DIR/seccomp_send_eagain.py" "$real" >"$wrap"
chmod +x "$wrap"
python3 "$SERVERS_DIR/seccomp_send_eagain.py" 2 /bin/true || \
	skip "cannot install a seccomp filter here"

# hangup_start: an upstream that closes each connection it accepts, with
# nothing read or sent; sets HUP_PORT.
hangup_start()
{
	local port

	port="$(pick_port)"
	python3 - "$port" >"$WORK/hup.$port.err" 2>&1 <<'PY' &
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(16)
while True:
    c, _ = s.accept()
    c.close()
PY
	_PIDS+=("$!")
	wait_listen "$port" "$!" || fail "the hangup upstream did not listen"
	HUP_PORT="$port"
}

hangup_start
u1="$HUP_PORT"
hangup_start
u2="$HUP_PORT"
closed_port
dst="$CLOSED_PORT"

acl="$WORK/pool.acl"
{
	echo 'upstream two {'
	echo "	server socks5h://127.0.0.1:$u1;"
	echo "	server socks5h://127.0.0.1:$u2;"
	echo '}'
	echo '-A OUTPUT -j UPSTREAM --to two'
} >"$acl"
chmod 600 "$acl"

# check <tag> <proxy port> <hangups>: a pipelined greeting and CONNECT must
# get "05 00", then a REP 0x01 reply, then EOF; and each of the <hangups>
# attempts be classed a hangup, the upstream's failure.
check()
{
	local out n log="$WORK/gwp.$2.log"

	out="$(python3 - "$2" "$dst" <<'PY'
import socket, struct, sys
port, dst = int(sys.argv[1]), int(sys.argv[2])
c = socket.create_connection(("127.0.0.1", port), timeout=10)
c.sendall(b"\x05\x01\x00" + b"\x05\x01\x00\x01\x7f\x00\x00\x01" +
          struct.pack("!H", dst))
got = b""
try:
    while True:
        d = c.recv(64)
        if not d:
            break
        got += d
except ConnectionResetError:
    got += b"<RST>"
except socket.timeout:
    got += b"<TIMEOUT>"
print(got.hex() if got else "nothing")
PY
)" || fail "$1: client failed: $out"
	case "$out" in
	05000501*) diag "$1: $out" ;;
	*) fail "$1: want 05 00 then REP 0x01, got $out" ;;
	esac
	n="$(grep -c 'Upstream attempt failed .*end=hangup, class=upstream' \
		"$log")"
	[ "$n" = "$3" ] || \
		fail "$1: want $3 attempts failed as hangups, got $n"
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	p="$(pick_port)"
	GWPROXY="$wrap" gwp_start "127.0.0.1:$p" --as-socks5=1 \
		--event-loop="$loop" --nr-workers=1 --log-level=4 \
		--upstream-proxy="socks5h://127.0.0.1:$u1"
	check "$loop single" "$p" 1
	kill -0 "$GWP_PID" 2>/dev/null || fail "$loop single: proxy died"
	kill "$GWP_PID"
	wait "$GWP_PID" 2>/dev/null

	p="$(pick_port)"
	GWPROXY="$wrap" gwp_start "127.0.0.1:$p" --as-socks5=1 \
		--event-loop="$loop" --nr-workers=1 --log-level=4 \
		--acl-file="$acl"
	check "$loop pool" "$p" 2
	grep -q 'Upstream retry for idx=' "$WORK/gwp.$p.log" || \
		fail "$loop pool: the first hangup was not retried"
	kill -0 "$GWP_PID" 2>/dev/null || fail "$loop pool: proxy died"
	kill "$GWP_PID"
	wait "$GWP_PID" 2>/dev/null
done

pass
