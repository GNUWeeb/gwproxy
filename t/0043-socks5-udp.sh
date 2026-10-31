#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# SOCKS5 UDP ASSOCIATE (RFC 1928): a client opens a TCP control connection,
# issues UDP ASSOCIATE, and the proxy returns a bound UDP relay endpoint. The
# client then sends SOCKS5-wrapped datagrams to that relay, which forwards them
# to a UDP echo server and relays the replies back. Verify datagrams of several
# sizes round-trip byte-exact, IPv4/IPv6 and cross-address-family targets all
# relay (the relay socket is dual-stack), the relay is torn down with its TCP
# control connection, and plain SOCKS5 CONNECT still works on the same port. The
# relay is exercised on both event loops (epoll and, when built, io_uring).
# The datagrams the relay must REFUSE are asserted too: a wrong source address
# (RFC 1928), a fragmented datagram, and a domain-name target.

. "$(dirname "$0")/lib.sh"
require curl
require python3
require ss

udp_client() { python3 "$SERVERS_DIR/socks5_udp_client.py" "$@"; }

# IPv4 UDP echo server.
start_udp_echo 127.0.0.1
ep="$UDP_ECHO_PORT"

# IPv6 UDP echo server (best-effort: skip the IPv6 cases where ::1 is absent).
have_v6=0
if python3 -c 'import socket,sys; socket.socket(socket.AF_INET6,socket.SOCK_DGRAM).bind(("::1",0))' 2>/dev/null; then
	have_v6=1
	start_udp_echo ::1
	ep6="$UDP_ECHO_PORT"
fi

# A TCP HTTP origin for the coexisting CONNECT check.
hp="$(pick_port)"
make_payload "$WORK/payload.bin" 100000
start_httpd "$hp" "$WORK" "1.1"

# A standalone SOCKS5 proxy used only as an upstream for the chaining-refusal
# check below (kept alive for the whole test via _PIDS).
up="$(pick_port)"
gwp_start "127.0.0.1:$up" --as-socks5=1 --event-loop=epoll --nr-workers=2

# Run the full relay matrix on one event loop.
run_loop() {
	local loop="$1" pp tp

	# (1) IPv4 client -> IPv4 target: datagrams of assorted sizes echo back.
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" --nr-workers=2
	udp_client "$pp" "$ep" 1 60 1400 9000 60000 \
		|| fail "$loop SOCKS5 UDP ASSOCIATE relay failed"

	# (2) A fresh association works after the first is gone (exercises the
	#     relay teardown that each closed control connection triggers).
	udp_client "$pp" "$ep" 200 \
		|| fail "$loop second SOCKS5 UDP association failed"

	# (3) Cross-address family: an IPv4-connected client reaches an IPv6
	#     target through the dual-stack relay socket.
	if [ "$have_v6" = 1 ]; then
		udp_client --target-host ::1 "$pp" "$ep6" 1 1400 60000 \
			|| fail "$loop IPv4-client -> IPv6-target relay failed"
	fi

	# (4) Coexistence: plain SOCKS5 CONNECT still works on the same port.
	curl -s --max-time 20 -x "socks5h://127.0.0.1:$pp" \
		"http://127.0.0.1:$hp/payload.bin" -o "$WORK/out.$loop.bin" \
		|| fail "$loop SOCKS5 CONNECT on the UDP-capable port failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/out.$loop.bin" \
		"$loop SOCKS5 CONNECT corrupted the payload"
	kill "$GWP_PID" 2>/dev/null

	# (5) IPv6 client, to both IPv6 and (cross-family) IPv4 targets.
	if [ "$have_v6" = 1 ]; then
		pp="$(pick_port)"
		gwp_start "[::1]:$pp" --as-socks5=1 --event-loop="$loop" \
			--nr-workers=2
		udp_client --proxy-host ::1 --target-host ::1 \
			"$pp" "$ep6" 1 1400 60000 \
			|| fail "$loop IPv6-client -> IPv6-target relay failed"
		udp_client --proxy-host ::1 --target-host 127.0.0.1 \
			"$pp" "$ep" 1 1400 60000 \
			|| fail "$loop IPv6-client -> IPv4-target relay failed"
		kill "$GWP_PID" 2>/dev/null
	fi

	# (6) The association outlives the protocol-handshake timeout (the
	#     handshake timer must be disarmed once the relay is up).
	tp="$(pick_port)"
	gwp_start "127.0.0.1:$tp" --as-socks5=1 --event-loop="$loop" \
		--protocol-timeout=1
	GWP_TP="$GWP_PID"
	udp_client "$tp" "$ep" --delay 2.0 64 \
		|| fail "$loop UDP association did not survive the timeout"
	kill "$GWP_TP" 2>/dev/null

	# (7) UDP ASSOCIATE is refused when an upstream proxy is configured:
	#     chaining UDP is unsupported and a local relay would bypass the
	#     upstream, so the proxy must reply with a non-zero REP.
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-socks5=1 --event-loop="$loop" \
		--upstream-proxy="socks5://127.0.0.1:$up"
	if udp_client "$fp" "$ep" 64 >"$WORK/upstream.$loop.log" 2>&1; then
		fail "$loop UDP ASSOCIATE accepted with an upstream configured"
	fi
	grep -qi refused "$WORK/upstream.$loop.log" \
		|| fail "$loop UDP ASSOCIATE upstream rejection lacked its error"
	kill "$GWP_PID" 2>/dev/null

	# (8) --udp-associate=0 rejects the command with REP 0x07 (command not
	#     supported), while plain CONNECT on the same proxy still works.
	np="$(pick_port)"
	gwp_start "127.0.0.1:$np" --as-socks5=1 --event-loop="$loop" \
		--udp-associate=0
	if udp_client "$np" "$ep" 64 >"$WORK/noudp.$loop.log" 2>&1; then
		fail "$loop UDP ASSOCIATE accepted with --udp-associate=0"
	fi
	grep -q 'REP=0x07' "$WORK/noudp.$loop.log" \
		|| fail "$loop --udp-associate=0 did not reply REP 0x07"
	curl -s --max-time 20 -x "socks5h://127.0.0.1:$np" \
		"http://127.0.0.1:$hp/payload.bin" -o "$WORK/noudp.out" \
		|| fail "$loop CONNECT broke with --udp-associate=0"
	assert_files_equal "$WORK/payload.bin" "$WORK/noudp.out" \
		"$loop CONNECT payload corrupted with --udp-associate=0"
	kill "$GWP_PID" 2>/dev/null

	# (9) What the relay must REFUSE. These are the security and
	#     robustness edges of the per-datagram path; every one of them
	#     returns the datagram unrelayed, which is indistinguishable from
	#     "it worked" unless asserted directly.
	sp="$(pick_port)"
	gwp_start "127.0.0.1:$sp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=2
	probe() { python3 "$SERVERS_DIR/socks5_udp_probe.py" "$@"; }

	# A plain datagram still relays -- the control for the cases below.
	[ "$(probe "$sp" "$ep")" = RELAYED ] \
		|| fail "$loop relay dropped an ordinary datagram"

	# An empty payload is a valid datagram, not a reason to drop.
	[ "$(probe --size 0 "$sp" "$ep")" = RELAYED ] \
		|| fail "$loop relay dropped a 0-byte datagram"

	# RFC 1928: the first datagram must come from the same address as the
	# TCP control connection, or an off-path host could hijack the
	# association. 127.0.0.2 is local, so this needs no privilege.
	[ "$(probe --src-ip 127.0.0.2 "$sp" "$ep")" = DROPPED ] \
		|| fail "$loop relay accepted a datagram from the wrong source"

	# Fragmentation (FRAG != 0) is not implemented and must be discarded
	# rather than forwarded with its header still attached.
	[ "$(probe --frag 1 "$sp" "$ep")" = DROPPED ] \
		|| fail "$loop relay accepted a fragmented datagram"

	# A domain-name target would need DNS in the datagram path; it is
	# dropped for now.
	[ "$(probe --atyp domain --dst localhost "$sp" "$ep")" = DROPPED ] \
		|| fail "$loop relay accepted a domain-name target"

	kill "$GWP_PID" 2>/dev/null
}

run_loop epoll

if grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null; then
	run_loop io_uring
fi

pass
