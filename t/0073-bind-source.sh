#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# --bind-source: the global default source address for outgoing (target)
# connections, and how an ACL "-j BIND" rule overrides it. Binding a source
# address that is already configured locally needs no privilege, so this test
# runs everywhere; the interface half of the feature (--bind-iface) needs a
# second path to the origin to be worth asserting on, so it needs root to build
# one and lives in 0074-bind-iface.sh.
#
# Every 127.0.0.0/8 address is local on Linux, so 127.0.0.2 and friends are
# bindable sources that the origin can tell apart from the 127.0.0.1 the kernel
# would have picked. t/servers/peer_addr.py reports the source address it saw,
# which is what every assertion here is made of.
#
# Covered, on every event loop:
#   * --bind-source alone pins the source address, in both the "ip" and the
#     "ip:port" spelling;
#   * the "ip:port" spelling pins the source PORT too, not just the address --
#     the address half passing says nothing about the port half;
#   * --bind-source applies to the hop toward an --upstream-proxy, which the
#     manual promises and which no other case here exercises: every other
#     assertion watches a direct target connection;
#   * an ACL "-j BIND --to-source" rule wins over the global default;
#   * a global source of the wrong address family is SKIPPED, not fatal: an
#     IPv4 --bind-source must not break IPv6 targets on a dual-stack proxy;
#   * the same mismatch in an explicit ACL rule stays strict (dropped), which
#     is the asymmetry the option is documented to have;
#   * a malformed --bind-source / --bind-iface is refused at startup, rather
#     than turning into every connection quietly failing later.

. "$(dirname "$0")/lib.sh"
require python3
require timeout
require_opt --bind-source

# Connect to <host>:<port> and print the source address the far end reports,
# or nothing at all if the connection was dropped without a reply. With a
# third argument, bind that source first -- used to check that a pinned source
# is observable at all on this host before asserting that gwproxy pins one.
peer_src()
{
	python3 -c 'import socket,sys
s=socket.socket()
if len(sys.argv) > 3:
    s.bind((sys.argv[3], 0))
s.settimeout(10); s.connect((sys.argv[1], int(sys.argv[2])))
print(s.recv(64).decode().strip())' "$1" "$2" ${3:+"$3"} 2>/dev/null
}

pa4="$(pick_port)"
pa6="$(pick_port)"
pap="$(pick_port)"
python3 "$SERVERS_DIR/peer_addr.py" 127.0.0.1 "$pa4" >"$WORK/peer4.log" 2>&1 &
pa4_pid=$!
_PIDS+=("$pa4_pid")
python3 "$SERVERS_DIR/peer_addr.py" ::1 "$pa6" >"$WORK/peer6.log" 2>&1 &
pa6_pid=$!
_PIDS+=("$pa6_pid")
# Reports "<ip> <port>", and also logs it to a file so it can double as the
# stand-in upstream proxy below, where gwproxy is the one doing the dialling.
python3 "$SERVERS_DIR/peer_addr.py" 127.0.0.1 "$pap" --with-port \
	--log "$WORK/peerport.log" >"$WORK/peerp.log" 2>&1 &
pap_pid=$!
_PIDS+=("$pap_pid")
wait_listen "$pa4" "$pa4_pid" || fail "the IPv4 peer-address server did not start"
wait_listen "$pa6" "$pa6_pid" || fail "the IPv6 peer-address server did not start"
wait_listen "$pap" "$pap_pid" || fail "the port-reporting peer-address server did not start"

# The whole test rests on the origin seeing 127.0.0.1 when nothing is pinned,
# and something else when a source is; if that is not true here, every
# assertion below is meaningless.
direct="$(peer_src 127.0.0.1 "$pa4")"
[ "$direct" = 127.0.0.1 ] || \
	skip "unexpected default loopback source '${direct:-<none>}'"
pinned="$(peer_src 127.0.0.1 "$pa4" 127.0.0.2)"
[ "$pinned" = 127.0.0.2 ] || \
	skip "a pinned loopback source is not observable here (saw '${pinned:-<none>}')"

printf -- '%s\n' '-A OUTPUT -j BIND --to-source 127.0.0.3' \
	'-P OUTPUT ACCEPT' >"$WORK/override.acl"
printf -- '%s\n' '-A OUTPUT -j BIND --to-source 127.0.0.2' \
	'-P OUTPUT ACCEPT' >"$WORK/mismatch.acl"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	# The global default alone pins the source.
	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --target="127.0.0.1:$pa4" --nr-workers=1 \
		--event-loop="$loop" --bind-source=127.0.0.2
	src="$(peer_src 127.0.0.1 "$p")"
	kill "$GWP_PID" 2>/dev/null
	[ "$src" = 127.0.0.2 ] || \
		fail "[$loop] --bind-source did not pin the source (saw '${src:-<none>}')"

	# The "ip:port" spelling parses and pins the same way. A fresh source
	# port per loop keeps the two runs from clashing in TIME_WAIT.
	sp="$(pick_port)"
	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --target="127.0.0.1:$pa4" --nr-workers=1 \
		--event-loop="$loop" --bind-source="127.0.0.4:$sp"
	src="$(peer_src 127.0.0.1 "$p")"
	kill "$GWP_PID" 2>/dev/null
	[ "$src" = 127.0.0.4 ] || \
		fail "[$loop] --bind-source=ip:port did not pin the source (saw '${src:-<none>}')"

	# ...and the port half of "ip:port" reaches the wire too. Asserting the
	# address alone would pass just as well with the port silently dropped,
	# which is the whole of what this case adds.
	sp="$(pick_port)"
	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --target="127.0.0.1:$pap" --nr-workers=1 \
		--event-loop="$loop" --bind-source="127.0.0.4:$sp"
	srcp="$(peer_src 127.0.0.1 "$p")"
	kill "$GWP_PID" 2>/dev/null
	[ "$srcp" = "127.0.0.4 $sp" ] || \
		fail "[$loop] --bind-source=ip:port did not pin the source port (wanted '127.0.0.4 $sp', saw '${srcp:-<none>}')"

	# The hop toward an upstream proxy is pinned as well. peer_addr.py plays
	# the upstream: gwproxy dials it, it records the source it was dialled
	# from and hangs up. The SOCKS5 handshake then fails, and that is fine --
	# the claim under test is about the source of the TCP connection to the
	# upstream, not about the tunnel completing.
	: >"$WORK/peerport.log"
	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --target="127.0.0.1:$pa4" --nr-workers=1 \
		--event-loop="$loop" --bind-source=127.0.0.5 \
		--upstream-proxy="socks5://127.0.0.1:$pap"
	peer_src 127.0.0.1 "$p" >/dev/null 2>&1
	for _ in $(seq 1 50); do
		[ -s "$WORK/peerport.log" ] && break
		sleep 0.1
	done
	kill "$GWP_PID" 2>/dev/null
	upsrc="$(cut -d' ' -f1 <"$WORK/peerport.log" 2>/dev/null | head -1)"
	[ "$upsrc" = 127.0.0.5 ] || \
		fail "[$loop] --bind-source did not pin the upstream hop (saw '${upsrc:-<none>}')"

	# An ACL rule overrides the global default.
	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --target="127.0.0.1:$pa4" --nr-workers=1 \
		--event-loop="$loop" --bind-source=127.0.0.2 \
		--acl-file="$WORK/override.acl"
	src="$(peer_src 127.0.0.1 "$p")"
	kill "$GWP_PID" 2>/dev/null
	[ "$src" = 127.0.0.3 ] || \
		fail "[$loop] -j BIND --to-source did not override --bind-source (saw '${src:-<none>}')"

	# A global IPv4 source does not apply to an IPv6 target: the source is
	# skipped and the connection still goes through.
	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --target="[::1]:$pa6" --nr-workers=1 \
		--event-loop="$loop" --bind-source=127.0.0.2
	src="$(peer_src 127.0.0.1 "$p")"
	kill "$GWP_PID" 2>/dev/null
	[ "$src" = "::1" ] || \
		fail "[$loop] an IPv4 --bind-source broke an IPv6 target (saw '${src:-<none>}')"

	# The same mismatch spelled out in a rule stays fatal.
	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --target="[::1]:$pa6" --nr-workers=1 \
		--event-loop="$loop" --acl-file="$WORK/mismatch.acl"
	src="$(peer_src 127.0.0.1 "$p")"
	kill "$GWP_PID" 2>/dev/null
	[ -z "$src" ] || \
		fail "[$loop] an ACL --to-source family mismatch was not strict (saw '$src')"
done

# reject <description> <args...>: gwproxy must refuse these at startup. Exit 0
# means it validated nothing and shut down for some other reason; timeout's 124
# means it started and kept running, i.e. the bad value was accepted.
reject()
{
	local desc="$1" p rc=0
	shift
	p="$(pick_port)"
	timeout 10 "$GWPROXY" --bind="127.0.0.1:$p" --target=127.0.0.1:9 \
		--acl-allow-all --nr-workers=1 "$@" >"$WORK/reject.log" 2>&1 || rc=$?
	case "$rc" in
	0)	fail "gwproxy exited 0 with $desc" ;;
	124)	fail "gwproxy started and kept running with $desc" ;;
	esac
}

reject "--bind-source=notanip"		--bind-source=notanip
reject "a hostname as --bind-source"	--bind-source=localhost
reject "an out-of-range source port"	--bind-source=127.0.0.2:70000
reject "an unterminated IPv6 source"	--bind-source='[::1'
reject "an oversized --bind-iface"	--bind-iface=abcdefghijklmnop
reject "an empty --bind-iface"		--bind-iface=

pass
