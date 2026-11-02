#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# An IPv4-mapped address (::ffff:a.b.c.d) is IPv4 traffic, whatever the family
# of the sockaddr holding it, so a pinned source has to treat it as IPv4. If it
# counted as IPv6, any client could leave an IPv4 --bind-source behind by
# spelling its target that way, and reach the same host from the default source.
#
# As in 0073-bind-source.sh, every 127.0.0.0/8 address is a bindable local
# source and t/servers/peer_addr.py reports the source it saw.
#
# Covered, on every event loop:
#   * a mapped target takes an IPv4 --bind-source, through SOCKS5, HTTP CONNECT
#     and --target, and through -j BIND --to-source, which refused it before;
#   * the source port of "ip:port" comes along;
#   * a mapped source is IPv4 too, for an IPv4 and for a mapped target;
#   * a mapped source does not apply to a genuine IPv6 target (skipped by
#     default, refused in a rule), and an IPv6 source does not apply to a mapped
#     target.

. "$(dirname "$0")/lib.sh"
require python3
require_opt --bind-source

# via_socks <proxy-port> <origin-port> <ipv4|mapped>: print what the origin
# sends through a SOCKS5 tunnel, or nothing if it was refused or dropped.
via_socks()
{
	python3 -c 'import socket,struct,sys
ip = bytes([127,0,0,1])
dst = b"\x01" + ip if sys.argv[3] == "ipv4" else b"\x04" + bytes(10) + b"\xff\xff" + ip
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10)
s.settimeout(10)
s.sendall(b"\x05\x01\x00")
assert s.recv(2) == b"\x05\x00"
s.sendall(b"\x05\x01\x00" + dst + struct.pack(">H", int(sys.argv[2])))
buf = b""
while True:
    d = s.recv(256)
    if not d:
        break
    buf += d
assert buf[1] == 0
alen = {1: 4, 4: 16}[buf[3]]
print(buf[4 + alen + 2:].decode().strip())' "$@" 2>/dev/null
}

# via_http <proxy-port> <origin-port> <host>: the same through HTTP CONNECT.
via_http()
{
	python3 -c 'import socket,sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10)
s.settimeout(10)
a = "%s:%s" % (sys.argv[3], sys.argv[2])
s.sendall(("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (a, a)).encode())
buf = b""
while True:
    d = s.recv(256)
    if not d:
        break
    buf += d
h, _, b = buf.partition(b"\r\n\r\n")
assert b" 200 " in h.split(b"\r\n")[0]
print(b.decode().strip())' "$@" 2>/dev/null
}

# direct <proxy-port>: what a plain forwarder's origin sends back.
direct()
{
	python3 -c 'import socket,sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10)
s.settimeout(10)
print(s.recv(64).decode().strip())' "$@" 2>/dev/null
}

# peer_src <port> [<source>]: what the origin reports to a direct connection,
# with that source bound first if one is given. Says whether a pinned source is
# observable on this host at all.
peer_src()
{
	python3 -c 'import socket,sys
s = socket.socket()
if len(sys.argv) > 2:
    s.bind((sys.argv[2], 0))
s.settimeout(10)
s.connect(("127.0.0.1", int(sys.argv[1])))
print(s.recv(64).decode().strip())' "$@" 2>/dev/null
}

expect()
{
	[ "$2" = "$3" ] || fail "$1: wanted source '${3:-<dropped>}', saw '${2:-<dropped>}'"
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
python3 "$SERVERS_DIR/peer_addr.py" 127.0.0.1 "$pap" --with-port \
	>"$WORK/peerp.log" 2>&1 &
pap_pid=$!
_PIDS+=("$pap_pid")
wait_listen "$pa4" "$pa4_pid" || fail "the IPv4 peer-address server did not start"
wait_listen "$pa6" "$pa6_pid" || fail "the IPv6 peer-address server did not start"
wait_listen "$pap" "$pap_pid" || fail "the port-reporting peer-address server did not start"

# Every assertion below rests on the origin seeing 127.0.0.1 when nothing is
# pinned, and something else when a source is. If that is not true here, they
# are meaningless.
unpinned="$(peer_src "$pa4")"
[ "$unpinned" = 127.0.0.1 ] || \
	skip "unexpected default loopback source '${unpinned:-<none>}'"
pinned="$(peer_src "$pa4" 127.0.0.2)"
[ "$pinned" = 127.0.0.2 ] || \
	skip "a pinned loopback source is not observable here (saw '${pinned:-<none>}')"

printf -- '%s\n' '-A OUTPUT -j BIND --to-source 127.0.0.3' \
	'-P OUTPUT ACCEPT' >"$WORK/rule4.acl"
printf -- '%s\n' '-A OUTPUT -j BIND --to-source ::ffff:127.0.0.4' \
	'-P OUTPUT ACCEPT' >"$WORK/rulemapped.acl"
printf -- '%s\n' '-A OUTPUT -j BIND --to-source ::1' \
	'-P OUTPUT ACCEPT' >"$WORK/rule6.acl"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	# An IPv4 --bind-source, through each way of naming a mapped target.
	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --as-http=1 --nr-workers=1 \
		--event-loop="$loop" --bind-source=127.0.0.2
	expect "[$loop] SOCKS5 IPv4 control" "$(via_socks "$p" "$pa4" ipv4)" 127.0.0.2
	expect "[$loop] SOCKS5 mapped target" "$(via_socks "$p" "$pa4" mapped)" 127.0.0.2
	expect "[$loop] HTTP mapped target" \
		"$(via_http "$p" "$pa4" '[::ffff:127.0.0.1]')" 127.0.0.2
	kill "$GWP_PID" 2>/dev/null

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --target="[::ffff:127.0.0.1]:$pa4" --nr-workers=1 \
		--event-loop="$loop" --bind-source=127.0.0.2
	expect "[$loop] --target mapped" "$(direct "$p")" 127.0.0.2
	kill "$GWP_PID" 2>/dev/null

	# The port half of "ip:port" reaches the mapped form too.
	sp="$(pick_port)"
	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --nr-workers=1 \
		--event-loop="$loop" --bind-source="127.0.0.5:$sp"
	expect "[$loop] mapped target, ip:port" "$(via_socks "$p" "$pap" mapped)" \
		"127.0.0.5 $sp"
	kill "$GWP_PID" 2>/dev/null

	# An ACL rule with an IPv4 source applies to a mapped target as well.
	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --nr-workers=1 \
		--event-loop="$loop" --acl-file="$WORK/rule4.acl"
	expect "[$loop] -j BIND, mapped target" "$(via_socks "$p" "$pa4" mapped)" 127.0.0.3
	kill "$GWP_PID" 2>/dev/null

	# A mapped source is IPv4 for both spellings of an IPv4 target, in the
	# default and in a rule.
	sp="$(pick_port)"
	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --nr-workers=1 --event-loop="$loop" \
		--bind-source="[::ffff:127.0.0.6]:$sp"
	expect "[$loop] mapped source:port, IPv4 target" \
		"$(via_socks "$p" "$pap" ipv4)" "127.0.0.6 $sp"
	kill "$GWP_PID" 2>/dev/null

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --nr-workers=1 --event-loop="$loop" \
		--bind-source=::ffff:127.0.0.7
	expect "[$loop] mapped source, IPv4 target" "$(via_socks "$p" "$pa4" ipv4)" 127.0.0.7
	expect "[$loop] mapped source, mapped target" "$(via_socks "$p" "$pa4" mapped)" 127.0.0.7
	kill "$GWP_PID" 2>/dev/null

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --nr-workers=1 \
		--event-loop="$loop" --acl-file="$WORK/rulemapped.acl"
	expect "[$loop] -j BIND mapped source, IPv4 target" \
		"$(via_socks "$p" "$pa4" ipv4)" 127.0.0.4
	kill "$GWP_PID" 2>/dev/null

	# A mapped source does not apply to a genuine IPv6 target: skipped as a
	# default, refused as a rule.
	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --target="[::1]:$pa6" --nr-workers=1 \
		--event-loop="$loop" --bind-source=::ffff:127.0.0.2
	expect "[$loop] mapped source, IPv6 target" "$(direct "$p")" ::1
	kill "$GWP_PID" 2>/dev/null

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --target="[::1]:$pa6" --nr-workers=1 \
		--event-loop="$loop" --acl-file="$WORK/rulemapped.acl"
	expect "[$loop] -j BIND mapped source, IPv6 target" "$(direct "$p")" ""
	kill "$GWP_PID" 2>/dev/null

	# Nor does a genuine IPv6 source apply to a mapped target.
	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --nr-workers=1 \
		--event-loop="$loop" --bind-source=::1
	expect "[$loop] IPv6 source, mapped target" "$(via_socks "$p" "$pa4" mapped)" 127.0.0.1
	kill "$GWP_PID" 2>/dev/null

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --nr-workers=1 \
		--event-loop="$loop" --acl-file="$WORK/rule6.acl"
	expect "[$loop] -j BIND IPv6 source, mapped target" \
		"$(via_socks "$p" "$pa4" mapped)" ""
	kill "$GWP_PID" 2>/dev/null
done

pass
