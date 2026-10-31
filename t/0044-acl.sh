#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# ACL rule file (--acl-file): a malformed file must be refused at startup, and
# a valid file must load without disturbing normal proxying. Enforcement of the
# rules is exercised by later checks in this file as it is wired in; for now
# this covers loading and validation on both event loops.

. "$(dirname "$0")/lib.sh"
require curl
require python3

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 20000
start_httpd "$hp" "$WORK" "1.1"


# A UDP echo server for the UDP-relay ACL checks.
start_udp_echo 127.0.0.1
ep="$UDP_ECHO_PORT"

# A malformed ACL is rejected at startup (gwproxy exits non-zero, no listener).
printf -- '-A OUTPUT -j BOGUS\n' >"$WORK/bad.acl"
bp="$(pick_port)"
if "$GWPROXY" --bind="127.0.0.1:$bp" --as-socks5=1 \
	--acl-file="$WORK/bad.acl" >"$WORK/bad.log" 2>&1; then
	fail "gwproxy accepted a malformed ACL file"
fi
grep -qi 'ACL' "$WORK/bad.log" || fail "malformed ACL startup lacked an error"

# So is an empty one: it is what a writer that truncates and refills the file
# leaves in between, not a rule set. If it were accepted, gwproxy would keep
# running; the timeout turns that into a failure instead of a hang.
: >"$WORK/empty.acl"
ec=0
timeout 10 "$GWPROXY" --bind="127.0.0.1:$(pick_port)" --as-socks5=1 \
	--acl-file="$WORK/empty.acl" >"$WORK/empty.log" 2>&1 || ec=$?
{ [ "$ec" -ne 0 ] && [ "$ec" -ne 124 ]; } || \
	fail "gwproxy accepted an empty ACL file (exit $ec)"
grep -qi 'ACL' "$WORK/empty.log" || fail "empty ACL startup lacked an error"

# A valid ACL loads and proxying still works, on every available loop.
printf -- '%s\n' \
	'# sample ACL: allow the HTTP origin port, deny port 9 (discard)' \
	'-P INPUT ACCEPT' \
	'-A OUTPUT --dports 9 -j REJECT' \
	'-P OUTPUT ACCEPT' >"$WORK/ok.acl"

# INPUT chain that rejects loopback clients (the test client is 127.0.0.1).
printf -- '%s\n' \
	'-A INPUT -s 127.0.0.1/32 -j REJECT' \
	'-P INPUT ACCEPT' >"$WORK/deny-client.acl"

# Read the SOCKS5 CONNECT reply code for a TCP target, via the given proxy.
socks5_connect_rep() {			# $1=proxy_port $2=dst_ip $3=dst_port
	python3 - "$@" <<-'PY'
	import socket, struct, sys
	pp, ip, dp = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
	t = socket.create_connection(('127.0.0.1', pp)); t.settimeout(10)
	t.sendall(b'\x05\x01\x00'); assert t.recv(2) == b'\x05\x00'
	t.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(ip) + struct.pack('!H', dp))
	print(t.recv(10)[1])
	PY
}

# Connect to a plain-forward proxy and print the source address the origin
# reported, or nothing at all when the connection was dropped without a reply
# (which is what an OUTPUT REJECT looks like on the plain path).
plain_peer_src() {			# $1=proxy_port
	python3 -c 'import socket,sys
s=socket.create_connection(("127.0.0.1", int(sys.argv[1]))); s.settimeout(10)
print(s.recv(64).decode().strip())' "$1" 2>/dev/null
}

# Built-in default ACL: with no --acl-file (and no --acl-allow-all) gwproxy
# rejects loopback/private targets. Launch directly to bypass gwp_start's
# automatic --acl-allow-all injection.
ddp="$(pick_port)"
"$GWPROXY" --bind="127.0.0.1:$ddp" --as-http=1 --nr-workers=1 --log-level=3 \
	>"$WORK/defacl.log" 2>&1 &
dpid=$!
_PIDS+=("$dpid")
wait_listen "$ddp" "$dpid" || fail "default-ACL proxy did not listen"
code="$(curl -s --max-time 10 -x "http://127.0.0.1:$ddp" \
	"http://127.0.0.1:$hp/payload.bin" -o /dev/null -w '%{http_code}')"
[ "$code" = 403 ] \
	|| fail "default ACL did not block the loopback target ($code, want 403)"
kill "$dpid" 2>/dev/null

# --acl-allow-all disables the default so the same fetch succeeds (gwp_start
# injects --acl-allow-all when no ACL argument is present).
ap="$(pick_port)"
gwp_start "127.0.0.1:$ap" --as-http=1
code="$(curl -s --max-time 20 -x "http://127.0.0.1:$ap" \
	"http://127.0.0.1:$hp/payload.bin" -o /dev/null -w '%{http_code}')"
[ "$code" = 200 ] \
	|| fail "--acl-allow-all did not permit the loopback target ($code, want 200)"
kill "$GWP_PID" 2>/dev/null

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	# gwp_start succeeds only once gwproxy is listening, which a valid ACL
	# reaches and a malformed one (rejected at startup) does not.
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --as-http=1 --event-loop="$loop" \
		--acl-file="$WORK/ok.acl"

	# An allowed target still proxies end-to-end.
	curl -s --max-time 20 -x "socks5h://127.0.0.1:$pp" \
		"http://127.0.0.1:$hp/payload.bin" -o "$WORK/out.bin" \
		|| fail "$loop SOCKS5 CONNECT to an allowed target failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
		"$loop payload corrupted for an allowed target"

	# A denied target: SOCKS5 replies REP 0x02 (not allowed by ruleset).
	rep="$(socks5_connect_rep "$pp" 127.0.0.1 9)"
	[ "$rep" = 2 ] \
		|| fail "$loop SOCKS5 CONNECT to a denied target got REP $rep (want 2)"

	# A denied target over HTTP forwarding: 403 Forbidden.
	code="$(curl -s --max-time 20 -x "http://127.0.0.1:$pp" \
		"http://127.0.0.1:9/" -o /dev/null -w '%{http_code}')"
	[ "$code" = 403 ] \
		|| fail "$loop HTTP forward to a denied target got $code (want 403)"

	kill "$GWP_PID" 2>/dev/null

	# End-to-end IPv6: an IPv6-bound listener with an ACL rule on an IPv6
	# CIDR blocks the IPv6 target (::1) but still serves an IPv4 target
	# (the dual-stack httpd is reachable both ways). Exercises the v6
	# address match and a v6 listener on both loops.
	printf -- '%s\n' '-A OUTPUT -d ::1/128 -j REJECT' \
		'-P OUTPUT ACCEPT' >"$WORK/v6.acl"
	v6p="$(pick_port)"
	gwp_start "[::1]:$v6p" --as-socks5=1 --event-loop="$loop" \
		--acl-file="$WORK/v6.acl"
	if curl -s --max-time 10 -x "socks5h://[::1]:$v6p" \
		"http://[::1]:$hp/payload.bin" -o /dev/null 2>/dev/null; then
		fail "$loop IPv6 ACL rule did not block the ::1 target"
	fi
	curl -s --max-time 20 -x "socks5h://[::1]:$v6p" \
		"http://127.0.0.1:$hp/payload.bin" -o "$WORK/v6.out" \
		|| fail "$loop IPv6 listener wrongly blocked the IPv4 target"
	assert_files_equal "$WORK/payload.bin" "$WORK/v6.out" \
		"$loop IPv6 path corrupted the IPv4-target payload"
	kill "$GWP_PID" 2>/dev/null

	# -m domain: a socks5h request naming a blocked host is refused (the
	# domain is matched before resolution), while a literal-IP request
	# (which carries no hostname) is allowed.
	printf -- '%s\n' '-A OUTPUT -m domain --domain localhost -j REJECT' \
		'-P OUTPUT ACCEPT' >"$WORK/domain.acl"
	dp="$(pick_port)"
	gwp_start "127.0.0.1:$dp" --as-socks5=1 --event-loop="$loop" \
		--acl-file="$WORK/domain.acl"
	if curl -s --max-time 10 -x "socks5h://127.0.0.1:$dp" \
		"http://localhost:$hp/payload.bin" -o /dev/null 2>/dev/null; then
		fail "$loop -m domain rule did not block the hostname request"
	fi
	# The same name with a trailing dot is the same name to the resolver.
	rep="$(python3 "$SERVERS_DIR/socks5_probe.py" --host 127.0.0.1 \
		--atyp domain --dst localhost. "$dp" "$hp")"
	[ "$rep" = "REP=0x02" ] \
		|| fail "$loop -m domain rule let 'localhost.' through ($rep)"
	curl -s --max-time 20 -x "socks5://127.0.0.1:$dp" \
		"http://127.0.0.1:$hp/payload.bin" -o "$WORK/dom.out" \
		|| fail "$loop literal-IP request wrongly blocked by -m domain"
	assert_files_equal "$WORK/payload.bin" "$WORK/dom.out" \
		"$loop -m domain corrupted the literal-IP payload"
	kill "$GWP_PID" 2>/dev/null

	# --domain-regexp (PCRE builds only): a raw/unanchored pattern matches
	# the requested hostname; a non-matching host is served.
	if grep -q CONFIG_PCRE "$ROOT/config.h" 2>/dev/null; then
		printf -- '%s\n' \
			'-A OUTPUT -m domain --domain-regexp ^localhost$ -j REJECT' \
			'-P OUTPUT ACCEPT' >"$WORK/domre.acl"
		rp="$(pick_port)"
		gwp_start "127.0.0.1:$rp" --as-socks5=1 --event-loop="$loop" \
			--acl-file="$WORK/domre.acl"
		if curl -s --max-time 10 -x "socks5h://127.0.0.1:$rp" \
			"http://localhost:$hp/payload.bin" -o /dev/null 2>/dev/null; then
			fail "$loop --domain-regexp did not block the hostname"
		fi
		rep="$(python3 "$SERVERS_DIR/socks5_probe.py" --host 127.0.0.1 \
			--atyp domain --dst localhost. "$rp" "$hp")"
		[ "$rep" = "REP=0x02" ] \
			|| fail "$loop --domain-regexp let 'localhost.' through ($rep)"
		curl -s --max-time 20 -x "socks5://127.0.0.1:$rp" \
			"http://127.0.0.1:$hp/payload.bin" -o "$WORK/domre.out" \
			|| fail "$loop literal-IP wrongly blocked by --domain-regexp"
		assert_files_equal "$WORK/payload.bin" "$WORK/domre.out" \
			"$loop --domain-regexp corrupted the literal-IP payload"
		kill "$GWP_PID" 2>/dev/null
	fi

	# -m user (OUTPUT-only): with an auth file, a rule keyed on the
	# authenticated username blocks that user while another is served. The
	# username is known only after the auth handshake.
	printf -- '%s\n' 'user001:pw1' 'user002:pw2' >"$WORK/user.auth"
	printf -- '%s\n' '-A OUTPUT -m user --user user001 -j REJECT' \
		'-P OUTPUT ACCEPT' >"$WORK/user.acl"
	uxp="$(pick_port)"
	gwp_start "127.0.0.1:$uxp" --as-socks5=1 --as-http=1 \
		--event-loop="$loop" --auth-file="$WORK/user.auth" \
		--acl-file="$WORK/user.acl"
	if curl -s --max-time 10 -x "socks5h://user001:pw1@127.0.0.1:$uxp" \
		"http://127.0.0.1:$hp/payload.bin" -o /dev/null 2>/dev/null; then
		fail "$loop -m user did not block user001 (socks5)"
	fi
	curl -s --max-time 20 -x "socks5h://user002:pw2@127.0.0.1:$uxp" \
		"http://127.0.0.1:$hp/payload.bin" -o "$WORK/user.out" \
		|| fail "$loop -m user wrongly blocked user002 (socks5)"
	assert_files_equal "$WORK/payload.bin" "$WORK/user.out" \
		"$loop -m user corrupted user002's payload"
	code="$(curl -s --max-time 20 -x "http://user001:pw1@127.0.0.1:$uxp" \
		"http://127.0.0.1:$hp/payload.bin" -o /dev/null -w '%{http_code}')"
	[ "$code" = 403 ] \
		|| fail "$loop -m user over HTTP got $code for user001 (want 403)"

	# The same rule must govern relayed UDP datagrams, which carry the
	# username of the authenticated control connection: user001's are
	# dropped, user002's still round-trip.
	python3 "$SERVERS_DIR/socks5_udp_client.py" --user user001 --pass pw1 \
		--expect-drop "$uxp" "$ep" 64 >/dev/null \
		|| fail "$loop -m user did not block user001's UDP datagram"
	python3 "$SERVERS_DIR/socks5_udp_client.py" --user user002 --pass pw2 \
		"$uxp" "$ep" 64 >/dev/null \
		|| fail "$loop -m user wrongly blocked user002's UDP datagram"
	kill "$GWP_PID" 2>/dev/null

	# -j BIND --to-source pins the outgoing source address. All of
	# 127.0.0.0/8 is local, so binding 127.0.0.2 needs no privilege; a
	# peer-reporting server confirms the proxy connected from that source.
	pa="$(pick_port)"
	python3 "$SERVERS_DIR/peer_addr.py" 127.0.0.1 "$pa" \
		>"$WORK/peer.log" 2>&1 &
	_PIDS+=("$!")
	wait_listen "$pa" "$!" || fail "$loop peer_addr server did not listen"
	printf -- '%s\n' '-A OUTPUT -j BIND --to-source 127.0.0.2' \
		'-P OUTPUT ACCEPT' >"$WORK/bind.acl"
	bpp="$(pick_port)"
	gwp_start "127.0.0.1:$bpp" --target="127.0.0.1:$pa" \
		--event-loop="$loop" --acl-file="$WORK/bind.acl"
	src="$(plain_peer_src "$bpp")"
	[ "$src" = 127.0.0.2 ] \
		|| fail "$loop BIND --to-source: server saw '$src' (want 127.0.0.2)"
	kill "$GWP_PID" 2>/dev/null

	# --accept makes BIND terminal. The two rule files below differ only by
	# that flag, so the pair pins the behaviour from both sides: without it
	# traversal reaches the REJECT and the connection dies, with it it stops
	# at the BIND -- and the source is still pinned, proving --accept ends
	# the walk rather than skipping the modifier.
	printf -- '%s\n' '-A OUTPUT -j BIND --to-source 127.0.0.2' \
		'-A OUTPUT -j REJECT' '-P OUTPUT ACCEPT' >"$WORK/bind-noacc.acl"
	printf -- '%s\n' '-A OUTPUT -j BIND --to-source 127.0.0.2 --accept' \
		'-A OUTPUT -j REJECT' '-P OUTPUT ACCEPT' >"$WORK/bind-acc.acl"

	bnp="$(pick_port)"
	gwp_start "127.0.0.1:$bnp" --target="127.0.0.1:$pa" \
		--event-loop="$loop" --acl-file="$WORK/bind-noacc.acl"
	src="$(plain_peer_src "$bnp")"
	kill "$GWP_PID" 2>/dev/null
	[ -z "$src" ] \
		|| fail "$loop BIND without --accept did not fall through to REJECT (saw '$src')"

	bap="$(pick_port)"
	gwp_start "127.0.0.1:$bap" --target="127.0.0.1:$pa" \
		--event-loop="$loop" --acl-file="$WORK/bind-acc.acl"
	src="$(plain_peer_src "$bap")"
	kill "$GWP_PID" 2>/dev/null
	[ "$src" = 127.0.0.2 ] \
		|| fail "$loop BIND --accept did not stop at the BIND (saw '${src:-<none>}')"

	# -j DNAT rewrites the destination: a CONNECT to a dead port is
	# redirected to the real origin and succeeds.
	printf -- '%s\n' \
		"-A OUTPUT -d 127.0.0.1 --dports 8080 -j DNAT --to :$hp" \
		'-P OUTPUT ACCEPT' >"$WORK/dnat.acl"
	np="$(pick_port)"
	gwp_start "127.0.0.1:$np" --as-socks5=1 --event-loop="$loop" \
		--acl-file="$WORK/dnat.acl"
	curl -s --max-time 20 -x "socks5://127.0.0.1:$np" \
		"http://127.0.0.1:8080/payload.bin" -o "$WORK/dnat.out" \
		|| fail "$loop DNAT-redirected CONNECT failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/dnat.out" \
		"$loop DNAT redirected to the wrong target"
	kill "$GWP_PID" 2>/dev/null

	# DNAT also applies to plain --target forwarding: the fixed dead target
	# is redirected to the real origin.
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --target="127.0.0.1:8080" --event-loop="$loop" \
		--acl-file="$WORK/dnat.acl"
	curl -s --max-time 20 "http://127.0.0.1:$fp/payload.bin" \
		-o "$WORK/dnat.plain.out" \
		|| fail "$loop plain DNAT-redirected forward failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/dnat.plain.out" \
		"$loop plain DNAT redirected to the wrong target"
	kill "$GWP_PID" 2>/dev/null

	# Upstream DNAT: the front rewrites the destination before handing it to
	# the upstream proxy. A plain upstream SOCKS5 hop (no ACL) is the chain
	# endpoint; the front carries the DNAT rule.
	uup="$(pick_port)"
	gwp_start "127.0.0.1:$uup" --as-socks5=1 --event-loop="$loop"
	usp="$GWP_PID"		# gwp_start overwrites GWP_PID with the front below

	# socks5:// front (front-resolved IP): a literal-IP request to a dead
	# port is DNAT-redirected, and the rewritten IP reaches the upstream.
	ufp="$(pick_port)"
	gwp_start "127.0.0.1:$ufp" --as-socks5=1 --event-loop="$loop" \
		--upstream-proxy="socks5://127.0.0.1:$uup" \
		--acl-file="$WORK/dnat.acl"
	curl -s --max-time 20 -x "socks5://127.0.0.1:$ufp" \
		"http://127.0.0.1:8080/payload.bin" -o "$WORK/updnat.out" \
		|| fail "$loop socks5:// upstream DNAT failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/updnat.out" \
		"$loop socks5:// upstream DNAT redirected to the wrong target"
	kill "$GWP_PID" 2>/dev/null

	# socks5h:// front (upstream resolves): a hostname request is rewritten
	# to the origin IP, so the (unresolvable) name never reaches DNS.
	printf -- '%s\n' \
		"-A OUTPUT -m domain --domain blocked.invalid -j DNAT --to 127.0.0.1:$hp" \
		'-P OUTPUT ACCEPT' >"$WORK/updnath.acl"
	ufp="$(pick_port)"
	gwp_start "127.0.0.1:$ufp" --as-socks5=1 --event-loop="$loop" \
		--upstream-proxy="socks5h://127.0.0.1:$uup" \
		--acl-file="$WORK/updnath.acl"
	curl -s --max-time 20 -x "socks5h://127.0.0.1:$ufp" \
		"http://blocked.invalid:9999/payload.bin" -o "$WORK/updnath.out" \
		|| fail "$loop socks5h:// upstream DNAT failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/updnath.out" \
		"$loop socks5h:// upstream DNAT redirected to the wrong target"
	kill "$GWP_PID" 2>/dev/null

	# socks5h:// address-only DNAT (--to <ip> with no port): the client's
	# original requested port must be preserved (not clobbered to :0), so a
	# request to blocked.invalid:$hp reaches the origin on $hp.
	printf -- '%s\n' \
		'-A OUTPUT -m domain --domain blocked.invalid -j DNAT --to 127.0.0.1' \
		'-P OUTPUT ACCEPT' >"$WORK/updnathp.acl"
	ufp="$(pick_port)"
	gwp_start "127.0.0.1:$ufp" --as-socks5=1 --event-loop="$loop" \
		--upstream-proxy="socks5h://127.0.0.1:$uup" \
		--acl-file="$WORK/updnathp.acl"
	curl -s --max-time 20 -x "socks5h://127.0.0.1:$ufp" \
		"http://blocked.invalid:$hp/payload.bin" -o "$WORK/updnathp.out" \
		|| fail "$loop socks5h:// address-only DNAT lost the original port"
	assert_files_equal "$WORK/payload.bin" "$WORK/updnathp.out" \
		"$loop socks5h:// address-only DNAT redirected to the wrong target"
	kill "$GWP_PID" 2>/dev/null

	kill "$usp" 2>/dev/null

	# Hot reload survives an atomic replace (write-temp + rename-over, as
	# editors and install(1) do): the watch is on the directory, so a
	# renamed-in acl file is still picked up. A file/inode watch would go
	# stale here and never reload.
	cp "$WORK/ok.acl" "$WORK/reload.acl"
	rp="$(pick_port)"
	gwp_start "127.0.0.1:$rp" --as-http=1 --event-loop="$loop" \
		--acl-file="$WORK/reload.acl"
	code="$(curl -s --max-time 20 -x "http://127.0.0.1:$rp" \
		"http://127.0.0.1:$hp/payload.bin" -o /dev/null -w '%{http_code}')"
	[ "$code" = 200 ] || fail "$loop pre-reload fetch got $code (want 200)"
	printf -- '%s\n' "-A OUTPUT --dports $hp -j REJECT" '-P OUTPUT ACCEPT' \
		>"$WORK/reload.new"
	mv -f "$WORK/reload.new" "$WORK/reload.acl"
	code=""
	for _ in $(seq 1 50); do
		code="$(curl -s --max-time 20 -x "http://127.0.0.1:$rp" \
			"http://127.0.0.1:$hp/payload.bin" -o /dev/null \
			-w '%{http_code}')"
		[ "$code" = 403 ] && break
		sleep 0.1
	done
	[ "$code" = 403 ] \
		|| fail "$loop acl not reloaded after atomic rename ($code, want 403)"
	kill "$GWP_PID" 2>/dev/null

	# INPUT chain: a denied client source is dropped at accept, before any
	# handshake, so the connection fails outright.
	ip="$(pick_port)"
	gwp_start "127.0.0.1:$ip" --as-socks5=1 --event-loop="$loop" \
		--acl-file="$WORK/deny-client.acl"
	if curl -s --max-time 10 -x "socks5h://127.0.0.1:$ip" \
		"http://127.0.0.1:$hp/payload.bin" -o /dev/null 2>/dev/null; then
		fail "$loop INPUT-denied client was served"
	fi
	kill "$GWP_PID" 2>/dev/null

	# Plain --target forwarding connects at accept time and enforces the
	# OUTPUT chain too: denied target -> dropped, allowed target -> served.
	printf -- '%s\n' "-A OUTPUT --dports $hp -j REJECT" '-P OUTPUT ACCEPT' \
		>"$WORK/plain-deny.acl"
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --target="127.0.0.1:$hp" --event-loop="$loop" \
		--acl-file="$WORK/plain-deny.acl"
	if curl -s --max-time 10 "http://127.0.0.1:$fp/payload.bin" \
		-o /dev/null 2>/dev/null; then
		fail "$loop plain forward to a denied target was served"
	fi
	kill "$GWP_PID" 2>/dev/null

	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --target="127.0.0.1:$hp" --event-loop="$loop" \
		--acl-file="$WORK/ok.acl"
	curl -s --max-time 20 "http://127.0.0.1:$fp/payload.bin" \
		-o "$WORK/plain.out" \
		|| fail "$loop plain forward to an allowed target failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/plain.out" \
		"$loop plain forward corrupted the payload"
	kill "$GWP_PID" 2>/dev/null

	# UDP relay OUTPUT: a datagram to a denied target is dropped, while an
	# allowed target (ok.acl only denies TCP port 9) round-trips.
	printf -- '%s\n' "-A OUTPUT -p udp --dports $ep -j REJECT" \
		'-P OUTPUT ACCEPT' >"$WORK/udp-deny.acl"
	up="$(pick_port)"
	gwp_start "127.0.0.1:$up" --as-socks5=1 --event-loop="$loop" \
		--acl-file="$WORK/udp-deny.acl"
	if python3 "$SERVERS_DIR/socks5_udp_client.py" "$up" "$ep" 64 \
		>/dev/null 2>&1; then
		fail "$loop UDP datagram to a denied target was relayed"
	fi
	kill "$GWP_PID" 2>/dev/null

	up="$(pick_port)"
	gwp_start "127.0.0.1:$up" --as-socks5=1 --event-loop="$loop" \
		--acl-file="$WORK/ok.acl"
	python3 "$SERVERS_DIR/socks5_udp_client.py" "$up" "$ep" 64 \
		|| fail "$loop UDP datagram to an allowed target failed"
	kill "$GWP_PID" 2>/dev/null

	# INPUT with -p udp: the UDP ASSOCIATE is refused, but TCP still works
	# (the rule is protocol-specific).
	printf -- '%s\n' '-A INPUT -s 127.0.0.1/32 -p udp -j REJECT' \
		'-P INPUT ACCEPT' >"$WORK/udp-in-deny.acl"
	up="$(pick_port)"
	gwp_start "127.0.0.1:$up" --as-socks5=1 --event-loop="$loop" \
		--acl-file="$WORK/udp-in-deny.acl"
	if python3 "$SERVERS_DIR/socks5_udp_client.py" "$up" "$ep" 64 \
		>/dev/null 2>&1; then
		fail "$loop UDP ASSOCIATE from a udp-denied client succeeded"
	fi
	curl -s --max-time 20 -x "socks5h://127.0.0.1:$up" \
		"http://127.0.0.1:$hp/payload.bin" -o /dev/null \
		|| fail "$loop TCP wrongly blocked by a -p udp INPUT rule"
	kill "$GWP_PID" 2>/dev/null

	# -m statistic --mode nth. The unit tests cover the arithmetic; what
	# this proves is that the module is wired through the real binary --
	# parsed at startup, evaluated per connection, and enforced.
	#
	# A literal IP target on purpose: a name could resolve to several
	# candidate addresses, and the OUTPUT chain runs once per candidate, so
	# the count would not be one per connection.
	printf -- '%s\n' \
		'-A OUTPUT --dports 9 -m statistic --mode nth --every 2 -j REJECT' \
		'-P OUTPUT ACCEPT' >"$WORK/nth.acl"
	np="$(pick_port)"
	gwp_start "127.0.0.1:$np" --as-socks5=1 --event-loop="$loop" \
		--acl-file="$WORK/nth.acl"
	rejected=0
	for i in 1 2 3 4 5 6 7 8; do
		rep="$(socks5_connect_rep "$np" 127.0.0.1 9)"
		[ "$rep" = 2 ] && rejected=$((rejected + 1))
	done
	[ "$rejected" = 4 ] || \
		fail "$loop -m statistic --every 2 rejected $rejected of 8 (want 4)"

	# The same proxy, a port the rule does not match: never rejected, and
	# those connections must not consume the counter either.
	for i in 1 2 3 4; do
		rep="$(socks5_connect_rep "$np" 127.0.0.1 "$hp")"
		[ "$rep" = 0 ] || \
			fail "$loop -m statistic leaked onto an unmatched port (REP $rep)"
	done
	kill "$GWP_PID" 2>/dev/null
done

pass
