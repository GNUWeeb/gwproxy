#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# "-j DNAT --to :port" on a hostname handed to a remote-DNS upstream: there is
# no address to keep or to rewrite, but the rule still rewrites the port. The
# upstream must be asked for the hostname on the new port. The rule used to be
# dropped, while its match still accepted the request past any later REJECT,
# which is the worst of both.

. "$(dirname "$0")/lib.sh"
require python3

acl="$WORK/acl"
cat >"$acl" <<-'ACL'
-P OUTPUT REJECT
-A OUTPUT --dports 80 -j DNAT --to :4444
-A OUTPUT -m domain --domain md.example -j DNAT --to :5555
-A OUTPUT --dports 81 -j REJECT
-A OUTPUT --dports 82 -j ACCEPT
ACL

# ask <port> <socks5|http> <host> <dport>: the reply code to a request for
# <host>:<dport> by name, or for an address when <host> is an IPv4 literal.
ask()
{
	python3 - "$@" <<-'PY'
	import socket, struct, sys
	port, front, host, dport = int(sys.argv[1]), sys.argv[2], sys.argv[3], int(sys.argv[4])
	c = socket.create_connection(("127.0.0.1", port))
	c.settimeout(60)
	if front == "socks5":
	    c.sendall(b"\x05\x01\x00")
	    c.recv(2)
	    try:
	        a = b"\x01" + socket.inet_aton(host)
	    except OSError:
	        a = b"\x03" + bytes([len(host)]) + host.encode()
	    c.sendall(b"\x05\x01\x00" + a + struct.pack("!H", dport))
	    r = c.recv(10)
	    print("%02x" % r[1] if len(r) > 1 else "CLOSED")
	else:
	    c.sendall(b"CONNECT %s:%d HTTP/1.1\r\nHost: x\r\n\r\n" % (host.encode(), dport))
	    r = c.recv(100)
	    print(r.split()[1].decode() if r else "CLOSED")
	PY
}

# upstream_saw: the destination of the one request in the upstream's log, as
# "host port", or "none".
upstream_saw()
{
	python3 - "$1" <<-'PY'
	import re, sys
	lines = open(sys.argv[1]).read().splitlines()
	if not lines:
	    print("none")
	else:
	    m = re.search(r"addr=(\S+) port=(\d+)", lines[-1])
	    if m:
	        print(m.group(1), m.group(2))
	    else:
	        print(*re.search(r"authority=(\S+):(\d+)", lines[-1]).groups())
	PY
}

# run_case <label> <port> <socks5|http> <host> <dport> <reply> <saw>
run_case()
{
	local label="$1" pp="$2" front="$3" host="$4" dport="$5" want="$6" saw="$7" got seen

	: >"$rlog"
	got="$(ask "$pp" "$front" "$host" "$dport")"
	# A refused request never reaches the upstream, so there is nothing to
	# wait for. An accepted one is logged before the upstream answers.
	seen="$(upstream_saw "$rlog")"
	diag "$label: reply $got, upstream asked for: $seen"
	[ "$got" = "$want" ] || fail "$label: expected reply $want, got $got"
	[ "$seen" = "$saw" ] || fail "$label: expected the upstream to see '$saw', got '$seen'"
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	for scheme in socks5h http; do
		kind=socks5
		[ "$scheme" = http ] && kind=http
		rlog="$WORK/up.$loop.$scheme.log"
		: >"$rlog"
		up="$(pick_port)"
		python3 "$SERVERS_DIR/stub_upstream.py" "$kind" "$up" "$rlog" \
			>"$WORK/up.err" 2>&1 &
		up_pid=$!
		_PIDS+=("$up_pid")
		wait_listen "$up" "$up_pid" || fail "stub upstream did not listen"

		pp="$(pick_port)"
		gwp_start "127.0.0.1:$pp" --as-socks5=1 --as-http=1 --nr-workers=1 \
			--event-loop="$loop" --acl-file="$acl" \
			--upstream-proxy="$scheme://127.0.0.1:$up"
		tag="[$loop] $scheme"

		run_case "$tag SOCKS5 name, port-only DNAT" "$pp" socks5 \
			foo.example 80 00 "foo.example 4444"
		run_case "$tag HTTP name, port-only DNAT" "$pp" http \
			foo.example 80 200 "foo.example 4444"
		run_case "$tag name, -m domain port-only DNAT" "$pp" socks5 \
			md.example 8080 00 "md.example 5555"

		# Rules that do not match leave the name and port alone, and the
		# REJECT behind them still holds.
		run_case "$tag name, accepted on its own port" "$pp" socks5 \
			foo.example 82 00 "foo.example 82"
		run_case "$tag name, rejected by rule" "$pp" socks5 \
			foo.example 81 02 none
		run_case "$tag name, rejected by policy" "$pp" socks5 \
			foo.example 83 02 none

		# An address keeps working as it did: it has a base for the port.
		run_case "$tag literal, port-only DNAT" "$pp" socks5 \
			192.0.2.9 80 00 "192.0.2.9 4444"
		kill "$GWP_PID" 2>/dev/null
		wait "$GWP_PID" 2>/dev/null

		# Plain forwarding to a --target the upstream resolves goes the same
		# way, and a second connection is judged as the first was.
		pp="$(pick_port)"
		gwp_start "127.0.0.1:$pp" --target=foo.example:80 --nr-workers=1 \
			--event-loop="$loop" --acl-file="$acl" \
			--upstream-proxy="$scheme://127.0.0.1:$up"
		for n in 1 2; do
			: >"$rlog"
			python3 - "$pp" <<-'PY' || fail "$tag plain forwarding $n: no tunnel"
			import socket, sys
			c = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
			c.settimeout(60)
			sys.exit(0 if c.recv(64).startswith(b"UPSTREAM-TUNNEL") else 1)
			PY
			seen="$(upstream_saw "$rlog")"
			diag "$tag plain forwarding $n: upstream asked for: $seen"
			[ "$seen" = "foo.example 4444" ] || \
				fail "$tag plain forwarding $n: upstream saw '$seen'"
		done
		kill "$GWP_PID" 2>/dev/null
		wait "$GWP_PID" 2>/dev/null
		kill "$up_pid" 2>/dev/null
		wait "$up_pid" 2>/dev/null
	done
done

pass
