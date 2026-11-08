#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# --outgoing-family: restrict outgoing (target) connections to one address
# family. Two halves have to hold, and they fail in different ways, so both are
# asserted separately:
#
#   * a literal target of the forbidden family is refused before any socket is
#     made -- SOCKS5 REP 0x08 ("address type not supported"), HTTP 502;
#   * a hostname resolves to the allowed family only, so a name with both A and
#     AAAA still connects rather than being refused.
#
# Through an upstream proxy, what counts is the destination named to it as well
# as the hop to it; a hostname the upstream resolves is the one exception.
#
# Every case here pins the family explicitly and asserts against a *pair* of
# runs where that is the only difference, because "the connection worked" on a
# dual-stack loopback proves nothing on its own.

. "$(dirname "$0")/lib.sh"
require curl
require python3
require_opt --outgoing-family

have_v6=0
python3 -c 'import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.bind(("::1", 0)); s.close()' 2>/dev/null && have_v6=1

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 4096
start_httpd "$hp" "$WORK" "1.1"

# Read the SOCKS5 CONNECT reply code for a literal target through the proxy.
socks5_rep() {			# $1=proxy_port $2=dst_ip $3=dst_port
	python3 - "$@" <<-'PY'
	import socket, struct, sys
	pp, ip, dp = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
	fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
	atyp = b'\x04' if fam == socket.AF_INET6 else b'\x01'
	t = socket.create_connection(('127.0.0.1', pp)); t.settimeout(10)
	t.sendall(b'\x05\x01\x00'); assert t.recv(2) == b'\x05\x00'
	t.sendall(b'\x05\x01\x00' + atyp + socket.inet_pton(fam, ip) +
		  struct.pack('!H', dp))
	print("0x%02x" % t.recv(10)[1])
	PY
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	# An IPv4 target is unaffected by --outgoing-family=ipv4: the pair below
	# is what makes the refusal cases mean something.
	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --event-loop="$loop" \
		--outgoing-family=ipv4
	rep="$(socks5_rep "$p" 127.0.0.1 "$hp")"
	[ "$rep" = 0x00 ] \
		|| fail "[$loop] ipv4 target under --outgoing-family=ipv4 got $rep (want 0x00)"
	curl -s --max-time 20 -x "socks5://127.0.0.1:$p" \
		"http://127.0.0.1:$hp/payload.bin" -o "$WORK/o4.bin" \
		|| fail "[$loop] ipv4 transfer under --outgoing-family=ipv4 failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/o4.bin" \
		"[$loop] --outgoing-family=ipv4 corrupted an ipv4 transfer"
	kill "$GWP_PID" 2>/dev/null

	# ...and the same literal, same proxy settings but family=ipv6, is
	# refused with 0x08 rather than being attempted.
	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --event-loop="$loop" \
		--outgoing-family=ipv6
	rep="$(socks5_rep "$p" 127.0.0.1 "$hp")"
	kill "$GWP_PID" 2>/dev/null
	[ "$rep" = 0x08 ] \
		|| fail "[$loop] ipv4 target under --outgoing-family=ipv6 got $rep (want 0x08)"

	if [ "$have_v6" = 1 ]; then
		# The mirror image: an IPv6 literal is refused under ipv4.
		p="$(pick_port)"
		gwp_start "127.0.0.1:$p" --as-socks5=1 --event-loop="$loop" \
			--outgoing-family=ipv4
		rep="$(socks5_rep "$p" ::1 "$hp")"
		kill "$GWP_PID" 2>/dev/null
		[ "$rep" = 0x08 ] \
			|| fail "[$loop] ipv6 target under --outgoing-family=ipv4 got $rep (want 0x08)"
	fi

	# A hostname that has both A and AAAA must still connect under ipv4:
	# resolution is restricted, not the whole request. "localhost" is the
	# one name guaranteed to exist here; skip if it has no A record.
	if python3 -c 'import socket,sys
sys.exit(0 if socket.getaddrinfo("localhost", None, socket.AF_INET) else 1)' 2>/dev/null; then
		p="$(pick_port)"
		gwp_start "127.0.0.1:$p" --as-socks5=1 --event-loop="$loop" \
			--outgoing-family=ipv4
		curl -s --max-time 20 -x "socks5h://127.0.0.1:$p" \
			"http://localhost:$hp/payload.bin" -o "$WORK/oh.bin" \
			|| fail "[$loop] hostname under --outgoing-family=ipv4 failed"
		assert_files_equal "$WORK/payload.bin" "$WORK/oh.bin" \
			"[$loop] hostname transfer under --outgoing-family=ipv4 corrupted"
		kill "$GWP_PID" 2>/dev/null
	fi

	# HTTP gets 502, not the ACL's 403: this is a configuration refusal,
	# not a policy denial, and the distinction matters when debugging.
	if [ "$have_v6" = 1 ]; then
		p="$(pick_port)"
		gwp_start "127.0.0.1:$p" --as-http=1 --event-loop="$loop" \
			--outgoing-family=ipv4
		code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 \
			-x "http://127.0.0.1:$p" "http://[::1]:$hp/payload.bin")"
		kill "$GWP_PID" 2>/dev/null
		[ "$code" = 502 ] \
			|| fail "[$loop] HTTP ipv6 target under ipv4 got $code (want 502)"
	fi
done

# Chaining: the destination named to an upstream is an outgoing target too. An
# address of the wrong family is refused before anything is dialled, whether a
# client asked for it or a DNAT made it, and only a hostname the upstream is to
# resolve is beyond the restriction. The stub upstream never connects anywhere,
# so none of this needs IPv6 on the host.
chain_acl="$WORK/chain.acl"
cat >"$chain_acl" <<-'ACL'
-P OUTPUT ACCEPT
-A OUTPUT -d 192.0.2.41/32 -j DNAT --to [2001:db8::1]:80
-A OUTPUT -m domain --domain dnat6.example -j DNAT --to [2001:db8::1]:80
-A OUTPUT -m domain --domain dnat4.example -j DNAT --to 192.0.2.9:80
ACL

# chain_cases <label> <proxy_port> <log> <case>...: run the cases in turn, each
# "<socks5|http>,<host>,<reply>,<requests>": the SOCKS5 REP or HTTP status for a
# CONNECT to <host> port 80, and how many requests the upstream must have seen
# by then. Exits non-zero at the first that is wrong.
chain_cases() {
	python3 - "$@" <<-'PY'
	import socket, sys
	label, pp, rlog = sys.argv[1], int(sys.argv[2]), sys.argv[3]
	def ask(front, host):
	    t = socket.create_connection(('127.0.0.1', pp)); t.settimeout(60)
	    if front == "http":
	        h = "[%s]" % host if ":" in host else host
	        t.sendall(b"CONNECT %s:80 HTTP/1.1\r\nHost: x\r\n\r\n" % h.encode())
	        r = t.recv(100)
	        return r.split()[1].decode() if r else "CLOSED"
	    t.sendall(b'\x05\x01\x00'); assert t.recv(2) == b'\x05\x00'
	    if ":" in host:
	        a = b'\x04' + socket.inet_pton(socket.AF_INET6, host)
	    else:
	        try:
	            a = b'\x01' + socket.inet_aton(host)
	        except OSError:
	            a = b'\x03' + bytes([len(host)]) + host.encode()
	    t.sendall(b'\x05\x01\x00' + a + b'\x00\x50')
	    r = t.recv(4)
	    return "0x%02x" % r[1] if len(r) > 1 else "CLOSED"
	for case in sys.argv[4:]:
	    front, host, want, nreq = case.split(",")
	    open(rlog, "w").close()
	    got = ask(front, host)
	    seen = len(open(rlog).readlines())
	    print("# %s, %s %s: reply %s, %d upstream requests" % (label, front, host, got, seen), file=sys.stderr)
	    if got != want or seen != int(nreq):
	        print("FAIL: %s, %s %s: reply %s (want %s), %d upstream requests (want %s)" % (label, front, host, got, want, seen, nreq))
	        sys.exit(1)
	PY
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	for scheme in socks5 socks5h http; do
		kind=socks5
		[ "$scheme" = http ] && kind=http
		rlog="$WORK/chain.$loop.$scheme.log"
		: >"$rlog"
		up="$(pick_port)"
		python3 "$SERVERS_DIR/stub_upstream.py" "$kind" "$up" "$rlog" \
			>"$WORK/chain.err" 2>&1 &
		up_pid=$!
		_PIDS+=("$up_pid")
		wait_listen "$up" "$up_pid" || fail "stub upstream did not listen"

		p="$(pick_port)"
		gwp_start "127.0.0.1:$p" --as-socks5=1 --as-http=1 --nr-workers=1 \
			--event-loop="$loop" --outgoing-family=ipv4 \
			--acl-file="$chain_acl" \
			--upstream-proxy="$scheme://127.0.0.1:$up"

		cases=(socks5,2001:db8::1,0x08,0 http,2001:db8::1,502,0
		       socks5,192.0.2.41,0x08,0 http,192.0.2.41,502,0
		       socks5,192.0.2.9,0x00,1 socks5,::ffff:192.0.2.9,0x00,1)
		# A name is resolved locally for socks5://, and tests resolve none.
		[ "$scheme" = socks5 ] || \
			cases+=(socks5,plain.example,0x00,1
				socks5,dnat6.example,0x08,0
				socks5,dnat4.example,0x00,1)
		chain_cases "[$loop] $scheme upstream" "$p" "$rlog" "${cases[@]}" \
			|| fail "[$loop] $scheme upstream: a destination was not judged right"
		kill "$GWP_PID" 2>/dev/null
		wait "$GWP_PID" 2>/dev/null

		# Plain forwarding has no reply to give: the client is closed, and
		# the upstream is not bothered.
		if [ "$scheme" = socks5h ]; then
			p="$(pick_port)"
			gwp_start "127.0.0.1:$p" --target='[2001:db8::1]:80' --nr-workers=1 \
				--event-loop="$loop" --outgoing-family=ipv4 --acl-allow-all \
				--upstream-proxy="$scheme://127.0.0.1:$up"
			: >"$rlog"
			got="$(python3 - "$p" <<-'PY'
			import socket, sys
			c = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
			c.settimeout(60)
			try:
			    print(c.recv(64).hex() or "-")
			except ConnectionResetError:
			    print("-")
			PY
			)"
			[ "$got" = - ] || fail "[$loop] plain ipv6 target: client got $got"
			[ ! -s "$rlog" ] || fail "[$loop] plain ipv6 target: reached the upstream"
			kill "$GWP_PID" 2>/dev/null
			wait "$GWP_PID" 2>/dev/null
		fi

		kill "$up_pid" 2>/dev/null
		wait "$up_pid" 2>/dev/null
	done
done

# Contradictory configurations are refused at startup rather than failing on
# every connection. timeout's 124 means it started and kept running.
reject() {			# $1=description, rest=args
	local desc="$1" p rc=0
	shift
	p="$(pick_port)"
	timeout --foreground 10 "$GWPROXY" --bind="127.0.0.1:$p" --as-socks5=1 \
		--acl-allow-all --nr-workers=1 "$@" >"$WORK/rej.log" 2>&1 || rc=$?
	case "$rc" in
	0)	fail "gwproxy exited 0 with $desc" ;;
	124)	fail "gwproxy started and kept running with $desc" ;;
	esac
}

reject "a bogus family"		--outgoing-family=bogus
reject "ipv4 with --prefer-ipv6" --outgoing-family=ipv4 --prefer-ipv6=1
reject "ipv4 with an ipv6 --bind-source" \
	--outgoing-family=ipv4 --bind-source='[::1]'
reject "ipv4 with an ipv6 upstream" \
	--outgoing-family=ipv4 --upstream-proxy='socks5://[::1]:1080'

pass
