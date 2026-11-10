#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A SOCKS5 client that sends its greeting (and its RFC 1929 credentials) and
# its CONNECT in one write, for a request the proxy refuses at once, must get
# the whole answer: the method reply, the authentication status, then the
# REP of the refusal, and a close. The io_uring loop queued the send of the
# method reply before it acted on the request, and the refusal's REP, added
# while that send was in flight, was dropped with the pair: the client got
# "05 00" and EOF. The refusals tried: the default ACL with a loopback target,
# given as an address and as a name that is an IP literal (REP 0x02),
# --outgoing-family=ipv6 with an IPv4 target (0x08) and a --bind-source the
# host does not have (0x01); in the clear and over TLS. Both loops.

. "$(dirname "$0")/lib.sh"
require python3

tls=0
if "$GWPROXY" --help 2>&1 | grep -q -- '--tls-cert' && \
   command -v openssl >/dev/null 2>&1 &&
   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
	-nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 \
	-subj '/CN=localhost' >/dev/null 2>&1; then
	tls=1
else
	diag "no TLS listener or no openssl: leaving the TLS cases out"
fi
printf 'pipe:lined\n' >"$WORK/auth"

# A target nothing listens on: every request here is refused before it is
# dialled, and one that was not must not reach anything.
closed_port
dp="$CLOSED_PORT"

REP_ZERO="0001000000000000"
METHOD="0500"
AUTH_METHOD="05020100"

# Start a proxy with no ACL argument: gwp_start would add --acl-allow-all.
start_default_acl()			# $1=port, rest: gwproxy args
{
	local port="$1"; shift

	"$GWPROXY" --bind="127.0.0.1:$port" --log-level=3 "$@" \
		>"$WORK/gwp.$port.log" 2>&1 &
	GWP_PID=$!
	_PIDS+=("$GWP_PID")
	if ! wait_listen "$port" "$GWP_PID"; then
		sed 's/^/# gwp: /' "$WORK/gwp.$port.log" >&2
		fail "gwproxy did not listen on $port"
	fi
}

# check <label> <port> <expected hex> <client args...>
check()
{
	local label="$1" port="$2" want="$3" got
	shift 3

	got="$(timeout 30 python3 "$SERVERS_DIR/socks5_pipelined_reply.py" \
		"$port" "$@")"
	if [ "$got" != "$want EOF" ]; then
		sed 's/^/# gwp: /' "$WORK/gwp.$port.log" >&2
		fail "$label: got '$got', want '$want EOF'"
	fi
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	tlsargs=()
	clients=(plain)
	if [ "$tls" = 1 ]; then
		tlsargs=(--tls-cert="$WORK/cert.pem" --tls-key="$WORK/key.pem")
		clients+=(tls)
	fi

	# The default ACL refuses loopback targets: REP 0x02.
	p="$(pick_port)"
	start_default_acl "$p" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1 "${tlsargs[@]}"
	pa="$(pick_port)"
	start_default_acl "$pa" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1 --auth-file="$WORK/auth" "${tlsargs[@]}"
	for c in "${clients[@]}"; do
		ca=()
		[ "$c" = tls ] && ca=(--tls)
		for i in 1 2 3; do
			check "[$loop/$c] ACL, IPv4 address" "$p" \
				"${METHOD}0502$REP_ZERO" 1 127.0.0.1 "$dp" "${ca[@]}"
			check "[$loop/$c] ACL, IP literal as a name" "$p" \
				"${METHOD}0502$REP_ZERO" 3 127.0.0.1 "$dp" "${ca[@]}"
			check "[$loop/$c] ACL, with credentials" "$pa" \
				"${AUTH_METHOD}0502$REP_ZERO" 1 127.0.0.1 "$dp" \
				--user pipe --pass lined "${ca[@]}"
		done
	done

	# --outgoing-family=ipv6 and an IPv4 target: REP 0x08.
	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1 --outgoing-family=ipv6 "${tlsargs[@]}"
	for c in "${clients[@]}"; do
		ca=()
		[ "$c" = tls ] && ca=(--tls)
		check "[$loop/$c] --outgoing-family" "$p" \
			"${METHOD}0508$REP_ZERO" 1 127.0.0.1 "$dp" "${ca[@]}"
	done

	# A source address the host does not have: the bind fails, REP 0x01.
	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1 --bind-source=192.0.2.1 "${tlsargs[@]}"
	for c in "${clients[@]}"; do
		ca=()
		[ "$c" = tls ] && ca=(--tls)
		check "[$loop/$c] --bind-source" "$p" \
			"${METHOD}0501$REP_ZERO" 1 127.0.0.1 "$dp" "${ca[@]}"
	done
done

pass
