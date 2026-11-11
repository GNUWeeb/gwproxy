#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A SOCKS5 client that sends its greeting and its CONNECT in one write, for
# a name in the negative DNS cache, must get the method reply, REP 0x04 and a
# close. The cached failure comes back through the worker's DNS completion
# queue at once, before the send of the method reply has completed; the
# io_uring loop appended the REP behind that send and tore the pair down,
# dropping the send's completion, so the client got "05 00" and EOF. Also
# over TLS, and with --connect-timeout=0 --protocol-timeout=0, where no timer
# of the pair's own bounds the wait for the reply. Both loops.
#
# The name fails to resolve on a DNS server of our own, so the body runs in
# a private user+mount+net namespace with its own resolv.conf, as t/0125
# does; no name leaves it.

. "$(dirname "$0")/lib.sh"
require python3
require unshare
require ip

if [ "${1:-}" != "--inner" ]; then
	ns_drop_setup
	$NS_DROP unshare -rmn --map-root-user true 2>/dev/null \
		|| skip "no user+mount+net namespaces (unshare -rmn) available"
	out="$WORK/inner.out"
	setsid $NS_DROP unshare -rmn --map-root-user "$0" --inner "$WORK" \
		</dev/null >"$out" 2>&1 &
	for i in $(seq 1 150); do
		grep -q '^INNER-DONE' "$out" 2>/dev/null && break
		sleep 1
	done
	sed 's/^/# /' "$out" >&2
	grep -q '^INNER-DONE rc=77' "$out" && skip "see the inner run above"
	grep -q '^INNER-DONE rc=0' "$out" || fail "inner run failed (see above)"
	pass
fi

# ---------------------------------------------------------------- inner ----
ns_inner_work "$2"
GWPROXY="${GWPROXY:-$ROOT/gwproxy}"
rc=1

cleanup_inner()
{
	echo "INNER-DONE rc=$rc"
	_release_ports
	kill 0 2>/dev/null
}
trap cleanup_inner EXIT

ip link set lo up || exit 1

printf 'nameserver 127.0.0.1\noptions timeout:5 attempts:1\n' >"$WORK/resolv.conf"
mount --bind "$WORK/resolv.conf" /etc/resolv.conf || { rc=77; exit 0; }
if [ -e /etc/nsswitch.conf ]; then
	printf 'hosts: files dns\n' >"$WORK/nsswitch.conf"
	mount --bind "$WORK/nsswitch.conf" /etc/nsswitch.conf || exit 1
fi

# dns_hold.py answers a "holdnx" name with NXDOMAIN once the release file
# exists: here, at once.
: >"$WORK/release"
python3 "$SERVERS_DIR/dns_hold.py" 53 "$WORK/names" "$WORK/release" \
	>"$WORK/dns.log" 2>&1 &
for i in $(seq 1 100); do
	grep -q READY "$WORK/dns.log" 2>/dev/null && break
	sleep 0.05
done
grep -q READY "$WORK/dns.log" || { echo "DNS server did not start"; exit 1; }

tlsargs=()
clients=(plain)
if "$GWPROXY" --help 2>&1 | grep -q -- '--tls-cert' && \
   command -v openssl >/dev/null 2>&1 &&
   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
	-nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 \
	-subj '/CN=localhost' >/dev/null 2>&1; then
	tlsargs=(--tls-cert="$WORK/cert.pem" --tls-key="$WORK/key.pem")
	clients+=(tls)
else
	echo "no TLS listener or no openssl: leaving the TLS cases out"
fi

NAME=holdnx-negative.cache.test
WANT="050005040001000000000000 EOF"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	for timeouts in "" "--connect-timeout=0 --protocol-timeout=0"; do
		p="$(pick_port)"
		# shellcheck disable=SC2086
		gwp_start "127.0.0.1:$p" --as-socks5=1 --event-loop="$loop" \
			--nr-workers=1 --dns-cache-secs=60 "${tlsargs[@]}" \
			$timeouts

		# Into the negative cache: a client that waits for each reply.
		got="$(timeout 30 python3 - "$p" "$NAME" <<-'PY'
		import socket, sys
		s = socket.create_connection(("127.0.0.1", int(sys.argv[1])),
					     timeout=20)
		name = sys.argv[2].encode()
		s.sendall(b"\x05\x01\x00")
		m = s.recv(2)
		s.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name +
			  b"\x00\x50")
		print((m + s.recv(10)).hex())
		PY
		)"
		if [ "$got" != "050005040001000000000000" ]; then
			sed 's/^/# gwp: /' "$WORK/gwp.$p.log"
			echo "[$loop $timeouts] priming the cache: got '$got'"
			exit 1
		fi

		for c in "${clients[@]}"; do
			ca=()
			[ "$c" = tls ] && ca=(--tls)
			for i in 1 2 3; do
				got="$(timeout 30 python3 \
					"$SERVERS_DIR/socks5_pipelined_reply.py" \
					"$p" 3 "$NAME" 80 "${ca[@]}")"
				[ "$got" = "$WANT" ] && continue
				sed 's/^/# gwp: /' "$WORK/gwp.$p.log"
				echo "[$loop/$c $timeouts] got '$got', want '$WANT'"
				exit 1
			done
		done
		echo "[$loop $timeouts] ok"
		kill "$GWP_PID" 2>/dev/null
		wait "$GWP_PID" 2>/dev/null
	done
done
rc=0
