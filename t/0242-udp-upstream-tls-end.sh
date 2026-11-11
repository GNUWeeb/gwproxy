#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A UDP association that a pool's socks5h:// server carries ends when the
# server closes its control connection, for a TLS client too. On io_uring
# the watch on the server's control connection was armed only from the
# completion of the client's reply send, and a TLS client's completion went
# back to the protocol pass instead: the association lived on, its client
# was not told, and its datagrams went to a relay that was gone.
#
# The stand-in server (t/servers/socks5_udp_upstream.py) closes its control
# connection on a datagram ending in "bye"; the client must then see its own
# control connection end. Plaintext and TLS clients, on every event loop.

. "$(dirname "$0")/lib.sh"
require python3
require openssl
require_opt --acl-file
require_opt --tls-cert

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 \
	-subj '/CN=localhost' >/dev/null 2>&1 \
	|| skip "openssl could not generate a test certificate"

: >"$WORK/up.log"
python3 "$SERVERS_DIR/socks5_udp_upstream.py" "$WORK/up.log" \
	>"$WORK/up.out" 2>&1 &
_PIDS+=("$!")
for i in $(seq 1 100); do
	up="$(sed -n 's/^READY \([0-9][0-9]*\)$/\1/p' "$WORK/up.out")"
	[ -n "$up" ] && break
	sleep 0.05
done
[ -n "$up" ] || fail "the stand-in upstream did not start"

cat >"$WORK/pool.acl" <<EOF
upstream p {
	server socks5h://127.0.0.1:$up;
}
-A OUTPUT -j UPSTREAM --to p
-P OUTPUT ACCEPT
EOF
chmod 600 "$WORK/pool.acl"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1 --log-level=4 --acl-file="$WORK/pool.acl" \
		--tls-cert="$WORK/cert.pem" --tls-key="$WORK/key.pem"
	for tls in "" --tls; do
		out="$(timeout 60 python3 "$SERVERS_DIR/socks5_udp_script.py" \
			$tls "$pp" send:127.0.0.1:9:hi send:127.0.0.1:9:bye eof)"
		want="REP 0
ECHO hi
NONE
EOF"
		if [ "$out" != "$want" ]; then
			sed 's/^/# gwp: /' "$WORK/gwp.$pp.log" | tail -n 40 >&2
			fail "[$loop ${tls:-plain}] got '$(echo $out)', want '$(echo $want)'"
		fi
	done
	gwp_stop_pids "$GWP_PID"
done

pass
