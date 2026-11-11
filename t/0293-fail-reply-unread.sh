#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A failure reply that the client's socket cannot take in one go must still
# reach the client whole, close_notify and all, once it reads. A TLS client
# asks for KeyUpdates without reading the answers, more of them than its
# socket can take, and sends a request the proxy refuses along with them
# (t/servers/tls_fail_reply_unread.py): the reply then waits behind the
# answers. The epoll loop sent what fitted and tore the pair down, so the
# client got the answers and then a connection cut short. Refused with 407,
# for a target that refuses the connect (502), and for one that never
# answers (504, from the connect timeout).
#
# epoll only: on io_uring this client is not read on while a send to it is
# in flight, and the reply then only comes once the client reads, so the
# case does not arise in the same way.

. "$(dirname "$0")/lib.sh"
require python3
require openssl
require_opt --tls-cert

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 \
	-subj '/CN=localhost' >/dev/null 2>&1 \
	|| skip "openssl could not generate a test certificate"
printf 'user:pass\n' >"$WORK/auth"

python3 "$SERVERS_DIR/blackhole_listener.py" 127.0.0.1 >"$WORK/bh.port" \
	2>"$WORK/bh.log" &
_PIDS+=("$!")
for i in $(seq 1 50); do
	tport="$(cat "$WORK/bh.port" 2>/dev/null)"
	[ -n "$tport" ] && break
	sleep 0.1
done
[ -n "${tport:-}" ] || fail "blackhole listener did not report its port"
closed_port

# check <status> <target> <wait> [proxy args...]
check()
{
	local st="$1" tgt="$2" wait="$3" pp out rc
	shift 3

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --event-loop=epoll --nr-workers=1 \
		--as-http=1 --tls-cert="$WORK/cert.pem" \
		--tls-key="$WORK/key.pem" "$@"
	out="$(timeout 150 python3 "$SERVERS_DIR/tls_fail_reply_unread.py" \
		"$pp" "$tgt" "$st" "$wait" 2>&1)"
	rc=$?
	[ "$rc" = 77 ] && skip "$out"
	[ "$out" = ok ] || fail "[$st] rc=$rc $out"
	gwp_stop_pids "$GWP_PID"
}

check 407 "127.0.0.1:$CLOSED_PORT" 1 --auth-file="$WORK/auth"
check 502 "127.0.0.1:$CLOSED_PORT" 1
check 504 "127.0.0.1:$tport" 2.5 --connect-timeout=1

pass
