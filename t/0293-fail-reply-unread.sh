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
# On io_uring the same client was not read while the engine's answers were
# being sent to it, and as it does not read before its request is out, the
# request never came in: the pair sat until the protocol timeout, and the
# client got no reply at all; and it did not keep the pair for a refusal,
# whose 407 then went with the teardown. Both loops, but io_uring does not
# hold the pair while connect attempts are in flight: not the 504 there.

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

# check <loop> <status> <target> <wait> [proxy args...]
check()
{
	local loop="$1" st="$2" tgt="$3" wait="$4" pp out rc
	shift 4

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --event-loop="$loop" --nr-workers=1 \
		--as-http=1 --tls-cert="$WORK/cert.pem" \
		--tls-key="$WORK/key.pem" "$@"
	out="$(timeout 150 python3 "$SERVERS_DIR/tls_fail_reply_unread.py" \
		"$pp" "$tgt" "$st" "$wait" 2>&1)"
	rc=$?
	[ "$rc" = 77 ] && skip "$out"
	[ "$out" = ok ] || fail "[$loop $st] rc=$rc $out"
	gwp_stop_pids "$GWP_PID"
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	check "$loop" 407 "127.0.0.1:$CLOSED_PORT" 1 --auth-file="$WORK/auth"
	check "$loop" 502 "127.0.0.1:$CLOSED_PORT" 1
	[ "$loop" = io_uring ] && continue
	check "$loop" 504 "127.0.0.1:$tport" 2.5 --connect-timeout=1
done

pass
