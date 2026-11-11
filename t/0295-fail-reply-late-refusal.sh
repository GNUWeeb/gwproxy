#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A pair held for its failure reply (t/0293) is held for the whole bound,
# whatever its own timer was armed for: a connect that fails just before
# the connect timeout runs out must not have its 502 cut short by that
# timeout. The io_uring loop kept the pair's timer when it was due sooner
# than the hold's 5 s, so the 502 behind a TLS client's unread KeyUpdate
# answers went with the teardown a second later, before the client read
# it. The connect is refused about a second after it began (the SYN is
# left unanswered once, t/servers/refuse_on_syn_retry.py), with
# --connect-timeout=2, and the client reads only after 3 s. Both loops.

. "$(dirname "$0")/lib.sh"
require python3
require openssl
require_opt --tls-cert

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 \
	-subj '/CN=localhost' >/dev/null 2>&1 \
	|| skip "openssl could not generate a test certificate"

# check <loop>
check()
{
	local loop="$1" pp tport rpid out rc i

	python3 "$SERVERS_DIR/refuse_on_syn_retry.py" 127.0.0.1 \
		>"$WORK/rf.$loop" 2>&1 &
	rpid=$!
	_PIDS+=("$rpid")
	for i in $(seq 1 50); do
		tport="$(head -n 1 "$WORK/rf.$loop" 2>/dev/null)"
		[ -n "$tport" ] && break
		sleep 0.1
	done
	[ -n "${tport:-}" ] || fail "the target did not report its port"

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --event-loop="$loop" --nr-workers=1 \
		--as-http=1 --tls-cert="$WORK/cert.pem" \
		--tls-key="$WORK/key.pem" --connect-timeout=2
	out="$(timeout 150 python3 "$SERVERS_DIR/tls_fail_reply_unread.py" \
		"$pp" "127.0.0.1:$tport" 502 3 2>&1)"
	rc=$?
	[ "$rc" = 77 ] && skip "$out"
	# The SYN went unanswered for 2 s: the timeout's 504, not the case.
	case "$out" in
	*"got b'HTTP/1.1 504 "*)
		skip "[$loop] the connect was not refused before its timeout" ;;
	esac
	grep -qx CLOSED "$WORK/rf.$loop" ||
		fail "[$loop] the target saw no connect: $(cat "$WORK/rf.$loop")"
	[ "$out" = ok ] || fail "[$loop] rc=$rc $out"
	gwp_stop_pids "$GWP_PID" "$rpid"
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue
	check "$loop"
done

pass
