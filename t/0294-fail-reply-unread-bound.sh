#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The epoll loop keeps a pair whose failure reply the client's socket could
# not take in one go, until the client has read it (t/0293). That wait is
# bounded: a client that never reads must not keep the pair or its sockets.
# With --protocol-timeout=0 and --idle-timeout=0, so that no timer of the
# pair's own bounds it, the proxy must be back to the descriptors it had
# before the client came within the hold's 5 s, the 2 s it may linger on
# the socket after it, and room to spare, while the client still reads
# nothing; the client then finds the connection closed without the reply.
# Several clients at once, so that their holds overlap.

. "$(dirname "$0")/lib.sh"
require python3
require openssl
require_opt --tls-cert

NR_CLIENTS=4

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 \
	-subj '/CN=localhost' >/dev/null 2>&1 \
	|| skip "openssl could not generate a test certificate"
printf 'user:pass\n' >"$WORK/auth"

nr_fds()
{
	ls "/proc/$1/fd" 2>/dev/null | wc -l
}

pp="$(pick_port)"
gwp_start "127.0.0.1:$pp" --event-loop=epoll --nr-workers=1 --as-http=1 \
	--tls-cert="$WORK/cert.pem" --tls-key="$WORK/key.pem" \
	--auth-file="$WORK/auth" --protocol-timeout=0 --idle-timeout=0
base="$(nr_fds "$GWP_PID")"
[ "$base" -gt 0 ] || fail "cannot count the proxy's descriptors"

# Unread for 25 s: longer than the wait for the descriptors below.
declare -a cl=()
for i in $(seq 1 "$NR_CLIENTS"); do
	timeout 150 python3 "$SERVERS_DIR/tls_fail_reply_unread.py" "$pp" \
		127.0.0.1:9 - 25 >"$WORK/c.$i" 2>&1 &
	cl+=("$!")
	_PIDS+=("$!")
done

for i in $(seq 1 "$NR_CLIENTS"); do
	timeout 100 bash -c "until grep -qs '^SENT' '$WORK/c.$i'; do
		kill -0 ${cl[$((i - 1))]} 2>/dev/null || exit 1; sleep 0.1; done" \
		|| fail "client $i did not get its request out: $(cat "$WORK/c.$i")"
done

# 5 s of hold and 2 s of lingering, plus a scheduler's worth of slack.
t0="$(date +%s)"
until [ "$(nr_fds "$GWP_PID")" -le "$base" ]; do
	[ $(($(date +%s) - t0)) -le 20 ] ||
		fail "the proxy still has $(nr_fds "$GWP_PID") descriptors, $base before the clients, $(($(date +%s) - t0)) s after their requests"
	kill -0 "$GWP_PID" 2>/dev/null || fail "gwproxy died"
	sleep 0.2
done
diag "descriptors back to $base after $(($(date +%s) - t0)) s"

for i in $(seq 1 "$NR_CLIENTS"); do
	rc=0
	wait "${cl[$((i - 1))]}" || rc=$?
	out="$(cat "$WORK/c.$i")"
	[ "$rc" = 77 ] && skip "$out"
	[ "$out" = "SENT
ok" ] || fail "client $i: rc=$rc $out"
done

pass
