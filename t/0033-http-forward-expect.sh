#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Forwarding HTTP proxy + "Expect: 100-continue" (RFC 9110 Section 10.1.1).
# The proxy forwards the expectation to the origin, so:
#   (a) an authenticated POST is forwarded and its body is relayed (the origin
#       drives the 100 Continue), and
#   (b) a POST that fails proxy authentication is rejected with 407 *before* the
#       origin is contacted, so the body is never sent upstream (no wasted
#       round-trip). The origin logs one line per request it receives, so the
#       test can confirm a rejected request left nothing behind.

. "$(dirname "$0")/lib.sh"
require curl
require python3

op="$(pick_port)"
olog="$WORK/origin.log"
: >"$olog"
python3 "$SERVERS_DIR/expect_origin.py" "$op" "$olog" >"$WORK/origin.out" 2>&1 &
opid=$!
_PIDS+=("$opid")
wait_listen "$op" "$opid" || fail "Expect origin did not start on port $op"

printf 'user:pass\n' >"$WORK/auth"
make_payload "$WORK/body.bin" 8000	# large enough that curl uses Expect

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-http=1 --auth-file="$WORK/auth" \
		--event-loop="$loop" --nr-workers=2

	# (a) Unauthenticated POST: 407, and the origin must not be contacted.
	before="$(wc -l <"$olog")"
	code="$(curl -s --max-time 20 -o /dev/null -w '%{http_code}' \
		-x "http://127.0.0.1:$pp" -H 'Expect: 100-continue' \
		--data-binary @"$WORK/body.bin" "http://127.0.0.1:$op/x")"
	[ "$code" = 407 ] \
		|| fail "[$loop] unauthenticated forward POST got $code, expected 407"
	after="$(wc -l <"$olog")"
	[ "$before" = "$after" ] \
		|| fail "[$loop] rejected request body was forwarded to the origin"

	# (b) Authenticated POST: forwarded, and the whole body reaches the origin.
	code="$(curl -s --max-time 20 -o /dev/null -w '%{http_code}' \
		-x "http://user:pass@127.0.0.1:$pp" -H 'Expect: 100-continue' \
		--data-binary @"$WORK/body.bin" "http://127.0.0.1:$op/x")"
	[ "$code" = 200 ] \
		|| fail "[$loop] authenticated forward POST got $code, expected 200"
	got="$(tail -n1 "$olog")"
	[ "$got" = 8000 ] \
		|| fail "[$loop] origin received $got body bytes, expected 8000"

	kill "$GWP_PID" 2>/dev/null
done

pass
