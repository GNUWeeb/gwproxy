#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The TLS engine produces records of its own in answer to what a client sends:
# a KeyUpdate that asks for one back, for instance. Those must reach the client
# even when there is no other traffic to carry them along, and a client that
# keeps asking without reading the answers must be stopped by no longer being
# read, not have them queued without limit. It has to be able to carry on when
# it does read. Once the proxy's sending to the client has ended, the answers
# must simply go. Exercised on every event loop.

. "$(dirname "$0")/lib.sh"
require python3

# Every KeyUpdate frees memory: keep a sanitizer from holding on to it, which
# would look like what this test is looking for.
export ASAN_OPTIONS="quarantine_size_mb=1:thread_local_quarantine_size_kb=64:${ASAN_OPTIONS:-}"

require_opt --tls-cert
require openssl

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 \
	-subj '/CN=localhost' >/dev/null 2>&1 \
	|| skip "openssl could not generate a test certificate"

# The scenarios take a lot of CPU, more so under a sanitizer, and each looks at
# the memory of a proxy of its own: run them all at once.
declare -a runs=()
start_scenario()
{
	local loop="$1" scenario="$2" pp
	shift 2

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-http=1 --event-loop="$loop" \
		--tls-cert="$WORK/cert.pem" --tls-key="$WORK/key.pem" \
		--nr-workers=1 --protocol-timeout=60 "$@"
	timeout 150 python3 "$SERVERS_DIR/tls_keyupdate_client.py" \
		"$scenario" "$pp" "$GWP_PID" >"$WORK/$loop.$scenario" 2>&1 &
	runs+=("$!:$loop.$scenario")
}

for loop in epoll; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	for scenario in answer noread burst shut; do
		start_scenario "$loop" "$scenario" --target-buf-size=4096
	done
	start_scenario "$loop" strand --client-buf-size=256 --target-buf-size=256
done

failed=""
for run in "${runs[@]}"; do
	pid="${run%%:*}"
	name="${run#*:}"
	rc=0
	wait "$pid" || rc=$?
	out="$(cat "$WORK/$name")"
	[ "$rc" = 77 ] && skip "$out"
	if [ "$out" != ok ]; then
		diag "$name: rc=$rc $out"
		failed="$failed $name"
	fi
done
[ -z "$failed" ] || fail "scenarios that failed:$failed"

pass
