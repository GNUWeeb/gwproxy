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
# would look like what this test is looking for. Nor may it move the frames of
# functions to a stack of its own, to catch their use after a return: each
# call takes the next frame there, so the stack's pages are touched one after
# the other, 1 MiB of them for each frame size, and under load a scenario can
# be measuring by the time that ends.
export ASAN_OPTIONS="quarantine_size_mb=1:thread_local_quarantine_size_kb=64:detect_stack_use_after_return=0:${ASAN_OPTIONS:-}"

require_opt --tls-cert
require openssl

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 \
	-subj '/CN=localhost' >/dev/null 2>&1 \
	|| skip "openssl could not generate a test certificate"

# The scenarios take a lot of CPU, more so under a sanitizer, and each looks at
# the memory of a proxy of its own: run them all at once.
#
# A scenario gives up once its proxy has stopped making progress, however long
# a proxy starved of CPU takes to get there. The timeout only catches a client
# that hangs: let it run for as long as the runner lets the test (t/run-one.sh),
# less the time to collect what the scenarios have to say.
limit=$((${GWP_TEST_TIMEOUT:-180} - 30))
[ "$limit" -ge 150 ] || limit=150
declare -a runs=()
start_scenario()
{
	local loop="$1" scenario="$2" pp
	shift 2

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-http=1 --event-loop="$loop" \
		--tls-cert="$WORK/cert.pem" --tls-key="$WORK/key.pem" \
		--nr-workers=1 --protocol-timeout=60 "$@"
	timeout "$limit" python3 "$SERVERS_DIR/tls_keyupdate_client.py" \
		"$scenario" "$pp" "$GWP_PID" >"$WORK/$loop.$scenario" 2>&1 &
	runs+=("$!:$loop.$scenario")
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	for scenario in answer noread burst shut; do
		start_scenario "$loop" "$scenario" --target-buf-size=4096
	done
	start_scenario "$loop" strand --client-buf-size=256 --target-buf-size=256
	# The epoll loop does not get its answers out on an association yet.
	[ "$loop" = io_uring ] &&
		start_scenario "$loop" udp --as-socks5=1 --target-buf-size=4096
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
