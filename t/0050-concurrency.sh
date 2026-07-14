#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Concurrency/integrity under load: run gwproxy as a SOCKS5 proxy with a pool
# of worker threads, then fire many simultaneous fetches of the same payload
# through it. Verify that every connection's bytes arrive intact, so no data
# is dropped, duplicated, or crossed between concurrent sessions. Repeated on
# every available event loop.

. "$(dirname "$0")/lib.sh"
require curl
require python3
require cmp

nr_conns=10

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 200000
start_httpd "$hp" "$WORK" "1.1"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start "[::1]:$pp" --as-socks5=1 --event-loop="$loop" --nr-workers=4

	# Launch nr_conns fetches at once and collect only their PIDs, so the
	# wait below never blocks on the servers lib.sh spawned.
	pids=()
	for i in $(seq 1 "$nr_conns"); do
		curl -s --max-time 30 --proxy "socks5h://[::1]:$pp" \
			"http://127.0.0.1:$hp/payload.bin" -o "$WORK/out.$i.bin" &
		pids+=("$!")
	done

	rc=0
	for pid in "${pids[@]}"; do
		wait "$pid" || rc=1
	done
	[ "$rc" -eq 0 ] || fail "[$loop] a concurrent curl via SOCKS5 failed"

	for i in $(seq 1 "$nr_conns"); do
		assert_files_equal "$WORK/payload.bin" "$WORK/out.$i.bin" \
			"[$loop] concurrent fetch #$i corrupted the payload"
	done

	kill "$GWP_PID" 2>/dev/null
done

pass
