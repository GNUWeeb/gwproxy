#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Every connection through an upstream proxy holds a reference to that
# upstream server, and every way the connection ends must drop it again: a
# leaked reference keeps a server alive after its pool is gone, one dropped
# twice frees it under the connections still using it. After its workers are
# gone, gwproxy checks that its --upstream-proxy server is back to the one
# reference of its pool, and says so at debug level.
#
# So drive a SOCKS5 front through many connections that end in every way
# (served, refused by the target, cut during the greeting or the request,
# a refused UDP ASSOCIATE), with a socks5h:// and an http:// upstream and one
# that refuses connections, leave some tunnels open, stop the front and read
# its verdict. On every available event loop.

. "$(dirname "$0")/lib.sh"
require python3
require_opt "--upstream-proxy"

COUNT=20
HELD=4

hp="$(pick_port)"
make_payload "$WORK/file.bin" 20000
start_httpd "$hp" "$WORK" "1.0"
closed_port
cport="$CLOSED_PORT"

# The upstreams: gwproxy itself, as a SOCKS5 and as an HTTP proxy.
us="$(pick_port)"
gwp_start "127.0.0.1:$us" --as-socks5=1 --event-loop=epoll --nr-workers=1
uh="$(pick_port)"
gwp_start "127.0.0.1:$uh" --as-http=1 --event-loop=epoll --nr-workers=1

# stop_front <pid>: SIGTERM the front and wait (bounded) for it to exit.
stop_front()
{
	local pid="$1" i

	wait_sigterm_handled "$pid" || fail "front $pid never set up SIGTERM"
	kill -TERM "$pid" 2>/dev/null
	for i in $(seq 1 200); do
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.1
	done
	kill -0 "$pid" 2>/dev/null && fail "front $pid did not exit on SIGTERM"
	wait "$pid" 2>/dev/null
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	for up in "socks5h://127.0.0.1:$us" "http://127.0.0.1:$uh" \
		  "socks5://127.0.0.1:$cport"; do
		tag="[$loop ${up%%:*}]"
		held="$HELD"
		[ "${up##*:}" = "$cport" ] && { tag="[$loop dead upstream]"; held=0; }

		fp="$(pick_port)"
		gwp_start "127.0.0.1:$fp" --as-socks5=1 --event-loop="$loop" \
			--nr-workers=2 --connect-timeout=5 --log-level=4 \
			--upstream-proxy="$up"
		front="$GWP_PID"
		flog="$WORK/gwp.$fp.log"

		out="$WORK/client.$fp.out"
		python3 "$SERVERS_DIR/upstream_refs_client.py" "$fp" "$hp" \
			"$cport" "$COUNT" "$held" >"$out" 2>&1 &
		cpid=$!
		_PIDS+=("$cpid")
		timeout 120 bash -c "until grep -q '^HELD' '$out' || ! kill -0 $cpid 2>/dev/null; do sleep 0.1; done"
		grep -q '^HELD' "$out" || {
			sed 's/^/# client: /' "$out" >&2
			fail "$tag the client did not get through its connections"
		}
		diag "$tag $(head -n 1 "$out")"
		if [ "$held" != 0 ]; then
			grep -q "^ok=$COUNT refused=$COUNT .* udp=$COUNT\$" "$out" || \
				fail "$tag not every kind of connection happened: $(head -n 1 "$out")"
		fi

		# Stop the front with the held tunnels still open.
		stop_front "$front"
		kill "$cpid" 2>/dev/null
		wait "$cpid" 2>/dev/null

		if grep -q "BUG: upstream proxy" "$flog"; then
			grep "BUG: upstream proxy" "$flog" | sed 's/^/# gwp: /' >&2
			fail "$tag connections left the upstream's references off"
		fi
		grep -q "all connection references dropped" "$flog" || {
			tail -n 20 "$flog" | sed 's/^/# gwp: /' >&2
			fail "$tag no verdict on the upstream's references at exit"
		}
	done
done

pass
