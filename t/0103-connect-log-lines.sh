#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Both event loops log a connection to the target the same way: one
# "Target socket connected" line at info level for plain forwarding
# (--target) and for a SOCKS5 CONNECT alike, and through an upstream proxy
# one "Upstream tunnel established" line naming the destination instead.
# The epoll loop used to log nothing for plain forwarding, and named the
# upstream proxy's address as the target when chaining.

. "$(dirname "$0")/lib.sh"
require curl
require python3
require_opt "--upstream-proxy"

hp="$(pick_port)"
echo hello >"$WORK/index.txt"
start_httpd "$hp" "$WORK" "1.0"

up="$(pick_port)"
gwp_start "127.0.0.1:$up" --as-http=1 --event-loop=epoll --nr-workers=1
up_pid="$GWP_PID"

# stop_gwp: stop the proxy started last and print its log's path.
stop_gwp()
{
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
	echo "$WORK/gwp.$1.log"
}

# count <log> <regex>: the number of matching lines.
count() { grep -c -- "$2" "$1"; }

tc='Target socket connected (fd=[0-9]*, idx=[0-9]*, ca=127\.0\.0\.1:[0-9]*, ta=127\.0\.0\.1:'"$hp"')$'

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	# Plain forwarding.
	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --target="127.0.0.1:$hp" \
		--event-loop="$loop" --nr-workers=1
	got="$(curl -s --max-time 10 "http://127.0.0.1:$p/index.txt")"
	[ "$got" = hello ] || fail "[$loop] plain forwarding: '$got'"
	log="$(stop_gwp "$p")"
	n="$(count "$log" "$tc")"
	[ "$n" = 1 ] || fail "[$loop] plain forwarding: $n connect lines"

	# SOCKS5, straight to the target.
	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1
	got="$(curl -s --max-time 10 --proxy "socks5://127.0.0.1:$p" \
		"http://127.0.0.1:$hp/index.txt")"
	[ "$got" = hello ] || fail "[$loop] socks5: '$got'"
	log="$(stop_gwp "$p")"
	n="$(count "$log" "$tc")"
	[ "$n" = 1 ] || fail "[$loop] socks5: $n connect lines"

	# SOCKS5 through the upstream HTTP proxy, by name and by address.
	for host in localhost 127.0.0.1; do
		p="$(pick_port)"
		gwp_start "127.0.0.1:$p" --as-socks5=1 --event-loop="$loop" \
			--nr-workers=1 --upstream-proxy="http://127.0.0.1:$up"
		got="$(curl -s --max-time 10 --proxy "socks5h://127.0.0.1:$p" \
			"http://$host:$hp/index.txt")"
		[ "$got" = hello ] || fail "[$loop] upstream $host: '$got'"
		log="$(stop_gwp "$p")"
		n="$(count "$log" 'Target socket connected')"
		[ "$n" = 0 ] ||
			fail "[$loop] upstream $host: $n target connect lines"
		n="$(count "$log" "Upstream tunnel established (idx=[0-9]*, ca=127\.0\.0\.1:[0-9]*, dst=${host//./\\.}:$hp)\$")"
		[ "$n" = 1 ] || fail "[$loop] upstream $host: $n tunnel lines"
	done
done

kill "$up_pid" 2>/dev/null
pass
