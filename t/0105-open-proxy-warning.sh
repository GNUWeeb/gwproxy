#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# By default gwproxy listens on [::]:1080 and SOCKS5/HTTP clients need no
# credentials, which makes an open proxy. It must say so at startup: a
# SOCKS5 or HTTP proxy without --auth-file on a non-loopback address logs a
# warning; on loopback, with --auth-file, or as a plain forwarder it does not.
#
# Binding a wildcard address on the host would expose the test proxy, so
# those cases run in a private network namespace (unshare -rn) and are
# skipped where user namespaces are unavailable.

. "$(dirname "$0")/lib.sh"

WARN="without --auth-file: anyone who can reach it can use this proxy"

# startup_log <port> <args...>: run gwproxy until it listens on <port>, stop
# it and print its log. The warning comes before the listeners are set up,
# and the log is flushed when gwproxy exits.
startup_log()
{
	local log="$WORK/start.log" port="$1" pid; shift

	"$GWPROXY" --nr-workers=1 --log-level=2 "$@" >"$log" 2>&1 &
	pid=$!
	wait_listen "$port" "$pid" || echo "NOT-LISTENING"
	kill "$pid" 2>/dev/null
	wait "$pid" 2>/dev/null
	cat "$log"
}

# expect_warn <yes|no> <what> <port> <args...>
expect_warn()
{
	local want="$1" what="$2" out; shift 2

	out="$(startup_log "$@")"
	# A proxy that never came up proves nothing either way.
	case "$out" in
	*NOT-LISTENING*) fail "$what: gwproxy did not listen: $out" ;;
	esac
	if printf '%s\n' "$out" | grep -q -- "$WARN"; then
		[ "$want" = yes ] || fail "$what: unexpected open-proxy warning: $out"
	else
		[ "$want" = no ] || fail "$what: no open-proxy warning: $out"
	fi
	return 0
}

if [ "${1:-}" = --inner ]; then
	ns_inner_work "$2"
	# The work directory is the outer half's: leave its removal to it.
	trap - EXIT
	printf 'u:p\n' >"$WORK/auth"
	expect_warn yes "SOCKS5 on the default [::]:1080" 1080 --as-socks5=1
	expect_warn yes "HTTP on 0.0.0.0" 8080 --as-http=1 --bind=0.0.0.0:8080
	expect_warn no "SOCKS5 on [::] with --auth-file" 1080 --as-socks5=1 \
		--auth-file="$WORK/auth"
	expect_warn no "plain forwarding on [::]" 1080 --target=127.0.0.1:1
	echo PASS-INNER
	exit 0
fi

printf 'u:p\n' >"$WORK/auth"
port="$(pick_port)"
expect_warn no "SOCKS5 on 127.0.0.1" "$port" --as-socks5=1 \
	--bind="127.0.0.1:$port"
port="$(pick_port)"
expect_warn no "HTTP on [::1]" "$port" --as-http=1 --bind="[::1]:$port"

ns_drop_setup
$NS_DROP unshare -rn true 2>/dev/null || \
	skip "no user namespaces (unshare -rn) for the wildcard cases"
out="$($NS_DROP unshare -rn "$0" --inner "$WORK" 2>&1)"
printf '%s\n' "$out" | grep -q '^PASS-INNER' || {
	printf '%s\n' "$out" | sed 's/^/# /' >&2
	fail "inner run failed"
}

pass
