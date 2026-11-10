#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A second gwproxy on the same --bind is warned about.
#
# Every listener sets SO_REUSEPORT, so a second instance started by mistake on
# a port another one already listens on starts without an error, and the
# kernel spreads new connections over both, each with its own configuration.
# Nothing said so. A deliberate overlapping restart works this way too, so
# the second instance still starts, but now logs a warning naming the address.
#
#  - The first instance, with several workers sharing the port, warns about
#    none of its own listeners.
#  - A second on the same address, and one on the wildcard address with the
#    same port, warn and keep running.
#  - Once the others are gone, an instance on the port warns no more.

. "$(dirname "$0")/lib.sh"

WARN="Another socket already listens on"

port="$(pick_port)"

# start_other <name> <bind> <args...>: start a proxy on <bind>, which another
# one may share, log to $WORK/<name>.log, and set OTHER_PID once it listens.
start_other()
{
	local name="$1" bind="$2" pid; shift 2

	"$GWPROXY" --bind="$bind" --log-level=3 --acl-allow-all "$@" \
		>"$WORK/$name.log" 2>&1 &
	pid=$!
	_PIDS+=("$pid")
	if ! wait_listen "${bind##*:}" "$pid"; then
		sed 's/^/# gwp: /' "$WORK/$name.log" >&2
		fail "$name did not listen on $bind"
	fi
	OTHER_PID="$pid"
}

# stop <pid>: stop a proxy and wait for it to exit.
stop()
{
	kill -TERM "$1" 2>/dev/null || true
	timeout 20 bash -c "while kill -0 $1 2>/dev/null; do sleep 0.1; done" ||
		fail "proxy $1 did not exit after SIGTERM"
	wait "$1" 2>/dev/null || true
}

start_other first "127.0.0.1:$port" --as-socks5=1 --nr-workers=4
first="$OTHER_PID"
grep -qF -- "$WARN" "$WORK/first.log" && {
	sed 's/^/# first: /' "$WORK/first.log" >&2
	fail "the first instance warned about its own listeners"
}

start_other second "127.0.0.1:$port" --as-http=1 --nr-workers=1
second="$OTHER_PID"
grep -qF -- "$WARN 127.0.0.1:$port" "$WORK/second.log" || {
	sed 's/^/# second: /' "$WORK/second.log" >&2
	fail "the second instance on 127.0.0.1:$port did not warn"
}

# Without IPv6 the wildcard is listened on as 0.0.0.0, and named so.
start_other wild "[::]:$port" --as-socks5=1 --nr-workers=1
wild="$OTHER_PID"
grep -qE -- "$WARN (\[::\]|0\.0\.0\.0):$port" "$WORK/wild.log" || {
	sed 's/^/# wild: /' "$WORK/wild.log" >&2
	fail "the instance on [::]:$port did not warn"
}
stop "$wild"

kill -0 "$first" 2>/dev/null && kill -0 "$second" 2>/dev/null ||
	fail "an instance sharing the port has exited"
stop "$second"
stop "$first"

start_other alone "127.0.0.1:$port" --as-socks5=1 --nr-workers=2
grep -qF -- "$WARN" "$WORK/alone.log" && {
	sed 's/^/# alone: /' "$WORK/alone.log" >&2
	fail "warned with no other listener on the port"
}

pass
