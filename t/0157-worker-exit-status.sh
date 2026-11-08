#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A fatal error in any worker stops the whole proxy, and the exit status must
# say so. Only worker 0's result used to be looked at, and worker 0 leaves
# cleanly when another worker stopped it, so the proxy reported success.
#
# strace makes a worker's event wait fail. It counts calls per thread, so
# which worker gets there first depends on where the connections land; with 4
# workers it is rarely worker 0, the main thread. Whichever it is, the exit
# status must not be 0, and the log must say which worker stopped the proxy and
# why: many of the errors that stop a worker log nothing of their own. A
# shutdown by signal, under the same strace, must exit with 0.

. "$(dirname "$0")/lib.sh"
require strace

# Leak checking does not work under ptrace.
export ASAN_OPTIONS="${ASAN_OPTIONS:+$ASAN_OPTIONS:}detect_leaks=0"

closed_port
tp="$CLOSED_PORT"

# start_traced <loop> <syscall> <when>: start the proxy under strace, failing
# call number <when> of <syscall> in each thread. Sets PP, ST_PID and SLOG.
start_traced()
{
	local loop="$1" sc="$2" when="$3"

	PP="$(pick_port)"
	SLOG="$WORK/strace.$PP"
	strace -f -qq -o "$SLOG" -e trace="$sc" \
		-e inject="$sc":error=EINVAL:when="$when" \
		"$GWPROXY" --event-loop="$loop" --nr-workers=4 \
		--bind="127.0.0.1:$PP" --target="127.0.0.1:$tp" \
		--acl-allow-all --log-level=2 >"$WORK/gwp.$PP.log" 2>&1 &
	ST_PID=$!
	_PIDS+=("$ST_PID")
	wait_listen "$PP" "$ST_PID" || fail "[$loop] proxy did not listen"
}

for loop in epoll io_uring; do
	if [ "$loop" = io_uring ]; then
		have_io_uring || continue
		sc=io_uring_enter
	else
		sc=epoll_wait,epoll_pwait
	fi

	# Control: nothing is injected this far in, and SIGTERM exits with 0.
	start_traced "$loop" "$sc" 65000
	gwp_pid=""
	for _ in $(seq 1 100); do
		gwp_pid="$(cat "/proc/$ST_PID/task/$ST_PID/children" 2>/dev/null)"
		gwp_pid="${gwp_pid%% *}"
		[ -n "$gwp_pid" ] && break
		sleep 0.1
	done
	[ -n "$gwp_pid" ] || fail "[$loop] cannot find the traced proxy"
	_PIDS=("$gwp_pid" "${_PIDS[@]}")
	wait_sigterm_handled "$gwp_pid" || fail "[$loop] no SIGTERM handler"
	kill "$gwp_pid" 2>/dev/null
	wait "$ST_PID"
	rc=$?
	[ "$rc" = 0 ] || fail "[$loop] exit status $rc after SIGTERM"

	for try in 1 2 3 4; do
		start_traced "$loop" "$sc" 3

		# Wake the workers until one has its call fail.
		for _ in $(seq 1 600); do
			kill -0 "$ST_PID" 2>/dev/null || break
			(exec 3<>"/dev/tcp/127.0.0.1/$PP") 2>/dev/null
			sleep 0.05
		done
		if kill -0 "$ST_PID" 2>/dev/null; then
			grep -q INJECTED "$SLOG" || skip "strace did not inject"
			fail "[$loop] the proxy did not stop on a failed $sc"
		fi
		wait "$ST_PID"
		rc=$?
		grep -q INJECTED "$SLOG" || skip "strace did not inject"
		[ "$rc" = 22 ] || {
			sed 's/^/# gwp: /' "$WORK/gwp.$PP.log" >&2
			grep INJECTED "$SLOG" | sed 's/^/# strace: /' >&2
			fail "[$loop] try $try: exit status $rc, want EINVAL (22)"
		}
		grep -q 'Worker [0-9]* stopped on an error, stopping the proxy: Invalid argument' \
			"$WORK/gwp.$PP.log" || {
			sed 's/^/# gwp: /' "$WORK/gwp.$PP.log" >&2
			fail "[$loop] try $try: the log does not say which worker stopped the proxy, and why"
		}
	done
done

pass
