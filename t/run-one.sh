#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Run ONE test -- a unit binary or an integration script -- and record the
# outcome in a result file. This is what `make -jN test` schedules, one test per
# make target, so make itself controls the parallelism.
#
# Usage: run-one.sh <unit|integ> <name> <command> <result-file>
#
# Always exits 0, even when the test fails, so that `make -jN` keeps going and
# every test gets a chance to run; t/summary.sh reads the result files and
# decides the final verdict. The result file holds one line:
#
#	<PASS|FAIL|SKIP> <seconds> <name>
#
# Each test runs in its OWN SESSION (setsid), and the session is the handle used
# to reap anything it leaked: a process keeps its session after being orphaned,
# so proxies left by a SIGKILLed test are still reachable, and so are processes
# that moved to a process group of their own, as timeout(1) moves its command.
# Every process of the session is signalled by PID, SIGTERM then SIGKILL, so a
# test that ignores SIGTERM still goes, and concurrent tests, each in a session
# of its own, cannot kill each other's proxies.

set -u

T_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$T_DIR/.." && pwd)"

kind="$1"
name="$2"
cmd="$3"
res="$4"

TIMEOUT="${GWP_TEST_TIMEOUT:-180}"
export GWPROXY="${GWPROXY:-$ROOT/gwproxy}"

log="${res%.res}.log"
stuck="${res%.res}.stuck"
rm -f "$stuck"
mkdir -p "$(dirname "$res")"

start=$SECONDS

# sess_pids <sid>: set PIDS to the processes of session <sid>, zombies left
# out: no signal reaches them, and their parents reap them. Bash builtins only,
# as the watchdog runs this between the deadline and the SIGTERM (see below).
# Only the comm field of stat may hold spaces or ')', so it is split after the
# last ") ".
sess_pids()
{
	local d st f

	PIDS=()
	for d in /proc/[0-9]*; do
		{ read -r st <"$d/stat"; } 2>/dev/null || continue
		st=${st##*) }
		f=($st)
		[ "${f[3]}" = "$1" ] && [ "${f[0]}" != Z ] && PIDS+=("${d#/proc/}")
	done
	return 0
}

# sess_kill <sid> <tenths>: SIGTERM every process of session <sid>, give them
# <tenths> tenths of a second to exit, then SIGKILL what is left until nothing
# is, since a process may fork in between. Never this script's own session.
sess_kill()
{
	local sid="$1" i own

	case "$sid" in
	''|0|*[!0-9]*) return 1 ;;
	esac
	{ read -r own </proc/$$/stat; } 2>/dev/null || return 1
	own=${own##*) }
	own=($own)
	[ "${own[3]}" != "$sid" ] || return 1

	sess_pids "$sid"
	[ ${#PIDS[@]} -gt 0 ] || return 0
	kill -TERM "${PIDS[@]}" 2>/dev/null
	for ((i = 0; i < $2; i++)); do
		sleep 0.1
		sess_pids "$sid"
		[ ${#PIDS[@]} -gt 0 ] || return 0
	done
	for ((i = 0; i < 50; i++)); do
		kill -KILL "${PIDS[@]}" 2>/dev/null
		sleep 0.1
		sess_pids "$sid"
		[ ${#PIDS[@]} -gt 0 ] || return 0
	done
	return 1
}

# Own session, so the whole tree can be signalled and reaped as a unit. Run in
# the background, setsid is not a process group leader and calls setsid() in
# place, so $! is both the test's PID and its session ID.
if [ "$kind" = unit ]; then
	setsid env LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}:$ROOT" "$cmd" \
		>"$log" 2>&1 &
else
	setsid env GWPROXY="$GWPROXY" bash "$cmd" >"$log" 2>&1 &
fi
sid=$!

# Watchdog: SIGTERM the session at the deadline, SIGKILL shortly after.
#
# It gets its OWN session so that cancelling its process group below takes the
# sleep it is blocked on with it, and so that it is not among the processes it
# signals. Signalling only the subshell leaves that sleep running for the rest
# of the timeout, holding every descriptor it inherited -- make's jobserver pipe
# among them, which keeps `make -jN test` blocked long after the last test has
# finished.
#
# Before that it records what the test is stuck on: a test that hangs usually
# prints nothing, and it is gone by the time anyone can look. From /proc alone,
# as ps differs between the systems the tests run on, and with bash builtins:
# the scan runs between the deadline and the SIGTERM, and a fork per process on
# the host (a few thousand on a busy one) took seconds, during which a test past
# its deadline could still finish and pass.
setsid bash -c "$(declare -f sess_pids sess_kill)"'
	sleep "$1"
	sess_pids "$2"
	for p in "${PIDS[@]}"; do
		d=/proc/$p
		cmd=
		while IFS= read -r -d "" a; do
			cmd+="$a "
		done 2>/dev/null <"$d/cmdline"
		echo "pid $p: $cmd"
		while read -r l; do
			case "$l" in
			SigBlk:*|SigIgn:*|SigCgt:*) echo "$l" ;;
			esac
		done 2>/dev/null <"$d/status"
		for t in "$d"/task/*; do
			comm= st= wchan=
			{ read -r comm <"$t/comm"; } 2>/dev/null
			{ read -r st <"$t/stat"; } 2>/dev/null
			st=${st##*) }
			{ read -r wchan <"$t/wchan"; } 2>/dev/null
			echo "  task ${t##*/} $comm state=${st%% *} wchan=$wchan"
		done
	done >"$3" 2>&1
	sess_kill "$2" 50
' watchdog "$TIMEOUT" "$sid" "$stuck" </dev/null >/dev/null 2>&1 &
watchdog=$!

rc=0
wait "$sid" || rc=$?
kill -TERM -"$watchdog" 2>/dev/null
wait "$watchdog" 2>/dev/null

# Reap whatever the test left: proxies it never cleaned up, and anything that
# left its process group, such as a command run under timeout(1). The session
# holds only this test, so the other tests in a parallel run are unaffected.
sess_kill "$sid" 2

elapsed=$((SECONDS - start))

case "$kind:$rc" in
*:0)	status=PASS ;;
integ:77) status=SKIP ;;
*)	status=FAIL ;;
esac

printf '%s %s %s\n' "$status" "$elapsed" "$name" >"$res"

case "$status" in
PASS)	printf 'ok    %-32s (%ss)\n' "$name" "$elapsed" ;;
SKIP)	printf 'skip  %-32s %s\n' "$name" \
		"$(sed -n 's/^SKIP: //p' "$log" | head -1)" ;;
FAIL)	printf 'FAIL  %-32s (rc=%s)\n' "$name" "$rc"
	[ ! -s "$stuck" ] || sed "s/^/# $name: /" "$stuck" ;;
esac

exit 0
