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
# Each test runs in its OWN PROCESS GROUP (setsid). That does two things:
# a test that ignores SIGTERM can still be killed as a group, and the group is
# the handle used to reap anything it leaked -- a process keeps its process
# group after being orphaned, so proxies left by a SIGKILLed test are still
# reachable. It also keeps concurrent tests from killing each other's proxies.

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

# Own process group, so the whole tree can be signalled and reaped as a unit.
if [ "$kind" = unit ]; then
	setsid env LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}:$ROOT" "$cmd" \
		>"$log" 2>&1 &
else
	setsid env GWPROXY="$GWPROXY" bash "$cmd" >"$log" 2>&1 &
fi
pgid=$!

# Watchdog: SIGTERM the group at the deadline, SIGKILL shortly after.
#
# It gets its OWN process group so that cancelling it below takes the sleep it
# is blocked on with it. Signalling only the subshell leaves that sleep running
# for the rest of the timeout, holding every descriptor it inherited -- make's
# jobserver pipe among them, which keeps `make -jN test` blocked long after the
# last test has finished.
#
# Before that it records what the test is stuck on: a test that hangs usually
# prints nothing, and it is gone by the time anyone can look. From /proc alone,
# as ps differs between the systems the tests run on.
setsid bash -c '
	sleep "$1"
	for d in /proc/[0-9]*; do
		st="$(sed "s/.*) //" "$d/stat" 2>/dev/null)" || continue
		read -r _ _ _ sid _ <<<"$st"
		[ "$sid" = "$2" ] || continue
		echo "pid ${d#/proc/}: $(tr "\\0" " " <"$d/cmdline")"
		grep -E "^(SigBlk|SigIgn|SigCgt):" "$d/status"
		for t in "$d"/task/*; do
			echo "  task ${t##*/} $(cat "$t/comm")" \
				"state=$(sed "s/.*) //;s/ .*//" "$t/stat")" \
				"wchan=$(cat "$t/wchan" 2>/dev/null)" \
				"syscall=$(cat "$t/syscall" 2>/dev/null)"
		done
	done >"$3" 2>&1
	kill -TERM -"$2" 2>/dev/null
	sleep 5
	kill -KILL -"$2" 2>/dev/null
' watchdog "$TIMEOUT" "$pgid" "$stuck" </dev/null >/dev/null 2>&1 &
watchdog=$!

rc=0
wait "$pgid" || rc=$?
kill -TERM -"$watchdog" 2>/dev/null
wait "$watchdog" 2>/dev/null

# Reap whatever the test left. Signalling the group catches proxies the test
# never cleaned up -- an orphan keeps its process group -- and touches only this
# test, so the other tests in a parallel run are unaffected.
kill -TERM -"$pgid" 2>/dev/null
sleep 0.2
kill -KILL -"$pgid" 2>/dev/null

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
