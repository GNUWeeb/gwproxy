#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# t/run-one.sh is the only thing that cleans up after a test that hangs or that
# leaves processes behind, so it is checked here on fake tests: nothing a test
# started may outlive run-one.sh, whether the test hangs or returns at once.
# timeout(1) moves its command into a process group of its own, so the test's
# group alone does not reach it, and a process that ignores SIGTERM still has
# to go.
#
# A test still running at its deadline fails, even if it then exits 0: when it
# catches SIGTERM, or when it ends while the watchdog records what it was stuck
# on.

. "$(dirname "$0")/lib.sh"

# run <name> <timeout> <body>: run a fake test with <body> under run-one.sh and
# print its result line. The fake writes its session id to $WORK/<name>.sid.
run()
{
	local name="$1" tmo="$2" body="$3"

	printf 'echo $$ >"%s"\n%s\n' "$WORK/$name.sid" "$body" >"$WORK/$name.sh"
	GWP_TEST_TIMEOUT="$tmo" "$T_DIR/run-one.sh" integ "$name" \
		"$WORK/$name.sh" "$WORK/$name.res" >/dev/null
	cat "$WORK/$name.res"
}

# left <sid>: print the processes still in session <sid>, zombies aside.
left()
{
	local d st f
	for d in /proc/[0-9]*; do
		{ read -r st <"$d/stat"; } 2>/dev/null || continue
		st=${st##*) }
		f=($st)
		[ "${f[3]}" = "$1" ] && [ "${f[0]}" != Z ] && echo "${d#/proc/}"
	done
	return 0
}

T_DIR="$(cd "$(dirname "$0")" && pwd)"

# Past its deadline: it must fail, whether it is still sleeping when the
# deadline has been dealt with or catches the SIGTERM and exits 0.
r="$(run late 1 'sleep 3')"
diag "late: $r"
case "$r" in
FAIL\ *) ;;
*) fail "a test that ran past its deadline did not fail: $r" ;;
esac
r="$(run late-term 1 'trap "exit 0" TERM
sleep 30 &
wait')"
diag "late-term: $r"
case "$r" in
FAIL\ *) ;;
*) fail "a test that exited 0 on SIGTERM at its deadline did not fail: $r" ;;
esac

# Stray processes under timeout(1), one of them deaf to SIGTERM, left by a test
# that hangs (the watchdog reaps them) and by one that returns (the runner's
# final cleanup does).
strays='timeout 500 sleep 777 &
(trap "" TERM; exec timeout 500 sleep 778) &
sleep 0.2'
for how in hang return; do
	case "$how" in
	hang)	r="$(run "$how" 5 "$strays"$'\nsleep 600')" ;;
	return)	r="$(run "$how" 60 "$strays")" ;;
	esac
	diag "$how: $r"
	sid="$(cat "$WORK/$how.sid" 2>/dev/null)"
	[ -n "$sid" ] || fail "$how: the fake test did not start"
	rest="$(left "$sid")"
	if [ -n "$rest" ]; then
		for p in $rest; do
			diag "left behind: $p $(tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null)"
		done
		kill -KILL $rest 2>/dev/null
		fail "$how: processes of the test outlived run-one.sh"
	fi
done

pass
