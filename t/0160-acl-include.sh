#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# "include PATH;" in the ACL file: the rules of an included file apply at the
# include line, a relative path is taken from the including file's directory,
# and a set with a broken or missing file is refused at startup. Every file of
# the set is watched: editing an included file reloads the whole set, a failed
# reload keeps the rules in force, a file added by a new include line is
# watched from then on (even while it is still missing), and a file whose
# include line is gone is not. A FIFO, included or put in place of the ACL
# file, is refused rather than opened and waited on, which would hold up every
# later reload and shutdown. Exercised on every available event loop.

. "$(dirname "$0")/lib.sh"
require curl
require mkfifo

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 1000
start_httpd "$hp" "$WORK" "1.1"

acl_ok="Reloaded ACL file"
acl_bad="Failed to reload ACL file"

# code <proxy-port> <target-port>: the HTTP status of a forwarded GET.
code()
{
	curl -s --max-time 20 -x "http://127.0.0.1:$1" \
		"http://127.0.0.1:$2/payload.bin" -o /dev/null -w '%{http_code}'
}

# wait_code <proxy-port> <target-port> <status>: poll until code() says so.
wait_code()
{
	local i c=""

	for i in $(seq 1 150); do
		c="$(code "$1" "$2")"
		[ "$c" = "$3" ] && return 0
		sleep 0.1
	done
	echo "# last status $c" >&2
	return 1
}

# wait_lines <log> <text> <count>: poll until <text> is logged <count> times.
wait_lines()
{
	local i

	for i in $(seq 1 300); do
		[ "$(grep -c "$2" "$1")" -ge "$3" ] && return 0
		sleep 0.1
	done
	return 1
}

# A broken set is refused at startup, naming the file at fault.
mkdir -p "$WORK/bad"
printf -- '%s\n' 'include missing.acl;' '-P OUTPUT ACCEPT' >"$WORK/bad/main.acl"
ec=0
timeout --foreground 10 "$GWPROXY" --bind="127.0.0.1:$(pick_port)" \
	--as-http=1 --acl-file="$WORK/bad/main.acl" >"$WORK/bad.log" 2>&1 || ec=$?
{ [ "$ec" -ne 0 ] && [ "$ec" -ne 124 ]; } || \
	fail "gwproxy accepted an ACL including a missing file (exit $ec)"
grep -q 'missing.acl' "$WORK/bad.log" || \
	fail "the startup error did not name the missing file"

printf -- '%s\n' 'include main.acl;' >"$WORK/bad/main.acl"
ec=0
timeout --foreground 10 "$GWPROXY" --bind="127.0.0.1:$(pick_port)" \
	--as-http=1 --acl-file="$WORK/bad/main.acl" >"$WORK/cycle.log" 2>&1 || ec=$?
{ [ "$ec" -ne 0 ] && [ "$ec" -ne 124 ]; } || \
	fail "gwproxy accepted an ACL that includes itself (exit $ec)"
grep -q 'include cycle' "$WORK/cycle.log" || \
	fail "the startup error did not report the cycle"

# wait_exit <pid>: poll until <pid> is gone (at most 30 s).
wait_exit()
{
	local i

	for i in $(seq 1 300); do
		kill -0 "$1" 2>/dev/null || return 0
		sleep 0.1
	done
	return 1
}

# stop <what>: SIGTERM stops the proxy, so no reload is stuck.
stop()
{
	kill "$GWP_PID" 2>/dev/null
	wait_exit "$GWP_PID" || fail "$1: the proxy did not exit on SIGTERM"
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	d="$WORK/$loop"
	mkdir -p "$d/rules.d" "$d/other"
	printf -- '%s\n' '-A OUTPUT --dports 9 -j REJECT' >"$d/rules.d/a.acl"
	printf -- '%s\n' 'include rules.d/a.acl;' '-P OUTPUT ACCEPT' \
		>"$d/main.acl"

	pp="$(pick_port)"
	log="$WORK/gwp.$pp.log"
	gwp_start "127.0.0.1:$pp" --as-http=1 --event-loop="$loop" \
		--nr-workers=1 --acl-file="$d/main.acl"

	# The included rule applies; the rest falls through to the policy.
	c="$(code "$pp" 9)"
	[ "$c" = 403 ] || fail "$loop: the included rule did not apply ($c)"
	c="$(code "$pp" "$hp")"
	[ "$c" = 200 ] || fail "$loop: an allowed target got $c"

	# Each step counts the reload messages before its change and waits for
	# the one it causes: the new rules are in force a little before the
	# message is logged, so a status alone does not say that the reload
	# is over.

	# Editing the included file in place reloads the set.
	n_ok="$(grep -c "$acl_ok" "$log")"
	printf -- '%s\n' "-A OUTPUT --dports $hp -j REJECT" >"$d/rules.d/a.acl"
	wait_code "$pp" "$hp" 403 || \
		fail "$loop: an edit of the included file was not reloaded"
	wait_lines "$log" "$acl_ok" $((n_ok + 1)) || \
		fail "$loop: the reload of the included file was not logged"

	# A new include of a file not there yet: the reload fails and the
	# rules stay; once the file appears it is picked up.
	n_bad="$(grep -c "$acl_bad" "$log")"
	printf -- '%s\n' 'include other/b.acl;' 'include rules.d/a.acl;' \
		'-P OUTPUT ACCEPT' >"$d/main.acl.new"
	mv -f "$d/main.acl.new" "$d/main.acl"
	wait_lines "$log" "$acl_bad" $((n_bad + 1)) || \
		fail "$loop: the include of a missing file did not fail the reload"
	c="$(code "$pp" "$hp")"
	[ "$c" = 403 ] || fail "$loop: a failed reload dropped the rules ($c)"
	n_ok="$(grep -c "$acl_ok" "$log")"
	printf -- '%s\n' "-A OUTPUT --dports $hp -j ACCEPT" >"$d/other/b.acl"
	wait_code "$pp" "$hp" 200 || \
		fail "$loop: the newly included file was not watched"
	wait_lines "$log" "$acl_ok" $((n_ok + 1)) || \
		fail "$loop: the reload of the new file was not logged"

	# Drop that include again: its file is no longer part of the set, so
	# a change to it reloads nothing.
	n_ok="$(grep -c "$acl_ok" "$log")"
	printf -- '%s\n' 'include rules.d/a.acl;' '-P OUTPUT ACCEPT' \
		>"$d/main.acl"
	wait_code "$pp" "$hp" 403 || \
		fail "$loop: dropping an include was not reloaded"
	wait_lines "$log" "$acl_ok" $((n_ok + 1)) || \
		fail "$loop: the reload dropping the include was not logged"
	printf -- '%s\n' '-A OUTPUT -j REJECT' >"$d/other/b.acl"
	# Longer than the periodic check's settling time.
	sleep 7
	[ "$(grep -c "$acl_ok" "$log")" = $((n_ok + 1)) ] || \
		fail "$loop: a file no longer included still triggered a reload"
	c="$(code "$pp" "$hp")"
	[ "$c" = 403 ] || fail "$loop: unexpected status $c at the end"

	# An include of a FIFO is refused, not waited on: the reload fails,
	# the rules stay, and the proxy still stops when told to.
	mkfifo "$d/rules.d/pipe.acl"
	n_bad="$(grep -c "$acl_bad" "$log")"
	printf -- '%s\n' 'include rules.d/pipe.acl;' '-P OUTPUT ACCEPT' \
		>"$d/main.acl"
	wait_lines "$log" "$acl_bad" $((n_bad + 1)) || \
		fail "$loop: the include of a FIFO did not fail the reload"
	grep -q 'pipe.acl: not a regular file' "$log" || \
		fail "$loop: the FIFO was not reported"
	c="$(code "$pp" "$hp")"
	[ "$c" = 403 ] || fail "$loop: a FIFO include dropped the rules ($c)"
	stop "$loop include of a FIFO"

	# The same for a FIFO renamed over the --acl-file itself.
	printf -- '%s\n' 'include rules.d/a.acl;' '-P OUTPUT ACCEPT' \
		>"$d/main.acl"
	pp="$(pick_port)"
	log="$WORK/gwp.$pp.log"
	gwp_start "127.0.0.1:$pp" --as-http=1 --event-loop="$loop" \
		--nr-workers=1 --acl-file="$d/main.acl"
	mkfifo "$d/main.fifo"
	mv -f "$d/main.fifo" "$d/main.acl"
	wait_lines "$log" "$acl_bad" 1 || \
		fail "$loop: a FIFO as the ACL file did not fail the reload"
	grep -q 'main.acl: not a regular file' "$log" || \
		fail "$loop: the FIFO ACL file was not reported"
	c="$(code "$pp" "$hp")"
	[ "$c" = 403 ] || fail "$loop: a FIFO ACL file dropped the rules ($c)"
	stop "$loop FIFO as the ACL file"
done

pass
