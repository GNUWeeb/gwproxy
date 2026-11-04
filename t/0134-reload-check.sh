#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The periodic check of --auth-file and --acl-file reloads a file when it
# changed and at no other time: not while it sits idle, not a second time
# after inotify already reported the change, and not over and over while the
# file is missing or malformed, which is logged once with the current contents
# kept in force. It waits for a change to settle, so a writer that pauses does
# not get its half written file reloaded before it closes it. A reload that
# failed for want of descriptors is retried. A FIFO it finds is not read: that
# would block for a writer that may never come and hold up shutdown. Exercised
# on every available event loop.
#
# Most of this is waiting for the check, so each scenario gets a proxy of its
# own and they all run at the same time, which keeps the test well within the
# time limit t/run-one.sh gives it.

. "$(dirname "$0")/lib.sh"
require curl
require mkfifo

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 1000
start_httpd "$hp" "$WORK" "1.1"

# More than the check interval, for "nothing more happens" to mean something.
settle() { sleep 2.5; }

# More than the settling time as well, for a change the check saw to be acted
# on if it is going to be.
settle_change() { sleep 7; }

# A pause in a writer's work, well within the settling time.
pause() { sleep 2.5; }

fetch()
{
	curl -s --max-time 30 --proxy "socks5h://$2:$3@127.0.0.1:$1" \
		"http://127.0.0.1:$hp/payload.bin" -o /dev/null
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

# wait_fetch_user <proxy-port> <user> <pass>: poll until fetch() succeeds.
wait_fetch_user()
{
	local i

	for i in $(seq 1 150); do
		fetch "$1" "$2" "$3" && return 0
		sleep 0.1
	done
	return 1
}

# expect_lines <what> <log> <text> <count>: <text> is logged exactly <count>
# times.
expect_lines()
{
	local n

	n="$(grep -c "$3" "$2")"
	[ "$n" = "$4" ] || fail "$1: '$3' logged $n times, expected $4"
}

# wait_exit <pid>: poll until <pid> is gone.
wait_exit()
{
	local i

	for i in $(seq 1 300); do
		kill -0 "$1" 2>/dev/null || return 0
		sleep 0.1
	done
	return 1
}

allow=$'-P INPUT ACCEPT\n-P OUTPUT ACCEPT\n'
auth_ok="Reloaded authentication file"
auth_bad="Failed to reload authentication file"
acl_ok="Reloaded ACL file"
acl_bad="Failed to reload ACL file"
not_reg="Not reloading"
deny="-A OUTPUT -d 127.0.0.1 --dports $hp -j REJECT"$'\n'

# The proxy with few descriptors, for the worker to use them all up.
limited="$WORK/limited"
cat >"$limited" <<EOF
#!/bin/sh
ulimit -n 32 || exit 1
exec "$GWPROXY" "\$@"
EOF
chmod +x "$limited"

# start_scenario <proxy args...>: start this scenario's proxy, set $pp and $log.
start_scenario()
{
	pp="$(pick_port)"
	log="$WORK/gwp.$pp.log"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1 "$@"
}

# stop_scenario <what>: the proxy exits when told to, so no reload is stuck.
stop_scenario()
{
	kill "$GWP_PID" 2>/dev/null
	wait_exit "$GWP_PID" || fail "[$1] the proxy did not exit, a reload is stuck"
}

# layout_links: the auth file and the ACL behind symlinks, where only the check
# sees a change to them.
layout_links()
{
	mkdir "$d/real" "$d/cfg"
	echo alice:pw >"$d/real/auth"
	printf '%s' "$allow" >"$d/real/acl"
	ln -s "$d/real/auth" "$d/cfg/auth"
	ln -s "$d/real/acl" "$d/cfg/acl"
	start_scenario --auth-file="$d/cfg/auth" --acl-file="$d/cfg/acl"
	fetch "$pp" alice pw || fail "[$name] initial credentials rejected"
}

scenario_idle()
{
	layout_links

	# Idle: no reload at all.
	settle
	expect_lines "[$name] idle" "$log" "$auth_ok" 0
	expect_lines "[$name] idle" "$log" "$acl_ok" 0

	# Reported by inotify: reloaded once, the check adds nothing.
	echo bob:pw >"$d/cfg/.new"
	mv -f "$d/cfg/.new" "$d/cfg/auth"
	wait_lines "$log" "$auth_ok" 1 \
		|| fail "[$name] the replaced symlink was not reloaded"
	settle_change
	expect_lines "[$name] inotify" "$log" "$auth_ok" 1
	stop_scenario "$name"
}

scenario_missing()
{
	layout_links

	# Missing: logged once, the current credentials stay in force.
	rm -f "$d/real/auth"
	wait_lines "$log" "$auth_bad" 1 || fail "[$name] a missing file was not logged"
	fetch "$pp" alice pw || fail "[$name] a missing file dropped the credentials"
	settle
	expect_lines "[$name] missing" "$log" "$auth_bad" 1

	# Back again: reloaded.
	echo carol:pw >"$d/real/auth.new"
	mv -f "$d/real/auth.new" "$d/real/auth"
	wait_lines "$log" "$auth_ok" 1 || fail "[$name] the file put back was not reloaded"
	fetch "$pp" carol pw || fail "[$name] the file put back is not in force"
	stop_scenario "$name"
}

scenario_malformed()
{
	layout_links

	# Malformed: logged once, the current rules stay in force.
	echo 'this is not a rule' >"$d/real/acl.new"
	mv -f "$d/real/acl.new" "$d/real/acl"
	wait_lines "$log" "$acl_bad" 1 || fail "[$name] a malformed ACL was not logged"
	fetch "$pp" alice pw || fail "[$name] a malformed ACL changed the rules"
	settle
	expect_lines "[$name] malformed" "$log" "$acl_bad" 1
	stop_scenario "$name"
}

scenario_fifo()
{
	layout_links

	# A FIFO behind the symlink, and no writer: not read, so the thread is
	# still there to reload the file put back and to let the proxy exit.
	mkfifo "$d/fifo"
	mv -f "$d/fifo" "$d/real/auth"
	wait_lines "$log" "$not_reg" 1 || fail "[$name] the FIFO was not logged"
	fetch "$pp" alice pw || fail "[$name] the FIFO dropped the credentials"
	settle
	expect_lines "[$name] FIFO" "$log" "$not_reg" 1
	echo erin:pw >"$d/real/auth.new"
	mv -f "$d/real/auth.new" "$d/real/auth"
	wait_lines "$log" "$auth_ok" 1 || fail "[$name] the file after the FIFO was not reloaded"
	fetch "$pp" erin pw || fail "[$name] the file after the FIFO is not in force"
	stop_scenario "$name"
}

# The proxy leaves a file alone until it has not changed for 5 seconds, so a
# half written file stays out of force only while no two of the writer's changes
# are further apart than that. SECONDS counts whole seconds, so a difference of
# $max_pause is less than 5 seconds. A machine stalled for longer may have
# reloaded the half written file, which is no fault of the proxy and leaves the
# later steps with nothing to go by, even the reload count after the close. So
# end_if_late ends the scenario there, passing.
max_pause=4
end_if_late()
{
	[ $((SECONDS - changed_at)) -le "$max_pause" ] && return 0
	diag "[$name] stalled for over ${max_pause}s between changes, ending here"
	stop_scenario "$name"
	exit 0
}

# change <command...>: change the file with <command>, and only then judge the
# time since the previous change, so that a stall right before it is counted.
# The time is taken before the change, so a stall right after it is counted for
# the next one.
change()
{
	local before="$SECONDS"

	"$@"
	end_if_late
	changed_at="$before"
}

# Auth file rewritten in place by a writer that pauses, truncated and then half
# written: the credentials stay until it closes the file.
scenario_inplace()
{
	echo alice:pw >"$d/auth"
	echo bob:pw >>"$d/auth"
	start_scenario --auth-file="$d/auth"
	fetch "$pp" alice pw || fail "[$name] initial credentials rejected"
	changed_at="$SECONDS"
	exec 3>"$d/auth"
	pause
	fetch "$pp" alice pw || { end_if_late;
		fail "[$name] a truncated file was reloaded before the close"; }
	change echo alice:pw >&3
	pause
	fetch "$pp" bob pw || { end_if_late;
		fail "[$name] a half written file was reloaded before the close"; }
	change echo carol:pw >&3
	exec 3>&-
	wait_lines "$log" "$auth_ok" 1 || fail "[$name] the close was not reloaded"
	fetch "$pp" carol pw || fail "[$name] the finished file is not in force"
	fetch "$pp" bob pw && fail "[$name] the finished file left a revoked user"
	stop_scenario "$name"
}

# The same for the ACL: its partial rules must not open what the old file and
# the finished file both reject.
scenario_inplace_acl()
{
	printf '%s%s' "$deny" "$allow" >"$d/acl"
	start_scenario --acl-file="$d/acl"
	fetch "$pp" x x && fail "[$name] the origin is allowed at first"
	changed_at="$SECONDS"
	exec 3>"$d/acl"
	change printf '%s' "$allow" >&3
	pause
	fetch "$pp" x x && { end_if_late;
		fail "[$name] partial rules were reloaded before the close"; }
	change printf '%s' "$deny" >&3
	exec 3>&-
	wait_lines "$log" "$acl_ok" 1 || fail "[$name] the close was not reloaded"
	fetch "$pp" x x && fail "[$name] the finished rules let the origin through"
	stop_scenario "$name"
}

# A reload that ran out of descriptors: logged once and retried, so the new
# contents apply once descriptors are free again. Whether the check meets a full
# table depends on what the worker has accepted by then, so rotate until a
# reload failed.
scenario_fds()
{
	local i j last reloads n fd fds=()

	echo alice:pw >"$d/auth"
	ln -s "$d/auth" "$d/link"
	GWPROXY="$limited"
	start_scenario --auth-file="$d/link"
	for i in $(seq 1 60); do
		exec {fd}<>"/dev/tcp/127.0.0.1/$pp" || break
		fds+=("$fd")
	done
	sleep 0.5
	for i in 1 2 3; do
		echo "user$i:pw" >"$d/auth.new"
		mv -f "$d/auth.new" "$d/auth"
		reloads=$(($(grep -c "$auth_ok" "$log") + 1))
		for j in $(seq 1 150); do
			grep -q "$auth_bad" "$log" && break 2
			[ "$(grep -c "$auth_ok" "$log")" -ge "$reloads" ] && break
			sleep 0.1
		done
	done
	last="$i"
	for fd in "${fds[@]}"; do
		exec {fd}>&-
	done
	wait_fetch_user "$pp" "user$last" pw \
		|| fail "[$name] the new contents did not apply once descriptors were free"
	n="$(grep -c "$auth_bad" "$log")"
	[ "$n" -le 1 ] || fail "[$name] the failure was logged $n times"
	stop_scenario "$name"
}

# Each scenario runs in a subshell of its own; fail() ends only that subshell,
# and the proxy it leaves is swept when the test exits.
jobs=()
for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	for scenario in idle missing malformed fifo inplace inplace_acl fds; do
		name="$loop/$scenario"
		d="$WORK/$loop.$scenario"
		mkdir "$d"
		"scenario_$scenario" &
		jobs+=("$!")
		_PIDS+=("$!")
	done
done

failed=0
for job in "${jobs[@]}"; do
	wait "$job" || failed=1
done
[ "$failed" = 0 ] || fail "a scenario failed, see above"

pass
