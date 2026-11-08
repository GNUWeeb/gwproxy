#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# --watch-files=1 with include patterns: a new file that a pattern matches, a
# matched file removed, a new directory at a wildcard level, and a missing
# directory of an include_optional pattern that appears, each reload the set
# by themselves. Files and directories the patterns do not look at are not
# watched: one inotify watch per directory the patterns need, no more.
# Exercised on every available event loop.

. "$(dirname "$0")/lib.sh"
require curl

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 1000
start_httpd "$hp" "$WORK" "1.1"

acl_ok="Reloaded ACL file"

# code <proxy-port> <target-port>: the HTTP status of a forwarded GET.
code()
{
	curl -s --max-time 20 -x "http://127.0.0.1:$1" \
		"http://127.0.0.1:$2/payload.bin" -o /dev/null -w '%{http_code}'
}

# wait_code <proxy-port> <target-port> <status>: poll until code() says so
# (30 s at most: longer than the periodic check's settling time, so either
# inotify or the check may be what sees the change).
wait_code()
{
	local i c=""

	for i in $(seq 1 300); do
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

# watches <pid>: the number of inotify watches the process holds, or nothing
# when /proc does not show them.
watches()
{
	local fd n=""

	for fd in /proc/"$1"/fd/*; do
		[ "$(readlink "$fd" 2>/dev/null)" = "anon_inode:inotify" ] || continue
		n="$(grep -c '^inotify wd:' "/proc/$1/fdinfo/${fd##*/}")"
	done
	echo "$n"
}

# check_watches <pid> <want> <what>: the proxy holds <want> watches, if /proc
# can tell. Polled, as the watch list follows a reload a moment after it.
check_watches()
{
	local i n=""

	for i in $(seq 1 100); do
		n="$(watches "$1")"
		[ -z "$n" ] && return 0
		[ "$n" = "$2" ] && return 0
		sleep 0.1
	done
	fail "$3: $n inotify watches, want $2"
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	d="$WORK/$loop"
	mkdir -p "$d/rules.d/a/deeper" "$d/unrelated"
	printf -- '%s\n' '-A OUTPUT --dports 9 -j REJECT' >"$d/rules.d/a/r.acl"
	printf -- '%s\n' '-A OUTPUT -j BOGUS' >"$d/rules.d/a/deeper/r.acl"
	printf -- '%s\n' 'include_optional extra.d/*/*.acl;' \
		'include rules.d/*/*.acl;' '-P OUTPUT ACCEPT' >"$d/main.acl"

	pp="$(pick_port)"
	log="$WORK/gwp.$pp.log"
	gwp_start "127.0.0.1:$pp" --as-http=1 --event-loop="$loop" \
		--nr-workers=1 --watch-files=1 --acl-file="$d/main.acl"
	c="$(code "$pp" "$hp")"
	[ "$c" = 200 ] || fail "$loop: an allowed target got $c"

	# $d (main.acl, and where extra.d would be), rules.d, rules.d/a:
	# neither rules.d/a/deeper nor unrelated.
	check_watches "$GWP_PID" 3 "$loop at startup"

	# Each step counts the reload messages before its change and waits for
	# the one it causes, as the rules are in force a little before the
	# message is logged.

	# A new file that the pattern matches.
	n="$(grep -c "$acl_ok" "$log")"
	printf -- '%s\n' "-A OUTPUT --dports $hp -j REJECT" >"$d/rules.d/a/x.acl"
	wait_code "$pp" "$hp" 403 || \
		fail "$loop: a new matching file was not loaded"
	wait_lines "$log" "$acl_ok" $((n + 1)) || \
		fail "$loop: the reload of the new file was not logged"

	# The same file removed.
	n="$(grep -c "$acl_ok" "$log")"
	rm -f "$d/rules.d/a/x.acl"
	wait_code "$pp" "$hp" 200 || \
		fail "$loop: a removed matching file was not dropped"
	wait_lines "$log" "$acl_ok" $((n + 1)) || \
		fail "$loop: the reload after the removal was not logged"

	# A new directory at the wildcard level, then a file in it.
	n="$(grep -c "$acl_ok" "$log")"
	mkdir "$d/rules.d/b"
	wait_lines "$log" "$acl_ok" $((n + 1)) || \
		fail "$loop: a new directory at a wildcard level did not reload"
	check_watches "$GWP_PID" 4 "$loop with rules.d/b"
	n="$(grep -c "$acl_ok" "$log")"
	printf -- '%s\n' "-A OUTPUT --dports $hp -j REJECT" >"$d/rules.d/b/z.acl"
	wait_code "$pp" "$hp" 403 || \
		fail "$loop: a file in a new directory was not loaded"
	wait_lines "$log" "$acl_ok" $((n + 1)) || \
		fail "$loop: the reload of the file in the new directory was not logged"

	# The missing directory of the include_optional pattern appears, two
	# levels at once; its rule comes first.
	n="$(grep -c "$acl_ok" "$log")"
	mkdir -p "$d/extra.d/q"
	printf -- '%s\n' "-A OUTPUT --dports $hp -j ACCEPT" >"$d/extra.d/q/e.acl"
	wait_code "$pp" "$hp" 200 || \
		fail "$loop: the include_optional directory was not picked up"
	wait_lines "$log" "$acl_ok" $((n + 1)) || \
		fail "$loop: the reload of the new optional directory was not logged"
	# Now extra.d and extra.d/q too.
	check_watches "$GWP_PID" 6 "$loop with extra.d"

	# And taken away again: the watches go with it.
	n="$(grep -c "$acl_ok" "$log")"
	rm -rf "${d:?}/extra.d" "${d:?}/rules.d/b"
	wait_code "$pp" "$hp" 200 || \
		fail "$loop: unexpected status after the removal ($c)"
	wait_lines "$log" "$acl_ok" $((n + 1)) || \
		fail "$loop: the removal of the directories did not reload"
	check_watches "$GWP_PID" 3 "$loop after the removal"

	kill "$GWP_PID"
done

pass
