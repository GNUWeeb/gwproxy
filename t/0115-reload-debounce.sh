#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# With --watch-files=1, a burst of changes to --auth-file and --acl-file is
# reloaded once it has settled, not once per change, and the reload reads the
# last version of each file. Changes that never pause are still reloaded now
# and then rather than waiting for a pause that never comes. Exercised on
# every available event loop.

. "$(dirname "$0")/lib.sh"
require curl
require python3

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 1000
start_httpd "$hp" "$WORK" "1.1"

# fetch <proxy-port> <user> <pass>: succeed iff the proxy let the request
# through to the origin.
fetch()
{
	curl -s --max-time 5 --proxy "socks5h://$2:$3@127.0.0.1:$1" \
		"http://127.0.0.1:$hp/payload.bin" -o /dev/null
}

# wait_fetch <want:0|1> <proxy-port> <user> <pass>: poll until fetch()
# succeeds (want=1) or fails (want=0).
wait_fetch()
{
	local i ok

	for i in $(seq 1 50); do
		ok=0
		fetch "$2" "$3" "$4" && ok=1
		[ "$ok" = "$1" ] && return 0
		sleep 0.1
	done
	return 1
}

# put <file> <contents>: replace <file> by rename, as editors do.
put()
{
	printf '%s' "$2" >"$1.new"
	mv -f "$1.new" "$1"
}

# writer <burst|constant>: change the files from one process, timing each
# change, and print the most reloads the changes may cause, followed by the
# number of the last auth version (constant only).
#
# The reload thread reloads once the files were quiet for 100 ms, or 1 s after
# the first change it has not reloaded yet (GWP_RELOAD_QUIET_MS and
# GWP_RELOAD_MAX_WAIT_MS in gwproxy.c). A reload therefore needs a pause of
# 100 ms between two changes, or 1 s of changes, or the end of the changes. A
# pause is timed from before one change to after the next, so it is never
# shorter than the real one: on a loaded host, where this process can be
# held up for longer than the quiet time, the bound grows with the pauses it
# really took, and on an idle one it is a single reload.
writer()
{
	python3 - "$1" "$WORK/auth" "$WORK/acl" "$allow" "$deny" <<-'PY'
	import os, sys, time
	mode, auth, acl, allow, deny = sys.argv[1:6]
	# Less a few ms: the thread counts whole milliseconds.
	QUIET, MAX_WAIT = 0.1 - 0.005, 1.0 - 0.005
	marks = []

	def put(path, data):
	    # Replace by rename, as editors do.
	    b = time.monotonic()
	    with open(path + ".new", "w") as f:
	        f.write(data)
	    os.rename(path + ".new", path)
	    marks.append((b, time.monotonic()))

	last = 0
	if mode == "burst":
	    # 20 versions of each file, then one more of the ACL. Only the
	    # last versions count: version 20 of the ACL denies the origin,
	    # the one after it allows it again.
	    for i in range(1, 21):
	        put(auth, "u%d:pw\n" % i)
	        put(acl, deny if i == 20 else "# version %d\n%s" % (i, allow))
	    put(acl, allow)
	else:
	    # A change every 20 ms for 3 s.
	    end = time.monotonic() + 3
	    last = 100
	    while time.monotonic() < end:
	        last += 1
	        put(auth, "u%d:pw\n" % last)
	        time.sleep(0.02)
	pauses = sum(1 for (b0, _), (_, a1) in zip(marks, marks[1:])
	             if a1 - b0 >= QUIET)
	span = marks[-1][1] - marks[0][0]
	print(1 + pauses + int(span / MAX_WAIT), last)
	sys.stderr.write("# %s: %d changes in %.3f s, %d pauses of %.0f ms or more\n" %
	                 (mode, len(marks), span, pauses, QUIET * 1000))
	PY
}

# nr_reloads <log> <auth|ACL>: how many reloads of that file were logged.
nr_reloads()
{
	local what="authentication file"

	[ "$2" = ACL ] && what="ACL file"
	grep -c "Reloaded $what" "$1"
}

allow=$'-P INPUT ACCEPT\n-P OUTPUT ACCEPT\n'
deny="-A OUTPUT -d 127.0.0.1 --dports $hp -j REJECT"$'\n'"$allow"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	put "$WORK/auth" $'u0:pw\n'
	put "$WORK/acl" "$allow"
	pp="$(pick_port)"
	log="$WORK/gwp.$pp.log"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --auth-file="$WORK/auth" \
		--acl-file="$WORK/acl" --event-loop="$loop" --nr-workers=1 \
		--watch-files=1
	fetch "$pp" u0 pw || fail "[$loop] initial credentials rejected"

	# A burst of 41 changes, as fast as they can be written.
	read -r most _ < <(writer burst)
	[ -n "${most:-}" ] || fail "[$loop] the burst was not written"
	wait_fetch 1 "$pp" u20 pw \
		|| fail "[$loop] the last version of the auth file was not loaded"
	fetch "$pp" u19 pw \
		&& fail "[$loop] an earlier version of the auth file is in force"
	sleep 1
	a="$(nr_reloads "$log" auth)"
	l="$(nr_reloads "$log" ACL)"
	diag "[$loop] burst of 20: $a auth and $l ACL reloads (at most $most)"
	[ "$a" -le "$most" ] || fail "[$loop] a burst of 20 changes gave $a auth reloads (want at most $most)"
	[ "$l" -le "$most" ] || fail "[$loop] a burst of 21 changes gave $l ACL reloads (want at most $most)"

	# A single change after the burst is reloaded on its own.
	put "$WORK/acl" "$deny"
	wait_fetch 0 "$pp" u20 pw \
		|| fail "[$loop] the last version of the ACL file was not loaded"

	put "$WORK/acl" "$allow"
	wait_fetch 1 "$pp" u20 pw \
		|| fail "[$loop] the ACL file put back was not loaded"

	# Changes every 20 ms for 3 s never pause long enough to settle, yet
	# they are reloaded meanwhile, not only once they stop: one reload
	# when they stop, at least one before.
	a0="$(nr_reloads "$log" auth)"
	read -r most i < <(writer constant)
	[ -n "${i:-}" ] || fail "[$loop] the constant changes were not written"
	wait_fetch 1 "$pp" "u$i" pw \
		|| fail "[$loop] the last of the constant changes was not loaded"
	for _ in $(seq 1 50); do
		a="$(( $(nr_reloads "$log" auth) - a0 ))"
		[ "$a" -ge 2 ] && break
		sleep 0.1
	done
	sleep 1
	a="$(( $(nr_reloads "$log" auth) - a0 ))"
	diag "[$loop] 3 s of constant changes: $a auth reloads (at most $most)"
	[ "$a" -ge 2 ] || fail "[$loop] constant changes held back every reload until they stopped"
	[ "$a" -le "$most" ] || fail "[$loop] constant changes gave $a reloads (want at most $most)"

	kill "$GWP_PID" 2>/dev/null
done

pass
