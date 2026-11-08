#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A NUL byte anywhere in a line of --auth-file refuses the file, with the
# number of the line. One at the start of a line used to make the line read
# as blank, so the loader skipped it in silence; one inside a line was
# refused, but as "too long".
#
#  - At startup, a NUL at the start of a line and one inside a line each make
#    the proxy exit with EINVAL (22) and say which line holds it.
#  - On a SIGHUP reload, each fails the reload, which says which line, and
#    the current credentials stay in force; a clean file is applied by the
#    next SIGHUP.
#
# Exercised on every available event loop.

. "$(dirname "$0")/lib.sh"
require curl

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

# wait_gone <pid> <tenths>: poll until <pid> is gone, at most <tenths>/10 s.
wait_gone()
{
	local i

	for i in $(seq 1 "$2"); do
		kill -0 "$1" 2>/dev/null || return 0
		sleep 0.1
	done
	return 1
}

# put_auth <printf-format>: rename a file made by printf over $WORK/auth.
put_auth()
{
	# shellcheck disable=SC2059
	printf "$1" >"$WORK/auth.new"
	mv -f "$WORK/auth.new" "$WORK/auth"
}

# The bad files: a NUL at the start of line 2 (it hides the line after it
# from a loader that takes it for a blank line) and one inside line 2.
lead='alice:pw-a\n\000mallory:pw-m\n'
mid='alice:pw-a\nmallory:pw\000-m\n'

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	# Startup: refused, naming the line.
	for f in lead mid; do
		put_auth "${!f}"
		[ "$(wc -c <"$WORK/auth")" -gt 20 ] \
			|| fail "printf did not write the NUL byte"
		pp="$(pick_port)"
		slog="$WORK/start.$f.$pp.log"
		"$GWPROXY" --bind="127.0.0.1:$pp" --as-socks5=1 \
			--acl-allow-all --event-loop="$loop" \
			--auth-file="$WORK/auth" --log-level=3 >"$slog" 2>&1 &
		spid=$!
		_PIDS+=("$spid")
		wait_gone "$spid" 100 || {
			sed 's/^/# gwp: /' "$slog" >&2
			fail "[$loop] the proxy started with a NUL byte ($f) in its auth file"
		}
		wait "$spid"
		ec=$?
		[ "$ec" = 22 ] \
			|| fail "[$loop] a NUL byte ($f) in the auth file gave exit status $ec, want 22"
		grep -q "auth: line 2 holds a NUL byte" "$slog" || {
			sed 's/^/# gwp: /' "$slog" >&2
			fail "[$loop] the startup did not name the line with the NUL byte ($f)"
		}
	done

	# SIGHUP reload: refused, naming the line; the current credentials
	# stay, and a clean file is applied by the next SIGHUP.
	put_auth 'alice:pw-a\n'
	pp="$(pick_port)"
	log="$WORK/gwp.$pp.log"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--auth-file="$WORK/auth"
	fetch "$pp" alice pw-a || fail "[$loop] initial credentials rejected"
	for f in lead mid; do
		put_auth "${!f}"
		n="$(grep -c "auth: line 2 holds a NUL byte" "$log")"
		nf="$(grep -c "Failed to reload authentication file" "$log")"
		gwp_hup "$GWP_PID" "$log" 1
		[ "$(grep -c "auth: line 2 holds a NUL byte" "$log")" -gt "$n" ] \
			|| fail "[$loop] the reload did not name the line with the NUL byte ($f)"
		[ "$(grep -c "Failed to reload authentication file" "$log")" -gt "$nf" ] \
			|| fail "[$loop] a NUL byte ($f) did not fail the reload"
		fetch "$pp" alice pw-a \
			|| fail "[$loop] a refused reload ($f) dropped the current credentials"
		fetch "$pp" mallory pw-m \
			&& fail "[$loop] a user from the refused file ($f) got in"
	done
	put_auth 'bob:pw-b\n'
	gwp_hup "$GWP_PID" "$log" 1
	fetch "$pp" bob pw-b \
		|| fail "[$loop] the clean file after the refused ones was not applied"
	fetch "$pp" alice pw-a \
		&& fail "[$loop] credentials removed by the clean file still work"
	kill "$GWP_PID" 2>/dev/null
	wait_gone "$GWP_PID" 100 || fail "[$loop] the proxy did not stop on SIGTERM"
done

pass
