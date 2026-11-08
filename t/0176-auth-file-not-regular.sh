#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Only a regular file is read as --auth-file. Opening a FIFO waits for a
# writer, and reading it waits for data, so a FIFO taken for the auth file
# used to hang the proxy at startup, before it listened, and on a reload held
# the reload thread for good, and with it SIGTERM, which waits for that thread.
#
#  - At startup a FIFO is refused at once: the proxy exits with EINVAL (22)
#    and says why.
#  - A FIFO renamed over the auth file is refused by a SIGHUP reload, which
#    says why and keeps the current credentials in force; a regular file put
#    back is applied by the next one; SIGTERM still exits at once.
#  - The same with --watch-files=1, where the rename itself starts a reload.
#  - A reload that fails for another reason, here a missing auth or ACL file,
#    says which.
#
# Exercised on every available event loop.

. "$(dirname "$0")/lib.sh"
require curl
require mkfifo

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 1000
start_httpd "$hp" "$WORK" "1.1"

not_reg="auth: $WORK/auth: not a regular file"

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

# put_fifo: rename a FIFO over $WORK/auth.
put_fifo()
{
	rm -f "$WORK/auth.fifo"
	mkfifo "$WORK/auth.fifo"
	mv -f "$WORK/auth.fifo" "$WORK/auth"
}

# stop_now <loop>: SIGTERM the proxy, which must exit at once and cleanly.
stop_now()
{
	local ec

	kill "$GWP_PID" 2>/dev/null
	wait_gone "$GWP_PID" 50 \
		|| fail "[$1] the proxy did not exit on SIGTERM with a FIFO as its auth file"
	wait "$GWP_PID"
	ec=$?
	[ "$ec" = 0 ] || fail "[$1] the proxy exited with $ec on SIGTERM"
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	# Startup: refused at once, with the reason.
	put_fifo
	pp="$(pick_port)"
	"$GWPROXY" --bind="127.0.0.1:$pp" --as-socks5=1 --acl-allow-all \
		--event-loop="$loop" --auth-file="$WORK/auth" --log-level=3 \
		>"$WORK/start.$pp.log" 2>&1 &
	spid=$!
	_PIDS+=("$spid")
	wait_gone "$spid" 100 || {
		sed 's/^/# gwp: /' "$WORK/start.$pp.log" >&2
		fail "[$loop] the proxy hangs at startup on a FIFO as its auth file"
	}
	wait "$spid"
	ec=$?
	[ "$ec" = 22 ] || fail "[$loop] a FIFO auth file gave exit status $ec, want 22"
	grep -qF "$not_reg" "$WORK/start.$pp.log" \
		|| fail "[$loop] the startup did not say the auth file is no regular file"
	grep -q "Failed to load auth file" "$WORK/start.$pp.log" \
		|| fail "[$loop] the startup did not report the auth file"

	# SIGHUP reload: refused, the current credentials stay, a regular
	# file put back is applied, SIGTERM exits at once.
	printf 'alice:pw-a\n' >"$WORK/auth.new"
	mv -f "$WORK/auth.new" "$WORK/auth"
	pp="$(pick_port)"
	log="$WORK/gwp.$pp.log"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--auth-file="$WORK/auth"
	fetch "$pp" alice pw-a || fail "[$loop] initial credentials rejected"
	put_fifo
	gwp_hup "$GWP_PID" "$log" 1
	grep -q "Failed to reload authentication file" "$log" \
		|| fail "[$loop] the FIFO did not fail the reload"
	grep -qF "$not_reg" "$log" \
		|| fail "[$loop] the reload did not say the auth file is no regular file"
	fetch "$pp" alice pw-a \
		|| fail "[$loop] a refused FIFO dropped the current credentials"
	printf 'bob:pw-b\n' >"$WORK/auth.new"
	mv -f "$WORK/auth.new" "$WORK/auth"
	gwp_hup "$GWP_PID" "$log" 1
	fetch "$pp" bob pw-b \
		|| fail "[$loop] the regular file put back was not applied"
	put_fifo
	gwp_hup "$GWP_PID" "$log" 1
	stop_now "$loop"

	# --watch-files=1: the rename starts the reload, which refuses it.
	printf 'carol:pw-c\n' >"$WORK/auth.new"
	mv -f "$WORK/auth.new" "$WORK/auth"
	pp="$(pick_port)"
	log="$WORK/gwp.$pp.log"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--auth-file="$WORK/auth" --watch-files=1
	put_fifo
	for _ in $(seq 1 100); do
		grep -qF "$not_reg" "$log" && break
		grep -q "Not reloading '$WORK/auth': not a regular file" "$log" \
			&& break
		sleep 0.1
	done
	grep -qF "$not_reg" "$log" ||
		grep -q "Not reloading '$WORK/auth': not a regular file" "$log" ||
		fail "[$loop] the watched FIFO was not refused"
	fetch "$pp" carol pw-c \
		|| fail "[$loop] a watched FIFO dropped the current credentials"
	stop_now "$loop"
	rm -f "$WORK/auth"

	# A reload that fails says why, for the ACL file too.
	printf 'dave:pw-d\n' >"$WORK/auth"
	printf -- '-P INPUT ACCEPT\n-P OUTPUT ACCEPT\n' >"$WORK/acl"
	pp="$(pick_port)"
	log="$WORK/gwp.$pp.log"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--auth-file="$WORK/auth" --acl-file="$WORK/acl"
	rm -f "$WORK/auth" "$WORK/acl"
	gwp_hup "$GWP_PID" "$log" 2
	grep -q "Failed to reload authentication file: No such file or directory" "$log" \
		|| fail "[$loop] a failed auth reload did not say why"
	grep -q "Failed to reload ACL file: No such file or directory" "$log" \
		|| fail "[$loop] a failed ACL reload did not say why"
	fetch "$pp" dave pw-d \
		|| fail "[$loop] a missing auth file dropped the current credentials"
	stop_now "$loop"
done

pass
