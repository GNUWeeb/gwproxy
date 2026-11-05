#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Reloading --auth-file or --acl-file must not hold up a worker. A single
# worker proxies while an auth reload is stuck: the file is replaced by a FIFO,
# so the reload a SIGHUP starts blocks opening and reading it until the test
# writes the new contents. In the meantime the worker must keep serving with
# the current credentials; once the contents arrive the reload completes. The
# ACL loader reads regular files only and does not wait on a FIFO in place of
# the ACL file: that reload fails at once and the current rules stay, the
# worker keeps serving throughout, and the proxy still stops on SIGTERM. So the
# ACL half no longer holds a reload stuck; that the reload thread is off the
# worker is shown by the auth half, whose reloads run on the same thread.
# Exercised on every available event loop.

. "$(dirname "$0")/lib.sh"
require curl
require python3
require mkfifo

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

# stuck_replace <file> <contents>: replace <file> by a FIFO, have the proxy
# reload it with SIGHUP and wait until the reload has opened it. The write end
# is held open, so the reload then blocks reading it until $WORK/go appears
# and <contents> is written.
#
# Until $WORK/done appears the writer serves the same contents to any later
# reader too, which settle_replace() then puts in place as a regular file. The
# writer opens the FIFO through a second link, so it still reaches a reader
# that opened <file> before that.
stuck_replace()
{
	rm -f "$WORK/go" "$WORK/ready" "$WORK/done" "$WORK/fifo"
	mkfifo "$WORK/fifo"
	ln -f "$WORK/fifo" "$WORK/fifo.lnk"
	mv -f "$WORK/fifo.lnk" "$1"
	python3 - "$WORK/fifo" "$WORK/ready" "$WORK/go" "$WORK/done" "$2" <<-'PY' &
	import os, sys, time
	fifo, ready, go, done, data = sys.argv[1:]
	def open_reader(until):
	    while time.monotonic() < until:
	        try:
	            return os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
	        except OSError:
	            time.sleep(0.02)
	    return -1
	def serve(fd):
	    # The reader that just got the contents may still hold the FIFO
	    # open (and so let the next open succeed) until it reads the end;
	    # it then leaves without reading, which is harmless.
	    try:
	        os.set_blocking(fd, True)
	        os.write(fd, data.encode())
	    except OSError:
	        pass
	    os.close(fd)
	    time.sleep(0.2)
	end = time.monotonic() + 30
	fd = open_reader(end)
	if fd < 0:
	    sys.exit(1)
	open(ready, "w").close()
	while not os.path.exists(go) and time.monotonic() < end:
	    time.sleep(0.02)
	serve(fd)
	while not os.path.exists(done) and time.monotonic() < end:
	    fd = open_reader(time.monotonic() + 0.05)
	    if fd >= 0:
	        serve(fd)
	PY
	WRITER_PID=$!
	_PIDS+=("$WRITER_PID")
	wait_sig_handled "$GWP_PID" 1 || return 1
	kill -HUP "$GWP_PID" || return 1

	local i
	for i in $(seq 1 100); do
		[ -e "$WORK/ready" ] && return 0
		sleep 0.1
	done
	return 1
}

# finish_replace: let the stuck reload read its contents and finish.
finish_replace()
{
	touch "$WORK/go"
}

# settle_replace <file> <contents>: put <contents> back as a regular file and
# stop the FIFO writer.
settle_replace()
{
	printf '%s' "$2" >"$WORK/settle"
	mv -f "$WORK/settle" "$1"
	sleep 0.5
	touch "$WORK/done"
	wait "$WRITER_PID"
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	printf 'alice:pw-a\n' >"$WORK/auth"
	printf -- '%s\n' '-P INPUT ACCEPT' '-P OUTPUT ACCEPT' >"$WORK/acl"
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --auth-file="$WORK/auth" \
		--acl-file="$WORK/acl" --event-loop="$loop" --nr-workers=1
	fetch "$pp" alice pw-a || fail "[$loop] initial credentials rejected"

	# Auth reload stuck: the worker still serves the current credentials.
	stuck_replace "$WORK/auth" $'bob:pw-b\n' \
		|| fail "[$loop] the auth reload never opened the new file"
	fetch "$pp" alice pw-a \
		|| fail "[$loop] the worker stopped serving during an auth reload"
	finish_replace
	wait_fetch 1 "$pp" bob pw-b \
		|| fail "[$loop] the stuck auth reload was not applied"
	fetch "$pp" alice pw-a \
		&& fail "[$loop] credentials removed by the reload still work"
	settle_replace "$WORK/auth" $'bob:pw-b\n'

	# A FIFO in place of the ACL file: the reload refuses it without
	# opening it for good, so nothing is stuck. The current rules must
	# stay in force, and a valid file put in place afterwards must still
	# be applied.
	acl="-A OUTPUT -d 127.0.0.1 --dports $hp -j REJECT"$'\n-P INPUT ACCEPT\n-P OUTPUT ACCEPT\n'
	rm -f "$WORK/acl.fifo"
	mkfifo "$WORK/acl.fifo"
	mv -f "$WORK/acl.fifo" "$WORK/acl"
	gwp_hup "$GWP_PID" "$WORK/gwp.$pp.log" 2
	fetch "$pp" bob pw-b \
		|| fail "[$loop] the worker stopped serving during an ACL reload"
	grep -q "Failed to reload ACL file" "$WORK/gwp.$pp.log" \
		|| fail "[$loop] the failed ACL reload was not reported"
	grep -q "acl: $WORK/acl: not a regular file" "$WORK/gwp.$pp.log" \
		|| fail "[$loop] the FIFO in place of the ACL file was not reported"
	fetch "$pp" bob pw-b \
		|| fail "[$loop] a failed ACL reload dropped the current rules"
	printf '%s' "$acl" >"$WORK/settle"
	mv -f "$WORK/settle" "$WORK/acl"
	gwp_hup "$GWP_PID" "$WORK/gwp.$pp.log" 2
	wait_fetch 0 "$pp" bob pw-b \
		|| fail "[$loop] the ACL file put in place was not applied"

	# With a FIFO in place again, SIGTERM still stops the proxy: no
	# reload is left stuck on it.
	mkfifo "$WORK/acl.fifo"
	mv -f "$WORK/acl.fifo" "$WORK/acl"
	gwp_hup "$GWP_PID" "$WORK/gwp.$pp.log" 2
	[ "$(grep -c "Failed to reload ACL file" "$WORK/gwp.$pp.log")" -ge 2 ] \
		|| fail "[$loop] the second FIFO was not refused"
	kill "$GWP_PID" 2>/dev/null
	for i in $(seq 1 300); do
		kill -0 "$GWP_PID" 2>/dev/null || break
		sleep 0.1
	done
	kill -0 "$GWP_PID" 2>/dev/null \
		&& fail "[$loop] the proxy did not exit on SIGTERM"
	# The next loop writes the ACL file anew, which would block on a FIFO.
	rm -f "$WORK/acl"
done

pass
