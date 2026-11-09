#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# SIGHUP reloads --auth-file and the --acl-file set, and the files are not
# watched unless --watch-files=1 asks for it:
#
#  - an edited file is not reloaded on its own, however long it waits, until a
#    SIGHUP comes; then the auth file, the ACL file and the files it includes
#    all take effect at once;
#  - a broken file keeps its current contents in force, the other file still
#    reloads, and a later SIGHUP applies the fixed file;
#  - SIGHUPs that arrive while a reload runs (here one held reading a file
#    with gigabytes of blank lines) give one more reload after it, not one
#    each;
#  - a SIGHUP, even many of them, neither stops the proxy nor disturbs a tunnel
#    in flight, with or without files to reload, and SIGTERM still stops it;
#  - --watch-files=1 reloads a changed file by itself, and SIGHUP still works;
#  - a SIGHUP during startup, before the handler is in place (here while the
#    proxy waits to open a FIFO as its log), is kept pending and taken as a
#    reload, rather than killing the proxy.
#
# Exercised on every available event loop.

. "$(dirname "$0")/lib.sh"
require curl
require python3
require mkfifo
require truncate

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 1000
make_payload "$WORK/big.bin" 1000000
start_httpd "$hp" "$WORK" "1.1"

hup_seen="Received SIGHUP"

# fetch <proxy-port> <user> <pass> [port]: succeed iff the proxy let the
# client in and through to the origin.
fetch()
{
	curl -s --max-time 10 --proxy "socks5h://$2:$3@127.0.0.1:$1" \
		"http://127.0.0.1:${4:-$hp}/payload.bin" -o /dev/null
}

# reading_hold <pid> <log> <n>: wait until the reload after SIGHUP number
# <n>+1 in <log> reads the auth file's blank lines: the read count of <pid>
# grows by tens of MB a second then. Where that count cannot be read, the
# reload has started at least once its SIGHUP is logged.
reading_hold()
{
	local i rc0 rc1

	for i in $(seq 1 300); do
		[ "$(grep -c "$hup_seen" "$2")" -gt "$3" ] && break
		sleep 0.1
	done
	[ "$(grep -c "$hup_seen" "$2")" -gt "$3" ] || return 1
	for i in $(seq 1 100); do
		rc0="$(sed -n 's/^rchar: //p' "/proc/$1/io" 2>/dev/null)"
		[ -n "$rc0" ] || return 0
		sleep 0.1
		rc1="$(sed -n 's/^rchar: //p' "/proc/$1/io" 2>/dev/null)"
		[ -n "$rc1" ] || return 0
		[ $((rc1 - rc0)) -gt 100000 ] && return 0
	done
	return 1
}

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

# --help shows the option.
"$GWPROXY" --help 2>&1 | grep -q -- '--watch-files=0|1' \
	|| fail "--help does not show --watch-files"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	d="$WORK/$loop"
	mkdir -p "$d"
	printf 'alice:pw-a\n' >"$d/auth"
	printf -- '%s\n' '-A OUTPUT --dports 9 -j REJECT' >"$d/inc.acl"
	printf -- '%s\n' 'include inc.acl;' '-P OUTPUT ACCEPT' >"$d/main.acl"

	# A SIGHUP during startup. The log is a FIFO nobody reads yet, so
	# the proxy stays in its startup, opening it, until the reader below
	# comes; the signal sent meanwhile must wait for the handler.
	rm -f "$d/log.fifo"
	mkfifo "$d/log.fifo"
	pp="$(pick_port)"
	"$GWPROXY" --bind="127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--acl-file="$d/main.acl" --log-level=3 \
		--log-file="$d/log.fifo" >"$d/early.out" 2>&1 &
	epid=$!
	_PIDS+=("$epid")
	exe="$(readlink -f "$GWPROXY")"
	held=0
	for i in $(seq 1 300); do
		kill -0 "$epid" 2>/dev/null || break
		if [ "$(readlink "/proc/$epid/exe" 2>/dev/null)" = "$exe" ]; then
			# Where wchan says nothing, a few seconds will do.
			grep -qE 'fifo|partner' "/proc/$epid/wchan" 2>/dev/null && break
			held=$((held + 1))
			[ "$held" -ge 30 ] && break
		fi
		sleep 0.1
	done
	kill -HUP "$epid" 2>/dev/null
	sleep 0.5
	kill -0 "$epid" 2>/dev/null \
		|| fail "[$loop] a SIGHUP during startup killed the proxy"
	cat "$d/log.fifo" >"$d/early.log" &
	_PIDS+=("$!")
	wait_listen "$pp" "$epid" \
		|| fail "[$loop] the proxy did not come up after an early SIGHUP"
	for _ in $(seq 1 300); do
		grep -q 'Reloaded ACL file' "$d/early.log" && break
		sleep 0.1
	done
	grep -q "$hup_seen" "$d/early.log" \
		|| fail "[$loop] a SIGHUP during startup was not taken as a reload"
	grep -q 'Reloaded ACL file' "$d/early.log" \
		|| fail "[$loop] a SIGHUP during startup did not reload the files"
	kill "$epid"
	wait_exit "$epid" || fail "[$loop] the proxy did not exit on SIGTERM"
	pp="$(pick_port)"
	log="$WORK/gwp.$pp.log"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=2 --auth-file="$d/auth" --acl-file="$d/main.acl"
	fetch "$pp" alice pw-a || fail "[$loop] initial credentials rejected"

	# Not watched: an edit, by rename or in place, is left alone for
	# longer than the inotify debounce and the periodic check's settling
	# time put together.
	printf 'bob:pw-b\n' >"$d/auth.new"
	mv -f "$d/auth.new" "$d/auth"
	printf -- '%s\n' "-A OUTPUT --dports $hp -j REJECT" >"$d/inc.acl"
	sleep 7
	fetch "$pp" alice pw-a \
		|| fail "[$loop] the auth file was reloaded without a SIGHUP"
	grep -q 'Reloaded' "$log" \
		&& fail "[$loop] a file was reloaded without a SIGHUP"

	# SIGHUP: both files, and the included one, take effect.
	gwp_hup "$GWP_PID" "$log" 2
	grep -q 'Reloaded authentication file' "$log" \
		|| fail "[$loop] the auth file reload was not logged"
	grep -q 'Reloaded ACL file' "$log" \
		|| fail "[$loop] the ACL file reload was not logged"
	fetch "$pp" alice pw-a \
		&& fail "[$loop] credentials removed by the SIGHUP reload still work"
	rep="$(python3 "$SERVERS_DIR/socks5_probe.py" --host 127.0.0.1 \
		--user bob --pass pw-b --atyp ipv4 --dst 127.0.0.1 "$pp" "$hp" \
		2>/dev/null)"
	[ "$rep" = "REP=0x02" ] \
		|| fail "[$loop] the included file's new rule did not apply ($rep)"
	printf -- '%s\n' '-A OUTPUT --dports 9 -j REJECT' >"$d/inc.acl"
	gwp_hup "$GWP_PID" "$log" 2
	fetch "$pp" bob pw-b \
		|| fail "[$loop] the restored include did not apply"

	# A broken file keeps its contents in force; the other one reloads.
	n_bad="$(grep -c 'Failed to reload ACL file' "$log")"
	printf 'carol:pw-c\n' >"$d/auth"
	printf -- '%s\n' '-A OUTPUT -j BOGUS' >"$d/inc.acl"
	gwp_hup "$GWP_PID" "$log" 2
	[ "$(grep -c 'Failed to reload ACL file' "$log")" = $((n_bad + 1)) ] \
		|| fail "[$loop] the broken ACL file was not reported"
	fetch "$pp" carol pw-c \
		|| fail "[$loop] the auth file did not reload next to a broken ACL"
	rep="$(python3 "$SERVERS_DIR/socks5_probe.py" --host 127.0.0.1 \
		--user carol --pass pw-c --atyp ipv4 --dst 127.0.0.1 "$pp" 9 \
		2>/dev/null)"
	[ "$rep" = "REP=0x02" ] \
		|| fail "[$loop] a broken ACL reload dropped the rules ($rep)"
	n_bad="$(grep -c 'Failed to reload authentication file' "$log")"
	printf -- '%s\n' '-A OUTPUT --dports 9 -j REJECT' >"$d/inc.acl"
	printf '%0300d:x\n' 0 >"$d/auth"
	gwp_hup "$GWP_PID" "$log" 2
	[ "$(grep -c 'Failed to reload authentication file' "$log")" = \
		$((n_bad + 1)) ] \
		|| fail "[$loop] the broken auth file was not reported"
	fetch "$pp" carol pw-c \
		|| fail "[$loop] a broken auth reload dropped the credentials"
	printf 'dave:pw-d\n' >"$d/auth"
	gwp_hup "$GWP_PID" "$log" 2
	fetch "$pp" dave pw-d \
		|| fail "[$loop] the fixed auth file was not applied"

	# A burst of SIGHUPs while a reload runs. The auth file becomes one
	# with gigabytes of blank lines after its contents
	# (t/servers/blank_hold.py), which the reload reads on until the file
	# is cut short through the second link below; ten SIGHUPs meanwhile
	# must give one more reload, not ten.
	rm -f "$d/hold" "$d/hold.lnk"
	python3 "$SERVERS_DIR/blank_hold.py" "$d/hold" $'erin:pw-e\n' \
		>/dev/null || fail "[$loop] cannot write the held auth file"
	ln -f "$d/hold" "$d/hold.lnk"
	mv -f "$d/hold.lnk" "$d/auth"
	n0="$(grep -c "$hup_seen" "$log")"
	kill -HUP "$GWP_PID"
	reading_hold "$GWP_PID" "$log" "$n0" \
		|| fail "[$loop] the SIGHUP reload never started reading the file"
	for _ in $(seq 1 10); do
		kill -HUP "$GWP_PID"
		sleep 0.05
	done
	# The worker keeps serving while the reload is stuck.
	fetch "$pp" dave pw-d \
		|| fail "[$loop] the worker stopped serving during a stuck reload"
	[ "$(grep -c "$hup_seen" "$log")" = $((n0 + 1)) ] \
		|| fail "[$loop] a SIGHUP was taken during the stuck reload"
	# The reload after it reads a regular file again.
	printf 'frank:pw-f\n' >"$d/auth.new"
	mv -f "$d/auth.new" "$d/auth"
	truncate -s 10 "$d/hold"
	rm -f "$d/hold"
	for _ in $(seq 1 300); do
		[ "$(grep -c "$hup_seen" "$log")" -ge $((n0 + 2)) ] && break
		sleep 0.1
	done
	for _ in $(seq 1 300); do
		fetch "$pp" frank pw-f && break
		sleep 0.1
	done
	fetch "$pp" frank pw-f \
		|| fail "[$loop] the reload after the burst did not apply"
	sleep 2
	[ "$(grep -c "$hup_seen" "$log")" = $((n0 + 2)) ] \
		|| fail "[$loop] the burst gave $(( $(grep -c "$hup_seen" "$log") - n0 )) reloads, want 2"

	# SIGHUPs while a tunnel is busy: the transfer goes on unharmed.
	curl -s --max-time 60 --limit-rate 300k \
		--proxy "socks5h://frank:pw-f@127.0.0.1:$pp" \
		"http://127.0.0.1:$hp/big.bin" -o "$d/big.out" &
	cpid=$!
	_PIDS+=("$cpid")
	for _ in $(seq 1 20); do
		kill -HUP "$GWP_PID"
		sleep 0.1
	done
	wait "$cpid" || fail "[$loop] a transfer failed under SIGHUPs"
	assert_files_equal "$WORK/big.bin" "$d/big.out" \
		"[$loop] a transfer was corrupted under SIGHUPs"

	kill "$GWP_PID"
	wait_exit "$GWP_PID" || fail "[$loop] the proxy did not exit on SIGTERM"
	wait "$GWP_PID"
	ec=$?
	[ "$ec" = 0 ] || fail "[$loop] the proxy exited with $ec after SIGHUPs"

	# Neither file: the SIGHUP is logged as having nothing to reload,
	# and the proxy goes on.
	pp="$(pick_port)"
	log="$WORK/gwp.$pp.log"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop"
	gwp_hup "$GWP_PID" "$log" 0
	grep -q 'nothing to reload' "$log" \
		|| fail "[$loop] a SIGHUP without files was not logged"
	fetch "$pp" x y || fail "[$loop] the proxy stopped serving after a SIGHUP"
	kill "$GWP_PID"
	wait_exit "$GWP_PID" || fail "[$loop] the proxy did not exit on SIGTERM"

	# No file option at all, the built-in ACL and the log on stdout: a
	# stray SIGHUP must not kill it either.
	pp="$(pick_port)"
	"$GWPROXY" --bind="127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--log-level=3 >"$WORK/bare.$pp.log" 2>&1 &
	bpid=$!
	_PIDS+=("$bpid")
	wait_listen "$pp" "$bpid" || fail "[$loop] the bare proxy did not listen"
	wait_sig_handled "$bpid" 1 || fail "[$loop] no SIGHUP handler"
	for _ in $(seq 1 3); do
		kill -HUP "$bpid"
		sleep 0.2
	done
	kill -0 "$bpid" 2>/dev/null || fail "[$loop] a SIGHUP killed the proxy"
	rep="$(python3 "$SERVERS_DIR/socks5_probe.py" --host 127.0.0.1 \
		--atyp ipv4 --dst 127.0.0.1 "$pp" "$hp" 2>/dev/null)"
	[ "$rep" = "REP=0x02" ] \
		|| fail "[$loop] the bare proxy did not answer after SIGHUPs ($rep)"
	kill "$bpid"
	wait_exit "$bpid" || fail "[$loop] the bare proxy did not exit on SIGTERM"

	# --watch-files=1: a change reloads by itself, and SIGHUP still works.
	printf 'gina:pw-g\n' >"$d/auth"
	printf -- '%s\n' '-A OUTPUT --dports 9 -j REJECT' >"$d/inc.acl"
	pp="$(pick_port)"
	log="$WORK/gwp.$pp.log"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--watch-files=1 --auth-file="$d/auth" --acl-file="$d/main.acl"
	printf 'hank:pw-h\n' >"$d/auth.new"
	mv -f "$d/auth.new" "$d/auth"
	for _ in $(seq 1 100); do
		fetch "$pp" hank pw-h && break
		sleep 0.1
	done
	fetch "$pp" hank pw-h \
		|| fail "[$loop] --watch-files=1 did not reload a changed file"
	grep -q "$hup_seen" "$log" \
		&& fail "[$loop] a watched reload was taken for a SIGHUP"
	gwp_hup "$GWP_PID" "$log" 2
	kill "$GWP_PID"
	wait_exit "$GWP_PID" || fail "[$loop] the proxy did not exit on SIGTERM"
done

pass
