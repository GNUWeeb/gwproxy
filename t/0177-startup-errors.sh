#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Startup checks and their exit status.
#
#  - --bind-source takes a port of decimal digits only, 0 to 65535. Trailing
#    characters, an empty port or one out of range are refused with EINVAL
#    (22) and a message naming the option; so are a sign and leading blanks,
#    which strtoul() took: "+80" and " 80" passed for 80, and a "-" value
#    wrapped around, "-18446744073709551535" giving port 81.
#  - A SIGTERM or SIGINT that arrives once the proxy listens but before its
#    handler is in place stops it cleanly, with status 0 and its PID file
#    removed, instead of killing it with the default action. strace holds the
#    proxy in that window by delaying the return from listen(2).

. "$(dirname "$0")/lib.sh"

# Leak checking does not work under ptrace.
export ASAN_OPTIONS="${ASAN_OPTIONS:+$ASAN_OPTIONS:}detect_leaks=0"

closed_port
tp="$CLOSED_PORT"

# start_bad <what> <exit-status> <message> <args...>: gwproxy must refuse to
# start with <args>, exit with <exit-status> and log <message> (fixed string).
start_bad()
{
	local what="$1" want="$2" msg="$3" pp ec out
	shift 3

	pp="$(pick_port)"
	out="$WORK/bad.$pp.log"
	timeout 20 "$GWPROXY" --bind="127.0.0.1:$pp" --target="127.0.0.1:$tp" \
		--acl-allow-all --log-level=3 "$@" >"$out" 2>&1
	ec=$?
	[ "$ec" = "$want" ] || {
		sed 's/^/# gwp: /' "$out" >&2
		fail "$what: exit status $ec, want $want"
	}
	grep -qF -- "$msg" "$out" || {
		sed 's/^/# gwp: /' "$out" >&2
		fail "$what: no '$msg' in the log"
	}
}

for v in '127.0.0.1:80x' '127.0.0.1:65536' '127.0.0.1:' '127.0.0.1:+80' \
	 '127.0.0.1: 80' '[::1]:-18446744073709551535' '[::1]:+0' \
	 '[::1]:99999999999999999999'; do
	start_bad "--bind-source=$v" 22 "Invalid --bind-source value '$v'" \
		--bind-source="$v"
done

# A good one still starts.
pp="$(pick_port)"
gwp_start "127.0.0.1:$pp" --target="127.0.0.1:$tp" --bind-source=127.0.0.1:0
grep -q 'bind to source 127.0.0.1' "$WORK/gwp.$pp.log" \
	|| fail "--bind-source=127.0.0.1:0 was not taken"
kill "$GWP_PID"

# early_stop <loop> <signal>: send <signal> while the proxy listens but has
# no handler yet; it must exit with 0 and remove its PID file. The proxy is
# started with SIGINT at its default action: bash starts a background command
# with SIGINT ignored, and an ignored signal says nothing.
early_stop()
{
	local loop="$1" sig="$2" pp spid gpid i bit cgt ec

	pp="$(pick_port)"
	python3 -c 'import os, signal, sys
signal.signal(signal.SIGINT, signal.SIG_DFL)
os.execvp(sys.argv[1], sys.argv[1:])' \
		strace -f -qq -o "$WORK/strace.$pp" -e trace=listen \
		-e inject=listen:delay_exit=6000000 \
		"$GWPROXY" --event-loop="$loop" --nr-workers=1 \
		--bind="127.0.0.1:$pp" --target="127.0.0.1:$tp" \
		--acl-allow-all --log-level=3 --pid-file="$WORK/pid.$pp" \
		>"$WORK/early.$pp.log" 2>&1 &
	spid=$!
	_PIDS+=("$spid")

	# Listening, and held in the delayed return from listen(2).
	for i in $(seq 1 300); do
		(exec 3<>"/dev/tcp/127.0.0.1/$pp") 2>/dev/null && break
		kill -0 "$spid" 2>/dev/null || break
		sleep 0.05
	done
	gpid="$(cat "/proc/$spid/task/$spid/children" 2>/dev/null)"
	gpid="${gpid%% *}"
	[ -n "$gpid" ] || fail "[$loop] SIG$sig: cannot find the traced proxy"
	_PIDS=("$gpid" "${_PIDS[@]}")
	grep -q 'listen(' "$WORK/strace.$pp" \
		|| fail "[$loop] SIG$sig: strace did not see listen()"
	bit=$(( 1 << (15 - 1) ))
	[ "$sig" = INT ] && bit=$(( 1 << (2 - 1) ))
	cgt="$(sed -n 's/^SigCgt:[[:space:]]*//p' "/proc/$gpid/status")"
	[ -n "$cgt" ] && [ $(( 0x$cgt & bit )) = 0 ] \
		|| fail "[$loop] SIG$sig: the handler was in place already; the test missed its window"

	kill -"$sig" "$gpid"
	for i in $(seq 1 300); do
		kill -0 "$spid" 2>/dev/null || break
		sleep 0.1
	done
	kill -0 "$spid" 2>/dev/null \
		&& fail "[$loop] SIG$sig before the handler did not stop the proxy"
	wait "$spid"
	ec=$?
	[ "$ec" = 0 ] || {
		sed 's/^/# gwp: /' "$WORK/early.$pp.log" >&2
		fail "[$loop] SIG$sig before the handler: exit status $ec, want 0"
	}
	[ ! -e "$WORK/pid.$pp" ] \
		|| fail "[$loop] SIG$sig before the handler left the PID file behind"
}

if command -v strace >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
	for loop in epoll io_uring; do
		[ "$loop" = io_uring ] && ! have_io_uring && continue
		early_stop "$loop" TERM
		early_stop "$loop" INT
	done
else
	diag "no strace or python3: a signal before the handler is not checked"
fi

pass
