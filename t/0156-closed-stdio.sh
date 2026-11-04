#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The default log target is fd 1. Started with stdout closed, the next
# descriptor the proxy opened took that number, so log lines went into the PID
# file or a socket, and a write to an unconnected socket killed it with
# SIGPIPE, which was ignored only after startup. A stdout pipe with no reader
# did the same. A closed standard descriptor must stay out of the way, and a log
# target nobody reads must not stop the proxy.

. "$(dirname "$0")/lib.sh"
require python3

closed_port
tp="$CLOSED_PORT"

# run_closed <what> <fds that end up on /dev/null> <redirections...>: start the
# proxy with those descriptors closed, check that it survives connections and
# that its PID file holds nothing but the PID. eval, as a redirection cannot
# come from a variable.
run_closed()
{
	local what="$1" fds="$2" close="$3" pp pid i fd pf="$WORK/pid.$RANDOM"

	pp="$(pick_port)"
	eval '"$GWPROXY" --bind="127.0.0.1:$pp" --target="127.0.0.1:$tp" \
		--nr-workers=1 --acl-allow-all --pid-file="$pf" '"$close"' &'
	pid=$!
	_PIDS+=("$pid")
	wait_listen "$pp" "$pid" || fail "$what: proxy did not listen"

	# Each connection logs a line.
	for i in 1 2 3 4 5; do
		(exec 3<>"/dev/tcp/127.0.0.1/$pp") 2>/dev/null
	done
	kill -0 "$pid" 2>/dev/null || fail "$what: proxy died"

	for fd in $fds; do
		[ "$(readlink "/proc/$pid/fd/$fd")" = /dev/null ] ||
			fail "$what: fd $fd is $(readlink "/proc/$pid/fd/$fd")"
	done
	[ "$(cat "$pf")" = "$pid" ] ||
		fail "$what: PID file holds: $(head -c 300 "$pf")"

	wait_sigterm_handled "$pid" || fail "$what: no SIGTERM handler"
	kill "$pid" 2>/dev/null
	wait "$pid"
	i=$?
	[ "$i" = 0 ] || fail "$what: exit status $i after SIGTERM"
}

run_closed "stdout closed" 1 '>&- 2>/dev/null'
run_closed "stdin closed" 0 '<&- >/dev/null 2>&1'
run_closed "stderr closed" 2 '2>&- >/dev/null'
run_closed "all closed" "0 1 2" '<&- >&- 2>&-'

# With no PID file the first descriptor opened after a closed stdout is a
# socket, and the first log line used to end the process with SIGPIPE. Started
# from python so SIGPIPE is at its default whatever this shell inherited.
PORT="$(pick_port)" python3 - "$GWPROXY" "$tp" <<'PY' ||
import os, signal, socket, subprocess, sys, time

gw, target = sys.argv[1:]
port = int(os.environ["PORT"])
args = [gw, "--bind=127.0.0.1:%d" % port, "--target=127.0.0.1:" + target,
        "--nr-workers=1", "--acl-allow-all"]


def run(what, **kw):
    p = subprocess.Popen(args, stderr=subprocess.DEVNULL, **kw)
    end = time.time() + 60
    while time.time() < end and p.poll() is None:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=5).close()
            break
        except OSError:
            time.sleep(0.1)
    # The listener comes up before the SIGTERM handler does.
    while time.time() < end and p.poll() is None:
        with open("/proc/%d/status" % p.pid) as f:
            cgt = [l for l in f if l.startswith("SigCgt:")][0].split()[1]
        if int(cgt, 16) & (1 << (signal.SIGTERM - 1)):
            break
        time.sleep(0.1)
    if p.poll() is not None:
        sys.exit("%s: exit status %d at startup" % (what, p.returncode))
    p.send_signal(signal.SIGTERM)
    rc = p.wait(60)
    if rc:
        sys.exit("%s: exit status %d after SIGTERM" % (what, rc))


def close_stdout():
    os.close(1)


run("stdout closed, no PID file", preexec_fn=close_stdout)

# A pipe whose reader has gone.
r, w = os.pipe()
os.close(r)
run("stdout a pipe with no reader", stdout=w)
os.close(w)
PY
	fail "the log target stopped the proxy"

pass
