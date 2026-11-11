#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A client the --acl-file INPUT chain rejects is closed right after accept, so
# it can come back as fast as it can connect. Each refusal used to write an
# info line, "ACL denied client <addr>", so such a client could flood the log
# and fill the disk. The proxy now writes at most one line a second per worker,
# with the number of refusals left out since the previous one.
#
# A flood of 1000 connections from a rejected address must give only a few
# lines, and one more connection after a pause must log a line that counts
# every refusal left out: the lines plus the counts they carry add up to the
# connections made. Run on both loops.

. "$(dirname "$0")/lib.sh"
require python3

FLOOD=1000
DENIED=127.0.0.77

printf -- '%s\n' \
	"-A INPUT -s $DENIED/32 -j REJECT" \
	'-P INPUT ACCEPT' \
	'-P OUTPUT ACCEPT' >"$WORK/deny.acl"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1 --acl-file="$WORK/deny.acl"
	log="$WORK/gwp.$p.log"

	timeout 120 python3 - "$p" "$DENIED" "$FLOOD" "$log" <<'PY' \
		|| fail "[$loop] see above"
import math, re, socket, sys, time

port, denied, flood, log = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), sys.argv[4]
LINE = re.compile(r"ACL denied client %s:\d+(?: \(and (\d+) more since the last such line\))?$"
                  % re.escape(denied))


def connect():
    c = socket.socket()
    c.bind((denied, 0))
    c.settimeout(10)
    c.connect(("127.0.0.1", port))
    c.close()


def tally():
    lines = quiet = 0
    with open(log) as f:
        for l in f:
            m = LINE.search(l.rstrip("\n"))
            if m:
                lines += 1
                quiet += int(m.group(1) or 0)
    return lines, quiet


t0 = time.monotonic()
for _ in range(flood):
    connect()
spent = time.monotonic() - t0

# The next line may come a second after the last one, at the coarse clock's
# resolution: after more than two, this connection's line is due, and counts
# every refusal of the flood that was left out.
time.sleep(2.2)
connect()
total = flood + 1
end = time.monotonic() + 30
while True:
    lines, quiet = tally()
    if lines + quiet >= total or time.monotonic() > end:
        break
    time.sleep(0.1)

print("%d connections in %.2f s: %d lines, %d more counted" % (total, spent, lines, quiet))
# One line at the start, one per second boundary crossed, the last one.
limit = math.ceil(spent) + 3
if lines > limit:
    print("%d lines for %d refusals in %.2f s; at most %d expected" % (lines, total, spent, limit))
    sys.exit(1)
if lines + quiet != total:
    print("the lines account for %d refusals, not %d" % (lines + quiet, total))
    sys.exit(1)
PY
	kill -0 "$GWP_PID" 2>/dev/null || fail "[$loop] proxy died"
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
done

pass
