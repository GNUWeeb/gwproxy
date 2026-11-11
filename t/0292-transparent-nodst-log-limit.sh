#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A client that connects to a transparent listener (--as-transparent=1)
# directly, with no REDIRECT on the way, has no original destination: the
# proxy closes it right after accept, so it can come back as fast as it can
# connect. Each one used to write a warning, "No original destination for
# <addr>: ...", so such a client could flood the log. The proxy now writes at
# most one line a second per worker, with the number left out since the
# previous one, as for the INPUT chain's refusals.
#
# A flood of 500 direct connections must give only a few lines, and one more
# connection after a pause must log a line that counts every one left out: the
# lines plus the counts they carry add up to the connections made. Run on both
# loops. No privilege is needed: reading the original destination of a direct
# connection fails either way (no conntrack entry, or one that names the
# listener itself).

. "$(dirname "$0")/lib.sh"
require python3

FLOOD=500

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-transparent=1 --event-loop="$loop" \
		--nr-workers=1
	log="$WORK/gwp.$p.log"

	timeout 120 python3 - "$p" "$FLOOD" "$log" <<'PY' \
		|| fail "[$loop] see above"
import math, re, socket, sys, time

port, flood, log = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
LINE = re.compile(r"No original destination for 127\.0\.0\.1:\d+: .* \(not a redirected connection\?\)"
                  r"(?: \(and (\d+) more since the last such line\))?$")


def connect():
    c = socket.create_connection(("127.0.0.1", port), timeout=10)
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
# every one of the flood that was left out.
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
    print("%d lines for %d direct connections in %.2f s; at most %d expected" % (lines, total, spent, limit))
    sys.exit(1)
if lines + quiet != total:
    print("the lines account for %d connections, not %d" % (lines + quiet, total))
    sys.exit(1)
PY
	kill -0 "$GWP_PID" 2>/dev/null || fail "[$loop] proxy died"
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
done

pass
