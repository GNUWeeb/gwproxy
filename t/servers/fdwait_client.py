#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# A plain forwarding client that waits for its target socket: the proxy's
# descriptor table is full when it is accepted, so the proxy keeps it and
# retries the target connect (log: "retrying the target connect"). What the
# client then does is the test.
#
# Usage: fdwait_client.py <proxy port> <proxy pid> <proxy log> <target log>
#                         <action> [protocol timeout]
#
# The proxy must run one worker in plain forwarding to an echo target that
# writes one "accept" line to <target log> per connection and closes once the
# client has half-closed. The soft RLIMIT_NOFILE of the proxy is lowered so
# that a single descriptor number is free below it, so the client's accept
# takes the last slot, and raised back afterwards. Actions:
#
#   rst    reset the waiting client: within 3 s the proxy is back at its idle
#          descriptor count, and once descriptors are free again the target
#          is not dialled for it.
#   fin    half-close the waiting client at --connect-timeout=0: the proxy
#          ends the pair after about the protocol timeout (the last argument),
#          and the target is not dialled for it. The proxy does not spin
#          meanwhile.
#   data   send some bytes while waiting, then free descriptors: they reach
#          the target and come back.
#   datafin  likewise, but half-close right after the bytes: they come back,
#          then the end of stream.
#
# Exits 0 on success, 1 on failure, 77 when the limit cannot be changed.

import os
import resource
import socket
import struct
import sys
import time

port, pid = int(sys.argv[1]), int(sys.argv[2])
plog, tlog, action = sys.argv[3], sys.argv[4], sys.argv[5]
ptmo = int(sys.argv[6]) if len(sys.argv) > 6 else 0


def nr_fds():
    return len(os.listdir("/proc/%d/fd" % pid))


def settled():
    last, same, end = nr_fds(), 0, time.time() + 20
    while same < 5 and time.time() < end:
        time.sleep(0.2)
        cur = nr_fds()
        same = same + 1 if cur == last else 0
        last = cur
    return last


def wait_for(cond, limit):
    end = time.monotonic() + limit
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return cond()


def cpu_s():
    with open("/proc/%d/stat" % pid) as f:
        st = f.read().rsplit(")", 1)[1].split()
    return (int(st[11]) + int(st[12])) / os.sysconf("SC_CLK_TCK")


def read(path):
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def dials():
    return read(tlog).count("accept")


def bye(msg, rc=1):
    print(msg)
    sys.exit(rc)


def recv_all(c, n, limit):
    c.settimeout(limit)
    got = b""
    try:
        while len(got) < n:
            b = c.recv(n - len(got))
            if not b:
                break
            got += b
    except (socket.timeout, OSError) as e:
        return got, repr(e)
    return got, None


base = settled()
nr_waits = read(plog).count("retrying the target connect")
dials0 = dials()
soft, hard = resource.prlimit(pid, resource.RLIMIT_NOFILE)


def one_slot_limit():
    """The limit that leaves exactly one descriptor number free below it.
    RLIMIT_NOFILE bounds numbers, not the count: under make -j the proxy
    inherits high-numbered descriptors (the jobserver's), so the idle
    count plus one would leave several low numbers free."""
    used = {int(f) for f in os.listdir("/proc/%d/fd" % pid)}
    free, n = 0, 0
    while True:
        if n not in used:
            free += 1
            if free == 2:
                return n
        n += 1


try:
    resource.prlimit(pid, resource.RLIMIT_NOFILE, (one_slot_limit(), hard))
except (OSError, ValueError) as e:
    bye("cannot lower the limit: %r" % e, 77)


def unlimit():
    resource.prlimit(pid, resource.RLIMIT_NOFILE, (soft, hard))


c = socket.create_connection(("127.0.0.1", port), timeout=5)
if not wait_for(lambda: read(plog).count("retrying the target connect") >
                nr_waits, 10):
    unlimit()
    bye("the client never waited for its target socket (idle fds %d)" % base)
time.sleep(0.3)

if action == "rst":
    c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    c.close()
    t0 = time.monotonic()
    ok = wait_for(lambda: nr_fds() <= base, 3)
    dt = time.monotonic() - t0
    if not ok:
        unlimit()
        bye("the reset client still held its descriptor %.1f s later "
            "(%d fds, idle %d)" % (dt, nr_fds(), base))
    unlimit()
    # Ten retry periods with descriptors to spare.
    time.sleep(1.0)
    if dials() != dials0:
        bye("the target was dialled for the client that had reset")
    # The proxy serves the next client as usual.
    n = socket.create_connection(("127.0.0.1", port), timeout=5)
    n.sendall(b"next")
    got, err = recv_all(n, 4, 5)
    n.close()
    if got != b"next":
        bye("the next client was not served: %r %s" % (got, err))
    print("pair ended %.2f s after the reset, target not dialled" % dt)

elif action == "fin":
    c.shutdown(socket.SHUT_WR)
    t0, cpu0 = time.monotonic(), cpu_s()
    got, err = recv_all(c, 1, ptmo + 6)
    dt, cpu = time.monotonic() - t0, cpu_s() - cpu0
    c.close()
    # A spinning worker burns the whole wait; retrying every 100 ms is far
    # below this, also under the sanitizers.
    if cpu > dt / 2:
        unlimit()
        bye("the proxy used %.2f s of CPU in the %.2f s wait" % (cpu, dt))
    if err and "timed out" in err:
        unlimit()
        bye("the half-closed client was still open %.1f s later" % dt)
    if got:
        unlimit()
        bye("the half-closed client got data: %r" % got)
    if dt < ptmo - 0.5:
        unlimit()
        bye("the half-closed client was closed after %.2f s, before the "
            "%d s protocol timeout" % (dt, ptmo))
    if not wait_for(lambda: nr_fds() <= base, 3):
        unlimit()
        bye("the pair kept its descriptor (%d fds, idle %d)"
            % (nr_fds(), base))
    unlimit()
    time.sleep(1.0)
    if dials() != dials0:
        bye("the target was dialled for the client that had left")
    print("half-closed client closed after %.2f s (%s), %.2f s of CPU"
          % (dt, err or "end of stream", cpu))

elif action in ("data", "datafin"):
    c.sendall(b"early")
    if action == "datafin":
        c.shutdown(socket.SHUT_WR)
    time.sleep(0.3)
    if dials() != dials0:
        unlimit()
        bye("the target was dialled while the table was full")
    unlimit()
    got, err = recv_all(c, 5, 5)
    if got != b"early":
        c.close()
        bye("the early bytes did not come back: %r %s" % (got, err))
    if action == "datafin":
        rest, err = recv_all(c, 1, 5)
        if rest or err:
            c.close()
            bye("no end of stream after the echo: %r %s" % (rest, err))
    c.close()
    print("early bytes delivered once descriptors were free")

else:
    bye("unknown action %r" % action)
