#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# A TCP endpoint that refuses a connect about a second after it has begun:
# it leaves the first SYN unanswered, as blackhole_listener.py does, and is
# gone by the time the SYN is sent again, which is then answered with a
# reset. The connect fails with ECONNREFUSED one initial retransmission
# timeout (1 s on Linux) after it began, which a test can put just before a
# --connect-timeout.
#
# Prints the bound port on stdout. Once a connect from anybody but itself
# is in SYN_SENT towards it (/proc/net/tcp), closes the listener and the
# connections that fill its accept queue, prints "CLOSED", and exits; after
# <limit> seconds (default 120) without one, exits with 1.
#
# Usage: refuse_on_syn_retry.py <ipv4 addr> [<limit>]

import socket
import sys
import time

SYN_SENT = "02"


def syn_sent_to(port, own):
    """Whether a socket other than one of @own is in SYN_SENT to @port."""
    with open("/proc/net/tcp") as f:
        next(f)
        for line in f:
            fld = line.split()
            lport = int(fld[1].split(":")[1], 16)
            rport = int(fld[2].split(":")[1], 16)
            if fld[3] == SYN_SENT and rport == port and lport not in own:
                return True
    return False


def main():
    host = sys.argv[1]
    limit = float(sys.argv[2]) if len(sys.argv) > 2 else 120.0

    ls = socket.socket()
    ls.bind((host, 0))
    ls.listen(0)
    port = ls.getsockname()[1]

    # Fill the accept queue, so that no later SYN is answered.
    fillers = []
    for _ in range(16):
        c = socket.socket()
        c.setblocking(False)
        c.connect_ex((host, port))
        fillers.append(c)
    own = set(c.getsockname()[1] for c in fillers)

    print(port, flush=True)
    end = time.monotonic() + limit
    while not syn_sent_to(port, own):
        if time.monotonic() > end:
            sys.exit(1)
        time.sleep(0.01)

    for c in fillers:
        c.close()
    ls.close()
    print("CLOSED", flush=True)


if __name__ == "__main__":
    main()
