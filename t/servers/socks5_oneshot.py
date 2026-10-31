#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Send raw bytes to the proxy in one write, then read until the proxy
# closes the connection (or the timeout runs out) and print what came back
# as hex, followed by " CLOSED" or " OPEN" for how the read ended.
#
# With --split, each further hex argument is sent in a write of its own
# once the proxy answered the one before; the answers are printed in
# order, separated by spaces.
#
# Usage: socks5_oneshot.py [--timeout S] [--split] port hexbytes...
import socket, sys

argv = sys.argv[1:]
timeout = 3.0
split = False
while argv and argv[0].startswith('--'):
    if argv[0] == '--timeout':
        timeout = float(argv[1])
        argv = argv[2:]
    elif argv[0] == '--split':
        split = True
        argv = argv[1:]
    else:
        sys.exit('unknown option ' + argv[0])

port = int(argv[0])
chunks = [bytes.fromhex(a) for a in argv[1:]]
if not split:
    chunks = [b''.join(chunks)]

s = socket.create_connection(('127.0.0.1', port), timeout=10)
s.settimeout(timeout)
out = []
for c in chunks[:-1]:
    s.sendall(c)
    try:
        out.append(s.recv(4096).hex())
    except socket.timeout:
        out.append('-')

s.sendall(chunks[-1])
got = b''
end = 'CLOSED'
try:
    while True:
        b = s.recv(4096)
        if not b:
            break
        got += b
except socket.timeout:
    end = 'OPEN'
except ConnectionResetError:
    pass
s.close()
out.append(got.hex())
print(' '.join(out), end)
