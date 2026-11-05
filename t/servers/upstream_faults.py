#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# An upstream proxy that goes wrong in a chosen way. It reads the fault's name
# from a file when a connection comes in, so one server can serve every case
# of a test, one connection at a time.
#
# Faults of either mode:
#   rst_accept       reset the connection as soon as it is accepted
#
# Faults of the SOCKS5 mode:
#   refuse           answer the CONNECT with REP 0x05
#   bad_method_ver   a method reply of the wrong version
#   bad_ver          a CONNECT reply of the wrong version
#   bad_atyp         a CONNECT reply with an unknown address type
#   close_greeting   hang up instead of answering the greeting
#   close_connect    hang up instead of answering the CONNECT
#   partial_close    hang up halfway through the CONNECT reply
#   rst_connect      reset the connection instead of answering the CONNECT
#   auth_fail        take user/password auth, then refuse the credentials
#
# Faults of the HTTP mode:
#   refuse           answer the CONNECT with 403
#   bad_reply        answer something that is no HTTP
#   bad_status       answer a status line with no status
#   close_connect    hang up instead of answering the CONNECT
#   partial_close    hang up halfway through the reply
#   rst_connect      reset the connection instead of answering the CONNECT
#   auth_required    answer the CONNECT with 407
#   bad_gateway      answer the CONNECT with 502
#
# Usage: upstream_faults.py <socks5|http> <bind_port> <fault_file>
import socket, struct, sys, threading

mode, port, fault_file = sys.argv[1], int(sys.argv[2]), sys.argv[3]
S5_OK_ADDR = b'\x00\x01' + b'\x00' * 6


def rst(c):
    c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))


def socks5(c, fault):
    c.recv(512)
    if fault == 'close_greeting':
        return
    if fault == 'bad_method_ver':
        c.sendall(b'\x04\x00')
        return
    if fault == 'auth_fail':
        c.sendall(b'\x05\x02')
        c.recv(512)
        c.sendall(b'\x01\x01')
        return
    c.sendall(b'\x05\x00')
    c.recv(512)
    if fault == 'close_connect':
        return
    if fault == 'rst_connect':
        rst(c)
    elif fault == 'partial_close':
        c.sendall(b'\x05\x00')
    elif fault == 'bad_atyp':
        c.sendall(b'\x05\x00\x00\x09' + b'\x00' * 6)
    elif fault == 'bad_ver':
        c.sendall(b'\x04\x00' + S5_OK_ADDR)
    elif fault == 'refuse':
        c.sendall(b'\x05\x05' + S5_OK_ADDR)


def http(c, fault):
    c.recv(2048)
    if fault == 'rst_connect':
        rst(c)
    elif fault == 'partial_close':
        c.sendall(b'HTTP/1.1 200')
    elif fault == 'bad_reply':
        c.sendall(b'garbage not http\r\n\r\n')
    elif fault == 'bad_status':
        c.sendall(b'HTTP/1.1 abc nope\r\n\r\n')
    elif fault == 'refuse':
        c.sendall(b'HTTP/1.1 403 Forbidden\r\n\r\n')
    elif fault == 'auth_required':
        c.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\n'
                  b'Proxy-Authenticate: Basic realm="t"\r\n'
                  b'Content-Length: 0\r\n\r\n')
    elif fault == 'bad_gateway':
        c.sendall(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n')


def serve(c, fault):
    try:
        if fault == 'rst_accept':
            rst(c)
        else:
            (socks5 if mode == 'socks5' else http)(c, fault)
    except OSError:
        pass
    c.close()


srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', port))
srv.listen(64)
while True:
    conn, _ = srv.accept()
    with open(fault_file) as f:
        name = f.read().strip()
    threading.Thread(target=serve, args=(conn, name), daemon=True).start()
