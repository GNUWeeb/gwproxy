#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Run a program with every sendto() of exactly <len> bytes failing with
# EAGAIN, as a send to a socket whose send buffer is full does. The other
# sends go through. A seccomp filter does it, so no privilege is needed;
# it does not reach io_uring's sends, which are not system calls.
#
# Usage: seccomp_send_eagain.py <len> <program> [args...]
# Exits 77 where the filter cannot be installed (unknown architecture, or
# seccomp not available).

import ctypes
import errno
import os
import platform
import struct
import sys

# (AUDIT_ARCH_*, sendto); both little-endian, 64-bit arguments.
ARCHES = {
    "x86_64": (0xC000003E, 44),
    "aarch64": (0xC00000B7, 206),
}

PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
BPF_LD_W_ABS = 0x20
BPF_JEQ_K = 0x15
BPF_RET_K = 0x06
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000
# struct seccomp_data: nr, arch, instruction_pointer, args[6].
OFF_NR, OFF_ARCH, OFF_ARG2_LO, OFF_ARG2_HI = 0, 4, 32, 36


def ins(code, jt, jf, k):
    return struct.pack("HBBI", code, jt, jf, k)


def main():
    arch = ARCHES.get(platform.machine())
    if arch is None:
        sys.stderr.write("no seccomp table for %s\n" % platform.machine())
        sys.exit(77)
    audit, nr_sendto = arch
    length = int(sys.argv[1])

    prog = b"".join([
        ins(BPF_LD_W_ABS, 0, 0, OFF_ARCH),
        ins(BPF_JEQ_K, 0, 6, audit),
        ins(BPF_LD_W_ABS, 0, 0, OFF_NR),
        ins(BPF_JEQ_K, 0, 4, nr_sendto),
        ins(BPF_LD_W_ABS, 0, 0, OFF_ARG2_LO),
        ins(BPF_JEQ_K, 0, 2, length),
        ins(BPF_LD_W_ABS, 0, 0, OFF_ARG2_HI),
        ins(BPF_JEQ_K, 1, 0, 0),
        ins(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
        ins(BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | errno.EAGAIN),
    ])
    buf = ctypes.create_string_buffer(prog, len(prog))

    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]

    fprog = SockFprog(len(prog) // 8, ctypes.addressof(buf))
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                           ctypes.c_ulong, ctypes.c_ulong]
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) or \
       libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
                  ctypes.addressof(fprog), 0, 0):
        sys.stderr.write("seccomp: %s\n" % os.strerror(ctypes.get_errno()))
        sys.exit(77)
    os.execv(sys.argv[2], sys.argv[2:])


if __name__ == "__main__":
    main()
