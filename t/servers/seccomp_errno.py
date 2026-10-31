#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Run a program with accept() and accept4() failing with a given errno, as
# when a security module refuses every connection or the kernel is out of
# socket memory. A seccomp filter does it, so no privilege is needed; it
# does not reach io_uring's accept, which is not a system call.
#
# Usage: seccomp_errno.py <errno name> <program> [args...]
# Exits 77 where the filter cannot be installed (unknown architecture, or
# seccomp not available).

import ctypes
import errno
import os
import platform
import struct
import sys

# (AUDIT_ARCH_*, accept, accept4)
ARCHES = {
    "x86_64": (0xC000003E, 43, 288),
    "aarch64": (0xC00000B7, 202, 242),
}

PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
BPF_LD_W_ABS = 0x20
BPF_JEQ_K = 0x15
BPF_RET_K = 0x06
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000


def ins(code, jt, jf, k):
    return struct.pack("HBBI", code, jt, jf, k)


def main():
    arch = ARCHES.get(platform.machine())
    if arch is None:
        sys.stderr.write("no seccomp table for %s\n" % platform.machine())
        sys.exit(77)
    audit, nr_accept, nr_accept4 = arch
    err = getattr(errno, sys.argv[1])

    prog = b"".join([
        ins(BPF_LD_W_ABS, 0, 0, 4),             # seccomp_data.arch
        ins(BPF_JEQ_K, 0, 3, audit),
        ins(BPF_LD_W_ABS, 0, 0, 0),             # seccomp_data.nr
        ins(BPF_JEQ_K, 2, 0, nr_accept4),
        ins(BPF_JEQ_K, 1, 0, nr_accept),
        ins(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
        ins(BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | err),
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
