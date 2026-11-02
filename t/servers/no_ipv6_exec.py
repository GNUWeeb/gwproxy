#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Run a program as if on a kernel without IPv6 (booted with ipv6.disable=1):
# socket(AF_INET6, ...) fails with EAFNOSUPPORT, through a seccomp filter. Every
# other system call is untouched.
#
# Usage: no_ipv6_exec.py program [args...]
#
# Exits 77 where the filter cannot be installed here.
import ctypes, errno, os, platform, socket, struct, sys

ARCHES = {
    'x86_64': (0xc000003e, 41),
    'aarch64': (0xc00000b7, 198),
}
if platform.machine() not in ARCHES:
    sys.exit(77)
audit_arch, nr_socket = ARCHES[platform.machine()]

BPF_LD_W_ABS, BPF_JEQ_K, BPF_RET_K = 0x20, 0x15, 0x06
SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO = 0x7fff0000, 0x00050000
PR_SET_SECCOMP, SECCOMP_MODE_FILTER = 22, 2
PR_SET_NO_NEW_PRIVS = 38


def ins(code, jt, jf, k):
    return struct.pack('HBBI', code, jt, jf, k)


# struct seccomp_data: nr at 0, arch at 4, args[0] at 16.
prog = b''.join([
    ins(BPF_LD_W_ABS, 0, 0, 4),
    ins(BPF_JEQ_K, 0, 4, audit_arch),
    ins(BPF_LD_W_ABS, 0, 0, 0),
    ins(BPF_JEQ_K, 0, 2, nr_socket),
    ins(BPF_LD_W_ABS, 0, 0, 16),
    ins(BPF_JEQ_K, 1, 0, socket.AF_INET6),
    ins(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
    ins(BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | errno.EAFNOSUPPORT),
])


class SockFprog(ctypes.Structure):
    _fields_ = [('len', ctypes.c_ushort), ('filter', ctypes.c_void_p)]


buf = ctypes.create_string_buffer(prog, len(prog))
fprog = SockFprog(len(prog) // 8, ctypes.addressof(buf))
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                       ctypes.c_ulong, ctypes.c_ulong]
if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) or \
   libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.addressof(fprog),
              0, 0):
    sys.exit(77)
os.execv(sys.argv[1], sys.argv[1:])
