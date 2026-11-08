#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Tell whether this process may set up an io_uring at all. A kernel built
# without io_uring, kernel.io_uring_disabled, a security module or a seccomp
# filter (Docker's default profile refuses io_uring_setup) all make
# io_uring_setup(2) fail before gwproxy can do anything about it, and every
# io_uring run of a test would then fail on the environment, not on gwproxy.
#
# Usage: iou_probe.py
#
# Exits 0 when a ring can be set up, and also whenever this cannot tell: an
# architecture whose system call number is not known here, or a failure other
# than the refusals below, which is left for gwproxy itself to report. Exits 77,
# with the reason on stdout, only when io_uring_setup() is refused outright:
# ENOSYS, EPERM or EACCES.
import ctypes, errno, os, platform, sys

# io_uring_setup is 425 on every architecture that uses the generic system call
# table; alpha, mips and ia64 number it differently, and are not probed.
NR_IO_URING_SETUP = 425
GENERIC = ('x86_64', 'i386', 'i686', 'aarch64', 'armv7l', 'armv8l', 'riscv64',
           'ppc64', 'ppc64le', 'ppc', 's390x', 'loongarch64')
REFUSED = (errno.ENOSYS, errno.EPERM, errno.EACCES)

if platform.machine() not in GENERIC:
    sys.exit(0)

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
params = ctypes.create_string_buffer(120)	# struct io_uring_params, zeroed
fd = libc.syscall(ctypes.c_long(NR_IO_URING_SETUP), ctypes.c_uint(1), params)
if fd >= 0:
    os.close(fd)
    sys.exit(0)
err = ctypes.get_errno()
if err in REFUSED:
    print('io_uring_setup() refused here: %s (%s)' %
          (errno.errorcode.get(err, str(err)), os.strerror(err)))
    sys.exit(77)
sys.exit(0)
