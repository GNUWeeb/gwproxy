#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Accept pauses when the process is short of something, and putting the
# listener back into the epoll set takes kernel memory and counts against the
# user's epoll watches. The epoll loop took one failure there as fatal: every
# worker stopped and every live tunnel was cut, with nothing in the log. It must
# go on serving and try again a little later, as the io_uring loop does.
#
# Covered: all three ways back, the retry after an accept error, the timed
# retry after EMFILE and the one when enough descriptors were closed. Neither
# failure can be caused from here, so a tracer on the worker thread makes them
# up: it fails one accept4() and then some EPOLL_CTL_ADD of the listener. It
# speaks ptrace on x86-64 only; the proxy has to be its child, which is all that
# kernel.yama.ptrace_scope=1 allows. epoll only: io_uring's accept is no system
# call, and its own retry is not in question here.

. "$(dirname "$0")/lib.sh"
require python3

p="$(pick_port)"
out="$(timeout 150 python3 - "$GWPROXY" "$p" "$WORK" <<'PY'
import ctypes, errno, os, platform, signal, socket, struct, subprocess, sys
import threading, time

gw, port, work = sys.argv[1], int(sys.argv[2]), sys.argv[3]
LIMIT = 60

if platform.machine() != "x86_64":
    print("the tracer speaks x86-64 only")
    sys.exit(77)

libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.restype = ctypes.c_long
libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]

PTRACE_GETREGS, PTRACE_SETREGS, PTRACE_SYSCALL = 12, 13, 24
PTRACE_SEIZE, PTRACE_INTERRUPT, PTRACE_GET_SYSCALL_INFO = 0x4206, 0x4207, 0x420e
PTRACE_O_TRACESYSGOOD = 1
WALL = 0x40000000
NR_EPOLL_CTL, NR_ACCEPT4 = 233, 288
EPOLL_CTL_ADD = 1
# struct user_regs_struct, in longs.
REG_RAX, REG_ORIG_RAX, NR_REGS = 10, 15, 27


class Tracer(threading.Thread):
    """Runs the worker: worker 0 is the process's main thread."""

    def __init__(self, pid):
        super().__init__(daemon=True)
        self.pid, self.lock = pid, threading.Lock()
        self.fail_accept, self.fail_add, self.add_errno = 0, 0, 0
        self.listener = -1
        self.nr_failed = self.nr_passed = 0
        self.status = None
        self.seized = threading.Event()
        self.denied = None

    def plan(self, accept_errno, nr_add, add_errno):
        with self.lock:
            self.fail_accept, self.fail_add, self.add_errno = accept_errno, nr_add, add_errno
            self.nr_failed = self.nr_passed = 0

    def pt(self, req, data=None, addr=None):
        r = libc.ptrace(req, self.pid, addr, data)
        if r < 0:
            raise OSError(ctypes.get_errno(), "ptrace %#x" % req)
        return r

    def entry_action(self, nr, args):
        """The errno to fail this system call with, or 0."""
        with self.lock:
            if nr == NR_ACCEPT4 and self.fail_accept:
                e, self.fail_accept = self.fail_accept, 0
                self.listener = args[0]
                return e
            if nr == NR_EPOLL_CTL and args[1] == EPOLL_CTL_ADD and args[2] == self.listener:
                if self.fail_add:
                    self.fail_add -= 1
                    self.nr_failed += 1
                    return self.add_errno
                self.nr_passed += 1
        return 0

    def run(self):
        try:
            self.pt(PTRACE_SEIZE, data=PTRACE_O_TRACESYSGOOD)
            self.pt(PTRACE_INTERRUPT)
        except OSError as e:
            self.denied = e
            self.seized.set()
            return
        self.seized.set()
        info = ctypes.create_string_buffer(88)
        regs = (ctypes.c_ulonglong * NR_REGS)()
        inject = 0
        while True:
            _, st = os.waitpid(self.pid, WALL)
            if os.WIFEXITED(st) or os.WIFSIGNALED(st):
                self.status = st
                return
            sig = os.WSTOPSIG(st)
            deliver = 0
            if sig == (signal.SIGTRAP | 0x80):
                self.pt(PTRACE_GET_SYSCALL_INFO, data=ctypes.addressof(info),
                        addr=ctypes.sizeof(info))
                if info.raw[0] == 1:    # entry
                    nr, *args = struct.unpack_from("=7Q", info.raw, 24)
                    inject = self.entry_action(nr, args)
                    if inject:
                        self.pt(PTRACE_GETREGS, data=ctypes.addressof(regs))
                        regs[REG_ORIG_RAX] = 2**64 - 1
                        self.pt(PTRACE_SETREGS, data=ctypes.addressof(regs))
                elif info.raw[0] == 2 and inject:    # exit
                    self.pt(PTRACE_GETREGS, data=ctypes.addressof(regs))
                    regs[REG_RAX] = 2**64 - inject
                    self.pt(PTRACE_SETREGS, data=ctypes.addressof(regs))
                    inject = 0
            elif (st >> 16) == 0 and sig != signal.SIGTRAP:
                deliver = sig
            self.pt(PTRACE_SYSCALL, data=deliver)


# The target of the tunnel that has to outlive all this: an echo.
ls = socket.socket()
ls.bind(("127.0.0.1", 0))
ls.listen(16)
oport = ls.getsockname()[1]


def echo():
    c, _ = ls.accept()
    while True:
        d = c.recv(4096)
        if not d:
            return
        c.sendall(d)


threading.Thread(target=echo, daemon=True).start()

log = open(work + "/gwp.log", "wb")
proxy = subprocess.Popen([gw, "--bind=127.0.0.1:%d" % port, "--log-level=3", "--acl-allow-all",
                          "--as-socks5=1", "--event-loop=epoll", "--nr-workers=1",
                          "--protocol-timeout=600"],
                         stdout=log, stderr=subprocess.STDOUT)


def hello():
    c = socket.create_connection(("127.0.0.1", port), timeout=LIMIT)
    c.settimeout(LIMIT)
    return c


def served(c, what):
    """Does this connection, made while accept is paused, get an answer?"""
    try:
        c.sendall(b"\x05\x01\x00")
        got = c.recv(2)
    except OSError as e:
        got = repr(e)
    if got != b"\x05\x00":
        die("%s: the client got %r (failed %d, passed %d)" %
            (what, got, tr.nr_failed, tr.nr_passed))
    c.close()


def die(msg):
    print(msg)
    os.kill(proxy.pid, signal.SIGKILL)
    sys.exit(1)


for _ in range(LIMIT * 20):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
        break
    except OSError:
        time.sleep(0.05)
else:
    die("the proxy did not listen")

tr = Tracer(proxy.pid)
tr.start()
tr.seized.wait()
if tr.denied:
    print("cannot trace: %s" % tr.denied)
    os.kill(proxy.pid, signal.SIGKILL)
    sys.exit(77)

tun = hello()
tun.sendall(b"\x05\x01\x00")
tun.recv(2)
tun.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", oport))
if tun.recv(10)[:2] != b"\x05\x00":
    die("no tunnel")


def check_tunnel(what):
    try:
        tun.sendall(b"ping")
        got = tun.recv(4)
    except OSError as e:
        got = repr(e)
    if got != b"ping":
        die("%s: the tunnel got %r" % (what, got))


def check_plan(what, want):
    # The retry that succeeded was counted before the client could be served.
    if tr.nr_failed != want or tr.nr_passed < 1:
        die("%s: %d re-adds failed and %d passed, want %d and some" %
            (what, tr.nr_failed, tr.nr_passed, want))


# After an accept error: the listener is out until the next timed try.
tr.plan(errno.ENOBUFS, 3, errno.ENOMEM)
served(hello(), "ENOBUFS, then ENOMEM")
check_tunnel("ENOBUFS, then ENOMEM")
check_plan("ENOBUFS, then ENOMEM", 3)

# After EMFILE, with nothing closing: the timed retry.
tr.plan(errno.EMFILE, 2, errno.ENOSPC)
served(hello(), "EMFILE, then ENOSPC")
check_tunnel("EMFILE, then ENOSPC")
check_plan("EMFILE, then ENOSPC", 2)

# After EMFILE, with enough closed to resume ahead of the timed retry.
idle = [hello() for _ in range(16)]
for c in idle:
    c.sendall(b"\x05\x01\x00")
    if c.recv(2) != b"\x05\x00":
        die("no method reply")
tr.plan(errno.EMFILE, 1, errno.ENOMEM)
c = hello()
for _ in range(LIMIT * 20):
    with tr.lock:
        if not tr.fail_accept:
            break
    time.sleep(0.05)
for i in idle:
    i.close()
served(c, "EMFILE, closes, then ENOMEM")
check_tunnel("EMFILE, closes, then ENOMEM")
check_plan("EMFILE, closes, then ENOMEM", 1)

# Not proxy.terminate(): its waitpid() would take the tracer's stop from it.
os.kill(proxy.pid, signal.SIGTERM)
tr.join(LIMIT)
log.close()
if tr.is_alive():
    die("the proxy did not stop")
print("OK")
PY
)"
rc=$?
[ $rc -eq 77 ] && skip "$out"
diag "$out"
[ $rc -eq 0 ] || fail "$out"

n="$(grep -c 'retrying' "$WORK/gwp.log")"
[ "$n" -ge 3 ] || fail "want each outage logged, got $n lines"
grep -q 'Failed to put the listener back' "$WORK/gwp.log" || fail "the failure was not logged"
pass
