#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Run a command and hold a reference to every socket it opens, the way a
# reader of /proc/<pid>/fd (ls -l, ss -p, lsof) holds one for a moment, but
# for as long as this helper runs. A descriptor the command closes then
# leaves its socket alive, and with it any epoll registration that was not
# removed with EPOLL_CTL_DEL: epoll drops an item only when the last
# reference to the file goes, not at close().
#
# Usage: fd_holder.py <state-file> <log-file> <command> [args...]
#
# The command runs as this helper's child, with stdout and stderr going to
# <log-file>; being its parent is what lets pidfd_getfd(2) take its
# descriptors under Yama's ptrace_scope=1. <state-file> is rewritten
# whenever something changes, one line:
#
#   PID <pid> HELD <n>    the child's pid and how many sockets are held
#   PID <pid> NOGETFD <errno>   pidfd_getfd() is not available or allowed
#
# The helper exits with the child's exit status once the child exits (128+N
# when a signal N killed it), releasing what it held. SIGTERM releases
# everything, stops the child with SIGTERM and exits likewise.
import ctypes, errno, os, signal, sys, time

SYS_pidfd_open = 434
SYS_pidfd_getfd = 438

state_file, log_file = sys.argv[1], sys.argv[2]
argv = sys.argv[3:]

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long


def write_state(line):
    tmp = state_file + '.tmp'
    with open(tmp, 'w') as f:
        f.write(line + '\n')
    os.replace(tmp, state_file)


logfd = os.open(log_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
pid = os.fork()
if pid == 0:
    os.dup2(logfd, 1)
    os.dup2(logfd, 2)
    os.close(logfd)
    try:
        os.execvp(argv[0], argv)
    finally:
        os._exit(127)
os.close(logfd)

stopping = False


def on_term(signo, frame):
    global stopping
    stopping = True


signal.signal(signal.SIGTERM, on_term)
signal.signal(signal.SIGINT, on_term)

pidfd = libc.syscall(SYS_pidfd_open, pid, 0)
nogetfd = None
if pidfd < 0:
    nogetfd = ctypes.get_errno()

held = {}   # (fd number, socket inode) -> our duplicate
last = None
status = None
while status is None:
    if stopping:
        for fd in held.values():
            os.close(fd)
        held.clear()
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        stopping = False
    r, st = os.waitpid(pid, os.WNOHANG)
    if r == pid:
        status = st
        break
    if nogetfd is None:
        try:
            names = os.listdir('/proc/%d/fd' % pid)
        except OSError:
            names = []
        for name in names:
            try:
                link = os.readlink('/proc/%d/fd/%s' % (pid, name))
            except OSError:
                continue
            if not link.startswith('socket:'):
                continue
            key = (int(name), link)
            if key in held:
                continue
            fd = libc.syscall(SYS_pidfd_getfd, pidfd, int(name), 0)
            if fd < 0:
                e = ctypes.get_errno()
                if e in (errno.EBADF,):
                    continue    # closed meanwhile
                nogetfd = e
                break
            held[key] = fd
    if nogetfd is not None:
        line = 'PID %d NOGETFD %d' % (pid, nogetfd)
    else:
        line = 'PID %d HELD %d' % (pid, len(held))
    if line != last:
        write_state(line)
        last = line
    time.sleep(0.01)

for fd in held.values():
    os.close(fd)
if os.WIFSIGNALED(status):
    sys.exit(128 + os.WTERMSIG(status))
sys.exit(os.WEXITSTATUS(status))
