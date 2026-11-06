#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Write a file that takes a line-by-line reader a long time to get through:
# <contents> followed by gigabytes of blank lines. A test puts it in place
# of an auth file and sends SIGHUP; the reload then reads blank lines, with
# the new credentials held unpublished, until the test cuts the file back to
# <contents> (truncate -s, through a second link), and the reload ends and
# applies them. The blank lines are real newlines, not a hole: a hole reads
# as NUL bytes, which the auth loader refuses.
#
# Usage: blank_hold.py <path> <contents>
#
# The first 64 MiB are written. Where the file system can share extents
# (FICLONERANGE: btrfs, XFS), the blank lines are then cloned onto the end
# of the file again and again up to 16 GiB, which costs no data blocks and
# takes a reader minutes at the least. Elsewhere 1 GiB is written in full,
# still seconds of reading. <contents> must fit in the first MiB, which is
# padded with blank lines so that every clone is block-aligned. Prints the
# file's final size.
import fcntl, os, struct, sys

MIB = 1 << 20
BASE = 64 * MIB
CLONE_TARGET = 16 << 30
COPY_TARGET = 1 << 30
FICLONERANGE = 0x4020940D  # _IOW(0x94, 13, struct file_clone_range)

path, contents = sys.argv[1], sys.argv[2].encode()
if len(contents) >= MIB:
    sys.exit("blank_hold.py: contents too long")

blank = b"\n" * MIB
fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, contents + b"\n" * (MIB - len(contents)))
size = MIB
while size < BASE:
    size += os.write(fd, blank)

try:
    while size < CLONE_TARGET:
        n = min(size - MIB, CLONE_TARGET - size)
        # struct file_clone_range { s64 src_fd; u64 src_offset,
        # src_length, dest_offset; }: clone the blank lines past the
        # first MiB onto the end of the same file.
        fcntl.ioctl(fd, FICLONERANGE,
                    struct.pack("=qQQQ", fd, MIB, n, size))
        size += n
except OSError:
    os.lseek(fd, size, os.SEEK_SET)
    while size < COPY_TARGET:
        size += os.write(fd, blank)
os.close(fd)
print(size)
