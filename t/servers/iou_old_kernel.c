// SPDX-License-Identifier: GPL-2.0-only
/*
 * LD_PRELOAD shim: make io_uring look like an older kernel's, as far as the
 * io_uring event loop can tell. liburing makes its system calls itself, so a
 * seccomp filter traps io_uring_setup(2) and io_uring_enter(2) into a signal
 * handler here, which makes the real call from the one place the filter lets
 * it through, and edits what goes in or comes out.
 *
 * $IOU_OLD_KERNEL says what to pretend:
 *   5.15          no IORING_FEAT_CQE_SKIP, and a request flagged
 *                 IOSQE_CQE_SKIP_SUCCESS fails with -EINVAL (as before 5.17)
 *   5.18          a cancel with any IORING_ASYNC_CANCEL_* flag fails with
 *                 -EINVAL (as before 5.19)
 *   close-einval  only: a close fails with -EINVAL; no kernel does just
 *                 this, it shows what the loop does with such a close
 * Every version also refuses IORING_SETUP_NO_SQARRAY (6.6) at setup, which
 * liburing then retries without, so the submission queue keeps its index
 * array.
 *
 * The SQEs are made to fail by setting a field their opcode's prep refuses
 * (sqe->off, for IORING_OP_CLOSE and IORING_OP_ASYNC_CANCEL alike), so the
 * kernel fails them itself, with a completion, before they run.
 *
 * x86-64 only; the test skips elsewhere. A program that cannot be filtered
 * exits 99 at startup.
 */
#if !defined(__x86_64__)
#error "x86-64 only"
#endif

#define _GNU_SOURCE
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>
#include <linux/filter.h>
#include <linux/io_uring.h>
#include <linux/seccomp.h>

#ifndef IORING_FEAT_CQE_SKIP
#define IORING_FEAT_CQE_SKIP		(1U << 11)
#endif
#ifndef IOSQE_CQE_SKIP_SUCCESS
#define IOSQE_CQE_SKIP_SUCCESS		(1U << 6)
#endif
#ifndef IORING_SETUP_NO_SQARRAY
#define IORING_SETUP_NO_SQARRAY		(1U << 16)
#endif

enum { OLD_5_15 = 1, OLD_5_18, CLOSE_EINVAL };

static int mode;

/* What the shim maps of each ring, by ring descriptor. */
#define MAX_RINGS 1024
static struct ring {
	uint32_t		*khead;
	uint32_t		*ktail;
	uint32_t		*mask;
	uint32_t		*array;
	struct io_uring_sqe	*sqes;
} rings[MAX_RINGS];

extern char real_syscall_ret[];
long real_syscall(long nr, long a, long b, long c, long d, long e, long f);

/* The filter lets io_uring calls through from real_syscall_ret only. */
__asm__(".text\n"
	".type real_syscall,@function\n"
	"real_syscall:\n"
	"	mov %rdi,%rax\n"
	"	mov %rsi,%rdi\n"
	"	mov %rdx,%rsi\n"
	"	mov %rcx,%rdx\n"
	"	mov %r8,%r10\n"
	"	mov %r9,%r8\n"
	"	mov 8(%rsp),%r9\n"
	"	syscall\n"
	"real_syscall_ret:\n"
	"	ret\n"
	".size real_syscall,.-real_syscall\n");

static void *map(int fd, size_t len, long off)
{
	return (void *)real_syscall(SYS_mmap, 0, (long)len,
				    PROT_READ | PROT_WRITE,
				    MAP_SHARED | MAP_POPULATE, fd, off);
}

/* Map the new ring @fd's submission queue too, to edit what is queued. */
static void track(int fd, const struct io_uring_params *p)
{
	struct ring *r;
	size_t len;
	char *sq;
	void *sqes;

	if (fd < 0 || fd >= MAX_RINGS)
		_exit(98);
	len = p->sq_off.array + p->sq_entries * sizeof(uint32_t);
	sq = map(fd, len, IORING_OFF_SQ_RING);
	sqes = map(fd, p->sq_entries * sizeof(struct io_uring_sqe),
		   IORING_OFF_SQES);
	if ((unsigned long)sq > -4096UL || (unsigned long)sqes > -4096UL)
		_exit(98);
	r = &rings[fd];
	r->khead = (uint32_t *)(sq + p->sq_off.head);
	r->ktail = (uint32_t *)(sq + p->sq_off.tail);
	r->mask = (uint32_t *)(sq + p->sq_off.ring_mask);
	r->array = (uint32_t *)(sq + p->sq_off.array);
	r->sqes = sqes;
}

static long do_setup(long entries, struct io_uring_params *p)
{
	long fd;

	if (p->flags & IORING_SETUP_NO_SQARRAY)
		return -22;	/* EINVAL: unknown to the kernel pretended */
	fd = real_syscall(SYS_io_uring_setup, entries, (long)p, 0, 0, 0, 0);
	if (fd < 0)
		return fd;
	if (mode == OLD_5_15)
		p->features &= ~IORING_FEAT_CQE_SKIP;
	track((int)fd, p);
	return fd;
}

static void edit(struct io_uring_sqe *sqe)
{
	switch (mode) {
	case OLD_5_15:
		if (sqe->flags & IOSQE_CQE_SKIP_SUCCESS)
			sqe->off = 1;
		break;
	case OLD_5_18:
		if (sqe->opcode == IORING_OP_ASYNC_CANCEL && sqe->cancel_flags)
			sqe->off = 1;
		break;
	case CLOSE_EINVAL:
		if (sqe->opcode == IORING_OP_CLOSE)
			sqe->off = 1;
		break;
	}
}

/* Edit every SQE queued on ring @fd and not yet taken by the kernel. */
static void edit_queued(long fd)
{
	struct ring *r;
	uint32_t head, tail;

	if (fd < 0 || fd >= MAX_RINGS || !rings[fd].sqes)
		return;
	r = &rings[fd];
	head = __atomic_load_n(r->khead, __ATOMIC_ACQUIRE);
	tail = __atomic_load_n(r->ktail, __ATOMIC_ACQUIRE);
	for (; head != tail; head++)
		edit(&r->sqes[r->array[head & *r->mask]]);
}

static void on_sigsys(int sig, siginfo_t *si, void *ucv)
{
	greg_t *g = ((ucontext_t *)ucv)->uc_mcontext.gregs;

	(void)sig;
	if (si->si_syscall == SYS_io_uring_setup) {
		g[REG_RAX] = do_setup(g[REG_RDI],
				      (struct io_uring_params *)g[REG_RSI]);
		return;
	}
	if ((unsigned int)g[REG_RSI])
		edit_queued(g[REG_RDI]);
	g[REG_RAX] = real_syscall(SYS_io_uring_enter, g[REG_RDI], g[REG_RSI],
				  g[REG_RDX], g[REG_R10], g[REG_R8], g[REG_R9]);
}

__attribute__((constructor))
static void install(void)
{
	uint64_t ip = (uint64_t)real_syscall_ret;
	struct sock_filter f[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_io_uring_enter, 2, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_io_uring_setup, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, instruction_pointer)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)ip, 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, instruction_pointer) + 4),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)(ip >> 32), 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
	};
	struct sock_fprog prog = {
		.len = sizeof(f) / sizeof(f[0]),
		.filter = f,
	};
	struct sigaction sa = {
		.sa_sigaction = on_sigsys,
		.sa_flags = SA_SIGINFO | SA_RESTART,
	};
	const char *m = getenv("IOU_OLD_KERNEL");

	if (!m)
		_exit(99);
	if (!strcmp(m, "5.15"))
		mode = OLD_5_15;
	else if (!strcmp(m, "5.18"))
		mode = OLD_5_18;
	else if (!strcmp(m, "close-einval"))
		mode = CLOSE_EINVAL;
	else
		_exit(99);

	if (sigaction(SIGSYS, &sa, NULL) ||
	    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
	    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
		_exit(99);
}
