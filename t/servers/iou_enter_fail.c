// SPDX-License-Identifier: GPL-2.0-only
/*
 * LD_PRELOAD shim: fail the io_uring_enter(2) calls that carry SQEs, as a kernel
 * short of memory does, for as long as a test asks. strace can only count calls,
 * and liburing makes its system calls itself, so a seccomp filter traps them
 * into a signal handler here. Calls that only wait for completions always reach
 * the kernel, from the one place the filter lets them through.
 *
 * $IOU_FAIL_CTL names a file of at least one page, shared with the test:
 *   u32 at 0:  errno to fail with, 0 to let everything through
 *   u64 at 8:  calls failed so far
 *
 * x86-64 only; the test skips elsewhere. A program that cannot be filtered exits
 * 99 at startup.
 */
#if !defined(__x86_64__)
#error "x86-64 only"
#endif

#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

struct ctl {
	volatile uint32_t	err;
	uint32_t		pad;
	volatile uint64_t	failed;
};

static struct ctl *ctl;

extern char real_syscall_ret[];
long real_syscall(long nr, long a, long b, long c, long d, long e, long f);

/* The filter lets io_uring_enter(2) through from real_syscall_ret only. */
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

static void on_sigsys(int sig, siginfo_t *si, void *ucv)
{
	greg_t *g = ((ucontext_t *)ucv)->uc_mcontext.gregs;
	uint32_t err = ctl->err;

	(void)sig;
	(void)si;
	if (err && (unsigned int)g[REG_RSI]) {
		__sync_add_and_fetch(&ctl->failed, 1);
		g[REG_RAX] = -(long)err;
		return;
	}
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
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_io_uring_enter, 1, 0),
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
	const char *path = getenv("IOU_FAIL_CTL");
	void *m;
	int fd;

	if (!path)
		_exit(99);
	fd = open(path, O_RDWR);
	if (fd < 0)
		_exit(99);
	m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	if (m == MAP_FAILED)
		_exit(99);
	ctl = m;

	if (sigaction(SIGSYS, &sa, NULL) ||
	    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
	    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
		_exit(99);
}
