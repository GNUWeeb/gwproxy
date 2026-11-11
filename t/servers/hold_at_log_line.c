// SPDX-License-Identifier: GPL-2.0-only
/*
 * LD_PRELOAD shim: hold the thread that is about to log a given line, for as
 * long as a test asks, so that the test can act at that exact point of the
 * program. The proxy logs with write(2) made by itself, not through the C
 * library, so a seccomp filter traps every write into a signal handler here,
 * which makes the real call from the one place the filter lets it through.
 *
 * The first line that contains both $HOLD_AT_LOG and $HOLD_AT_LOG2 (if set)
 * is held: the shim creates the file $HOLD_FILE, then waits, for 30 seconds
 * at most, until the test removes it, and only then writes the line. Any
 * other line goes out at once.
 *
 * x86-64 only; the test skips elsewhere. A program that cannot be filtered
 * exits 99 at startup.
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
#include <string.h>
#include <time.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

static const char *at, *at2, *hold_file;
static int held;

extern char real_syscall_ret[];
long real_syscall(long nr, long a, long b, long c, long d, long e, long f);

/* The filter lets write(2) through from real_syscall_ret only. */
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

static int has(const char *buf, size_t len, const char *s)
{
	return !s || memmem(buf, len, s, strlen(s)) != NULL;
}

static void hold(void)
{
	struct timespec ts = { 0, 10 * 1000 * 1000 };
	int fd, i;

	fd = open(hold_file, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
	if (fd < 0)
		return;
	close(fd);
	for (i = 0; i < 3000 && !access(hold_file, F_OK); i++)
		nanosleep(&ts, NULL);
}

static void on_sigsys(int sig, siginfo_t *si, void *ucv)
{
	greg_t *g = ((ucontext_t *)ucv)->uc_mcontext.gregs;
	const char *buf = (const char *)g[REG_RSI];
	size_t len = (size_t)g[REG_RDX];

	(void)sig;
	(void)si;
	if (!__atomic_load_n(&held, __ATOMIC_RELAXED) && has(buf, len, at) &&
	    has(buf, len, at2) && !__atomic_exchange_n(&held, 1, __ATOMIC_RELAXED))
		hold();
	g[REG_RAX] = real_syscall(SYS_write, g[REG_RDI], g[REG_RSI],
				  g[REG_RDX], 0, 0, 0);
}

__attribute__((constructor))
static void install(void)
{
	uint64_t ip = (uint64_t)real_syscall_ret;
	struct sock_filter f[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 1, 0),
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

	at = getenv("HOLD_AT_LOG");
	at2 = getenv("HOLD_AT_LOG2");
	hold_file = getenv("HOLD_FILE");
	if (!at || !hold_file)
		_exit(99);

	if (sigaction(SIGSYS, &sa, NULL) ||
	    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
	    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
		_exit(99);
}
