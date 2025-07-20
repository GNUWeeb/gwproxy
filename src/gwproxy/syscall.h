// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWPROXY_SYSCALL_H
#define GWPROXY_SYSCALL_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/timerfd.h>
#include <sys/inotify.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

/*
 * Advantages of using inline assembly for syscalls:
 *
 *  1) Avoid the use of `errno`. Mostly it's implemented as
 *     a function call to `__errno_location()`.
 *
 *  2) Fewer register clobberings. x86-64 syscall only clobbers
 *     `rax`, `rcx`, `r11`, and `memory`. While libc function
 *     calls clobber `rax`, `rdi`, `rsi`, `rdx`, `r10`, `r8`,
 *     `r9`, `rcx`, `r11`, and `memory`.
 */
#ifdef __x86_64__
#define __do_syscall0(NUM) ({			\
	intptr_t rax;				\
						\
	__asm__ volatile(			\
		"syscall"			\
		: "=a"(rax)	/* %rax */	\
		: "a"(NUM)	/* %rax */	\
		: "rcx", "r11", "memory"	\
	);					\
	rax;					\
})

#define __do_syscall1(NUM, ARG1) ({		\
	intptr_t rax;				\
						\
	__asm__ volatile(			\
		"syscall"			\
		: "=a"(rax)	/* %rax */	\
		: "a"(NUM),	/* %rax */	\
		  "D"(ARG1)	/* %rdi */	\
		: "rcx", "r11", "memory"	\
	);					\
	rax;					\
})

#define __do_syscall2(NUM, ARG1, ARG2) ({	\
	intptr_t rax;				\
						\
	__asm__ volatile(			\
		"syscall"			\
		: "=a"(rax)	/* %rax */	\
		: "a"(NUM),	/* %rax */	\
		  "D"(ARG1),	/* %rdi */	\
		  "S"(ARG2)	/* %rsi */	\
		: "rcx", "r11", "memory"	\
	);					\
	rax;					\
})

#define __do_syscall3(NUM, ARG1, ARG2, ARG3) ({	\
	intptr_t rax;				\
						\
	__asm__ volatile(			\
		"syscall"			\
		: "=a"(rax)	/* %rax */	\
		: "a"(NUM),	/* %rax */	\
		  "D"(ARG1),	/* %rdi */	\
		  "S"(ARG2),	/* %rsi */	\
		  "d"(ARG3)	/* %rdx */	\
		: "rcx", "r11", "memory"	\
	);					\
	rax;					\
})

#define __do_syscall4(NUM, ARG1, ARG2, ARG3, ARG4) ({			\
	intptr_t rax;							\
	register __typeof__(ARG4) __r10 __asm__("r10") = (ARG4);	\
									\
	__asm__ volatile(						\
		"syscall"						\
		: "=a"(rax)	/* %rax */				\
		: "a"(NUM),	/* %rax */				\
		  "D"(ARG1),	/* %rdi */				\
		  "S"(ARG2),	/* %rsi */				\
		  "d"(ARG3),	/* %rdx */				\
		  "r"(__r10)	/* %r10 */				\
		: "rcx", "r11", "memory"				\
	);								\
	rax;								\
})

#define __do_syscall5(NUM, ARG1, ARG2, ARG3, ARG4, ARG5) ({		\
	intptr_t rax;							\
	register __typeof__(ARG4) __r10 __asm__("r10") = (ARG4);	\
	register __typeof__(ARG5) __r8 __asm__("r8") = (ARG5);		\
									\
	__asm__ volatile(						\
		"syscall"						\
		: "=a"(rax)	/* %rax */				\
		: "a"(NUM),	/* %rax */				\
		  "D"(ARG1),	/* %rdi */				\
		  "S"(ARG2),	/* %rsi */				\
		  "d"(ARG3),	/* %rdx */				\
		  "r"(__r10),	/* %r10 */				\
		  "r"(__r8)	/* %r8 */				\
		: "rcx", "r11", "memory"				\
	);								\
	rax;								\
})

#define __do_syscall6(NUM, ARG1, ARG2, ARG3, ARG4, ARG5, ARG6) ({	\
	intptr_t rax;							\
	register __typeof__(ARG4) __r10 __asm__("r10") = (ARG4);	\
	register __typeof__(ARG5) __r8 __asm__("r8") = (ARG5);		\
	register __typeof__(ARG6) __r9 __asm__("r9") = (ARG6);		\
									\
	__asm__ volatile(						\
		"syscall"						\
		: "=a"(rax)	/* %rax */				\
		: "a"(NUM),	/* %rax */				\
		  "D"(ARG1),	/* %rdi */				\
		  "S"(ARG2),	/* %rsi */				\
		  "d"(ARG3),	/* %rdx */				\
		  "r"(__r10),	/* %r10 */				\
		  "r"(__r8),	/* %r8 */				\
		  "r"(__r9)	/* %r9 */				\
		: "rcx", "r11", "memory"				\
	);								\
	rax;								\
})

static inline int __sys_epoll_wait(int epfd, struct epoll_event *events,
				   int maxevents, int timeout)
{
	return (int) __do_syscall4(__NR_epoll_wait, epfd, events, maxevents,
				   timeout);
}

static inline ssize_t __sys_read(int fd, void *buf, size_t len)
{
	return (ssize_t) __do_syscall3(__NR_read, fd, buf, len);
}

static inline ssize_t __sys_write(int fd, const void *buf, size_t len)
{
	return (ssize_t) __do_syscall3(__NR_write, fd, buf, len);
}

static inline ssize_t __sys_recvfrom(int sockfd, void *buf, size_t len,
				     int flags, struct sockaddr *src_addr,
				     socklen_t *addrlen)
{
	return (ssize_t) __do_syscall6(__NR_recvfrom, sockfd, buf, len, flags,
				       src_addr, addrlen);
}

static inline ssize_t __sys_sendto(int sockfd, const void *buf, size_t len,
				   int flags, const struct sockaddr *dest_addr,
				   socklen_t addrlen)
{
	return (ssize_t) __do_syscall6(__NR_sendto, sockfd, buf, len, flags,
				       dest_addr, addrlen);
}

static inline int __sys_close(int fd)
{
	return (int) __do_syscall1(__NR_close, fd);
}

static inline ssize_t __sys_recv(int sockfd, void *buf, size_t len, int flags)
{
	return __sys_recvfrom(sockfd, buf, len, flags, NULL, NULL);
}

static inline ssize_t __sys_send(int sockfd, const void *buf, size_t len,
				 int flags)
{
	return __sys_sendto(sockfd, buf, len, flags, NULL, 0);
}

static inline int __sys_accept4(int sockfd, struct sockaddr *addr,
				 socklen_t *addrlen, int flags)
{
	return (int) __do_syscall4(__NR_accept4, sockfd, addr, addrlen, flags);
}

static inline int __sys_epoll_ctl(int epfd, int op, int fd,
				 struct epoll_event *event)
{
	return (int) __do_syscall4(__NR_epoll_ctl, epfd, op, fd, event);
}

static inline int __sys_setsockopt(int sockfd, int level, int optname,
				   const void *optval, socklen_t optlen)
{
	return (int) __do_syscall5(__NR_setsockopt, sockfd, level, optname,
				   optval, optlen);
}

static inline int __sys_getsockopt(int sockfd, int level, int optname,
				   void *optval, socklen_t *optlen)
{
	return (int) __do_syscall5(__NR_getsockopt, sockfd, level, optname,
				   optval, optlen);
}

static inline int __sys_socket(int domain, int type, int protocol)
{
	return (int) __do_syscall3(__NR_socket, domain, type, protocol);
}

static inline int __sys_bind(int sockfd, const struct sockaddr *addr,
			     socklen_t addrlen)
{
	return (int) __do_syscall3(__NR_bind, sockfd, addr, addrlen);
}

static inline int __sys_listen(int sockfd, int backlog)
{
	return (int) __do_syscall2(__NR_listen, sockfd, backlog);
}

static inline int __sys_epoll_create1(int flags)
{
	return (int) __do_syscall1(__NR_epoll_create1, flags);
}

static inline int __sys_connect(int sockfd, const struct sockaddr *addr,
				socklen_t addrlen)
{
	return (int) __do_syscall3(__NR_connect, sockfd, addr, addrlen);
}

static inline int __sys_getsockname(int sockfd, struct sockaddr *addr,
				socklen_t *addrlen)
{
	return (int) __do_syscall3(__NR_getsockname, sockfd, addr, addrlen);
}

static inline int __sys_timerfd_create(int clockid, int flags)
{
	return (int) __do_syscall2(__NR_timerfd_create, clockid, flags);
}

static inline int __sys_timerfd_settime(int fd, int flags,
				 const struct itimerspec *new_value,
				 struct itimerspec *old_value)
{
	return (int) __do_syscall4(__NR_timerfd_settime, fd, flags, new_value,
				   old_value);
}

#ifndef __NR_eventfd2
#error "eventfd2 syscall not defined"
#endif

static inline int __sys_eventfd(unsigned int c, int flags)
{
	return (int) __do_syscall2(__NR_eventfd2, c, flags);
}

#else /* #ifdef __x86_64__ */

#include <errno.h>
static inline int __sys_epoll_wait(int epfd, struct epoll_event *events,
				   int maxevents, int timeout)
{
	int r = epoll_wait(epfd, events, maxevents, timeout);
	return (r < 0) ? -errno : r;
}

static inline ssize_t __sys_read(int fd, void *buf, size_t len)
{
	ssize_t r = read(fd, buf, len);
	return (r < 0) ? -errno : r;
}

static inline ssize_t __sys_write(int fd, const void *buf, size_t len)
{
	ssize_t r = write(fd, buf, len);
	return (r < 0) ? -errno : r;
}

static inline ssize_t __sys_recvfrom(int sockfd, void *buf, size_t len,
				     int flags, struct sockaddr *src_addr,
				     socklen_t *addrlen)
{
	ssize_t r = recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
	return (r < 0) ? -errno : r;
}

static inline ssize_t __sys_sendto(int sockfd, const void *buf, size_t len,
				   int flags, const struct sockaddr *dest_addr,
				   socklen_t addrlen)
{
	ssize_t r = sendto(sockfd, buf, len, flags, dest_addr, addrlen);
	return (r < 0) ? -errno : r;
}

static inline int __sys_close(int fd)
{
	int r = close(fd);
	return (r < 0) ? -errno : r;
}

static inline ssize_t __sys_recv(int sockfd, void *buf, size_t len, int flags)
{
	return __sys_recvfrom(sockfd, buf, len, flags, NULL, NULL);
}

static inline ssize_t __sys_send(int sockfd, const void *buf, size_t len,
				 int flags)
{
	return __sys_sendto(sockfd, buf, len, flags, NULL, 0);
}

static inline int __sys_accept4(int sockfd, struct sockaddr *addr,
				 socklen_t *addrlen, int flags)
{
	int r = accept4(sockfd, addr, addrlen, flags);
	return (r < 0) ? -errno : r;
}

static inline int __sys_epoll_ctl(int epfd, int op, int fd,
				 struct epoll_event *event)
{
	int r = epoll_ctl(epfd, op, fd, event);
	return (r < 0) ? -errno : r;
}

static inline int __sys_setsockopt(int sockfd, int level, int optname,
				   const void *optval, socklen_t optlen)
{
	int r = setsockopt(sockfd, level, optname, optval, optlen);
	return (r < 0) ? -errno : r;
}

static inline int __sys_getsockopt(int sockfd, int level, int optname,
				   void *optval, socklen_t *optlen)
{
	int r = getsockopt(sockfd, level, optname, optval, optlen);
	return (r < 0) ? -errno : r;
}

static inline int __sys_socket(int domain, int type, int protocol)
{
	int r = socket(domain, type, protocol);
	return (r < 0) ? -errno : r;
}

static inline int __sys_bind(int sockfd, const struct sockaddr *addr,
			     socklen_t addrlen)
{
	int r = bind(sockfd, addr, addrlen);
	return (r < 0) ? -errno : r;
}

static inline int __sys_listen(int sockfd, int backlog)
{
	int r = listen(sockfd, backlog);
	return (r < 0) ? -errno : r;
}

static inline int __sys_epoll_create1(int flags)
{
	int r = epoll_create1(flags);
	return (r < 0) ? -errno : r;
}

static inline int __sys_eventfd(unsigned int c, int flags)
{
	int r = eventfd(c, flags);
	return (r < 0) ? -errno : r;
}

static inline int __sys_connect(int sockfd, const struct sockaddr *addr,
				socklen_t addrlen)
{
	int r = connect(sockfd, addr, addrlen);
	return (r < 0) ? -errno : r;
}

static inline int __sys_getsockname(int sockfd, struct sockaddr *addr,
				socklen_t *addrlen)
{
	int r = getsockname(sockfd, addr, addrlen);
	return (r < 0) ? -errno : r;
}

static inline int __sys_timerfd_create(int clockid, int flags)
{
	int r = timerfd_create(clockid, flags);
	return (r < 0) ? -errno : r;
}

static inline int __sys_timerfd_settime(int fd, int flags,
				 const struct itimerspec *new_value,
				 struct itimerspec *old_value)
{
	int r = timerfd_settime(fd, flags, new_value, old_value);
	return (r < 0) ? -errno : r;
}
#endif /* #endif __x86_64__ */

#endif /* #ifndef GWPROXY_SYSCALL_H */
