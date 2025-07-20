// SPDX-License-Identifier: GPL-2.0-only
/*
 * gwproxy - A simple TCP proxy server.
 *
 * Copyright (C) 2025 Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <gwproxy/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include <assert.h>
#include <stdarg.h>
#include <time.h>
#include <inttypes.h>
#include <stdatomic.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <getopt.h>
#include <signal.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <netinet/tcp.h>
#include <sys/timerfd.h>
#include <sys/resource.h>
#include <sys/inotify.h>

#include <gwproxy/socks5.h>
#include <gwproxy/dns.h>

#ifndef likely
#define likely(x)	__builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif

#ifndef __cold
#define __cold		__attribute__((__cold__))
#endif

#ifndef __hot
#define __hot		__attribute__((__hot__))
#endif

#ifndef noinline
#define noinline	__attribute__((__noinline__))
#endif

#ifdef __CHECKER__
#define __must_hold(x) __attribute__((context(x,1,1)))
#define __acquires(x)  __attribute__((context(x,0,1)))
#define __releases(x)  __attribute__((context(x,1,0)))
#else
#define __must_hold(x)
#define __acquires(x)
#define __releases(x)
#endif

static const struct option long_opts[] = {
	{ "help",		no_argument,		NULL,	'h' },
	{ "event-loop",		required_argument,	NULL,	'e' },
	{ "bind",		required_argument,	NULL,	'b' },
	{ "target",		required_argument,	NULL,	't' },
	{ "as-socks5",		required_argument,	NULL,	'S' },
	{ "socks5-prefer-ipv6",	required_argument,	NULL,	'Q' },
	{ "socks5-timeout",	required_argument,	NULL,	'o' },
	{ "socks5-auth-file",	required_argument,	NULL,	'A' },
	{ "socks5-dns-cache-secs",	required_argument,	NULL,	'L' },
	{ "nr-workers",		required_argument,	NULL,	'w' },
	{ "nr-dns-workers",	required_argument,	NULL,	'W' },
	{ "connect-timeout",	required_argument,	NULL,	'c' },
	{ "target-buf-size",	required_argument,	NULL,	'T' },
	{ "client-buf-size",	required_argument,	NULL,	'C' },
	{ "tcp-nodelay",	required_argument,	NULL,	'd' },
	{ "tcp-quickack",	required_argument,	NULL,	'K' },
	{ "tcp-keepalive",	required_argument,	NULL,	'k' },
	{ "tcp-keepidle",	required_argument,	NULL,	'i' },
	{ "tcp-keepintvl",	required_argument,	NULL,	'l' },
	{ "tcp-keepcnt",	required_argument,	NULL,	'g' },
	{ "log-level",		required_argument,	NULL,	'm' },
	{ "log-file",		required_argument,	NULL,	'f' },
	{ "pid-file",		required_argument,	NULL,	'p' },
	{ NULL,			0,			NULL,	0 }
};

struct gwp_cfg {
	const char	*event_loop;
	const char	*bind;
	const char	*target;
	bool		as_socks5;
	bool		socks5_prefer_ipv6;
	int		socks5_timeout;
	const char	*socks5_auth_file;
	int		socks5_dns_cache_secs;
	int		nr_workers;
	int		nr_dns_workers;
	int		connect_timeout;
	int		target_buf_size;
	int		client_buf_size;
	bool		tcp_nodelay;
	bool		tcp_quickack;
	bool		tcp_keepalive;
	int		tcp_keepidle;
	int		tcp_keepintvl;
	int		tcp_keepcnt;
	int		log_level;
	const char	*log_file;
	const char	*pid_file;
};

static const struct gwp_cfg default_opts = {
	.event_loop		= "epoll",
	.bind			= "[::]:1080",
	.target			= NULL,
	.as_socks5		= false,
	.socks5_prefer_ipv6	= false,
	.socks5_timeout		= 10,
	.socks5_auth_file	= NULL,
	.socks5_dns_cache_secs	= 0,
	.nr_workers		= 4,
	.nr_dns_workers		= 4,
	.connect_timeout	= 5,
	.target_buf_size	= 2048,
	.client_buf_size	= 2048,
	.tcp_nodelay		= 1,
	.tcp_quickack		= 1,
	.tcp_keepalive		= 1,
	.tcp_keepidle		= 60,
	.tcp_keepintvl		= 10,
	.tcp_keepcnt		= 5,
	.log_level		= 3,
	.log_file		= "/dev/stdout",
	.pid_file		= NULL,
};

struct gwp_ctx;

enum {
	EV_BIT_ACCEPT		= (1ull << 48ull),
	EV_BIT_EVENTFD		= (2ull << 48ull),
	EV_BIT_TARGET		= (3ull << 48ull),
	EV_BIT_CLIENT		= (4ull << 48ull),
	EV_BIT_TIMER		= (5ull << 48ull),
	EV_BIT_CLIENT_SOCKS5	= (6ull << 48ull),
	EV_BIT_DNS_QUERY	= (7ull << 48ull),
	EV_BIT_SOCKS5_AUTH_FILE	= (8ull << 48ull),
};

#define EV_BIT_ALL	(0xffffull << 48ull)
#define GET_EV_BIT(X)	((X) & EV_BIT_ALL)
#define CLEAR_EV_BIT(X)	((X) & ~EV_BIT_ALL)

enum {
	CONN_STATE_INIT			= 101,

	CONN_STATE_SOCKS5_DATA		= 100,
	CONN_STATE_SOCKS5_CMD_CONNECT	= 221,
	CONN_STATE_SOCKS5_ERR		= 250,
	CONN_STATE_SOCKS5_DNS_QUERY	= 260,

	CONN_STATE_FORWARDING		= 301,
};

struct gwp_conn {
	int		fd;
	uint32_t	len;
	uint32_t	cap;
	char		*buf;
	uint32_t	ep_mask;
};

struct gwp_dns_query;

struct gwp_conn_pair {
	struct gwp_conn		target;
	struct gwp_conn		client;
	bool			is_target_alive;
	int			conn_state;
	int			timer_fd;
	uint32_t		idx;
	struct gwp_socks5_conn	*s5_conn;
	struct gwp_dns_query	*gdq;
	struct gwp_dns_entry	*gde;
	struct gwp_sockaddr	client_addr;
	struct gwp_sockaddr	target_addr;
};

struct gwp_conn_slot {
	struct gwp_conn_pair	**pairs;
	size_t			nr;
	size_t			cap;
};

struct gwp_wrk {
	int			tcp_fd;
	int			ep_fd;
	int			ev_fd;
	struct gwp_conn_slot	conn_slot;

	/*
	 * If it's true, the worker MUST call epoll_wait() again
	 * before continue iterating over the events.
	 */
	bool			ev_need_reload;

	bool			accept_is_stopped;

	struct gwp_ctx		*ctx;
	struct epoll_event	*events;
	uint16_t		evsz;
	uint32_t		idx;
	pthread_t		thread;
};

struct gwp_socks5_user {
	char	*u, *p;
	uint8_t	ulen, plen;
};

struct gwp_socks5_auth {
	FILE			*handle;
	struct gwp_socks5_user	*users;
	int			ino_fd;
	size_t			nr;
	size_t			cap;
	pthread_rwlock_t	lock;
};

struct gwp_ctx {
	volatile bool			stop;
	FILE				*log_file;
	struct gwp_wrk			*workers;
	struct gwp_socks5_auth		*s5auth;
	struct gwp_sockaddr		target_addr;
	struct gwp_socks5_ctx		*socks5;
	struct gwp_dns_ctx		*dns;
	struct gwp_cfg			cfg;
	_Atomic(int32_t)		nr_fd_closed;
	_Atomic(int32_t)		nr_accept_stopped;
};

__cold
static void show_help(const char *app)
{
	printf("Usage: %s [options]\n", app);
	printf("Options:\n");
	printf("  -h, --help                      Show this help message and exit\n");
	printf("  -e, --event-loop=name           Specify the event loop to use (default: %s)\n", default_opts.event_loop);
	printf("                                  Available values: epoll, io_uring\n");
	printf("  -b, --bind=addr:port            Bind to the specified address (default: %s)\n", default_opts.bind);
	printf("  -t, --target=addr_port          Target address to connect to\n");
	printf("  -S, --as-socks5=0|1             Run as a SOCKS5 proxy (default: %d)\n", default_opts.as_socks5);
	printf("  -Q, --socks5-prefer-ipv6=0|1    Prefer IPv6 for SOCKS5 DNS queries (default: %d)\n", default_opts.socks5_prefer_ipv6);
	printf("  -o, --socks5-timeout=sec        SOCKS5 auth timeout in seconds (default: %d)\n", default_opts.socks5_timeout);
	printf("  -A, --socks5-auth-file=file     File containing username:password for SOCKS5 auth (default: no auth)\n");
	printf("  -L, --socks5-dns-cache-secs=sec SOCKS5 DNS cache duration in seconds (default: %d)\n", default_opts.socks5_dns_cache_secs);
	printf("                                  Set to 0 or a negative number to disable DNS caching.\n");
	printf("  -w, --nr-workers=nr             Number of worker threads (default: %d)\n", default_opts.nr_workers);
	printf("  -W, --nr-dns-workers=nr         Number of DNS worker threads for SOCKS5 (default: %d)\n", default_opts.nr_dns_workers);
	printf("  -c, --connect-timeout=sec       Connection to target timeout in seconds (default: %d)\n", default_opts.connect_timeout);
	printf("  -T, --target-buf-size=nr        Target buffer size in bytes (default: %d)\n", default_opts.target_buf_size);
	printf("  -C, --client-buf-size=nr        Client buffer size in bytes (default: %d)\n", default_opts.client_buf_size);
	printf("  -d, --tcp-nodelay=0|1           Enable/disable TCP_NODELAY (default: %d)\n", default_opts.tcp_nodelay);
	printf("  -K, --tcp-quickack=0|1          Enable/disable TCP_QUICKACK (default: %d)\n", default_opts.tcp_quickack);
	printf("  -k, --tcp-keepalive=0|1         Enable/disable TCP_KEEPALIVE (default: %d)\n", default_opts.tcp_keepalive);
	printf("  -i, --tcp-keepidle=sec          TCP_KEEPIDLE in seconds (default: %d)\n", default_opts.tcp_keepidle);
	printf("  -l, --tcp-keepintvl=sec         TCP_KEEPINTVL in seconds (default: %d)\n", default_opts.tcp_keepintvl);
	printf("  -g, --tcp-keepcnt=nr            TCP_KEEPCNT (default: %d)\n", default_opts.tcp_keepcnt);
	printf("  -m, --log-level=level           Set log level (0=none, 1=error, 2=warning, 3=info, 4=debug, default: %d)\n", default_opts.log_level);
	printf("  -f, --log-file=file             Log to the specified file (default: %s)\n", default_opts.log_file);
	printf("  -p, --pid-file=file             Write PID to the specified file (default is no pid file)\n");
	printf("\n");
}

__cold
static int parse_options(int argc, char *argv[], struct gwp_cfg *cfg)
{
	#define NR_OPTS ((sizeof(long_opts) / sizeof(long_opts[0])) - 1)
	char short_opts[(NR_OPTS * 2) + 1], *p;
	size_t i;
	int c;

	p = short_opts;
	for (i = 0; i < NR_OPTS; i++) {
		*p++ = long_opts[i].val;
		if (long_opts[i].has_arg == required_argument ||
		    long_opts[i].has_arg == optional_argument)
			*p++ = ':';
	}
	*p = '\0';
	#undef NR_OPTS

	*cfg = default_opts;
	while (1) {
		c = getopt_long(argc, argv, short_opts, long_opts, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			show_help(argv[0]);
			exit(0);
		case 'e':
			cfg->event_loop = optarg;
			break;
		case 'b':
			cfg->bind = optarg;
			break;
		case 't':
			cfg->target = optarg;
			break;
		case 'S':
			cfg->as_socks5 = !!atoi(optarg);
			break;
		case 'Q':
			cfg->socks5_prefer_ipv6 = !!atoi(optarg);
			break;
		case 'o':
			cfg->socks5_timeout = atoi(optarg);
			break;
		case 'A':
			cfg->socks5_auth_file = optarg;
			break;
		case 'L':
			cfg->socks5_dns_cache_secs = atoi(optarg);
			break;
		case 'w':
			cfg->nr_workers = atoi(optarg);
			break;
		case 'W':
			cfg->nr_dns_workers = atoi(optarg);
			break;
		case 'c':
			cfg->connect_timeout = atoi(optarg);
			break;
		case 'T':
			cfg->target_buf_size = atoi(optarg);
			break;
		case 'C':
			cfg->client_buf_size = atoi(optarg);
			break;
		case 'd':
			cfg->tcp_nodelay = !!atoi(optarg);
			break;
		case 'K':
			cfg->tcp_quickack = !!atoi(optarg);
			break;
		case 'k':
			cfg->tcp_keepalive = !!atoi(optarg);
			break;
		case 'i':
			cfg->tcp_keepidle = atoi(optarg);
			break;
		case 'l':
			cfg->tcp_keepintvl = atoi(optarg);
			break;
		case 'g':
			cfg->tcp_keepcnt = atoi(optarg);
			break;
		case 'm':
			cfg->log_level = atoi(optarg);
			break;
		case 'f':
			cfg->log_file = optarg;
			break;
		case 'p':
			cfg->pid_file = optarg;
			break;
		default:
			fprintf(stderr, "Unknown option: %c\n", c);
			show_help(argv[0]);
			return -EINVAL;
		}
	}

	if (!cfg->as_socks5 && !cfg->target) {
		fprintf(stderr, "Error: --target is required unless --as-socks5 is specified.\n");
		return -EINVAL;
	}

	if (cfg->nr_workers <= 0) {
		fprintf(stderr, "Error: --nr-workers must be at least 1.\n");
		return -EINVAL;
	}

	if (cfg->target_buf_size <= 1) {
		fprintf(stderr, "Error: --target-buf-size must be greater than 1.\n");
		return -EINVAL;
	}

	if (cfg->client_buf_size <= 1) {
		fprintf(stderr, "Error: --client-buf-size must be greater than 1.\n");
		return -EINVAL;
	}

	return 0;
}

__hot
__attribute__((__format__(printf, 3, 4)))
static void __pr_log(FILE *handle, int level, const char *fmt, ...)
{
	char loc_buf[4096], *tmp, *pb, time_buf[64];
	va_list ap, ap2;
	const char *ls;
	struct tm tm;
	time_t now;
	int r;

	if (!handle)
		return;

	switch (level) {
	case 1:  ls = "error "; break;
	case 2:  ls = "warn  "; break;
	case 3:  ls = "info  "; break;
	case 4:  ls = "debug "; break;
	default: ls = "????? "; break;
	}

	va_start(ap, fmt);
	va_copy(ap2, ap);
	r = vsnprintf(loc_buf, sizeof(loc_buf), fmt, ap);
	if (unlikely((size_t)r >= sizeof(loc_buf))) {
		tmp = malloc(r + 1);
		if (!tmp)
			goto out;

		vsnprintf(tmp, r + 1, fmt, ap2);
		pb = tmp;
	} else {
		pb = loc_buf;
	}

	now = time(NULL);
	if (likely(localtime_r(&now, &tm)))
		strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm);
	else
		time_buf[0] = '\0';

	fprintf(handle, "[%s][%s][%08d]: %s\n", time_buf, ls, gettid(), pb);
	if (unlikely(pb != loc_buf))
		free(pb);
out:
	va_end(ap2);
	va_end(ap);
}

#ifndef GWP_STATIC_LOG_LEVEL
#define GWP_STATIC_LOG_LEVEL 4
#endif

#define pr_log(CTX, LEVEL, FMT, ...)		\
do {						\
	struct gwp_ctx *__ctx = (CTX);		\
	int __level = (LEVEL);			\
	if (__level > GWP_STATIC_LOG_LEVEL)	\
		break;				\
	if (__level > __ctx->cfg.log_level)	\
		break;				\
	if (!__ctx->log_file)			\
		break;				\
	__pr_log(__ctx->log_file, __level, FMT, ##__VA_ARGS__);	\
} while (0)

#define pr_err(CTX, FMT, ...)	\
	pr_log((CTX), 1, FMT, ##__VA_ARGS__)

#define pr_warn(CTX, FMT, ...)	\
	pr_log((CTX), 2, FMT, ##__VA_ARGS__)

#define pr_info(CTX, FMT, ...)	\
	pr_log((CTX), 3, FMT, ##__VA_ARGS__)

#define pr_dbg(CTX, FMT, ...)	\
	pr_log((CTX), 4, FMT, ##__VA_ARGS__)



#define FULL_ADDRSTRLEN (INET6_ADDRSTRLEN + sizeof(":65535[]") - 1)

static inline ssize_t gwp_eventfd_write(int fd, uint64_t val)
{
	uint64_t v = val;
	ssize_t r;

	do {
		r = __sys_write(fd, &v, sizeof(v));
	} while (r < 0 && r == -EINTR);

	if (r < 0)
		return r;
	if (r != sizeof(v))
		return -EIO;

	return 0;
}

__hot
static int convert_ssaddr_to_str(char buf[FULL_ADDRSTRLEN],
				 const struct gwp_sockaddr *gs)
{
	int f = gs->sa.sa_family;
	uint16_t port = 0;
	size_t l;

	if (f == AF_INET) {
		if (!inet_ntop(f, &gs->i4.sin_addr, buf, INET_ADDRSTRLEN))
			return -EINVAL;
		l = strlen(buf);
		port = ntohs(gs->i4.sin_port);
	} else if (f == AF_INET6) {
		buf[0] = '[';
		if (!inet_ntop(f, &gs->i6.sin6_addr, buf + 1, INET6_ADDRSTRLEN))
			return -EINVAL;
		l = strlen(buf);
		buf[l++] = ']';
		port = ntohs(gs->i6.sin6_port);
	} else {
		return -EINVAL;
	}

	buf[l++] = ':';
	snprintf(buf + l, FULL_ADDRSTRLEN - l, "%hu", port);
	return 0;
}

__hot
static const char *ip_to_str(const struct gwp_sockaddr *gs)
{
	static __thread char buf[8][FULL_ADDRSTRLEN];
	static __thread uint8_t idx = 0;
	char *bp = buf[idx++ % 8];

	return convert_ssaddr_to_str(bp, gs) ? NULL : bp;
}

__cold
static int convert_str_to_ssaddr(const char *str, struct gwp_sockaddr *gs)
{
	static const struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
	};
	char host[NI_MAXHOST], port[6], *p;
	struct addrinfo *res, *ai;
	bool found = false;
	size_t l;
	int r;

	if (*str == '[') {
		p = strchr(++str, ']');
		if (!p)
			return -EINVAL;
		l = p - str;
		if (l >= sizeof(host))
			return -EINVAL;
		p++;
		if (*p != ':')
			return -EINVAL;
	} else {
		p = strchr(str, ':');
		if (!p)
			return -EINVAL;
		l = p - str;
		if (l >= sizeof(host))
			return -EINVAL;
	}

	strncpy(host, str, l);
	host[l] = '\0';
	strncpy(port, p + 1, sizeof(port) - 1);
	port[sizeof(port) - 1] = '\0';

	r = getaddrinfo(host, port, &hints, &res);
	if (r)
		return -EINVAL;
	if (!res)
		return -EINVAL;

	memset(gs, 0, sizeof(*gs));
	for (ai = res; ai; ai = ai->ai_next) {
		if (ai->ai_family == AF_INET) {
			gs->i4 = *(struct sockaddr_in *)ai->ai_addr;
			found = true;
			break;
		} else if (ai->ai_family == AF_INET6) {
			gs->i6 = *(struct sockaddr_in6 *)ai->ai_addr;
			found = true;
			break;
		}
	}

	freeaddrinfo(res);
	return found ? 0 : -EINVAL;
}

__cold
static int gwp_ctx_init_log(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;
	int r = 0;

	if (!strcmp("/dev/stdout", cfg->log_file)) {
		ctx->log_file = stdout;
	} else if (!strcmp("/dev/stderr", cfg->log_file)) {
		ctx->log_file = stderr;
	} else if (!*cfg->log_file) {
		ctx->log_file = NULL;
	} else {
		ctx->log_file = fopen(cfg->log_file, "ab");
		if (!ctx->log_file) {
			r = -errno;
			pr_err(ctx, "Failed to open log file '%s': %s",
				cfg->log_file, strerror(-r));
		}
	}

	return r;
}

__cold
static void gwp_ctx_free_log(struct gwp_ctx *ctx)
{
	if (ctx->log_file &&
	    ctx->log_file != stdout &&
	    ctx->log_file != stderr) {
		fclose(ctx->log_file);
		ctx->log_file = NULL;
	}
}

__cold
static int gwp_ctx_init_pid_file(struct gwp_ctx *ctx)
{
	FILE *f;
	int r;

	f = fopen(ctx->cfg.pid_file, "wb");
	if (!f) {
		r = -errno;
		pr_warn(ctx, "Failed to open PID file '%s': %s",
			ctx->cfg.pid_file, strerror(-r));
		return r;
	}

	r = getpid();
	pr_info(ctx, "Writing PID to '%s' (pid=%d)", ctx->cfg.pid_file, r);
	fprintf(f, "%d\n", r);
	fclose(f);
	return 0;
}

__cold
static int gwp_ctx_init_thread_sock(struct gwp_wrk *w,
				    const struct gwp_sockaddr *ba)
{
	static const int type = SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC;
	struct gwp_cfg *cfg = &w->ctx->cfg;
	socklen_t slen;
	int fd, r, v;

	r = ba->sa.sa_family;
	if (r == AF_INET) {
		slen = sizeof(struct sockaddr_in);
	} else if (r == AF_INET6) {
		slen = sizeof(struct sockaddr_in6);
	} else {
		pr_err(w->ctx, "Unsupported address family: %d", r);
		return -EAFNOSUPPORT;
	}

	fd = __sys_socket(r, type, 0);
	if (fd < 0) {
		pr_err(w->ctx, "Failed to create socket: %s", strerror(-r));
		return r;
	}

	v = 1;
	__sys_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
	__sys_setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &v, sizeof(v));

	r = __sys_bind(fd, (struct sockaddr *)ba, slen);
	if (r < 0) {
		pr_err(w->ctx, "Failed to bind socket: %s", strerror(-r));
		goto out_close;
	}

	r = __sys_listen(fd, SOMAXCONN);
	if (r < 0) {
		pr_err(w->ctx, "Failed to listen on socket: %s", strerror(-r));
		goto out_close;
	}

	w->tcp_fd = fd;
	pr_info(w->ctx, "Worker %u is listening on %s (fd=%d)", w->idx,
		cfg->bind, fd);
	return 0;

out_close:
	__sys_close(fd);
	w->tcp_fd = -1;
	return r;
}

__cold
static void gwp_ctx_free_thread_sock(struct gwp_wrk *w)
{
	if (w->tcp_fd >= 0) {
		__sys_close(w->tcp_fd);
		pr_dbg(w->ctx, "Worker %u socket closed (fd=%d)", w->idx,
			w->tcp_fd);
		w->tcp_fd = -1;
	}
}

__cold
static int gwp_ctx_init_thread_epoll(struct gwp_wrk *w)
{
	struct epoll_event ev, *events;
	struct gwp_ctx *ctx = w->ctx;
	int ep_fd, ev_fd, r;

	ep_fd = __sys_epoll_create1(EPOLL_CLOEXEC);
	if (ep_fd < 0) {
		r = ep_fd;
		pr_err(w->ctx, "Failed to create epoll instance: %s\n",
			strerror(-r));
		return r;
	}

	ev_fd = __sys_eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (ev_fd < 0) {
		r = ev_fd;
		pr_err(w->ctx, "Failed to create eventfd: %s\n", strerror(-r));
		goto out_close_ep_fd;
	}

	w->evsz = 512;
	events = calloc(w->evsz, sizeof(*events));
	if (!events) {
		r = -ENOMEM;
		pr_err(w->ctx, "Failed to allocate memory for events: %s\n",
			strerror(-r));
		goto out_close_ev_fd;
	}

	w->ev_fd = ev_fd;
	w->ep_fd = ep_fd;
	w->events = events;

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.u64 = EV_BIT_EVENTFD;
	r = __sys_epoll_ctl(ep_fd, EPOLL_CTL_ADD, ev_fd, &ev);
	if (unlikely(r))
		goto out_free_events;

	ev.events = EPOLLIN;
	ev.data.u64 = EV_BIT_ACCEPT;
	r = __sys_epoll_ctl(ep_fd, EPOLL_CTL_ADD, w->tcp_fd, &ev);
	if (unlikely(r))
		goto out_free_events;

	if (w->idx == 0 && ctx->s5auth) {
		ev.events = EPOLLIN;
		ev.data.u64 = EV_BIT_SOCKS5_AUTH_FILE;
		r = __sys_epoll_ctl(ep_fd, EPOLL_CTL_ADD, ctx->s5auth->ino_fd, &ev);
		if (unlikely(r))
			goto out_free_events;
	}

	pr_dbg(w->ctx, "Worker %u epoll (ep_fd=%d, ev_fd=%d)", w->idx,
		ep_fd, ev_fd);
	return 0;

out_free_events:
	free(events);
	w->events = NULL;
out_close_ev_fd:
	__sys_close(ev_fd);
out_close_ep_fd:
	__sys_close(ep_fd);
	w->ev_fd = w->ep_fd = -1;
	return r;
}

__cold
static void gwp_ctx_free_thread_epoll(struct gwp_wrk *w)
{
	if (w->ev_fd >= 0) {
		__sys_close(w->ev_fd);
		pr_dbg(w->ctx, "Worker %u eventfd closed (fd=%d)", w->idx,
		       w->ev_fd);
		w->ev_fd = -1;
	}

	if (w->ep_fd >= 0) {
		__sys_close(w->ep_fd);
		pr_dbg(w->ctx, "Worker %u epoll closed (fd=%d)", w->idx,
		       w->ep_fd);
		w->ep_fd = -1;
	}

	free(w->events);
	w->events = NULL;
}

__cold
static int gwp_ctx_init_thread(struct gwp_wrk *w,
			       const struct gwp_sockaddr *bind_addr)
{
	int r;

	r = gwp_ctx_init_thread_sock(w, bind_addr);
	if (r < 0) {
		pr_err(w->ctx, "Failed to initialize thread socket: %s\n",
		       strerror(-r));
		return r;
	}

	r = gwp_ctx_init_thread_epoll(w);
	if (r < 0) {
		pr_err(w->ctx, "Failed to initialize epoll for worker %u: %s\n",
			w->idx, strerror(-r));
		goto out_free_sock;
	}

	return 0;

out_free_sock:
	gwp_ctx_free_thread_sock(w);
	return -r;
}

static void free_conn(struct gwp_conn *conn);

static void log_conn_pair_close(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	pr_info(w->ctx,
		"Closing connection pair (idx=%u, cfd=%d, tfd=%d, ca=%s, ta=%s)",
		gcp->idx, gcp->client.fd, gcp->target.fd,
		ip_to_str(&gcp->client_addr),
		ip_to_str(&gcp->target_addr));
}

__cold
static void gwp_ctx_free_thread_sock_pairs(struct gwp_wrk *w)
{
	struct gwp_conn_slot *gcs = &w->conn_slot;
	size_t i;

	if (!gcs->pairs)
		return;

	for (i = 0; i < gcs->nr; i++) {
		struct gwp_conn_pair *gcp = gcs->pairs[i];
		if (!gcp)
			continue;

		log_conn_pair_close(w, gcp);
		free_conn(&gcp->target);
		free_conn(&gcp->client);
		if (gcp->timer_fd >= 0)
			__sys_close(gcp->timer_fd);

		if (gcp->s5_conn)
			gwp_socks5_conn_free(gcp->s5_conn);

		free(gcp);
	}

	free(gcs->pairs);
	gcs->pairs = NULL;
	gcs->nr = 0;
	gcs->cap = 0;
}

__cold
static void gwp_ctx_free_thread(struct gwp_wrk *w)
{
	if (w->idx > 0)
		pthread_join(w->thread, NULL);
	gwp_ctx_free_thread_sock_pairs(w);
	gwp_ctx_free_thread_epoll(w);
	gwp_ctx_free_thread_sock(w);
}

__cold
static int gwp_ctx_init_threads(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;
	struct gwp_sockaddr bind_addr;
	struct gwp_wrk *workers, *w;
	int i, r;

	if (cfg->nr_workers <= 0) {
		pr_err(ctx, "Number of workers must be at least 1\n");
		return -EINVAL;
	}

	r = convert_str_to_ssaddr(cfg->bind, &bind_addr);
	if (r) {
		pr_err(ctx, "Invalid bind address '%s'\n", cfg->bind);
		return r;
	}

	workers = calloc(cfg->nr_workers, sizeof(*workers));
	if (!workers)
		return -ENOMEM;

	ctx->workers = workers;
	for (i = 0; i < cfg->nr_workers; i++) {
		w = &workers[i];
		w->ctx = ctx;
		w->idx = i;
		r = gwp_ctx_init_thread(w, &bind_addr);
		if (r < 0)
			goto out_err;
	}

	return 0;

out_err:
	while (i--)
		gwp_ctx_free_thread(&workers[i]);
	free(workers);
	ctx->workers = NULL;
	return r;
}

__cold
static void gwp_ctx_free_threads(struct gwp_ctx *ctx)
{
	struct gwp_wrk *workers = ctx->workers;
	int i;

	if (!workers)
		return;

	for (i = 0; i < ctx->cfg.nr_workers; i++)
		gwp_ctx_free_thread(&workers[i]);

	free(workers);
	ctx->workers = NULL;
}

static int gwp_load_s5auth_add_user(struct gwp_socks5_auth *s5a,
				    const char *line)
{
	char *u, *p;

	if (s5a->nr >= s5a->cap) {
		size_t new_cap = s5a->cap ? s5a->cap * 2 : 16;
		struct gwp_socks5_user *new_users;
		new_users = realloc(s5a->users, new_cap * sizeof(*new_users));
		if (!new_users)
			return -ENOMEM;
		s5a->users = new_users;
		s5a->cap = new_cap;
	}

	u = strdup(line);
	if (!u)
		return -ENOMEM;

	p = strchr(u, ':');
	if (p)
		*p++ = '\0';

	if (unlikely(strlen(u) > 255)) {
		free(u);
		return -EINVAL;
	}

	if (unlikely(p && strlen(p) > 255)) {
		free(u);
		return -EINVAL;
	}

	s5a->users[s5a->nr].u = u;
	s5a->users[s5a->nr].p = p;
	s5a->users[s5a->nr].ulen = strlen(u);
	s5a->users[s5a->nr].plen = p ? strlen(p) : 0;
	s5a->nr++;
	return 0;
}

static void gwp_load_s5auth_free_users(struct gwp_socks5_auth *s5a)
{
	size_t i;

	if (!s5a->users)
		return;

	for (i = 0; i < s5a->nr; i++)
		free(s5a->users[i].u);

	free(s5a->users);
	s5a->users = NULL;
	s5a->nr = 0;
	s5a->cap = 0;
}

static bool is_space(unsigned char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static char *trim_str(char *str)
{
	char *end;

	while (is_space((unsigned char)*str))
		str++;

	end = str + strlen(str) - 1;
	while (end > str && is_space((unsigned char)*end))
		end--;

	end[1] = '\0';
	return str;
}

__cold
static int gwp_load_s5auth(struct gwp_ctx *ctx)
{
	const char *s5a_file = ctx->cfg.socks5_auth_file;
	struct gwp_socks5_auth *s5a = ctx->s5auth;
	char buf[512], *t;
	int r = 0;
	size_t l;

	pr_info(ctx, "Loading SOCKS5 authentication from '%s'", s5a_file);
	pthread_rwlock_wrlock(&s5a->lock);
	gwp_load_s5auth_free_users(s5a);
	while (1) {
		t = fgets(buf, sizeof(buf), s5a->handle);
		if (!t)
			break;

		t = trim_str(t);
		l = strlen(t);
		if (!l)
			continue;

		r = gwp_load_s5auth_add_user(s5a, t);
		if (r)
			pr_err(ctx, "Failed to add user: %s (line='%s')",
				t, strerror(-r));
	}
	rewind(s5a->handle);
	l = s5a->nr;
	pthread_rwlock_unlock(&s5a->lock);
	pr_info(ctx, "Loaded %zu users from '%s'", l, s5a_file);
	return 0;
}

__cold
static int gwp_ctx_init_s5auth(struct gwp_ctx *ctx)
{
	const char *s5a_file = ctx->cfg.socks5_auth_file;
	struct gwp_socks5_auth *s5a;
	int r;

	if (!ctx->cfg.as_socks5 || !s5a_file || !*s5a_file) {
		ctx->s5auth = NULL;
		return 0;
	}

	s5a = calloc(1, sizeof(*s5a));
	if (!s5a)
		return -ENOMEM;

	r = pthread_rwlock_init(&s5a->lock, NULL);
	if (r) {
		r = -r;
		pr_err(ctx, "Failed to initialize SOCKS5 auth lock: %s",
			strerror(r));
		goto out_free_s5a;
	}

	s5a->handle = fopen(s5a_file, "rb");
	if (!s5a->handle) {
		r = -errno;
		pr_err(ctx, "Failed to open SOCKS5 auth file '%s': %s",
			s5a_file, strerror(-r));
		goto out_destroy_lock;
	}

	s5a->ino_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (s5a->ino_fd < 0) {
		r = -errno;
		pr_err(ctx, "Failed to create inotify instance: %s",
		       strerror(-r));
		goto out_fclose_handle;
	}

	r = inotify_add_watch(s5a->ino_fd, s5a_file, IN_CLOSE_WRITE | IN_DELETE);
	if (r < 0) {
		r = -errno;
		pr_err(ctx, "Failed to add inotify watch for '%s': %s",
		       s5a_file, strerror(-r));
		goto out_close_ino_fd;
	}

	ctx->s5auth = s5a;
	r = gwp_load_s5auth(ctx);
	if (r < 0) {
		free(ctx->s5auth->users);
		ctx->s5auth->users = NULL;
		pr_err(ctx, "Failed to load SOCKS5 authentication: %s",
		       strerror(-r));
		goto out_close_ino_fd;
	}

	return 0;

out_close_ino_fd:
	__sys_close(s5a->ino_fd);
out_fclose_handle:
	fclose(s5a->handle);
out_destroy_lock:
	pthread_rwlock_destroy(&s5a->lock);
out_free_s5a:
	free(s5a);
	ctx->s5auth = NULL;
	return r;
}

__cold
static void gwp_ctx_free_s5auth(struct gwp_ctx *ctx)
{
	struct gwp_socks5_auth *s5a = ctx->s5auth;

	if (!s5a)
		return;

	gwp_load_s5auth_free_users(s5a);
	__sys_close(s5a->ino_fd);
	fclose(s5a->handle);
	pthread_rwlock_destroy(&s5a->lock);
	free(s5a);
	ctx->s5auth = NULL;
}

static int gwp_ctx_init_socks5(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;
	struct gwp_socks5_cfg s5cfg;
	int r;

	if (!cfg->as_socks5) {
		ctx->socks5 = NULL;
		return 0;
	}

	pr_dbg(ctx, "Initializing SOCKS5 context");
	memset(&s5cfg, 0, sizeof(s5cfg));
	s5cfg.auth_file = (char *)cfg->socks5_auth_file;
	r = gwp_socks5_ctx_init(&ctx->socks5, &s5cfg);
	if (r < 0) {
		pr_err(ctx, "Failed to initialize SOCKS5 context: %s",
			strerror(-r));
		return r;
	}

	return 0;
}

static void gwp_ctx_free_socks5(struct gwp_ctx *ctx)
{
	if (!ctx->socks5)
		return;

	gwp_socks5_ctx_free(ctx->socks5);
	ctx->socks5 = NULL;
	pr_dbg(ctx, "SOCKS5 context freed");
}

static int gwp_ctx_init_dns(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;
	const struct gwp_dns_cfg dns_cfg = {
		.cache_expiry = cfg->socks5_dns_cache_secs,
		.restyp = cfg->socks5_prefer_ipv6 ? GWP_DNS_RESTYP_PREFER_IPV6 : 0,
		.nr_workers = cfg->nr_dns_workers
	};
	int r;

	if (!cfg->as_socks5) {
		ctx->dns = NULL;
		return 0;
	}

	r = gwp_dns_ctx_init(&ctx->dns, &dns_cfg);
	if (r < 0) {
		pr_err(ctx, "Failed to initialize DNS context: %s", strerror(-r));
		return r;
	}

	return 0;
}

static void gwp_ctx_free_dns(struct gwp_ctx *ctx)
{
	if (!ctx->dns)
		return;

	gwp_dns_ctx_free(ctx->dns);
	ctx->dns = NULL;
	pr_dbg(ctx, "DNS context freed");
}

__cold
static int gwp_ctx_init(struct gwp_ctx *ctx)
{
	int r;

	r = gwp_ctx_init_log(ctx);
	if (r < 0)
		return r;

	r = gwp_ctx_init_s5auth(ctx);
	if (r < 0) {
		pr_err(ctx, "Failed to init SOCKS5 authentication: %s", strerror(-r));
		goto out_free_log;
	}

	if (!ctx->cfg.as_socks5) {
		const char *t = ctx->cfg.target;
		r = convert_str_to_ssaddr(t, &ctx->target_addr);
		if (r) {
			pr_err(ctx, "Invalid target address '%s'", t);
			goto out_free_s5auth;
		}
	}

	if (ctx->cfg.pid_file)
		gwp_ctx_init_pid_file(ctx);

	r = gwp_ctx_init_socks5(ctx);
	if (r < 0)
		goto out_free_s5auth;

	r = gwp_ctx_init_dns(ctx);
	if (r < 0)
		goto out_free_socks5;

	r = gwp_ctx_init_threads(ctx);
	if (r < 0) {
		pr_err(ctx, "Failed to initialize worker threads: %s", strerror(-r));
		goto out_free_dns;
	}

	return 0;

out_free_dns:
	gwp_ctx_free_dns(ctx);
out_free_socks5:
	gwp_ctx_free_socks5(ctx);
out_free_s5auth:
	gwp_ctx_free_s5auth(ctx);
out_free_log:
	gwp_ctx_free_log(ctx);
	return r;
}

__cold
static void gwp_ctx_signal_all_workers(struct gwp_ctx *ctx)
{
	int i;

	if (!ctx->workers)
		return;

	for (i = 0; i < ctx->cfg.nr_workers; i++) {
		struct gwp_wrk *w = &ctx->workers[i];
		gwp_eventfd_write(w->ev_fd, 1);
	}
}

__cold
static void gwp_ctx_stop(struct gwp_ctx *ctx)
{
	ctx->stop = true;
	gwp_ctx_signal_all_workers(ctx);
}

__cold
static void gwp_ctx_free(struct gwp_ctx *ctx)
{
	gwp_ctx_stop(ctx);
	gwp_ctx_free_threads(ctx);
	gwp_ctx_free_dns(ctx);
	gwp_ctx_free_s5auth(ctx);
	gwp_ctx_free_socks5(ctx);
	gwp_ctx_free_log(ctx);
}

__cold
static int init_conn(struct gwp_conn *conn, uint32_t buf_size)
{
	conn->fd = -1;
	conn->len = 0;
	conn->cap = buf_size;
	conn->ep_mask = 0;
	conn->buf = malloc(buf_size);
	return conn->buf ? 0 : -ENOMEM;
}

static void free_conn(struct gwp_conn *conn)
{
	if (!conn)
		return;

	if (conn->buf)
		free(conn->buf);

	if (conn->fd >= 0)
		__sys_close(conn->fd);

	conn->len = 0;
	conn->cap = 0;
	conn->ep_mask = 0;
}

__hot
static struct gwp_conn_pair *alloc_conn_pair(struct gwp_wrk *w)
{
	struct gwp_conn_slot *gcs = &w->conn_slot;
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_cfg *cfg = &ctx->cfg;
	struct gwp_conn_pair *gcp;
	int r;

	if (gcs->nr >= gcs->cap) {
		struct gwp_conn_pair **new_pairs;
		size_t new_cap = gcs->cap + 4;

		new_pairs = realloc(gcs->pairs, new_cap * sizeof(*new_pairs));
		if (!new_pairs)
			return NULL;

		gcs->pairs = new_pairs;
		gcs->cap = new_cap;
		pr_dbg(ctx, "Increased connection slot capacity to %zu", gcs->cap);
	}

	gcp = calloc(1, sizeof(*gcp));
	if (!gcp)
		return NULL;

	assert(cfg->target_buf_size > 1);
	assert(cfg->client_buf_size > 1);
	r = init_conn(&gcp->target, cfg->target_buf_size);
	if (r)
		goto out_free_gcp;
	r = init_conn(&gcp->client, cfg->client_buf_size);
	if (r)
		goto out_free_target_conn;

	gcp->timer_fd = -1;
	gcp->idx = gcs->nr;
	gcp->conn_state = CONN_STATE_INIT;
	gcs->pairs[gcs->nr++] = gcp;
	return gcp;

out_free_target_conn:
	free_conn(&gcp->target);
out_free_gcp:
	free(gcp);
	pr_err(ctx, "Failed to allocate connection pair: %s", strerror(-r));
	return NULL;
}

static int rearm_accept(struct gwp_wrk *w, int nr_fd_closed)
{
	struct gwp_ctx *ctx = w->ctx;
	struct epoll_event ev;
	int x, r;

	/*
	 * Each connection pair consists of at least 3 file descriptors:
	 *
	 *   1. TCP socket for the client connection.
	 *   2. TCP socket for the target connection.
	 *   3. Timer file descriptor (if used).
	 *
	 * Before rearming the main TCP socket, wait until we have free
	 * space for at least 3 connection pairs per worker thread.
	 */
	if (nr_fd_closed <= ((3 * ctx->cfg.nr_workers) * 3))
		return 0;

	ev.events = EPOLLIN;
	ev.data.u64 = EV_BIT_ACCEPT;
	r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, w->tcp_fd, &ev);
	if (unlikely(r))
		return r;

	w->accept_is_stopped = false;
	pr_info(ctx,
		"Rearmed main TCP socket for accepting new connections (tidx=%u, fd=%d)",
		w->idx, w->tcp_fd);

	x = atomic_fetch_sub(&ctx->nr_accept_stopped, 1);
	if (x == 1)
		atomic_store(&ctx->nr_fd_closed, 0);

	return 0;
}

__hot
static int free_conn_pair(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_conn_slot *gcs = &w->conn_slot;
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_dns_entry *gde;
	struct gwp_conn_pair *tmp;
	uint32_t i = gcp->idx;
	int nr_fd_closed = 0;
	int r;

	tmp = gcs->pairs[i];
	assert(tmp == gcp);
	if (unlikely(tmp != gcp))
		return -EINVAL;

	gde = gcp->gde;
	if (gde) {
		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_DEL, gde->ev_fd, NULL);
		if (unlikely(r))
			return r;

		gwp_dns_entry_put(gde);
		gcp->gde = NULL;
	}

	if (gcp->client.fd >= 0) {
		nr_fd_closed++;
		w->ev_need_reload = true;
		log_conn_pair_close(w, gcp);
	}

	if (gcp->timer_fd >= 0) {
		nr_fd_closed++;
		__sys_close(gcp->timer_fd);
		gcp->timer_fd = -1;
	}

	if (gcp->target.fd >= 0)
		nr_fd_closed++;

	if (gcp->s5_conn) {
		gwp_socks5_conn_free(gcp->s5_conn);
		gcp->s5_conn = NULL;
	}

	tmp = gcs->pairs[--gcs->nr];
	gcs->pairs[gcs->nr] = NULL;
	gcs->pairs[i] = tmp;
	tmp->idx = i;
	free_conn(&gcp->target);
	free_conn(&gcp->client);
	free(gcp);

	if (!gcs->nr) {
		free(gcs->pairs);
		gcs->pairs = NULL;
		gcs->cap = 0;
		pr_dbg(ctx, "Decreased connection slot capacity to 0");
	} else if ((gcs->cap - gcs->nr) >= 16) {
		struct gwp_conn_pair **new_pairs;
		size_t new_cap = gcs->nr;

		new_pairs = realloc(gcs->pairs, new_cap * sizeof(*new_pairs));
		if (new_pairs) {
			gcs->pairs = new_pairs;
			gcs->cap = new_cap;
			pr_dbg(ctx, "Decreased connection slot capacity to %zu",
				gcs->cap);
		}
	}

	if (unlikely(w->accept_is_stopped)) {
		int x;
		/*
		 * If we have closed at least one file descriptor, we can
		 * rearm the main TCP socket with EPOLLIN to accept new
		 * connections.
		 */
		x = atomic_fetch_add(&ctx->nr_fd_closed, nr_fd_closed);
		r = rearm_accept(w, x);
		if (r)
			return r;
	}

	return 0;
}

static int setskopt_int(int fd, int level, int optname, int value)
{
	return __sys_setsockopt(fd, level, optname, &value, sizeof(value));
}

static void setup_sock_options(struct gwp_wrk *w, int fd)
{
	struct gwp_cfg *cfg = &w->ctx->cfg;

	if (cfg->tcp_nodelay)
		setskopt_int(fd, IPPROTO_TCP, TCP_NODELAY, 1);

	if (cfg->tcp_keepalive)
		setskopt_int(fd, SOL_SOCKET, SO_KEEPALIVE, 1);

	if (cfg->tcp_keepidle > 0)
		setskopt_int(fd, IPPROTO_TCP, TCP_KEEPIDLE, cfg->tcp_keepidle);

	if (cfg->tcp_keepintvl > 0)
		setskopt_int(fd, IPPROTO_TCP, TCP_KEEPINTVL, cfg->tcp_keepintvl);

	if (cfg->tcp_keepcnt > 0)
		setskopt_int(fd, IPPROTO_TCP, TCP_KEEPCNT, cfg->tcp_keepcnt);
}

__hot
static int create_sock_target(struct gwp_wrk *w, struct gwp_sockaddr *addr,
			      bool *is_target_alive)
{
	static const int t = SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC;
	socklen_t len;
	int fd, r;

	fd = __sys_socket(addr->sa.sa_family, t, 0);
	if (unlikely(fd < 0))
		return fd;

	setup_sock_options(w, fd);
	len = (addr->sa.sa_family == AF_INET) ? sizeof(struct sockaddr_in)
					      : sizeof(struct sockaddr_in6);
	r = __sys_connect(fd, &addr->sa, len);
	if (likely(r)) {
		if (r != -EINPROGRESS) {
			__sys_close(fd);
			return r;
		}
		*is_target_alive = false;
	} else {
		*is_target_alive = true;
	}

	return fd;
}

__hot
static int create_timer(int fd, int sec, int nsec)
{
	static const int flags = TFD_CLOEXEC | TFD_NONBLOCK;
	const struct itimerspec its = {
		.it_value.tv_sec = sec,
		.it_value.tv_nsec = nsec,
		.it_interval.tv_sec = 0,
		.it_interval.tv_nsec = 0,
	};
	bool need_close = false;
	int r;

	if (fd < 0) {
		fd = __sys_timerfd_create(CLOCK_MONOTONIC, flags);
		if (fd < 0)
			return fd;

		need_close = true;
	}

	r = __sys_timerfd_settime(fd, 0, &its, NULL);
	if (r < 0) {
		if (need_close)
			__sys_close(fd);
		return r;
	}

	return fd;
}

static void log_conn_pair_created(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	pr_info(ctx, "New connection pair created (idx=%u, cfd=%d, tfd=%d, ca=%s, ta=%s)",
		gcp->idx, gcp->client.fd, gcp->target.fd,
		ip_to_str(&gcp->client_addr), ip_to_str(&gcp->target_addr));
}

__hot
static int handle_new_client(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_cfg *cfg = &ctx->cfg;
	int fd, timer_fd, timeout, r;
	struct epoll_event ev;
	uint64_t cl_ev_bit;

	if (ctx->cfg.as_socks5) {
		/*
		 * If we are running as a SOCKS5 proxy, the initial connection
		 * does not have a target socket. We will create the target
		 * socket later, when the client sends a CONNECT command.
		 */
		timeout = cfg->socks5_timeout;
		fd = -1;
		gcp->conn_state = CONN_STATE_SOCKS5_DATA;
		cl_ev_bit = EV_BIT_CLIENT_SOCKS5;
		gcp->is_target_alive = false;
		gcp->s5_conn = gwp_socks5_conn_alloc(ctx->socks5);
		if (unlikely(!gcp->s5_conn))
			return -ENOMEM;
	} else {
		fd = create_sock_target(w, &gcp->target_addr,
					&gcp->is_target_alive);
		if (unlikely(fd < 0)) {
			pr_err(ctx, "Failed to create target socket: %s",
				strerror(-fd));
			return fd;
		}
		timeout = cfg->connect_timeout;
		gcp->conn_state = CONN_STATE_FORWARDING;
		cl_ev_bit = EV_BIT_CLIENT;
	}

	if (timeout > 0) {
		timer_fd = create_timer(-1, timeout, 0);
		if (unlikely(timer_fd < 0)) {
			pr_err(ctx, "Failed to create connect timeout timer: %s",
				strerror(-timer_fd));
			__sys_close(fd);
			gwp_socks5_conn_free(gcp->s5_conn);
			gcp->s5_conn = NULL;
			return timer_fd;
		}
		gcp->timer_fd = timer_fd;
	}

	/*
	 * If epoll_ctl() fails, don't bother closing the target socket
	 * because it will be closed in free_conn_pair() anyway.
	 */
	gcp->target.fd = fd;
	gcp->client.ep_mask = EPOLLIN | EPOLLRDHUP;

	if (gcp->target.fd >= 0) {
		gcp->target.ep_mask = EPOLLOUT | EPOLLIN | EPOLLRDHUP;
		ev.events = gcp->target.ep_mask;
		ev.data.u64 = 0;
		ev.data.ptr = gcp;
		ev.data.u64 |= EV_BIT_TARGET;
		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, gcp->target.fd, &ev);
		if (unlikely(r))
			return r;
	} else {
		gcp->target.ep_mask = 0;
	}

	ev.events = gcp->client.ep_mask;
	ev.data.u64 = 0;
	ev.data.ptr = gcp;
	ev.data.u64 |= cl_ev_bit;
	r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, gcp->client.fd, &ev);
	if (unlikely(r))
		return r;

	if (gcp->timer_fd >= 0) {
		ev.events = EPOLLIN;
		ev.data.u64 = 0;
		ev.data.ptr = gcp;
		ev.data.u64 |= EV_BIT_TIMER;
		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, gcp->timer_fd, &ev);
		if (unlikely(r))
			return r;
	}

	if (gcp->target.fd >= 0)
		log_conn_pair_created(w, gcp);

	return 0;
}

static int handle_accept_error(struct gwp_wrk *w, int e)
{
	int r;

	if (likely(e == -EAGAIN || e == -EINTR))
		return e;

	if (likely(e == -EMFILE || e == -ENFILE || e == -ENOMEM)) {
		/*
		 * We have reached the limit of open files. Delete the
		 * main TCP socket from the epoll instance to avoid
		 * getting EPOLLIN in the next epoll_wait() call.
		 *
		 * Set the accept_is_stopped flag to true to let the
		 * worker thread know that it should rearm the main
		 * TCP socket with EPOLLIN again after it has at least
		 * closed a file descriptor.
		 *
		 * See free_conn_pair() for more details.
		 */
		pr_warn(w->ctx, "Too many open files, stop accepting new connections");
		w->accept_is_stopped = true;
		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_DEL, w->tcp_fd, NULL);
		if (unlikely(r))
			return r;

		atomic_fetch_add(&w->ctx->nr_accept_stopped, 1);
		return -EAGAIN;
	}

	pr_err(w->ctx, "Failed to accept new connection: %s", strerror(-e));
	return e;
}

__hot
static int __handle_ev_accept(struct gwp_wrk *w)
{
	static const int flags = SOCK_NONBLOCK | SOCK_CLOEXEC;
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_conn_pair *gcp;
	struct sockaddr *addr;
	socklen_t addr_len;
	int fd, r;

	gcp = alloc_conn_pair(w);
	if (unlikely(!gcp)) {
		pr_err(ctx, "Failed to allocate connection pair on accept");
		return handle_accept_error(w, -ENOMEM);
	}

	addr = &gcp->client_addr.sa;
	addr_len = sizeof(gcp->client_addr);
	fd = __sys_accept4(w->tcp_fd, addr, &addr_len, flags);
	if (fd < 0) {
		r = handle_accept_error(w, fd);
		goto out_err;
	}

	setup_sock_options(w, fd);
	gcp->client.fd = fd;
	pr_dbg(ctx, "New connection from %s (fd=%d)",
		ip_to_str(&gcp->client_addr), fd);

	if (!ctx->cfg.as_socks5)
		gcp->target_addr = ctx->target_addr;

	r = handle_new_client(w, gcp);
	if (r) {
		if (r == -EMFILE || r == -ENFILE)
			r = handle_accept_error(w, r);
		goto out_err;
	}

	return 0;

out_err:
	free_conn_pair(w, gcp);
	return r;
}

__hot
static int handle_ev_accept(struct gwp_wrk *w, struct epoll_event *ev)
{
	static const uint32_t nr_loop = 32;
	uint32_t i;
	int r;

	if (unlikely(ev->events & EPOLLERR)) {
		pr_err(w->ctx, "EPOLLERR on accept event");
		return -EIO;
	}

	for (i = 0; i < nr_loop; i++) {
		r = __handle_ev_accept(w);
		if (r) {
			if (likely(r == -EAGAIN || r == -EINTR)) {
				r = 0;
				break;
			}
		}
	}

	return r;
}

static int handle_ev_eventfd(struct gwp_wrk *w, struct epoll_event *ev)
{
	eventfd_t val;

	if (unlikely(ev->events & EPOLLERR)) {
		pr_err(w->ctx, "EPOLLERR on eventfd event");
		return -EIO;
	}

	return eventfd_read(w->ev_fd, &val);
}

static bool adj_epl_out(struct gwp_conn *src, struct gwp_conn *dst)
{
	if (src->len > 0) {
		if (!(dst->ep_mask & EPOLLOUT)) {
			dst->ep_mask |= EPOLLOUT;
			return true;
		}
	} else {
		if (dst->ep_mask & EPOLLOUT) {
			dst->ep_mask &= ~EPOLLOUT;
			return true;
		}
	}

	return false;
}

static bool adj_epl_in(struct gwp_conn *src)
{
	if (src->cap - src->len) {
		if (!(src->ep_mask & EPOLLIN)) {
			src->ep_mask |= EPOLLIN;
			return true;
		}
	} else {
		if (src->ep_mask & EPOLLIN) {
			src->ep_mask &= ~EPOLLIN;
			return true;
		}
	}

	return false;
}

__hot
static int adjust_epl_mask(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	bool client_need_ctl = false;
	bool target_need_ctl = false;
	struct epoll_event ev;
	int r;

	client_need_ctl |= adj_epl_out(&gcp->target, &gcp->client);
	target_need_ctl |= adj_epl_out(&gcp->client, &gcp->target);
	client_need_ctl |= adj_epl_in(&gcp->client);
	target_need_ctl |= adj_epl_in(&gcp->target);

	if (client_need_ctl) {
		ev.events = gcp->client.ep_mask;
		ev.data.u64 = 0;
		ev.data.ptr = gcp;
		ev.data.u64 |= EV_BIT_CLIENT;

		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, gcp->client.fd, &ev);
		if (unlikely(r))
			return r;
	}

	if (target_need_ctl) {
		ev.events = gcp->target.ep_mask;
		ev.data.u64 = 0;
		ev.data.ptr = gcp;
		ev.data.u64 |= EV_BIT_TARGET;

		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, gcp->target.fd, &ev);
		if (unlikely(r))
			return r;
	}

	return 0;
}

__hot
static void gwp_conn_buf_advance(struct gwp_conn *conn, size_t len)
{
	conn->len -= len;
	if (conn->len)
		memmove(conn->buf, conn->buf + len, conn->len);
}

__hot
static ssize_t __do_recv(struct gwp_conn *src)
{
	ssize_t ret;
	size_t len;
	char *buf;

	len = src->cap - src->len;
	if (unlikely(len == 0))
		return 0;

	buf = src->buf + src->len;
	ret = __sys_recv(src->fd, buf, len, MSG_NOSIGNAL);
	if (unlikely(ret < 0)) {
		if (ret != -EAGAIN && ret != -EINTR)
			return ret;
		ret = 0;
	} else if (!ret) {
		return -ECONNRESET;
	}

	src->len += (size_t)ret;
	assert(src->len <= src->cap);
	return ret;
}

__hot
static ssize_t __do_send(struct gwp_conn *src, struct gwp_conn *dst)
{
	ssize_t ret;

	if (unlikely(src->len == 0))
		return 0;

	ret = __sys_send(dst->fd, src->buf, src->len, MSG_NOSIGNAL);
	if (unlikely(ret < 0)) {
		if (ret != -EAGAIN && ret != -EINTR)
			return ret;
		ret = 0;
	} else if (!ret) {
		return -ECONNRESET;
	}

	gwp_conn_buf_advance(src, (size_t)ret);
	return ret;
}

__hot
static int do_splice(struct gwp_conn *src, struct gwp_conn *dst, bool do_recv,
		     bool do_send)
{
	ssize_t ret;

	if (do_recv) {
		ret = __do_recv(src);
		if (unlikely(ret < 0))
			return ret;
	}

	if (do_send) {
		ret = __do_send(src, dst);
		if (unlikely(ret < 0))
			return ret;
	}

	return 0;
}

static int get_local_addr(struct gwp_ctx *ctx, int fd,
			  struct gwp_socks5_addr *ba)
{
	struct gwp_sockaddr t;
	socklen_t len = sizeof(t);
	int r;

	r = __sys_getsockname(fd, &t.sa, &len);
	if (r < 0) {
		pr_err(ctx, "getsockname error: %s", strerror(-r));
		return r;
	}

	switch (t.sa.sa_family) {
	case AF_INET:
		ba->ver = GWP_SOCKS5_ATYP_IPV4;
		memcpy(&ba->ip4, &t.i4.sin_addr, 4);
		ba->port = ntohs(t.i4.sin_port);
		return 0;
	case AF_INET6:
		ba->ver = GWP_SOCKS5_ATYP_IPV6;
		memcpy(&ba->ip6, &t.i6.sin6_addr, 16);
		ba->port = ntohs(t.i6.sin6_port);
		return 0;
	default:
		pr_err(ctx, "Unsupported address family %d for local socket",
			t.sa.sa_family);
		return -EAFNOSUPPORT;
	}
}

static int socks5_translate_err(int err)
{
	switch (err) {
	case 0:
		return GWP_SOCKS5_REP_SUCCESS;
	case -EPERM:
	case -EACCES:
		return GWP_SOCKS5_REP_NOT_ALLOWED;
	case -ENETUNREACH:
		return GWP_SOCKS5_REP_NETWORK_UNREACHABLE;
	case -EHOSTUNREACH:
		return GWP_SOCKS5_REP_HOST_UNREACHABLE;
	case -ECONNREFUSED:
		return GWP_SOCKS5_REP_CONN_REFUSED;
	case -ETIMEDOUT:
		return GWP_SOCKS5_REP_TTL_EXPIRED;
	default:
		return GWP_SOCKS5_REP_FAILURE;
	}
}

__hot
static int prep_and_send_socks5_rep_connect(struct gwp_wrk *w,
					    struct gwp_conn_pair *gcp,
					    int err)
{
	struct gwp_socks5_conn *sc = gcp->s5_conn;
	struct gwp_socks5_addr ba;
	size_t out_len;
	ssize_t sr;
	void *out;
	int r;

	if (err == 0) {
		r = get_local_addr(w->ctx, gcp->target.fd, &ba);
		if (unlikely(r))
			return r;
	} else {
		memset(&ba, 0, sizeof(ba));
		ba.ver = GWP_SOCKS5_ATYP_IPV4;
	}

	err = socks5_translate_err(err);
	out = gcp->target.buf + gcp->target.len;
	out_len = gcp->target.cap - gcp->target.len;
	r = gwp_socks5_conn_cmd_connect_res(sc, &ba, err, out, &out_len);
	if (r < 0)
		return r;

	gcp->target.len += out_len;
	sr = __do_send(&gcp->target, &gcp->client);
	if (unlikely(sr < 0))
		return sr;

	return 0;
}

__hot
static int handle_ev_target_conn_result(struct gwp_wrk *w,
					struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	socklen_t l = sizeof(int);
	int r, err = 0;
	ssize_t sr;

	r = __sys_getsockopt(gcp->target.fd, SOL_SOCKET, SO_ERROR, &err, &l);
	if (unlikely(r < 0)) {
		pr_err(ctx, "getsockopt error: %s", strerror(-r));
		goto out_conn_err;
	}

	if (likely(!err)) {
		pr_info(ctx, "Target socket connected (fd=%d, idx=%u, ca=%s, ta=%s)",
			gcp->target.fd, gcp->idx, ip_to_str(&gcp->client_addr),
			ip_to_str(&gcp->target_addr));
	} else {
		pr_err(ctx, "Target socket connect error: %s (fd=%d, idx=%u, ca=%s, ta=%s)",
			strerror(err), gcp->target.fd, gcp->idx,
			ip_to_str(&gcp->client_addr),
			ip_to_str(&gcp->target_addr));
		r = -err;
		goto out_conn_err;
	}

	if (gcp->timer_fd >= 0) {
		__sys_close(gcp->timer_fd);
		gcp->timer_fd = -1;
	}

	if (gcp->conn_state == CONN_STATE_SOCKS5_CMD_CONNECT) {
		r = prep_and_send_socks5_rep_connect(w, gcp, 0);
		if (r)
			return r;
	}

	gcp->is_target_alive = true;
	gcp->conn_state = CONN_STATE_FORWARDING;

	if (gcp->client.len) {
		sr = __do_send(&gcp->client, &gcp->target);
		if (unlikely(sr < 0))
			return sr;
	}

	return adjust_epl_mask(w, gcp);

out_conn_err:
	if (gcp->conn_state == CONN_STATE_SOCKS5_CMD_CONNECT) {
		int x = prep_and_send_socks5_rep_connect(w, gcp, err);
		if (x)
			return x;
	}
	return r;
}

__hot
static int handle_ev_target(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			    struct epoll_event *ev)
{
	int r;

	if (unlikely(ev->events & EPOLLERR)) {
		pr_err(w->ctx, "EPOLLERR on target connection event");
		return -ECONNRESET;
	}

	if (!gcp->is_target_alive)
		return handle_ev_target_conn_result(w, gcp);

	assert(gcp->conn_state == CONN_STATE_FORWARDING);
	if (ev->events & EPOLLIN) {
		r = do_splice(&gcp->target, &gcp->client, true, true);
		if (r)
			return r;
	}

	if (ev->events & EPOLLOUT) {
		r = do_splice(&gcp->client, &gcp->target, true, true);
		if (r)
			return r;
	}

	if (ev->events & (EPOLLRDHUP | EPOLLHUP))
		return -ECONNRESET;

	return adjust_epl_mask(w, gcp);
}

__hot
static int handle_ev_client(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			    struct epoll_event *ev)
{
	int r;

	if (unlikely(ev->events & EPOLLERR)) {
		pr_err(w->ctx, "EPOLLERR on client connection event");
		return -ECONNRESET;
	}

	if (ev->events & EPOLLIN) {
		r = do_splice(&gcp->client, &gcp->target, true, gcp->is_target_alive);
		if (r)
			return r;
	}

	if (ev->events & EPOLLOUT) {
		r = do_splice(&gcp->target, &gcp->client, true, true);
		if (r)
			return r;
	}

	if (ev->events & (EPOLLRDHUP | EPOLLHUP))
		return -ECONNRESET;

	return adjust_epl_mask(w, gcp);
}

__hot
static int handle_ev_timer(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;

	if (gcp->timer_fd < 0)
		return 0;

	pr_warn(ctx, "Connection timeout! (idx=%u, cfd=%d, tfd=%d, ca=%s, ta=%s)",
		gcp->idx, gcp->client.fd, gcp->target.fd,
		ip_to_str(&gcp->client_addr), ip_to_str(&gcp->target_addr));

	return -ETIMEDOUT;
}

__hot
static int handle_socks5_connect_domain_async(struct gwp_wrk *w,
					      struct gwp_conn_pair *gcp,
					      const char *host,
					      const char *port)
{
	struct gwp_dns_ctx *dns = w->ctx->dns;
	struct gwp_dns_entry *gde;
	struct epoll_event ev;
	int r;

	gde = gwp_dns_queue(dns, host, port);
	if (unlikely(!gde)) {
		pr_err(w->ctx, "Failed to allocate DNS entry for %s:%s", host, port);
		return -ENOMEM;
	}

	ev.events = EPOLLIN;
	ev.data.u64 = 0;
	ev.data.ptr = gcp;
	ev.data.u64 |= EV_BIT_DNS_QUERY;
	r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, gde->ev_fd, &ev);
	if (unlikely(r)) {
		gwp_dns_entry_put(gde);
		return r;
	}

	gcp->conn_state = CONN_STATE_SOCKS5_DNS_QUERY;
	gcp->gde = gde;
	return -EINPROGRESS;
}

static int socks5_prepare_target_addr_domain(struct gwp_wrk *w,
					     struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_socks5_addr *dst;
	const char *host;
	char portstr[6];
	uint16_t port;
	int r;

	dst = &gcp->s5_conn->dst_addr;
	port = ntohs(dst->port);
	host = dst->domain.str;
	snprintf(portstr, sizeof(portstr), "%hu", port);
	r = gwp_dns_cache_lookup(ctx->dns, host, portstr, &gcp->target_addr);
	if (!r) {
		/*
		 * Found the address in the DNS cache!
		 */
		pr_dbg(ctx, "Found %s:%s in DNS cache %s", host, portstr,
			ip_to_str(&gcp->target_addr));
		return 0;
	}

	return handle_socks5_connect_domain_async(w, gcp, host, portstr);
}

static int socks5_prepare_target_addr(struct gwp_wrk *w,
				      struct gwp_conn_pair *gcp)
{
	struct gwp_sockaddr *ta = &gcp->target_addr;
	struct gwp_socks5_conn *sc = gcp->s5_conn;
	struct gwp_socks5_addr *dst;

	assert(sc);
	assert(sc->state == GWP_SOCKS5_ST_CMD_CONNECT);

	dst = &sc->dst_addr;
	memset(ta, 0, sizeof(*ta));
	switch (dst->ver) {
	case GWP_SOCKS5_ATYP_IPV4:
		memcpy(&ta->i4.sin_addr, &dst->ip4, 4);
		ta->i4.sin_port = dst->port;
		ta->i4.sin_family = AF_INET;
		return 0;
	case GWP_SOCKS5_ATYP_IPV6:
		memcpy(&ta->i6.sin6_addr, &dst->ip6, 16);
		ta->i6.sin6_port = dst->port;
		ta->i6.sin6_family = AF_INET6;
		return 0;
	case GWP_SOCKS5_ATYP_DOMAIN:
		return socks5_prepare_target_addr_domain(w, gcp);
	}

	return -ENOSYS;
}

__hot
static int handle_socks5_connect(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct epoll_event ev;
	int tfd, r;

	if (gcp->timer_fd >= 0) {
		/*
		 * If we already have a timer fd, close it and use the new
		 * timer fd instead. There are two timers used in the socks5
		 * case:
		 *
		 *    1. Timer for waiting socks5 auth and command.
		 *    2. Timer for waiting target connect().
		 *
		 * If we've reached this point. Timer no (1) has already
		 * served its purpose and we can close it.
		 */
		__sys_close(gcp->timer_fd);
		gcp->timer_fd = -1;
	}

	tfd = create_sock_target(w, &gcp->target_addr, &gcp->is_target_alive);
	if (unlikely(tfd < 0)) {
		pr_err(w->ctx, "Failed to create target socket: %s", strerror(-tfd));
		return tfd;
	}

	r = w->ctx->cfg.connect_timeout;
	if (r > 0) {
		r = create_timer(-1, r, 0);
		if (unlikely(r < 0))
			return r;
		gcp->timer_fd = r;
	}

	gcp->target.fd = tfd;
	gcp->target.ep_mask = EPOLLOUT | EPOLLIN | EPOLLRDHUP;

	/*
	 * If epoll_ctl() calls fail, don't bother closing the
	 * newly created file descriptors as they will be closed
	 * in free_conn_pair() anyway.
	 */
	ev.events = gcp->client.ep_mask;
	ev.data.u64 = 0;
	ev.data.ptr = gcp;
	ev.data.u64 |= EV_BIT_CLIENT;
	r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, gcp->client.fd, &ev);
	if (unlikely(r))
		return r;

	ev.events = gcp->target.ep_mask;
	ev.data.u64 = 0;
	ev.data.ptr = gcp;
	ev.data.u64 |= EV_BIT_TARGET;
	r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, gcp->target.fd, &ev);
	if (unlikely(r))
		return r;

	if (gcp->timer_fd >= 0) {
		ev.events = EPOLLIN;
		ev.data.u64 = 0;
		ev.data.ptr = gcp;
		ev.data.u64 |= EV_BIT_TIMER;
		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, gcp->timer_fd, &ev);
		if (unlikely(r))
			return r;
	}

	gcp->conn_state = CONN_STATE_SOCKS5_CMD_CONNECT;
	log_conn_pair_created(w, gcp);
	return 0;
}

__hot
static int handle_socks5_pollout(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct epoll_event ev;
	ssize_t sr;
	int r;

	sr = __do_send(&gcp->target, &gcp->client);
	if (unlikely(sr < 0))
		return sr;

	if (likely(!adj_epl_out(&gcp->target, &gcp->client)))
		return 0;

	pr_dbg(w->ctx, "Handling short send on client SOCKS5 data");
	ev.events = gcp->client.ep_mask;
	ev.data.u64 = 0;
	ev.data.ptr = gcp;
	ev.data.u64 |= EV_BIT_CLIENT_SOCKS5;
	r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, gcp->client.fd, &ev);
	if (unlikely(r))
		return r;

	return -EAGAIN;
}

static int handle_socks5_data(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_socks5_conn *sc = gcp->s5_conn;
	size_t out_len, in_len;
	void *in, *out;
	int r;

	assert(sc);

	in = gcp->client.buf;
	in_len = gcp->client.len;
	out = gcp->target.buf + gcp->target.len;
	out_len = gcp->target.cap - gcp->target.len;
	r = gwp_socks5_conn_handle_data(sc, in, &in_len, out, &out_len);
	gwp_conn_buf_advance(&gcp->client, in_len);
	gcp->target.len += out_len;
	if (r)
		return (r == -EAGAIN) ? 0 : r;

	if (sc->state == GWP_SOCKS5_ST_CMD_CONNECT) {
		r = socks5_prepare_target_addr(w, gcp);
		if (r)
			return (r == -EINPROGRESS) ? 0 : r;

		r = handle_socks5_connect(w, gcp);
	}

	return r;
}

__hot
static int handle_ev_client_socks5(struct gwp_wrk *w,
				   struct gwp_conn_pair *gcp,
				   struct epoll_event *ev)
{
	struct gwp_ctx *ctx = w->ctx;
	ssize_t sr;
	int r = 0;

	assert(ctx->cfg.as_socks5);

	if (unlikely(ev->events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP))) {
		pr_info(ctx, "(EPOLLERR|EPOLLHUP|EPOLLRDHUP) on client SOCKS5 event");
		return -ECONNRESET;
	}

	if (ev->events & EPOLLOUT) {
		r = handle_socks5_pollout(w, gcp);
		if (r)
			return (r == -EAGAIN) ? 0 : r;
	}

	if (ev->events & EPOLLIN) {
		sr = __do_recv(&gcp->client);

		/*
		 * sr == 0 is fine, but must be back to
		 * epoll_wait() before continuing.
		 */
		if (unlikely(sr <= 0))
			return sr;
	}

	if (gcp->conn_state == CONN_STATE_SOCKS5_DATA) {
		r = handle_socks5_data(w, gcp);
		if (gcp->target.len) {
			r = handle_socks5_pollout(w, gcp);
			if (r && r != -EAGAIN)
				return r;
		}
	}

	return r;
}

static void log_dns_query(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			  struct gwp_dns_entry *gde)
{
	struct gwp_ctx *ctx = w->ctx;

	if (gde->res) {
		pr_dbg(ctx, "DNS query failed: %s:%s (res=%d; idx=%u; cfd=%d; tfd=%d; ca=%s)",
			gde->name, gde->service, gde->res,
			gcp->idx, gcp->client.fd, gcp->target.fd,
			ip_to_str(&gcp->client_addr));
		return;
	}

	pr_dbg(ctx, "DNS query resolved: %s:%s -> %s (res=%d; idx=%u; cfd=%d; tfd=%d; ca=%s)",
		gde->name, gde->service, ip_to_str(&gde->addr), gde->res,
		gcp->idx, gcp->client.fd, gcp->target.fd,
		ip_to_str(&gcp->client_addr));
}

__hot
static int handle_ev_dns_query(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_dns_entry *gde = gcp->gde;
	int r;

	assert(gde);
	assert(gde->ev_fd >= 0);
	assert(gcp->conn_state == CONN_STATE_SOCKS5_DNS_QUERY);

	r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_DEL, gde->ev_fd, NULL);
	if (unlikely(r))
		return r;

	log_dns_query(w, gcp, gde);
	if (likely(!gde->res)) {
		gcp->target_addr = gde->addr;
		r = handle_socks5_connect(w, gcp);
	} else {
		r = prep_and_send_socks5_rep_connect(w, gcp, gde->res);
	}

	gwp_dns_entry_put(gde);
	gcp->gde = NULL;

	if (unlikely(gcp->conn_state == CONN_STATE_SOCKS5_ERR))
		return -ECONNRESET;

	return r;
}

static int handle_ev_socks5_auth_file(struct gwp_wrk *w)
{
	char buf[sizeof(struct inotify_event) + NAME_MAX + 1];
	struct gwp_ctx *ctx = w->ctx;
	ssize_t r;

	assert(ctx->cfg.as_socks5);
	assert(ctx->s5auth);

	r = __sys_read(ctx->s5auth->ino_fd, buf, sizeof(buf));
	if (unlikely(r < 0)) {
		if (r == -EINTR || r == -EAGAIN)
			return 0;
		return r;
	}

	return gwp_load_s5auth(ctx);
}

static bool is_ev_bit_conn_pair(uint64_t ev_bit)
{
	static const uint64_t conn_pair_ev_bit =
		EV_BIT_CLIENT | EV_BIT_TARGET | EV_BIT_TIMER |
		EV_BIT_CLIENT_SOCKS5 | EV_BIT_DNS_QUERY;

	return !!(ev_bit & conn_pair_ev_bit);
}

static int handle_event(struct gwp_wrk *w, struct epoll_event *ev)
{
	uint64_t ev_bit;
	void *udata;
	int r;

	ev_bit = GET_EV_BIT(ev->data.u64);
	ev->data.u64 = CLEAR_EV_BIT(ev->data.u64);
	udata = ev->data.ptr;

	switch (ev_bit) {
	case EV_BIT_ACCEPT:
		r = handle_ev_accept(w, ev);
		break;
	case EV_BIT_EVENTFD:
		r = handle_ev_eventfd(w, ev);
		break;
	case EV_BIT_TARGET:
		r = handle_ev_target(w, udata, ev);
		break;
	case EV_BIT_CLIENT:
		r = handle_ev_client(w, udata, ev);
		break;
	case EV_BIT_TIMER:
		r = handle_ev_timer(w, udata);
		break;
	case EV_BIT_CLIENT_SOCKS5:
		r = handle_ev_client_socks5(w, udata, ev);
		break;
	case EV_BIT_DNS_QUERY:
		r = handle_ev_dns_query(w, udata);
		break;
	case EV_BIT_SOCKS5_AUTH_FILE:
		r = handle_ev_socks5_auth_file(w);
		break;
	default:
		pr_err(w->ctx, "Unknown event bit: %" PRIu64, ev_bit);
		return -EINVAL;
	}

	if (r && is_ev_bit_conn_pair(ev_bit)) {
		struct gwp_conn_pair *gcp = udata;
		r = free_conn_pair(w, gcp);
	}

	return r;
}

static int handle_events(struct gwp_wrk *w, int nr_events)
{
	struct epoll_event *events = w->events;
	struct gwp_ctx *ctx = w->ctx;
	int i, r = 0;

	for (i = 0; i < nr_events; i++) {
		if (unlikely(ctx->stop))
			break;

		r = handle_event(w, &events[i]);
		if (unlikely(r < 0))
			break;

		if (w->ev_need_reload)
			break;
	}

	return r;
}

static int fish_events(struct gwp_wrk *w)
{
	int r;

	w->ev_need_reload = false;
	r = __sys_epoll_wait(w->ep_fd, w->events, w->evsz, -1);
	if (unlikely(r < 0)) {
		if (r != -EINTR)
			pr_err(w->ctx, "epoll_wait failed: %s", strerror(-r));
		else
			r = 0;
	}

	return r;
}

noinline
static void *gwp_ctx_thread_entry(void *arg)
{
	struct gwp_wrk *w = arg;
	struct gwp_ctx *ctx = w->ctx;
	int r = 0;

	pr_info(ctx, "Worker %u started", w->idx);
	while (!ctx->stop) {
		r = fish_events(w);
		if (unlikely(r < 0))
			break;

		r = handle_events(w, r);
		if (unlikely(r < 0))
			break;
	}

	ctx->stop = true;
	gwp_ctx_signal_all_workers(ctx);
	pr_info(ctx, "Worker %u stopped", w->idx);
	return (void *)(intptr_t)r;
}

static int gwp_ctx_run(struct gwp_ctx *ctx)
{
	int i, r;

	for (i = 0; i < ctx->cfg.nr_workers; i++) {
		struct gwp_wrk *w = &ctx->workers[i];
		char tmp[128];

		/*
		 * Skip the first worker as it will
		 * run on the main thread.
		 */
		if (i == 0)
			continue;

		r = pthread_create(&w->thread, NULL, &gwp_ctx_thread_entry, w);
		if (r) {
			gwp_ctx_stop(ctx);
			pr_err(ctx, "Failed to create worker thread %d: %s",
				i, strerror(r));
			return -r;
		}

		snprintf(tmp, sizeof(tmp), "gwproxy-wrk-%d", i);
		pthread_setname_np(w->thread, tmp);
	}

	return (int)(intptr_t)gwp_ctx_thread_entry(&ctx->workers[0]);
}

static struct gwp_ctx *g_ctx = NULL;

__cold
static void sig_handler(int sig)
{
	if (g_ctx)
		gwp_ctx_stop(g_ctx);

	(void)sig;
}

static void prepare_rlimit(void)
{
	struct rlimit rl;
	int r;

	r = getrlimit(RLIMIT_NOFILE, &rl);
	if (r < 0) {
		fprintf(stderr, "Failed to get RLIMIT_NOFILE: %s\n", strerror(errno));
		return;
	}

	rl.rlim_cur = rl.rlim_max;
	r = setrlimit(RLIMIT_NOFILE, &rl);
	if (r < 0) {
		fprintf(stderr, "Failed to set RLIMIT_NOFILE: %s\n", strerror(errno));
		return;
	}
}

int main(int argc, char *argv[])
{
	struct sigaction sa = { .sa_handler = &sig_handler };
	struct gwp_ctx ctx;
	int r;

	memset(&ctx, 0, sizeof(ctx));
	r = parse_options(argc, argv, &ctx.cfg);
	if (r < 0)
		goto out;

	prepare_rlimit();
	r = gwp_ctx_init(&ctx);
	if (r < 0)
		goto out;

	g_ctx = &ctx;
	r |= sigaction(SIGINT, &sa, NULL);
	r |= sigaction(SIGTERM, &sa, NULL);
	sa.sa_handler = SIG_IGN;
	r |= sigaction(SIGPIPE, &sa, NULL);
	if (r < 0) {
		r = -errno;
		fprintf(stderr, "Failed to set signal handlers: %s\n", strerror(-r));
		goto out_free;
	}

	r = gwp_ctx_run(&ctx);
out_free:
	gwp_ctx_free(&ctx);
out:
	return -r;
}
