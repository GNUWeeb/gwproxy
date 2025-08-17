// SPDX-License-Identifier: GPL-2.0-only
/*
 * gwproxy - A simple TCP proxy server.
 *
 * Copyright (C) 2025 Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#include <gwproxy/gwproxy.h>
#include <gwproxy/common.h>
#include <gwproxy/log.h>
#include <gwproxy/ev/epoll.h>
#ifdef CONFIG_IO_URING
#include <gwproxy/ev/io_uring.h>
#endif

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

static const struct option long_opts[] = {
	{ "help",		no_argument,		NULL,	'h' },
	{ "event-loop",		required_argument,	NULL,	'e' },
	{ "bind",		required_argument,	NULL,	'b' },
	{ "target",		required_argument,	NULL,	't' },
	{ "as-socks5",		required_argument,	NULL,	'S' },
	{ "as-http",		required_argument,	NULL,	'H' },
	{ "socks5-prefer-ipv6",	required_argument,	NULL,	'Q' },
	{ "protocol-timeout",	required_argument,	NULL,	'o' },
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

static const struct gwp_cfg default_opts = {
	.event_loop		= "epoll",
	.bind			= "[::]:1080",
	.target			= NULL,
	.as_socks5		= false,
	.as_http		= false,
	.socks5_prefer_ipv6	= false,
	.protocol_timeout	= 10,
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
	printf("  -H, --as-http=0|1               Run as an HTTP proxy (default: %d)\n", default_opts.as_http);
	printf("  -Q, --socks5-prefer-ipv6=0|1    Prefer IPv6 for SOCKS5 DNS queries (default: %d)\n", default_opts.socks5_prefer_ipv6);
	printf("  -o, --protocol-timeout=sec      Timeout for protocol handshake process (default: %d)\n", default_opts.protocol_timeout);
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
	#define ERR_WRAP "==============================================\n"
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
		case 'H':
			cfg->as_http = !!atoi(optarg);
			break;
		case 'Q':
			cfg->socks5_prefer_ipv6 = !!atoi(optarg);
			break;
		case 'o':
			cfg->protocol_timeout = atoi(optarg);
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

	if (!cfg->as_socks5 && !cfg->as_http && !cfg->target) {
		fprintf(stderr, ERR_WRAP "Error: --target is required unless --as-socks5=1 or --as-http=1\n" ERR_WRAP);
		goto einval;
	}

	if (cfg->nr_workers <= 0) {
		fprintf(stderr, ERR_WRAP "Error: --nr-workers must be at least 1.\n" ERR_WRAP);
		goto einval;
	}

	if (cfg->target_buf_size <= 1) {
		fprintf(stderr, ERR_WRAP "Error: --target-buf-size must be greater than 1.\n" ERR_WRAP);
		goto einval;
	}

	if (cfg->client_buf_size <= 1) {
		fprintf(stderr, ERR_WRAP "Error: --client-buf-size must be greater than 1.\n" ERR_WRAP);
		goto einval;
	}

	if (cfg->as_socks5 || cfg->as_http) {
		if (cfg->client_buf_size < 256) {
			fprintf(stderr, ERR_WRAP "Error: --client-buf-size must be at least 256 for SOCKS5 or HTTP.\n" ERR_WRAP);
			goto einval;
		}

		if (cfg->target_buf_size < 256) {
			fprintf(stderr, ERR_WRAP "Error: --target-buf-size must be at least 256 for SOCKS5 or HTTP.\n" ERR_WRAP);
			goto einval;
		}
	}

	return 0;

einval:
	fprintf(stderr, "\n");
	show_help(argv[0]);
	return -EINVAL;
}

#define FULL_ADDRSTRLEN (INET6_ADDRSTRLEN + sizeof(":65535[]") - 1)

__hot
const char *ip_to_str(const struct gwp_sockaddr *gs)
{
	static __thread char buf[8][FULL_ADDRSTRLEN];
	static __thread uint8_t idx = 0;
	char *bp = buf[idx++ % 8];

	return convert_ssaddr_to_str(bp, gs) ? NULL : bp;
}

__cold
static int gwp_ctx_init_log(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;
	int r = 0;

	if (!strcmp("/dev/stdout", cfg->log_file)) {
		ctx->lh.handle = stdout;
	} else if (!strcmp("/dev/stderr", cfg->log_file)) {
		ctx->lh.handle = stderr;
	} else if (!*cfg->log_file) {
		ctx->lh.handle = NULL;
	} else {
		ctx->lh.handle = fopen(cfg->log_file, "ab");
		if (!ctx->lh.handle) {
			r = -errno;
			pr_err(&ctx->lh, "Failed to open log file '%s': %s",
				cfg->log_file, strerror(-r));
		}
	}

	ctx->lh.level = ctx->cfg.log_level;
	return r;
}

__cold
static void gwp_ctx_free_log(struct gwp_ctx *ctx)
{
	if (ctx->lh.handle &&
	    ctx->lh.handle != stdout &&
	    ctx->lh.handle != stderr) {
		fclose(ctx->lh.handle);
		ctx->lh.handle = NULL;
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
		pr_warn(&ctx->lh, "Failed to open PID file '%s': %s",
			ctx->cfg.pid_file, strerror(-r));
		return r;
	}

	r = getpid();
	pr_info(&ctx->lh, "Writing PID to '%s' (pid=%d)", ctx->cfg.pid_file, r);
	fprintf(f, "%d\n", r);
	fclose(f);
	return 0;
}

__cold
static int gwp_ctx_init_thread_sock(struct gwp_wrk *w,
				    const struct gwp_sockaddr *ba)
{
	struct gwp_ctx *ctx = w->ctx;
	int type = SOCK_STREAM | SOCK_CLOEXEC | 
			(ctx->ev_used == GWP_EV_EPOLL ? SOCK_NONBLOCK : 0);
	struct gwp_cfg *cfg = &w->ctx->cfg;
	socklen_t slen;
	int fd, r, v;

	r = ba->sa.sa_family;
	if (r == AF_INET) {
		slen = sizeof(struct sockaddr_in);
	} else if (r == AF_INET6) {
		slen = sizeof(struct sockaddr_in6);
	} else {
		pr_err(&w->ctx->lh, "Unsupported address family: %d", r);
		return -EAFNOSUPPORT;
	}

	fd = __sys_socket(r, type, 0);
	if (fd < 0) {
		pr_err(&w->ctx->lh, "Failed to create socket: %s", strerror(-r));
		return r;
	}

	v = 1;
	__sys_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
	__sys_setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &v, sizeof(v));

	r = __sys_bind(fd, (struct sockaddr *)ba, slen);
	if (r < 0) {
		pr_err(&w->ctx->lh, "Failed to bind socket: %s", strerror(-r));
		goto out_close;
	}

	r = __sys_listen(fd, SOMAXCONN);
	if (r < 0) {
		pr_err(&w->ctx->lh, "Failed to listen on socket: %s", strerror(-r));
		goto out_close;
	}

	w->tcp_fd = fd;
	pr_info(&w->ctx->lh, "Worker %u is listening on %s (fd=%d)", w->idx,
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
		pr_dbg(&w->ctx->lh, "Worker %u socket closed (fd=%d)", w->idx,
			w->tcp_fd);
		w->tcp_fd = -1;
	}
}

static int gwp_ctx_init_thread_event(struct gwp_wrk *w)
{
	switch (w->ctx->ev_used) {
	case GWP_EV_EPOLL:
		return gwp_ctx_init_thread_epoll(w);
	case GWP_EV_IO_URING:
#ifdef CONFIG_IO_URING
		return gwp_ctx_init_thread_io_uring(w);
#else
		pr_err(&w->ctx->lh, "IO_URING support is not enabled in this build");
		return -ENOSYS;
#endif
	default:
		pr_err(&w->ctx->lh, "Unknown event loop type: %d", w->ctx->ev_used);
		return -EINVAL;
	}
}

static void gwp_ctx_free_thread_event(struct gwp_wrk *w)
{
	switch (w->ctx->ev_used) {
	case GWP_EV_EPOLL:
		gwp_ctx_free_thread_epoll(w);
		break;
	case GWP_EV_IO_URING:
#ifdef CONFIG_IO_URING
		gwp_ctx_free_thread_io_uring(w);
#else
		pr_err(&w->ctx->lh, "IO_URING support is not enabled in this build");
#endif
		break;
	default:
		pr_err(&w->ctx->lh, "Unknown event loop type: %d", w->ctx->ev_used);
		break;
	}
}

__cold
static int gwp_ctx_init_thread(struct gwp_wrk *w,
			       const struct gwp_sockaddr *bind_addr)
{
	struct gwp_ctx *ctx = w->ctx;
	int r;

	r = gwp_ctx_init_thread_sock(w, bind_addr);
	if (r < 0) {
		pr_err(&ctx->lh, "gwp_ctx_init_thread_sock: %s\n", strerror(-r));
		return r;
	}

	r = gwp_ctx_init_thread_event(w);
	if (r < 0) {
		pr_err(&ctx->lh, "gwp_ctx_init_thread_event: %s\n", strerror(-r));
		gwp_ctx_free_thread_sock(w);
	}

	return r;
}

static void free_conn(struct gwp_conn *conn);

static void log_conn_pair_close(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	pr_info(&w->ctx->lh,
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
static void gwp_ctx_signal_all_workers(struct gwp_ctx *ctx)
{
	if (!ctx->workers)
		return;

	if (ctx->ev_used == GWP_EV_EPOLL) {
		gwp_ctx_signal_all_epoll(ctx);
	} else if (ctx->ev_used == GWP_EV_IO_URING) {
#ifdef CONFIG_IO_URING
		gwp_ctx_signal_all_io_uring(ctx);
#endif
	}
}

__cold
static void gwp_ctx_free_thread(struct gwp_wrk *w)
{
	gwp_ctx_free_thread_sock_pairs(w);
	gwp_ctx_free_thread_sock(w);
	gwp_ctx_free_thread_event(w);
}

__cold
static int gwp_ctx_init_threads(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;
	struct gwp_sockaddr bind_addr;
	struct gwp_wrk *workers, *w;
	int i, r;

	if (cfg->nr_workers <= 0) {
		pr_err(&ctx->lh, "Number of workers must be at least 1\n");
		return -EINVAL;
	}

	r = convert_str_to_ssaddr(cfg->bind, &bind_addr, 0);
	if (r) {
		pr_err(&ctx->lh, "Invalid bind address '%s'\n", cfg->bind);
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
	struct gwp_wrk *w, *workers = ctx->workers;
	int i;

	if (!workers)
		return;

	ctx->stop = true;
	gwp_ctx_signal_all_workers(ctx);
	for (i = 0; i < ctx->cfg.nr_workers; i++) {
		w = &workers[i];
		if (!w->need_join)
			continue;

		pr_dbg(&ctx->lh, "Joining worker thread %d", i);
		pthread_join(w->thread, NULL);
		w->need_join = false;
	}

	for (i = 0; i < ctx->cfg.nr_workers; i++)
		gwp_ctx_free_thread(&workers[i]);

	free(workers);
	ctx->workers = NULL;
}

static int gwp_ctx_init_socks5(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;
	struct gwp_socks5_cfg s5cfg;
	int r;

	pr_dbg(&ctx->lh, "Initializing SOCKS5 context");
	memset(&s5cfg, 0, sizeof(s5cfg));
	s5cfg.auth_file = (char *)cfg->socks5_auth_file;
	r = gwp_socks5_ctx_init(&ctx->socks5, &s5cfg);
	if (r < 0) {
		pr_err(&ctx->lh, "Failed to initialize SOCKS5 context: %s",
			strerror(-r));
		return r;
	}

	if (!s5cfg.auth_file || !*s5cfg.auth_file) {
		pr_dbg(&ctx->lh, "SOCKS5 context initialized without auth file");
		ctx->ino_buf = NULL;
		ctx->ino_fd = -1;
		return 0;
	}

	r = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (r < 0) {
		pr_err(&ctx->lh, "Failed to initialize inotify: %s", strerror(-r));
		goto out_err;
	}

	pr_dbg(&ctx->lh, "Inotify file descriptor initialized (fd=%d)", r);

	ctx->ino_fd = r;
	r = inotify_add_watch(ctx->ino_fd, cfg->socks5_auth_file,
			      IN_DELETE | IN_CLOSE_WRITE);
	if (r < 0) {
		pr_err(&ctx->lh, "Failed to add inotify watch: %s", strerror(-r));
		goto out_err;
	}

	pr_dbg(&ctx->lh, "Inotify watch added for '%s' (wd=%d)", cfg->socks5_auth_file, r);

	ctx->ino_buf = malloc(sizeof(struct inotify_event) + NAME_MAX + 1);
	if (!ctx->ino_buf) {
		pr_err(&ctx->lh, "Failed to allocate inotify buffer: %s", strerror(ENOMEM));
		r = -ENOMEM;
		goto out_err;
	}

	return 0;

out_err:
	gwp_socks5_ctx_free(ctx->socks5);
	ctx->socks5 = NULL;
	if (ctx->ino_fd >= 0) {
		__sys_close(ctx->ino_fd);
		ctx->ino_fd = -1;
	}
	return r;
}

static void gwp_ctx_free_socks5(struct gwp_ctx *ctx)
{
	assert(ctx->cfg->as_socks5);
	gwp_socks5_ctx_free(ctx->socks5);
	ctx->socks5 = NULL;
	pr_dbg(&ctx->lh, "SOCKS5 context freed");

	if (ctx->ino_fd >= 0) {
		__sys_close(ctx->ino_fd);
		ctx->ino_fd = -1;
		pr_dbg(&ctx->lh, "Inotify file descriptor closed");
	}

	if (ctx->ino_buf) {
		free(ctx->ino_buf);
		ctx->ino_buf = NULL;
		pr_dbg(&ctx->lh, "Inotify buffer freed");
	}
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

	if (!cfg->as_socks5 && !cfg->as_http) {
		ctx->dns = NULL;
		return 0;
	}

	r = gwp_dns_ctx_init(&ctx->dns, &dns_cfg);
	if (r < 0) {
		pr_err(&ctx->lh, "Failed to initialize DNS context: %s", strerror(-r));
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
	pr_dbg(&ctx->lh, "DNS context freed");
}

static int gwp_ctx_parse_ev(struct gwp_ctx *ctx)
{
	const char *ev = ctx->cfg.event_loop;

	if (!ev || !*ev) {
		ctx->ev_used = GWP_EV_EPOLL;
		pr_dbg(&ctx->lh, "Using default event loop: epoll");
		return 0;
	}

	if (!strcmp(ev, "epoll")) {
		ctx->ev_used = GWP_EV_EPOLL;
		pr_dbg(&ctx->lh, "Using event loop: epoll");
	} else if (!strcmp(ev, "io_uring") || !strcmp(ev, "iou")) {
		ctx->ev_used = GWP_EV_IO_URING;
		pr_dbg(&ctx->lh, "Using event loop: io_uring");
	} else {
		pr_err(&ctx->lh, "Unknown event loop '%s'", ev);
		return -EINVAL;
	}

	return 0;
}

__cold
static int gwp_ctx_init_prot(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;

	/*
	 * socks5 and http can't be running together.
	 */
	assert(!(cfg->as_socks5 && cfg->as_http));

	if (cfg->as_socks5) {
		return gwp_ctx_init_socks5(ctx);
	} else {
		ctx->socks5 = NULL;
		ctx->ino_fd = -1;
	}

	return 0;
}

__cold
static void gwp_ctx_free_prot(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;

	if (cfg->as_socks5)
		gwp_ctx_free_socks5(ctx);
}

__cold
static int gwp_ctx_init(struct gwp_ctx *ctx)
{
	int r;

	r = gwp_ctx_init_log(ctx);
	if (r < 0)
		return r;

	r = gwp_ctx_parse_ev(ctx);
	if (r < 0)
		goto out_free_log;

	if (!ctx->cfg.as_socks5 && !ctx->cfg.as_http) {
		const char *t = ctx->cfg.target;
		r = convert_str_to_ssaddr(t, &ctx->target_addr, 0);
		if (r) {
			pr_err(&ctx->lh, "Invalid target address '%s'", t);
			goto out_free_log;
		}
	}

	if (ctx->cfg.pid_file)
		gwp_ctx_init_pid_file(ctx);

	r = gwp_ctx_init_prot(ctx);
	if (r < 0)
		goto out_free_log;

	r = gwp_ctx_init_dns(ctx);
	if (r < 0)
		goto out_free_prot;

	r = gwp_ctx_init_threads(ctx);
	if (r < 0) {
		pr_err(&ctx->lh, "Failed to initialize worker threads: %s", strerror(-r));
		goto out_free_dns;
	}

	return 0;

out_free_dns:
	gwp_ctx_free_dns(ctx);
out_free_prot:
	gwp_ctx_free_prot(ctx);
out_free_log:
	gwp_ctx_free_log(ctx);
	return r;
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
	gwp_ctx_free_prot(ctx);
	gwp_ctx_free_log(ctx);
}

__cold
static int init_conn(struct gwp_conn *conn, uint32_t buf_size)
{
	conn->fd = -1;
	conn->len = 0;
	conn->cap = buf_size;
	conn->ep_mask = 0;
	conn->buf = NULL;
	return posix_memalign((void **)&conn->buf, 4096, buf_size) ? -ENOMEM : 0;
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

static int expand_conn_slot(struct gwp_wrk *w)
{
	struct gwp_conn_slot *gcs = &w->conn_slot;
	struct gwp_ctx *ctx = w->ctx;

	if (gcs->nr >= gcs->cap) {
		uint32_t new_cap = gcs->cap ? gcs->cap * 2 : 16;
		struct gwp_conn_pair **new_pairs;

		new_pairs = realloc(gcs->pairs, new_cap * sizeof(*new_pairs));
		if (!new_pairs)
			return -ENOMEM;

		gcs->pairs = new_pairs;
		gcs->cap = new_cap;
		pr_dbg(&ctx->lh, "Increased connection slot capacity to %u", gcs->cap);
	}

	return 0;
}

__hot
struct gwp_conn_pair *gwp_alloc_conn_pair(struct gwp_wrk *w)
{
	struct gwp_conn_slot *gcs = &w->conn_slot;
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_cfg *cfg = &ctx->cfg;
	struct gwp_conn_pair *gcp;
	int r;

	r = expand_conn_slot(w);
	if (unlikely(r))
		return NULL;

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
	gcp->flags = 0;
	gcp->prot_type = GWP_PROT_TYPE_NONE;
	return gcp;

out_free_target_conn:
	free_conn(&gcp->target);
out_free_gcp:
	free(gcp);
	pr_err(&ctx->lh, "Failed to allocate connection pair: %s", strerror(-r));
	return NULL;
}

static int shrink_conn_slot(struct gwp_wrk *w)
{
	struct gwp_conn_slot *gcs = &w->conn_slot;
	struct gwp_conn_pair **new_pairs;
	struct gwp_ctx *ctx = w->ctx;
	uint32_t new_cap;

	if (!gcs->pairs)
		return 0;

	if (!gcs->nr) {
		free(gcs->pairs);
		gcs->pairs = NULL;
		gcs->cap = 0;
		pr_dbg(&ctx->lh, "Connection slot capacity shrunk to 0");
		return 0;
	}

	if (gcs->cap <= 16 || (gcs->cap - gcs->nr) < 16)
		return 0;

	new_cap = gcs->nr;
	new_pairs = realloc(gcs->pairs, new_cap * sizeof(*new_pairs));
	if (!new_pairs) {
		pr_err(&ctx->lh, "Failed to shrink connection slot!");
		return -ENOMEM;
	}
	gcs->pairs = new_pairs;
	gcs->cap = new_cap;
	pr_dbg(&ctx->lh, "Connection slot capacity shrunk to %u", gcs->cap);
	return 0;
}

__hot
int gwp_free_conn_pair(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_conn_slot *gcs = &w->conn_slot;
	struct gwp_conn_pair *tmp;
	uint32_t i = gcp->idx;

	tmp = gcs->pairs[i];
	assert(tmp == gcp);
	if (unlikely(tmp != gcp))
		return -EINVAL;

	log_conn_pair_close(w, gcp);

	if (gcp->flags & GWP_CONN_FLAG_NO_CLOSE_FD)
		gcp->target.fd = gcp->client.fd = gcp->timer_fd = -1;

	tmp = gcs->pairs[--gcs->nr];
	gcs->pairs[gcs->nr] = NULL;
	gcs->pairs[i] = tmp;
	tmp->idx = i;

	free_conn(&gcp->target);
	free_conn(&gcp->client);

	if (gcp->timer_fd >= 0)
		__sys_close(gcp->timer_fd);

	if (gcp->gde)
		gwp_dns_entry_put(gcp->gde);

	switch (gcp->prot_type) {
	case GWP_PROT_TYPE_SOCKS5:
		gwp_socks5_conn_free(gcp->s5_conn);
		break;
	case GWP_PROT_TYPE_HTTP:
		gwp_http_conn_free(gcp->http_conn);
		break;
	}

	free(gcp);
	shrink_conn_slot(w);
	return 0;
}

static int setskopt_int(int fd, int level, int optname, int value)
{
	return __sys_setsockopt(fd, level, optname, &value, sizeof(value));
}

void gwp_setup_cli_sock_options(struct gwp_wrk *w, int fd)
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
int gwp_create_sock_target(struct gwp_wrk *w, struct gwp_sockaddr *addr,
			   bool *is_target_alive, bool non_block)
{
	int t = SOCK_STREAM | SOCK_CLOEXEC | (non_block ? SOCK_NONBLOCK : 0);
	socklen_t len;
	int fd, r;

	fd = __sys_socket(addr->sa.sa_family, t, 0);
	if (unlikely(fd < 0))
		return fd;

	gwp_setup_cli_sock_options(w, fd);

	/*
	 * Do not connect if non_block is false, as we
	 * will not be able to handle the connection
	 * in a non-blocking way.
	 */
	if (!non_block) {
		if (is_target_alive)
			*is_target_alive = false;
		return fd;
	}

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
int gwp_create_timer(int fd, int sec, int nsec)
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

static int get_local_addr_for_socks5(struct gwp_ctx *ctx, int fd,
				     struct gwp_socks5_addr *ba)
{
	struct gwp_sockaddr t;
	socklen_t len = sizeof(t);
	int r;

	r = __sys_getsockname(fd, &t.sa, &len);
	if (r < 0) {
		pr_err(&ctx->lh, "getsockname error: %s", strerror(-r));
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
		pr_err(&ctx->lh, "Unsupported address family %d for local socket",
			t.sa.sa_family);
		return -EAFNOSUPPORT;
	}
}

__hot
int gwp_socks5_prep_connect_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				  int err)
{
	struct gwp_socks5_conn *sc = gcp->s5_conn;
	struct gwp_socks5_addr ba;
	size_t out_len;
	void *out;
	int r;

	if (err == 0) {
		r = get_local_addr_for_socks5(w->ctx, gcp->target.fd, &ba);
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
	return 0;
}

static int queue_dns_resolution(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				const char *host, const char *port)
{
	struct gwp_dns_ctx *dns = w->ctx->dns;
	struct gwp_dns_entry *gde;

	gde = gwp_dns_queue(dns, host, port);
	if (unlikely(!gde)) {
		pr_err(&w->ctx->lh, "Failed to allocate DNS entry for %s:%s", host, port);
		return -ENOMEM;
	}

	gcp->gde = gde;
	return -EINPROGRESS;
}

static int prepare_target_addr_domain(struct gwp_wrk *w,
				      struct gwp_conn_pair *gcp,
				      const char *host, const char *port)
{
	struct gwp_ctx *ctx = w->ctx;
	int r;

	r = gwp_dns_cache_lookup(ctx->dns, host, port, &gcp->target_addr);
	if (!r) {
		pr_dbg(&ctx->lh, "Found %s:%s in DNS cache %s", host, port,
			ip_to_str(&gcp->target_addr));
		return 0;
	}

	return queue_dns_resolution(w, gcp, host, port);
}

static int socks5_prepare_target_addr_domain(struct gwp_wrk *w,
					     struct gwp_conn_pair *gcp)
{
	struct gwp_socks5_addr *dst;
	const char *host;
	char portstr[6];
	uint16_t port;
	int r;

	dst = &gcp->s5_conn->dst_addr;
	port = ntohs(dst->port);
	host = dst->domain.str;
	snprintf(portstr, sizeof(portstr), "%hu", port);
	r = prepare_target_addr_domain(w, gcp, host, portstr);
	if (r == -EINPROGRESS)
		gcp->conn_state = CONN_STATE_SOCKS5_DNS_QUERY;

	return r;
}

int gwp_socks5_prepare_target_addr(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_sockaddr *ta = &gcp->target_addr;
	struct gwp_socks5_conn *sc = gcp->s5_conn;
	struct gwp_socks5_addr *dst;

	assert(sc);
	assert(sc->state == CONN_STATE_SOCKS5_CONNECT);

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

int gwp_socks5_handle_data(struct gwp_conn_pair *gcp)
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
	return (r == -EAGAIN) ? 0 : r;
}

struct gwp_http_conn *gwp_http_conn_alloc(void)
{
	struct gwp_http_conn *ghc = malloc(sizeof(*ghc));
	int r;

	if (!ghc)
		return NULL;

	r = gwnet_http_hdr_pctx_init(&ghc->ctx_hdr);
	if (r < 0) {
		free(ghc);
		return NULL;
	}

	return ghc;
}

static int handle_socks5_prot(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	int r;

	gcp->s5_conn = gwp_socks5_conn_alloc(ctx->socks5);
	if (!gcp->s5_conn) {
		pr_err(&ctx->lh, "Failed to allocate SOCKS5 connection");
		return -ENOMEM;
	}

	r = gwp_socks5_handle_data(gcp);
	if (r < 0) {
		gwp_socks5_conn_free(gcp->s5_conn);
		gcp->s5_conn = NULL;
		return r;
	}

	if (gcp->s5_conn->state != GWP_SOCKS5_ST_INIT) {
		/*
		 * This must be a SOCKS5 data connection, there is no
		 * possibility to fallback to HTTP because the SOCKS5
		 * parser already sees the SOCKS5 header.
		 */
		gcp->conn_state = CONN_STATE_SOCKS5_DATA;
		gcp->prot_type = GWP_PROT_TYPE_SOCKS5;
	}

	return 0;
}

int gwp_handle_conn_state_socks5(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	int r, ct;

	ct = gcp->conn_state;
	if (ct == CONN_STATE_PROT) {
		return handle_socks5_prot(w, gcp);
	} else if (ct == CONN_STATE_SOCKS5_DATA) {
		r = gwp_socks5_handle_data(gcp);
		if (r)
			return r;
	} else {
		assert(0 && "Invalid SOCKS5 connection state");
		return -EINVAL;
	}

	if (gcp->s5_conn->state == GWP_SOCKS5_ST_CMD_CONNECT) {
		r = gwp_socks5_prepare_target_addr(w, gcp);
		if (r == -EINPROGRESS) {
			gcp->conn_state = CONN_STATE_SOCKS5_DNS_QUERY;
			return r;
		}

		if (!r)
			gcp->conn_state = CONN_STATE_SOCKS5_CONNECT;
	}

	return r;
}

static int handle_http_hdr(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwnet_http_hdr_pctx *ctx_hdr;
	struct gwnet_http_req_hdr *req_hdr;
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_http_conn *conn;
	int r;

	conn = gcp->http_conn;
	ctx_hdr = &conn->ctx_hdr;
	req_hdr = &conn->req_hdr;
	ctx_hdr->buf = gcp->client.buf;
	ctx_hdr->len = gcp->client.len;
	ctx_hdr->off = 0;
	r = gwnet_http_req_hdr_parse(ctx_hdr, req_hdr);
	gwp_conn_buf_advance(&gcp->client, ctx_hdr->off);
	if (r < 0) {
		if (r == -EAGAIN)
			return 0;
		pr_dbg(&ctx->lh, "Invalid HTTP header: %s", strerror(-r));
		return r;
	}

	gcp->prot_type = GWP_PROT_TYPE_HTTP;
	return 0;
}

static int handle_http_prot(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	int r;

	gcp->http_conn = gwp_http_conn_alloc();
	if (!gcp->http_conn) {
		pr_err(&ctx->lh, "Failed to allocate HTTP connection");
		return -ENOMEM;
	}

	gcp->conn_state = CONN_STATE_HTTP_HDR;
	r = handle_http_hdr(w, gcp);
	if (r)
		return r;

	return 0;
}

int gwp_handle_conn_state_http(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwnet_http_req_hdr *req_hdr;
	bool port_found = false;
	char *host, *port;
	int r, ct;

	ct = gcp->conn_state;
	if (ct == CONN_STATE_PROT) {
		r = handle_http_prot(w, gcp);
	} else if (ct == CONN_STATE_HTTP_HDR) {
		r = handle_http_hdr(w, gcp);
	} else {
		assert(0 && "Invalid HTTP connection state");
		return -EINVAL;
	}

	if (r == -EAGAIN)
		return r;

	req_hdr = &gcp->http_conn->req_hdr;

	/*
	 * TODO(ammarfaizi2): Support non-HTTP CONNECT methods.
	 */
	if (req_hdr->method != GWNET_HTTP_METHOD_CONNECT)
		return -EINVAL;

	host = req_hdr->uri;
	port = strlen(host) + host;
	while (port > host) {
		if (*port == ':') {
			port_found = true;
			*port = '\0';
			port++;
			break;
		}
		port--;
	}

	if (!port_found)
		return -EINVAL;

	r = prepare_target_addr_domain(w, gcp, host, port);
	if (r == -EINPROGRESS)
		gcp->conn_state = CONN_STATE_HTTP_DNS_QUERY;
	else if (!r)
		gcp->conn_state = CONN_STATE_HTTP_CONNECT;

	return r;
}

int gwp_handle_conn_state_prot(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_cfg *cfg = &w->ctx->cfg;
	struct gwp_ctx *ctx = w->ctx;
	bool socks5_einval = false;
	int r = 0;

	assert(gcp->target.fd < 0);
	assert(cfg->as_http || cfg->as_socks5);
	assert(gcp->conn_state == CONN_STATE_PROT);

	/*
	 * At this point, the used protocol may not be known yet.
	 *
	 * If both as_socks5 and as_http and are true. Then, try
	 * parsing as SOCKS5 first. If it fails with -EINVAL, try
	 * parsing as HTTP.
	 *
	 * This allows a single server port be used as both HTTP
	 * and SOCKS5 simultaneously.
	 */
	if (cfg->as_socks5) {
		r = gwp_handle_conn_state_socks5(w, gcp);
		if (r != -EINVAL)
			return r;
		socks5_einval = true;
	}

	if (cfg->as_http) {
		if (socks5_einval)
			pr_dbg(&ctx->lh,
				"Not a socks5 protocol, fallback to HTTP (fd=%d; ca=%s)",
				gcp->client.fd, ip_to_str(&gcp->client_addr));

		r = gwp_handle_conn_state_http(w, gcp);
		if (r != -EINVAL)
			return r;
	}

	return r;
}

void gwp_http_conn_free(struct gwp_http_conn *conn)
{
	gwnet_http_hdr_pctx_free(&conn->ctx_hdr);
	free(conn);
}

noinline
static void *gwp_ctx_thread_entry(void *arg)
{
	struct gwp_wrk *w = arg;
	struct gwp_ctx *ctx = w->ctx;
	int r;

	switch (ctx->ev_used) {
	case GWP_EV_EPOLL:
		r = gwp_ctx_thread_entry_epoll(w);
		break;
	case GWP_EV_IO_URING:
#ifdef CONFIG_IO_URING
		r = gwp_ctx_thread_entry_io_uring(w);
#else
		pr_err(&ctx->lh, "IO_URING support is not enabled in this build");
		r = -ENOSYS;
#endif
		break;
	default:
		pr_err(&ctx->lh, "Unknown event loop type: %d", ctx->ev_used);
		r = -EINVAL;
		break;
	}
	ctx->stop = true;
	gwp_ctx_signal_all_workers(ctx);
	pr_info(&ctx->lh, "Worker %u stopped", w->idx);
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
			pr_err(&ctx->lh, "Failed to create worker thread %d: %s",
				i, strerror(r));
			return -r;
		}

		w->need_join = true;
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
