// SPDX-License-Identifier: GPL-2.0-only
/*
 * gwproxy - A simple TCP proxy server.
 *
 * Copyright (C) 2025 Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
/* Before common.h defines __unused, which musl's struct stat has a field of. */
#include <sys/stat.h>

#include <gwproxy/gwproxy.h>
#include <gwproxy/upstream.h>
#include <gwproxy/common.h>
#include <gwproxy/log.h>
#include <gwproxy/acl.h>
#include <gwproxy/ev/epoll.h>
#ifdef CONFIG_IO_URING
#include <gwproxy/ev/io_uring.h>
#endif
#ifdef CONFIG_HTTPS
#include <gwproxy/ssl.h>
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
#include <sched.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#ifdef CONFIG_HAVE_GETRANDOM
#include <sys/random.h>
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <getopt.h>
#include <signal.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <netinet/tcp.h>
#include <sys/resource.h>
#include <sys/inotify.h>
#include <poll.h>
#include <sys/file.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

/* Long-only options (no short letter): values >= 128 are skipped by the
 * short-option string builder below. */
enum {
	OPT_ACL_ALLOW_ALL = 0x100,
	OPT_OUTGOING_FAMILY,
	OPT_BIND_IPV6_ONLY,
	OPT_DNS_CACHE_MAX_ENTRIES,
	OPT_IDLE_TIMEOUT,
	OPT_UPSTREAM_AUTH_FILE,
	OPT_MAX_CONNS_PER_IP,
	OPT_UPSTREAM_CA_FILE,
	OPT_WATCH_FILES,
};

/*
 * Upper bound for --nr-workers and --nr-dns-workers: far above any useful
 * thread count, low enough that a typo cannot ask for millions of threads.
 */
#define GWP_MAX_WORKERS	1024

static const struct option long_opts[] = {
	{ "help",		no_argument,		NULL,	'h' },
	{ "event-loop",		required_argument,	NULL,	'e' },
	{ "bind",		required_argument,	NULL,	'b' },
	{ "target",		required_argument,	NULL,	't' },
	{ "as-socks5",		required_argument,	NULL,	'S' },
	{ "as-http",		required_argument,	NULL,	'H' },
	{ "udp-associate",	required_argument,	NULL,	'U' },
	{ "prefer-ipv6",	required_argument,	NULL,	'Q' },
	{ "protocol-timeout",	required_argument,	NULL,	'o' },
	{ "auth-file",		required_argument,	NULL,	'A' },
	{ "acl-file",		required_argument,	NULL,	'a' },
	{ "acl-allow-all",	no_argument,		NULL,	OPT_ACL_ALLOW_ALL },
	{ "watch-files",	required_argument,	NULL,	OPT_WATCH_FILES },
	{ "outgoing-family",	required_argument,	NULL,	OPT_OUTGOING_FAMILY },
	{ "bind-ipv6-only",	required_argument,	NULL,	OPT_BIND_IPV6_ONLY },
	{ "dns-cache-secs",	required_argument,	NULL,	'L' },
	{ "dns-cache-max-entries", required_argument,	NULL,	OPT_DNS_CACHE_MAX_ENTRIES },
	{ "nr-workers",		required_argument,	NULL,	'w' },
	{ "nr-dns-workers",	required_argument,	NULL,	'W' },
	{ "connect-timeout",	required_argument,	NULL,	'c' },
	{ "idle-timeout",	required_argument,	NULL,	OPT_IDLE_TIMEOUT },
	{ "max-conns-per-ip",	required_argument,	NULL,	OPT_MAX_CONNS_PER_IP },
	{ "connect-attempt-delay", required_argument,	NULL,	'D' },
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
	{ "upstream-proxy",	required_argument,	NULL,	'x' },
	{ "upstream-proxy-auth-file", required_argument, NULL,	OPT_UPSTREAM_AUTH_FILE },
	{ "mark",		required_argument,	NULL,	'M' },
	{ "bind-source",	required_argument,	NULL,	'B' },
	{ "bind-iface",		required_argument,	NULL,	'I' },
	{ "as-transparent",	required_argument,	NULL,	'R' },
#ifdef CONFIG_HTTPS
	{ "tls-cert",		required_argument,	NULL,	'E' },
	{ "tls-key",		required_argument,	NULL,	'Y' },
	{ "upstream-ca-file",	required_argument,	NULL,	OPT_UPSTREAM_CA_FILE },
#endif
#ifdef CONFIG_NEW_DNS_RESOLVER
	{ "dns-server",		required_argument,	NULL,	'j' },
	{ "raw-dns",		required_argument,	NULL,	'r' },
#endif
	{ NULL,			0,			NULL,	0 }
};

static const struct gwp_cfg default_opts = {
	.event_loop		= "epoll",
	.bind			= "[::]:1080",
	.target			= NULL,
	.as_socks5		= false,
	.as_http		= false,
	.udp_associate		= true,
	.prefer_ipv6		= false,
	.outgoing_family	= GWP_OUT_FAMILY_ANY,
	.bind_ipv6_only		= false,
	.use_raw_dns		= false,
	.protocol_timeout	= 10,
	.auth_file		= NULL,
	.acl_file		= NULL,
	.watch_files		= false,
	.dns_cache_secs		= 0,
	.dns_cache_max_entries	= 65536,
	.nr_workers		= 4,
	.nr_dns_workers		= 4,
	.connect_timeout	= 5,
	.connect_attempt_delay	= 250,
	.target_buf_size	= 65536,
	.client_buf_size	= 65536,
	.tcp_nodelay		= 1,
	.tcp_keepalive		= 1,
	.tcp_keepidle		= 60,
	.tcp_keepintvl		= 10,
	.tcp_keepcnt		= 5,
	.log_level		= 3,
	.log_file		= "/dev/stdout",
	.pid_file		= NULL,
	.dns_servers		= "1.1.1.1",
	.upstream_proxy	= NULL,
	.mark			= 0,
	.bind_source		= NULL,
	.bind_iface		= NULL,
	.as_transparent		= false
};

/*
 * The longest SOCKS5 message a client sends, an RFC 1929 request with a name
 * and a password of 255 bytes each. A greeting takes up to 257 bytes and a
 * CONNECT request up to 262.
 */
#define GWP_SOCKS5_MIN_CLIENT_BUF	513

static int setskopt_int(int fd, int level, int optname, int val);
static uint32_t cfg_dns_restyp(const struct gwp_cfg *cfg);

__cold
static void show_help(const char *app)
{
	printf("Usage: %s [options]\n", app);
	printf("Options:\n");
	printf("  -h, --help                      Show this help message and exit\n");
	printf("  -e, --event-loop=name           Specify the event loop to use (default: %s)\n", default_opts.event_loop);
	printf("                                  Available values: epoll, io_uring\n");
	printf("  -b, --bind=addr:port            Bind to the specified address (default: %s)\n", default_opts.bind);
	printf("  -t, --target=addr:port          Target address to connect to\n");
	printf("  -S, --as-socks5=0|1             Run as a SOCKS5 proxy (default: %d)\n", default_opts.as_socks5);
	printf("  -H, --as-http=0|1               Run as an HTTP proxy (default: %d)\n", default_opts.as_http);
	printf("  -U, --udp-associate=0|1         Allow SOCKS5 UDP ASSOCIATE; 0 rejects it with REP 0x07 (default: %d)\n", default_opts.udp_associate);
	printf("  -Q, --prefer-ipv6=0|1           Prefer IPv6 for proxy DNS queries (default: %d)\n", default_opts.prefer_ipv6);
	printf("      --outgoing-family=fam       Restrict outgoing connections to one family: any|ipv4|ipv6 (default: any)\n");
	printf("                                  Resolves that family only; a literal target of the other one is refused\n");
	printf("      --bind-ipv6-only=0|1        Set IPV6_V6ONLY on the listener, so an IPv6 bind refuses IPv4 (default: 0)\n");
	printf("  -o, --protocol-timeout=sec      Timeout for protocol handshake process (default: %d)\n", default_opts.protocol_timeout);
	printf("  -A, --auth-file=file            File with username:password credentials for SOCKS5 and HTTP auth (default: no auth)\n");
	printf("  -a, --acl-file=file             iptables-style ACL rule file for target/client filtering\n");
	printf("                                  (default: a built-in ACL that rejects private/loopback target ranges)\n");
	printf("      --acl-allow-all             Do not apply the built-in default ACL (allow all; ignored with --acl-file)\n");
	printf("      --watch-files=0|1           Also reload the auth and ACL files when they change (default: %d)\n", default_opts.watch_files);
	printf("                                  SIGHUP reloads them either way.\n");
	printf("  -L, --dns-cache-secs=sec        Proxy DNS cache duration in seconds (default: %d)\n", default_opts.dns_cache_secs);
	printf("                                  Set to 0 or a negative number to disable DNS caching.\n");
	printf("      --dns-cache-max-entries=nr  Max DNS cache entries; 0 = unlimited (default: %d)\n", default_opts.dns_cache_max_entries);
	printf("  -w, --nr-workers=nr             Number of worker threads (default: %d)\n", default_opts.nr_workers);
	printf("  -W, --nr-dns-workers=nr         Number of DNS worker threads kept running (default: %d)\n", default_opts.nr_dns_workers);
	printf("                                  More are started while lookups queue up, up to 64 or nr if larger.\n");
	printf("  -c, --connect-timeout=sec       Connection to target timeout in seconds (default: %d)\n", default_opts.connect_timeout);
	printf("      --idle-timeout=sec          Close a tunnel or UDP association idle this long; 0 = never (default: %d)\n", default_opts.idle_timeout);
	printf("      --max-conns-per-ip=nr       Most client connections at once per IPv4 address or IPv6 /64; 0 = no cap (default: %d)\n", default_opts.max_conns_per_ip);
	printf("                                  One more is closed as soon as it is accepted.\n");
	printf("  -D, --connect-attempt-delay=ms  Delay before racing the next target address (Happy Eyeballs); 0 disables racing (default: %d)\n", default_opts.connect_attempt_delay);
	printf("  -T, --target-buf-size=nr        Target buffer size in bytes (default: %d)\n", default_opts.target_buf_size);
	printf("  -C, --client-buf-size=nr        Client buffer size in bytes (default: %d)\n", default_opts.client_buf_size);
	printf("  -d, --tcp-nodelay=0|1           Enable/disable TCP_NODELAY (default: %d)\n", default_opts.tcp_nodelay);
	printf("  -k, --tcp-keepalive=0|1         Enable/disable TCP_KEEPALIVE (default: %d)\n", default_opts.tcp_keepalive);
	printf("  -i, --tcp-keepidle=sec          TCP_KEEPIDLE in seconds (default: %d)\n", default_opts.tcp_keepidle);
	printf("  -l, --tcp-keepintvl=sec         TCP_KEEPINTVL in seconds (default: %d)\n", default_opts.tcp_keepintvl);
	printf("  -g, --tcp-keepcnt=nr            TCP_KEEPCNT (default: %d)\n", default_opts.tcp_keepcnt);
	printf("  -m, --log-level=level           Set log level (0=none, 1=error, 2=warning, 3=info, 4=debug, default: %d)\n", default_opts.log_level);
	printf("  -f, --log-file=file             Log to the specified file (default: %s)\n", default_opts.log_file);
	printf("  -p, --pid-file=file             Write PID to the specified file (default is no pid file)\n");
	printf("  -x, --upstream-proxy=url        Route outgoing connections through an upstream proxy\n");
	printf("                                  URL: socks5://[user:pass@]host:port  (local DNS)\n");
	printf("                                       socks5h://[user:pass@]host:port (proxy resolves the host)\n");
	printf("                                       http://[user:pass@]host:port    (HTTP CONNECT)\n");
#ifdef CONFIG_HTTPS
	printf("                                       https://[user:pass@]host:port   (HTTP CONNECT over TLS)\n");
#endif
	printf("      --upstream-proxy-auth-file=file  Read the upstream proxy's user:pass from the first line of file\n");
	printf("                                  instead of the URL, where other local users can see it\n");
#ifdef CONFIG_HTTPS
	printf("      --upstream-ca-file=file     PEM CA certificates to verify https:// upstream proxies with, the\n");
	printf("                                  --upstream-proxy and ACL pool servers (default: the system's trust store)\n");
#endif
	printf("  -M, --mark=nr                   Set SO_MARK (fwmark) on outgoing connections (needs CAP_NET_ADMIN or CAP_NET_RAW; 0 = off)\n");
	printf("  -B, --bind-source=ip[:port]     Bind outgoing connections to this source address (default -j BIND --to-source)\n");
	printf("                                  Skipped for targets of the other address family; omit the port for an ephemeral one\n");
	printf("  -I, --bind-iface=name           Bind outgoing connections to this interface (SO_BINDTODEVICE)\n");
	printf("                                  Both are strict: a failed bind drops the connection. An ACL -j BIND rule replaces\n");
	printf("                                  them wholesale for the connections it matches\n");
	printf("  -R, --as-transparent=0|1        Transparent proxy: take the target from SO_ORIGINAL_DST (iptables REDIRECT) (default: %d)\n", default_opts.as_transparent);
#ifdef CONFIG_HTTPS
	printf("  -E, --tls-cert=file             PEM certificate chain; enables TLS termination on a SOCKS5 or HTTP listener (auto-detected per connection)\n");
	printf("  -Y, --tls-key=file              PEM private key matching --tls-cert\n");
#endif
#ifdef CONFIG_NEW_DNS_RESOLVER
	printf("  -j, --dns-server=addr:port      DNS server address for --raw-dns (default: %s)\n", default_opts.dns_servers);
	printf("  -r, --raw-dns=0|1               Use raw DNS for hostname targets (default: %d)\n", default_opts.use_raw_dns);
#endif
	printf("\n");
}

/*
 * Whether --event-loop selects the io_uring backend. "iou" is an accepted
 * alias for "io_uring" (see gwp_ctx_parse_ev()), so both spellings must be
 * recognised when gating features that io_uring does not support yet.
 */
static bool ev_is_io_uring(const struct gwp_cfg *cfg)
{
	return cfg->event_loop &&
	       (!strcmp(cfg->event_loop, "io_uring") ||
		!strcmp(cfg->event_loop, "iou"));
}

/*
 * Locate the password of an --upstream-proxy URL the way gwp_parse_upstream()
 * splits it: the "user:pass" before the last '@' after the scheme, the
 * password after its first ':'. Works on malformed URLs too, so an error
 * message can leave the password out. Returns false when there is none;
 * otherwise the password spans @url[*off, *off + *len), possibly empty.
 */
static bool upstream_pass_span(const char *url, size_t *off, size_t *len)
{
	const char *rest, *at, *colon;

	rest = strstr(url, "://");
	rest = rest ? rest + 3 : url;
	at = strrchr(rest, '@');
	if (!at)
		return false;
	colon = memchr(rest, ':', (size_t)(at - rest));
	if (!colon)
		return false;
	*off = (size_t)(colon + 1 - url);
	*len = (size_t)(at - colon - 1);
	return true;
}

/*
 * Take the --upstream-proxy URL out of argv. Its password is readable by
 * every local user through ps and /proc/<pid>/cmdline for as long as the
 * process runs, so keep a private copy for the parser and overwrite the
 * password in the argv string with "***", shifting the rest of it left and
 * zeroing the freed tail, so that not even its length shows. It is still
 * visible between exec and this point; --upstream-proxy-auth-file avoids
 * that window entirely.
 *
 * A URL too long for the copy is left alone: the parser rejects it anyway.
 */
static const char *upstream_take_url(char *arg)
{
	static char url[1024];
	size_t off, len, n, tail;

	tail = strlen(arg);
	if (tail >= sizeof(url))
		return arg;
	memcpy(url, arg, tail + 1);

	if (!upstream_pass_span(arg, &off, &len) || !len)
		return url;
	n = len < 3 ? len : 3;
	tail = strlen(arg + off + len) + 1;
	memset(arg + off, '*', n);
	memmove(arg + off + n, arg + off + len, tail);
	memset(arg + off + n + tail, 0, len - n);
	return url;
}

/*
 * Name an option by its getopt value, for error messages: the long name,
 * which every option has.
 */
static const char *opt_name(int c)
{
	size_t i;

	for (i = 0; long_opts[i].name; i++) {
		if (long_opts[i].val == c)
			return long_opts[i].name;
	}
	return "?";
}

/*
 * Parse the argument of option @c as a whole integer in [@min, @max] (@max at
 * least 0): decimal digits, after a "-" when @min is negative, or with @hex
 * also "0x" (or "0X") and hexadecimal digits. atoi() took "abc" or "5s" for a
 * number, quietly turned "0x10" into 0 and had undefined behaviour on
 * overflow, so a typo started the proxy with some other setting than the one
 * asked for. strtoll() is not used either: it takes leading blanks and a "+",
 * which no option documents, and in base 0 reads "010" as octal 8. Where @hex
 * allows a prefix, a decimal number may not start with 0, so "010" is refused
 * rather than read as 10 now; without @hex, "010" is decimal 10, as it was.
 */
static int opt_num(int c, const char *arg, long long min, long long max,
		   bool hex, long long *out)
{
	unsigned long long v = 0, d, lim = (unsigned long long)max, base = 10;
	const char *p = arg, *why = "";
	bool neg = false;

	if (*p == '-' && min < 0) {
		neg = true;
		lim = -(unsigned long long)min;
		p++;
	}
	if (*p < '0' || *p > '9')
		goto bad;
	if (hex && p[0] == '0' && p[1]) {
		if (p[1] != 'x' && p[1] != 'X') {
			if (p[1] >= '0' && p[1] <= '9')
				why = " (no leading 0: it once meant octal)";
			goto bad;
		}
		base = 16;
		p += 2;
		if (!*p)
			goto bad;
	}
	for (; *p; p++) {
		if (*p >= '0' && *p <= '9')
			d = (unsigned long long)(*p - '0');
		else if (base == 16 && *p >= 'a' && *p <= 'f')
			d = (unsigned long long)(*p - 'a' + 10);
		else if (base == 16 && *p >= 'A' && *p <= 'F')
			d = (unsigned long long)(*p - 'A' + 10);
		else
			goto bad;
		if (d > lim || v > (lim - d) / base)
			goto bad;
		v = v * base + d;
	}
	if (neg) {
		/* v is at most -@min, so -v fits even for LLONG_MIN. */
		*out = v ? -(long long)(v - 1) - 1 : 0;
	} else {
		*out = (long long)v;
		if (*out < min)
			goto bad;
	}
	return 0;
bad:
	fprintf(stderr, "Error: --%s: '%s' is not a %sinteger in the range %lld..%lld%s\n",
		opt_name(c), arg, hex ? "decimal or 0x hexadecimal " : "decimal ",
		min, max, why);
	return -EINVAL;
}

static int opt_int(int c, const char *arg, int min, int max, int *out)
{
	long long v;
	int r;

	r = opt_num(c, arg, min, max, false, &v);
	if (!r)
		*out = (int)v;
	return r;
}

/* An on/off switch: any integer, non-zero is on. */
static int opt_bool(int c, const char *arg, bool *out)
{
	long long v;
	int r;

	r = opt_num(c, arg, INT_MIN, INT_MAX, false, &v);
	if (!r)
		*out = !!v;
	return r;
}

__cold
static int parse_options(int argc, char *argv[], struct gwp_cfg *cfg)
{
	#define ERR_WRAP "==============================================\n"
	#define NR_OPTS ((sizeof(long_opts) / sizeof(long_opts[0])) - 1)
	char short_opts[(NR_OPTS * 2) + 1], *p;
	size_t i;
	long long v;
	int c;

	p = short_opts;
	for (i = 0; i < NR_OPTS; i++) {
		/* Long-only options use a val >= 128 and have no short letter. */
		if (long_opts[i].val <= 0 || long_opts[i].val >= 128)
			continue;
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
			if (opt_bool(c, optarg, &cfg->as_socks5))
				goto einval;
			break;
		case 'H':
			if (opt_bool(c, optarg, &cfg->as_http))
				goto einval;
			break;
		case 'U':
			if (opt_bool(c, optarg, &cfg->udp_associate))
				goto einval;
			break;
		case 'Q':
			if (opt_bool(c, optarg, &cfg->prefer_ipv6))
				goto einval;
			break;
		case 'o':
			if (opt_int(c, optarg, INT_MIN, INT_MAX, &cfg->protocol_timeout))
				goto einval;
			break;
		case 'A':
			cfg->auth_file = optarg;
			break;
		case 'a':
			cfg->acl_file = optarg;
			break;
		case OPT_OUTGOING_FAMILY:
			if (!strcmp(optarg, "any"))
				cfg->outgoing_family = GWP_OUT_FAMILY_ANY;
			else if (!strcmp(optarg, "ipv4"))
				cfg->outgoing_family = GWP_OUT_FAMILY_IPV4;
			else if (!strcmp(optarg, "ipv6"))
				cfg->outgoing_family = GWP_OUT_FAMILY_IPV6;
			else
				goto einval_outfam;
			break;
		case OPT_BIND_IPV6_ONLY:
			if (opt_bool(c, optarg, &cfg->bind_ipv6_only))
				goto einval;
			break;
		case OPT_ACL_ALLOW_ALL:
			cfg->acl_allow_all = true;
			break;
		case OPT_WATCH_FILES:
			if (opt_bool(c, optarg, &cfg->watch_files))
				goto einval;
			break;
		case 'L':
			if (opt_int(c, optarg, INT_MIN, INT_MAX, &cfg->dns_cache_secs))
				goto einval;
			break;
		case OPT_DNS_CACHE_MAX_ENTRIES:
			if (opt_int(c, optarg, INT_MIN, INT_MAX, &cfg->dns_cache_max_entries))
				goto einval;
			break;
		case 'w':
			if (opt_int(c, optarg, 1, GWP_MAX_WORKERS, &cfg->nr_workers))
				goto einval;
			break;
		case 'W':
			if (opt_int(c, optarg, 0, GWP_MAX_WORKERS, &cfg->nr_dns_workers))
				goto einval;
			break;
		case 'c':
			if (opt_int(c, optarg, INT_MIN, INT_MAX, &cfg->connect_timeout))
				goto einval;
			break;
		case OPT_IDLE_TIMEOUT:
			if (opt_int(c, optarg, INT_MIN, INT_MAX, &cfg->idle_timeout))
				goto einval;
			if (cfg->idle_timeout < 0)
				cfg->idle_timeout = 0;
			break;
		case OPT_MAX_CONNS_PER_IP:
			if (opt_int(c, optarg, 0, INT_MAX, &cfg->max_conns_per_ip))
				goto einval;
			break;
		case 'D':
			if (opt_int(c, optarg, INT_MIN, INT_MAX, &cfg->connect_attempt_delay))
				goto einval;
			break;
		case 'T':
			if (opt_int(c, optarg, INT_MIN, INT_MAX, &cfg->target_buf_size))
				goto einval;
			break;
		case 'C':
			if (opt_int(c, optarg, INT_MIN, INT_MAX, &cfg->client_buf_size))
				goto einval;
			break;
		case 'd':
			if (opt_bool(c, optarg, &cfg->tcp_nodelay))
				goto einval;
			break;
		case 'K':
			/*
			 * --tcp-quickack never did anything: no TCP_QUICKACK was
			 * ever set, and a one-shot set would not stick anyway,
			 * since the kernel leaves quickack mode on its own.
			 * Accepted so existing command lines still start.
			 */
			fprintf(stderr, "Warning: --tcp-quickack has no effect and is ignored\n");
			break;
		case 'k':
			if (opt_bool(c, optarg, &cfg->tcp_keepalive))
				goto einval;
			break;
		case 'i':
			if (opt_int(c, optarg, INT_MIN, INT_MAX, &cfg->tcp_keepidle))
				goto einval;
			break;
		case 'l':
			if (opt_int(c, optarg, INT_MIN, INT_MAX, &cfg->tcp_keepintvl))
				goto einval;
			break;
		case 'g':
			if (opt_int(c, optarg, INT_MIN, INT_MAX, &cfg->tcp_keepcnt))
				goto einval;
			break;
		case 'm':
			if (opt_int(c, optarg, INT_MIN, INT_MAX, &cfg->log_level))
				goto einval;
			break;
		case 'f':
			cfg->log_file = optarg;
			break;
		case 'p':
			cfg->pid_file = optarg;
			break;
		case 'x':
			cfg->upstream_proxy = upstream_take_url(optarg);
			break;
		case OPT_UPSTREAM_AUTH_FILE:
			cfg->upstream_auth_file = optarg;
			break;
		case 'M':
			if (opt_num(c, optarg, 0, UINT32_MAX, true, &v))
				goto einval;
			cfg->mark = (uint32_t)v;
			break;
		case 'B':
			cfg->bind_source = optarg;
			break;
		case 'I':
			cfg->bind_iface = optarg;
			break;
		case 'R':
			if (opt_bool(c, optarg, &cfg->as_transparent))
				goto einval;
			break;
#ifdef CONFIG_HTTPS
		case 'E':
			cfg->tls_cert = optarg;
			break;
		case 'Y':
			cfg->tls_key = optarg;
			break;
		case OPT_UPSTREAM_CA_FILE:
			cfg->upstream_ca_file = optarg;
			break;
#endif
		case 'j':
			cfg->dns_servers = optarg;
			break;
		case 'r':
			if (opt_bool(c, optarg, &cfg->use_raw_dns))
				goto einval;
			break;
		default:
			fprintf(stderr, "Unknown option: %c\n", c);
			show_help(argv[0]);
			return -EINVAL;
		}
	}


	if (cfg->use_raw_dns && ev_is_io_uring(cfg)) {
		fprintf(stderr, ERR_WRAP "Error: The raw DNS feature is currently not supported with the io_uring event loop\n" ERR_WRAP);
		goto einval;
	}

	if (cfg->use_raw_dns && cfg->dns_cache_secs) {
		fprintf(stderr, ERR_WRAP "Error: The -L/--dns-cache-secs option is not supported with the raw DNS feature\n" ERR_WRAP);
		goto einval;
	}

#ifdef CONFIG_HTTPS
	if ((cfg->tls_cert != NULL) != (cfg->tls_key != NULL)) {
		fprintf(stderr, ERR_WRAP "Error: --tls-cert and --tls-key must be provided together\n" ERR_WRAP);
		goto einval;
	}

	/*
	 * The TLS listener detects a ClientHello in the SOCKS5 and HTTP paths
	 * only. Elsewhere the certificate would do nothing but log that TLS is
	 * on while the listener speaks cleartext.
	 */
	if (cfg->tls_cert && !cfg->as_socks5 && !cfg->as_http) {
		fprintf(stderr, ERR_WRAP "Error: --tls-cert needs --as-socks5=1 or --as-http=1\n" ERR_WRAP);
		goto einval;
	}
#endif

	if (cfg->as_transparent && (cfg->as_socks5 || cfg->as_http)) {
		fprintf(stderr, ERR_WRAP "Error: --as-transparent cannot be combined with --as-socks5 or --as-http\n" ERR_WRAP);
		goto einval;
	}

	if (cfg->as_transparent && cfg->target) {
		fprintf(stderr, ERR_WRAP "Error: --target must not be set with --as-transparent (the target comes from SO_ORIGINAL_DST)\n" ERR_WRAP);
		goto einval;
	}

	if (!cfg->as_socks5 && !cfg->as_http && !cfg->as_transparent && !cfg->target) {
		fprintf(stderr, ERR_WRAP "Error: --target is required unless --as-socks5=1, --as-http=1 or --as-transparent=1\n" ERR_WRAP);
		goto einval;
	}

	if (cfg->upstream_auth_file && !cfg->upstream_proxy) {
		fprintf(stderr, ERR_WRAP "Error: --upstream-proxy-auth-file needs --upstream-proxy\n" ERR_WRAP);
		goto einval;
	}

	/*
	 * The URL's scheme is checked once it is parsed (upstream_init_tls());
	 * an ACL file may name https:// pool servers.
	 */
	if (cfg->upstream_ca_file && !cfg->upstream_proxy &&
	    !(cfg->acl_file && *cfg->acl_file)) {
		fprintf(stderr, ERR_WRAP "Error: --upstream-ca-file needs an https:// --upstream-proxy or an --acl-file\n" ERR_WRAP);
		goto einval;
	}

	if (cfg->nr_workers <= 0) {
		fprintf(stderr, ERR_WRAP "Error: --nr-workers must be at least 1.\n" ERR_WRAP);
		goto einval;
	}

	/*
	 * --prefer-ipv6 asks for a family that --outgoing-family forbids. Take
	 * it as a mistake rather than silently letting the hard restriction win
	 * -- an operator who wrote both is describing two different intents.
	 */
	if (cfg->prefer_ipv6 && cfg->outgoing_family == GWP_OUT_FAMILY_IPV4) {
		fprintf(stderr, ERR_WRAP "Error: --prefer-ipv6=1 contradicts --outgoing-family=ipv4.\n" ERR_WRAP);
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

	/*
	 * Each SOCKS5 message has to fit in client.buf as a whole, and the
	 * proxy has no other way to read the rest of it.
	 */
	if (cfg->as_socks5 && cfg->client_buf_size < GWP_SOCKS5_MIN_CLIENT_BUF) {
		fprintf(stderr, ERR_WRAP "Error: --client-buf-size must be at least %d for SOCKS5.\n" ERR_WRAP,
			GWP_SOCKS5_MIN_CLIENT_BUF);
		goto einval;
	}

	if (cfg->upstream_proxy && cfg->target_buf_size < GWP_UPSTREAM_MIN_TARGET_BUF) {
		fprintf(stderr, ERR_WRAP "Error: --target-buf-size must be at least %d with --upstream-proxy.\n" ERR_WRAP,
			GWP_UPSTREAM_MIN_TARGET_BUF);
		goto einval;
	}

	return 0;

einval_outfam:
	fprintf(stderr, ERR_WRAP "Error: --outgoing-family must be any, ipv4 or ipv6.\n" ERR_WRAP);
	goto einval;

einval:
	fprintf(stderr, "\n");
	show_help(argv[0]);
	return -EINVAL;
}

#ifdef CONFIG_NEW_DNS_RESOLVER
static int gwp_ctx_init_raw_dns(struct gwp_wrk *w)
{
	struct gwp_ctx *ctx = w->ctx;
	int r;

	w->dns = calloc(1, sizeof(*w->dns));
	if (!w->dns)
		return -ENOMEM;

	/*
	 * TODO(Viro_SSFS): Support multiple DNS servers by splitting
	 *                  ctx->cfg.dns_servers by comma.
	 *
	 * For now, support only one DNS server.
	 */
	w->dns->nr = 1;
	w->dns->resolvers = calloc(w->dns->nr, sizeof(*w->dns->resolvers));
	if (!w->dns->resolvers) {
		r = -ENOMEM;
		goto err_dns;
	}

	r = gwp_dns_res_init(ctx, &w->dns->resolvers[0], ctx->cfg.dns_servers);
	if (r < 0)
		goto err_resolvers;

	pr_dbg(&ctx->lh, "Worker %u initialized raw DNS resolver: %s",
		w->idx, ctx->cfg.dns_servers);
	return 0;

err_resolvers:
	free(w->dns->resolvers);
	w->dns->resolvers = NULL;
err_dns:
	free(w->dns);
	w->dns = NULL;
	return r;
}

static void gwp_ctx_free_raw_dns(struct gwp_wrk *w)
{
	size_t i;

	if (!w->dns)
		return;

	if (w->dns->resolvers) {
		for (i = 0; i < w->dns->nr; i++)
			gwp_dns_res_free(&w->dns->resolvers[i]);
		free(w->dns->resolvers);
		w->dns->resolvers = NULL;
	}

	free(w->dns);
	w->dns = NULL;
}

static int gwp_alloc_dns_packet(struct gwp_conn_pair *gcp)
{
	gcp->gdp = calloc(1, sizeof(*gcp->gdp));
	if (!gcp->gdp)
		return -ENOMEM;

	gcp->gdp->fd = -1;
	return 0;
}

static void gwp_free_dns_packet(struct gwp_conn_pair *gcp)
{
	if (gcp->gdp) {
		gwp_dns_res_drop_query(gcp->gdp);
		free(gcp->gdp->host);
		free(gcp->gdp);
		gcp->gdp = NULL;
	}
}

static int gwp_raw_dns_resolve(struct gwp_wrk *w,
			       struct gwp_conn_pair *gcp,
			       const char *host, uint16_t port)
{
	struct gwp_dns_resolver *res;
	struct gwp_dns_packet *gdp;
	int r;

	assert(w->dns);

	res = &w->dns->resolvers[0];
	r = gwp_alloc_dns_packet(gcp);
	if (r < 0)
		return r;

	gdp = gcp->gdp;
	gdp->host = strdup(host);
	if (!gdp->host) {
		r = -ENOMEM;
		goto out_err;
	}

	gdp->restyp = cfg_dns_restyp(&w->ctx->cfg);

	gdp->port = port;
	gdp->gcp = gcp;
	r = gwp_dns_res_prep_query(res, gdp);
	if (r < 0)
		goto out_err;

	return -EINPROGRESS;

out_err:
	gwp_free_dns_packet(gcp);
	return r;
}
#else /* #ifdef CONFIG_NEW_DNS_RESOLVER */
static int gwp_ctx_init_raw_dns(struct gwp_wrk __unused *w)
{
	return -ENOSYS;
}

static void gwp_ctx_free_raw_dns(struct gwp_wrk __unused *w)
{
}

static int gwp_raw_dns_resolve(struct gwp_wrk __unused *w,
			       struct gwp_conn_pair __unused *gcp,
			       const char __unused *host,
			       uint16_t __unused port)
{
	return -ENOSYS;
}
#endif /* #ifdef CONFIG_NEW_DNS_RESOLVER */

#define FULL_ADDRSTRLEN (INET6_ADDRSTRLEN + sizeof(":65535[]") - 1)

/*
 * Never NULL: the result goes straight to "%s". An address that is not set
 * yet (the target of a pair closed during its handshake) prints as "-".
 */
const char *ip_to_str(const struct gwp_sockaddr *gs)
{
	static __thread char buf[8][FULL_ADDRSTRLEN];
	static __thread uint8_t idx = 0;
	char *bp = buf[idx++ % 8];

	return convert_ssaddr_to_str(bp, gs) ? "-" : bp;
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
		/*
		 * Not fopen(): it follows a symlink at the path, so a local
		 * user who can write to the log directory could have a proxy
		 * running as root append to any file at all.
		 */
		int fd = open(cfg->log_file, O_WRONLY | O_CREAT | O_APPEND |
			      O_NOFOLLOW | O_CLOEXEC, 0640);

		ctx->lh.handle = fd >= 0 ? fdopen(fd, "ab") : NULL;
		if (!ctx->lh.handle) {
			r = -errno;
			if (fd >= 0)
				close(fd);
			/* There is no log to report this to, so not pr_err(). */
			fprintf(stderr, "Failed to open log file '%s': %s\n",
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

/*
 * Write our PID to --pid-file. The file is opened without following a
 * symlink, which fopen("w") did, truncating whatever the link pointed to, and
 * only truncated once we hold its lock, so a second instance pointed at the
 * same file leaves the first one's PID alone. The lock is held, and the file
 * kept, for as long as the proxy runs; gwp_ctx_free_pid_file() removes it.
 *
 * Nothing here stops the proxy: a PID file that cannot be written (a symlink,
 * one locked by another instance, a read-only directory) is warned about and
 * the proxy runs without it, as the manual says. Hence no return value.
 */
__cold
static void gwp_ctx_init_pid_file(struct gwp_ctx *ctx)
{
	const char *path = ctx->cfg.pid_file;
	char buf[32];
	int fd, n;

	fd = open(path, O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0644);
	if (fd < 0) {
		pr_warn(&ctx->lh, "Failed to open PID file '%s': %s; running without it",
			path, strerror(errno));
		return;
	}

	if (flock(fd, LOCK_EX | LOCK_NB)) {
		pr_warn(&ctx->lh, "PID file '%s' is locked by another process; not writing it",
			path);
		close(fd);
		return;
	}

	n = snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
	errno = 0;
	if (ftruncate(fd, 0) || write(fd, buf, (size_t)n) != n) {
		pr_warn(&ctx->lh, "Failed to write PID file '%s': %s; running without it",
			path, strerror(errno ? errno : EIO));
		close(fd);
		return;
	}

	pr_info(&ctx->lh, "Writing PID to '%s' (pid=%d)", path, (int)getpid());
	ctx->pid_fd = fd;
}

__cold
static void gwp_ctx_free_pid_file(struct gwp_ctx *ctx)
{
	if (ctx->pid_fd < 0)
		return;

	/* Ours: we hold the lock, so no other instance wrote it since. */
	unlink(ctx->cfg.pid_file);
	close(ctx->pid_fd);
	ctx->pid_fd = -1;
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
		pr_err(&w->ctx->lh, "Failed to create socket: %s", strerror(-fd));
		return fd;
	}

	v = 1;
	__sys_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
	__sys_setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &v, sizeof(v));

	/*
	 * The client-side TCP options. An accepted socket inherits
	 * TCP_NODELAY, SO_KEEPALIVE and the keepalive timings from the
	 * listener, so setting them here once covers every client of this
	 * worker, whichever event loop accepts it.
	 */
	gwp_setup_cli_sock_options(w, fd);

	/*
	 * --bind-ipv6-only. Set unconditionally on an IPv6 listener rather than
	 * only when asked, so the behaviour does not depend on the host's
	 * net.ipv6.bindv6only sysctl: a wildcard [::] bind accepts IPv4 clients
	 * as ::ffff:a.b.c.d by default, and refuses them when this is on.
	 *
	 * This is the LISTENER only. The SOCKS5 UDP relay socket deliberately
	 * clears IPV6_V6ONLY (see gwp_socks5_udp_associate_setup) because a
	 * single-family bind cannot egress the other family; applying this
	 * there would break UDP ASSOCIATE to IPv4 targets.
	 */
	if (ba->sa.sa_family == AF_INET6) {
		int v6only = cfg->bind_ipv6_only ? 1 : 0;

		r = setskopt_int(fd, IPPROTO_IPV6, IPV6_V6ONLY, v6only);
		if (r < 0) {
			pr_err(&w->ctx->lh, "Failed to set IPV6_V6ONLY=%d: %s",
			       v6only, strerror(-r));
			goto out_close;
		}
	}

	r = __sys_bind(fd, (struct sockaddr *)ba, slen);
	if (r < 0) {
		/* What an IPv6 address gets on a host with IPv6 turned off. */
		pr_err(&w->ctx->lh, "Failed to bind %s: %s%s", ip_to_str(ba),
		       strerror(-r),
		       ba->sa.sa_family == AF_INET6 && r == -EADDRNOTAVAIL ?
		       " (is IPv6 disabled on this host?)" : "");
		goto out_close;
	}

	r = __sys_listen(fd, SOMAXCONN);
	if (r < 0) {
		pr_err(&w->ctx->lh, "Failed to listen on socket: %s", strerror(-r));
		goto out_close;
	}

	slen = sizeof(w->listen_addr);
	r = __sys_getsockname(fd, &w->listen_addr.sa, &slen);
	if (r < 0) {
		pr_err(&w->ctx->lh, "Failed to get the listening address: %s",
		       strerror(-r));
		goto out_close;
	}

	w->tcp_fd = fd;
	pr_info(&w->ctx->lh, "Worker %u is listening on %s (fd=%d)", w->idx,
		ip_to_str(&w->listen_addr), fd);
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
	struct gwp_cfg *cfg = &ctx->cfg;
	int r;

	r = gwp_ctx_init_thread_sock(w, bind_addr);
	if (r < 0) {
		pr_err(&ctx->lh, "gwp_ctx_init_thread_sock: %s", strerror(-r));
		return r;
	}


	if (cfg->use_raw_dns) {
		r = gwp_ctx_init_raw_dns(w);
		if (r < 0) {
			pr_err(&ctx->lh, "Failed to initialize raw DNS: %s", strerror(-r));
			goto out_err;
		}
	}

	r = gwp_ctx_init_thread_event(w);
	if (r < 0) {
		pr_err(&ctx->lh, "gwp_ctx_init_thread_event: %s", strerror(-r));
		goto out_err_raw_dns;
	}

	return r;

out_err_raw_dns:
	if (cfg->use_raw_dns)
		gwp_ctx_free_raw_dns(w);
out_err:
	gwp_ctx_free_thread_sock(w);
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

/*
 * Drop the name lookup a connection pair may still be waiting for: free a
 * raw-DNS query's packet and close its socket, or tell the DNS thread pool
 * that nobody wants the answer any more. gdp and gde share a union, so which
 * one is live depends on --raw-dns.
 */
static void gwp_conn_pair_drop_dns(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
#ifdef CONFIG_NEW_DNS_RESOLVER
	if (w->ctx->cfg.use_raw_dns) {
		/* Closes the query's socket if it is still open. */
		gwp_free_dns_packet(gcp);
		return;
	}
#else
	(void)w;
#endif
	if (gcp->gde)
		gwp_dns_entry_cancel(gcp->gde);
}

/*
 * TLS tells the end of a client's stream from it being cut: a forged or broken
 * record, a fatal alert, a reset, half a record. A pair that goes down with the
 * target's write side not shut has not seen that end, so a plain close() would
 * hand the target the very EOF that a protocol framed by it takes for a complete
 * stream. Make the close reset the connection. A plaintext client has no such
 * end to tell apart, and is left as it is.
 *
 * A connect attempt counts as well: the target may have accepted long before the
 * proxy gets to see the result, and would read an empty stream as a complete one.
 *
 * The same holds the other way round for an https:// upstream proxy once the
 * tunnel through it is up: a client whose write side was not shut has not seen
 * the end of the upstream's stream, and gets a reset. Before that, the client
 * may still be owed its failure reply, which a reset would throw away.
 */
#ifdef CONFIG_HTTPS
static void gwp_set_reset_on_close(int fd)
{
	static const struct linger l = { .l_onoff = 1, .l_linger = 0 };

	__sys_setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l));
}
#endif

void gwp_conn_pair_abort_attempts(const struct gwp_conn_pair __unused *gcp)
{
#ifdef CONFIG_HTTPS
	uint8_t i;

	if (!gcp->client.tls)
		return;

	for (i = 0; i < GWP_MAX_CONN_CAND; i++) {
		if (gcp->attempt_fd[i] >= 0)
			gwp_set_reset_on_close(gcp->attempt_fd[i]);
	}
#endif
}

static void gwp_conn_pair_abort_target(const struct gwp_conn_pair __unused *gcp)
{
#ifdef CONFIG_HTTPS
	if (gcp->client.tls && gcp->target.fd >= 0 && !gcp->target.wr_shut)
		gwp_set_reset_on_close(gcp->target.fd);
	if (gcp->target.tls && gcp->is_target_alive && gcp->client.fd >= 0 &&
	    !gcp->client.wr_shut)
		gwp_set_reset_on_close(gcp->client.fd);
	gwp_conn_pair_abort_attempts(gcp);
#endif
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
		gwp_conn_pair_abort_target(gcp);
		if (gcp->flags & GWP_CONN_FLAG_IPLIM)
			gwp_ctx_iplim_put(w->ctx, &gcp->client_addr);
		free_conn(&gcp->target);
		free_conn(&gcp->client);
		if (gcp->timer_fd >= 0)
			__sys_close(gcp->timer_fd);
		if (gcp->udp_fd >= 0)
			__sys_close(gcp->udp_fd);
		gwp_conn_close_attempts(gcp);
		gwp_conn_pair_drop_dns(w, gcp);
		free(gcp->udp_iou);	/* io_uring relay scratch, else NULL */
		free(gcp->udp_peers);
		gwp_conn_set_upstream(w->ctx, gcp, NULL);

		/*
		 * s5_conn and http_conn share a union, so the protocol object
		 * must be freed through the correct type; freeing an http_conn
		 * as a SOCKS5 conn corrupts memory. Mirror gwp_free_conn_pair().
		 */
		switch (gcp->prot_type) {
		case GWP_PROT_TYPE_SOCKS5:
			gwp_socks5_conn_free(gcp->s5_conn);
			break;
		case GWP_PROT_TYPE_HTTP:
			gwp_http_conn_free(gcp->http_conn);
			break;
		}

#ifdef CONFIG_HTTPS
		gwp_ssl_free(gcp->client.tls);
		gwp_ssl_free(gcp->target.tls);
#if defined(CONFIG_IO_URING)
		free(gcp->tls_io);
		free(gcp->up_tls_io);
#endif
#endif

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
	struct gwp_cfg *cfg = &w->ctx->cfg;

	/*
	 * Event loop first: an io_uring request still in flight would write
	 * into the buffers freed below (closing a socket's fd does not end a
	 * recv armed on it), so the ring must be done with them before they
	 * go. Tearing it down cancels whatever it has left.
	 */
	gwp_ctx_free_thread_event(w);

	if (cfg->use_raw_dns)
		gwp_ctx_free_raw_dns(w);

	gwp_ctx_free_thread_sock_pairs(w);
	gwp_ctx_free_thread_sock(w);
}

/*
 * The defaults make an open proxy: the listener is the [::]:1080 wildcard and
 * SOCKS5 and HTTP clients need no credentials without --auth-file. Changing
 * either default would break existing setups, so say it loudly at startup
 * instead when a SOCKS5 or HTTP proxy without --auth-file listens on anything
 * but loopback. The ACL's INPUT chain may still limit the clients; whether it
 * does cannot be told from here, so the warning names it.
 */
__cold
static void gwp_ctx_warn_open_proxy(struct gwp_ctx *ctx,
				    const struct gwp_sockaddr *addr)
{
	const struct gwp_cfg *cfg = &ctx->cfg;
	const uint8_t *a6;

	if (!cfg->as_socks5 && !cfg->as_http)
		return;
	if (cfg->auth_file && *cfg->auth_file)
		return;

	if (addr->sa.sa_family == AF_INET) {
		if ((ntohl(addr->i4.sin_addr.s_addr) >> 24) == 127)
			return;
	} else {
		a6 = addr->i6.sin6_addr.s6_addr;
		if (IN6_IS_ADDR_LOOPBACK(&addr->i6.sin6_addr) ||
		    (IN6_IS_ADDR_V4MAPPED(&addr->i6.sin6_addr) && a6[12] == 127))
			return;
	}

	pr_warn(&ctx->lh, "Listening on %s without --auth-file: anyone who can reach it can use this proxy, unless an --acl-file INPUT rule limits the clients",
		ip_to_str(addr));
}

/*
 * A kernel without IPv6 (booted with ipv6.disable=1) refuses every AF_INET6
 * socket. The wildcard [::] -- the default --bind among others -- asks for
 * every address the host has, which there are the IPv4 ones: listen on
 * 0.0.0.0 instead, and say so, rather than refuse to start. Not with
 * --bind-ipv6-only=1, which asks for IPv6 alone. Any other IPv6 address
 * cannot be listened on at all, and the error says why.
 *
 * A host that has IPv6 but turned it off with the disable_ipv6 sysctl still
 * creates the socket, and a [::] bind there works and takes IPv4 clients;
 * a bind to an IPv6 address then fails, see gwp_ctx_init_thread_sock().
 */
__cold
static int gwp_ctx_check_bind_family(struct gwp_ctx *ctx,
				     struct gwp_sockaddr *addr)
{
	uint16_t port = addr->i6.sin6_port;
	int fd;

	if (addr->sa.sa_family != AF_INET6)
		return 0;

	fd = __sys_socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd >= 0) {
		__sys_close(fd);
		return 0;
	}
	/* Anything else is for the listener's own setup to report. */
	if (fd != -EAFNOSUPPORT)
		return 0;

	if (!IN6_IS_ADDR_UNSPECIFIED(&addr->i6.sin6_addr) ||
	    ctx->cfg.bind_ipv6_only) {
		pr_err(&ctx->lh, "Cannot listen on %s: IPv6 is not available on this host",
		       ip_to_str(addr));
		return -EAFNOSUPPORT;
	}

	memset(addr, 0, sizeof(*addr));
	addr->i4.sin_family = AF_INET;
	addr->i4.sin_addr.s_addr = htonl(INADDR_ANY);
	addr->i4.sin_port = port;
	pr_warn(&ctx->lh, "IPv6 is not available on this host: listening on %s, IPv4 only, instead of %s",
		ip_to_str(addr), ctx->cfg.bind);
	return 0;
}

__cold
static int gwp_ctx_init_threads(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;
	struct gwp_sockaddr bind_addr;
	struct gwp_wrk *workers, *w;
	int i, r;

	if (cfg->nr_workers <= 0) {
		pr_err(&ctx->lh, "Number of workers must be at least 1");
		return -EINVAL;
	}

	r = convert_str_to_ssaddr(cfg->bind, &bind_addr, 0);
	if (r) {
		pr_err(&ctx->lh, "Invalid bind address '%s'", cfg->bind);
		return r;
	}
	r = gwp_ctx_check_bind_family(ctx, &bind_addr);
	if (r)
		return r;
	gwp_ctx_warn_open_proxy(ctx, &bind_addr);

	if (posix_memalign((void **)&workers, GWP_CACHELINE,
			   (size_t)cfg->nr_workers * sizeof(*workers)))
		return -ENOMEM;
	memset(workers, 0, (size_t)cfg->nr_workers * sizeof(*workers));

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
	void *ret;
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
		pthread_join(w->thread, &ret);
		w->need_join = false;
		if ((intptr_t)ret < 0 && !ctx->worker_err)
			ctx->worker_err = (int)(intptr_t)ret;
	}

	for (i = 0; i < ctx->cfg.nr_workers; i++)
		gwp_ctx_free_thread(&workers[i]);

	free(workers);
	ctx->workers = NULL;
}

/*
 * Reload of the auth and ACL files. A SIGHUP reloads them all (see
 * gwp_ctx_reload_hup()); with --watch-files=1, watching them also reloads a
 * file when it changes.
 *
 * The watch: the reload thread reads ctx->ino_fd into a GWP_INO_BUF_SIZE
 * buffer (room for a burst of records, so one read usually drains it),
 * gwp_reload_events() turns the records into the GWP_RELOAD_* files they name,
 * and gwp_ctx_reload_files() reloads each of those once.
 *
 * Inotify only reports changes made through the configured name in its
 * directory. A file can also change behind a symlink, by a swap of a directory
 * or a symlink further up the path, or by unlink and link, and neither the
 * parent watch nor a watch on the inode sees all of those. So the thread also
 * stat()s the paths every GWP_RELOAD_CHECK_MS and reloads a file whose
 * gwp_file_id changed and then stayed the same for GWP_RELOAD_SETTLE_MS: inotify
 * keeps the common case prompt, the check is what catches the other layouts.
 *
 * The check cannot tell a finished change from a writer that merely paused,
 * while inotify reports the close. Hence the long wait, and it has no upper
 * limit: reading too soon can put a half written file in force, which for an
 * ACL can let through what the finished file rejects.
 */
#define GWP_INO_BUF_SIZE	4096
#define GWP_RELOAD_CHECK_MS	1000
#define GWP_RELOAD_SETTLE_MS	5000
#define GWP_RELOAD_AUTH		(1u << 0)
#define GWP_RELOAD_ACL		(1u << 1)

static const char *path_basename(const char *path)
{
	const char *slash = strrchr(path, '/');

	return slash ? slash + 1 : path;
}

/*
 * Add an inotify watch that survives an atomic replace of `path`. We watch the
 * *parent directory*, not the file: an inode watch is silently dropped the
 * moment an editor, `install`, or `mv` swaps the file via rename, and never
 * fires again. Watching the directory for IN_CLOSE_WRITE (in-place writes) and
 * IN_MOVED_TO (rename-into-place) catches both update styles; handlers narrow
 * the reported events down to the file's basename with
 * gwp_reload_events(). Returns the watch descriptor or -errno.
 */
static int add_reload_watch(int ino_fd, const char *path)
{
	const char *slash = strrchr(path, '/');
	char dir[PATH_MAX];
	int r;

	if (!slash) {
		dir[0] = '.';
		dir[1] = '\0';
	} else {
		size_t n = (size_t)(slash - path);

		if (n == 0)		/* "/file": watch the root directory */
			n = 1;
		if (n >= sizeof(dir))
			return -ENAMETOOLONG;
		memcpy(dir, path, n);
		dir[n] = '\0';
	}

	r = inotify_add_watch(ino_fd, dir, IN_CLOSE_WRITE | IN_MOVED_TO);
	return (r < 0) ? -errno : r;
}

/*
 * The identity of a file as @st describes it, or as missing for the reason
 * @err (a positive errno; @st is not read then). Beyond a FIFO's or a device's
 * identity nothing is compared: writing to it is not a new version of it. The
 * ctime is what catches a rewrite that restores the mtime, at the price of a
 * harmless reload after a chmod or a new hard link.
 */
static void gwp_file_id_from_stat(const struct stat *st, int err,
				  struct gwp_file_id *id)
{
	memset(id, 0, sizeof(*id));
	if (err) {
		id->err = (uint64_t)err;
		return;
	}
	id->dev = (uint64_t)st->st_dev;
	id->ino = (uint64_t)st->st_ino;
	id->mode = (uint64_t)(st->st_mode & S_IFMT);
	if (!S_ISREG(st->st_mode))
		return;
	id->size = (uint64_t)st->st_size;
	id->mtime_sec = (uint64_t)st->st_mtim.tv_sec;
	id->mtime_nsec = (uint64_t)st->st_mtim.tv_nsec;
	id->ctime_sec = (uint64_t)st->st_ctim.tv_sec;
	id->ctime_nsec = (uint64_t)st->st_ctim.tv_nsec;
}

/* Take the identity of the file @path resolves to now. */
static void gwp_file_id_read(const char *path, struct gwp_file_id *id)
{
	struct stat st;

	if (stat(path, &st))
		gwp_file_id_from_stat(NULL, errno, id);
	else
		gwp_file_id_from_stat(&st, 0, id);
}

/* Refresh @id from @path and tell whether it differs from what it was. */
static bool gwp_file_id_changed(const char *path, struct gwp_file_id *id)
{
	struct gwp_file_id cur;

	gwp_file_id_read(path, &cur);
	if (!memcmp(&cur, id, sizeof(cur)))
		return false;
	*id = cur;
	return true;
}

static void gwp_acl_files_free(struct gwp_reload_acl_file *v, size_t nr)
{
	size_t i;

	for (i = 0; i < nr; i++)
		free(v[i].path);
	free(v);
}

/*
 * Make ctx->acl_files follow the files of the ACL's last load or reload (see
 * gwp_acl_file()), which change as includes are added or dropped. A file that
 * stays keeps its state, and so the identity taken before it was read; so does
 * a new one, from what the load saw right before reading it. A stat() taken
 * now could already see a change made since, which would then never be
 * reloaded, as no watch on a new directory existed yet to report it. With
 * @watch, a new file's directory gets a watch, and a watch that neither the
 * new set nor the auth file needs any more is removed. On failure (out of
 * memory) the set stays as it was.
 */
static int gwp_acl_files_sync(struct gwp_ctx *ctx, bool watch)
{
	struct gwp_reload_acl_file *old = ctx->acl_files, *nv;
	size_t nr_old = ctx->nr_acl_files, nr = 0, i, j;
	struct stat st;
	ssize_t *from;
	int r = 0;

	while (gwp_acl_file(ctx->acl, nr))
		nr++;
	nv = calloc(nr ? nr : 1, sizeof(*nv));
	from = calloc(nr ? nr : 1, sizeof(*from));
	if (!nv || !from) {
		r = -ENOMEM;
		goto out;
	}

	/* Everything that can fail first, so a failure changes nothing. */
	for (i = 0; i < nr; i++) {
		const char *path = gwp_acl_file(ctx->acl, i);

		from[i] = -1;
		for (j = 0; j < nr_old; j++) {
			if (!strcmp(old[j].path, path)) {
				from[i] = (ssize_t)j;
				break;
			}
		}
		if (from[i] >= 0)
			continue;
		nv[i].path = strdup(path);
		if (!nv[i].path) {
			for (j = 0; j < i; j++)
				free(nv[j].path);
			r = -ENOMEM;
			goto out;
		}
	}

	for (i = 0; i < nr; i++) {
		int sr, wd;

		if (from[i] >= 0) {
			nv[i] = old[from[i]];
			old[from[i]].path = NULL;
			continue;
		}
		nv[i].wd = -1;
		sr = gwp_acl_file_stat(ctx->acl, i, &st);
		gwp_file_id_from_stat(&st, sr < 0 ? -sr : 0, &nv[i].rf.id);
		if (!watch)
			continue;
		wd = add_reload_watch(ctx->ino_fd, nv[i].path);
		if (wd < 0)
			pr_warn(&ctx->lh, "Failed to add inotify watch for '%s', checking it every second only: %s",
				nv[i].path, strerror(-wd));
		else
			nv[i].wd = wd;
	}

	for (j = 0; watch && j < nr_old; j++) {
		int wd = old[j].wd;

		if (!old[j].path || wd < 0 || wd == ctx->auth_wd)
			continue;
		for (i = 0; i < nr && nv[i].wd != wd; i++)
			;
		/* Two dropped files may share one; the second call fails. */
		if (i == nr)
			inotify_rm_watch(ctx->ino_fd, wd);
	}

	gwp_acl_files_free(old, nr_old);
	ctx->acl_files = nv;
	ctx->nr_acl_files = nr;
	nv = NULL;
out:
	free(nv);
	free(from);
	return r;
}

/*
 * Tell whether the periodic check should reload @path now. A change only starts
 * the wait for it to settle, and any further change restarts that wait. Opening
 * a FIFO or a device could block for a writer that never comes, stopping every
 * later reload and shutdown, so one that only the check found is left alone
 * until the path leads to something else.
 */
static bool gwp_reload_check_file(struct gwp_ctx *ctx, const char *path,
				  struct gwp_reload_file *rf, uint64_t now)
{
	if (gwp_file_id_changed(path, &rf->id)) {
		rf->settle_at = now + GWP_RELOAD_SETTLE_MS;
		return false;
	}
	if (!rf->settle_at)
		return rf->retry;
	if (now < rf->settle_at)
		return false;
	if (rf->id.err || rf->id.mode == S_IFREG)
		return true;

	rf->settle_at = 0;
	rf->retry = false;
	pr_warn(&ctx->lh, "Not reloading '%s': not a regular file; keeping its current contents",
		path);
	return false;
}

/* The GWP_RELOAD_* files the periodic check wants reloaded now. */
static unsigned gwp_reload_check(struct gwp_ctx *ctx, uint64_t now)
{
	unsigned flags = 0;
	size_t i;

	if (ctx->auth && gwp_reload_check_file(ctx, ctx->cfg.auth_file,
					       &ctx->auth_reload, now))
		flags |= GWP_RELOAD_AUTH;
	for (i = 0; ctx->acl_watched && i < ctx->nr_acl_files; i++) {
		struct gwp_reload_acl_file *f = &ctx->acl_files[i];

		if (gwp_reload_check_file(ctx, f->path, &f->rf, now))
			flags |= GWP_RELOAD_ACL;
	}
	return flags;
}

/*
 * Record the identity right before the file is read, so a change made during
 * or after that read differs from it and is reloaded in turn, while a file that
 * failed to load is not read (and logged) again until it changes.
 */
static void gwp_reload_begin(const char *path, struct gwp_reload_file *rf)
{
	gwp_file_id_read(path, &rf->id);
	rf->settle_at = 0;
}

/*
 * Note the outcome @r of a reload and tell whether a failure is to be logged.
 * Running out of descriptors or memory says nothing about the file, and its new
 * contents would otherwise be lost until it changes again, so such a reload is
 * retried at each check, logged only the first time.
 */
static bool gwp_reload_end(struct gwp_reload_file *rf, int r)
{
	bool was_retry = rf->retry;

	rf->retry = r == -EMFILE || r == -ENFILE || r == -ENOMEM;
	return r && !(was_retry && rf->retry);
}

/* True when inotify record @e names the basename of @path (NULL: never). */
static bool inotify_names(const struct inotify_event *e, const char *path)
{
	return path && e->len && !strcmp(e->name, path_basename(path));
}

/*
 * Classify a drained inotify buffer into the GWP_RELOAD_* files it names. The
 * watches sit on the parent directories (see add_reload_watch), so records for
 * unrelated directory churn are ignored, and a burst of records for the same
 * file still yields a single reload.
 */
static unsigned gwp_reload_events(const struct gwp_ctx *ctx, const void *buf,
				  size_t len)
{
	const char *auth = ctx->auth ? ctx->cfg.auth_file : NULL;
	unsigned flags = 0;
	size_t off = 0, i;

	while (off + sizeof(struct inotify_event) <= len) {
		const struct inotify_event *e =
			(const struct inotify_event *)((const char *)buf + off);
		size_t rec = sizeof(*e) + e->len;

		/*
		 * The kernel dropped events (queue overflow, delivered as a
		 * nameless wd=-1 record). A watched file's change may have been
		 * among the lost ones, so force a reload rather than miss it.
		 */
		if (e->mask & IN_Q_OVERFLOW)
			return GWP_RELOAD_AUTH | GWP_RELOAD_ACL;

		if (off + rec > len)
			break;
		if (inotify_names(e, auth))
			flags |= GWP_RELOAD_AUTH;
		for (i = 0; ctx->acl_watched && i < ctx->nr_acl_files; i++) {
			const struct gwp_reload_acl_file *f = &ctx->acl_files[i];

			/*
			 * Files of the set can share a basename, so the
			 * directory the record came from must match too.
			 */
			if (e->wd == f->wd && inotify_names(e, f->path)) {
				flags |= GWP_RELOAD_ACL;
				break;
			}
		}
		off += rec;
	}
	return flags;
}

/* Reload the files named by @flags (GWP_RELOAD_*), logging the outcome. */
static void gwp_ctx_reload_files(struct gwp_ctx *ctx, unsigned flags)
{
	int r;

	if ((flags & GWP_RELOAD_AUTH) && ctx->auth) {
		gwp_reload_begin(ctx->cfg.auth_file, &ctx->auth_reload);
		r = gwp_auth_reload(ctx->auth);
		if (gwp_reload_end(&ctx->auth_reload, r))
			pr_warn(&ctx->lh, "Failed to reload authentication file: %s; keeping current credentials",
				strerror(-r));
		else if (!r)
			pr_info(&ctx->lh, "Reloaded authentication file");
	}
	if ((flags & GWP_RELOAD_ACL) && ctx->acl_watched) {
		bool log_err = false;
		size_t i;
		int rs;

		for (i = 0; i < ctx->nr_acl_files; i++)
			gwp_reload_begin(ctx->acl_files[i].path,
					 &ctx->acl_files[i].rf);
		r = gwp_acl_reload(ctx->acl);
		rs = gwp_acl_files_sync(ctx, ctx->ino_fd >= 0);
		if (rs)
			pr_warn(&ctx->lh, "Failed to update the set of ACL files to reload: %s",
				strerror(-rs));
		/*
		 * The set reloads as one, so each file carries its outcome;
		 * the --acl-file, always the first, says whether to log it.
		 */
		for (i = 0; i < ctx->nr_acl_files; i++) {
			bool e = gwp_reload_end(&ctx->acl_files[i].rf, r);

			if (!i)
				log_err = e;
		}
		if (log_err)
			pr_warn(&ctx->lh, "Failed to reload ACL file: %s; keeping current rules",
				strerror(-r));
		else if (!r)
			pr_info(&ctx->lh, "Reloaded ACL file");
	}
}

/*
 * Read every inotify record queued so far and return the GWP_RELOAD_* files
 * they name, or -errno. The drain is bounded so a directory under constant
 * churn cannot keep the caller here forever.
 */
static int gwp_reload_drain(struct gwp_ctx *ctx, char *buf, unsigned *flags)
{
	ssize_t r;
	int i;

	for (i = 0; i < 16; i++) {
		r = __sys_read(ctx->ino_fd, buf, GWP_INO_BUF_SIZE);
		if (r < 0) {
			if (r == -EINTR)
				continue;
			if (r == -EAGAIN)
				break;
			return (int)r;
		}
		if (!r)
			break;
		*flags |= gwp_reload_events(ctx, buf, (size_t)r);
	}
	return 0;
}

/*
 * A burst of file events (an editor's save, a deploy script writing both
 * files, a config manager rewriting a file line by line) is reloaded once it
 * has been quiet for GWP_RELOAD_QUIET_MS, instead of once per event. Under
 * changes that never pause, a reload still runs every GWP_RELOAD_MAX_WAIT_MS.
 */
#define GWP_RELOAD_QUIET_MS	100
#define GWP_RELOAD_MAX_WAIT_MS	1000

static uint64_t gwp_reload_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/*
 * A SIGHUP: the operator says the files are ready, so every configured file is
 * reloaded at once, with no wait for it to settle. Each failure is logged, even
 * one the periodic check would retry quietly.
 */
static void gwp_ctx_reload_hup(struct gwp_ctx *ctx)
{
	size_t i;

	if (!ctx->auth && !ctx->acl_watched) {
		pr_info(&ctx->lh, "Received SIGHUP, but no auth or ACL file is configured; nothing to reload");
		return;
	}

	pr_info(&ctx->lh, "Received SIGHUP, reloading the configured files");
	ctx->auth_reload.retry = false;
	for (i = 0; i < ctx->nr_acl_files; i++)
		ctx->acl_files[i].rf.retry = false;
	gwp_ctx_reload_files(ctx, GWP_RELOAD_AUTH | GWP_RELOAD_ACL);
}

/*
 * The reload thread. Reading, parsing and compiling a large auth or ACL file
 * takes milliseconds (tens with many regexes), and a worker doing it serves
 * none of its connections meanwhile, so the files are reloaded here instead.
 * The stores publish a new set under their own locks, so no worker waits for
 * more than that swap.
 *
 * A SIGHUP reloads every file. The eventfd is drained before the flag is
 * taken, so the signals that arrive during a reload give one more reload after
 * it, not one each.
 *
 * When the files are watched, the paths are also checked every
 * GWP_RELOAD_CHECK_MS. The first check, at once, catches a change made since
 * the startup load.
 */
static void *gwp_reload_thread(void *arg)
{
	struct gwp_ctx *ctx = arg;
	char buf[GWP_INO_BUF_SIZE]
		__attribute__((aligned(__alignof__(struct inotify_event))));
	/* poll() skips a negative fd: ino_fd when nothing is watched. */
	struct pollfd pfd[3] = {
		{ .fd = ctx->reload_efd, .events = POLLIN },
		{ .fd = ctx->hup_efd, .events = POLLIN },
		{ .fd = ctx->ino_fd, .events = POLLIN },
	};
	bool watch = ctx->ino_fd >= 0;
	uint64_t now, first = 0, due = 0, next_check = 0;
	unsigned flags, pending = 0;
	int r, timeout;

	for (;;) {
		uint64_t wake = pending && due < next_check ? due : next_check;

		now = gwp_reload_now_ms();
		if (!watch)
			timeout = -1;
		else
			timeout = wake > now ? (int)(wake - now) : 0;

		r = poll(pfd, 3, timeout);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			r = -errno;
			break;
		}
		if (pfd[0].revents)
			return NULL;

		if (pfd[1].revents) {
			eventfd_t v;

			/* Nonblocking; empty (EAGAIN) is fine too. */
			(void)eventfd_read(ctx->hup_efd, &v);
			if (atomic_exchange(&ctx->reload_hup, false)) {
				/*
				 * The reload covers every change made so far:
				 * drop what the watch queued for them, or the
				 * same edit is reloaded again right after.
				 */
				if (watch) {
					flags = 0;
					r = gwp_reload_drain(ctx, buf, &flags);
					if (r < 0)
						break;
					pfd[2].revents = 0;
				}
				gwp_ctx_reload_hup(ctx);
				pending = 0;
			}
		}
		if (!watch)
			continue;

		flags = 0;
		if (pfd[2].revents) {
			r = gwp_reload_drain(ctx, buf, &flags);
			if (r < 0)
				break;
		}

		now = gwp_reload_now_ms();
		if (now >= next_check) {
			flags |= gwp_reload_check(ctx, now);
			next_check = now + GWP_RELOAD_CHECK_MS;
		}
		if (flags) {
			if (!pending)
				first = now;
			pending |= flags;
			due = now + GWP_RELOAD_QUIET_MS;
			if (due > first + GWP_RELOAD_MAX_WAIT_MS)
				due = first + GWP_RELOAD_MAX_WAIT_MS;
		}

		if (!pending || now < due)
			continue;
		gwp_ctx_reload_files(ctx, pending);
		pending = 0;
	}

	pr_err(&ctx->lh, "Reload thread stopped, the files are no longer reloaded: %s",
	       strerror(-r));
	return NULL;
}

/*
 * With --watch-files=1, one inotify instance watches the auth file and the
 * files of the ACL (the --acl-file and those it includes), so when they share a
 * directory each event is read once, not once per file. Leaves ino_fd at -1
 * when the files are not watched or neither is configured.
 */
static int gwp_ctx_init_watch(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;
	size_t i;
	int r;

	if (!cfg->watch_files || (!ctx->auth && !ctx->acl_watched))
		return 0;

	r = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (r < 0) {
		r = -errno;
		pr_err(&ctx->lh, "Failed to initialize inotify: %s", strerror(-r));
		return r;
	}
	ctx->ino_fd = r;
	pr_dbg(&ctx->lh, "Inotify file descriptor initialized (fd=%d)", r);

	if (ctx->auth) {
		r = add_reload_watch(ctx->ino_fd, cfg->auth_file);
		if (r < 0) {
			pr_err(&ctx->lh, "Failed to add inotify watch for '%s': %s",
				cfg->auth_file, strerror(-r));
			goto out_err;
		}
		pr_dbg(&ctx->lh, "Inotify watch added for '%s' (wd=%d)",
			cfg->auth_file, r);
		ctx->auth_wd = r;
	}

	for (i = 0; ctx->acl_watched && i < ctx->nr_acl_files; i++) {
		struct gwp_reload_acl_file *f = &ctx->acl_files[i];

		r = add_reload_watch(ctx->ino_fd, f->path);
		if (r < 0) {
			pr_err(&ctx->lh, "Failed to add inotify watch for '%s': %s",
				f->path, strerror(-r));
			goto out_err;
		}
		pr_dbg(&ctx->lh, "Inotify watch added for '%s' (wd=%d)",
			f->path, r);
		f->wd = r;
	}
	return 0;

out_err:
	__sys_close(ctx->ino_fd);
	ctx->ino_fd = -1;
	ctx->auth_wd = -1;
	for (i = 0; i < ctx->nr_acl_files; i++)
		ctx->acl_files[i].wd = -1;
	return r;
}

/*
 * Stop the reload thread. A reload in progress finishes first, so the stores
 * are not freed under it.
 */
static void gwp_ctx_free_reload(struct gwp_ctx *ctx)
{
	size_t i;

	if (ctx->reload_running) {
		eventfd_t one = 1;

		if (eventfd_write(ctx->reload_efd, one))
			pr_err(&ctx->lh, "Failed to signal the reload thread: %s",
			       strerror(errno));
		pthread_join(ctx->reload_thread, NULL);
		ctx->reload_running = false;
	}
	if (ctx->reload_efd >= 0) {
		__sys_close(ctx->reload_efd);
		ctx->reload_efd = -1;
	}
	if (ctx->hup_efd >= 0) {
		__sys_close(ctx->hup_efd);
		ctx->hup_efd = -1;
	}
	if (ctx->ino_fd >= 0) {
		__sys_close(ctx->ino_fd);
		ctx->ino_fd = -1;
	}
	ctx->auth_wd = -1;
	for (i = 0; i < ctx->nr_acl_files; i++)
		ctx->acl_files[i].wd = -1;
}

/*
 * Start the reload thread, with the file watch (see gwp_ctx_init_watch()) and
 * the eventfds it polls. It runs even when no file is configured, so that a
 * SIGHUP is answered with a log line rather than nothing.
 */
static int gwp_ctx_init_reload(struct gwp_ctx *ctx)
{
	sigset_t all, old;
	int r;

	ctx->ino_fd = -1;
	ctx->reload_efd = -1;
	ctx->hup_efd = -1;
	ctx->auth_wd = -1;
	ctx->reload_running = false;
	atomic_store(&ctx->reload_hup, false);

	r = gwp_ctx_init_watch(ctx);
	if (r < 0)
		return r;

	r = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (r < 0) {
		r = -errno;
		pr_err(&ctx->lh, "Failed to create reload eventfd: %s", strerror(-r));
		goto out_err;
	}
	ctx->reload_efd = r;

	r = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (r < 0) {
		r = -errno;
		pr_err(&ctx->lh, "Failed to create SIGHUP eventfd: %s", strerror(-r));
		goto out_err;
	}
	ctx->hup_efd = r;

	/*
	 * The handlers of SIGINT, SIGTERM and SIGHUP run on the other threads:
	 * the reload thread starts with every signal blocked so they are never
	 * delivered here (a SIGHUP only wakes it, see gwp_ctx_hup()).
	 */
	sigfillset(&all);
	pthread_sigmask(SIG_SETMASK, &all, &old);
	r = pthread_create(&ctx->reload_thread, NULL, gwp_reload_thread, ctx);
	pthread_sigmask(SIG_SETMASK, &old, NULL);
	if (r) {
		r = -r;
		pr_err(&ctx->lh, "Failed to create reload thread: %s", strerror(-r));
		goto out_err;
	}
	pthread_setname_np(ctx->reload_thread, "gwproxy-reload");
	ctx->reload_running = true;
	return 0;

out_err:
	gwp_ctx_free_reload(ctx);
	return r;
}

/*
 * Load the shared credential store from the auth file (if configured). The
 * store is shared by the SOCKS5 and HTTP CONNECT front-ends and reloaded by
 * gwp_ctx_init_reload()'s thread. Leaves ctx->auth NULL when no auth file is
 * configured.
 */
static int gwp_ctx_init_auth(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;
	int r;

	ctx->auth = NULL;

	if (!cfg->auth_file || !*cfg->auth_file) {
		pr_dbg(&ctx->lh, "Authentication disabled (no auth file)");
		return 0;
	}

	/* Before the load: a change made after it must differ from this. */
	gwp_file_id_read(cfg->auth_file, &ctx->auth_reload.id);
	r = gwp_auth_create(&ctx->auth, cfg->auth_file);
	if (r < 0) {
		pr_err(&ctx->lh, "Failed to load auth file '%s': %s",
			cfg->auth_file, strerror(-r));
		ctx->auth = NULL;
		return r;
	}
	return 0;
}

static void gwp_ctx_free_auth(struct gwp_ctx *ctx)
{
	gwp_auth_destroy(ctx->auth);
	ctx->auth = NULL;
}

/*
 * Applied when no --acl-file is given (and --acl-allow-all is not set): an
 * SSRF-hardening default that rejects outgoing connections to every address
 * that is not ordinary public unicast, while accepting all clients.
 * --acl-file overrides it wholesale; --acl-allow-all disables it (allow
 * everything).
 *
 * "Local" is wider than 127/8: on Linux a connect() to the unspecified address
 * (0.0.0.0, ::) lands on the local host, ::1 is loopback, and a name such as
 * "localhost" resolves to both families, so leaving any of these out lets a
 * client reach loopback-only services anyway. 169.254/16 holds the cloud
 * metadata endpoint. The IPv6 transition prefixes (IPv4-compatible ::/96,
 * NAT64, 6to4, Teredo, SIIT's ::ffff:0:a.b.c.d) can embed any of the IPv4
 * ranges above. ::ffff:a.b.c.d needs no rule of its own: the matcher folds it
 * into IPv4 before comparing, which also keeps ::/8 from covering it.
 *
 * The rest is what the IANA special-purpose registries do not call globally
 * reachable (documentation, benchmarking, ORCHID, the old 6to4 relay anycast),
 * and all of IPv6 outside 2000::/3, the only part allocated for global unicast.
 * That takes in the discard prefixes 100::/64 and 100:0:0:1::/64 under 100::/8,
 * SRv6 5f00::/16 under 4000::/3, and SIIT under ::/8.
 *
 * ::/128 and ::1/128 are listed even though ::/96 covers them, so that each
 * of them is rejected by a rule of its own.
 */
static const char gwp_acl_default_rules[] =
	"-P INPUT ACCEPT\n"
	/* IPv4 */
	"-A OUTPUT -d 0.0.0.0/8 -j REJECT\n"
	"-A OUTPUT -d 10.0.0.0/8 -j REJECT\n"
	"-A OUTPUT -d 100.64.0.0/10 -j REJECT\n"
	"-A OUTPUT -d 127.0.0.0/8 -j REJECT\n"
	"-A OUTPUT -d 169.254.0.0/16 -j REJECT\n"
	"-A OUTPUT -d 172.16.0.0/12 -j REJECT\n"
	"-A OUTPUT -d 192.0.0.0/24 -j REJECT\n"
	"-A OUTPUT -d 192.0.2.0/24 -j REJECT\n"
	"-A OUTPUT -d 192.88.99.0/24 -j REJECT\n"
	"-A OUTPUT -d 192.168.0.0/16 -j REJECT\n"
	"-A OUTPUT -d 198.18.0.0/15 -j REJECT\n"
	"-A OUTPUT -d 198.51.100.0/24 -j REJECT\n"
	"-A OUTPUT -d 203.0.113.0/24 -j REJECT\n"
	"-A OUTPUT -d 224.0.0.0/4 -j REJECT\n"
	"-A OUTPUT -d 240.0.0.0/4 -j REJECT\n"
	/* IPv6 */
	"-A OUTPUT -d ::/128 -j REJECT\n"
	"-A OUTPUT -d ::1/128 -j REJECT\n"
	"-A OUTPUT -d ::/96 -j REJECT\n"
	"-A OUTPUT -d 64:ff9b::/96 -j REJECT\n"
	"-A OUTPUT -d 64:ff9b:1::/48 -j REJECT\n"
	"-A OUTPUT -d ::/8 -j REJECT\n"
	"-A OUTPUT -d 100::/8 -j REJECT\n"
	"-A OUTPUT -d 200::/7 -j REJECT\n"
	"-A OUTPUT -d 400::/6 -j REJECT\n"
	"-A OUTPUT -d 800::/5 -j REJECT\n"
	"-A OUTPUT -d 1000::/4 -j REJECT\n"
	"-A OUTPUT -d 2001::/32 -j REJECT\n"
	"-A OUTPUT -d 2001:2::/48 -j REJECT\n"
	"-A OUTPUT -d 2001:10::/28 -j REJECT\n"
	"-A OUTPUT -d 2001:db8::/32 -j REJECT\n"
	"-A OUTPUT -d 2002::/16 -j REJECT\n"
	"-A OUTPUT -d 3fff::/20 -j REJECT\n"
	"-A OUTPUT -d 4000::/3 -j REJECT\n"
	"-A OUTPUT -d 6000::/3 -j REJECT\n"
	"-A OUTPUT -d 8000::/3 -j REJECT\n"
	"-A OUTPUT -d a000::/3 -j REJECT\n"
	"-A OUTPUT -d c000::/3 -j REJECT\n"
	"-A OUTPUT -d e000::/4 -j REJECT\n"
	"-A OUTPUT -d f000::/5 -j REJECT\n"
	"-A OUTPUT -d f800::/6 -j REJECT\n"
	"-A OUTPUT -d fc00::/7 -j REJECT\n"
	"-A OUTPUT -d fe00::/9 -j REJECT\n"
	"-A OUTPUT -d fe80::/10 -j REJECT\n"
	"-A OUTPUT -d fec0::/10 -j REJECT\n"
	"-A OUTPUT -d ff00::/8 -j REJECT\n"
	/*
	 * With a remote-DNS upstream the name is resolved over there, so the
	 * address rules above never see where "localhost" leads.
	 */
	"-A OUTPUT -m domain --domain localhost -j REJECT\n"
#ifdef CONFIG_PCRE
	"-A OUTPUT -m domain --domain-regexp \\.localhost$ -j REJECT\n"
#endif
	"-P OUTPUT ACCEPT\n";

/*
 * Load the ACL rule file (--acl-file); gwp_ctx_init_reload()'s thread then
 * reloads it and the files it includes, like the auth store.
 * Unlike auth (prot-only), the ACL is global to every proxy mode, so this is
 * initialised from gwp_ctx_init() regardless of SOCKS5/HTTP/transparent/plain
 * forwarding. With no file it applies the built-in default ACL (not reloaded),
 * unless --acl-allow-all leaves it disabled (NULL).
 */
static int acl_srv_make(void *arg, const char *url,
			const struct gwp_up_opts *opts, void **srv, char *why,
			size_t size);
static void acl_srv_put(void *arg, void *srv);
static void acl_srv_member(void *arg, void *srv, struct gwp_up_member *m);

static int gwp_ctx_init_acl(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;
	int r;

	ctx->acl = NULL;
	ctx->acl_watched = false;
	ctx->acl_files = NULL;
	ctx->nr_acl_files = 0;
	ctx->acl_srv_ops.make = acl_srv_make;
	ctx->acl_srv_ops.put = acl_srv_put;
	ctx->acl_srv_ops.member = acl_srv_member;
	ctx->acl_srv_ops.arg = ctx;
	atomic_init(&ctx->nr_acl_srv, 0);

	if (!cfg->acl_file || !*cfg->acl_file) {
		if (cfg->acl_allow_all) {
			pr_dbg(&ctx->lh, "ACL disabled (--acl-allow-all)");
			return 0;
		}

		/* No file to watch/reload: the default rules are compiled in. */
		r = gwp_acl_parse_str(&ctx->acl, gwp_acl_default_rules);
		if (r < 0) {
			pr_err(&ctx->lh, "Failed to build default ACL: %s",
				strerror(-r));
			ctx->acl = NULL;
			return r;
		}
		pr_info(&ctx->lh,
			"Applied built-in default ACL (loopback/private targets blocked; --acl-allow-all to disable)");
		return 0;
	}

	/*
	 * Before the load: a change made after it must differ from this. The
	 * files it includes are only known after it; theirs is taken then.
	 */
	ctx->acl_files = calloc(1, sizeof(*ctx->acl_files));
	if (!ctx->acl_files)
		return -ENOMEM;
	ctx->acl_files[0].path = strdup(cfg->acl_file);
	if (!ctx->acl_files[0].path) {
		r = -ENOMEM;
		goto out_err;
	}
	ctx->acl_files[0].wd = -1;
	ctx->nr_acl_files = 1;
	gwp_file_id_read(cfg->acl_file, &ctx->acl_files[0].rf.id);

	r = gwp_acl_create_ops(&ctx->acl, cfg->acl_file, &ctx->acl_srv_ops);
	if (r < 0) {
		pr_err(&ctx->lh, "Failed to load ACL file '%s': %s",
			cfg->acl_file, strerror(-r));
		goto out_err;
	}
	r = gwp_acl_files_sync(ctx, false);
	if (r < 0) {
		gwp_acl_destroy(ctx->acl);
		ctx->acl = NULL;
		goto out_err;
	}

	ctx->acl_watched = true;
	pr_info(&ctx->lh, "Loaded ACL file '%s'", cfg->acl_file);
	return 0;

out_err:
	gwp_acl_files_free(ctx->acl_files, ctx->nr_acl_files);
	ctx->acl_files = NULL;
	ctx->nr_acl_files = 0;
	return r;
}

static void gwp_ctx_free_acl(struct gwp_ctx *ctx)
{
	uint32_t left;

	gwp_acl_destroy(ctx->acl);
	/*
	 * The workers are gone, and their connections with them, and so are
	 * the pools: no pool server may be left. One that is was not given
	 * back by a connection teardown.
	 */
	left = atomic_load_explicit(&ctx->nr_acl_srv, memory_order_acquire);
	if (left)
		pr_err(&ctx->lh, "BUG: %u upstream pool server(s) still referenced at exit, want 0",
		       left);
	else if (ctx->acl_watched)
		pr_dbg(&ctx->lh, "Upstream pool servers: all connection references dropped");
	ctx->acl = NULL;
	ctx->acl_watched = false;
	gwp_acl_files_free(ctx->acl_files, ctx->nr_acl_files);
	ctx->acl_files = NULL;
	ctx->nr_acl_files = 0;
}

/*
 * --max-conns-per-ip: the count of client connections per address, shared by
 * every worker. Left NULL without a cap, which is what the accept paths test.
 */
static int gwp_ctx_init_iplim(struct gwp_ctx *ctx)
{
	int max = ctx->cfg.max_conns_per_ip;

	ctx->iplim = NULL;
	if (max <= 0)
		return 0;

	ctx->iplim = gwp_iplim_create((uint32_t)max);
	if (!ctx->iplim) {
		pr_err(&ctx->lh, "Failed to allocate the --max-conns-per-ip table");
		return -ENOMEM;
	}
	pr_info(&ctx->lh, "Allowing at most %d connections per client IPv4 address or IPv6 /64",
		max);
	return 0;
}

static void gwp_ctx_free_iplim(struct gwp_ctx *ctx)
{
	gwp_iplim_destroy(ctx->iplim);
	ctx->iplim = NULL;
}

/*
 * Count a client just accepted from @addr against --max-conns-per-ip, before
 * anything is read from it or set up for it. Returns false when it is over
 * the cap (logged at most once a second per address, so a flood of them
 * cannot flood the log) or cannot be counted, and must be closed; true when
 * it was counted, and its pair must then carry GWP_CONN_FLAG_IPLIM. Only
 * called with a cap (gwp_ctx::iplim set).
 */
bool gwp_ctx_iplim_get(struct gwp_wrk *w, const struct gwp_sockaddr *addr)
{
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_iplim_key key;
	uint32_t quiet = 0;
	int r;

	gwp_iplim_key(addr, &key);
	r = gwp_iplim_get(ctx->iplim, &key, w->now, &quiet);
	if (likely(r == GWP_IPLIM_ADMIT))
		return true;

	if (r == GWP_IPLIM_REFUSE_LOG) {
		const char *grp = addr->sa.sa_family == AF_INET6 &&
			!IN6_IS_ADDR_V4MAPPED(&addr->i6.sin6_addr) ?
			"/64" : "address";

		if (quiet)
			pr_warn(&ctx->lh, "Refused client %s: its %s is at the --max-conns-per-ip limit of %d (and %u more refused since the last such line)",
				ip_to_str(addr), grp,
				ctx->cfg.max_conns_per_ip, quiet);
		else
			pr_warn(&ctx->lh, "Refused client %s: its %s is at the --max-conns-per-ip limit of %d",
				ip_to_str(addr), grp,
				ctx->cfg.max_conns_per_ip);
	} else if (r < 0) {
		pr_err(&ctx->lh, "Refused client %s: no memory to count its connections",
		       ip_to_str(addr));
	}
	return false;
}

/* Uncount a client gwp_ctx_iplim_get() admitted. */
void gwp_ctx_iplim_put(struct gwp_ctx *ctx, const struct gwp_sockaddr *addr)
{
	struct gwp_iplim_key key;

	gwp_iplim_key(addr, &key);
	gwp_iplim_put(ctx->iplim, &key);
}

/*
 * Evaluate the ACL OUTPUT chain for a connection's resolved TCP target. Returns
 * true when the connection is allowed. With no ACL loaded, or when the target
 * has no locally-resolved IP (e.g. a socks5h remote-DNS upstream, where only a
 * domain is known), it is allowed here; domain-based rules are applied
 * separately once wired in.
 */
/* Host-order port of a sockaddr, regardless of family. */
static uint16_t sa_port_h(const struct gwp_sockaddr *s)
{
	return ntohs(s->sa.sa_family == AF_INET ? s->i4.sin_port
						: s->i6.sin6_port);
}

static int upstream_dst_from_sockaddr(const struct gwp_sockaddr *sa,
				      struct gwp_socks5_addr *out);
static int upstream_target_init(struct gwp_ctx *ctx);
static int parse_port(const char *s, uint16_t *port);

/*
 * Fill the inputs of an OUTPUT request for @target (NULL when only a domain is
 * known) from @client, with the optional requested @domain / @user. Only the
 * inputs: gwp_acl_eval_output() resets the output flags itself, and the
 * output payloads are only read behind those flags, so zeroing the whole
 * request first would be done twice.
 */
static void acl_out_req(struct gwp_acl_req *req,
			const struct gwp_sockaddr *client,
			const struct gwp_sockaddr *target,
			const char *domain, const char *user,
			enum gwp_acl_proto proto)
{
	req->memo = NULL;
	req->client = client;
	req->target = target;
	req->domain = domain;
	req->user = user;
	req->proto = proto;
	req->dport = target ? sa_port_h(target) : 0;
	req->sport = client ? sa_port_h(client) : 0;
}

/*
 * Evaluate the ACL OUTPUT chain for a connection to @target from @client (with
 * an optional requested @domain / @user). Returns the verdict; allows (with no
 * eval) when there is no ACL, or nothing to match on. When a matching -j DNAT
 * rule produced a concrete address, the rewritten destination is written back
 * to *@target (for the direct connection and, via the caller, the upstream)
 * and *@dnat_out (when non-NULL) is set true. A port-only -j DNAT of a request
 * that only has a domain has no address to write there: *@dnat_port_out (when
 * non-NULL) gets the new port instead, 0 for none. Composable -j MARK / -j BIND
 * modifiers are surfaced in *@so_out. @memo (may be NULL) carries the
 * -m domain/-m user results between evaluations of the same request.
 */
static enum gwp_acl_verdict acl_out(struct gwp_ctx *ctx,
				    const struct gwp_sockaddr *client,
				    struct gwp_sockaddr *target, uint16_t dport,
				    const char *domain, const char *user,
				    struct gwp_acl_memo *memo,
				    struct gwp_conn_sockopt *so_out,
				    bool *dnat_out, uint16_t *dnat_port_out,
				    enum gwp_acl_proto proto)
{
	int fam = target ? target->sa.sa_family : 0;
	bool have_ip = (fam == AF_INET || fam == AF_INET6);
	enum gwp_acl_verdict v;
	struct gwp_acl_req req;

	if (so_out)
		memset(so_out, 0, sizeof(*so_out));
	if (dnat_out)
		*dnat_out = false;
	if (dnat_port_out)
		*dnat_port_out = 0;

	if (!ctx->acl)
		return GWP_ACL_ACCEPT;
	/* A domain-only request (remote-DNS upstream) still matches -m domain. */
	if (!have_ip && !domain)
		return GWP_ACL_ACCEPT;

	acl_out_req(&req, client, have_ip ? target : NULL, domain, user, proto);
	if (!have_ip)
		req.dport = dport;
	req.memo = memo;
	v = gwp_acl_eval_output(ctx->acl, &req);
	/* The -j UPSTREAM choice is not used yet; give its pool back. */
	gwp_acl_req_release(&req);
	if (v != GWP_ACL_ACCEPT)
		return v;

	/*
	 * Apply a matched DNAT when it produced a concrete address, rewriting
	 * the destination for both the direct path (*target) and, via the
	 * caller, the upstream destination. A port-only DNAT with no base IP
	 * (e.g. a socks5h domain request) yields no address, just the port.
	 */
	if (req.dnat_applied && req.dnat.sa.sa_family) {
		if (have_ip)
			pr_info(&ctx->lh, "ACL DNAT %s -> %s",
				ip_to_str(target), ip_to_str(&req.dnat));
		else
			pr_info(&ctx->lh, "ACL DNAT %s -> %s",
				domain ? domain : "?", ip_to_str(&req.dnat));
		*target = req.dnat;
		if (dnat_out)
			*dnat_out = true;
	} else if (req.dnat_applied && req.dnat_port && dnat_port_out) {
		pr_info(&ctx->lh, "ACL DNAT %s -> port %u",
			domain ? domain : "?", req.dnat_port);
		*dnat_port_out = req.dnat_port;
	}
	/* Surface composable -j MARK / -j BIND to the socket-creation path. */
	if (so_out && req.mark_set) {
		so_out->mark_set = true;
		so_out->mark = req.mark;
	}
	if (so_out && req.bind.set)
		so_out->bind = req.bind;
	return v;
}

/* Verdict + DNAT rewrite of *@target, for the accept-time plain/transparent
 * forwarding path (which has no gwp_conn_pair yet, hence no username). */
bool gwp_ctx_acl_output_dnat(struct gwp_ctx *ctx,
			     const struct gwp_sockaddr *client,
			     struct gwp_sockaddr *target,
			     struct gwp_conn_sockopt *so,
			     enum gwp_acl_proto proto)
{
	return acl_out(ctx, client, target, 0, NULL, NULL, NULL, so, NULL, NULL,
		       proto) == GWP_ACL_ACCEPT;
}

/* The authenticated username for an ACL "-m user" match, or NULL when the
 * connection carried no proxy authentication. */
static const char *gcp_req_user(const struct gwp_conn_pair *gcp)
{
	if (gcp->prot_type == GWP_PROT_TYPE_SOCKS5 && gcp->s5_conn)
		return gwp_socks5_conn_username(gcp->s5_conn);
	if (gcp->prot_type == GWP_PROT_TYPE_HTTP && gcp->http_conn)
		return gwp_http_conn_username(gcp->http_conn);
	return NULL;
}

/*
 * OUTPUT verdict for a UDP ASSOCIATE datagram to @target. Only the verdict
 * applies to UDP (no DNAT, MARK or BIND), and every input but the target is
 * fixed for the association (pinned peer, username), so the last target's
 * verdict is reused while the target and the ruleset generation stay the
 * same: a client streaming to one peer costs one evaluation, not one per
 * datagram. A chain with a -m statistic rule is evaluated every time, as its
 * answer changes per evaluation.
 */
static bool udp_target_allowed(struct gwp_ctx *ctx, struct gwp_conn_pair *gcp,
			       const struct gwp_sockaddr *target)
{
	struct gwp_udp_acl_cache *c = &gcp->udp_acl;
	struct gwp_acl_req req;
	bool ok;

	if (!ctx->acl)
		return true;
	if (c->valid && c->gen == gwp_acl_generation(ctx->acl) &&
	    gwp_sockaddr_eq(&c->dst, target))
		return c->ok;

	acl_out_req(&req, &gcp->udp_peer, target, NULL, gcp_req_user(gcp),
		    GWP_ACL_PROTO_UDP);
	ok = gwp_acl_eval_output(ctx->acl, &req) == GWP_ACL_ACCEPT;
	/* UDP is relayed direct: -j UPSTREAM does not apply to it. */
	gwp_acl_req_release(&req);

	c->valid = req.cacheable;
	c->gen = req.gen;
	c->dst = *target;
	c->ok = ok;
	return ok;
}

/*
 * A UDP association relays replies only from targets its client has sent to,
 * so a host that learns the relay port cannot inject datagrams the client
 * never asked for. Each target goes into gcp->udp_peers once a datagram to
 * it passes the OUTPUT chain, tagged with the ruleset generation of that
 * verdict. Matching is by exact address and port, as a UDP "connection" is.
 */
static int udp_peer_find(const struct gwp_udp_peers *p,
			 const struct gwp_sockaddr *a)
{
	uint8_t i;

	/* Most associations talk to one target: try the last hit first. */
	if (p->last < p->nr && gwp_sockaddr_eq(&p->addr[p->last], a))
		return p->last;
	for (i = 0; i < p->nr; i++) {
		if (gwp_sockaddr_eq(&p->addr[i], a))
			return i;
	}
	return -1;
}

/*
 * The address a reply to a datagram sent to @a comes from. A datagram to the
 * unspecified address (0.0.0.0 or ::) goes to the local host over loopback,
 * so its answer comes from 127.0.0.1 or ::1. (Replies to a broadcast or
 * multicast send come from unicast addresses and are not recognised.)
 */
static void udp_peer_canon(struct gwp_sockaddr *a)
{
	static const uint8_t v4_lo[4] = { 127, 0, 0, 1 };
	static const uint8_t v4_any[4];
	uint8_t *b = a->i6.sin6_addr.s6_addr;

	if (a->sa.sa_family == AF_INET) {
		if (a->i4.sin_addr.s_addr == htonl(INADDR_ANY))
			a->i4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		return;
	}
	if (IN6_IS_ADDR_UNSPECIFIED(&a->i6.sin6_addr))
		a->i6.sin6_addr = in6addr_loopback;
	else if (IN6_IS_ADDR_V4MAPPED(&a->i6.sin6_addr) &&
		 !memcmp(b + 12, v4_any, 4))
		memcpy(b + 12, v4_lo, 4);
}

/* Record that the client sent to @dst, accepted at ACL generation @gen. */
static bool udp_peer_note(struct gwp_conn_pair *gcp,
			  const struct gwp_sockaddr *dst, uint32_t gen)
{
	struct gwp_udp_peers *p = gcp->udp_peers;
	struct gwp_sockaddr ca = *dst, *a = &ca;
	uint32_t age, oldest = 0;
	uint8_t j;
	int i;

	udp_peer_canon(a);
	if (unlikely(!p)) {
		p = calloc(1, sizeof(*p));
		if (unlikely(!p))
			return false;
		gcp->udp_peers = p;
	}

	i = udp_peer_find(p, a);
	if (i < 0) {
		if (p->nr < GWP_UDP_MAX_PEERS) {
			i = p->nr++;
		} else {
			/* Full: reuse the least recently sent-to entry. */
			for (i = 0, j = 0; j < p->nr; j++) {
				age = p->next_seq - p->seq[j];
				if (age > oldest) {
					oldest = age;
					i = j;
				}
			}
		}
		p->addr[i] = *a;
	}
	p->gen[i] = gen;
	p->seq[i] = p->next_seq++;
	p->last = (uint8_t)i;
	return true;
}

/*
 * May a datagram from @src be relayed to the client as a target's reply?
 * Only if the client sent to @src, and the ACL still lets it do so: after a
 * reload the OUTPUT verdict for @src is checked again (through the same
 * per-association cache as the client's datagrams) before its replies flow.
 */
static bool udp_reply_allowed(struct gwp_ctx *ctx, struct gwp_conn_pair *gcp,
			      const struct gwp_sockaddr *src)
{
	struct gwp_udp_peers *p = gcp->udp_peers;
	int i;

	if (!p)
		return false;
	i = udp_peer_find(p, src);
	if (i < 0)
		return false;
	p->last = (uint8_t)i;
	if (ctx->acl && p->gen[i] != gwp_acl_generation(ctx->acl)) {
		if (!udp_target_allowed(ctx, gcp, src)) {
			/* Denied now: forget it until the client is let through. */
			p->addr[i] = p->addr[p->nr - 1];
			p->gen[i] = p->gen[p->nr - 1];
			p->seq[i] = p->seq[p->nr - 1];
			p->nr--;
			return false;
		}
		p->gen[i] = gcp->udp_acl.gen;
	}
	return true;
}

/*
 * Name the server @up for a log line: the @idx-th (from 0) of @pool, or the
 * default upstream (no @pool). An address, never a URL: it may hold a
 * password.
 */
static const char *up_desc(const struct gwp_acl_pool *pool, uint32_t idx,
			   struct gwp_upstream *up, char *buf, size_t size)
{
	if (pool)
		snprintf(buf, size, "pool %s server %u (%s)",
			 gwp_acl_pool_name(pool), idx + 1, ip_to_str(&up->addr));
	else
		snprintf(buf, size, "default upstream (%s)",
			 ip_to_str(&up->addr));
	return buf;
}

/* Log that @up, the @idx-th server of @pool (or the default), is back. */
static void up_back(struct gwp_ctx *ctx, const struct gwp_acl_pool *pool,
		    uint32_t idx, struct gwp_upstream *up)
{
	char desc[320];

	pr_info(&ctx->lh, "Upstream %s is back in service after its ejection",
		up_desc(pool, idx, up, desc, sizeof(desc)));
}

/*
 * How many milliseconds the ejection of @up (the @idx-th server of @pool,
 * or the default upstream) still runs, 0 while it is in service. Reads the
 * clock into *@now only when it may be ejected and *@now is still 0; the
 * health state takes it truncated to 32 bits. The caller that sees
 * an ejection run out logs the server's return, once per ejection however
 * many pools list the server.
 */
static uint32_t up_ejected(struct gwp_ctx *ctx, const struct gwp_acl_pool *pool,
			   uint32_t idx, struct gwp_upstream *up, uint64_t *now)
{
	uint32_t left;
	bool back;

	if (!gwp_up_health_may_be_ejected(up->health))
		return 0;
	if (!*now)
		*now = gwp_now_ms();
	left = gwp_up_health_ejected(up->health, (uint32_t)*now, &back);
	if (back)
		up_back(ctx, pool, idx, up);
	return left;
}

/* What pool_pick_server()'s callbacks need. */
struct pool_pick_env {
	struct gwp_ctx		*ctx;
	struct gwp_acl_pool	*pool;
};

static uint32_t pool_pick_now(void __unused *arg)
{
	return (uint32_t)gwp_now_ms();
}

/*
 * Round-robin's probes (gwp_up_pick::random): a generator per thread, so
 * no lock and no shared line; seeded on its first use, the only time it
 * may make a syscall, from getrandom() or else the clock and the thread's
 * own address. Not secret: it only spreads an ejected server's turns.
 */
static __thread uint32_t pool_pick_rnd;

static uint32_t pool_pick_random(void __unused *arg)
{
	if (unlikely(!pool_pick_rnd)) {
		struct timespec ts;
		uint32_t seed = 0;

#ifdef CONFIG_HAVE_GETRANDOM
		if (getrandom(&seed, sizeof(seed), GRND_NONBLOCK) !=
		    (ssize_t)sizeof(seed))
			seed = 0;
#endif
		if (!seed) {
			clock_gettime(CLOCK_MONOTONIC, &ts);
			seed = (uint32_t)ts.tv_nsec ^ (uint32_t)ts.tv_sec;
			seed ^= (uint32_t)(uintptr_t)&pool_pick_rnd * 2654435761u;
		}
		pool_pick_rnd = seed ? seed : 1;
	}
	return gwp_up_rand(&pool_pick_rnd);
}

static void pool_pick_back(void *arg, uint32_t i)
{
	struct pool_pick_env *env = arg;
	struct gwp_upstream *up = gwp_acl_pool_server(env->pool, i);

	if (up)
		up_back(env->ctx, env->pool, i, up);
}

/*
 * Which of @pool's servers (from 0) a pair goes to, by the pool's method:
 * round-robin, the default, takes them in turn; least_conn the one with
 * the fewest open pairs, ties in round-robin order. Both turn on the
 * pool's cursor, shared by all workers, and least_conn reads the counts
 * all workers keep (struct gwp_up_state), which carry across reloads.
 * Workers picking at the same time may see the same counts and choose the
 * same server; the next picks see the result, which is close enough.
 *
 * Only servers in service are taken; with all of them ejected, the one
 * back soonest. With @skip, the server of @skip's place whose attempt
 * failed, it is a retry: another server in service, the next one after
 * @skip in pool order (least_conn: the fewest open, ties from there), or
 * UINT32_MAX for none; a retry leaves the cursor alone, so the pool's
 * turns go on as if the failed pick had worked.
 *
 * The pick reads the states in place, through the pool's members (see
 * acl_srv_member()), with no copy: round-robin looks at the cursor's
 * server, and only when it is ejected at a few random ones and then the
 * next ones in turn; least_conn scans
 * the open counts of the whole pool (see gwp_up_lb_pick()). UINT32_MAX,
 * when the pool has no server object at all, is a bug conn_pick_upstream()
 * reports.
 */
static uint32_t pool_pick_server(struct gwp_ctx *ctx, struct gwp_acl_pool *pool,
				 uint32_t skip)
{
	struct pool_pick_env env = { .ctx = ctx, .pool = pool };
	struct gwp_up_pick pk = {
		.m = gwp_acl_pool_members(pool),
		.nr = gwp_acl_pool_nr_servers(pool),
		.least_conn = gwp_acl_pool_method(pool) ==
			      GWP_ACL_POOL_LEAST_CONN,
		.skip = skip,
		.now = pool_pick_now,
		.back = pool_pick_back,
		.random = pool_pick_random,
		.arg = &env,
	};

	if (unlikely(!pk.m))
		return UINT32_MAX;
	if (skip == UINT32_MAX)
		pk.rr = gwp_acl_pool_next(pool);
	return gwp_up_lb_pick(&pk);
}

/* Every place in a pool fits gwp_conn_pair::up_srv. */
_Static_assert(GWP_ACL_POOL_MAX_SERVERS - 1 <= UINT16_MAX,
	       "gwp_conn_pair::up_srv cannot hold a pool server's place");

/*
 * Decide, once per pair and before its target's name is resolved, which
 * upstream @gcp goes through: the one an ACL -j UPSTREAM rule picks for
 * what the client asked for -- the name @domain, the address @lit (either
 * may be NULL) and port @port -- or else the default (--upstream-proxy, or
 * none). With neither @domain nor @lit there is no target at all (a UDP
 * ASSOCIATE), and a rule that tests one is not taken. Later calls change
 * nothing. Returns 0, or -EACCES when the choice cannot be told and might
 * be a pool (see gwp_acl_eval_upstream()), -EINVAL when the pool picked has
 * no server to use: the pair must then not go anywhere.
 */
static int conn_pick_upstream(struct gwp_ctx *ctx, struct gwp_conn_pair *gcp,
			      const char *domain,
			      const struct gwp_sockaddr *lit, uint16_t port)
{
	struct gwp_upstream *up;
	struct gwp_acl_req req;
	uint32_t i;
	int r = 0;

	if (gcp->flags & GWP_CONN_FLAG_UP_PICKED)
		return 0;
	gcp->flags |= GWP_CONN_FLAG_UP_PICKED;
	if (!ctx->acl)
		return 0;

	acl_out_req(&req, &gcp->client_addr, lit, domain, gcp_req_user(gcp),
		    GWP_ACL_PROTO_TCP);
	if (!lit)
		req.dport = port;
	req.memo = NULL;
	req.no_target = !domain && !lit;
	switch (gwp_acl_eval_upstream(ctx->acl, &req)) {
	case GWP_ACL_UPSTREAM_POOL:
		/*
		 * The pool holds its servers, so the one picked is there; the
		 * pair takes its own reference, and the pool's goes with @req.
		 */
		i = pool_pick_server(ctx, req.upstream_pool, UINT32_MAX);
		up = gwp_acl_pool_server(req.upstream_pool, i);
		if (unlikely(!up)) {
			/* Never past the pool: refuse, not the default. */
			pr_err(&ctx->lh, "BUG: upstream pool %s has no server object (idx=%u)",
			       gwp_acl_pool_name(req.upstream_pool), gcp->idx);
			r = -EINVAL;
			break;
		}
		gwp_conn_set_upstream(ctx, gcp, up);
		/* Kept for the logs and the retry, until the tunnel is up. */
		gcp->up_pool = gwp_acl_req_take_pool(&req);
		gcp->up_srv = (uint16_t)i;
		pr_dbg(&ctx->lh, "Upstream for idx=%u: pool %s server %u, %s (%s), %u open",
		       gcp->idx, gwp_acl_pool_name(gcp->up_pool), i + 1,
		       ip_to_str(&up->addr), up->host,
		       gwp_up_state_open(up->state));
		if (gwp_up_health_may_be_ejected(up->health))
			pr_dbg(&ctx->lh, "Upstream pool %s has every server ejected; idx=%u takes server %u, back soonest",
			       gwp_acl_pool_name(gcp->up_pool), gcp->idx, i + 1);
		break;
	case GWP_ACL_UPSTREAM_DIRECT:
		gwp_conn_set_upstream(ctx, gcp, NULL);
		pr_dbg(&ctx->lh, "Upstream for idx=%u: none (DIRECT)", gcp->idx);
		break;
	case GWP_ACL_UPSTREAM_UNSURE:
		/* It may be a pool: neither the default nor DIRECT will do. */
		pr_info(&ctx->lh, "Upstream for idx=%u cannot be decided by the ACL; refusing it",
			gcp->idx);
		r = -EACCES;
		break;
	case GWP_ACL_UPSTREAM_NONE:
		break;
	}
	gwp_acl_req_release(&req);
	return r;
}

bool gwp_ctx_acl_target_allowed(struct gwp_ctx *ctx, struct gwp_conn_pair *gcp)
{
	uint16_t dport = 0, dnat_port = 0;
	bool dnat = false;
	enum gwp_acl_verdict v;

	/*
	 * Plain and transparent forwarding pick their upstream on the first
	 * evaluation, the one for the target as configured or redirected:
	 * a --target name as written, else the address.
	 */
	if (!ctx->cfg.as_socks5 && !ctx->cfg.as_http) {
		int r;

		if (ctx->target_name.ver)
			r = conn_pick_upstream(ctx, gcp,
					       ctx->target_name.domain.str,
					       NULL, ntohs(ctx->target_name.port));
		else
			r = conn_pick_upstream(ctx, gcp, NULL, &gcp->target_addr,
					       sa_port_h(&gcp->target_addr));
		if (unlikely(r))
			return false;
	}

	/*
	 * Plain forwarding to a --target name: a pair whose upstream resolves
	 * names asks it for that name, and it is what the ACL judges. Set it
	 * each time, since a connect retried for want of a descriptor must be
	 * judged afresh, not as an earlier DNAT left it. Any other pair goes
	 * to the address the name resolved to at startup, which there is none
	 * of when --upstream-proxy resolves names remotely.
	 */
	if (ctx->target_name.ver) {
		if (gcp->upstream && gcp->upstream->remote_dns) {
			gcp->up_dst = ctx->target_name;
			gcp->req_domain = ctx->target_name.domain.str;
			memset(&gcp->target_addr, 0, sizeof(gcp->target_addr));
		} else if (!gcp->target_addr.sa.sa_family) {
			pr_warn(&ctx->lh, "--target %s was left for --upstream-proxy to resolve, so it has no address to go to without it (idx=%u)",
				ctx->target_name.domain.str, gcp->idx);
			return false;
		}
	}

	/*
	 * Only a walk over several candidates evaluates the same domain and
	 * user more than once; gwp_conn_set_candidates() resets the memo for
	 * each new list.
	 */
	/* A domain-only request still has the port it asked for. */
	if (gcp->up_dst.ver == GWP_SOCKS5_ATYP_DOMAIN)
		dport = ntohs(gcp->up_dst.port);
	v = acl_out(ctx, &gcp->client_addr, &gcp->target_addr, dport,
		    gcp->req_domain, gcp_req_user(gcp),
		    gcp->nr_cand > 1 ? &gcp->acl_memo : NULL,
		    &gcp->acl_sockopt, &dnat, &dnat_port, GWP_ACL_PROTO_TCP);
	if (v != GWP_ACL_ACCEPT)
		return false;

	/* The hostname stays for the upstream to resolve, on the new port. */
	if (dnat_port && gcp->up_dst.ver == GWP_SOCKS5_ATYP_DOMAIN)
		gcp->up_dst.port = htons(dnat_port);

	/*
	 * When chaining to an upstream by remote DNS (socks5h), up_dst carries
	 * the requested hostname. A DNAT has rewritten target_addr to a concrete
	 * IP, so push that into up_dst too, making the upstream connect to the
	 * DNAT target instead of resolving the original name. For socks5:// the
	 * up_dst is still unset here (ver == 0) and is finalised from the
	 * (already rewritten) target_addr after the upstream connects.
	 */
	if (dnat && gcp->upstream && gcp->up_dst.ver != 0) {
		__be16 orig_port = gcp->up_dst.port;

		upstream_dst_from_sockaddr(&gcp->target_addr, &gcp->up_dst);
		/*
		 * An address-only DNAT (--to <ip> with no port) has no port to
		 * apply for a domain request (the target IP was unknown at eval
		 * time), so target_addr carries port 0. Keep the client's
		 * original requested port instead of connecting to :0.
		 */
		if (gcp->up_dst.port == 0)
			gcp->up_dst.port = orig_port;
	}

	return true;
}

/*
 * Evaluate the ACL INPUT chain for an incoming client. Returns true when the
 * client is allowed (always so when no ACL is loaded). @proto distinguishes the
 * client's TCP control connection (accept time) from a UDP association it later
 * requests.
 */
bool gwp_ctx_acl_client_allowed(struct gwp_ctx *ctx,
				const struct gwp_sockaddr *client,
				enum gwp_acl_proto proto)
{
	struct gwp_acl_req req;

	if (!ctx->acl)
		return true;

	memset(&req, 0, sizeof(req));
	req.client = client;
	req.proto = proto;
	req.sport = sa_port_h(client);
	return gwp_acl_eval_input(ctx->acl, &req) == GWP_ACL_ACCEPT;
}

static int gwp_ctx_init_socks5(struct gwp_ctx *ctx)
{
	struct gwp_socks5_cfg s5cfg;
	int r;

	pr_dbg(&ctx->lh, "Initializing SOCKS5 context");
	memset(&s5cfg, 0, sizeof(s5cfg));
	s5cfg.auth = ctx->auth;
	s5cfg.udp_associate = ctx->cfg.udp_associate;
	r = gwp_socks5_ctx_init(&ctx->socks5, &s5cfg);
	if (r < 0) {
		pr_err(&ctx->lh, "Failed to initialize SOCKS5 context: %s",
			strerror(-r));
		return r;
	}

	return 0;
}

static void gwp_ctx_free_socks5(struct gwp_ctx *ctx)
{
	assert(ctx->cfg.as_socks5);
	gwp_socks5_ctx_free(ctx->socks5);
	ctx->socks5 = NULL;
	pr_dbg(&ctx->lh, "SOCKS5 context freed");
}

/*
 * The DNS resolution type implied by the configuration. --outgoing-family wins
 * over --prefer-ipv6: the former is a hard restriction, the latter only a
 * preference, and the two are rejected together at startup anyway.
 */
static uint32_t cfg_dns_restyp(const struct gwp_cfg *cfg)
{
	switch (cfg->outgoing_family) {
	case GWP_OUT_FAMILY_IPV4:
		return GWP_DNS_RESTYP_IPV4_ONLY;
	case GWP_OUT_FAMILY_IPV6:
		return GWP_DNS_RESTYP_IPV6_ONLY;
	default:
		return cfg->prefer_ipv6 ? GWP_DNS_RESTYP_PREFER_IPV6 :
					  GWP_DNS_RESTYP_PREFER_IPV4;
	}
}

static int gwp_ctx_init_dns(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;
	const struct gwp_dns_cfg dns_cfg = {
		.cache_expiry = cfg->dns_cache_secs,
		.max_entries = cfg->dns_cache_max_entries > 0 ?
			       (uint32_t)cfg->dns_cache_max_entries : 0,
		.restyp = cfg_dns_restyp(cfg),
		.nr_workers = cfg->nr_dns_workers,
		.nr_cqs = (uint32_t)cfg->nr_workers
	};
	int r;

	if ((!cfg->as_socks5 && !cfg->as_http) || cfg->use_raw_dns) {
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
	int r;

	ctx->socks5 = NULL;
	ctx->auth = NULL;

	/*
	 * SOCKS5 and HTTP may run together on the same port: the connection
	 * protocol handler tries SOCKS5 first and falls back to HTTP (see
	 * gwp_handle_conn_state_prot()). Authentication credentials are shared
	 * between the two, so the store is set up here (once) whenever a proxy
	 * front-end is enabled; HTTP per-connection state is allocated lazily.
	 */
	if (!cfg->as_socks5 && !cfg->as_http)
		return 0;

	r = gwp_ctx_init_auth(ctx);
	if (r < 0)
		return r;

	if (cfg->as_socks5) {
		r = gwp_ctx_init_socks5(ctx);
		if (r < 0) {
			gwp_ctx_free_auth(ctx);
			return r;
		}
	}

	return 0;
}

__cold
static void gwp_ctx_free_prot(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;

	if (cfg->as_socks5)
		gwp_ctx_free_socks5(ctx);

	if (cfg->as_socks5 || cfg->as_http)
		gwp_ctx_free_auth(ctx);
}

/*
 * Is the host of @up, as its URL names it, worth resolving? An address literal
 * is (gwp_upstream_url_host() has set @host_is_ip), and so is a DNS name:
 * labels of 1 to 63 letters, digits, '-' and '_', none at either end of a
 * label with a '-', and one trailing dot, which is dropped. A name of digits
 * and dots only is an IPv4 address in one of the forms inet_aton() takes
 * ("127.1" too, which resolved before this check), and is then rewritten
 * in the usual dotted form; one that does not parse, such as "999.999.1.1",
 * is refused, where a resolver would look it up as a name.
 */
static bool upstream_host_ok(struct gwp_upstream *up)
{
	char c, prev = '.', *host = up->host;
	size_t n = strlen(host), label = 0, i;
	struct in_addr a4;

	if (up->host_is_ip)
		return true;
	if (n > 1 && host[n - 1] == '.')
		host[--n] = '\0';
	if (!n || n > 253)
		return false;

	if (strspn(host, "0123456789.") == n) {
		if (!inet_aton(host, &a4) ||
		    !inet_ntop(AF_INET, &a4, host, sizeof(up->host)))
			return false;
		up->host_is_ip = true;
		return true;
	}

	for (i = 0; (c = host[i]); i++) {
		if (c == '.') {
			if (!label || prev == '-')
				return false;
			label = 0;
		} else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			   (c >= '0' && c <= '9') || c == '_' ||
			   (c == '-' && label)) {
			label++;
		} else {
			return false;
		}
		if (label > 63)
			return false;
		prev = c;
	}

	return label && prev != '-';
}

/*
 * Parse a --upstream-proxy URL of the form:
 *
 *    socks5://[user:pass@]host:port     (gwproxy resolves the target)
 *    socks5h://[user:pass@]host:port    (the upstream proxy resolves it)
 *    http://[user:pass@]host:port       (HTTP CONNECT, cleartext to the proxy)
 *    https://[user:pass@]host:port      (HTTP CONNECT, TLS to the proxy)
 *
 * The port is optional and defaults to 1080 for socks5 and 8080 for http.
 * Returns 0, -EINVAL for a URL that is not one of those, or -EHOSTUNREACH
 * when its host name does not resolve.
 */
__cold
int gwp_parse_upstream(const char *url, struct gwp_upstream *up)
{
	char buf[512], *at, *host;
	const char *rest;
	uint16_t def_port;
	bool has_port;
	size_t n;

	memset(up, 0, sizeof(*up));

	if (!strncmp(url, "socks5h://", 10)) {
		up->type = GWP_UPSTREAM_SOCKS5;
		up->remote_dns = true;
		rest = url + 10;
		def_port = 1080;
	} else if (!strncmp(url, "socks5://", 9)) {
		up->type = GWP_UPSTREAM_SOCKS5;
		up->remote_dns = false;
		rest = url + 9;
		def_port = 1080;
	} else if (!strncmp(url, "https://", 8)) {
		up->type = GWP_UPSTREAM_HTTP;
		up->use_tls = true;
		up->remote_dns = true;	/* the HTTP proxy resolves the CONNECT host */
		rest = url + 8;
		def_port = 8080;
	} else if (!strncmp(url, "http://", 7)) {
		up->type = GWP_UPSTREAM_HTTP;
		up->remote_dns = true;
		rest = url + 7;
		def_port = 8080;
	} else {
		return -EINVAL;
	}

	n = strlen(rest);
	if (n == 0 || n >= sizeof(buf))
		return -EINVAL;
	memcpy(buf, rest, n + 1);

	/* Optional "user:pass@" credentials; split at the last '@'. */
	at = strrchr(buf, '@');
	if (at) {
		char *creds = buf, *pass;
		size_t ul, pl;

		*at = '\0';
		host = at + 1;

		pass = strchr(creds, ':');
		if (pass)
			*pass++ = '\0';

		ul = strlen(creds);
		pl = pass ? strlen(pass) : 0;
		if (ul == 0 || ul > 255 || pl > 255)
			return -EINVAL;

		up->has_auth = true;
		up->ulen = (uint8_t)ul;
		up->plen = (uint8_t)pl;
		memcpy(up->user, creds, ul + 1);
		if (pass)
			memcpy(up->pass, pass, pl + 1);
	} else {
		host = buf;
	}

	if (gwp_upstream_url_host(host, up->host, sizeof(up->host),
				  &up->host_is_ip) ||
	    !upstream_host_ok(up))
		return -EINVAL;

	/*
	 * convert_str_to_ssaddr() ignores an explicit port in the string when
	 * a non-zero default_port is passed, so only pass the default when the
	 * host has no port of its own.
	 */
	if (host[0] == '[') {
		char *rb = strchr(host, ']');
		has_port = rb && rb[1] == ':';
	} else {
		has_port = strchr(host, ':') != NULL;
	}

	if (convert_str_to_ssaddr(host, &up->addr, has_port ? 0 : def_port))
		return up->host_is_ip ? -EINVAL : -EHOSTUNREACH;
	return 0;
}

/*
 * Read the upstream proxy credentials for --upstream-proxy-auth-file: the
 * first line of @path, "user:pass" or a bare "user", split at the first ':'
 * and with the same limits as in the URL (user 1..255 bytes, password up to
 * 255). Unlike the URL, which sits in argv where every local user can read
 * it, the file can be kept private, and the password may contain any byte
 * but NUL, CR and LF ('@' and ':' included). Read with read(2) rather than
 * stdio, so no buffer outside this function ever holds the password.
 */
__cold
static int upstream_read_auth(const char *path, struct gwp_upstream *up)
{
	/* "user:pass", CRLF, and one byte more to tell an overlong line. */
	char buf[255 + 1 + 255 + 3], *line_end, *colon;
	size_t n = 0, len, ul, pl;
	ssize_t rd;
	int fd, r = -EINVAL;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	while (n < sizeof(buf)) {
		rd = read(fd, buf + n, sizeof(buf) - n);
		if (rd < 0) {
			if (errno == EINTR)
				continue;
			r = -errno;
			goto out;
		}
		if (!rd)
			break;
		n += (size_t)rd;
	}

	line_end = memchr(buf, '\n', n);
	if (!line_end && n == sizeof(buf))
		goto out;
	len = line_end ? (size_t)(line_end - buf) : n;
	if (len && buf[len - 1] == '\r')
		len--;
	if (!len || memchr(buf, '\0', len) || memchr(buf, '\r', len))
		goto out;

	colon = memchr(buf, ':', len);
	ul = colon ? (size_t)(colon - buf) : len;
	pl = colon ? len - ul - 1 : 0;
	if (ul == 0 || ul > 255 || pl > 255)
		goto out;

	up->has_auth = true;
	up->ulen = (uint8_t)ul;
	up->plen = (uint8_t)pl;
	memcpy(up->user, buf, ul);
	up->user[ul] = '\0';
	if (pl)
		memcpy(up->pass, colon + 1, pl);
	up->pass[pl] = '\0';
	r = 0;
out:
	explicit_bzero(buf, sizeof(buf));
	close(fd);
	return r;
}

/*
 * Turn --bind-source/--bind-iface into the ready-made bind spec the connect
 * path applies when no ACL -j BIND rule claimed the connection. Done once here
 * rather than per connection, and validated here so a typo (a malformed
 * address, an interface name that cannot fit IFNAMSIZ) is a startup error
 * instead of every connection quietly failing later.
 *
 * The interface is not probed against the running system: a device named here
 * may legitimately appear after gwproxy starts (a WireGuard or PPP link), and
 * the strict per-connection bind already fails safe until it does.
 */
__cold
static int gwp_ctx_init_bind_def(struct gwp_ctx *ctx)
{
	struct gwp_acl_bind *b = &ctx->bind_def;
	struct gwp_cfg *cfg = &ctx->cfg;
	size_t l;

	memset(b, 0, sizeof(*b));

	if (cfg->bind_iface) {
		l = strlen(cfg->bind_iface);
		if (!l || l >= sizeof(b->iface)) {
			pr_err(&ctx->lh,
			       "Invalid --bind-iface value '%s': an interface name is 1 to %zu characters",
			       cfg->bind_iface, sizeof(b->iface) - 1);
			return -EINVAL;
		}
		memcpy(b->iface, cfg->bind_iface, l + 1);
		b->set = true;
	}

	if (cfg->bind_source) {
		if (gwp_acl_parse_bind_source(cfg->bind_source, &b->src)) {
			pr_err(&ctx->lh,
			       "Invalid --bind-source value '%s': expected an IP literal, optionally 'ip:port' or '[v6]:port'",
			       cfg->bind_source);
			return -EINVAL;
		}
		b->have_src = true;
		b->set = true;
	}

	if (b->set)
		pr_info(&ctx->lh, "Outgoing connections bind to source %s on interface %s by default",
			b->have_src ? ip_to_str(&b->src) : "(any)",
			b->iface[0] ? b->iface : "(any)");

	return 0;
}

#ifdef CONFIG_HTTPS
__cold
static int gwp_ctx_init_tls(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;
	int r;

	ctx->ssl_ctx = NULL;
	if (!cfg->tls_cert)	/* validated: cert and key are both set or both unset */
		return 0;

	r = gwp_ssl_ctx_server_create(&ctx->ssl_ctx, cfg->tls_cert, cfg->tls_key);
	if (r < 0) {
		pr_err(&ctx->lh, "Failed to load TLS cert/key ('%s' / '%s'): %s",
		       cfg->tls_cert, cfg->tls_key, gwp_ssl_errstr());
		return r;
	}

	pr_info(&ctx->lh, "TLS termination enabled on the listener (cert=%s)",
		cfg->tls_cert);
	return 0;
}

__cold
static void gwp_ctx_free_tls(struct gwp_ctx *ctx)
{
	gwp_ssl_ctx_free(ctx->ssl_ctx);
	ctx->ssl_ctx = NULL;
}
#else /* !CONFIG_HTTPS */
static int gwp_ctx_init_tls(struct gwp_ctx *ctx)
{
	ctx->ssl_ctx = NULL;
	return 0;
}

static void gwp_ctx_free_tls(struct gwp_ctx *ctx)
{
	(void)ctx;
}
#endif /* CONFIG_HTTPS */

#ifdef CONFIG_HTTPS
/*
 * The client TLS context of every https:// upstream, the --upstream-proxy
 * one and the servers of ACL upstream pools alike, verifying the proxy's
 * certificate against --upstream-ca-file, or else the system's trust store:
 * one trust store for all. @need says whether one is needed at all.
 *
 * With an ACL file it is always needed: any load, the first or a reload,
 * may bring an https:// pool server. So it is made here, at startup,
 * before the ACL first loads and before any worker runs, and freed only
 * after the workers are gone (gwp_ctx_free_upstream()); every server object
 * a worker can be handed thus finds it in place, with no lazy setup racing
 * the workers. A set with no https:// server pays for one unused SSL_CTX.
 */
__cold
static int upstream_init_tls_ctx(struct gwp_ctx *ctx, bool need)
{
	const char *ca = ctx->cfg.upstream_ca_file;
	int r, fd;

	if (!need) {
		if (ca) {
			pr_err(&ctx->lh, "--upstream-ca-file needs an https:// --upstream-proxy or an --acl-file");
			return -EINVAL;
		}
		return 0;
	}

	/*
	 * OpenSSL only says that it loaded no certificate. Say why, when the
	 * file cannot be read at all.
	 */
	if (ca) {
		fd = open(ca, O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			r = -errno;
			pr_err(&ctx->lh, "Cannot read --upstream-ca-file '%s': %s",
			       ca, strerror(-r));
			return r;
		}
		close(fd);
	}

	r = gwp_ssl_ctx_client_verify_create(&ctx->up_ssl_ctx, ca);
	if (r) {
		if (ca)
			pr_err(&ctx->lh, "No usable CA certificate in --upstream-ca-file '%s': %s",
			       ca, gwp_ssl_errstr());
		else
			pr_err(&ctx->lh, "Cannot set up TLS to the https:// upstream proxy: %s",
			       gwp_ssl_errstr());
		return r;
	}
	return 0;
}

/*
 * Try the host of the https:// upstream @up on a connection of the client
 * context, so a host OpenSSL cannot use (for SNI, say) fails now rather than
 * every connection.
 */
__cold
static int upstream_check_tls_host(struct gwp_ctx *ctx, struct gwp_upstream *up)
{
	struct gwp_ssl *s;
	int r;

	s = gwp_ssl_client_new(ctx->up_ssl_ctx);
	if (!s)
		return -ENOMEM;
	r = gwp_ssl_set_peer_name(s, up->host, up->host_is_ip);
	gwp_ssl_free(s);
	return r;
}

/* Whether ACL upstream pools may hold https:// servers: an ACL file. */
static bool upstream_acl_may_tls(struct gwp_ctx *ctx)
{
	return ctx->cfg.acl_file && *ctx->cfg.acl_file;
}

/*
 * The client TLS context with no --upstream-proxy: for the https:// servers
 * an ACL file's pools may hold.
 */
__cold
static int upstream_init_acl_tls(struct gwp_ctx *ctx)
{
	const char *ca = ctx->cfg.upstream_ca_file;
	int r;

	r = upstream_init_tls_ctx(ctx, upstream_acl_may_tls(ctx));
	if (!r && ctx->up_ssl_ctx)
		pr_dbg(&ctx->lh, "TLS to https:// upstream pool servers: verifying against %s",
		       ca ? ca : "the system's trust store");
	return r;
}

/*
 * An https:// pool server @up, as its pool loads: the context is there
 * (upstream_init_tls_ctx()), and its host must do as a TLS server name.
 */
__cold
static int upstream_acl_srv_tls(struct gwp_ctx *ctx, struct gwp_upstream *up,
				char *why, size_t size)
{
	int r;

	if (!ctx->up_ssl_ctx) {
		snprintf(why, size, "the upstream TLS context is not set up");
		return -EINVAL;
	}
	r = upstream_check_tls_host(ctx, up);
	if (r == -EINVAL)
		snprintf(why, size, "host %s cannot be checked as a TLS server name",
			 up->host);
	return r;
}

/*
 * The --upstream-proxy: its host, and the client TLS context, which an
 * https:// one needs and an ACL file's pools may.
 */
__cold
static int upstream_init_tls(struct gwp_ctx *ctx, struct gwp_upstream *up)
{
	const char *ca = ctx->cfg.upstream_ca_file;
	int r;

	r = upstream_init_tls_ctx(ctx, up->use_tls || upstream_acl_may_tls(ctx));
	if (r || !up->use_tls)
		return r;

	r = upstream_check_tls_host(ctx, up);
	if (r) {
		if (r == -EINVAL)
			pr_err(&ctx->lh, "--upstream-proxy host '%s' cannot be checked as a TLS server name",
			       up->host);
		return r;
	}

	pr_info(&ctx->lh, "TLS to the upstream proxy: verifying %s %s against %s",
		up->host_is_ip ? "address" : "name", up->host,
		ca ? ca : "the system's trust store");
	return 0;
}

__cold
static void upstream_free_tls(struct gwp_ctx *ctx)
{
	gwp_ssl_ctx_free(ctx->up_ssl_ctx);
	ctx->up_ssl_ctx = NULL;
}
#else /* !CONFIG_HTTPS */
static int upstream_init_tls(struct gwp_ctx *ctx, struct gwp_upstream *up)
{
	if (!up->use_tls)
		return 0;
	pr_err(&ctx->lh, "An https:// (TLS) upstream proxy needs gwproxy built with OpenSSL; use http:// or socks5[h]://");
	return -ENOTSUP;
}

static void upstream_free_tls(struct gwp_ctx __unused *ctx)
{
}

static int upstream_init_acl_tls(struct gwp_ctx __unused *ctx)
{
	return 0;
}

static int upstream_acl_srv_tls(struct gwp_ctx __unused *ctx,
				struct gwp_upstream __unused *up, char *why,
				size_t size)
{
	snprintf(why, size, "https:// needs gwproxy built with OpenSSL; use http:// or socks5h://");
	return -ENOTSUP;
}
#endif /* CONFIG_HTTPS */

/*
 * Give the server @up its entry in the shared state table, by identity: the
 * URL's scheme, the address it resolved to and the user (struct
 * gwp_up_key), and its ejection state for the health settings of @o. The
 * last step of making a server, once all of that is set.
 */
__cold
static int upstream_attach_state(struct gwp_ctx *ctx, struct gwp_upstream *up,
				 const struct gwp_up_opts *o)
{
	enum gwp_up_scheme scheme;
	struct gwp_up_key key;

	if (up->type == GWP_UPSTREAM_SOCKS5)
		scheme = up->remote_dns ? GWP_UP_SCHEME_SOCKS5H :
					  GWP_UP_SCHEME_SOCKS5;
	else
		scheme = up->use_tls ? GWP_UP_SCHEME_HTTPS : GWP_UP_SCHEME_HTTP;
	gwp_up_key_init(&key, scheme, &up->addr, up->user,
			up->has_auth ? up->ulen : 0);
	up->state = gwp_up_state_get(ctx->up_tab, &key);
	explicit_bzero(&key, sizeof(key));
	if (!up->state)
		return -ENOMEM;
	if (!o->max_fails)
		return 0;
	up->health = gwp_up_health_get(up->state, o);
	if (up->health)
		return 0;
	gwp_up_state_put(up->state);
	up->state = NULL;
	return -ENOMEM;
}

/*
 * --upstream-proxy and --upstream-proxy-auth-file: build the default upstream
 * pool, of the one server they name. The pool owns that server's first
 * reference; every connection through it takes one more.
 */
__cold
static int gwp_ctx_init_upstream(struct gwp_ctx *ctx)
{
	struct gwp_upstream_pool *pool = &ctx->upstream_pool;
	const char *url = ctx->cfg.upstream_proxy;
	struct gwp_upstream *up;
	struct gwp_up_opts o;
	size_t off, len;
	int r;

	/* Every server's, the ACL pools' too: made even without this one. */
	ctx->up_tab = gwp_up_table_create();
	if (!ctx->up_tab)
		return -ENOMEM;
	if (!url)
		return upstream_init_acl_tls(ctx);

	up = calloc(1, sizeof(*up));
	if (!up)
		return -ENOMEM;
	pool->srv = calloc(1, sizeof(*pool->srv));
	if (!pool->srv) {
		free(up);
		return -ENOMEM;
	}

	r = gwp_parse_upstream(url, up);
	if (r) {
		/* Name the URL, but never its password. */
		if (!upstream_pass_span(url, &off, &len)) {
			off = strlen(url);
			len = 0;
		}
		if (r == -EHOSTUNREACH)
			pr_err(&ctx->lh, "--upstream-proxy host '%s' does not resolve",
			       up->host);
		else
			pr_err(&ctx->lh, "Invalid --upstream-proxy value '%.*s%s%s'",
			       (int)off, url, len ? "***" : "",
			       url + off + len);
		goto out_free;
	}
	if (ctx->cfg.upstream_auth_file) {
		const char *path = ctx->cfg.upstream_auth_file;

		/* Two sources for one secret: refuse to guess. */
		if (up->has_auth) {
			pr_err(&ctx->lh, "--upstream-proxy carries credentials and --upstream-proxy-auth-file is given; use one of them");
			r = -EINVAL;
			goto out_free;
		}
		r = upstream_read_auth(path, up);
		if (r == -EINVAL) {
			pr_err(&ctx->lh, "Invalid --upstream-proxy-auth-file '%s': want one line of user:password, each 1..255 bytes (password may be empty)",
			       path);
			goto out_free;
		} else if (r) {
			pr_err(&ctx->lh, "Cannot read --upstream-proxy-auth-file '%s': %s",
			       path, strerror(-r));
			goto out_free;
		}
	}
	r = upstream_init_tls(ctx, up);
	if (r)
		goto out_free;
	/*
	 * The upstream proxy is itself an outgoing connection, so it is
	 * subject to --outgoing-family. Catching it here turns what
	 * would be an every-connection failure into one startup error.
	 */
	if (!gwp_ctx_outgoing_family_ok(ctx, &up->addr)) {
		pr_err(&ctx->lh, "--upstream-proxy address %s is not allowed by --outgoing-family",
		       ip_to_str(&up->addr));
		r = -EAFNOSUPPORT;
		goto out_free;
	}
	pr_info(&ctx->lh, "Routing outgoing connections via upstream %s proxy %s (%s DNS)",
		up->type == GWP_UPSTREAM_SOCKS5 ? "SOCKS5" :
		up->use_tls ? "HTTPS" : "HTTP",
		ip_to_str(&up->addr),
		up->remote_dns ? "remote" : "local");

	/* The default upstream has the default health settings. */
	gwp_up_opts_default(&o);
	r = upstream_attach_state(ctx, up, &o);
	if (r)
		goto out_free;
	atomic_init(&up->refcnt, 1);
	pool->srv[0] = up;
	pool->nr = 1;
	return 0;

out_free:
	upstream_free_tls(ctx);
	explicit_bzero(up, sizeof(*up));
	free(up);
	free(pool->srv);
	pool->srv = NULL;
	return r;
}

/*
 * Drop the default pool's servers, after the workers and so every connection
 * are gone: each server should be down to the pool's own reference by now.
 * Anything else is a reference a connection teardown failed to drop (or
 * dropped twice), which would leak (or free early) a server once pools come
 * and go on an ACL reload; say so.
 */
__cold
static void gwp_ctx_free_upstream(struct gwp_ctx *ctx)
{
	struct gwp_upstream_pool *pool = &ctx->upstream_pool;
	uint32_t i, refs;

	for (i = 0; i < pool->nr; i++) {
		struct gwp_upstream *up = pool->srv[i];

		refs = atomic_load_explicit(&up->refcnt, memory_order_acquire);
		if (refs != 1)
			pr_err(&ctx->lh, "BUG: upstream proxy %s has %u references left at exit, want 1",
			       ip_to_str(&up->addr), refs);
		else
			pr_dbg(&ctx->lh, "Upstream proxy %s: all connection references dropped",
			       ip_to_str(&up->addr));
		refs = gwp_up_state_open(up->state);
		if (refs)
			pr_err(&ctx->lh, "BUG: upstream proxy %s has %u open pairs at exit, want 0",
			       ip_to_str(&up->addr), refs);
		gwp_upstream_put(up);
	}
	free(pool->srv);
	pool->srv = NULL;
	pool->nr = 0;
	upstream_free_tls(ctx);

	/*
	 * After the ACL's pools (gwp_ctx_free_acl()): every server is gone,
	 * and each took its entry with it.
	 */
	refs = gwp_up_table_destroy(ctx->up_tab);
	ctx->up_tab = NULL;
	if (refs)
		pr_err(&ctx->lh, "BUG: %u upstream server state entries left at exit, want 0",
		       refs);
}

void gwp_upstream_put(struct gwp_upstream *up)
{
	_Atomic(uint32_t) *live;

	if (atomic_fetch_sub_explicit(&up->refcnt, 1, memory_order_acq_rel) != 1)
		return;
	live = up->live;
	gwp_up_health_put(up->health);
	gwp_up_state_put(up->state);
	explicit_bzero(up, sizeof(*up));
	free(up);
	if (live)
		atomic_fetch_sub_explicit(live, 1, memory_order_release);
}

/*
 * Make an upstream pool's server of @url, for the ACL load that reads it
 * (struct gwp_acl_server_ops): parsed, resolved and checked once here, so a
 * server no connection could use fails the load with its file and line,
 * and a connection only ever takes a reference. @url passed acl.c's shape
 * check; @why must not quote it, as it may hold a password. @opts are what
 * the pool sets for the server.
 */
__cold
static int acl_srv_make(void *arg, const char *url,
			const struct gwp_up_opts *opts, void **srv, char *why,
			size_t size)
{
	struct gwp_ctx *ctx = arg;
	struct gwp_upstream *up;
	int r;

	up = calloc(1, sizeof(*up));
	if (!up)
		return -ENOMEM;

	r = gwp_parse_upstream(url, up);
	if (r == -EHOSTUNREACH) {
		snprintf(why, size, "host %s does not resolve", up->host);
	} else if (r) {
		snprintf(why, size, "the host is not a valid name or address");
	} else if (!gwp_ctx_outgoing_family_ok(ctx, &up->addr)) {
		snprintf(why, size, "address %s is not allowed by --outgoing-family",
			 ip_to_str(&up->addr));
		r = -EAFNOSUPPORT;
	} else if (ctx->cfg.target_buf_size < GWP_UPSTREAM_MIN_TARGET_BUF) {
		snprintf(why, size, "an upstream needs --target-buf-size of at least %d",
			 GWP_UPSTREAM_MIN_TARGET_BUF);
		r = -EINVAL;
	} else if (up->use_tls) {
		r = upstream_acl_srv_tls(ctx, up, why, size);
	}
	if (r) {
		explicit_bzero(up, sizeof(*up));
		free(up);
		return r;
	}

	r = upstream_attach_state(ctx, up, opts);
	if (r) {
		snprintf(why, size, "out of memory");
		explicit_bzero(up, sizeof(*up));
		free(up);
		return r;
	}
	atomic_init(&up->refcnt, 1);
	up->live = &ctx->nr_acl_srv;
	atomic_fetch_add_explicit(&ctx->nr_acl_srv, 1, memory_order_relaxed);
	*srv = up;
	return 0;
}

static void acl_srv_put(void __unused *arg, void *srv)
{
	gwp_upstream_put(srv);
}

/*
 * A pool keeps each server's shared state and ejection state beside it,
 * which the server holds until it is freed, so pool_pick_server() reads
 * them without reaching every server object.
 */
static void acl_srv_member(void __unused *arg, void *srv,
			   struct gwp_up_member *m)
{
	struct gwp_upstream *up = srv;

	m->st = up->state;
	m->h = up->health;
}

/*
 * The one place a pair's upstream changes, so the open-pair count of each
 * server identity (struct gwp_up_state) follows the pairs that hold one of
 * its servers: a pair takes a slot with the server, when it is given it,
 * not when it connects, and gives it back with the server, whichever way
 * the pair stops using it -- replaced by an ACL pick, or freed (every
 * teardown, failed or not, and worker shutdown end in a free).
 */
void gwp_conn_set_upstream(struct gwp_ctx *ctx, struct gwp_conn_pair *gcp,
			   struct gwp_upstream *up)
{
	struct gwp_upstream *old = gcp->upstream;
	uint32_t n;

	if (up) {
		gwp_upstream_get(up);
		gwp_up_state_take(up->state);
	}
	gcp->upstream = up;
	if (!up)
		gwp_conn_upstream_up(gcp);	/* no pool without a server */
	if (!old)
		return;

	n = gwp_up_state_give(old->state);
	if (unlikely(n == UINT32_MAX))
		pr_err(&ctx->lh, "BUG: upstream %s had no open pair to give back (idx=%u)",
		       ip_to_str(&old->addr), gcp->idx);
	else
		pr_dbg(&ctx->lh, "Upstream %s released by idx=%u, %u open",
		       ip_to_str(&old->addr), gcp->idx, n);
	gwp_upstream_put(old);
}

/*
 * How an attempt through the upstream failed, from the errno it failed
 * with, when nothing more telling was noted: the proxy hanging up on the
 * handshake, or the connect (the timers note their timeouts).
 */
static enum gwp_upstream_end upstream_end_of(struct gwp_conn_pair *gcp,
					     int err)
{
	if (gwp_in_upstream_hs(gcp) &&
	    (err == -ECONNRESET || err == -EPIPE || err == -ECONNABORTED))
		return GWP_UPSTREAM_END_HUP;
	return GWP_UPSTREAM_END_CONNECT;
}

/* @ms for a log line: in seconds when it is whole seconds. */
static const char *up_ms_str(uint32_t ms, char *buf, size_t size)
{
	if (ms % 1000)
		snprintf(buf, size, "%u ms", ms);
	else
		snprintf(buf, size, "%u s", ms / 1000);
	return buf;
}

/* What up_ejected_other() is told. */
struct up_fail_env {
	struct gwp_ctx		*ctx;
	struct gwp_upstream	*up;
};

/*
 * A failure of the server @arg's up ejected its identity for the pools that
 * list it with the health settings of @h, which are not its own: those
 * pools are not known here, only the address.
 */
static void up_ejected_other(void *arg, const struct gwp_up_health *h)
{
	struct up_fail_env *env = arg;
	struct gwp_upstream *up = env->up;
	char e[24], w[24];

	pr_warn(&env->ctx->lh, "Upstream %s ejected for %s after %u failures in %s, in the pools that list it with these settings",
		ip_to_str(&up->addr), up_ms_str(h->eject_ms, e, sizeof(e)),
		h->max_fails, up_ms_str(h->window_ms, w, sizeof(w)));
}

/*
 * The one retry of @gcp, whose attempt through the @gcp->up_srv-th server
 * of its pool failed: move it to the next server in service, if there is
 * one. Returns whether it did.
 */
static bool upstream_retry(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_upstream *old = gcp->upstream, *up;
	char d_old[320];
	uint32_t i;

	gcp->flags |= GWP_CONN_FLAG_UP_RETRIED;
	i = pool_pick_server(w->ctx, gcp->up_pool, gcp->up_srv);
	up = gwp_acl_pool_server(gcp->up_pool, i);
	if (!up) {
		pr_dbg(&w->ctx->lh, "Upstream %s failed (idx=%u); no other server in service to retry on",
		       up_desc(gcp->up_pool, gcp->up_srv, old, d_old,
			       sizeof(d_old)), gcp->idx);
		return false;
	}

	up_desc(gcp->up_pool, gcp->up_srv, old, d_old, sizeof(d_old));
	gwp_conn_set_upstream(w->ctx, gcp, up);
	gcp->up_srv = (uint16_t)i;
	/* A new attempt: its failure is its own. */
	gcp->flags &= ~GWP_CONN_FLAG_UP_FAILED;
	gcp->up_end = 0;
	gcp->up_val = 0;
	pr_dbg(&w->ctx->lh, "Upstream retry for idx=%u: %s failed, trying server %u (%s), %u open",
	       gcp->idx, d_old, i + 1, ip_to_str(&up->addr),
	       gwp_up_state_open(up->state));
	return true;
}

bool gwp_conn_upstream_failed(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			      int err, bool may_retry)
{
	enum gwp_upstream_fail_class cls;
	enum gwp_upstream_end end;
	struct gwp_upstream *up = gcp->upstream;
	unsigned int val;
	char why[64];

	if (!up || gcp->is_target_alive || (gcp->flags & GWP_CONN_FLAG_UP_FAILED))
		return false;
	gcp->flags |= GWP_CONN_FLAG_UP_FAILED;

	if (gcp->up_end) {
		end = (enum gwp_upstream_end)(gcp->up_end - 1);
		val = gcp->up_val;
	} else {
		end = upstream_end_of(gcp, err);
		val = (unsigned int)(err < 0 ? -err : err);
	}
	/*
	 * A retry runs on what the first attempt left of the connect
	 * timeout, which may be next to nothing: running out of it says
	 * little about the second server, so it does not count.
	 */
	if (end == GWP_UPSTREAM_END_TIMEOUT &&
	    (gcp->flags & GWP_CONN_FLAG_UP_RETRIED))
		val = 1;
	cls = gwp_upstream_fail_classify(end, (int)val);

	switch (end) {
	case GWP_UPSTREAM_END_CONNECT:
	case GWP_UPSTREAM_END_HUP:
		snprintf(why, sizeof(why), "%s",
			 val ? strerror((int)val) : "-");
		break;
	case GWP_UPSTREAM_END_S5_METHOD:
	case GWP_UPSTREAM_END_S5_AUTH:
	case GWP_UPSTREAM_END_S5_REP:
		snprintf(why, sizeof(why), "0x%02x", val);
		break;
	case GWP_UPSTREAM_END_HTTP:
		snprintf(why, sizeof(why), "%u", val);
		break;
	default:
		snprintf(why, sizeof(why), "-");
		break;
	}
	pr_dbg(&w->ctx->lh, "Upstream attempt failed (idx=%u, up=%s, end=%s, class=%s): %s",
	       gcp->idx, ip_to_str(&up->addr), gwp_upstream_end_str(end),
	       gwp_upstream_fail_class_str(cls), why);

	/* Only the upstream's own failures count against its health. */
	if (cls == GWP_UPSTREAM_FAIL_UPSTREAM) {
		struct up_fail_env env = { .ctx = w->ctx, .up = up };
		uint64_t now = gwp_now_ms();
		char desc[320], e[24], wd[24];

		/* An ejection that ran out is ended (and logged) first. */
		up_ejected(w->ctx, gcp->up_pool, gcp->up_srv, up, &now);
		if (gwp_up_state_fail(up->state, up->health, (uint32_t)now,
				      up_ejected_other, &env))
			pr_warn(&w->ctx->lh, "Upstream %s ejected for %s after %u failures in %s",
				up_desc(gcp->up_pool, gcp->up_srv, up, desc,
					sizeof(desc)),
				up_ms_str(up->health->eject_ms, e, sizeof(e)),
				up->health->max_fails,
				up_ms_str(up->health->window_ms, wd,
					  sizeof(wd)));
	}

	if (cls != GWP_UPSTREAM_FAIL_UPSTREAM || !may_retry || !gcp->up_pool ||
	    (gcp->flags & (GWP_CONN_FLAG_UP_RETRIED | GWP_CONN_FLAG_IS_DYING |
			   GWP_CONN_FLAG_IS_CANCEL)))
		return false;
	return upstream_retry(w, gcp);
}

void gwp_conn_upstream_up(struct gwp_conn_pair *gcp)
{
	gwp_acl_pool_put(gcp->up_pool);
	gcp->up_pool = NULL;
}

/* Block or unblock (@how) SIGINT and SIGTERM on the calling thread. */
__cold
static void gwp_block_stop_signals(int how)
{
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGTERM);
	pthread_sigmask(how, &set, NULL);
}

__cold
static int gwp_ctx_init(struct gwp_ctx *ctx)
{
	int r;

	ctx->pid_fd = -1;
	r = gwp_ctx_init_log(ctx);
	if (r < 0)
		return r;

	r = gwp_ctx_parse_ev(ctx);
	if (r < 0)
		goto out_free_log;

	r = gwp_ctx_init_bind_def(ctx);
	if (!r && ctx->bind_def.have_src &&
	    !gwp_ctx_outgoing_family_ok(ctx, &ctx->bind_def.src)) {
		/*
		 * A source of the family we are forbidden to dial can never
		 * apply: apply_conn_bind() would skip it on every connection.
		 */
		pr_err(&ctx->lh, "--bind-source %s is not allowed by --outgoing-family",
		       ip_to_str(&ctx->bind_def.src));
		r = -EAFNOSUPPORT;
	}
	if (r < 0)
		goto out_free_log;

	r = gwp_ctx_init_upstream(ctx);
	if (r < 0)
		goto out_free_log;

	/*
	 * A transparent proxy takes the target from SO_ORIGINAL_DST per
	 * connection, so there is no --target to resolve here.
	 */
	if (!ctx->cfg.as_socks5 && !ctx->cfg.as_http && !ctx->cfg.as_transparent) {
		const char *t = ctx->cfg.target;

		/*
		 * With a remote-DNS upstream the proxy resolves the target, so
		 * we must not resolve --target locally; keep a hostname to hand
		 * to the proxy later. Otherwise resolve it, and still keep the
		 * hostname, if it is one, for the pairs an ACL -j UPSTREAM rule
		 * sends to a remote-DNS pool.
		 */
		if (ctx->upstream_pool.nr &&
		    ctx->upstream_pool.srv[0]->remote_dns) {
			r = upstream_target_init(ctx);
		} else {
			r = convert_str_to_ssaddr(t, &ctx->target_addr, 0);
			if (!r && upstream_target_init(ctx))
				ctx->target_name.ver = 0;
		}
		if (r) {
			pr_err(&ctx->lh, "Invalid target address '%s'", t);
			goto out_free_log;
		}
	}

	if (ctx->cfg.mark) {
		int tfd = __sys_socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);

		if (tfd >= 0) {
			r = __sys_setsockopt(tfd, SOL_SOCKET, SO_MARK,
					     &ctx->cfg.mark, sizeof(ctx->cfg.mark));
			__sys_close(tfd);
			if (r) {
				pr_err(&ctx->lh, "Cannot set --mark=%u (SO_MARK): %s (CAP_NET_ADMIN or CAP_NET_RAW required)",
				       ctx->cfg.mark, strerror(-r));
				goto out_free_log;
			}
		}
	}

	if (ctx->cfg.pid_file)
		gwp_ctx_init_pid_file(ctx);

	r = gwp_ctx_init_tls(ctx);
	if (r < 0)
		goto out_free_log;

	r = gwp_ctx_init_prot(ctx);
	if (r < 0)
		goto out_free_tls;

	r = gwp_ctx_init_acl(ctx);
	if (r < 0)
		goto out_free_prot;

	r = gwp_ctx_init_iplim(ctx);
	if (r < 0)
		goto out_free_acl;

	r = gwp_ctx_init_reload(ctx);
	if (r < 0)
		goto out_free_iplim;

	/*
	 * From here on threads start (the DNS workers) and the listeners
	 * open, and either would make a SIGINT or SIGTERM with no handler
	 * yet a death by signal: the default action, which skips the
	 * cleanup and fails whatever waited for the proxy to listen. Keep
	 * them pending instead, as SIGHUP is from the top of main(), so the
	 * handler takes them as a stop once it is in place; the threads
	 * started meanwhile inherit the block, so they never land there.
	 * Before this point a signal still stops a slow or stuck startup
	 * (a log FIFO with no reader, a large ACL file) at once.
	 */
	gwp_block_stop_signals(SIG_BLOCK);

	r = gwp_ctx_init_dns(ctx);
	if (r < 0)
		goto out_free_reload;

	r = gwp_ctx_init_threads(ctx);
	if (r < 0) {
		pr_err(&ctx->lh, "Failed to initialize worker threads: %s", strerror(-r));
		goto out_free_dns;
	}

	return 0;

out_free_dns:
	gwp_ctx_free_dns(ctx);
out_free_reload:
	gwp_ctx_free_reload(ctx);
out_free_iplim:
	gwp_ctx_free_iplim(ctx);
out_free_acl:
	gwp_ctx_free_acl(ctx);
out_free_prot:
	gwp_ctx_free_prot(ctx);
out_free_tls:
	gwp_ctx_free_tls(ctx);
out_free_log:
	gwp_ctx_free_pid_file(ctx);
	gwp_ctx_free_upstream(ctx);
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
	gwp_ctx_free_reload(ctx);
	gwp_ctx_free_iplim(ctx);
	gwp_ctx_free_acl(ctx);
	gwp_ctx_free_prot(ctx);
	gwp_ctx_free_tls(ctx);
	gwp_ctx_free_pid_file(ctx);
	gwp_ctx_free_upstream(ctx);
	gwp_ctx_free_log(ctx);
}

__cold
static int init_conn(struct gwp_conn *conn, uint32_t buf_size)
{
	conn->fd = -1;
	conn->len = 0;
	conn->cap = buf_size;
	conn->off = 0;
	conn->ep_mask = 0;
	/*
	 * Nothing needs these page aligned (no registered buffers, O_DIRECT or
	 * zero-copy send), and an aligned allocation makes glibc over-allocate
	 * and split chunks, which fragments the heap.
	 */
	conn->buf = malloc(buf_size);
	return conn->buf ? 0 : -ENOMEM;
}

static void free_conn(struct gwp_conn *conn)
{
	if (!conn)
		return;

	if (conn->buf)
		free(conn->buf - conn->off);

	if (conn->fd >= 0)
		__sys_close(conn->fd);

	conn->buf = NULL;
	conn->len = 0;
	conn->cap = 0;
	conn->off = 0;
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

	/*
	 * Both event loops carry this pointer in the low 48 bits of the event
	 * word (see EV_BIT_ALL). Refusing the connection is a poor outcome, but
	 * it is a diagnosable one: proceeding would hand the loops a pointer
	 * they silently truncate on the way back out.
	 */
	if (unlikely(!EV_PTR_OK(gcp))) {
		pr_err(&ctx->lh,
		       "BUG: connection pair %p has bits 48..63 set; the event word cannot carry it",
		       (void *)gcp);
		free(gcp);
		return NULL;
	}

	assert(cfg->target_buf_size > 1);
	assert(cfg->client_buf_size > 1);
	r = init_conn(&gcp->target, cfg->target_buf_size);
	if (r)
		goto out_free_gcp;
	/* Room behind the buffer for an HTTP request's rewrite to grow into. */
	r = init_conn(&gcp->client,
		      (uint32_t)cfg->client_buf_size + GWP_HTTP_REWRITE_SLACK);
	if (r)
		goto out_free_target_conn;
	gcp->client.cap = (uint32_t)cfg->client_buf_size;

	gcp->timer_fd = -1;
	gcp->udp_fd = -1;
	memset(gcp->attempt_fd, 0xff, sizeof(gcp->attempt_fd));	/* all -1 */
	gcp->idx = gcs->nr;
	gcp->conn_state = CONN_STATE_INIT;
	gcs->pairs[gcs->nr++] = gcp;
	gcp->flags = 0;
	gcp->prot_type = GWP_PROT_TYPE_NONE;
	/* Every connection goes through the default pool, when there is one. */
	if (ctx->upstream_pool.nr) {
		uint64_t now = 0;

		gwp_conn_set_upstream(ctx, gcp, ctx->upstream_pool.srv[0]);
		/* Its only server: an ejection only shows in the log. */
		up_ejected(ctx, NULL, 0, gcp->upstream, &now);
	}
	return gcp;

out_free_target_conn:
	free_conn(&gcp->target);
out_free_gcp:
	free(gcp);
	pr_err(&ctx->lh, "Failed to allocate connection pair: %s", strerror(-r));
	return NULL;
}

/*
 * Shrink with hysteresis: only once the array is less than a quarter used,
 * and then only to half its size, so it never ends up exactly full. Shrinking
 * to exactly @nr (and freeing it at zero) made the next accept double it
 * again: two reallocs per connection at a steady load, each an mremap()
 * syscall once the array outgrows the mmap threshold. The array itself is
 * only walked at teardown, which frees it.
 */
static int shrink_conn_slot(struct gwp_wrk *w)
{
	struct gwp_conn_slot *gcs = &w->conn_slot;
	struct gwp_conn_pair **new_pairs;
	struct gwp_ctx *ctx = w->ctx;
	uint32_t new_cap;

	if (gcs->cap <= 16 || gcs->nr >= gcs->cap / 4)
		return 0;

	new_cap = gcs->cap / 2;
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
	gwp_conn_pair_abort_target(gcp);

	/*
	 * Every way a client goes away ends here (or, at shutdown, in
	 * gwp_ctx_free_thread_sock_pairs()), so the count cannot leak.
	 */
	if (gcp->flags & GWP_CONN_FLAG_IPLIM)
		gwp_ctx_iplim_put(w->ctx, &gcp->client_addr);

	if (gcp->flags & GWP_CONN_FLAG_NO_CLOSE_FD)
		gcp->target.fd = gcp->client.fd = gcp->timer_fd = gcp->udp_fd = -1;

	tmp = gcs->pairs[--gcs->nr];
	gcs->pairs[gcs->nr] = NULL;
	gcs->pairs[i] = tmp;
	tmp->idx = i;

	free_conn(&gcp->target);
	free_conn(&gcp->client);

	if (gcp->timer_fd >= 0)
		__sys_close(gcp->timer_fd);
	if (gcp->udp_fd >= 0)
		__sys_close(gcp->udp_fd);
	gwp_conn_close_attempts(gcp);
	free(gcp->udp_peers);
	gwp_conn_set_upstream(w->ctx, gcp, NULL);

	gwp_conn_pair_drop_dns(w, gcp);

	switch (gcp->prot_type) {
	case GWP_PROT_TYPE_SOCKS5:
		gwp_socks5_conn_free(gcp->s5_conn);
		break;
	case GWP_PROT_TYPE_HTTP:
		gwp_http_conn_free(gcp->http_conn);
		break;
	}

#ifdef CONFIG_HTTPS
	gwp_ssl_free(gcp->client.tls);
	gwp_ssl_free(gcp->target.tls);
#if defined(CONFIG_IO_URING)
	free(gcp->tls_io);	/* flat buffer struct; NULL unless io_uring+TLS */
	free(gcp->up_tls_io);	/* likewise, for an https:// upstream */
#endif
#endif

	free(gcp);
	shrink_conn_slot(w);
	return 0;
}

/*
 * These come from linux/netfilter_ipv4.h and
 * linux/netfilter_ipv6/ip6_tables.h, but including those headers tends to
 * clash with <netinet/in.h>. The values are part of the stable UAPI.
 */
#ifndef SO_MARK
#define SO_MARK 36
#endif
#ifndef IP_BIND_ADDRESS_NO_PORT
#define IP_BIND_ADDRESS_NO_PORT 24
#endif
#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif
#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST 80
#endif

/*
 * Fetch the pre-DNAT destination of a connection redirected to us by iptables
 * REDIRECT (used by --as-transparent). @client is the accepted peer address,
 * used to pick the right protocol level (an IPv4 or v4-mapped peer carries an
 * IPv4 original destination).
 *
 * Returns -ELOOP when that destination is the proxy itself: a client that
 * reached the listener directly, with no REDIRECT on the way, still has a
 * conntrack entry, and its "original destination" is the address it
 * connected to. Forwarding there connects to the listener again, whose new
 * connection is just the same, and so on until descriptors run out.
 */
int gwp_get_orig_dst(int fd, const struct gwp_sockaddr *client,
		     struct gwp_sockaddr *dst)
{
	struct gwp_sockaddr local;
	socklen_t len;
	bool v4;
	int r;

	v4 = (client->sa.sa_family == AF_INET) ||
	     (client->sa.sa_family == AF_INET6 &&
	      IN6_IS_ADDR_V4MAPPED(&client->i6.sin6_addr));

	memset(dst, 0, sizeof(*dst));
	if (v4) {
		len = sizeof(dst->i4);
		r = __sys_getsockopt(fd, IPPROTO_IP, SO_ORIGINAL_DST,
				     &dst->i4, &len);
	} else {
		len = sizeof(dst->i6);
		r = __sys_getsockopt(fd, IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST,
				     &dst->i6, &len);
	}
	if (r)
		return r;

	len = sizeof(local);
	r = __sys_getsockname(fd, &local.sa, &len);
	if (r)
		return r;

	if (gwp_sockaddr_ip_eq(dst, &local) && sa_port_h(dst) == sa_port_h(&local))
		return -ELOOP;

	return 0;
}

static int setskopt_int(int fd, int level, int optname, int value)
{
	return __sys_setsockopt(fd, level, optname, &value, sizeof(value));
}

/* Write the IPv4-mapped IPv6 form (::ffff:a.b.c.d) of a 4-byte address. */
static void set_v4mapped(struct in6_addr *a6, const void *v4)
{
	memset(a6, 0, sizeof(*a6));
	a6->s6_addr[10] = 0xff;
	a6->s6_addr[11] = 0xff;
	memcpy(&a6->s6_addr[12], v4, 4);
}

/* Canonicalise an address to (is_v4, pointer to its 4- or 16-byte IP). */
static void sockaddr_canon_ip(const struct gwp_sockaddr *a, bool *is_v4,
			      const uint8_t **ip)
{
	if (a->sa.sa_family == AF_INET) {
		*is_v4 = true;
		*ip = (const uint8_t *)&a->i4.sin_addr;
		return;
	}
	if (IN6_IS_ADDR_V4MAPPED(&a->i6.sin6_addr)) {
		*is_v4 = true;
		*ip = &a->i6.sin6_addr.s6_addr[12];
		return;
	}
	*is_v4 = false;
	*ip = a->i6.sin6_addr.s6_addr;
}

/*
 * Write to @out the form of source @src that a socket about to dial @dst can
 * bind. An IPv4-mapped address is IPv4 traffic on an AF_INET6 socket, so what
 * has to match is the canonical family, and the spelling then follows the
 * socket's: @dst decides, as the socket was created with its family. Returns
 * false when @src is of the other family and cannot apply to @dst.
 */
static bool conn_bind_src(struct gwp_sockaddr *out,
			  const struct gwp_sockaddr *src,
			  const struct gwp_sockaddr *dst)
{
	const uint8_t *src_ip, *dst_ip;
	bool src_v4, dst_v4;

	sockaddr_canon_ip(src, &src_v4, &src_ip);
	sockaddr_canon_ip(dst, &dst_v4, &dst_ip);
	if (src_v4 != dst_v4)
		return false;

	if (src->sa.sa_family == dst->sa.sa_family) {
		*out = *src;
		return true;
	}

	memset(out, 0, sizeof(*out));
	if (dst->sa.sa_family == AF_INET) {
		out->i4.sin_family = AF_INET;
		out->i4.sin_port = src->i6.sin6_port;
		memcpy(&out->i4.sin_addr, src_ip, 4);
	} else {
		out->i6.sin6_family = AF_INET6;
		out->i6.sin6_port = src->i4.sin_port;
		set_v4mapped(&out->i6.sin6_addr, src_ip);
	}
	return true;
}

/*
 * Apply a bind spec to socket @fd before connect: pin the outgoing interface
 * (SO_BINDTODEVICE) and/or source address (bind()). Strict -- any failure is
 * returned so the caller drops the connection rather than proceeding on the
 * default route/source (which would leak traffic via the wrong path). @dst is
 * the address about to be connected, used to require a matching source family.
 * Neither operation needs a capability of its own: SO_BINDTODEVICE has been
 * unprivileged since Linux 5.7 (it wanted CAP_NET_RAW, never CAP_NET_ADMIN,
 * before that), and bind() to a locally configured address never needed one.
 * A source port below 1024 still needs CAP_NET_BIND_SERVICE.
 *
 * @b is either an ACL -j BIND rule or, when @global, the --bind-source /
 * --bind-iface default. The only difference is the family mismatch: an explicit
 * rule that names a source of the wrong family is a configuration error and is
 * refused, whereas the global default must not turn a dual-stack proxy into a
 * single-family one -- an IPv4 --bind-source simply does not apply to an IPv6
 * target, so the source is skipped and the connection proceeds. An interface
 * has no family, so --bind-iface still applies to every target. A v4-mapped
 * address is IPv4 here, as it is to --outgoing-family and the ACL: were it to
 * count as IPv6, a client could dodge an IPv4 source by spelling its target so.
 */
static int apply_conn_bind(struct gwp_wrk *w, int fd,
			   const struct gwp_sockaddr *dst,
			   const struct gwp_acl_bind *b, bool global)
{
	const char *tag = global ? "bind default" : "ACL BIND";
	int r;

	if (b->iface[0]) {
		r = __sys_setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
				     b->iface, (socklen_t)strlen(b->iface));
		if (unlikely(r < 0)) {
			pr_err(&w->ctx->lh,
			       "%s: SO_BINDTODEVICE(%s) failed: %s (no such interface, or a kernel older than 5.7 without CAP_NET_RAW)",
			       tag, b->iface, strerror(-r));
			return r;
		}
	}

	if (b->have_src) {
		struct gwp_sockaddr src;
		const struct gwp_sockaddr *s = &src;
		socklen_t len;
		in_port_t port;

		/* The source family must match the socket/target family. */
		if (!conn_bind_src(&src, &b->src, dst)) {
			if (global) {
				pr_dbg(&w->ctx->lh,
				       "bind default: --bind-source does not apply to target %s (other address family)",
				       ip_to_str(dst));
				return 0;
			}
			pr_err(&w->ctx->lh,
			       "ACL BIND: --to-source family does not match target %s",
			       ip_to_str(dst));
			return -EAFNOSUPPORT;
		}

		len = (s->sa.sa_family == AF_INET) ? sizeof(struct sockaddr_in)
						   : sizeof(struct sockaddr_in6);

		/*
		 * With no port asked for, leave choosing one to connect(), which
		 * knows the destination and only needs a unique 4-tuple. bind()
		 * alone would take the port for every destination, TIME_WAIT
		 * included, capping all egress from this source at one local
		 * port range. Not fatal: only pre-4.2 kernels refuse it, and the
		 * source is pinned either way. IPv6 sockets take it at SOL_IP too.
		 */
		port = (s->sa.sa_family == AF_INET) ? s->i4.sin_port
						    : s->i6.sin6_port;
		if (!port)
			setskopt_int(fd, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, 1);

		r = __sys_bind(fd, &s->sa, len);
		if (unlikely(r < 0)) {
			pr_err(&w->ctx->lh, "%s: bind(%s) failed: %s",
			       tag, ip_to_str(s), strerror(-r));
			return r;
		}
	}
	return 0;
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
			   const struct gwp_conn_sockopt *so,
			   bool *is_target_alive, bool non_block)
{
	int t = SOCK_STREAM | SOCK_CLOEXEC | (non_block ? SOCK_NONBLOCK : 0);
	socklen_t len;
	int fd, r;

	/*
	 * --outgoing-family. This is the one choke point every outgoing TCP
	 * socket passes through, and it sits after the ACL has run, so a
	 * "-j DNAT" rewrite into the forbidden family is caught here too.
	 * -EAFNOSUPPORT reaches the client as SOCKS5 REP 0x08 / HTTP 502.
	 */
	if (!gwp_ctx_outgoing_family_ok(w->ctx, addr)) {
		pr_info(&w->ctx->lh,
			"--outgoing-family refuses target %s", ip_to_str(addr));
		return -EAFNOSUPPORT;
	}

	fd = __sys_socket(addr->sa.sa_family, t, 0);
	if (unlikely(fd < 0))
		return fd;

	gwp_setup_cli_sock_options(w, fd);

	/*
	 * Mark the outgoing connection for policy routing / iptables matching.
	 * A per-connection -j MARK from the ACL overrides the global --mark, and
	 * is strict like -j BIND: if SO_MARK fails (it needs CAP_NET_ADMIN or,
	 * since Linux 5.11, CAP_NET_RAW) the connection is dropped rather than
	 * egressing unmarked via the wrong route. The coarse global --mark stays
	 * best-effort.
	 */
	if (so && so->mark_set) {
		r = setskopt_int(fd, SOL_SOCKET, SO_MARK, (int)so->mark);
		if (unlikely(r < 0)) {
			pr_err(&w->ctx->lh,
			       "ACL MARK: SO_MARK=%u failed: %s (CAP_NET_ADMIN or CAP_NET_RAW required)",
			       so->mark, strerror(-r));
			__sys_close(fd);
			return r;
		}
	} else if (w->ctx->cfg.mark) {
		setskopt_int(fd, SOL_SOCKET, SO_MARK, (int)w->ctx->cfg.mark);
	}

	/*
	 * Pin the source interface/address before connect. Strict -- a failure
	 * drops the connection rather than falling back to the wrong source
	 * (see apply_conn_bind). A matching ACL -j BIND rule replaces the
	 * global --bind-source/--bind-iface default wholesale, exactly as -j
	 * MARK replaces --mark: a rule that names only an interface must not
	 * silently inherit the global source address, which would apply a
	 * policy neither the rule nor the default describes.
	 */
	if (so && so->bind.set) {
		r = apply_conn_bind(w, fd, addr, &so->bind, false);
		if (unlikely(r)) {
			__sys_close(fd);
			return r;
		}
	} else if (w->ctx->bind_def.set) {
		r = apply_conn_bind(w, fd, addr, &w->ctx->bind_def, true);
		if (unlikely(r)) {
			__sys_close(fd);
			return r;
		}
	}

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
	case -EAFNOSUPPORT:
		return GWP_SOCKS5_REP_ATYP_NOT_SUPPORTED;
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
		ba->port = t.i4.sin_port;
		return 0;
	case AF_INET6:
		ba->ver = GWP_SOCKS5_ATYP_IPV6;
		memcpy(&ba->ip6, &t.i6.sin6_addr, 16);
		ba->port = t.i6.sin6_port;
		return 0;
	default:
		pr_err(&ctx->lh, "Unsupported address family %d for local socket",
			t.sa.sa_family);
		return -EAFNOSUPPORT;
	}
}

/*
 * Build a SOCKS5 CONNECT reply for the downstream client into an arbitrary
 * output buffer. @err is 0 on success or a positive errno on failure.
 */
__hot
int gwp_socks5_build_connect_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				   int err, void *out, size_t *out_len)
{
	struct gwp_socks5_conn *sc = gcp->s5_conn;
	struct gwp_socks5_addr ba;
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
	return gwp_socks5_conn_cmd_connect_res(sc, &ba, err, out, out_len);
}

__hot
int gwp_socks5_prep_connect_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				  int err)
{
	size_t out_len = gcp->target.cap - gcp->target.len;
	void *out = gcp->target.buf + gcp->target.len;
	int r;

	r = gwp_socks5_build_connect_reply(w, gcp, err, out, &out_len);
	if (r < 0)
		return r;

	gcp->target.len += out_len;
	return 0;
}

int gwp_conn_fail_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp, int err)
{
	/*
	 * The two event loops report a connect timeout with different errnos:
	 * epoll's timer path uses -ETIMEDOUT, io_uring's timeout CQE gives
	 * -ETIME. Normalise, or the SOCKS5 mapping below would answer the
	 * generic REP 0x01 on io_uring instead of 0x06 (TTL expired).
	 */
	bool timed_out = (err == -ETIMEDOUT || err == -ETIME);

	gcp->flags |= GWP_CONN_FLAG_FAIL_REPLIED;
	if (timed_out)
		err = -ETIMEDOUT;

	/*
	 * Through an upstream proxy, a connect that failed was to the proxy,
	 * not to the destination: a proxy that refused it, reset it or could
	 * not be reached says nothing about the destination, so it is the
	 * chain's failure, REP 0x01, as a failed handshake with the proxy is
	 * (gwp_upstream_fail_reply(), which has noted how the handshake
	 * ended). These are the errnos that count against the proxy's
	 * health. Anything else keeps its answer: a destination of a family
	 * --outgoing-family forbids (REP 0x08), local trouble (0x01), and a
	 * timeout, which still says that time ran out.
	 */
	if (!timed_out && gcp->upstream &&
	    (gcp->flags & GWP_CONN_FLAG_UP_FAILED) && !gcp->up_end &&
	    gwp_upstream_connect_class(err) == GWP_UPSTREAM_FAIL_UPSTREAM)
		err = -EPROTO;

	if (gcp->prot_type == GWP_PROT_TYPE_SOCKS5)
		return gwp_socks5_prep_connect_reply(w, gcp, err);

	if (gcp->prot_type == GWP_PROT_TYPE_HTTP) {
		void *out = gcp->target.buf + gcp->target.len;
		size_t cap = gcp->target.cap - gcp->target.len;
		int r;

		if (timed_out)
			r = gwp_http_build_gateway_timeout_reply(out, cap);
		else
			r = gwp_http_build_bad_gateway_reply(out, cap);
		if (r < 0)
			return r;
		gcp->target.len += (uint32_t)r;
		return 0;
	}

	return 0;	/* plain/transparent forwarding speaks no protocol */
}

/*
 * No descriptor for a raw query's socket, no memory for the query or for the
 * system resolver's request, a send refused: the name was never looked up,
 * which leaves the origin as unreachable as a lookup that failed, so the
 * client gets the same answer, host unreachable, as from a lookup that fails
 * later. Closing the connection without a word left a SOCKS5 client without
 * its reply and an HTTP client without a status.
 */
int gwp_dns_start_failed(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			 const char *host, int err)
{
	int r;

	pr_dbg(&w->ctx->lh, "DNS query could not be started: %s (%s; gcp_idx=%u)",
	       host, strerror(-err), gcp->idx);
	r = gwp_conn_fail_reply(w, gcp, -EHOSTUNREACH);
	return r ? r : -EBADMSG;
}

int gwp_acl_reject_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	pr_info(&w->ctx->lh, "ACL denied target %s for client %s (idx=%u)",
		gwp_upstream_dst_str(gcp), ip_to_str(&gcp->client_addr),
		gcp->idx);

	if (gcp->prot_type == GWP_PROT_TYPE_SOCKS5) {
		int r = gwp_socks5_prep_connect_reply(w, gcp, -EACCES);

		if (r)
			return r;
	} else if (gcp->prot_type == GWP_PROT_TYPE_HTTP) {
		int r = gwp_http_build_forbidden_reply(
				gcp->target.buf + gcp->target.len,
				gcp->target.cap - gcp->target.len);

		if (r < 0)
			return r;
		gcp->target.len += (uint32_t)r;
	}
	return -EACCES;
}

/*
 * Queue the lookup, or, when @res is an error the cache remembered for the
 * name, an entry that already failed with it: either way the result comes
 * back through the worker's DNS completion queue.
 */
static int queue_dns_resolution(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				const char *host, uint16_t port, int res)
{
	struct gwp_dns_ctx *dns = w->ctx->dns;
	struct gwp_iplim_key client;
	struct gwp_dns_entry *gde;

	gwp_iplim_key(&gcp->client_addr, &client);
	if (res)
		gde = gwp_dns_queue_result(dns, w->idx, host, port, gcp, res);
	else
		gde = gwp_dns_queue(dns, w->idx, host, port, &client, gcp);
	if (unlikely(!gde)) {
		pr_err(&w->ctx->lh, "Failed to allocate DNS entry for %s:%hu", host, port);
		return -ENOMEM;
	}

	gcp->gde = gde;
	return -EINPROGRESS;
}

/*
 * Fill @out (SOCKS5 address form) from a resolved sockaddr. Used to hand the
 * already-resolved destination IP to the upstream SOCKS5 proxy (socks5://).
 */
static int upstream_dst_from_sockaddr(const struct gwp_sockaddr *sa,
				      struct gwp_socks5_addr *out)
{
	memset(out, 0, sizeof(*out));
	switch (sa->sa.sa_family) {
	case AF_INET:
		out->ver = GWP_SOCKS5_ATYP_IPV4;
		memcpy(out->ip4, &sa->i4.sin_addr, 4);
		out->port = sa->i4.sin_port;
		return 0;
	case AF_INET6:
		out->ver = GWP_SOCKS5_ATYP_IPV6;
		memcpy(out->ip6, &sa->i6.sin6_addr, 16);
		out->port = sa->i6.sin6_port;
		return 0;
	default:
		return -EAFNOSUPPORT;
	}
}

/*
 * Fill @out as a domain-name destination. Used with socks5h:// so the upstream
 * proxy performs the resolution.
 */
static int upstream_dst_from_domain(const char *host, uint16_t port,
				    struct gwp_socks5_addr *out)
{
	size_t hl = strlen(host);

	if (hl == 0 || hl > 255)
		return -EINVAL;

	memset(out, 0, sizeof(*out));
	out->ver = GWP_SOCKS5_ATYP_DOMAIN;
	out->domain.len = (uint8_t)hl;
	memcpy(out->domain.str, host, hl);
	out->domain.str[hl] = '\0';
	out->port = htons(port);
	return 0;
}

/*
 * Split a "host:port" (or "[ipv6]:port") string and fill @out as a domain
 * destination. Used for plain --target mode with socks5h://.
 */
static int upstream_dst_from_hostport(const char *hostport,
				      struct gwp_socks5_addr *out)
{
	char buf[300], *colon, *host;
	size_t hl, n = strlen(hostport);
	uint16_t port;

	if (n == 0 || n >= sizeof(buf))
		return -EINVAL;
	memcpy(buf, hostport, n + 1);

	colon = strrchr(buf, ':');
	if (!colon)
		return -EINVAL;
	*colon = '\0';
	if (parse_port(colon + 1, &port) || !port)
		return -EINVAL;

	host = buf;
	hl = strlen(host);
	if (host[0] == '[' && hl >= 2 && host[hl - 1] == ']') {
		host[hl - 1] = '\0';
		host++;
	}

	return upstream_dst_from_domain(host, port, out);
}

/*
 * Whether a client-requested hostname is fit for the ACL, the resolver and an
 * upstream CONNECT request: an IPv6 literal, or letters, digits, '-' and '_'
 * in non-empty dot-separated labels of at most 63 characters (which covers
 * IPv4 literals). Anything else, CR, LF and ':' in particular, would be
 * pasted verbatim into the request to an http:// upstream, which then reads
 * a different target than the one the ACL judged.
 */
static bool req_host_valid(const char *host)
{
	struct in6_addr a6;
	size_t label = 0;
	size_t n = 0;

	if (inet_pton(AF_INET6, host, &a6) == 1)
		return true;

	for (; host[n]; n++) {
		unsigned char c = (unsigned char)host[n];

		if (c == '.') {
			if (!label)
				return false;
			label = 0;
			continue;
		}
		if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') &&
		    !(c >= '0' && c <= '9') && c != '-' && c != '_')
			return false;
		/*
		 * A label's length byte leaves room for 63 octets (RFC 1035
		 * 2.3.4): a longer one can never resolve either.
		 */
		if (++label > 63)
			return false;
	}

	/*
	 * At most 253 characters, 254 with the root's dot: on the wire a name
	 * takes a length byte per label and the root's zero, two more than its
	 * text without that dot, and may not exceed 255 octets (RFC 1035
	 * 2.3.4). A longer one can never resolve, so it is malformed, whichever
	 * resolver would look it up.
	 */
	if (n && host[n - 1] == '.')
		n--;
	return n > 0 && n <= 253;
}

/*
 * Format gcp->up_dst as an HTTP authority ("host:port" or "[ipv6]:port") for an
 * upstream CONNECT request. Returns 0 on success, -EINVAL on a bad address.
 */
int gwp_upstream_authority(const struct gwp_socks5_addr *dst, char *buf,
			   size_t cap)
{
	uint16_t port = ntohs(dst->port);
	char ip[INET6_ADDRSTRLEN];
	int n;

	switch (dst->ver) {
	case GWP_SOCKS5_ATYP_DOMAIN:
		/* It goes into a request line: never let it end one early. */
		if (!req_host_valid(dst->domain.str))
			return -EINVAL;
		n = snprintf(buf, cap, "%s:%u", dst->domain.str, port);
		break;
	case GWP_SOCKS5_ATYP_IPV4:
		if (!inet_ntop(AF_INET, dst->ip4, ip, sizeof(ip)))
			return -EINVAL;
		n = snprintf(buf, cap, "%s:%u", ip, port);
		break;
	case GWP_SOCKS5_ATYP_IPV6:
		if (!inet_ntop(AF_INET6, dst->ip6, ip, sizeof(ip)))
			return -EINVAL;
		n = snprintf(buf, cap, "[%s]:%u", ip, port);
		break;
	default:
		return -EINVAL;
	}

	if (n < 0 || (size_t)n >= cap)
		return -EINVAL;
	return 0;
}

/*
 * Finalize gcp->up_dst (the destination requested from the upstream proxy)
 * right before the client handshake. A hostname for the upstream to resolve is
 * already there, requested by the client or configured with --target; anything
 * else goes by the target address, as the ACL may have rewritten it.
 */
int gwp_upstream_finalize_dst(struct gwp_conn_pair *gcp)
{
	if (gcp->up_dst.ver != 0)
		return 0;

	return upstream_dst_from_sockaddr(&gcp->target_addr, &gcp->up_dst);
}

int gwp_conn_close_attempts(struct gwp_conn_pair *gcp)
{
	int n = 0;
	uint8_t i;

	for (i = 0; i < GWP_MAX_CONN_CAND; i++) {
		if (gcp->attempt_fd[i] < 0)
			continue;
		__sys_close(gcp->attempt_fd[i]);
		gcp->attempt_fd[i] = -1;
		n++;
	}

	return n;
}

void gwp_conn_set_candidates(struct gwp_conn_pair *gcp,
			     const struct gwp_sockaddr *addrs, uint8_t nr)
{
	if (nr > GWP_MAX_CONN_CAND)
		nr = GWP_MAX_CONN_CAND;

	memcpy(gcp->cand, addrs, (size_t)nr * sizeof(*addrs));
	gcp->nr_cand = nr;
	gcp->next_cand = 0;
	gwp_acl_memo_reset(&gcp->acl_memo);

	/*
	 * Keep target_addr meaningful for callers that read it before the
	 * first attempt starts (logging, upstream_dst_from_sockaddr()).
	 */
	if (nr)
		gcp->target_addr = gcp->cand[0];
}

void gwp_conn_set_single_candidate(struct gwp_conn_pair *gcp,
				   const struct gwp_sockaddr *addr)
{
	gwp_conn_set_candidates(gcp, addr, 1);
}

/*
 * Parse @host as an IP literal, IPv6 or any form inet_aton() accepts (which
 * includes "2130706433" and "127.1", spellings a resolver takes as numbers
 * too), into @sa with @port. Returns false for a real name.
 */
static bool req_host_ip(const char *host, uint16_t port, struct gwp_sockaddr *sa)
{
	memset(sa, 0, sizeof(*sa));
	if (inet_pton(AF_INET6, host, &sa->i6.sin6_addr) == 1) {
		sa->i6.sin6_family = AF_INET6;
		sa->i6.sin6_port = htons(port);
		return true;
	}
	if (inet_aton(host, &sa->i4.sin_addr)) {
		sa->i4.sin_family = AF_INET;
		sa->i4.sin_port = htons(port);
		return true;
	}
	return false;
}

/*
 * Take --target apart for a remote-DNS upstream, without resolving anything. It
 * goes by the rules of a hostname a client requests (see
 * prepare_target_addr_domain()), and the ACL needs it: an address is the
 * target, for -d rules and DNAT, and a name is matched by -m domain.
 */
__cold
static int upstream_target_init(struct gwp_ctx *ctx)
{
	struct gwp_socks5_addr *dst = &ctx->target_name;
	uint16_t port;
	int r;

	r = upstream_dst_from_hostport(ctx->cfg.target, dst);
	if (!r && !req_host_valid(dst->domain.str))
		r = -EINVAL;
	if (r) {
		dst->ver = 0;
		return r;
	}

	if (dst->domain.str[dst->domain.len - 1] == '.')
		dst->domain.str[--dst->domain.len] = '\0';

	port = ntohs(dst->port);
	if (req_host_ip(dst->domain.str, port, &ctx->target_addr))
		dst->ver = 0;
	return 0;
}

/*
 * A SOCKS5 or HTTP request whose upstream could not be picked: refuse it as
 * the ACL refuses a target (SOCKS5 0x02, HTTP 403). Returns -EBADMSG once
 * the reply is queued, so it goes out before the teardown.
 */
static int pick_refused(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	int r = gwp_acl_reject_reply(w, gcp);

	return r == -EACCES ? -EBADMSG : r;
}

static int prepare_target_addr_domain(struct gwp_wrk *w,
				      struct gwp_conn_pair *gcp,
				      char *host, uint16_t port)
{
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_cfg *cfg = &ctx->cfg;
	struct gwp_sockaddr sa;
	bool is_ip;
	size_t hl;
	int r;

	if (!req_host_valid(host)) {
		pr_info(&ctx->lh, "Rejected a malformed target hostname (idx=%u)",
			gcp->idx);
		return -EINVAL;
	}

	/*
	 * "name." is the same name as "name" to the resolver and to an
	 * upstream, so it must be the same name to the ACL too, or a deny rule
	 * for "name" (or a regexp anchored with '$') is dodged by the dot.
	 * req_host_valid() has ruled out "." and "..".
	 */
	hl = strlen(host);
	if (host[hl - 1] == '.')
		host[hl - 1] = '\0';

	/* Remember the requested hostname for ACL "-m domain" matching. */
	gcp->req_domain = host;

	/*
	 * An address in disguise ("127.0.0.1", "::1", or a legacy form such
	 * as "2130706433") is the target itself, to the ACL and to an
	 * upstream alike.
	 */
	is_ip = req_host_ip(host, port, &sa);

	/* The name decides the upstream, and the upstream how it resolves. */
	r = conn_pick_upstream(ctx, gcp, host, is_ip ? &sa : NULL, port);
	if (unlikely(r))
		return pick_refused(w, gcp);

	/*
	 * socks5h://: don't resolve locally; hand the hostname to the upstream
	 * proxy. up_dst carries the domain and we're ready to connect.
	 */
	if (gcp->upstream && gcp->upstream->remote_dns) {
		if (!port)
			return -EINVAL;
		/*
		 * An address is taken as one, so -d rules see it, and the
		 * upstream is asked for that address rather than a name it
		 * would only parse back.
		 */
		if (is_ip) {
			gwp_conn_set_single_candidate(gcp, &sa);
			return 0;
		}
		return upstream_dst_from_domain(host, port, &gcp->up_dst);
	}

	if (cfg->use_raw_dns) {
		/*
		 * An address is the target, not a name to ask the server about:
		 * the query would tell the server where the client is going, and
		 * its answer would choose where the tunnel goes. The system
		 * resolver parses these itself.
		 */
		if (is_ip) {
			gwp_conn_set_single_candidate(gcp, &sa);
			return 0;
		}
		r = gwp_raw_dns_resolve(w, gcp, host, port);
		/* -EINVAL: a name DNS cannot carry, a malformed request. */
		if (r != -EINPROGRESS && r != -EINVAL)
			r = gwp_dns_start_failed(w, gcp, host, r);
		return r;
	} else {
		struct gwp_sockaddr addrs[GWP_MAX_CONN_CAND];
		uint8_t nr = 0;

		r = gwp_dns_cache_lookup_list(ctx->dns, host, port, addrs,
					      GWP_MAX_CONN_CAND, &nr);
		if (!r) {
			gwp_conn_set_candidates(gcp, addrs, nr);
			pr_dbg(&ctx->lh, "Found %s:%hu in DNS cache %s (%u addr)",
				host, port, ip_to_str(&gcp->target_addr), nr);
			return 0;
		}

		r = queue_dns_resolution(w, gcp, host, port,
					 r == -EHOSTUNREACH ? r : 0);
		if (r != -EINPROGRESS)
			r = gwp_dns_start_failed(w, gcp, host, r);
		return r;
	}
}

static int socks5_prepare_target_addr_domain(struct gwp_wrk *w,
					     struct gwp_conn_pair *gcp)
{
	struct gwp_socks5_addr *dst;
	int r;

	dst = &gcp->s5_conn->dst_addr;
	/* A NUL inside the name would cut it short for everyone after us. */
	if (strlen(dst->domain.str) != dst->domain.len)
		r = -EINVAL;
	else
		r = prepare_target_addr_domain(w, gcp, dst->domain.str,
					       ntohs(dst->port));
	/* The name may have lost its trailing dot. */
	dst->domain.len = (uint8_t)strlen(dst->domain.str);
	if (r == -EINPROGRESS)
		gcp->conn_state = CONN_STATE_SOCKS5_DNS_QUERY;
	else if (r == -EINVAL && !gwp_conn_fail_reply(w, gcp, r))
		return -EBADMSG;	/* the REP 0x01 goes out first */

	return r;
}

int gwp_socks5_prepare_target_addr(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_sockaddr *ta = &gcp->target_addr;
	struct gwp_socks5_conn *sc = gcp->s5_conn;
	struct gwp_socks5_addr *dst;

	assert(sc);

	dst = &sc->dst_addr;
	memset(ta, 0, sizeof(*ta));
	switch (dst->ver) {
	case GWP_SOCKS5_ATYP_IPV4:
		memcpy(&ta->i4.sin_addr, &dst->ip4, 4);
		ta->i4.sin_port = dst->port;
		ta->i4.sin_family = AF_INET;
		gwp_conn_set_single_candidate(gcp, ta);
		if (conn_pick_upstream(w->ctx, gcp, NULL, ta, ntohs(dst->port)))
			return pick_refused(w, gcp);
		return 0;
	case GWP_SOCKS5_ATYP_IPV6:
		memcpy(&ta->i6.sin6_addr, &dst->ip6, 16);
		ta->i6.sin6_port = dst->port;
		ta->i6.sin6_family = AF_INET6;
		gwp_conn_set_single_candidate(gcp, ta);
		if (conn_pick_upstream(w->ctx, gcp, NULL, ta, ntohs(dst->port)))
			return pick_refused(w, gcp);
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
	if (r == -ENOBUFS)
		return r;
	gwp_conn_buf_advance(&gcp->client, in_len);
	gcp->target.len += out_len;
	return (r == -EAGAIN) ? 0 : r;
}

/*
 * Log a SOCKS5 username/password failure, so that failed guesses show up
 * in the log and a tool watching it can block the source. The username
 * comes from the client and may hold any byte; escape everything outside
 * printable ASCII, and the quote and backslash that delimit it, so the
 * client cannot forge or break log lines.
 */
static void socks5_log_auth_failure(struct gwp_wrk *w,
				    struct gwp_conn_pair *gcp)
{
	char user[GWP_LOG_ESC_SIZE(255)];
	const char *u;
	size_t len;

	u = gwp_socks5_conn_rejected_user(gcp->s5_conn, &len);
	if (!u)
		return;

	gwp_log_escape(user, u, len < 255 ? len : 255);
	pr_info(&w->ctx->lh, "SOCKS5 authentication failed (ca=%s, user=\"%s\")",
		ip_to_str(&gcp->client_addr), user);
}

/*
 * Log a failed HTTP proxy login like the SOCKS5 one. A request without
 * Proxy-Authorization is how a client learns that credentials are needed,
 * not a failure, and is not logged.
 */
static void http_log_auth_failure(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	char user[GWP_LOG_ESC_SIZE(255)];
	const char *u;
	size_t len;

	if (!gwp_http_conn_auth_failed(gcp->http_conn, &u, &len))
		return;

	if (!u) {
		pr_info(&w->ctx->lh, "HTTP proxy authentication failed (ca=%s, malformed credentials)",
			ip_to_str(&gcp->client_addr));
		return;
	}

	gwp_log_escape(user, u, len < 255 ? len : 255);
	pr_info(&w->ctx->lh, "HTTP proxy authentication failed (ca=%s, user=\"%s\")",
		ip_to_str(&gcp->client_addr), user);
}

static int handle_socks5_prot(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	uint32_t clen = gcp->client.len, tlen = gcp->target.len;
	struct gwp_ctx *ctx = w->ctx;
	int r;

	/*
	 * Only on the first pass. The greeting need not arrive in one segment,
	 * and a second allocation would leak the first and throw away the
	 * parser state along with it.
	 */
	if (!gcp->s5_conn) {
		gcp->s5_conn = gwp_socks5_conn_alloc(ctx->socks5);
		if (!gcp->s5_conn) {
			pr_err(&ctx->lh, "Failed to allocate SOCKS5 connection");
			return -ENOMEM;
		}
		/*
		 * Claim the connection as SOCKS5 now, exactly as the HTTP side
		 * does: s5_conn and http_conn share a union, and gwp_free_conn_pair()
		 * picks the member to free by prot_type. Leaving it NONE while
		 * the greeting is still arriving means a teardown in that window
		 * frees neither, which a client can repeat at will.
		 */
		gcp->prot_type = GWP_PROT_TYPE_SOCKS5;
	}

	r = gwp_socks5_handle_data(gcp);
	socks5_log_auth_failure(w, gcp);
	if (r < 0) {
		gwp_socks5_conn_free(gcp->s5_conn);
		gcp->s5_conn = NULL;
		/* Unclaim it, so an HTTP fallback can take the union over. */
		gcp->prot_type = GWP_PROT_TYPE_NONE;
		/*
		 * Only a first byte that is not SOCKS5 leaves both buffers
		 * as they were. Once the parser took a greeting and queued
		 * its reply, the client spoke SOCKS5: a later failure
		 * (wrong password, bad request) is final, or the HTTP parser
		 * would get the rest of the bytes, answer behind the SOCKS5
		 * replies and give the client another password guess.
		 */
		if (r == -EINVAL &&
		    (gcp->client.len != clen || gcp->target.len != tlen))
			r = -EPROTO;
		return r;
	}

	if (gcp->s5_conn->state == GWP_SOCKS5_ST_INIT) {
		/*
		 * The greeting is still incomplete, so the protocol remains
		 * undecided -- the parser needs VER and NMETHODS before it can
		 * even reject a non-SOCKS5 first byte, and it has consumed
		 * nothing. Report that rather than success: gwp_socks5_handle_data()
		 * folds the parser's -EAGAIN into 0 for its other caller, and
		 * taking that 0 at face value here would leave the pair in
		 * CONN_STATE_PROT while claiming the state machine had advanced.
		 * epoll's dispatcher asserts on exactly that combination.
		 */
		return -EAGAIN;
	}

	/*
	 * This must be a SOCKS5 data connection, there is no possibility to
	 * fallback to HTTP because the SOCKS5 parser already sees the SOCKS5
	 * header.
	 */
	gcp->conn_state = CONN_STATE_SOCKS5_DATA;
	gcp->prot_type = GWP_PROT_TYPE_SOCKS5;
	return 0;
}

/*
 * True when @a may be dialled under --outgoing-family.
 *
 * The comparison must be v4-mapped aware: the SOCKS5 UDP relay hands targets
 * over as ::ffff:a.b.c.d on a dual-stack socket, so a bare
 * sa_family == AF_INET6 test would refuse ordinary IPv4 traffic.
 */
bool gwp_ctx_outgoing_family_ok(const struct gwp_ctx *ctx,
				const struct gwp_sockaddr *a)
{
	const uint8_t *ip;
	bool is_v4;

	if (ctx->cfg.outgoing_family == GWP_OUT_FAMILY_ANY)
		return true;

	sockaddr_canon_ip(a, &is_v4, &ip);
	if (ctx->cfg.outgoing_family == GWP_OUT_FAMILY_IPV4)
		return is_v4;
	return !is_v4;
}

int gwp_conn_dial_addr(struct gwp_ctx *ctx, struct gwp_conn_pair *gcp,
		       struct gwp_sockaddr **addr)
{
	int fam = gcp->target_addr.sa.sa_family;

	if (!gcp->upstream) {
		*addr = &gcp->target_addr;
		return 0;
	}

	/*
	 * --outgoing-family also binds an address the upstream will be asked
	 * for, requested by the client or made by a -j DNAT: it is not this
	 * proxy that dials it, but it is this proxy that sends it there. Only a
	 * hostname for the upstream to resolve is out of reach. A DNAT that
	 * replaced such a hostname has updated target_addr too.
	 */
	if (gcp->up_dst.ver != GWP_SOCKS5_ATYP_DOMAIN &&
	    (fam == AF_INET || fam == AF_INET6) &&
	    !gwp_ctx_outgoing_family_ok(ctx, &gcp->target_addr)) {
		pr_info(&ctx->lh, "--outgoing-family refuses target %s",
			ip_to_str(&gcp->target_addr));
		return -EAFNOSUPPORT;
	}

	*addr = &gcp->upstream->addr;
	return 0;
}


/*
 * Compare two addresses by IP only (not port), treating an IPv4 address and its
 * IPv4-mapped IPv6 form as equal. The UDP relay socket is normally dual-stack,
 * so a datagram's source is AF_INET6 (v4-mapped for an IPv4 peer) while the
 * pinned client address may be either family; this bridges them.
 */
bool gwp_sockaddr_ip_eq(const struct gwp_sockaddr *a, const struct gwp_sockaddr *b)
{
	const uint8_t *ai, *bi;
	bool av4, bv4;

	sockaddr_canon_ip(a, &av4, &ai);
	sockaddr_canon_ip(b, &bv4, &bi);
	if (av4 != bv4)
		return false;
	return !memcmp(ai, bi, av4 ? 4 : 16);
}

/*
 * Ask the routing table whether connections to @a stay on this host, secondary
 * addresses and local routes of either family included. The reply is written
 * while the request is sent, so nothing here waits. An error reply is a route
 * that does not exist or leads nowhere. Returns 1 or 0, or a negative errno when
 * the kernel could not be asked.
 */
static int route_is_local(const struct gwp_sockaddr *a)
{
	struct {
		struct nlmsghdr	nh;
		struct rtmsg	rt;
		struct rtattr	dst;
		uint8_t		ip[16];
	} req;
	union {
		struct nlmsghdr	nh;
		char		buf[1024];
	} rsp;
	const struct rtmsg *rt = NLMSG_DATA(&rsp.nh);
	const uint8_t *ip;
	uint32_t ip_len;
	ssize_t n;
	bool v4;
	int fd;

	sockaddr_canon_ip(a, &v4, &ip);
	ip_len = v4 ? 4 : 16;

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = (uint32_t)(NLMSG_LENGTH(sizeof(req.rt)) + RTA_LENGTH(ip_len));
	req.nh.nlmsg_type = RTM_GETROUTE;
	req.nh.nlmsg_flags = NLM_F_REQUEST;
	req.rt.rtm_family = v4 ? AF_INET : AF_INET6;
	req.rt.rtm_dst_len = (uint8_t)(ip_len * 8);
	req.dst.rta_type = RTA_DST;
	req.dst.rta_len = (uint16_t)RTA_LENGTH(ip_len);
	memcpy(req.ip, ip, ip_len);

	fd = __sys_socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
			  NETLINK_ROUTE);
	if (fd < 0)
		return fd;
	n = __sys_send(fd, &req, req.nh.nlmsg_len, 0);
	if (n >= 0)
		n = __sys_recv(fd, &rsp, sizeof(rsp), 0);
	__sys_close(fd);

	if (n < 0)
		return (int)n;
	if (n < (ssize_t)NLMSG_HDRLEN)
		return -EIO;
	if (rsp.nh.nlmsg_type == NLMSG_ERROR)
		return 0;
	if (rsp.nh.nlmsg_type != RTM_NEWROUTE ||
	    n < (ssize_t)NLMSG_LENGTH(sizeof(*rt)))
		return -EIO;
	return rt->rtm_type == RTN_LOCAL;
}

/*
 * Whether @a is an address of this host. Where netlink is shut off, bind() is the
 * next best: it has no word on IPv6 local routes and says yes to anything under
 * ip_nonlocal_bind, though EADDRINUSE is the ephemeral ports running out, for an
 * address that is local. Returns 1 or 0, or a negative errno with no descriptor to
 * ask with.
 */
static int ip_is_local(const struct gwp_sockaddr *a)
{
	struct gwp_sockaddr s = *a;
	socklen_t len;
	int fd, r;

	r = route_is_local(a);
	if (r >= 0)
		return r;

	if (a->sa.sa_family == AF_INET) {
		s.i4.sin_port = 0;
		len = sizeof(s.i4);
	} else {
		s.i6.sin6_port = 0;
		len = sizeof(s.i6);
	}

	fd = __sys_socket(a->sa.sa_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return fd;
	r = __sys_bind(fd, &s.sa, len);
	__sys_close(fd);
	return !r || r == -EADDRINUSE;
}

/*
 * Write to @out the address connect() actually goes to for @dst. The unspecified
 * address means loopback on IPv6. On IPv4 it means the source of the socket when
 * one is forced (see gwp_create_sock_target() for which one applies), and
 * 127.0.0.1 otherwise.
 */
static void target_connect_addr(const struct gwp_wrk *w,
				const struct gwp_conn_pair *gcp,
				const struct gwp_sockaddr *dst,
				struct gwp_sockaddr *out)
{
	static const uint8_t any[sizeof(struct in6_addr)];
	static const uint8_t lo4[4] = { 127, 0, 0, 1 };
	const struct gwp_acl_bind *b = gcp->acl_sockopt.bind.set ?
				       &gcp->acl_sockopt.bind : &w->ctx->bind_def;
	const uint8_t *ip;
	bool v4;

	*out = *dst;
	sockaddr_canon_ip(dst, &v4, &ip);
	if (memcmp(ip, any, v4 ? 4 : 16))
		return;

	if (!v4) {
		out->i6.sin6_addr = in6addr_loopback;
		return;
	}

	if (b->set && b->have_src && conn_bind_src(out, &b->src, dst)) {
		sockaddr_canon_ip(out, &v4, &ip);
		if (memcmp(ip, any, 4))
			return;
	}

	*out = *dst;
	if (dst->sa.sa_family == AF_INET)
		memcpy(&out->i4.sin_addr, lo4, 4);
	else
		set_v4mapped(&out->i6.sin6_addr, lo4);
}

/*
 * A client must not get to connect the proxy to itself: the bytes it pipelines
 * behind the request are passed on once the target is up, so they make the next
 * request, and one connection and a few KB nest the proxy in itself thousands
 * of times, each hop one more pair of descriptors. A proxy request is asked about
 * when its attempt has connected: no client bytes have moved yet, so the chain
 * ends at the first hop, and the failure takes the way of a refused connect, reply
 * included.
 *
 * Plain forwarding needs no client bytes: each hop dials the next by itself, and
 * by the time a connection is seen to be up the next hop is on its way, and it
 * goes on after the client has left. So plain forwarding is asked about before
 * the connect, and the connection is never made.
 *
 * Only the port is looked at for every connection. The rest is for the few that
 * match, so it costs ordinary traffic nothing. A path back through NAT or another
 * host cannot be told from here.
 *
 * A full descriptor table leaves nothing to ask the kernel with. Before a connect
 * the answer is then no: the caller's own socket will not be had either, it waits
 * for a descriptor and comes back here with one. With @connected there is no
 * coming back and the answer is yes, as a no would let the hop through, and so on
 * for each two descriptors freed: the chain would soak up all of them and keep the
 * table full. The price is that a remote service on the listener's port number is
 * refused for as long as the table is full.
 */
bool gwp_target_is_self(struct gwp_wrk *w, const struct gwp_conn_pair *gcp,
			const struct gwp_sockaddr *dst, bool connected)
{
	static const uint8_t any[sizeof(struct in6_addr)];
	const struct gwp_sockaddr *lst = &w->listen_addr;
	struct gwp_sockaddr to;
	const uint8_t *lip, *dip;
	bool lv4, dv4, self, unsure = false;

	if (gcp->upstream)
		dst = &gcp->upstream->addr;
	if (sa_port_h(dst) != sa_port_h(lst))
		return false;

	sockaddr_canon_ip(lst, &lv4, &lip);
	target_connect_addr(w, gcp, dst, &to);
	sockaddr_canon_ip(&to, &dv4, &dip);
	if (memcmp(lip, any, lv4 ? 4 : 16)) {
		self = gwp_sockaddr_ip_eq(&to, lst);
	} else if (lv4 ? !dv4 : (dv4 && w->ctx->cfg.bind_ipv6_only)) {
		self = false;		/* a family the wildcard leaves out */
	} else {
		int r = ip_is_local(&to);

		unsure = r < 0;
		self = unsure ? connected : r;
	}

	if (self)
		pr_info(&w->ctx->lh,
			"Refused a target that %s this proxy: %s (idx=%u, ca=%s)",
			unsure ? "may be" : "is",
			ip_to_str(dst), gcp->idx, ip_to_str(&gcp->client_addr));
	return self;
}

bool gwp_sockaddr_eq(const struct gwp_sockaddr *a, const struct gwp_sockaddr *b)
{
	if (a->sa.sa_family != b->sa.sa_family)
		return false;
	if (a->sa.sa_family == AF_INET)
		return a->i4.sin_port == b->i4.sin_port &&
		       a->i4.sin_addr.s_addr == b->i4.sin_addr.s_addr;
	if (a->sa.sa_family == AF_INET6)
		return a->i6.sin6_port == b->i6.sin6_port &&
		       !memcmp(&a->i6.sin6_addr, &b->i6.sin6_addr, 16);
	return false;
}

enum gwp_udp_act gwp_udp_relay_classify(struct gwp_wrk *w,
					struct gwp_conn_pair *gcp,
					unsigned char *base, size_t n,
					const struct gwp_sockaddr *src,
					struct gwp_udp_out *out)
{
	bool client_dgram;

	if (gcp->udp_pinned) {
		client_dgram = gwp_sockaddr_eq(src, &gcp->udp_peer);
	} else {
		/*
		 * Until the client is pinned nothing can be relayed back, so
		 * accept only its first valid datagram, and only from the same
		 * IP as its TCP control connection (RFC 1928); this keeps an
		 * off-path source from hijacking the association.
		 */
		if (!gwp_sockaddr_ip_eq(src, &gcp->client_addr))
			return GWP_UDP_DROP;
		client_dgram = true;
	}

	if (client_dgram) {
		/* Client -> target: strip the header, forward the payload. */
		struct gwp_socks5_addr dst;
		struct gwp_sockaddr tsa;
		socklen_t tslen;
		size_t hdr_len;

		if (gwp_socks5_udp_parse_hdr(base, n, &dst, &hdr_len))
			return GWP_UDP_DROP;
		/* A source has the relay socket's family: see addr_to_sockaddr. */
		if (gwp_socks5_addr_to_sockaddr(&dst, src->sa.sa_family, &tsa,
						&tslen))
			return GWP_UDP_DROP;	/* no way to reach this target */
		/*
		 * --outgoing-family. tsa is v4-mapped for an IPv4 target on a
		 * dual-stack relay socket, which the predicate accounts for.
		 */
		if (!gwp_ctx_outgoing_family_ok(w->ctx, &tsa))
			return GWP_UDP_DROP;	/* wrong family for this proxy */
		/*
		 * Pin only now: a datagram that cannot be relayed whatever the
		 * rules say must not lock the real client out. The ACL below
		 * judges the pinned address, so this comes before it.
		 */
		if (!gcp->udp_pinned) {
			gcp->udp_peer = *src;
			gcp->udp_pinned = true;
		}
		if (!udp_target_allowed(w->ctx, gcp, &tsa))
			return GWP_UDP_DROP;	/* ACL denied this datagram */
		/* Only a target the client has sent to may answer it. */
		if (!udp_peer_note(gcp, &tsa,
				   w->ctx->acl ? gcp->udp_acl.gen : 0))
			return GWP_UDP_DROP;
		out->buf = base + hdr_len;
		out->len = n - hdr_len;
		out->dst = tsa;
		out->dstlen = tslen;
		return GWP_UDP_TO_TARGET;
	} else {
		/* Target -> client: prepend a header in the front slack. */
		struct gwp_socks5_addr sa;
		size_t h, hlen;

		if (!udp_reply_allowed(w->ctx, gcp, src))
			return GWP_UDP_DROP;	/* not a target of this client */
		gwp_socks5_reply_addr_from_sockaddr(src, &sa);
		h = (sa.ver == GWP_SOCKS5_ATYP_IPV4) ? 3 + 1 + 4 + 2
						     : 3 + 1 + 16 + 2;
		if (gwp_socks5_udp_build_hdr(&sa, base - h, h, &hlen))
			return GWP_UDP_DROP;
		out->buf = base - h;
		out->len = h + n;
		out->dst = gcp->udp_peer;
		out->dstlen = gcp->udp_peer.sa.sa_family == AF_INET ?
			      sizeof(gcp->udp_peer.i4) : sizeof(gcp->udp_peer.i6);
		return GWP_UDP_TO_CLIENT;
	}
}

int gwp_socks5_addr_to_sockaddr(const struct gwp_socks5_addr *a, int family,
				struct gwp_sockaddr *sa, socklen_t *slen)
{
	memset(sa, 0, sizeof(*sa));
	switch (a->ver) {
	case GWP_SOCKS5_ATYP_IPV4:
		if (family == AF_INET) {
			sa->i4.sin_family = AF_INET;
			memcpy(&sa->i4.sin_addr, a->ip4, 4);
			sa->i4.sin_port = a->port;
			*slen = sizeof(sa->i4);
			return 0;
		}
		/*
		 * A dual-stack AF_INET6 relay socket expresses every target as
		 * an IPv6 sockaddr: an IPv4 target becomes its IPv4-mapped form
		 * so one socket can reach both families.
		 */
		sa->i6.sin6_family = AF_INET6;
		set_v4mapped(&sa->i6.sin6_addr, a->ip4);
		sa->i6.sin6_port = a->port;
		*slen = sizeof(sa->i6);
		return 0;
	case GWP_SOCKS5_ATYP_IPV6:
		if (family == AF_INET) {
			if (!IN6_IS_ADDR_V4MAPPED((const struct in6_addr *)a->ip6))
				return -EAFNOSUPPORT;
			sa->i4.sin_family = AF_INET;
			memcpy(&sa->i4.sin_addr, a->ip6 + 12, 4);
			sa->i4.sin_port = a->port;
			*slen = sizeof(sa->i4);
			return 0;
		}
		sa->i6.sin6_family = AF_INET6;
		memcpy(&sa->i6.sin6_addr, a->ip6, 16);
		sa->i6.sin6_port = a->port;
		*slen = sizeof(sa->i6);
		return 0;
	default:
		/* Domain targets in relayed datagrams need DNS; not yet. */
		return -EAFNOSUPPORT;
	}
}

/*
 * Fill a SOCKS5 header address from a UDP reply's source. A dual-stack relay
 * sees a source as AF_INET6; a v4-mapped source is unmapped back to an IPv4 ATYP
 * so the client sees the target it actually addressed.
 */
void gwp_socks5_reply_addr_from_sockaddr(const struct gwp_sockaddr *src,
					 struct gwp_socks5_addr *a)
{
	if (src->sa.sa_family == AF_INET) {
		a->ver = GWP_SOCKS5_ATYP_IPV4;
		memcpy(a->ip4, &src->i4.sin_addr, 4);
		a->port = src->i4.sin_port;
		return;
	}
	if (IN6_IS_ADDR_V4MAPPED(&src->i6.sin6_addr)) {
		a->ver = GWP_SOCKS5_ATYP_IPV4;
		memcpy(a->ip4, &src->i6.sin6_addr.s6_addr[12], 4);
		a->port = src->i6.sin6_port;
		return;
	}
	a->ver = GWP_SOCKS5_ATYP_IPV6;
	memcpy(a->ip6, &src->i6.sin6_addr, 16);
	a->port = src->i6.sin6_port;
}

/*
 * Pin the UDP client up front when its request says where it will send from
 * (RFC 1928: the server MAY use DST.ADDR and DST.PORT to limit access), so that
 * another port on its IP cannot take the association by sending first. Only a
 * declared port together with the control connection's own IP counts: a client
 * that declares another address, or none, may be behind a NAT and have its port
 * rewritten too, and it would be cut off. Such a client is pinned from its first
 * valid datagram instead.
 */
static void udp_pin_declared(struct gwp_conn_pair *gcp, int family)
{
	const struct gwp_socks5_addr *d = &gcp->s5_conn->dst_addr;
	struct gwp_sockaddr sa;
	socklen_t slen;

	if (!d->port || gwp_socks5_addr_to_sockaddr(d, family, &sa, &slen))
		return;
	if (!gwp_sockaddr_ip_eq(&sa, &gcp->client_addr))
		return;
	/* The bytes carry no scope, which a link-local peer needs to be sent to. */
	if (family == AF_INET6 && gcp->client_addr.sa.sa_family == AF_INET6)
		sa.i6.sin6_scope_id = gcp->client_addr.i6.sin6_scope_id;
	gcp->udp_peer = sa;
	gcp->udp_pinned = true;
}

int gwp_socks5_udp_associate_setup(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	static const int type = SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC;
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_socks5_addr bnd;
	struct gwp_sockaddr local, relay;
	socklen_t slen = sizeof(local);
	socklen_t relay_len;
	int fd = -1, r, rep = GWP_SOCKS5_REP_SUCCESS;
	size_t out_len;

	/*
	 * UDP ASSOCIATE is not chained through an upstream proxy: an HTTP
	 * upstream cannot carry UDP at all, and SOCKS5 upstream UDP is not
	 * implemented. Binding a local relay here would silently bypass the
	 * configured chain, so refuse the command instead. The chain is the
	 * user's own when an ACL -j UPSTREAM rule picks one, from what is
	 * known now (the user and the client, no target): a pool is refused
	 * like --upstream-proxy, and so is a pool rule that only its target
	 * tests could tell, DIRECT gets the relay even past it, and no choice
	 * leaves the default to decide.
	 */
	r = conn_pick_upstream(ctx, gcp, NULL, NULL, 0);
	if (r || gcp->upstream) {
		rep = GWP_SOCKS5_REP_COMMAND_NOT_SUPPORTED;
		goto reply;
	}

	/*
	 * Re-check the INPUT chain for this client as a UDP request: a "-p udp"
	 * rule cannot match at accept time, where the control connection is TCP.
	 */
	if (!gwp_ctx_acl_client_allowed(ctx, &gcp->client_addr,
					GWP_ACL_PROTO_UDP)) {
		pr_info(&ctx->lh, "ACL denied UDP ASSOCIATE for client %s",
			ip_to_str(&gcp->client_addr));
		rep = GWP_SOCKS5_REP_NOT_ALLOWED;
		goto reply;
	}

	/*
	 * The relay is a dual-stack IPv6 socket bound to the wildcard address so
	 * one socket can both receive from the client and reach IPv4 and IPv6
	 * targets (a socket bound to a single-family local address cannot egress
	 * the other family). BND.ADDR must still be an address the client can
	 * reach, so it is taken from the proxy address the client connected to
	 * (getsockname() on the control fd), paired with the relay's ephemeral
	 * port. Widening the bind to the wildcard does not change the threat
	 * model: the port is ephemeral and the client is IP-pinned.
	 *
	 * A kernel without IPv6 (ipv6.disable=1) has no such socket, and no
	 * IPv6 targets either: use an IPv4 wildcard socket there.
	 */
	r = __sys_getsockname(gcp->client.fd, &local.sa, &slen);
	if (r < 0) {
		pr_err(&ctx->lh, "UDP associate: getsockname(client) failed: %s",
			strerror(-r));
		rep = GWP_SOCKS5_REP_FAILURE;
		goto reply;
	}

	memset(&relay, 0, sizeof(relay));
	fd = __sys_socket(AF_INET6, type, 0);
	if (fd == -EAFNOSUPPORT) {
		fd = __sys_socket(AF_INET, type, 0);
		relay.i4.sin_family = AF_INET;
		relay_len = sizeof(relay.i4);
	} else {
		relay.i6.sin6_family = AF_INET6;
		relay_len = sizeof(relay.i6);
	}
	if (fd < 0) {
		pr_err(&ctx->lh, "UDP associate: socket() failed: %s", strerror(-fd));
		rep = GWP_SOCKS5_REP_FAILURE;
		goto reply;
	}

	if (relay.sa.sa_family == AF_INET6)
		setskopt_int(fd, IPPROTO_IPV6, IPV6_V6ONLY, 0);
	if (ctx->cfg.mark)
		setskopt_int(fd, SOL_SOCKET, SO_MARK, (int)ctx->cfg.mark);

	r = __sys_bind(fd, &relay.sa, relay_len);
	if (r < 0) {
		pr_err(&ctx->lh, "UDP associate: bind() failed: %s", strerror(-r));
		__sys_close(fd);
		fd = -1;
		rep = GWP_SOCKS5_REP_FAILURE;
		goto reply;
	}

	slen = sizeof(relay);
	r = __sys_getsockname(fd, &relay.sa, &slen);
	if (r < 0) {
		pr_err(&ctx->lh, "UDP associate: getsockname(relay) failed: %s",
			strerror(-r));
		__sys_close(fd);
		fd = -1;
		rep = GWP_SOCKS5_REP_FAILURE;
		goto reply;
	}
	/*
	 * BND.ADDR from the control connection, BND.PORT from the relay socket.
	 * An IPv4 client of a dual-stack listener is told an IPv4 address, not
	 * the v4-mapped form of it that getsockname() reports.
	 */
	gwp_socks5_reply_addr_from_sockaddr(&local, &bnd);
	bnd.port = relay.sa.sa_family == AF_INET ? relay.i4.sin_port :
						   relay.i6.sin6_port;

	udp_pin_declared(gcp, relay.sa.sa_family);
	gcp->udp_fd = fd;
	pr_info(&ctx->lh,
		"SOCKS5 UDP ASSOCIATE relay bound (idx=%u, cfd=%d, ufd=%d)",
		gcp->idx, gcp->client.fd, fd);

reply:
	out_len = gcp->target.cap - gcp->target.len;
	r = gwp_socks5_conn_cmd_udp_associate_res(gcp->s5_conn,
			(rep == GWP_SOCKS5_REP_SUCCESS) ? &bnd : NULL, rep,
			gcp->target.buf + gcp->target.len, &out_len);
	if (r < 0)
		return r;
	gcp->target.len += (uint32_t)out_len;

	return (rep == GWP_SOCKS5_REP_SUCCESS) ? 0 : -ECONNREFUSED;
}

int gwp_handle_conn_state_socks5(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	bool decided = false;
	int r, ct;

	ct = gcp->conn_state;
	if (ct == CONN_STATE_PROT) {
		r = handle_socks5_prot(w, gcp);
		if (r)
			return r;
		/*
		 * A client that does not wait for each reply sends its request
		 * in the same read as the greeting, and the parser has already
		 * reached the command. No further read brings us back here
		 * when the client has nothing more to send, so act on it now,
		 * as for a request that arrives on its own.
		 */
		decided = true;
	} else if (ct == CONN_STATE_SOCKS5_DATA) {
		r = gwp_socks5_handle_data(gcp);
		socks5_log_auth_failure(w, gcp);
		if (r)
			return r;
	} else if (ct == CONN_STATE_SOCKS5_DNS_QUERY ||
		   ct == CONN_STATE_SOCKS5_CONNECT) {
		/*
		 * The request is parsed; we are waiting on the resolver or on
		 * connect(), and the client is still armed for input: waiting
		 * on the resolver does not touch the client's registration.
		 * A client that pipelines data behind its request therefore
		 * arrives here, which is rude rather than impossible -- it
		 * used to abort the process.
		 *
		 * There is nothing to parse yet, so leave the bytes buffered:
		 * once the target is up, forwarding sends them on, which is
		 * what the client was banking on.
		 */
		return -EAGAIN;
	} else {
		assert(0 && "Invalid SOCKS5 connection state");
		return -EINVAL;
	}

	if (gcp->s5_conn->state == GWP_SOCKS5_ST_ERR) {
		/*
		 * The parser answered with a failure (no acceptable method,
		 * wrong password) and took nothing after it. RFC 1928 and
		 * RFC 1929 have the server close the connection then; a
		 * client that waits for the close would otherwise hold the
		 * slot until the protocol timeout. The reply is flushed
		 * before the teardown, as for any other error.
		 */
		return -EPROTO;
	}

	if (gcp->s5_conn->state == GWP_SOCKS5_ST_CMD_CONNECT) {
		r = gwp_socks5_prepare_target_addr(w, gcp);
		if (r == -EINPROGRESS) {
			gcp->conn_state = CONN_STATE_SOCKS5_DNS_QUERY;
			return r;
		}

		if (!r)
			gcp->conn_state = CONN_STATE_SOCKS5_CONNECT;
	} else if (gcp->s5_conn->state == GWP_SOCKS5_ST_CMD_UDP_ASSOCIATE) {
		/*
		 * Bind the relay socket and queue the reply; both event loops
		 * then arm their own relay (handle_udp_associate on epoll,
		 * arm_udp_relay on io_uring).
		 */
		r = gwp_socks5_udp_associate_setup(w, gcp);
		if (!r)
			gcp->conn_state = CONN_STATE_SOCKS5_UDP_ASSOCIATE;
	}

	/*
	 * The greeting made this a SOCKS5 connection. A failure from here
	 * on must not read as "not SOCKS5" to gwp_handle_conn_state_prot(),
	 * which would hand the rest of the bytes to the HTTP parser.
	 */
	if (decided && r == -EINVAL)
		r = -EPROTO;
	return r;
}

/*
 * Queue the HTTP 407 "Proxy Authentication Required" reply for the client. It
 * is written into the client-bound buffer; the event loop flushes it before
 * tearing the connection down (the same path as SOCKS5 error replies). Returns
 * a negative error so the caller drops the connection.
 */
static int http_reject_unauthorized(struct gwp_conn_pair *gcp)
{
	int r = gwp_http_build_auth_required_reply(gcp->target.buf + gcp->target.len,
						   gcp->target.cap - gcp->target.len);
	if (r < 0)
		return -ENOBUFS;

	gcp->target.len += (uint32_t)r;
	return -EACCES;
}

/*
 * Queue the HTTP 431 reply for a request header that will not fit in the
 * client buffer or breaks the parser's length or field-count limit, so the
 * client is told its header is too large instead of just having the
 * connection reset. Same mechanism as the 407 above: written to the
 * client-bound buffer, flushed by the event loop before teardown. Returns a
 * negative error so the caller drops the connection.
 */
static int http_reject_too_large(struct gwp_conn_pair *gcp)
{
	int r = gwp_http_build_too_large_reply(gcp->target.buf + gcp->target.len,
					       gcp->target.cap - gcp->target.len);
	if (r < 0)
		return -E2BIG;

	gcp->target.len += (uint32_t)r;
	return -E2BIG;
}

/*
 * Queue the HTTP 400 reply for a request the forwarding proxy refuses to relay
 * (GWP_HTTP_BAD_REQUEST). Same mechanism as the 407 above. Returns a negative
 * error so the caller drops the connection.
 */
static int http_reject_bad_request(struct gwp_conn_pair *gcp)
{
	int r = gwp_http_build_bad_request_reply(gcp->target.buf + gcp->target.len,
						 gcp->target.cap - gcp->target.len);
	if (r < 0)
		return -ENOBUFS;

	gcp->target.len += (uint32_t)r;
	return -EBADMSG;
}

/*
 * A port as an HTTP authority carries it: decimal digits only, no sign, no
 * service name, at most 65535.
 */
static int parse_port(const char *s, uint16_t *port)
{
	uint32_t v = 0;

	if (!*s)
		return -EINVAL;

	for (; *s; s++) {
		if (*s < '0' || *s > '9')
			return -EINVAL;
		v = v * 10 + (uint32_t)(*s - '0');
		if (v > 65535)
			return -EINVAL;
	}

	*port = (uint16_t)v;
	return 0;
}

/* Resolve and connect to @host:@port, setting the HTTP connect/DNS state. */
static int http_connect_target(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			       char *host, const char *port)
{
	uint16_t p;
	int r;

	/*
	 * The resolver takes the port as a number; a port that is not one
	 * used to reach getaddrinfo() and come back as a 502.
	 */
	if (parse_port(port, &p))
		return http_reject_bad_request(gcp);

	r = prepare_target_addr_domain(w, gcp, host, p);
	if (r == -EINVAL)
		return http_reject_bad_request(gcp);

	if (r == -EINPROGRESS)
		gcp->conn_state = CONN_STATE_HTTP_DNS_QUERY;
	else if (!r)
		gcp->conn_state = CONN_STATE_HTTP_CONNECT;

	return r;
}

/*
 * Room kept free in the target buffer while the response header is held back:
 * enough for the "Connection: close" and "Proxy-Connection: close" lines the
 * rewrite adds. A header therefore gets at most target-buf-size minus this,
 * counted together with any interim (1xx) responses still queued for the
 * client. That is enough for any CRLF header that fits, but the rewrite also
 * turns bare LF line ends into CRLF, so an LF-only header near the limit can
 * still outgrow the buffer; the rewrite is bounds-checked and answers 502.
 */
#define HTTP_FWD_RES_SLACK	64

/*
 * The origin's response is unusable (see gwp_http_fwd_res_input()). Throw
 * away whatever it sent that the client has not seen, answer 502 in its
 * place, and treat the origin as finished: the normal forwarding path then
 * delivers the 502 and closes towards the client.
 */
static int http_fwd_res_fail(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			     uint32_t from, int err)
{
	struct gwp_conn *t = &gcp->target;
	int r;

	pr_info(&w->ctx->lh, "Rejecting response from origin %s: %s (idx=%u)",
		ip_to_str(&gcp->target_addr),
		err == -EACCES ? "it asked for proxy authentication" :
				 strerror(-err), gcp->idx);

	/* The cap below counts from the start of the buffer. */
	gwp_conn_buf_compact(t);
	t->cap = (uint32_t)w->ctx->cfg.target_buf_size;
	t->len = from;
	r = gwp_http_build_bad_gateway_reply(t->buf + t->len, t->cap - t->len);
	if (r < 0)
		return r;
	t->len += (uint32_t)r;
	t->rd_eof = true;
	return 0;
}

static int http_fwd_target_in(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			      uint32_t from)
{
	struct gwp_http_conn *hc = gcp->http_conn;
	uint32_t cap = (uint32_t)w->ctx->cfg.target_buf_size;
	struct gwp_conn *t = &gcp->target;
	size_t out_len, pending;
	int r;

	switch (gwp_http_fwd_res_state(hc)) {
	case GWP_HTTP_RES_NONE:
	case GWP_HTTP_RES_BODY:
		return 0;
	case GWP_HTTP_RES_FAILED:
		/* Already answered 502; whatever else it says is dropped. */
		t->len = from;
		return 0;
	}

	if (t->len == from && !t->rd_eof)
		return 0;

	/*
	 * The header is rewritten in place and the caps set below count from
	 * the start of the buffer, so put the data back there first. @from
	 * is relative to t->buf and stays valid.
	 */
	gwp_conn_buf_compact(t);
	r = gwp_http_fwd_res_input(hc, t->buf + from, t->len - from, t->rd_eof,
				   t->buf + from, cap - from, &out_len);
	if (r < 0)
		return http_fwd_res_fail(w, gcp, from, r);

	t->len = from + (uint32_t)out_len;
	if (gwp_http_fwd_res_state(hc) != GWP_HTTP_RES_HDR) {
		t->cap = cap;
		return 0;
	}

	/*
	 * Still collecting the header. Shrink the buffer the event loop reads
	 * into, so that what is held back, what is still queued for the
	 * client (an interim response) and the next read can never add up to
	 * more than the rewritten header and the body behind it can occupy.
	 *
	 * Filling that room exactly is fine: a run of interim responses that
	 * comes in one full read leaves no room, and the loop then reads no
	 * more until the client has taken some of them. Only more than that
	 * is too much, which a header that grew in the rewrite can be.
	 */
	pending = gwp_http_fwd_res_pending(hc);
	if (t->len + pending + HTTP_FWD_RES_SLACK > cap)
		return http_fwd_res_fail(w, gcp, from, -E2BIG);
	t->cap = cap - HTTP_FWD_RES_SLACK - (uint32_t)pending;
	return 0;
}

/*
 * Client bytes: only the rest of the request's body goes to the origin. What
 * follows it -- typically the client's next request, for whatever host, with
 * its Proxy-Authorization -- was never checked against the ACL and is meant
 * for somebody else, so it is dropped.
 */
static int http_fwd_client_in(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			      uint32_t from)
{
	struct gwp_conn *c = &gcp->client;
	size_t fwd;
	int r;

	if (c->len == from)
		return 0;

	r = gwp_http_fwd_req_body(gcp->http_conn, c->buf + from, c->len - from,
				  &fwd);
	if (r < 0) {
		pr_dbg(&w->ctx->lh, "Malformed request body (idx=%u)", gcp->idx);
		return r;
	}

	if (fwd < c->len - from)
		pr_dbg(&w->ctx->lh,
			"Dropping %zu client bytes after the request (idx=%u)",
			c->len - from - fwd, gcp->idx);
	c->len = from + (uint32_t)fwd;
	return 0;
}

int gwp_http_fwd_in(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
		    struct gwp_conn *c, uint32_t from)
{
	if (c == &gcp->target)
		return http_fwd_target_in(w, gcp, from);
	return http_fwd_client_in(w, gcp, from);
}

int gwp_http_fwd_begin(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	uint32_t cap = (uint32_t)w->ctx->cfg.target_buf_size;
	int r;

	if (!gwp_http_fwd_active(gcp))
		return 0;

	r = gwp_http_fwd_res_init(gcp->http_conn, cap - HTTP_FWD_RES_SLACK);
	if (r)
		return r;
	gwp_conn_buf_compact(&gcp->target);
	gcp->target.cap = cap - HTTP_FWD_RES_SLACK;

	/*
	 * Bytes may already be waiting: an upstream proxy can deliver some
	 * behind its CONNECT reply. They are the start of the response.
	 */
	return http_fwd_target_in(w, gcp, 0);
}

int gwp_handle_conn_state_http(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	size_t len, hdr_len;
	char *host, *port;
	int r;

	if (gcp->conn_state == CONN_STATE_PROT) {
		gcp->http_conn = gwp_http_conn_alloc();
		if (!gcp->http_conn) {
			pr_err(&ctx->lh, "Failed to allocate HTTP connection");
			return -ENOMEM;
		}
		/*
		 * Claim the connection as HTTP now, so a teardown while the
		 * header is still arriving frees http_conn (gwp_free_conn_pair
		 * switches on prot_type).
		 */
		gcp->prot_type = GWP_PROT_TYPE_HTTP;
		gcp->conn_state = CONN_STATE_HTTP_HDR;
	} else if (gcp->conn_state == CONN_STATE_HTTP_DNS_QUERY ||
		   gcp->conn_state == CONN_STATE_HTTP_CONNECT) {
		/* Pipelined behind the request; see the SOCKS5 side. */
		return -EAGAIN;
	} else if (gcp->conn_state != CONN_STATE_HTTP_HDR) {
		assert(0 && "Invalid HTTP connection state");
		return -EINVAL;
	}

	/*
	 * A forwarding request is rewritten in place, ready to go to the
	 * origin, in the buffer and the room kept behind it, which from then
	 * on is simply part of the buffer; any other header is dropped once
	 * it has been dealt with.
	 */
	len = gcp->client.len;
	r = gwp_http_conn_process(gcp->http_conn, ctx->auth, gcp->client.buf,
				  &len, gcp->client.cap + GWP_HTTP_REWRITE_SLACK,
				  &host, &port, &hdr_len);
	if (r == GWP_HTTP_FORWARD) {
		gcp->client.len = (uint32_t)len;
		gcp->client.cap += GWP_HTTP_REWRITE_SLACK;
	} else {
		gwp_conn_buf_advance(&gcp->client, hdr_len);
	}

	switch (r) {
	case GWP_HTTP_NEED_MORE:
		/*
		 * Header still incomplete. If the client buffer is already full
		 * the parser can never accumulate the rest (a header line longer
		 * than the buffer), so reject rather than ask a full,
		 * level-triggered socket to be read again -- which would
		 * busy-spin until the protocol timeout fires.
		 */
		if (gcp->client.len >= gcp->client.cap)
			return http_reject_too_large(gcp);
		return 0;
	case GWP_HTTP_NEED_AUTH:
		http_log_auth_failure(w, gcp);
		return http_reject_unauthorized(gcp);
	case GWP_HTTP_CONNECT:
		return http_connect_target(w, gcp, host, port);
	case GWP_HTTP_FORWARD:
		/* Whatever came in behind the header is the body, or not. */
		r = http_fwd_client_in(w, gcp, (uint32_t)hdr_len);
		if (r == -EBADMSG)
			return http_reject_bad_request(gcp);
		if (r < 0)
			return r;
		return http_connect_target(w, gcp, host, port);
	case GWP_HTTP_BAD_REQUEST:
		pr_dbg(&ctx->lh, "Refusing HTTP request (fd=%d)", gcp->client.fd);
		return http_reject_bad_request(gcp);
	case GWP_HTTP_TOO_LARGE:
		pr_dbg(&ctx->lh, "HTTP request header too large (fd=%d)",
		       gcp->client.fd);
		return http_reject_too_large(gcp);
	default:	/* GWP_HTTP_ERR */
		pr_dbg(&ctx->lh, "Invalid HTTP request (fd=%d)", gcp->client.fd);
		return -EINVAL;
	}
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
	/*
	 * An error here stops the whole proxy and becomes its exit status
	 * (see main()). Many of the paths that return one log nothing of
	 * their own, so say here, once per worker, which worker stopped and
	 * why.
	 */
	if (r < 0)
		pr_err(&ctx->lh, "Worker %u stopped on an error, stopping the proxy: %s",
		       w->idx, strerror(-r));
	else
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

static struct gwp_ctx *_Atomic g_ctx = NULL;
static atomic_int g_nr_sig_handlers = 0;

/*
 * Ask the reload thread to reload the files (see gwp_reload_thread()). Called
 * from the signal handler, so it only sets the flag and wakes the thread: an
 * atomic store and a write(2) are async-signal-safe. A full eventfd counter
 * (EAGAIN) still has the thread awake, so the result needs no check.
 */
__cold
static void gwp_ctx_hup(struct gwp_ctx *ctx)
{
	uint64_t one = 1;

	atomic_store(&ctx->reload_hup, true);
	(void)__sys_write(ctx->hup_efd, &one, sizeof(one));
}

/*
 * Runs on whichever thread the signal lands on, possibly in the middle of a
 * worker's event loop, so gwp_ctx_stop() and gwp_ctx_hup() must stay
 * async-signal-safe: set a flag and wake a thread through its eventfd,
 * nothing more.
 */
__cold
static void sig_handler(int sig)
{
	int saved_errno = errno;
	struct gwp_ctx *ctx;

	atomic_fetch_add(&g_nr_sig_handlers, 1);
	ctx = atomic_load(&g_ctx);
	if (ctx) {
		if (sig == SIGHUP)
			gwp_ctx_hup(ctx);
		else
			gwp_ctx_stop(ctx);
	}
	atomic_fetch_sub(&g_nr_sig_handlers, 1);

	errno = saved_errno;
}

/*
 * The context is about to go, and main()'s frame with it, but a signal can
 * still arrive: timeout(1) sends its SIGTERM twice, and exit() may take a while
 * yet. Have the handler leave it alone, and wait out one running on another
 * thread. This thread is the last one left once the context is freed, so keep
 * the signals pending on it from here on: there is nothing left for them to
 * stop, and one landing in exit() can upset what runs there, such as the
 * leak check of a sanitizer build, which stops the process with ptrace.
 */
__cold
static void sig_handler_detach_ctx(void)
{
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGHUP);
	pthread_sigmask(SIG_BLOCK, &set, NULL);
	atomic_store(&g_ctx, NULL);
	while (atomic_load(&g_nr_sig_handlers))
		sched_yield();
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

/*
 * Give any of fds 0-2 that was closed to /dev/null. The default log target is
 * fd 1 whatever it has become: left closed, the next descriptor we open takes
 * its number, and the log lines go to the PID file or a client's socket.
 */
__cold
static int open_std_fds(void)
{
	int fd;

	for (fd = 0; fd <= 2; fd++) {
		if (fcntl(fd, F_GETFD) >= 0 || errno != EBADF)
			continue;
		/* The lowest free number, so this one: the lower ones are open. */
		if (open("/dev/null", O_RDWR) < 0)
			return -errno;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	struct sigaction sa = { .sa_handler = SIG_IGN };
	struct gwp_ctx ctx;
	sigset_t hup;
	int r;

	/*
	 * Until its handler is in place, a SIGHUP would kill the proxy, and
	 * the startup can take a while (a large ACL, a log FIFO): keep it
	 * pending instead, to be taken as a reload once the handler is in.
	 * The threads started meanwhile inherit the block and keep it, so a
	 * SIGHUP lands on this thread, worker 0, alone.
	 */
	sigemptyset(&hup);
	sigaddset(&hup, SIGHUP);
	pthread_sigmask(SIG_BLOCK, &hup, NULL);

	memset(&ctx, 0, sizeof(ctx));
	r = open_std_fds();
	if (r < 0) {
		fprintf(stderr, "Failed to open /dev/null: %s\n", strerror(-r));
		goto out;
	}

	/* Before the first log line: its target may be a pipe nobody reads. */
	r = sigaction(SIGPIPE, &sa, NULL);
	if (r < 0) {
		r = -errno;
		fprintf(stderr, "Failed to set signal handlers: %s\n", strerror(-r));
		goto out;
	}

	r = parse_options(argc, argv, &ctx.cfg);
	if (r < 0)
		goto out;

	prepare_rlimit();
	r = gwp_ctx_init(&ctx);
	if (r < 0)
		goto out;

	atomic_store(&g_ctx, &ctx);
	sa.sa_handler = &sig_handler;
	r |= sigaction(SIGINT, &sa, NULL);
	r |= sigaction(SIGTERM, &sa, NULL);
	/*
	 * A SIGHUP reloads the files and the proxy goes on, so let the system
	 * calls it interrupts restart where they can; the workers' waits
	 * (epoll_wait, io_uring_enter) never do and take the EINTR as a
	 * spurious wakeup.
	 */
	sa.sa_flags = SA_RESTART;
	r |= sigaction(SIGHUP, &sa, NULL);
	if (r < 0) {
		r = -errno;
		fprintf(stderr, "Failed to set signal handlers: %s\n", strerror(-r));
		goto out_free;
	}
	/*
	 * A SIGINT or SIGTERM held since gwp_ctx_init() started the threads
	 * is taken here and stops the proxy before a worker runs: each worker
	 * finds ctx.stop set and leaves its loop at once, and the proxy exits
	 * as on any other stop.
	 */
	gwp_block_stop_signals(SIG_UNBLOCK);
	pthread_sigmask(SIG_UNBLOCK, &hup, NULL);

	r = gwp_ctx_run(&ctx);
out_free:
	sig_handler_detach_ctx();
	gwp_ctx_free(&ctx);
	/* Worker 0 leaves cleanly when another worker's error stopped it. */
	if (!r)
		r = ctx.worker_err;
out:
	return -r;
}
