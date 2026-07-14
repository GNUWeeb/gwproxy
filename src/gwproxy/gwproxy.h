// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWPROXY_H
#define GWPROXY_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <gwproxy/syscall.h>
#include <gwproxy/socks5.h>
#include <gwproxy/auth.h>
#include <gwproxy/dns.h>
#include <gwproxy/log.h>
#include <assert.h>
#ifdef CONFIG_IO_URING
#include <liburing.h>
#endif

#ifdef CONFIG_NEW_DNS_RESOLVER
#include <gwproxy/dns_resolver.h>
#endif

#include <gwproxy/http1.h>

struct gwp_cfg {
	const char	*event_loop;
	const char	*bind;
	const char	*target;
	bool		as_socks5;
	bool		as_http;
	bool		socks5_prefer_ipv6;
	bool		use_raw_dns;
	int		protocol_timeout;
	const char	*auth_file;
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
	const char	*dns_servers;
	const char	*upstream_socks5;
	int		mark;
	bool		as_transparent;
};

struct gwp_ctx;

/*
 * Parsed form of the --upstream-socks5 option. When @enabled, every outgoing
 * connection is routed through this upstream SOCKS5 proxy instead of being
 * connected to directly. Populated once at startup and shared read-only by
 * all workers.
 */
struct gwp_upstream_s5 {
	bool			enabled;
	bool			remote_dns;	/* socks5h:// (proxy resolves) */
	bool			has_auth;
	uint8_t			ulen;
	uint8_t			plen;
	struct gwp_sockaddr	addr;		/* proxy endpoint */
	char			user[256];
	char			pass[256];
};

int gwp_parse_upstream_socks5(const char *url, struct gwp_upstream_s5 *up);

enum {
	EV_BIT_ACCEPT			= (1ull << 48ull),
	EV_BIT_EVENTFD			= (2ull << 48ull),
	EV_BIT_TARGET			= (3ull << 48ull),
	EV_BIT_CLIENT			= (4ull << 48ull),
	EV_BIT_TIMER			= (5ull << 48ull),
	EV_BIT_CLIENT_SOCKS5		= (6ull << 48ull),
	EV_BIT_DNS_QUERY		= (7ull << 48ull),
	EV_BIT_SOCKS5_AUTH_FILE		= (8ull << 48ull),

	EV_BIT_HTTP_CONN		= (18ull << 48ull),
	EV_BIT_RAW_DNS_QUERY		= (19ull << 48ull),

	/*
	 * This ev_bit is used for user_data masking during protocol
	 * initalization.
	 *
	 * Supported protocols:
	 *   - SOCKS5
	 *   - HTTP
	 *
	 * It means it waits for the data specific protocol before
	 * solely forwarding the received data to the destination host.
	 */
	EV_BIT_CLIENT_PROT		= (1000ull << 48ull),

#ifdef CONFIG_IO_URING
	/*
	 * Only used by io_uring.
	 */
	EV_BIT_IOU_DNS_QUERY		= EV_BIT_DNS_QUERY,
	EV_BIT_IOU_SOCKS5_AUTH_FILE	= EV_BIT_SOCKS5_AUTH_FILE,
	EV_BIT_IOU_TIMER		= EV_BIT_TIMER,
	EV_BIT_IOU_ACCEPT		= EV_BIT_ACCEPT,
	EV_BIT_IOU_CLIENT_PROT		= EV_BIT_CLIENT_SOCKS5,
	EV_BIT_IOU_CLIENT_RECV		= EV_BIT_CLIENT,
	EV_BIT_IOU_TARGET_RECV		= EV_BIT_TARGET,
	EV_BIT_IOU_TARGET_SEND		= (9ull << 48ull),
	EV_BIT_IOU_CLIENT_SEND		= (10ull << 48ull),
	EV_BIT_IOU_CLOSE		= (11ull << 48ull),
	EV_BIT_IOU_TARGET_CONNECT	= (12ull << 48ull),
	EV_BIT_IOU_TARGET_CANCEL	= (13ull << 48ull),
	EV_BIT_IOU_CLIENT_CANCEL	= (14ull << 48ull),
	EV_BIT_IOU_TIMER_DEL		= (15ull << 48ull),
	EV_BIT_IOU_MSG_RING		= (16ull << 48ull),
	EV_BIT_IOU_UPSTREAM_S5		= (20ull << 48ull),
	EV_BIT_IOU_ACCEPT_RETRY		= (21ull << 48ull),
#endif
};


#define EV_BIT_ALL	(0xffffull << 48ull)
#define GET_EV_BIT(X)	((X) & EV_BIT_ALL)
#define CLEAR_EV_BIT(X)	((X) & ~EV_BIT_ALL)

enum {
	CONN_STATE_INIT			= 0,
	CONN_STATE_FORWARDING		= 1,

	CONN_STATE_SOCKS5_MIN		= 100,
	CONN_STATE_SOCKS5_DATA		= 101,
	CONN_STATE_SOCKS5_CONNECT	= 102,
	CONN_STATE_SOCKS5_DNS_QUERY	= 104,
	CONN_STATE_SOCKS5_MAX		= 199,

	/*
	 * The target socket is connected to an upstream SOCKS5 proxy and we
	 * are performing the client-side handshake with it before forwarding.
	 */
	CONN_STATE_UPSTREAM_S5_MIN	= 200,
	CONN_STATE_UPSTREAM_S5_METHOD	= 201,	/* await method selection    */
	CONN_STATE_UPSTREAM_S5_AUTH	= 202,	/* await user/pass status    */
	CONN_STATE_UPSTREAM_S5_CONNECT	= 203,	/* await CONNECT reply       */
	CONN_STATE_UPSTREAM_S5_MAX	= 299,

	CONN_STATE_HTTP_MIN		= 400,
	CONN_STATE_HTTP_HDR		= 401,
	CONN_STATE_HTTP_CONNECT		= 402,
	CONN_STATE_HTTP_DNS_QUERY	= 403,
	CONN_STATE_HTTP_MAX		= 499,

	/*
	 * Still waiting for protocol specific. Can be one of these:
	 *    - SOCKS5
	 *    - HTTP
	 */
	CONN_STATE_PROT			= 500,
};

struct gwp_conn {
	int		fd;
	uint32_t	len;
	uint32_t	cap;
	char		*buf;
	uint32_t	ep_mask;

	/*
	 * Half-close bookkeeping for the forwarding path. @rd_eof is set once
	 * this fd's read side has reached EOF (the peer closed its write side
	 * and we have drained everything). @wr_shut is set once we have shut
	 * this fd's write side (propagated the peer's EOF towards it). The
	 * connection pair is torn down only after both directions have been
	 * fully drained and shut, so no buffered data is dropped on close.
	 */
	bool		rd_eof;
	bool		wr_shut;
};

enum {
	/*
	 * Don't close the file descriptor when freeing the connection pair.
	 */
	GWP_CONN_FLAG_NO_CLOSE_FD	= (1ull << 0ull),
	GWP_CONN_FLAG_IS_DYING		= (1ull << 1ull),
	GWP_CONN_FLAG_IS_CANCEL		= (1ull << 2ull),
};

enum {
	GWP_PROT_TYPE_NONE	= 0,
	GWP_PROT_TYPE_SOCKS5	= 1,
	GWP_PROT_TYPE_HTTP	= 2,
};

struct gwp_http_conn {
	struct gwnet_http_hdr_pctx	ctx_hdr;
	struct gwnet_http_req_hdr	req_hdr;
};

struct gwp_dns_packet;

struct gwp_conn_pair {
	struct gwp_conn		target;
	struct gwp_conn		client;
	bool			is_target_alive;
	uint8_t			prot_type;

#ifdef CONFIG_IO_URING
	int				ref_cnt;
	struct __kernel_timespec	ts;
#endif

	uint64_t		flags;
	int			conn_state;
	int			timer_fd;
	uint32_t		idx;
	union {
		struct gwp_socks5_conn	*s5_conn;
		struct gwp_http_conn	*http_conn;
	};
	union {
		struct gwp_dns_entry	*gde;
		struct gwp_dns_packet	*gdp;
	};
	struct gwp_sockaddr	client_addr;
	struct gwp_sockaddr	target_addr;

	/*
	 * Destination requested from the upstream SOCKS5 proxy. Only used
	 * when ctx->upstream.enabled. For socks5:// this is filled from
	 * target_addr (an IP); for socks5h:// it carries the hostname.
	 */
	struct gwp_socks5_addr	up_dst;

	/*
	 * True while an upstream-handshake request is still being flushed to
	 * the proxy (target buffer holds outbound bytes); false while awaiting
	 * a reply.
	 */
	bool			up_tx;
};


struct gwp_conn_slot {
	struct gwp_conn_pair	**pairs;
	uint32_t		nr;
	uint32_t		cap;
};

#ifdef CONFIG_IO_URING
struct iou {
	struct io_uring		ring;
	struct gwp_sockaddr	accept_addr;
	socklen_t		accept_addr_len;

	/*
	 * Deadline for the accept-retry timer armed when accept() is paused
	 * due to fd exhaustion (EMFILE/ENFILE). Must outlive SQE submission.
	 */
	struct __kernel_timespec accept_retry_ts;
};
#endif

struct gwp_dns_resolver;

struct gwp_wrk_dns {
	struct gwp_dns_resolver		*resolvers;
	uint32_t			nr;
};

struct gwp_wrk {
	int			tcp_fd;
	struct gwp_conn_slot	conn_slot;

	union {
		struct {
			int			ep_fd;
			int			ev_fd;
			struct epoll_event	*events;
			uint16_t		evsz;
			/*
			 * If it's true, the worker MUST call epoll_wait() again
			 * before continue iterating over the events.
			 */
			bool			ev_need_reload;
		};
#ifdef CONFIG_IO_URING
		struct iou	*iou;
#endif
	};

	bool			accept_is_stopped;
	bool			need_join;
	struct gwp_ctx		*ctx;
	uint32_t		idx;
	pthread_t		thread;

#ifdef CONFIG_NEW_DNS_RESOLVER
	struct gwp_wrk_dns	*dns;
#endif
};

enum {
	GWP_EV_EPOLL,
	GWP_EV_IO_URING
};

struct gwp_ctx {
	volatile bool			stop;
	uint8_t				ev_used;
	struct log_handle		lh;
	struct gwp_wrk			*workers;
	struct gwp_sockaddr		target_addr;
	struct gwp_socks5_ctx		*socks5;
	struct gwp_auth			*auth;
	struct gwp_dns_ctx		*dns;
	struct gwp_upstream_s5		upstream;
	struct gwp_cfg			cfg;
	int				ino_fd;
	char				*ino_buf;
	_Atomic(int32_t)		nr_fd_closed;
	_Atomic(int32_t)		nr_accept_stopped;
};

struct gwp_conn_pair *gwp_alloc_conn_pair(struct gwp_wrk *w);
int gwp_free_conn_pair(struct gwp_wrk *w, struct gwp_conn_pair *gcp);
int gwp_create_sock_target(struct gwp_wrk *w, struct gwp_sockaddr *addr,
			   bool *is_target_alive, bool non_block);
int gwp_create_timer(int fd, int sec, int nsec);
void gwp_setup_cli_sock_options(struct gwp_wrk *w, int fd);
int gwp_get_orig_dst(int fd, const struct gwp_sockaddr *client,
		     struct gwp_sockaddr *dst);
const char *ip_to_str(const struct gwp_sockaddr *gs);

static inline void gwp_conn_buf_advance(struct gwp_conn *conn, size_t len)
{
	assert(len <= conn->len);
	conn->len -= len;
	if (conn->len)
		memmove(conn->buf, conn->buf + len, conn->len);
}

static inline
void log_conn_pair_created(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	pr_info(&ctx->lh, "New connection pair created (idx=%u, cfd=%d, tfd=%d, ca=%s, ta=%s)",
		gcp->idx, gcp->client.fd, gcp->target.fd,
		ip_to_str(&gcp->client_addr), ip_to_str(&gcp->target_addr));
}

int gwp_socks5_prep_connect_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				  int err);
int gwp_socks5_build_connect_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				   int err, void *out, size_t *out_len);
int gwp_socks5_prepare_target_addr(struct gwp_wrk *w, struct gwp_conn_pair *gcp);
int gwp_upstream_finalize_dst(struct gwp_wrk *w, struct gwp_conn_pair *gcp);

struct gwp_http_conn *gwp_http_conn_alloc(void);
void gwp_http_conn_free(struct gwp_http_conn *conn);
int gwp_socks5_handle_data(struct gwp_conn_pair *gcp);
int gwp_handle_conn_state_prot(struct gwp_wrk *w, struct gwp_conn_pair *gcp);
int gwp_handle_conn_state_socks5(struct gwp_wrk *w, struct gwp_conn_pair *gcp);
int gwp_handle_conn_state_http(struct gwp_wrk *w, struct gwp_conn_pair *gcp);

#endif /* #ifndef GWPROXY_H */
