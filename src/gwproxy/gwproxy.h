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
#include <gwproxy/http.h>
#include <gwproxy/dns.h>
#include <gwproxy/acl.h>
#include <gwproxy/iplimit.h>
#include <gwproxy/log.h>
#include <assert.h>
#include <stdatomic.h>
#include <time.h>
#ifdef CONFIG_IO_URING
#include <liburing.h>
#endif

#ifdef CONFIG_NEW_DNS_RESOLVER
#include <gwproxy/dns_resolver.h>
#endif

#include <gwproxy/http1.h>

/*
 * Forward declarations for the optional TLS module (src/gwproxy/ssl.c, built
 * only under CONFIG_HTTPS). The pointers below are always present but stay NULL
 * and unused unless TLS is compiled in and configured.
 */
struct gwp_ssl_ctx;
struct gwp_ssl;
struct gwp_iou_tls;
struct gwp_iou_udp;
struct gwp_acl;

/*
 * Which address family outgoing (target) connections may use. IPv4/IPv6 force
 * DNS to resolve that family only and refuse a literal target of the other one;
 * ANY leaves the choice to DNS and --prefer-ipv6.
 */
enum {
	GWP_OUT_FAMILY_ANY	= 0,
	GWP_OUT_FAMILY_IPV4	= 1,
	GWP_OUT_FAMILY_IPV6	= 2,
};

struct gwp_cfg {
	const char	*event_loop;
	const char	*bind;
	const char	*target;
	bool		as_socks5;
	bool		as_http;
	bool		udp_associate;	/* allow SOCKS5 UDP ASSOCIATE (default on) */
	bool		prefer_ipv6;
	uint8_t		outgoing_family;/* enum GWP_OUT_FAMILY_* */
	bool		bind_ipv6_only;	/* IPV6_V6ONLY on the listener */
	bool		use_raw_dns;
	int		protocol_timeout;
	const char	*auth_file;
	const char	*acl_file;
	bool		acl_allow_all;	/* skip the built-in default ACL */
	int		dns_cache_secs;
	int		dns_cache_max_entries;	/* cap; <=0 = unlimited */
	int		nr_workers;
	int		nr_dns_workers;
	int		connect_timeout;
	/*
	 * Close a tunnel or UDP association that has moved no data for this
	 * many seconds; 0 keeps them for as long as both ends do.
	 */
	int		idle_timeout;
	/*
	 * Most client connections held at once per client address (IPv4) or
	 * /64 (IPv6), see iplimit.h; 0 for no cap.
	 */
	int		max_conns_per_ip;
	/*
	 * Happy Eyeballs Connection Attempt Delay in milliseconds (RFC 8305
	 * Section 5): how long before the next candidate address joins the
	 * race. 0 disables racing, leaving plain sequential fallback.
	 */
	int		connect_attempt_delay;
	int		target_buf_size;
	int		client_buf_size;
	bool		tcp_nodelay;
	bool		tcp_keepalive;
	int		tcp_keepidle;
	int		tcp_keepintvl;
	int		tcp_keepcnt;
	int		log_level;
	const char	*log_file;
	const char	*pid_file;
	const char	*dns_servers;
	const char	*upstream_proxy;
	const char	*upstream_auth_file;	/* user:pass for the upstream */
	uint32_t	mark;
	/*
	 * Global default for the ACL's -j BIND: the source address
	 * (--bind-source, "ip[:port]") and/or interface (--bind-iface) to pin
	 * outgoing connections to. Kept as the raw strings the user gave; they
	 * are parsed once into gwp_ctx::bind_def at startup.
	 */
	const char	*bind_source;
	const char	*bind_iface;
	bool		as_transparent;
	const char	*tls_cert;
	const char	*tls_key;
};

struct gwp_ctx;

enum {
	GWP_UPSTREAM_SOCKS5	= 0,
	GWP_UPSTREAM_HTTP	= 1,
};

/*
 * Parsed form of the --upstream-proxy option. When @enabled, every outgoing
 * connection is routed through this upstream proxy instead of being connected
 * to directly. The URL scheme picks @type (socks5[h]:// vs http[s]://) and, for
 * HTTP, whether the hop to the proxy is TLS (@use_tls, https://). Populated once
 * at startup and shared read-only by all workers.
 */
struct gwp_upstream {
	bool			enabled;
	uint8_t			type;		/* GWP_UPSTREAM_SOCKS5 / HTTP */
	bool			remote_dns;	/* socks5h:// (proxy resolves) */
	bool			use_tls;	/* https:// (TLS to the proxy) */
	bool			has_auth;
	uint8_t			ulen;
	uint8_t			plen;
	struct gwp_sockaddr	addr;		/* proxy endpoint */
	char			user[256];
	char			pass[256];
};

int gwp_parse_upstream(const char *url, struct gwp_upstream *up);

/*
 * How many of a name's addresses one connection may try. The resolver can hand
 * back more (GWP_DNS_MAX_ADDRS); this bounds what is copied per connection,
 * since every candidate costs memory in every conn pair.
 */
#define GWP_MAX_CONN_CAND	4u

enum {
	EV_BIT_ACCEPT			= (1ull << 48ull),
	EV_BIT_EVENTFD			= (2ull << 48ull),
	EV_BIT_TARGET			= (3ull << 48ull),
	EV_BIT_CLIENT			= (4ull << 48ull),
	EV_BIT_TIMER			= (5ull << 48ull),
	EV_BIT_CLIENT_SOCKS5		= (6ull << 48ull),
	EV_BIT_DNS_QUERY		= (7ull << 48ull),
	/*
	 * 8 was the inotify watch for the auth and ACL files, now polled by
	 * the reload thread instead of worker 0.
	 */

	/*
	 * Raw DNS resolver socket (--raw-dns), epoll only. Values 9-21 belong
	 * to the io_uring selectors below, so use 26 -- this used to be 19,
	 * which is EV_BIT_IOU_TLS_HS_SEND.
	 */
	EV_BIT_RAW_DNS_QUERY		= (26ull << 48ull),

	/*
	 * Per-connection UDP relay socket for a SOCKS5 UDP ASSOCIATE. Values
	 * 9-21 are reserved by the io_uring aliases below, so use 22.
	 */
	EV_BIT_UDP_RELAY		= (22ull << 48ull),

	/* 25 was the ACL file's own inotify watch. */

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
	/*
	 * One in-flight connect attempt of a Happy Eyeballs race, plus N for
	 * the attempt's slot, so the completion can be attributed without
	 * disturbing the conn-pair pointer in the low bits. Values 32..47 are
	 * reserved for this.
	 */
	EV_BIT_TARGET_ATTEMPT		= (32ull << 48ull),

	/*
	 * Fires when it is time to start the next attempt in the race. Only
	 * the io_uring loop has timer events; the epoll loop runs its timers
	 * from a heap (ev/tmr.h).
	 */
	EV_BIT_ATTEMPT_TIMER		= (48ull << 48ull),

	EV_BIT_CLIENT_PROT		= (1000ull << 48ull),

#ifdef CONFIG_IO_URING
	/*
	 * Only used by io_uring.
	 */
	EV_BIT_IOU_DNS_QUERY		= EV_BIT_DNS_QUERY,
	EV_BIT_IOU_TIMER		= EV_BIT_TIMER,
	EV_BIT_IOU_ACCEPT		= EV_BIT_ACCEPT,
	EV_BIT_IOU_CLIENT_PROT		= EV_BIT_CLIENT_SOCKS5,
	EV_BIT_IOU_CLIENT_RECV		= EV_BIT_CLIENT,
	EV_BIT_IOU_TARGET_RECV		= EV_BIT_TARGET,
	EV_BIT_IOU_TARGET_SEND		= (9ull << 48ull),
	EV_BIT_IOU_CLIENT_SEND		= (10ull << 48ull),
	EV_BIT_IOU_CLOSE		= (11ull << 48ull),
	/* 12 was the single target connect, now EV_BIT_TARGET_ATTEMPT. */
	EV_BIT_IOU_TARGET_CANCEL	= (13ull << 48ull),
	EV_BIT_IOU_CLIENT_CANCEL	= (14ull << 48ull),
	EV_BIT_IOU_TIMER_DEL		= (15ull << 48ull),
	EV_BIT_IOU_STOP			= (16ull << 48ull),
	EV_BIT_IOU_TLS_DETECT		= (17ull << 48ull),
	EV_BIT_IOU_TLS_HS_RECV		= (18ull << 48ull),
	EV_BIT_IOU_TLS_HS_SEND		= (19ull << 48ull),
	EV_BIT_IOU_UPSTREAM_S5		= (20ull << 48ull),
	EV_BIT_IOU_ACCEPT_RETRY		= (21ull << 48ull),

	/*
	 * SOCKS5 UDP relay on io_uring. The recvmsg reuses the shared
	 * EV_BIT_UDP_RELAY (22); the sendmsg and the fd-cancel need their own
	 * selectors so the completion dispatch can tell them apart.
	 */
	EV_BIT_IOU_UDP_RX		= EV_BIT_UDP_RELAY,
	EV_BIT_IOU_UDP_TX		= (23ull << 48ull),
	EV_BIT_IOU_UDP_CANCEL		= (24ull << 48ull),

	/*
	 * Happy Eyeballs on io_uring. The attempt-delay timeout shares the
	 * generic EV_BIT_ATTEMPT_TIMER selector, but it needs a removal key
	 * distinct from the connect timer's (EV_BIT_IOU_TIMER | gcp): the two
	 * are live at the same time, and io_uring_prep_timeout_remove()
	 * addresses a timeout solely by its user_data. A losing attempt's
	 * socket is retired with its own cancel selector so the completion is
	 * not mistaken for the adopted target's.
	 */
	EV_BIT_IOU_ATTEMPT_TIMER	= EV_BIT_ATTEMPT_TIMER,
	EV_BIT_IOU_ATTEMPT_TIMER_DEL	= (49ull << 48ull),
	EV_BIT_IOU_ATTEMPT_CANCEL	= (50ull << 48ull),
#endif
};


/*
 * The event word packs a payload pointer in bits 0..47 and a selector in bits
 * 48..63. That is sound on Linux because the kernel will not hand userspace a
 * virtual address above the 47-bit default mapping window unless the process
 * asks for one with an mmap() hint above 2^47 -- a policy the kernel adopted
 * *precisely* to keep pointer-tagging schemes like this one working when
 * 5-level paging widened the hardware VA to 57 bits. See
 * Documentation/arch/x86/x86_64/5level-paging.rst ("we are not going to
 * allocate virtual address space above 47-bit by default") and
 * Documentation/arch/arm64/memory.rst, where the default window is 48-bit and
 * 52-bit needs the same opt-in. Note bit 47 is live on arm64, which is why the
 * selector starts at 48 and not 47.
 *
 * gwproxy never opts in: every tagged payload comes from calloc(), and there
 * is no mmap()/MAP_FIXED/arch_prctl() anywhere in this tree. So a 57-bit-VA
 * host does not break the encoding.
 *
 * Do not introduce a high mmap() hint, arm64 MTE/HWASAN heap tagging, or x86
 * LAM without revisiting this. EV_PTR_OK() is the enforcement, and it is
 * deliberately not assert(): release builds define NDEBUG (Makefile, configure)
 * and would compile the check out exactly where it matters.
 *
 * Combine the halves arithmetically, never by writing a pointer through one
 * union member and the selector through another -- on a 32-bit big-endian
 * target epoll_data.ptr aliases the *high* half of .u64 and the two overlap.
 */
#define EV_BIT_ALL	(0xffffull << 48ull)
#define GET_EV_BIT(X)	((X) & EV_BIT_ALL)
#define CLEAR_EV_BIT(X)	((X) & ~EV_BIT_ALL)
#define EV_PTR_OK(P)	(!((uint64_t)(uintptr_t)(P) & EV_BIT_ALL))

static_assert((EV_BIT_CLIENT_PROT & ~EV_BIT_ALL) == 0,
	      "the largest event selector must fit inside EV_BIT_ALL");

enum {
	CONN_STATE_INIT			= 0,
	CONN_STATE_FORWARDING		= 1,

	CONN_STATE_SOCKS5_MIN		= 100,
	CONN_STATE_SOCKS5_DATA		= 101,
	CONN_STATE_SOCKS5_CONNECT	= 102,
	CONN_STATE_SOCKS5_UDP_ASSOCIATE	= 103,	/* relay active; TCP conn idle */
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

	/*
	 * The target socket is connected to an upstream HTTP proxy and we are
	 * performing an HTTP CONNECT to it before forwarding.
	 */
	CONN_STATE_UPSTREAM_HTTP_MIN	= 300,
	CONN_STATE_UPSTREAM_HTTP_CONNECT = 301,	/* await "HTTP/1.x 2xx"      */
	CONN_STATE_UPSTREAM_HTTP_MAX	= 399,

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

	/*
	 * HTTPS proxy: the listener may speak TLS. TLS_DETECT peeks the first
	 * byte to tell a TLS ClientHello (0x16) from a plaintext SOCKS5/HTTP
	 * client; TLS_HANDSHAKE runs the server-side handshake. Both are
	 * serviced under EV_BIT_CLIENT_PROT (EPOLLIN and EPOLLOUT). On success
	 * the connection continues at CONN_STATE_PROT on the decrypted stream.
	 */
	CONN_STATE_TLS_MIN		= 600,
	CONN_STATE_TLS_DETECT		= 601,
	CONN_STATE_TLS_HANDSHAKE	= 602,
	CONN_STATE_TLS_MAX		= 699,
};

struct gwp_conn {
	int		fd;
	/*
	 * @buf points at the first byte not consumed yet and holds @len bytes
	 * of data, with room for @cap bytes from @buf. @off bytes in front of
	 * @buf were already consumed (the allocation starts at buf - off).
	 * gwp_conn_buf_consume() only moves @buf forward, so a partial send
	 * does not shift the rest of the data down; gwp_conn_buf_compact()
	 * moves it back to the start of the allocation.
	 */
	uint32_t	len;
	uint32_t	cap;
	uint32_t	off;
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

	/*
	 * TLS state for this endpoint (HTTPS proxy). NULL for a plaintext
	 * endpoint; only the client side is ever TLS in this cut. Once set and
	 * the handshake has completed, __do_recv()/__do_send() transparently
	 * decrypt/encrypt through it. Owned here and released in
	 * gwp_free_conn_pair().
	 */
	struct gwp_ssl	*tls;
};

enum {
	/*
	 * Don't close the file descriptor when freeing the connection pair.
	 */
	GWP_CONN_FLAG_NO_CLOSE_FD	= (1ull << 0ull),
	GWP_CONN_FLAG_IS_DYING		= (1ull << 1ull),
	GWP_CONN_FLAG_IS_CANCEL		= (1ull << 2ull),
	/*
	 * At least one candidate address made it past the OUTPUT chain, so a
	 * later denial cannot be the reason the request failed. Sticky for the
	 * life of the pair: the candidate walk is re-entered once per failed
	 * attempt, and a local would only remember the most recent walk.
	 */
	GWP_CONN_FLAG_ACL_CAND_OK	= (1ull << 3ull),
	/*
	 * The target socket could not be created for want of descriptors and
	 * the connect is being retried; set so that this is logged once per
	 * pair rather than on every retry. io_uring only: the epoll loop logs
	 * when it puts the pair on its own wait list (gwp_wrk::tgt_wait) and
	 * retries from that list, so it never logs a retry and needs no flag.
	 */
	GWP_CONN_FLAG_FD_WAIT		= (1ull << 4ull),
	/*
	 * The client is counted in gwp_ctx::iplim, so freeing the pair must
	 * uncount it (gwp_ctx_iplim_put()).
	 */
	GWP_CONN_FLAG_IPLIM		= (1ull << 5ull),
};

enum {
	GWP_PROT_TYPE_NONE	= 0,
	GWP_PROT_TYPE_SOCKS5	= 1,
	GWP_PROT_TYPE_HTTP	= 2,
};

struct gwp_dns_packet;

/*
 * Per-connection socket options that the ACL OUTPUT chain can impose on the
 * outgoing target socket (composable -j MARK / -j BIND modifiers). Built from
 * the ACL result and applied in gwp_create_sock_target() before connect(). A
 * NULL pointer (or all-unset fields) means "use the global defaults".
 */
struct gwp_conn_sockopt {
	bool			mark_set;	/* -j MARK: use @mark, not cfg.mark */
	uint32_t		mark;		/* SO_MARK value */
	struct gwp_acl_bind	bind;		/* -j BIND: bind.set when present */
};

/*
 * A UDP association's last client->target ACL verdict: @ok for @dst, valid
 * while @valid and the ACL is still at generation @gen.
 */
struct gwp_udp_acl_cache {
	struct gwp_sockaddr	dst;
	uint32_t		gen;
	bool			valid;
	bool			ok;
};

/*
 * The targets a UDP association's client has sent to, the only sources the
 * relay accepts replies from. Each entry is an exact address and port whose
 * last datagram the ACL accepted at generation @gen[i]; @seq[i] records when
 * the client last sent to it, so a full table evicts the least recently
 * used. Allocated on the association's first relayed datagram.
 */
#define GWP_UDP_MAX_PEERS	32

struct gwp_udp_peers {
	struct gwp_sockaddr	addr[GWP_UDP_MAX_PEERS];
	uint32_t		gen[GWP_UDP_MAX_PEERS];
	uint32_t		seq[GWP_UDP_MAX_PEERS];
	uint32_t		next_seq;
	uint8_t			nr;
	uint8_t			last;	/* index of the last hit */
};

struct gwp_conn_pair {
	/*
	 * Field order here is deliberate: members are grouped by alignment,
	 * widest first, with the one-byte scalars collected at the end. Laid
	 * out in logical order instead, the small members scatter and leave
	 * 22 bytes of holes. Keep new members in the group that matches their
	 * alignment rather than next to the code that uses them; `pahole -C
	 * gwp_conn_pair src/gwproxy/gwproxy.c.o` reports the damage if not.
	 */
	struct gwp_conn		target;
	struct gwp_conn		client;
	uint64_t		flags;

#ifdef CONFIG_IO_URING
	struct __kernel_timespec	ts;
	/*
	 * The Connection Attempt Delay needs its own timespec: an armed
	 * io_uring timeout keeps reading the struct it was given, so it cannot
	 * share @ts with the connect timer that is live alongside it.
	 * @attempt_timer_armed (below) tracks whether one is outstanding, since
	 * io_uring has no timerfd to test for.
	 */
	struct __kernel_timespec	ats;
#ifdef CONFIG_HTTPS
	/*
	 * Persistent ciphertext scratch for the client's TLS on the io_uring
	 * loop. Unlike epoll (synchronous stack scratch), an async recv/send
	 * needs the wire buffers to outlive the operation. Allocated when a TLS
	 * handshake starts, freed in gwp_free_conn_pair().
	 */
	struct gwp_iou_tls		*tls_io;
#endif
#endif

	union {
		struct gwp_socks5_conn	*s5_conn;
		struct gwp_http_conn	*http_conn;
	};
	union {
		struct gwp_dns_entry	*gde;
		struct gwp_dns_packet	*gdp;
	};

	/*
	 * @udp_iou is the io_uring UDP relay's per-connection async scratch
	 * (msghdr + buffer), NULL on the epoll loop which relays synchronously
	 * into the per-worker udp_buf.
	 */
	struct gwp_iou_udp	*udp_iou;
	/* Targets a UDP association may hear from; NULL until it sends. */
	struct gwp_udp_peers	*udp_peers;

	/*
	 * The hostname the client asked for, when it used a domain target
	 * (SOCKS5 ATYP 0x03 or an HTTP host), for ACL "-m domain" matching.
	 * Points into s5_conn/http_conn and stays valid for the connection's
	 * life; NULL for literal-IP requests.
	 */
	const char		*req_domain;

	int			conn_state;
	int			timer_fd;
	/*
	 * @udp_fd is the per-connection bound UDP socket a SOCKS5 UDP
	 * ASSOCIATE client sends datagrams to (-1 when not a UDP association);
	 * its lifetime is tied to this (TCP control) connection.
	 */
	int			udp_fd;
	/*
	 * The epoll loop's timers of this pair (GWP_TMR_*): where each sits in
	 * the worker's timer heap, plus one, or 0 while it is not armed. The
	 * protocol, connect and idle timeouts share GWP_TMR_CONN; the delay
	 * before the next connect attempt joins the race is GWP_TMR_ATTEMPT,
	 * separate because it runs alongside the connect timeout.
	 */
	uint32_t		tmr_pos[2];
	uint32_t		idx;
#ifdef CONFIG_IO_URING
	int			ref_cnt;
#endif

	/*
	 * Connect attempts still in flight, one slot per candidate already
	 * started, -1 when idle. Happy Eyeballs races several at once, so the
	 * winner is not known until one of them reports success; the winning
	 * fd then moves into target.fd and the rest are closed.
	 */
	int			attempt_fd[GWP_MAX_CONN_CAND];

	/*
	 * @udp_peer is the UDP client's source address, pinned from its first
	 * datagram (@udp_pinned); datagrams from other sources are replies,
	 * relayed only from a target in @udp_peers.
	 */
	struct gwp_sockaddr	udp_peer;
	/* Last client->target datagram's ACL verdict; see udp_target_allowed(). */
	struct gwp_udp_acl_cache	udp_acl;
	struct gwp_sockaddr	client_addr;
	struct gwp_sockaddr	target_addr;

	/*
	 * Candidate target addresses, in the order they should be tried (see
	 * struct gwp_dns_entry). A name that resolves to several addresses
	 * fills all of them, so a dead address can be stepped over instead of
	 * failing the connection; a literal IP, a transparent redirect or an
	 * upstream proxy fills exactly one.
	 *
	 * @nr_cand is how many are valid, @next_cand the index of the first
	 * one not yet tried. target_addr always holds the candidate currently
	 * being attempted -- it is re-copied from here on every attempt, since
	 * a "-j DNAT" rule rewrites it in place.
	 */
	struct gwp_sockaddr	cand[GWP_MAX_CONN_CAND];

	/*
	 * The address each attempt actually dialled, captured after the ACL
	 * ran. It is not simply cand[slot]: a "-j DNAT" rule rewrites the
	 * destination in place, so the winner must be reported (and used for
	 * up_dst) as the rewritten address, not the resolved one.
	 */
	struct gwp_sockaddr	attempt_addr[GWP_MAX_CONN_CAND];

	/*
	 * Per-connection socket options from the ACL OUTPUT chain (-j MARK /
	 * -j BIND), filled by gwp_ctx_acl_target_allowed() and applied when the
	 * target socket is created.
	 */
	struct gwp_conn_sockopt	acl_sockopt;
	/* -m domain/-m user results shared by this candidate list's ACL checks. */
	struct gwp_acl_memo	acl_memo;

	/*
	 * Destination requested from the upstream SOCKS5 proxy. Only used
	 * when ctx->upstream.enabled. For socks5:// this is filled from
	 * target_addr (an IP); for socks5h:// it carries the hostname.
	 *
	 * This is the single largest member (262 bytes, mostly the 256-byte
	 * domain buffer) and is dead weight on every connection that does not
	 * chain through an upstream proxy.
	 */
	struct gwp_socks5_addr	up_dst;

	/*
	 * When the pair last had I/O (gwp_wrk::now), and so how long it has
	 * been idle once @idle_timer has replaced the handshake's timer.
	 */
	uint32_t		last_act;

	/*
	 * How much of an http:// upstream's CONNECT reply has been searched
	 * for the end of its header, so a reply arriving in pieces is not
	 * searched from its start again on every read.
	 */
	uint32_t		up_scan;

	/* One-byte scalars last, so they pack instead of each opening a hole. */
	bool			is_target_alive;
	/* The pair's timer is now the --idle-timeout check. */
	bool			idle_timer;
	uint8_t			prot_type;
	bool			udp_pinned;
	/*
	 * True while an upstream-handshake request is still being flushed to
	 * the proxy (target buffer holds outbound bytes); false while awaiting
	 * a reply.
	 */
	bool			up_tx;
	uint8_t			nr_cand;
	uint8_t			next_cand;
#ifdef CONFIG_IO_URING
	bool			attempt_timer_armed;
	/*
	 * Protocol/connect timeouts (EV_BIT_IOU_TIMER) still outstanding. Each
	 * holds a reference, so teardown has to remove them or the pair, and
	 * the client socket with it, stays open until they expire. A count
	 * rather than a flag: the protocol timer can still be pending when the
	 * connect timer is armed.
	 */
	uint8_t			nr_timers_armed;
	/*
	 * Requests in flight on the client, target and UDP relay sockets
	 * (recv, send, poll; not timeouts or cancels), so that teardown
	 * cancels only on the sockets that still have any.
	 */
	uint8_t			nr_ops_client;
	uint8_t			nr_ops_target;
	uint8_t			nr_ops_udp;
	/*
	 * A plaintext send of target.buf to the client is in flight. It
	 * covers the bytes that were there when it was queued, so another
	 * send must not be queued over them; its completion sends whatever
	 * was appended in the meantime.
	 */
	bool			client_tx;
#endif
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

	/*
	 * Stop doorbell: gwp_ctx_signal_all_io_uring() writes it, and a poll
	 * in this worker's own ring wakes the worker up.
	 */
	int			stop_efd;

	/*
	 * The last io_uring_submit_and_wait() failed with a transient error
	 * and is being retried (see fish_events()), so that it is logged
	 * once per episode rather than on every retry.
	 */
	bool			submit_stalled;
};
#endif

struct gwp_dns_resolver;

struct gwp_wrk_dns {
	struct gwp_dns_resolver		*resolvers;
	uint32_t			nr;
};

/*
 * Each worker owns its own cache lines: the conn slot fields are written on
 * every accept and close, and the loop fields next to them are read on every
 * iteration, so a worker must not share a line with its neighbour in the
 * workers array (which is allocated GWP_CACHELINE aligned).
 */
#define GWP_CACHELINE	64

/* What a timer of the epoll loop does when it expires. */
enum {
	/* The protocol, connect or idle timeout of the pair. */
	GWP_TMR_CONN		= 0,
	/* The next connect attempt joins the race. */
	GWP_TMR_ATTEMPT		= 1,
};

/* An entry of the epoll loop's per-worker timer heap. */
struct gwp_tmr {
	/* When it expires, in CLOCK_MONOTONIC milliseconds. */
	uint64_t		at_ms;
	struct gwp_conn_pair	*gcp;
	/* GWP_TMR_*, also the index into gcp->tmr_pos. */
	uint32_t		kind;
};

/* A binary min-heap of timers on gwp_tmr::at_ms (ev/tmr.h). */
struct gwp_tmr_heap {
	struct gwp_tmr		*tmr;
	uint32_t		nr;
	uint32_t		cap;
};

struct gwp_wrk {
	int			tcp_fd;
	struct gwp_conn_slot	conn_slot;

	union {
		struct {
			int			ep_fd;
			int			ev_fd;
			struct epoll_event	*events;
			/*
			 * Pairs torn down while the current batch of events is
			 * handled. They are only marked dying then, and freed
			 * once the batch is done, because a later event in the
			 * same batch may still point at them.
			 */
			struct gwp_conn_pair	**dead;
			/*
			 * The timers of every pair of this worker (see
			 * ev/tmr.h). They drive the epoll_wait() timeout, so
			 * a timer costs no descriptor and no system call.
			 */
			struct gwp_tmr_heap	tmrs;
			/*
			 * When to retry what is waiting on a timed pause
			 * (accept, see handle_accept_error(), or a target
			 * socket, see wait_for_target()), in CLOCK_MONOTONIC
			 * milliseconds; 0 while nothing is.
			 */
			uint64_t		retry_at_ms;
			/*
			 * Plain and transparent forwarding clients whose
			 * target socket could not be created for want of
			 * descriptors, retried by run_retries().
			 */
			struct gwp_conn_pair	**tgt_wait;
			uint32_t		nr_tgt_wait;
			uint32_t		tgt_wait_cap;
			uint16_t		evsz;
			uint16_t		nr_dead;
			uint16_t		dead_cap;
			/*
			 * If it's true, the worker MUST call epoll_wait() again
			 * before continue iterating over the events. Only set
			 * when @dead is full and a pair had to be freed at once.
			 */
			bool			ev_need_reload;
			/*
			 * accept() failed for a reason that closing
			 * descriptors does not cure: the listener is out of
			 * the epoll set until retry_at_ms (accept_retry).
			 * Any accept pause, this one or the one for running
			 * out of descriptors (accept_is_stopped), is logged
			 * once, until a connection is accepted again
			 * (accept_paused).
			 */
			bool			accept_retry;
			bool			accept_paused;
		};
#ifdef CONFIG_IO_URING
		struct iou	*iou;
#endif
	};

	bool			accept_is_stopped;
	bool			need_join;
	struct gwp_ctx		*ctx;
	uint32_t		idx;
	/*
	 * Coarse monotonic seconds, taken once per wakeup of the loop: cheap
	 * enough to stamp every event with (gwp_conn_pair::last_act).
	 */
	uint32_t		now;
	pthread_t		thread;

	/*
	 * Per-worker scratch for the SOCKS5 UDP relay, allocated at worker
	 * start when SOCKS5 is enabled. A datagram is received at offset
	 * GWP_SOCKS5_UDP_HDR_MAX so a reply header can be prepended in-place
	 * (no copy); the tail holds up to one max-size UDP payload.
	 */
	unsigned char		*udp_buf;

#ifdef CONFIG_NEW_DNS_RESOLVER
	struct gwp_wrk_dns	*dns;
#endif
} __attribute__((__aligned__(GWP_CACHELINE)));

enum {
	GWP_EV_EPOLL,
	GWP_EV_IO_URING
};

struct gwp_ctx {
	/*
	 * Set from the signal handler and from any worker that exits, read by
	 * every worker loop: an atomic, which volatile is not. Lock-free, so it
	 * is also safe to store from a signal handler.
	 */
	_Atomic(bool)			stop;
	uint8_t				ev_used;
	struct log_handle		lh;
	struct gwp_wrk			*workers;
	struct gwp_sockaddr		target_addr;
	struct gwp_socks5_ctx		*socks5;
	struct gwp_auth			*auth;
	struct gwp_ssl_ctx		*ssl_ctx;
	struct gwp_dns_ctx		*dns;
	struct gwp_upstream		upstream;
	/*
	 * Parsed --bind-source/--bind-iface: the source pin applied to every
	 * outgoing connection that no ACL -j BIND rule claimed. Built once at
	 * startup so the connect path never parses anything, and shaped like an
	 * ACL bind so both tiers share one apply path. @set is false when
	 * neither option was given.
	 */
	struct gwp_acl_bind		bind_def;
	struct gwp_cfg			cfg;
	/* The locked --pid-file, removed on exit; -1 when there is none. */
	int				pid_fd;
	/*
	 * One inotify instance watching the auth file and the ACL file (their
	 * parent directories, see add_reload_watch()); -1 when neither is
	 * configured. @reload_thread polls it and reloads the files, off the
	 * workers; @reload_efd tells it to exit. @reload_running: the thread
	 * was started and still needs a join.
	 */
	int				ino_fd;
	int				reload_efd;
	pthread_t			reload_thread;
	bool				reload_running;
	/* ACL rule store. Global to all proxy modes, unlike @auth which is
	 * prot-only. @acl_watched: loaded from --acl-file (so reloadable),
	 * not the built-in default rules. */
	struct gwp_acl			*acl;
	bool				acl_watched;
	/* Client connections per address, for --max-conns-per-ip; NULL when
	 * there is no cap, so the accept path costs nothing then. */
	struct gwp_iplim		*iplim;
	_Atomic(int32_t)		nr_fd_closed;
	_Atomic(int32_t)		nr_accept_stopped;
	/* The workers' stop doorbells have been rung (io_uring). */
	_Atomic(bool)			stop_signalled;
};

struct gwp_conn_pair *gwp_alloc_conn_pair(struct gwp_wrk *w);
bool gwp_ctx_iplim_get(struct gwp_wrk *w, const struct gwp_sockaddr *addr);
void gwp_ctx_iplim_put(struct gwp_ctx *ctx, const struct gwp_sockaddr *addr);
int gwp_free_conn_pair(struct gwp_wrk *w, struct gwp_conn_pair *gcp);
int gwp_create_sock_target(struct gwp_wrk *w, struct gwp_sockaddr *addr,
			   const struct gwp_conn_sockopt *so,
			   bool *is_target_alive, bool non_block);
void gwp_setup_cli_sock_options(struct gwp_wrk *w, int fd);

/*
 * Per-worker SOCKS5 UDP relay scratch: room to prepend a max relay header plus
 * one max-size UDP payload (65535 bytes). Datagrams are received at offset
 * GWP_SOCKS5_UDP_HDR_MAX within it.
 */
#define GWP_UDP_RELAY_BUFSZ	(GWP_SOCKS5_UDP_HDR_MAX + 65535)

/*
 * Create and bind the per-connection UDP relay socket for a SOCKS5 UDP
 * ASSOCIATE, derive its BND.ADDR:PORT and write the SOCKS5 reply into
 * gcp->target.buf (for the caller to flush to the client), and stash the fd in
 * gcp->udp_fd. On failure a SOCKS5 failure reply is queued instead and a
 * negative error is returned. The caller registers the fd with its event loop.
 */
int gwp_socks5_udp_associate_setup(struct gwp_wrk *w, struct gwp_conn_pair *gcp);

/*
 * Convert a SOCKS5 IPv4/IPv6 target to a sockaddr for the dual-stack UDP relay
 * (always AF_INET6; IPv4 is returned v4-mapped). Domain -> -EAFNOSUPPORT.
 */
int gwp_socks5_addr_to_sockaddr(const struct gwp_socks5_addr *a,
				struct gwp_sockaddr *sa, socklen_t *slen);

/* Fill a SOCKS5 UDP reply-header address from a datagram source (unmaps v4). */
void gwp_socks5_reply_addr_from_sockaddr(const struct gwp_sockaddr *src,
					 struct gwp_socks5_addr *a);

/* Compare two addresses by IP only, matching IPv4 with its v4-mapped form. */
bool gwp_sockaddr_ip_eq(const struct gwp_sockaddr *a,
			const struct gwp_sockaddr *b);

/* Compare two addresses by family, port, and IP; v4 and v4-mapped v6 differ. */
bool gwp_sockaddr_eq(const struct gwp_sockaddr *a,
		     const struct gwp_sockaddr *b);

enum gwp_udp_act { GWP_UDP_DROP, GWP_UDP_TO_TARGET, GWP_UDP_TO_CLIENT };

struct gwp_udp_out {
	unsigned char		*buf;
	size_t			len;
	struct gwp_sockaddr	dst;
	socklen_t		dstlen;
};

/*
 * SOCKS5 UDP relay per-datagram classifier, shared by both event loops. @base
 * points at a received datagram of @n bytes, with GWP_SOCKS5_UDP_HDR_MAX bytes
 * of slack before it; @src is its source. Maintain the client pin
 * (gcp->udp_peer / gcp->udp_pinned) and decide:
 *   GWP_UDP_TO_TARGET - client datagram: strip the SOCKS5 header, forward @out
 *                       to the encapsulated target.
 *   GWP_UDP_TO_CLIENT - target reply: prepend a SOCKS5 header in the slack, send
 *                       @out back to the pinned client.
 *   GWP_UDP_DROP      - unpinned/wrong source, bad header, domain target, ACL
 *                       denial, or a "reply" from a source the client has not
 *                       sent to (or that the ACL no longer accepts).
 * On a forward verdict @out holds the buffer + destination; each loop performs
 * the send with its own I/O primitive.
 */
enum gwp_udp_act gwp_udp_relay_classify(struct gwp_wrk *w,
					struct gwp_conn_pair *gcp,
					unsigned char *base, size_t n,
					const struct gwp_sockaddr *src,
					struct gwp_udp_out *out);

/* True if the ACL OUTPUT chain permits a @proto connection from @client to
 * @target (allow-all when no ACL is loaded). A matching -j DNAT rewrites
 * *@target and any -j MARK/-j BIND modifiers are written to *@so (ignored when
 * @so is NULL). For the accept-time plain/transparent path, which has no
 * gwp_conn_pair. */
bool gwp_ctx_acl_output_dnat(struct gwp_ctx *ctx,
			     const struct gwp_sockaddr *client,
			     struct gwp_sockaddr *target,
			     struct gwp_conn_sockopt *so,
			     enum gwp_acl_proto proto);

/* Convenience wrapper: ACL OUTPUT check for a TCP target (gcp->target_addr). */
bool gwp_ctx_acl_target_allowed(struct gwp_ctx *ctx, struct gwp_conn_pair *gcp);

/*
 * Install the addresses the connect path may try, in priority order, and reset
 * the attempt cursor. At most GWP_MAX_CONN_CAND are kept.
 */
void gwp_conn_set_candidates(struct gwp_conn_pair *gcp,
			     const struct gwp_sockaddr *addrs, uint8_t nr);
/* The one-address case: a literal IP, a transparent redirect, an upstream. */
void gwp_conn_set_single_candidate(struct gwp_conn_pair *gcp,
				   const struct gwp_sockaddr *addr);

/*
 * Close every connect attempt still in flight, e.g. once one attempt has won
 * the race or the pair is being torn down. Returns how many descriptors were
 * closed, which the epoll loop credits to its accept-rearm accounting.
 */
int gwp_conn_close_attempts(struct gwp_conn_pair *gcp);

/* True if the ACL INPUT chain permits an incoming client for @proto (allow-all
 * with no ACL). */
bool gwp_ctx_acl_client_allowed(struct gwp_ctx *ctx,
				const struct gwp_sockaddr *client,
				enum gwp_acl_proto proto);
/*
 * True when @a may be dialled under --outgoing-family. v4-mapped aware, so a
 * ::ffff:a.b.c.d target from the UDP relay counts as IPv4.
 */
bool gwp_ctx_outgoing_family_ok(const struct gwp_ctx *ctx,
				const struct gwp_sockaddr *a);
int gwp_get_orig_dst(int fd, const struct gwp_sockaddr *client,
		     struct gwp_sockaddr *dst);
const char *ip_to_str(const struct gwp_sockaddr *gs);

/* Monotonic seconds, at the coarse clock's resolution (a few ms). */
static inline uint32_t gwp_now_sec(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC_COARSE, &t);
	return (uint32_t)t.tv_sec;
}

/*
 * Is the target socket carrying the upstream proxy handshake? Until the tunnel
 * is up, gcp->target is that handshake's I/O buffer: whatever it holds (our
 * unsent request, a partial or refusing reply) belongs to the upstream proxy
 * and must never be relayed to the client.
 */
static inline bool gwp_in_upstream_hs(const struct gwp_conn_pair *gcp)
{
	int cs = gcp->conn_state;

	return cs >= CONN_STATE_UPSTREAM_S5_MIN &&
	       cs <= CONN_STATE_UPSTREAM_HTTP_MAX;
}

/* Move the data back to the start of the buffer, regaining the room in front. */
static inline void gwp_conn_buf_compact(struct gwp_conn *conn)
{
	if (!conn->off)
		return;
	if (conn->len)
		memmove(conn->buf - conn->off, conn->buf, conn->len);
	conn->buf -= conn->off;
	conn->cap += conn->off;
	conn->off = 0;
}

static inline void __gwp_conn_buf_skip(struct gwp_conn *conn, size_t len)
{
	assert(len <= conn->len);
	conn->buf += len;
	conn->len -= (uint32_t)len;
	conn->cap -= (uint32_t)len;
	conn->off += (uint32_t)len;
}

/*
 * Drop @len bytes from the front and keep the rest at the start of the
 * buffer. For the protocol parsers, which want the next message at the start
 * and the whole buffer behind it.
 */
static inline void gwp_conn_buf_advance(struct gwp_conn *conn, size_t len)
{
	__gwp_conn_buf_skip(conn, len);
	gwp_conn_buf_compact(conn);
}

/*
 * Drop @len bytes from the front after they were sent. The rest stays where
 * it is: it is compacted only once the buffer is empty (which costs nothing)
 * or once at least half of it lies consumed in front of the data, so the
 * bytes moved never exceed the bytes sent. Moving the rest down on every
 * partial send copied up to a whole buffer each time.
 */
static inline void gwp_conn_buf_consume(struct gwp_conn *conn, size_t len)
{
	__gwp_conn_buf_skip(conn, len);
	if (!conn->len || conn->off >= conn->cap)
		gwp_conn_buf_compact(conn);
}

/*
 * Debug, not info: at the default level every connection already logs
 * "Target socket connected" (fds, both addresses) and "Closing connection
 * pair" (idx, fds, both addresses), so this line only repeated them.
 */
static inline
void log_conn_pair_created(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	pr_dbg(&ctx->lh, "New connection pair created (idx=%u, cfd=%d, tfd=%d, ca=%s, ta=%s)",
		gcp->idx, gcp->client.fd, gcp->target.fd,
		ip_to_str(&gcp->client_addr), ip_to_str(&gcp->target_addr));
}

int gwp_socks5_prep_connect_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				  int err);

/*
 * Build the "ACL denied" downstream reply (SOCKS5 CONNECT refusal or HTTP 403)
 * into gcp->target.buf, ready for the caller to flush its own way. Logs the
 * denial. Returns -EACCES (the terminal handshake verdict) once the reply is
 * built, or a negative errno if it could not be built.
 */
int gwp_acl_reject_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp);

/*
 * Build the "could not reach the origin" reply for whichever protocol the
 * client speaks -- a SOCKS5 reply carrying the REP for @err, or HTTP 502 --
 * into gcp->target.buf, ready for the caller to flush its own way. @err is a
 * negative errno. Returns 0 (including for plain forwarding, which has no
 * protocol to answer in), or a negative errno if the reply could not be built.
 */
int gwp_conn_fail_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp, int err);
int gwp_socks5_build_connect_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				   int err, void *out, size_t *out_len);
int gwp_socks5_prepare_target_addr(struct gwp_wrk *w, struct gwp_conn_pair *gcp);
int gwp_upstream_finalize_dst(struct gwp_wrk *w, struct gwp_conn_pair *gcp);
int gwp_upstream_authority(const struct gwp_socks5_addr *dst, char *buf,
			   size_t cap);

/*
 * The upstream proxy handshake succeeded: build our downstream CONNECT reply
 * (SOCKS5 or HTTP), drop the proxy's @consumed reply bytes from the target
 * buffer while keeping any early destination data, and splice our reply ahead
 * of it. Returns 0, or a negative errno if the reply could not be built or fit.
 */
int gwp_upstream_splice_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			      size_t consumed);

/* "host:port" for a domain upstream target, else its resolved IP. Returns a
 * thread-local buffer valid until the next call on the same thread. */
const char *gwp_upstream_dst_str(struct gwp_conn_pair *gcp);

/*
 * The next I/O step in the transport-agnostic upstream-proxy handshake state
 * machine (gwp_upstream_hs_start / gwp_upstream_hs_on_reply). The request bytes
 * live in gcp->target.buf; the caller performs the send/recv with its own I/O
 * primitive.
 */
enum gwp_upstream_io {
	GWP_UPSTREAM_IO_SEND,	/* a request is built; flush target.buf */
	GWP_UPSTREAM_IO_RECV,	/* reply incomplete; read more into target.buf */
	GWP_UPSTREAM_IO_DONE,	/* tunnel up (reply spliced); start forwarding */
};

/*
 * Begin the upstream-proxy handshake: finalize gcp->up_dst and build the SOCKS5
 * greeting or HTTP CONNECT into gcp->target.buf. Returns GWP_UPSTREAM_IO_SEND,
 * or a negative errno.
 */
int gwp_upstream_hs_start(struct gwp_wrk *w, struct gwp_conn_pair *gcp);

/*
 * Fresh proxy bytes were appended to gcp->target.buf: parse the current
 * handshake state and either build the next request (GWP_UPSTREAM_IO_SEND), ask
 * for more (GWP_UPSTREAM_IO_RECV), or on final success splice the downstream
 * reply and report GWP_UPSTREAM_IO_DONE. On failure returns a negative errno
 * (logging its own pr_err) and, when @notify is non-NULL, sets *@notify true if
 * the failure is a protocol-level rejection whose downstream client should be
 * told; the caller owns that notification and all timer / forwarding state.
 */
int gwp_upstream_hs_on_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			     bool *notify);

/*
 * The upstream handshake failed with @err and the client is to be told: put
 * its failure reply in target.buf in place of whatever the upstream sent --
 * SOCKS5 REP 0x05 for a refused CONNECT and 0x01 for anything else, an HTTP
 * client a 502. Returns the number of bytes to send to the client (0 for
 * plain forwarding, which has no reply to give), or a negative errno.
 */
int gwp_upstream_fail_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			    int err);

int gwp_socks5_handle_data(struct gwp_conn_pair *gcp);
int gwp_handle_conn_state_prot(struct gwp_wrk *w, struct gwp_conn_pair *gcp);
int gwp_handle_conn_state_socks5(struct gwp_wrk *w, struct gwp_conn_pair *gcp);
int gwp_handle_conn_state_http(struct gwp_wrk *w, struct gwp_conn_pair *gcp);

/*
 * HTTP forwarding-proxy requests (absolute-form "GET http://..."), unlike
 * every other mode, are not relayed blindly once the target is up: what
 * passes between client and origin is filtered by gwp_http_fwd_in(). Both
 * event loops call gwp_http_fwd_begin() when such a pair starts forwarding,
 * and gwp_http_fwd_in() after every read into either buffer while
 * gwp_http_fwd_active() holds.
 */
static inline bool gwp_http_fwd_active(const struct gwp_conn_pair *gcp)
{
	return gcp->prot_type == GWP_PROT_TYPE_HTTP && gcp->http_conn &&
	       gwp_http_conn_is_forward(gcp->http_conn);
}

int gwp_http_fwd_begin(struct gwp_wrk *w, struct gwp_conn_pair *gcp);

/*
 * @c (&gcp->client or &gcp->target) has just had bytes appended at
 * c->buf[@from..c->len), or reached EOF (c->rd_eof). The bytes may be
 * rewritten, held back or dropped, so c->len and c->cap can change. Returns
 * 0 or a negative errno that tears the pair down.
 */
int gwp_http_fwd_in(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
		    struct gwp_conn *c, uint32_t from);

#endif /* #ifndef GWPROXY_H */
