// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <gwproxy/ev/epoll.h>
#include <gwproxy/ev/tmr.h>
#include <gwproxy/common.h>
#include <gwproxy/acl.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#ifdef CONFIG_HTTPS
#include <gwproxy/ssl.h>
#endif


#ifdef CONFIG_HTTPS
static int tls_flush_hs(struct gwp_conn *c);
#endif

#ifdef CONFIG_NEW_DNS_RESOLVER
#include <gwproxy/dns_resolver.h>
static int send_dns_payload(struct gwp_conn_pair *gcp)
{
	struct gwp_dns_packet *gdp = gcp->gdp;
	ssize_t sr;

	sr = __sys_sendto(gdp->fd, gdp->buf, gdp->buf_len, MSG_NOSIGNAL,
			  NULL, 0);
	if (unlikely(sr < 0))
		return (int)sr;

	return 0;
}

/*
 * A lookup is pending. The getaddrinfo() path needs nothing more here: its
 * result arrives on the worker's DNS completion queue (handle_ev_dns_cq()).
 */
static int chk_handle_dns_query(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_cfg *cfg = &w->ctx->cfg;

	if (cfg->use_raw_dns) {
		struct epoll_event ev;
		int r;

		/* The reply comes back on the query's own socket. */
		ev.events = EPOLLIN;
		ev.data.u64 = PTR_TO_U64(gcp) | EV_BIT_RAW_DNS_QUERY;
		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, gcp->gdp->fd, &ev);
		if (unlikely(r))
			return r;
		return send_dns_payload(gcp);
	}

	return 0;
}

static int handle_connect(struct gwp_wrk *w, struct gwp_conn_pair *gcp);
static int free_conn_pair(struct gwp_wrk *w, struct gwp_conn_pair *gcp);
static ssize_t __do_send(struct gwp_conn *src, struct gwp_conn *dst);

/*
 * One datagram from the query's socket. Returns 1 when the lookup is still
 * pending (a stray reply, or the fallback query went out), 0 when it is
 * done with, or a negative error that ends the connection.
 */
static int handle_raw_dns_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				uint8_t *buf, uint16_t len)
{
	struct gwp_dns_resolver *res = &w->dns->resolvers[0];
	struct gwp_sockaddr addrs[GWP_MAX_CONN_CAND];
	struct gwp_ctx *ctx = w->ctx;
	uint8_t nr = 0;
	ssize_t ret;
	int r;

	ret = gwp_dns_res_complete_query(res, gcp->gdp, buf, len, addrs,
					 GWP_MAX_CONN_CAND, &nr);
	if (ret == -ESRCH)
		return 1;
	if (ret == -EAGAIN) {
		/* Retry with the fallback record type. */
		ret = send_dns_payload(gcp);
		if (likely(!ret))
			return 1;
	} else if (likely(!ret)) {
		/* Every address of the reply, so a dead one has a fallback. */
		gwp_conn_set_candidates(gcp, addrs, nr);
		pr_dbg(&ctx->lh, "Resolved DNS query for %s to %s (%u addr, gcp_idx=%u)",
			gcp->gdp->host, ip_to_str(&gcp->target_addr), nr,
			gcp->idx);
		return handle_connect(w, gcp);
	}

	/*
	 * The name did not resolve, so the origin is unreachable: answer
	 * in whatever protocol the client speaks (SOCKS5 REP, or HTTP 502)
	 * and close, as the getaddrinfo path does. The error then tears
	 * down this one pair (handle_event()).
	 */
	r = gwp_conn_fail_reply(w, gcp, (int)ret);
	if (!r && gcp->target.len) {
		ssize_t sr = __do_send(&gcp->target, &gcp->client);

		if (unlikely(sr < 0))
			r = (int)sr;
	}

	return r ? r : (int)ret;
}

/*
 * Replies read per wakeup, at most: enough to take a burst in one go, few
 * enough that a flood on this socket cannot starve the worker's other
 * events. The socket is level-triggered, so whatever is left wakes the
 * loop again.
 */
#define GWP_RAW_DNS_BUDGET	64

static int handle_ev_raw_dns_query(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	uint8_t buf[DNS_EDNS_UDP_SIZE];
	ssize_t ret;
	int i, r;

	for (i = 0; i < GWP_RAW_DNS_BUDGET; i++) {
		ret = __sys_recv(gcp->gdp->fd, buf, sizeof(buf), 0);
		if (ret < 0) {
			/*
			 * The socket is connected, so an ICMP port unreachable
			 * from a DNS server that is down -- or simply not
			 * listening where we were told -- is reported here as
			 * -ECONNREFUSED. It ends nothing: the lookup times out
			 * on its own, as it would with no reply at all.
			 */
			if (ret != -EAGAIN && ret != -EINTR)
				pr_dbg(&ctx->lh, "DNS socket recv failed: %s",
				       strerror((int)-ret));
			return 0;
		}

		r = handle_raw_dns_reply(w, gcp, buf, (uint16_t)ret);
		if (r <= 0)
			return r;
	}

	return 0;
}
#else
static int chk_handle_dns_query(struct gwp_wrk __unused *w,
				struct gwp_conn_pair __unused *gcp)
{
	return 0;
}

static int handle_ev_raw_dns_query(struct gwp_wrk __unused *w,
				   struct gwp_conn_pair __unused *gcp)
{
	return -ENOSYS;
}
#endif

static int connect_next_candidate(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				  int err);
static bool has_inflight_attempt(const struct gwp_conn_pair *gcp);
static int __forward_progress(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			      struct gwp_conn *hup, bool force_target);
static int forward_progress(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			    struct gwp_conn *hup);

__cold
int gwp_ctx_init_thread_epoll(struct gwp_wrk *w)
{
	struct epoll_event ev, *events;
	struct gwp_ctx *ctx = w->ctx;
	int ep_fd, ev_fd, r;

	memset(&w->tmrs, 0, sizeof(w->tmrs));
	w->retry_at_ms = 0;
	w->accept_retry = false;
	w->accept_paused = false;
	w->tgt_wait = NULL;
	w->nr_tgt_wait = w->tgt_wait_cap = 0;
	ep_fd = __sys_epoll_create1(EPOLL_CLOEXEC);
	if (ep_fd < 0) {
		r = ep_fd;
		pr_err(&w->ctx->lh, "Failed to create epoll instance: %s",
			strerror(-r));
		return r;
	}

	ev_fd = __sys_eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (ev_fd < 0) {
		r = ev_fd;
		pr_err(&w->ctx->lh, "Failed to create eventfd: %s", strerror(-r));
		goto out_close_ep_fd;
	}

	w->evsz = 512;
	events = calloc(w->evsz, sizeof(*events));
	if (!events) {
		r = -ENOMEM;
		pr_err(&w->ctx->lh, "Failed to allocate memory for events: %s",
			strerror(-r));
		goto out_close_ev_fd;
	}

	/*
	 * Every event tears down at most one pair, except the accept event,
	 * which handles up to 32 connections (see handle_ev_accept()). The
	 * list never fills in practice; free_conn_pair() copes if it does.
	 */
	w->nr_dead = 0;
	w->dead_cap = w->evsz + 32;
	w->dead = calloc(w->dead_cap, sizeof(*w->dead));
	if (!w->dead) {
		r = -ENOMEM;
		free(events);
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

	/* Results of this worker's getaddrinfo() lookups. */
	if (ctx->dns) {
		ev.events = EPOLLIN;
		ev.data.u64 = EV_BIT_DNS_QUERY;
		r = __sys_epoll_ctl(ep_fd, EPOLL_CTL_ADD,
				    gwp_dns_cq_fd(ctx->dns, w->idx), &ev);
		if (unlikely(r))
			goto out_free_events;
	}

	/* Scratch for the SOCKS5 UDP relay; only reachable when as_socks5. */
	if (ctx->cfg.as_socks5) {
		w->udp_buf = malloc(GWP_UDP_RELAY_BUFSZ);
		if (!w->udp_buf) {
			r = -ENOMEM;
			goto out_free_events;
		}
	}

	pr_dbg(&w->ctx->lh, "Worker %u epoll (ep_fd=%d, ev_fd=%d)", w->idx,
		ep_fd, ev_fd);
	return 0;

out_free_events:
	free(events);
	w->events = NULL;
	free(w->dead);
	w->dead = NULL;
out_close_ev_fd:
	__sys_close(ev_fd);
out_close_ep_fd:
	__sys_close(ep_fd);
	w->ev_fd = w->ep_fd = -1;
	return r;
}

__cold
void gwp_ctx_free_thread_epoll(struct gwp_wrk *w)
{
	if (w->ev_fd >= 0) {
		__sys_close(w->ev_fd);
		pr_dbg(&w->ctx->lh, "Worker %u eventfd closed (fd=%d)", w->idx,
		       w->ev_fd);
		w->ev_fd = -1;
	}

	if (w->ep_fd >= 0) {
		__sys_close(w->ep_fd);
		pr_dbg(&w->ctx->lh, "Worker %u epoll closed (fd=%d)", w->idx,
		       w->ep_fd);
		w->ep_fd = -1;
	}

	free(w->events);
	w->events = NULL;
	free(w->dead);
	w->dead = NULL;
	free(w->tgt_wait);
	w->tgt_wait = NULL;
	w->nr_tgt_wait = w->tgt_wait_cap = 0;
	gwp_tmr_free(&w->tmrs);
	free(w->udp_buf);
	w->udp_buf = NULL;
}

static int rearm_accept(struct gwp_wrk *w, int nr_fd_closed)
{
	struct gwp_ctx *ctx = w->ctx;
	struct epoll_event ev;
	int x, r;

	/*
	 * Each connection pair takes up to 3 file descriptors while it is
	 * set up:
	 *
	 *   1. TCP socket for the client connection.
	 *   2. TCP socket for the target connection.
	 *   3. A DNS query socket or a second racing connect attempt.
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
	pr_dbg(&ctx->lh,
		"Rearmed main TCP socket for accepting new connections (tidx=%u, fd=%d)",
		w->idx, w->tcp_fd);

	x = atomic_fetch_sub(&ctx->nr_accept_stopped, 1);
	if (x == 1)
		atomic_store(&ctx->nr_fd_closed, 0);

	return 0;
}

/*
 * Credit @n closed descriptors to the accept throttle, and rearm accept once
 * enough have been returned. Only while this worker's accept is stopped: the
 * shared counter is reset when the last stopped worker rearms, so credits
 * taken in normal operation would pile up without bound and let the next
 * EMFILE rearm at once, which is the churn the throttle exists to prevent.
 */
static int credit_fd_closed(struct gwp_wrk *w, int n)
{
	int x;

	if (likely(!w->accept_is_stopped) || !n)
		return 0;

	x = atomic_fetch_add(&w->ctx->nr_fd_closed, n);
	return rearm_accept(w, x);
}

static uint64_t now_ms(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}

/*
 * The pairs' timers: the protocol, connect and idle timeouts and the delay
 * before the next connect attempt. They live in a binary min-heap per worker
 * whose earliest entry sets the epoll_wait() timeout (wait_timeout()), and
 * run_timers() runs those that are due once a batch of events is handled.
 *
 * A timerfd per pair cost a timerfd_create(), a timerfd_settime() and an
 * EPOLL_CTL_ADD to arm, a close() to drop, a timerfd_settime() to re-arm,
 * and a descriptor for as long as it was armed, which could be the one a
 * client needed under descriptor pressure. Here arming, re-arming and
 * dropping are O(log n) in memory, and a pair only ever takes its sockets.
 *
 * Re-arming moves the pair's entry instead of adding a second one, and an
 * entry never outlives its pair: free_conn_pair() takes both out. A re-armed
 * timer therefore cannot fire for the deadline it replaced, which a timerfd
 * could if its expiry was already reported later in the same batch.
 */
static int tmr_arm(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
		   uint32_t kind, uint64_t ms)
{
	return gwp_tmr_arm(&w->tmrs, gcp, kind, now_ms() + ms);
}

static void tmr_disarm(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
		       uint32_t kind)
{
	gwp_tmr_disarm(&w->tmrs, gcp, kind);
}

__hot
static int __free_conn_pair(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	int nr_fd_closed = 0;
	int r;

	if (gcp->client.fd >= 0)
		nr_fd_closed++;
	if (gcp->target.fd >= 0)
		nr_fd_closed++;
	if (gcp->udp_fd >= 0)
		nr_fd_closed++;
#ifdef CONFIG_NEW_DNS_RESOLVER
	if (gcp->gdp && gcp->gdp->fd >= 0)
		nr_fd_closed++;	/* a raw DNS query's socket */
#endif

	/*
	 * A race that was still running when the pair went away: those sockets
	 * count too, or the accept path under-credits them and stays throttled.
	 */
	{
		uint8_t i;

		for (i = 0; i < GWP_MAX_CONN_CAND; i++)
			if (gcp->attempt_fd[i] >= 0)
				nr_fd_closed++;
	}

	r = gwp_free_conn_pair(w, gcp);
	if (unlikely(r)) {
		pr_err(&ctx->lh, "Failed to free connection pair: %s", strerror(-r));
		return r;
	}

	return credit_fd_closed(w, nr_fd_closed);
}

/*
 * Tear a pair down. Events later in the batch being handled may still carry
 * a pointer to it, so it is only marked dying here: handle_event() skips its
 * events, and reap_dead_pairs() frees it once the batch is done. Freeing at
 * once used to force a fresh epoll_wait() after every closed connection,
 * throwing away the rest of the batch only to collect it again.
 *
 * Its descriptors stay open until then, which also keeps their numbers from
 * being reused within the batch. The one way to reach a pair that is not an
 * event of its own, a raw DNS reply looked up by transaction id, is cut off
 * here, so a reply later in the batch cannot revive it.
 */
static int free_conn_pair(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	uint32_t i;

	if (gcp->flags & GWP_CONN_FLAG_IS_DYING)
		return 0;

	tmr_disarm(w, gcp, GWP_TMR_CONN);
	tmr_disarm(w, gcp, GWP_TMR_ATTEMPT);

	/* A client waiting for its target socket (see wait_for_target()). */
	for (i = 0; unlikely(i < w->nr_tgt_wait); i++) {
		if (w->tgt_wait[i] == gcp) {
			w->tgt_wait[i] = w->tgt_wait[--w->nr_tgt_wait];
			break;
		}
	}

	if (unlikely(w->nr_dead >= w->dead_cap)) {
		w->ev_need_reload = true;
		return __free_conn_pair(w, gcp);
	}

#ifdef CONFIG_NEW_DNS_RESOLVER
	/*
	 * Close the query's socket now, so no reply for this pair is read
	 * later in the batch, and count it towards the accept throttle.
	 */
	if (w->ctx->cfg.use_raw_dns && gcp->gdp && gcp->gdp->fd >= 0) {
		int r;

		gwp_dns_res_drop_query(gcp->gdp);
		r = credit_fd_closed(w, 1);
		if (unlikely(r))
			return r;
	}
#endif

	gcp->flags |= GWP_CONN_FLAG_IS_DYING;
	w->dead[w->nr_dead++] = gcp;
	return 0;
}

static int reap_dead_pairs(struct gwp_wrk *w)
{
	int r, ret = 0;
	uint16_t i;

	for (i = 0; i < w->nr_dead; i++) {
		r = __free_conn_pair(w, w->dead[i]);
		if (unlikely(r) && !ret)
			ret = r;
	}

	w->nr_dead = 0;
	return ret;
}

/*
 * The timeout handle_new_client() arms for a client: the protocol timeout for
 * the SOCKS5 and HTTP front-ends, the connect timeout for plain and
 * transparent forwarding.
 */
static int new_client_timeout(const struct gwp_cfg *cfg)
{
	if (cfg->as_http || cfg->as_socks5)
		return cfg->protocol_timeout;
	return cfg->connect_timeout;
}

/*
 * Every connection to a target is logged once it is up, the same way on both
 * event loops: in handle_ev_target_conn_result() once the connect completes,
 * or in handle_new_client() for a plain forwarding connect that completed at
 * once. A connection through an upstream proxy is logged when the tunnel is
 * up instead.
 */
static void log_target_connected(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	pr_info(&w->ctx->lh, "Target socket connected (fd=%d, idx=%u, ca=%s, ta=%s)",
		gcp->target.fd, gcp->idx, ip_to_str(&gcp->client_addr),
		ip_to_str(&gcp->target_addr));
}

/*
 * Register a new client's descriptors: its target socket, if it has one by
 * now, and the client socket under @cl_ev_bit.
 */
static int register_new_client(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			       uint64_t cl_ev_bit)
{
	struct epoll_event ev;
	int r;

	/*
	 * If epoll_ctl() fails, don't bother closing the target socket
	 * because it will be closed in free_conn_pair() anyway.
	 */
	gcp->client.ep_mask = EPOLLIN | EPOLLRDHUP;

	if (gcp->target.fd >= 0) {
		gcp->target.ep_mask = EPOLLOUT | EPOLLIN | EPOLLRDHUP;
		ev.events = gcp->target.ep_mask;
		ev.data.u64 = PTR_TO_U64(gcp) | EV_BIT_TARGET;
		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, gcp->target.fd, &ev);
		if (unlikely(r))
			return r;
	} else {
		gcp->target.ep_mask = 0;
	}

	ev.events = gcp->client.ep_mask;
	ev.data.u64 = PTR_TO_U64(gcp) | cl_ev_bit;
	r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, gcp->client.fd, &ev);
	if (unlikely(r))
		return r;

	if (gcp->target.fd >= 0) {
		log_conn_pair_created(w, gcp);
		/* Otherwise it is logged when EPOLLOUT reports the connect. */
		if (gcp->is_target_alive)
			log_target_connected(w, gcp);
	}

	return 0;
}

/*
 * Plain and transparent forwarding: create the target socket, start its
 * connect, and register the pair. -EMFILE or -ENFILE leaves the pair as it
 * was, to be tried again (see wait_for_target()).
 */
static int start_new_target(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_sockaddr *ca = &gcp->target_addr;
	struct gwp_ctx *ctx = w->ctx;
	int target_fd;

	/* With an upstream proxy, connect to the proxy instead. */
	if (ctx->upstream.enabled)
		ca = &ctx->upstream.addr;

	target_fd = gwp_create_sock_target(w, ca, &gcp->acl_sockopt,
					   &gcp->is_target_alive, true);
	if (target_fd < 0) {
		if (target_fd != -EMFILE && target_fd != -ENFILE)
			pr_err(&ctx->lh, "Failed to create target socket: %s",
				strerror(-target_fd));
		return target_fd;
	}
	gcp->target.fd = target_fd;
	gcp->conn_state = CONN_STATE_FORWARDING;

	/*
	 * Force the connect-result path so the upstream handshake runs
	 * (see handle_ev_target_conn_result).
	 */
	if (ctx->upstream.enabled)
		gcp->is_target_alive = false;

	return register_new_client(w, gcp, EV_BIT_CLIENT);
}

static void arm_retry(struct gwp_wrk *w);

/*
 * The descriptor table is full, and an accepted client has no target socket
 * yet. Closing the client would turn a passing shortage into a reset seen by
 * the client, so keep it and try again every 100 ms (RETRY_DELAY_MS), as the
 * io_uring loop does, for as long as its connect timeout allows. Only its
 * timer runs meanwhile: what the client sends waits in its socket.
 */
static int wait_for_target(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			   int e)
{
	if (w->nr_tgt_wait == w->tgt_wait_cap) {
		uint32_t cap = w->tgt_wait_cap ? w->tgt_wait_cap * 2 : 16;
		struct gwp_conn_pair **p;

		p = realloc(w->tgt_wait, cap * sizeof(*p));
		if (unlikely(!p))
			return e;
		w->tgt_wait = p;
		w->tgt_wait_cap = cap;
	}

	pr_warn(&w->ctx->lh,
		"Too many open files, retrying the target connect (idx=%u, ca=%s)",
		gcp->idx, ip_to_str(&gcp->client_addr));
	w->tgt_wait[w->nr_tgt_wait++] = gcp;
	arm_retry(w);
	return 0;
}

/* Try the waiting clients' target sockets again. */
static void retry_new_targets(struct gwp_wrk *w)
{
	uint32_t i, n = w->nr_tgt_wait;
	struct gwp_conn_pair *gcp;
	int r;

	w->nr_tgt_wait = 0;
	for (i = 0; i < n; i++) {
		gcp = w->tgt_wait[i];
		r = start_new_target(w, gcp);
		if (r == -EMFILE || r == -ENFILE) {
			/* Still waiting; the list only shrinks here. */
			w->tgt_wait[w->nr_tgt_wait++] = gcp;
			continue;
		}
		if (r)
			free_conn_pair(w, gcp);
	}

	if (w->nr_tgt_wait)
		arm_retry(w);
}

__hot
static int handle_new_client(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	int timeout, r;
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_cfg *cfg = &ctx->cfg;

	/*
	 * Plain and transparent forwarding connect at accept time (no
	 * SOCKS5/HTTP handshake, hence no reply): enforce the OUTPUT chain
	 * here and drop the connection if the target is denied.
	 */
	if (!cfg->as_http && !cfg->as_socks5 &&
	    !gwp_ctx_acl_target_allowed(ctx, gcp)) {
		pr_info(&ctx->lh, "ACL denied target %s for client %s",
			ip_to_str(&gcp->target_addr),
			ip_to_str(&gcp->client_addr));
		return -EACCES;
	}

	timeout = new_client_timeout(cfg);
	if (timeout > 0) {
		r = tmr_arm(w, gcp, GWP_TMR_CONN, timeout * 1000ull);
		if (unlikely(r))
			return r;
	}

	/*
	 * If we are running as a SOCKS5 proxy or an HTTP proxy, the initial
	 * connection does not have a target socket. We will create the target
	 * socket later.
	 */
	if (cfg->as_http || cfg->as_socks5) {
		gcp->is_target_alive = false;
		gcp->conn_state = CONN_STATE_PROT;
#ifdef CONFIG_HTTPS
		/*
		 * With a TLS listener, defer to a per-connection first-byte
		 * probe so plaintext SOCKS5/HTTP clients still work on the same
		 * port (see handle_ev_tls_detect()).
		 */
		if (ctx->ssl_ctx)
			gcp->conn_state = CONN_STATE_TLS_DETECT;
#endif
		gcp->target.fd = -1;
		return register_new_client(w, gcp, EV_BIT_CLIENT_PROT);
	}

	r = start_new_target(w, gcp);
	if (r == -EMFILE || r == -ENFILE)
		r = wait_for_target(w, gcp, r);
	return r;
}

/* How long a timed pause lasts, in milliseconds; the io_uring loop's too. */
#define RETRY_DELAY_MS	100

/* Have fish_events() wake up for run_retries() RETRY_DELAY_MS from now. */
static void arm_retry(struct gwp_wrk *w)
{
	if (!w->retry_at_ms)
		w->retry_at_ms = now_ms() + RETRY_DELAY_MS;
}

/*
 * The epoll_wait() timeout: until the next timed retry or the next timer is
 * due, or for ever when neither is.
 */
static int wait_timeout(const struct gwp_wrk *w)
{
	const struct gwp_tmr *t = gwp_tmr_first(&w->tmrs);
	uint64_t at = w->retry_at_ms, now;

	if (t && (!at || t->at_ms < at))
		at = t->at_ms;
	if (!at)
		return -1;

	now = now_ms();
	if (now >= at)
		return 0;
	at -= now;
	return at < INT_MAX ? (int)at : INT_MAX;
}

/* Do what a timed pause has been holding back, once it is due. */
static int run_retries(struct gwp_wrk *w)
{
	struct epoll_event ev;
	int r;

	if (likely(!w->retry_at_ms) || now_ms() < w->retry_at_ms)
		return 0;

	w->retry_at_ms = 0;
	if (w->accept_retry) {
		ev.events = EPOLLIN;
		ev.data.u64 = EV_BIT_ACCEPT;
		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, w->tcp_fd, &ev);
		if (unlikely(r))
			return r;
		w->accept_retry = false;
	}

	if (w->nr_tgt_wait)
		retry_new_targets(w);

	return 0;
}

static int handle_accept_error(struct gwp_wrk *w, int e)
{
	int r;

	if (likely(e == -EAGAIN || e == -EINTR))
		return e;

	if (e == -ENOBUFS || e == -EPERM || e == -EACCES) {
		/*
		 * Out of socket memory, or a security module refusing the
		 * connection at the head of the backlog. The listener stays
		 * readable, so trying again at once would only fail again,
		 * as fast as the worker can loop, and freeing descriptors
		 * does not help either. Take it out of the epoll set and try
		 * again a little later, until a connection is accepted.
		 */
		if (!w->accept_paused) {
			w->accept_paused = true;
			pr_warn(&w->ctx->lh,
				"Failed to accept new connection: %s, pausing accept (tidx=%u)",
				strerror(-e), w->idx);
		}
		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_DEL, w->tcp_fd, NULL);
		if (unlikely(r))
			return r;
		w->accept_retry = true;
		arm_retry(w);
		return -EAGAIN;
	}

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
		 *
		 * The pause is logged once, until a connection is accepted
		 * again, in the same words as the io_uring loop uses.
		 */
		if (!w->accept_paused) {
			w->accept_paused = true;
			pr_warn(&w->ctx->lh,
				"Too many open files, pausing accept (tidx=%u)",
				w->idx);
		}
		w->accept_is_stopped = true;
		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_DEL, w->tcp_fd, NULL);
		if (unlikely(r))
			return r;

		atomic_fetch_add(&w->ctx->nr_accept_stopped, 1);
		return -EAGAIN;
	}

	pr_err(&w->ctx->lh, "Failed to accept new connection: %s", strerror(-e));
	return e;
}

__hot
static int __handle_ev_accept(struct gwp_wrk *w)
{
	static const int flags = SOCK_NONBLOCK | SOCK_CLOEXEC;
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_cfg *cfg = &ctx->cfg;
	struct gwp_conn_pair *gcp;
	struct gwp_sockaddr addr;
	socklen_t addr_len;
	int fd, r;

	addr_len = sizeof(addr);
	fd = __sys_accept4(w->tcp_fd, &addr.sa, &addr_len, flags);
	if (fd < 0)
		return handle_accept_error(w, fd);

	if (unlikely(w->accept_paused)) {
		w->accept_paused = false;
		pr_info(&ctx->lh, "Resumed accepting new connections (tidx=%u)",
			w->idx);
	}

	pr_dbg(&ctx->lh, "New connection from %s (fd=%d)", ip_to_str(&addr),
		fd);

	/*
	 * Evaluate the INPUT chain before allocating anything, as the
	 * io_uring loop does: when it is used to shed unwanted clients, a
	 * flood of them should cost no more than an accept and a close.
	 */
	if (!gwp_ctx_acl_client_allowed(ctx, &addr, GWP_ACL_PROTO_TCP)) {
		pr_info(&ctx->lh, "ACL denied client %s", ip_to_str(&addr));
		__sys_close(fd);
		return 0;
	}

	/* --max-conns-per-ip: likewise before anything is read or set up. */
	if (unlikely(ctx->iplim) && !gwp_ctx_iplim_get(w, &addr)) {
		__sys_close(fd);
		return 0;
	}

	gcp = gwp_alloc_conn_pair(w);
	if (unlikely(!gcp)) {
		pr_err(&ctx->lh, "Failed to allocate connection pair on accept");
		if (ctx->iplim)
			gwp_ctx_iplim_put(ctx, &addr);
		__sys_close(fd);
		return handle_accept_error(w, -ENOMEM);
	}

	gcp->client_addr = addr;
	gcp->client.fd = fd;
	if (ctx->iplim)
		gcp->flags |= GWP_CONN_FLAG_IPLIM;

	if (cfg->as_transparent) {
		r = gwp_get_orig_dst(fd, &gcp->client_addr, &gcp->target_addr);
		if (r) {
			pr_warn(&ctx->lh, "No original destination for %s: %s (not a redirected connection?)",
				ip_to_str(&gcp->client_addr),
				r == -ELOOP ? "it is this proxy" : strerror(-r));
			free_conn_pair(w, gcp);
			return 0;
		}
		gwp_conn_set_single_candidate(gcp, &gcp->target_addr);
	} else if (!cfg->as_socks5 && !cfg->as_http) {
		gwp_conn_set_single_candidate(gcp, &ctx->target_addr);
	}

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
		pr_err(&w->ctx->lh, "EPOLLERR on accept event");
		return -EIO;
	}

	for (i = 0; i < nr_loop; i++) {
		r = __handle_ev_accept(w);
		if (r) {
			if (likely(r == -EAGAIN || r == -EINTR)) {
				r = 0;
				break;
			}
			/*
			 * A per-connection failure: already logged, and the
			 * pair (if any) already freed. Returning it kills the
			 * worker, and gwp_ctx_thread_entry() then stops the
			 * whole proxy -- so a single client hitting
			 * ECONNABORTED could take every live connection down
			 * with it. accept(2) says to retry this class, and
			 * io_uring's loop never propagates it either. Keep
			 * draining the backlog instead. Otherwise whether the
			 * error escapes depends only on which of the 32
			 * iterations it landed on.
			 */
			r = 0;
		}
	}

	return r;
}

static int handle_ev_eventfd(struct gwp_wrk *w, struct epoll_event *ev)
{
	uint64_t val;
	ssize_t r;

	if (unlikely(ev->events & EPOLLERR)) {
		pr_err(&w->ctx->lh, "EPOLLERR on eventfd event");
		return -EIO;
	}

	/*
	 * __sys_read(), not glibc's eventfd_read(): that returns -1 and sets
	 * errno, which the loop would read as -EPERM. A spurious wakeup with
	 * nothing to read (-EAGAIN) is not an error either.
	 */
	r = __sys_read(w->ev_fd, &val, sizeof(val));
	if (unlikely(r < 0) && r != -EAGAIN && r != -EINTR)
		return (int)r;

	return 0;
}

static bool adj_epl_out(struct gwp_conn *src, struct gwp_conn *dst)
{
	bool want_out = src->len > 0;

#ifdef CONFIG_HTTPS
	/*
	 * A TLS destination may have ciphertext still queued in its send BIO
	 * (a short socket write, or a handshake/alert record) even when there
	 * is no plaintext to forward, so keep EPOLLOUT armed until it drains.
	 */
	if (dst->tls && gwp_ssl_bio_pending(dst->tls) > 0)
		want_out = true;
#endif

	/* Nothing to write, or the write side is already shut down. */
	if (want_out && !dst->wr_shut) {
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
	uint32_t desired;

	/*
	 * Listen for input only while there is room for it. Once this fd's
	 * read side is at EOF, or while the buffer is full, register neither
	 * EPOLLIN nor EPOLLRDHUP. The registration is level-triggered and no
	 * handler acts on RDHUP alone, so a peer FIN queued behind data we
	 * have no room for would be reported on every epoll_wait() and spin
	 * the worker until the other side drained the buffer. Nothing is
	 * lost by not watching: EPOLLERR and EPOLLHUP are always reported,
	 * and the FIN is read as recv() == 0 once there is room again, which
	 * is also the only point at which data ordering lets us act on it.
	 *
	 * EPOLLHUP cannot be masked, though, and a socket that hangs up with
	 * unread data (its write side shut, then the peer's FIN) would spin
	 * the same way while the buffer is full. So a full buffer parks the
	 * fd edge-triggered: the hangup is reported once, and the switch
	 * back to level-triggered EPOLLIN when room appears reports it again
	 * together with the data still to be read. An EPOLLOUT armed on the
	 * same fd is not lost by this: every EPOLLOUT event leads to a send,
	 * and a socket that is still full wakes us again when it drains.
	 */
	if (src->rd_eof)
		desired = 0;
	else if (src->cap - src->len)
		desired = EPOLLIN | EPOLLRDHUP;
	else
		desired = EPOLLET;

	if ((src->ep_mask & (EPOLLIN | EPOLLRDHUP | EPOLLET)) != desired) {
		src->ep_mask &= ~(EPOLLIN | EPOLLRDHUP | EPOLLET);
		src->ep_mask |= desired;
		return true;
	}

	return false;
}

/*
 * Bring both fds' registrations in line with the pair's buffers. @force_target
 * re-registers the target even when its mask is unchanged, for a target fd that
 * is still registered under another tag (see adopt_winning_attempt()).
 */
__hot
static int __adjust_epl_mask(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			     bool force_target)
{
	bool client_need_ctl = false;
	bool target_need_ctl = force_target;
	struct epoll_event ev;
	int r;

	client_need_ctl |= adj_epl_out(&gcp->target, &gcp->client);
	client_need_ctl |= adj_epl_in(&gcp->client);

	/*
	 * Until the target is connected, its registration belongs to the
	 * connect, and client events must leave it alone. There may be no
	 * target socket yet: connect attempts live in attempt_fd[] until one
	 * wins, and adopt_winning_attempt() sets the mask it registers the
	 * winner with. A target socket created at accept time waits for
	 * EPOLLOUT to learn that its connect completed, which taking it away
	 * for want of client data to send would leave unreported.
	 */
	if (gcp->is_target_alive) {
		target_need_ctl |= adj_epl_out(&gcp->client, &gcp->target);
		target_need_ctl |= adj_epl_in(&gcp->target);
	}

	if (client_need_ctl) {
		ev.events = gcp->client.ep_mask;
		ev.data.u64 = PTR_TO_U64(gcp) | EV_BIT_CLIENT;

		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, gcp->client.fd, &ev);
		if (unlikely(r))
			return r;
	}

	if (target_need_ctl) {
		ev.events = gcp->target.ep_mask;
		ev.data.u64 = PTR_TO_U64(gcp) | EV_BIT_TARGET;

		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, gcp->target.fd, &ev);
		if (unlikely(r))
			return r;
	}

	return 0;
}

#ifdef CONFIG_HTTPS
/*
 * Decrypt as much of what the TLS engine holds as fits into src->buf, without
 * touching the socket. Returns the number of plaintext bytes produced, or <0
 * on error.
 */
static ssize_t tls_decrypt(struct gwp_conn *src)
{
	size_t space = src->cap - src->len, got = 0;
	int sr;

	while (space) {
		size_t out = 0;

		sr = gwp_ssl_read(src->tls, src->buf + src->len, space, &out);
		if (sr == GWP_SSL_OK) {
			if (out == 0) {		/* clean close_notify */
				src->rd_eof = true;
				break;
			}
			src->len += (uint32_t)out;
			got += out;
			space -= out;
			continue;
		}
		if (sr == GWP_SSL_WANT_READ || sr == GWP_SSL_WANT_WRITE)
			break;
		return -EIO;
	}

	return (ssize_t)got;
}

/*
 * TLS receive: decrypt into src->buf, reading more ciphertext from the socket
 * only once the engine has used up what it already holds, so its input stays
 * within about two records. The ciphertext goes straight into the engine's
 * input queue, at least one whole record's worth per call, with no bounce
 * buffer. Anything left on the socket keeps the level-triggered EPOLLIN live.
 * Returns the number of plaintext bytes produced, or <0 on error.
 */
static ssize_t do_recv_tls(struct gwp_conn *src)
{
	ssize_t got = 0, n;
	size_t len;
	void *p;

	if (unlikely(src->len == src->cap))
		return 0;

	if (gwp_ssl_rx_more(src->tls)) {
		got = tls_decrypt(src);
		if (got < 0 || src->len == src->cap)
			return got;
	}

	if (src->rd_eof)
		return got;

	p = gwp_ssl_rx_space(src->tls, GWP_SSL_RECORD_MAX, &len);
	if (unlikely(!p))
		return -ENOMEM;

	n = __sys_recv(src->fd, p, len, MSG_NOSIGNAL);
	if (n > 0) {
		gwp_ssl_rx_commit(src->tls, (size_t)n);
	} else if (n == 0) {
		src->rd_eof = true;
	} else if (n != -EAGAIN && n != -EINTR) {
		return n;
	}

	n = tls_decrypt(src);
	if (n < 0)
		return n;
	return got + n;
}

/*
 * TLS send: encrypt src->buf into the send queue and flush the ciphertext to
 * dst->fd straight from the queue, consuming only what the socket accepts.
 * Unflushed ciphertext stays queued; adj_epl_out() keeps EPOLLOUT armed on a
 * TLS peer while bytes remain.
 *
 * The send queue takes any amount, so encrypt only while less than one source
 * buffer of ciphertext is queued. Past that the plaintext stays in src->buf,
 * whose full buffer stops adj_epl_in() reading from the source, and the queue
 * stays bounded when the peer does not read.
 *
 * Returns the number of ciphertext bytes flushed, or <0 on a fatal error.
 */
static ssize_t do_send_tls(struct gwp_conn *src, struct gwp_conn *dst)
{
	size_t sent = 0, plen;
	const void *p;
	bool capped;
	ssize_t n;
	int sr;

again:
	capped = false;
	while (src->len) {
		size_t consumed = 0;

		if (gwp_ssl_bio_pending(dst->tls) >= src->cap) {
			capped = true;
			break;
		}

		sr = gwp_ssl_write(dst->tls, src->buf, src->len, &consumed);
		if (sr == GWP_SSL_OK) {
			gwp_conn_buf_advance(src, consumed);
			if (consumed == 0)
				break;
			continue;
		}
		if (sr == GWP_SSL_WANT_READ || sr == GWP_SSL_WANT_WRITE)
			break;		/* ciphertext must drain first */
		return -EIO;
	}

	while ((p = gwp_ssl_bio_peek(dst->tls, &plen)) != NULL) {
		n = __sys_send(dst->fd, p, plen, MSG_NOSIGNAL);
		if (n > 0) {
			gwp_ssl_bio_consume(dst->tls, (size_t)n);
			sent += (size_t)n;
			if ((size_t)n < plen)
				return (ssize_t)sent;	/* socket full */
		} else if (n == -EAGAIN || n == -EINTR) {
			return (ssize_t)sent;
		} else if (n == 0) {
			return -ECONNRESET;
		} else {
			return n;
		}
	}

	/* The queue drained with plaintext held back by the cap: go on. */
	if (capped)
		goto again;

	return (ssize_t)sent;
}
#endif /* CONFIG_HTTPS */

__hot
static ssize_t __do_recv(struct gwp_conn *src)
{
	ssize_t ret;
	size_t len;
	char *buf;

#ifdef CONFIG_HTTPS
	if (src->tls)
		return do_recv_tls(src);
#endif

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
		/*
		 * Peer closed its write side. Flag EOF instead of erroring so
		 * the caller can flush any buffered data before tearing the
		 * connection down (see forward_progress()).
		 */
		src->rd_eof = true;
		return 0;
	}

	src->len += (size_t)ret;
	assert(src->len <= src->cap);
	return ret;
}

__hot
static ssize_t __do_send(struct gwp_conn *src, struct gwp_conn *dst)
{
	ssize_t ret;

#ifdef CONFIG_HTTPS
	/*
	 * A TLS peer may still have queued ciphertext to flush even when there
	 * is no new plaintext (src->len == 0), so route through do_send_tls()
	 * unconditionally rather than short-circuiting on an empty source.
	 */
	if (dst->tls)
		return do_send_tls(src, dst);
#endif

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

	gwp_conn_buf_consume(src, (size_t)ret);
	return ret;
}

/*
 * Receive into src->buf. The first pass of do_splice() reads the socket. A TLS
 * source decrypts only as much as src->buf has room for, so when it filled up,
 * the engine may still hold plaintext, or whole records, whose ciphertext has
 * already left the socket, and no EPOLLIN would ever bring them back. Later
 * passes decrypt only those, once the send has made room; they never read the
 * socket, so a busy client cannot keep the worker here.
 */
static ssize_t splice_recv(struct gwp_conn *src, bool first)
{
#ifdef CONFIG_HTTPS
	if (!first)
		return tls_decrypt(src);
#else
	(void)first;
#endif
	return __do_recv(src);
}

static bool splice_again(const struct gwp_conn __unused *src,
			 bool __unused was_full)
{
#ifdef CONFIG_HTTPS
	return src->tls && was_full && src->len < src->cap;
#else
	return false;
#endif
}

__hot
static int do_splice(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
		     struct gwp_conn *src, struct gwp_conn *dst, bool do_recv,
		     bool do_send)
{
	bool first = true, full;
	ssize_t ret;

	do {
		full = false;
		if (do_recv) {
			uint32_t from = src->len;

			ret = splice_recv(src, first);
			if (unlikely(ret < 0))
				return (int)ret;

			if (gwp_http_fwd_active(gcp)) {
				int r = gwp_http_fwd_in(w, gcp, src, from);

				if (unlikely(r))
					return r;
			}
			full = src->len == src->cap;
		}

		if (do_send) {
			ret = __do_send(src, dst);
			if (unlikely(ret < 0))
				return (int)ret;
		}
		first = false;
	} while (splice_again(src, full));

	return 0;
}

__hot
static int prep_and_send_socks5_rep_connect(struct gwp_wrk *w,
					    struct gwp_conn_pair *gcp,
					    int err)
{
	ssize_t sr;
	int r;

	r = gwp_socks5_prep_connect_reply(w, gcp, err);
	if (gcp->target.len) {
		sr = __do_send(&gcp->target, &gcp->client);
		if (unlikely(sr < 0))
			return (int)sr;
	}

	return r;
}

/*
 * ------------------------------------------------------------------------
 * Upstream SOCKS5 proxy client handshake (epoll).
 *
 * When ctx->upstream.enabled, the "target" socket is connected to an upstream
 * SOCKS5 proxy rather than the real destination. Before forwarding, we perform
 * the SOCKS5 client handshake on that socket:
 *
 *    greeting -> [user/pass auth] -> CONNECT(real dst) -> reply
 *
 * gcp->target is used as the I/O buffer for the proxy connection during the
 * handshake (it is otherwise unused until CONN_STATE_FORWARDING). Client data
 * that arrives meanwhile is buffered by handle_ev_client() because
 * is_target_alive is still false.
 * ------------------------------------------------------------------------
 */

/*
 * Describe the upstream destination for logging. With socks5h:// the real
 * destination is a hostname (target_addr is unset), so show up_dst instead.
 */
/*
 * A handshake with the upstream proxy failed. Tell the downstream client in
 * whatever protocol it speaks (gwp_upstream_fail_reply()), then return @err
 * so the caller tears the connection down.
 */
static int upstream_fail(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			 int err)
{
	int r = gwp_upstream_fail_reply(w, gcp, err);

	if (r > 0) {
		ssize_t sr = __do_send(&gcp->target, &gcp->client);

		if (unlikely(sr < 0))
			return (int)sr;
	} else if (r < 0) {
		return r;
	}

	return err;
}

static int upstream_arm(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			uint32_t mask)
{
	struct epoll_event ev;

	/*
	 * Nothing to tell the kernel if the mask is what it already has. A
	 * target just adopted from an attempt has ep_mask 0, which no caller
	 * passes, so it is always re-registered under its proper tag.
	 */
	if (gcp->target.ep_mask == mask)
		return 0;

	gcp->target.ep_mask = mask;
	ev.events = mask;
	ev.data.u64 = PTR_TO_U64(gcp) | EV_BIT_TARGET;
	return __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, gcp->target.fd, &ev);
}

/*
 * The tunnel or UDP association is up, and the handshake's timer has served
 * its purpose. With --idle-timeout it becomes the idle check; without, it
 * just goes.
 */
static int arm_idle_timer(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	int sec = w->ctx->cfg.idle_timeout;

	if (sec <= 0) {
		tmr_disarm(w, gcp, GWP_TMR_CONN);
		return 0;
	}

	gcp->idle_timer = true;
	gcp->last_act = w->now;
	return tmr_arm(w, gcp, GWP_TMR_CONN, sec * 1000ull);
}

/*
 * Send what the client sent while the target was being connected. A TLS
 * client may have sent more than client.buf holds: the rest is held by the
 * engine, off the socket already, so no EPOLLIN would bring it back. Take it
 * in as the send makes room, as forwarding does.
 */
static int flush_early_data(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	bool held = false;

#ifdef CONFIG_HTTPS
	held = gcp->client.tls && gwp_ssl_rx_more(gcp->client.tls);
#endif
	if (!gcp->client.len && !held)
		return 0;

	return do_splice(w, gcp, &gcp->client, &gcp->target, held, true);
}

/* The upstream tunnel is up (reply already spliced); start forwarding. */
static int upstream_finish(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	ssize_t sr;
	int r;

	r = arm_idle_timer(w, gcp);
	if (unlikely(r))
		return r;

	/*
	 * target.ep_mask is left as upstream_arm() registered it, so that
	 * forward_progress() below changes only what actually differs.
	 */
	gcp->up_tx = false;
	gcp->is_target_alive = true;
	gcp->conn_state = CONN_STATE_FORWARDING;

	r = gwp_http_fwd_begin(w, gcp);
	if (unlikely(r))
		return r;

	pr_info(&ctx->lh, "Upstream tunnel established (idx=%u, ca=%s, dst=%s)",
		gcp->idx, ip_to_str(&gcp->client_addr),
		gwp_upstream_dst_str(gcp));

	/* Flush downstream reply (+ early data) to the client. */
	if (gcp->target.len) {
		sr = __do_send(&gcp->target, &gcp->client);
		if (unlikely(sr < 0))
			return (int)sr;
	}

	/* Flush any client data buffered during the handshake to the target. */
	r = flush_early_data(w, gcp);
	if (unlikely(r))
		return r;

	/* And a FIN the client sent meanwhile. */
	return forward_progress(w, gcp, NULL);
}

/*
 * Send the request the handshake has just queued. It is tried at once rather
 * than after another EPOLLOUT: the socket has just connected or answered, so
 * it almost always takes the whole request, and then the reply is all there is
 * to wait for.
 */
static int upstream_send(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	ssize_t sr;

	sr = __do_send(&gcp->target, &gcp->target);
	if (unlikely(sr < 0))
		return (int)sr;

	if (gcp->target.len)
		return upstream_arm(w, gcp, EPOLLOUT | EPOLLRDHUP);

	gcp->up_tx = false;
	return upstream_arm(w, gcp, EPOLLIN | EPOLLRDHUP);
}

/* Begin the upstream-proxy handshake and send its first request. */
static int upstream_start(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	int r = gwp_upstream_hs_start(w, gcp);

	if (r == GWP_UPSTREAM_IO_SEND)
		return upstream_send(w, gcp);
	return r;	/* negative errno */
}

/*
 * Whether part of a reply to the client is still waiting to be sent: in
 * target.buf, or for a TLS client also as ciphertext in the engine.
 */
static bool client_reply_pending(struct gwp_conn_pair *gcp)
{
#ifdef CONFIG_HTTPS
	if (gcp->client.tls && gwp_ssl_bio_pending(gcp->client.tls) > 0)
		return true;
#endif
	return gcp->target.len > 0;
}

/*
 * Connected to the upstream proxy, but the handshake with it has not begun:
 * upstream_hold() left that until the client has its reply.
 */
static bool upstream_start_held(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	int cs = gcp->conn_state;

	return w->ctx->upstream.enabled && gcp->target.fd >= 0 &&
	       (cs == CONN_STATE_SOCKS5_CONNECT || cs == CONN_STATE_HTTP_CONNECT);
}

/*
 * The handshake builds its requests in target.buf, which still holds part
 * of a SOCKS5 method or auth reply to the client: the client was answered
 * and asked to connect in one go, and the reply's send came up short. Have
 * the client socket flush it first (handle_ev_client_held()), and watch the
 * target only for a hangup meanwhile.
 */
static int upstream_hold(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct epoll_event ev;
	int r;

	r = upstream_arm(w, gcp, EPOLLRDHUP);
	if (unlikely(r))
		return r;

	if (!adj_epl_out(&gcp->target, &gcp->client))
		return 0;

	ev.events = gcp->client.ep_mask;
	ev.data.u64 = PTR_TO_U64(gcp) | EV_BIT_CLIENT;
	return __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, gcp->client.fd, &ev);
}

__hot
static int handle_ev_upstream(struct gwp_wrk *w,
			      struct gwp_conn_pair *gcp,
			      struct epoll_event *ev)
{
	ssize_t sr;
	bool notify;
	int r;

	/* Transmit phase: flush the pending request to the proxy. */
	if (gcp->up_tx) {
		if (ev->events & EPOLLOUT) {
			sr = __do_send(&gcp->target, &gcp->target);
			if (unlikely(sr < 0))
				return (int)sr;
			if (gcp->target.len == 0)
				gcp->up_tx = false;
		}

		if (gcp->up_tx) {
			if (ev->events & (EPOLLRDHUP | EPOLLHUP))
				return -ECONNRESET;
			return upstream_arm(w, gcp, EPOLLOUT | EPOLLRDHUP);
		}

		/* Fully sent; wait for the reply. */
		return upstream_arm(w, gcp, EPOLLIN | EPOLLRDHUP);
	}

	/* Receive phase: read and parse the reply. */
	if (ev->events & EPOLLIN) {
		sr = __do_recv(&gcp->target);
		if (unlikely(sr < 0))
			return (int)sr;
		if (unlikely(gcp->target.rd_eof))
			return -ECONNRESET;
	}

	r = gwp_upstream_hs_on_reply(w, gcp, &notify);
	switch (r) {
	case GWP_UPSTREAM_IO_SEND:
		return upstream_send(w, gcp);
	case GWP_UPSTREAM_IO_RECV:
		if (ev->events & (EPOLLRDHUP | EPOLLHUP))
			return -ECONNRESET;
		return upstream_arm(w, gcp, EPOLLIN | EPOLLRDHUP);
	case GWP_UPSTREAM_IO_DONE:
		return upstream_finish(w, gcp);
	default:			/* negative errno */
		return notify ? upstream_fail(w, gcp, r) : r;
	}
}

/*
 * An attempt won the race. Adopt its socket as the pair's target and drop every
 * other attempt and the attempt timer.
 *
 * The fd is left registered under its attempt tag. The caller,
 * handle_ev_target_conn_result(), re-registers it under the normal target tag
 * with the mask it actually needs next, through upstream_arm() or
 * __adjust_epl_mask(); doing it here as well cost a second EPOLL_CTL_MOD right
 * behind the first. ep_mask 0 records that the kernel does not hold a target
 * registration for it yet. Should the caller fail before that, the attempt
 * tag finds the slot empty and the pair is torn down anyway.
 */
static int adopt_winning_attempt(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				 uint8_t slot)
{
	int fd = gcp->attempt_fd[slot];
	int closed, r;

	gcp->attempt_fd[slot] = -1;
	tmr_disarm(w, gcp, GWP_TMR_ATTEMPT);
	closed = gwp_conn_close_attempts(gcp);
	if (closed) {
		/*
		 * Losing sockets are descriptors returned to the process; the
		 * accept path throttles on that count, so tell it.
		 */
		r = credit_fd_closed(w, closed);
		if (unlikely(r))
			return r;
	}

	gcp->target.fd = fd;
	gcp->target.ep_mask = 0;
	return 0;
}

__hot
static int handle_ev_target_conn_result(struct gwp_wrk *w,
					struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	int r;

	/*
	 * Connected to the upstream SOCKS5 proxy. Perform the client handshake
	 * before forwarding; the connect timer is kept to bound it, also while
	 * the client's reply is still being flushed (upstream_hold()).
	 */
	if (ctx->upstream.enabled) {
		if (client_reply_pending(gcp))
			return upstream_hold(w, gcp);
		return upstream_start(w, gcp);
	}

	log_target_connected(w, gcp);
	r = arm_idle_timer(w, gcp);
	if (unlikely(r))
		return r;

	if (gcp->conn_state == CONN_STATE_SOCKS5_CONNECT) {
		r = prep_and_send_socks5_rep_connect(w, gcp, 0);
		if (r)
			return r;
	} else if (gcp->conn_state == CONN_STATE_HTTP_CONNECT) {
		/*
		 * "200 OK" for a CONNECT tunnel, nothing for a forwarding
		 * request -- whose rewritten origin-form request is already
		 * queued in client.buf and flushed to the origin below, with the
		 * origin's response relayed back.
		 */
		r = gwp_http_build_connect_reply(gcp->http_conn, gcp->target.buf,
						 gcp->target.cap);
		if (r < 0)
			return r;
		gcp->target.len = (uint32_t)r;
	}

	gcp->is_target_alive = true;
	gcp->conn_state = CONN_STATE_FORWARDING;

	r = gwp_http_fwd_begin(w, gcp);
	if (unlikely(r))
		return r;

	r = flush_early_data(w, gcp);
	if (unlikely(r))
		return r;

	/*
	 * Pass on a FIN the client sent during the connect. Forced: the
	 * target may still carry its attempt tag.
	 */
	return __forward_progress(w, gcp, NULL, true);
}

/*
 * A racing connect attempt reported a result. The first one to succeed wins and
 * its socket becomes the target; a failure just retires that attempt, and only
 * when nothing is left in flight and no candidate remains does the client hear
 * about it.
 */
__hot
static int handle_ev_target_attempt(struct gwp_wrk *w,
				    struct gwp_conn_pair *gcp, uint8_t slot)
{
	struct gwp_ctx *ctx = w->ctx;
	socklen_t l = sizeof(int);
	int r, err = 0, fd;

	if (unlikely(slot >= GWP_MAX_CONN_CAND))
		return -EINVAL;

	fd = gcp->attempt_fd[slot];
	if (unlikely(fd < 0))
		return 0;		/* already retired */

	r = __sys_getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &l);
	if (unlikely(r < 0)) {
		pr_err(&ctx->lh, "getsockopt error: %s", strerror(-r));
		err = -r;
	}

	if (unlikely(err)) {
		pr_dbg(&ctx->lh, "Target attempt failed: %s (fd=%d, idx=%u, ta=%s)",
			strerror(err), fd, gcp->idx,
			ip_to_str(&gcp->target_addr));

		__sys_close(fd);
		gcp->attempt_fd[slot] = -1;
		r = credit_fd_closed(w, 1);
		if (unlikely(r))
			return r;

		/*
		 * Another attempt may still be racing; only step to a new
		 * candidate once nothing is outstanding, so a slow-but-working
		 * address is not abandoned because a faster one was refused.
		 */
		if (has_inflight_attempt(gcp))
			return 0;

		return connect_next_candidate(w, gcp, -err);
	}

	/*
	 * Restore the address this attempt actually dialled: with a race the
	 * winner is often not the last one started, and target_addr currently
	 * holds whichever candidate was most recently set up. Using the
	 * recorded address also keeps a -j DNAT rewrite intact, which
	 * re-deriving from cand[] would silently undo.
	 */
	gcp->target_addr = gcp->attempt_addr[slot];
	r = adopt_winning_attempt(w, gcp, slot);
	if (unlikely(r))
		return r;

	return handle_ev_target_conn_result(w, gcp);
}

/*
 * The target is done and its data has been handed to the client side. Before
 * the client's write side can be shut, a TLS client is owed a close_notify,
 * and all of the ciphertext must have left: a slow client may not have taken
 * it yet, and adj_epl_out() keeps EPOLLOUT armed to flush the rest and come
 * back here. Returns 1 when the write side can be shut, 0 to wait, or <0 on
 * error.
 */
static int client_wr_flushed(struct gwp_conn_pair __unused *gcp)
{
#ifdef CONFIG_HTTPS
	struct gwp_conn *c = &gcp->client;
	int r;

	if (c->tls) {
		gwp_ssl_shutdown(c->tls);
		r = tls_flush_hs(c);
		if (r)
			return r;
		if (gwp_ssl_bio_pending(c->tls) > 0)
			return 0;
	}
#endif
	return 1;
}

/*
 * After a forwarding splice, propagate half-closes and decide whether the
 * pair is done. Once a direction's source has reached EOF and everything it
 * sent has been flushed to the peer, shut the peer's write side so it sees the
 * FIN. When both directions have been shut, the pair is fully drained and is
 * torn down without dropping any buffered data.
 *
 * @hup, if not NULL, is a side whose fd hung up after its read side was
 * drained (see handle_ev_hup()); it stops being monitored here unless the pair
 * is torn down anyway.
 */
static int __forward_progress(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			      struct gwp_conn *hup, bool force_target)
{
	bool shut_client = false, shut_target = false, done;

	if (gcp->target.rd_eof && gcp->target.len == 0 && !gcp->client.wr_shut) {
		int r = client_wr_flushed(gcp);

		if (r < 0)
			return r;
		/*
		 * Only once a TLS client's ciphertext, close_notify included,
		 * has gone out; the shutdown() itself is issued below, where
		 * it is skipped if the pair is torn down anyway.
		 */
		if (r) {
			shut_client = true;
			gcp->client.wr_shut = true;
		}
	}

	if (gcp->client.rd_eof && gcp->client.len == 0 && !gcp->target.wr_shut) {
		/*
		 * The client may finish before the target is even connected.
		 * There is no target socket yet, or only one still in
		 * SYN_SENT, which shutdown() would abort: hold the FIN back
		 * until handle_ev_target_conn_result() or upstream_finish()
		 * comes back here. A client that hung up altogether is owed
		 * nothing, though, so the pair goes now.
		 */
		if (gcp->is_target_alive) {
			shut_target = true;
			gcp->target.wr_shut = true;
		} else if (gcp->client.wr_shut) {
			return -ECONNRESET;
		}
	}

	/*
	 * Once both directions are done the pair is torn down, and closing
	 * its sockets sends the FINs. A shutdown() right before that close()
	 * only costs a syscall, provided nothing is left unread on the
	 * socket: close() answers unread data with an RST instead of a FIN,
	 * so a socket whose read side has not reached EOF still gets the
	 * explicit shutdown(). Likewise a hung-up fd needs no EPOLL_CTL_DEL
	 * when close() is about to remove it.
	 */
	done = gcp->client.wr_shut && gcp->target.wr_shut;
	if (shut_client && !(done && gcp->client.rd_eof))
		__sys_shutdown(gcp->client.fd, SHUT_WR);
	if (shut_target && !(done && gcp->target.rd_eof))
		__sys_shutdown(gcp->target.fd, SHUT_WR);
	if (done)
		return -ECONNRESET;

	if (hup && hup->ep_mask) {
		__sys_epoll_ctl(w->ep_fd, EPOLL_CTL_DEL, hup->fd, NULL);
		hup->ep_mask = 0;
	}

	return __adjust_epl_mask(w, gcp, force_target);
}

static int forward_progress(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			    struct gwp_conn *hup)
{
	return __forward_progress(w, gcp, hup, false);
}

/*
 * @c's fd hung up (EPOLLHUP) and its read side has already been drained to
 * EOF. No further I/O is possible on it, so mark its write side shut; it must
 * also stop being monitored (EPOLLHUP is level-triggered and would otherwise
 * wake us in a loop), which forward_progress() does unless the pair is done.
 * Returns @c for forward_progress().
 */
static struct gwp_conn *handle_ev_hup(struct gwp_conn *c)
{
	c->wr_shut = true;
	return c;
}

__hot
/*
 * The Connection Attempt Delay expired: bring the next candidate into the race
 * alongside the ones already running. Nothing is cancelled here -- an attempt
 * that is merely slow may still win.
 */
static int handle_attempt_timer(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	if (gcp->next_cand >= gcp->nr_cand)
		return 0;

	/*
	 * -EINPROGRESS is not a failure to report: attempts are still running,
	 * and connect_next_candidate() only speaks to the client once nothing
	 * is left in flight.
	 */
	return connect_next_candidate(w, gcp, -EINPROGRESS);
}

/*
 * EPOLLERR on a target that is not up yet. Only two kinds of pair get here:
 * plain and transparent forwarding, whose target socket is created directly
 * at accept time rather than raced through attempt sockets, and a pair in
 * the upstream proxy handshake. The SOCKS5 and HTTP front-ends connect
 * through attempts, whose failures handle_ev_target_attempt() answers.
 *
 * The connect failed, or the upstream proxy dropped us mid-handshake, so
 * collect the reason and tear the pair down. Neither case has a reply to
 * give, and the socket must not be treated as connected: EPOLLERR is
 * level-triggered and stays raised, so going on with the upstream
 * handshake on it would come straight back here until the connect timer
 * fired.
 */
static int handle_ev_target_conn_err(struct gwp_wrk *w,
				     struct gwp_conn_pair *gcp)
{
	socklen_t l = sizeof(int);
	int r, err = 0;

	r = __sys_getsockopt(gcp->target.fd, SOL_SOCKET, SO_ERROR, &err, &l);
	if (unlikely(r < 0))
		err = -r;
	if (!err)
		err = ECONNRESET;

	pr_dbg(&w->ctx->lh, "Target connect failed: %s (fd=%d, idx=%u, ca=%s)",
		strerror(err), gcp->target.fd, gcp->idx,
		ip_to_str(&gcp->client_addr));
	return -err;
}

static int handle_ev_target(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			    struct epoll_event *ev)
{
	struct gwp_conn *hup = NULL;
	int r;

	/*
	 * Held before the upstream handshake, the target is watched only for
	 * a hangup: the upstream went away before it was spoken to.
	 */
	if (unlikely(upstream_start_held(w, gcp)))
		return -ECONNRESET;

	if (unlikely(ev->events & EPOLLERR)) {
		if (!gcp->is_target_alive)
			return handle_ev_target_conn_err(w, gcp);

		pr_err(&w->ctx->lh, "EPOLLERR on target connection event");
		return -ECONNRESET;
	}

	if (!gcp->is_target_alive) {
		if (gwp_in_upstream_hs(gcp))
			return handle_ev_upstream(w, gcp, ev);

		return handle_ev_target_conn_result(w, gcp);
	}

	assert(gcp->conn_state == CONN_STATE_FORWARDING);

	/*
	 * Drain on EPOLLHUP as well as EPOLLIN: a hung-up socket can still have
	 * unread data in its receive buffer, and EPOLLIN keeps firing (level
	 * triggered) until recv() returns 0 and sets rd_eof.
	 */
	if (ev->events & (EPOLLIN | EPOLLHUP)) {
		r = do_splice(w, gcp, &gcp->target, &gcp->client, true, true);
		if (r)
			return r;
	}

	if (ev->events & EPOLLOUT) {
		r = do_splice(w, gcp, &gcp->client, &gcp->target, true, true);
		if (r)
			return r;
	}

	if ((ev->events & EPOLLHUP) && gcp->target.rd_eof)
		hup = handle_ev_hup(&gcp->target);

	return forward_progress(w, gcp, hup);
}

/*
 * A client event while the upstream proxy handshake runs. The handshake owns
 * the target socket and gcp->target until the tunnel is up, so all there is to
 * do is take in what the client sends; upstream_finish() flushes it to the
 * target. Going through the forwarding path instead armed EPOLLOUT on the
 * client for whatever sat in gcp->target, sent a partial upstream reply to the
 * client, and shut the target's write side on a client half-close.
 */
static int handle_ev_client_upstream_hs(struct gwp_wrk *w,
					struct gwp_conn_pair *gcp,
					struct epoll_event *ev)
{
	struct epoll_event cev;
	int r;

	if (ev->events & (EPOLLIN | EPOLLHUP)) {
		r = do_splice(w, gcp, &gcp->client, &gcp->target, true, false);
		if (r)
			return r;
	}

	/* Both directions gone: nothing left to tunnel for. */
	if ((ev->events & EPOLLHUP) && gcp->client.rd_eof)
		return -ECONNRESET;

	if (!adj_epl_in(&gcp->client))
		return 0;

	cev.events = gcp->client.ep_mask;
	cev.data.u64 = PTR_TO_U64(gcp) | EV_BIT_CLIENT;
	return __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, gcp->client.fd, &cev);
}

/*
 * A client event while the upstream handshake waits for the client's reply to
 * be flushed (upstream_hold()). Once it is out, drop EPOLLOUT and start the
 * handshake; what the client sends is taken in as during the handshake.
 */
static int handle_ev_client_held(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				 struct epoll_event *ev)
{
	struct epoll_event cev;
	ssize_t sr;
	int r;

	if (ev->events & EPOLLOUT) {
		sr = __do_send(&gcp->target, &gcp->client);
		if (unlikely(sr < 0))
			return (int)sr;
	}

	if (!client_reply_pending(gcp)) {
		gcp->client.ep_mask &= ~EPOLLOUT;
		cev.events = gcp->client.ep_mask;
		cev.data.u64 = PTR_TO_U64(gcp) | EV_BIT_CLIENT;
		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, gcp->client.fd,
				    &cev);
		if (unlikely(r))
			return r;

		r = upstream_start(w, gcp);
		if (unlikely(r))
			return r;
	}

	return handle_ev_client_upstream_hs(w, gcp, ev);
}

__hot
static int handle_ev_client(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			    struct epoll_event *ev)
{
	struct gwp_conn *hup = NULL;
	int r;

	if (unlikely(ev->events & EPOLLERR)) {
		pr_err(&w->ctx->lh, "EPOLLERR on client connection event");
		return -ECONNRESET;
	}

	if (gwp_in_upstream_hs(gcp))
		return handle_ev_client_upstream_hs(w, gcp, ev);

	if (unlikely(upstream_start_held(w, gcp)))
		return handle_ev_client_held(w, gcp, ev);

	if (ev->events & (EPOLLIN | EPOLLHUP)) {
		r = do_splice(w, gcp, &gcp->client, &gcp->target, true,
			      gcp->is_target_alive);
		if (r)
			return r;
	}

	/*
	 * Before the target is up, EPOLLOUT on the client can only be the rest
	 * of a handshake reply (target.buf) still being flushed; there is no
	 * target socket to read from yet.
	 */
	if (ev->events & EPOLLOUT) {
		r = do_splice(w, gcp, &gcp->target, &gcp->client,
			      gcp->is_target_alive, true);
		if (r)
			return r;
	}

	if ((ev->events & EPOLLHUP) && gcp->client.rd_eof)
		hup = handle_ev_hup(&gcp->client);

	return forward_progress(w, gcp, hup);
}

__hot
static int handle_conn_timer(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;

	/*
	 * Idle check: close the pair if nothing moved for the whole timeout,
	 * else look again once the rest of it has passed. Re-arming here, not
	 * on every I/O, keeps the cost to one heap update per timeout.
	 */
	if (gcp->idle_timer) {
		int sec = w->ctx->cfg.idle_timeout;
		uint32_t idle = w->now - gcp->last_act;

		if (idle < (uint32_t)sec)
			return tmr_arm(w, gcp, GWP_TMR_CONN,
				       (uint64_t)(sec - (int)idle) * 1000);
		pr_info(&w->ctx->lh, "Idle timeout (idx=%u, ca=%s, ta=%s)",
			gcp->idx, ip_to_str(&gcp->client_addr),
			ip_to_str(&gcp->target_addr));
		return -ETIMEDOUT;
	}

	pr_warn(&ctx->lh, "Connection timeout! (idx=%u, cfd=%d, tfd=%d, ca=%s, ta=%s)",
		gcp->idx, gcp->client.fd, gcp->target.fd,
		ip_to_str(&gcp->client_addr), ip_to_str(&gcp->target_addr));

	/*
	 * A target socket that never came up: tell the client the origin timed
	 * out (SOCKS5 REP 0x06, HTTP 504) instead of just dropping it. Only
	 * once the target socket exists -- the other user of this timer is the
	 * protocol handshake, where the client has not asked for anything yet
	 * and a CONNECT reply would answer a request that was never made.
	 *
	 * Send only what gwp_conn_fail_reply() added: plain forwarding has no
	 * reply to give, and a stalled upstream handshake leaves its own bytes
	 * in target.buf, which are dropped first.
	 */
	if ((gcp->target.fd >= 0 || has_inflight_attempt(gcp)) &&
	    !gcp->is_target_alive) {
		uint32_t len;

		if (gwp_in_upstream_hs(gcp))
			gcp->target.len = 0;
		len = gcp->target.len;
		if (!gwp_conn_fail_reply(w, gcp, -ETIMEDOUT) &&
		    gcp->target.len > len) {
			ssize_t sr = __do_send(&gcp->target, &gcp->client);

			if (unlikely(sr < 0))
				return (int)sr;
		}
	}

	return -ETIMEDOUT;
}

__hot
/*
 * The ACL rejected this target: tell the client (SOCKS5 REP 0x02, or HTTP 403)
 * and return an error so the caller tears the connection down. The reply is
 * sent synchronously here, so it works from both the handshake and the async
 * DNS-completion callers of handle_connect().
 */
static int acl_reject_target(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	int r = gwp_acl_reject_reply(w, gcp);

	if (r != -EACCES)
		return r;

	if (gcp->target.len) {
		ssize_t sr = __do_send(&gcp->target, &gcp->client);

		if (sr < 0)
			return (int)sr;
	}
	return -EACCES;
}

/*
 * Start one connect attempt to gcp->target_addr, which the caller has already
 * selected and had the ACL approve. Registers the new target fd with epoll.
 * Returns 0 once the attempt is in flight (or has already completed), or a
 * negative errno if this attempt could not be started at all -- the caller
 * decides whether another candidate is worth trying.
 */
/* Are any connect attempts of this pair still waiting for a result? */
static bool has_inflight_attempt(const struct gwp_conn_pair *gcp)
{
	uint8_t i;

	for (i = 0; i < GWP_MAX_CONN_CAND; i++) {
		if (gcp->attempt_fd[i] >= 0)
			return true;
	}
	return false;
}

/*
 * Start one connect attempt to gcp->target_addr, which the caller has already
 * selected and had the ACL approve. The socket goes into attempt slot @slot and
 * is registered under its own event tag, so several attempts can be in flight
 * at once and each completion is attributable. Returns 0 once the attempt is
 * running, or a negative errno if it could not be started.
 */
static int start_connect_attempt(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				 uint8_t slot)
{
	struct epoll_event ev;
	bool alive = false;
	int tfd, r;

	if (w->ctx->upstream.enabled) {
		/* Connect to the upstream proxy, not the real destination. */
		tfd = gwp_create_sock_target(w, &w->ctx->upstream.addr,
					     &gcp->acl_sockopt, &alive, true);
	} else {
		tfd = gwp_create_sock_target(w, &gcp->target_addr,
					     &gcp->acl_sockopt, &alive, true);
	}
	if (unlikely(tfd < 0))
		return tfd;

	gcp->attempt_fd[slot] = tfd;
	/* Post-ACL, so a -j DNAT rewrite is what gets recorded. */
	gcp->attempt_addr[slot] = gcp->target_addr;

	/*
	 * Even a connect that completed synchronously is reported through the
	 * event loop, so the winner is picked in exactly one place.
	 */
	ev.events = EPOLLOUT | EPOLLRDHUP;
	ev.data.u64 = PTR_TO_U64(gcp) |
		      (EV_BIT_TARGET_ATTEMPT + ((uint64_t)slot << 48ull));
	r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, tfd, &ev);
	if (unlikely(r)) {
		__sys_close(tfd);
		gcp->attempt_fd[slot] = -1;
		return r;
	}

	return 0;
}

/*
 * Arm the delay after which the next candidate joins the race. Racing is what
 * makes a black-holed address cheap: without it a target that silently drops
 * SYNs costs the whole connect timeout before anything else is tried.
 */
static int arm_attempt_timer(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	int ms;

	if (gcp->next_cand >= gcp->nr_cand)
		return 0;			/* nothing left to start */
	if (w->ctx->cfg.connect_attempt_delay <= 0)
		return 0;			/* racing disabled: fall back only */
	if (w->ctx->upstream.enabled)
		return 0;			/* one proxy, nothing to race */

	ms = w->ctx->cfg.connect_attempt_delay;
	return tmr_arm(w, gcp, GWP_TMR_ATTEMPT, (uint64_t)ms);
}

/*
 * Start the next candidate address, having already tried (or not yet started)
 * the others. @err is why the previous attempt failed, reported to the client
 * if no candidate is left. Returns 0 once an attempt is in flight, or a
 * negative errno once they are exhausted.
 *
 * A candidate the ACL rejects is skipped rather than being fatal: the rule
 * denied that address, not the name, and another address of the same host may
 * well be permitted. Only when every candidate is denied does the client get
 * the ACL rejection.
 */
static int connect_next_candidate(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				  int err)
{
	bool acl_denied = false;
	int r;

	/*
	 * No candidate list at all: socks5h:// hands the hostname to the
	 * upstream proxy and never resolves it here, so target_addr stays
	 * unset and there is exactly one connect to make -- to the upstream.
	 * Attempt it once, leaving target_addr untouched so the ACL keeps
	 * seeing "no resolved IP" and matches on -m domain as before.
	 */
	if (!gcp->nr_cand) {
		if (gcp->next_cand)
			goto exhausted;

		gcp->next_cand = 1;
		if (!gwp_ctx_acl_target_allowed(w->ctx, gcp))
			return acl_reject_target(w, gcp);

		err = start_connect_attempt(w, gcp, 0);
		if (!err)
			return 0;
		goto exhausted;
	}

	while (gcp->next_cand < gcp->nr_cand) {
		uint8_t slot = gcp->next_cand;

		gcp->target_addr = gcp->cand[gcp->next_cand++];

		if (!gwp_ctx_acl_target_allowed(w->ctx, gcp)) {
			acl_denied = true;
			continue;
		}

		gcp->flags |= GWP_CONN_FLAG_ACL_CAND_OK;
		err = start_connect_attempt(w, gcp, slot);
		if (!err) {
			/*
			 * Racing: do not wait for this attempt to resolve
			 * before queueing the next one.
			 */
			r = arm_attempt_timer(w, gcp);
			if (unlikely(r))
				return r;
			return 0;
		}

		pr_dbg(&w->ctx->lh, "Target %s did not start: %s (idx=%u)",
			ip_to_str(&gcp->target_addr), strerror(-err), gcp->idx);

		/*
		 * Chaining: every attempt dials the same upstream proxy, so
		 * walking the target's addresses would just repeat the same
		 * failure. The candidates still matter for the ACL above and
		 * for the destination named to the upstream.
		 */
		if (w->ctx->upstream.enabled)
			break;
	}

	/*
	 * Nothing new could be started. If earlier attempts are still racing,
	 * one of them may yet succeed -- wait for it rather than failing now.
	 */
	if (has_inflight_attempt(gcp))
		return 0;

	/*
	 * The ACL is the reason this request failed only if it denied every
	 * candidate. Once any address was allowed -- possibly on an earlier
	 * walk, whose attempt has since failed -- the honest answer is that
	 * attempt's error, not a rejection that applies to the addresses we
	 * merely skipped.
	 */
	if (acl_denied && !(gcp->flags & GWP_CONN_FLAG_ACL_CAND_OK))
		return acl_reject_target(w, gcp);

exhausted:
	pr_dbg(&w->ctx->lh, "No target address left to try (idx=%u): %s",
		gcp->idx, strerror(-err));

	if (!gwp_conn_fail_reply(w, gcp, err) && gcp->target.len) {
		ssize_t sr = __do_send(&gcp->target, &gcp->client);

		if (unlikely(sr < 0))
			return (int)sr;
	}
	return err;
}

static int handle_connect(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	int r;

	/*
	 * The connect timeout bounds the whole operation, across every
	 * candidate address, so it is armed once here rather than per attempt.
	 *
	 * The SOCKS5 and HTTP handshakes ran under the protocol timer, which
	 * has served its purpose by now: the same timer now runs for the
	 * connect timeout instead, or goes when there is none.
	 */
	r = w->ctx->cfg.connect_timeout;
	if (r > 0) {
		r = tmr_arm(w, gcp, GWP_TMR_CONN, r * 1000ull);
		if (unlikely(r))
			return r;
	} else {
		tmr_disarm(w, gcp, GWP_TMR_CONN);
	}

	/*
	 * The client stays registered under EV_BIT_CLIENT_PROT: from here on
	 * the pair's state hands its events to handle_ev_client() (see
	 * client_past_handshake()), which saves an EPOLL_CTL_MOD that would
	 * only change the tag.
	 *
	 * Take the first candidate the ACL allows; the same helper walks the
	 * rest, so a candidate that cannot even be started is not fatal while
	 * others remain.
	 */
	r = connect_next_candidate(w, gcp, -EHOSTUNREACH);
	if (r)
		return r;

	r = gcp->conn_state;
	if (CONN_STATE_SOCKS5_MIN <= r && r <= CONN_STATE_SOCKS5_MAX)
		gcp->conn_state = CONN_STATE_SOCKS5_CONNECT;
	else if (CONN_STATE_HTTP_MIN <= r && r <= CONN_STATE_HTTP_MAX)
		gcp->conn_state = CONN_STATE_HTTP_CONNECT;

	log_conn_pair_created(w, gcp);
	return 0;
}

static void log_dns_query(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			  struct gwp_dns_entry *gde)
{
	struct gwp_ctx *ctx = w->ctx;

	if (gde->res) {
		pr_dbg(&ctx->lh, "DNS query failed: %s:%hu (res=%d; idx=%u; cfd=%d; tfd=%d; ca=%s)",
			gde->name, gde->port, gde->res,
			gcp->idx, gcp->client.fd, gcp->target.fd,
			ip_to_str(&gcp->client_addr));
		return;
	}

	pr_dbg(&ctx->lh, "DNS query resolved: %s:%hu -> %s (res=%d; idx=%u; cfd=%d; tfd=%d; ca=%s)",
		gde->name, gde->port, ip_to_str(&gde->addrs[0]), gde->res,
		gcp->idx, gcp->client.fd, gcp->target.fd,
		ip_to_str(&gcp->client_addr));
}

__hot
static int handle_ev_dns_query(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_dns_entry *gde = gcp->gde;
	int r;

	assert(gde);
	assert(gcp->conn_state == CONN_STATE_SOCKS5_DNS_QUERY ||
	       gcp->conn_state == CONN_STATE_HTTP_DNS_QUERY);

	log_dns_query(w, gcp, gde);
	if (likely(!gde->res)) {
		gwp_conn_set_candidates(gcp, gde->addrs, gde->nr_addrs);
		r = handle_connect(w, gcp);
	} else {
		/*
		 * The name did not resolve, so the origin is unreachable:
		 * answer in whatever protocol the client speaks (SOCKS5 REP,
		 * or HTTP 502) instead of hanging up silently.
		 */
		r = gwp_conn_fail_reply(w, gcp, gde->res);
		if (!r && gcp->target.len) {
			ssize_t sr = __do_send(&gcp->target, &gcp->client);

			if (unlikely(sr < 0))
				r = (int)sr;
		}
		if (!r)
			r = gde->res ? gde->res : -EIO;
	}

	gwp_dns_entry_free(gde);
	gcp->gde = NULL;
	return r;
}

/*
 * Finished getaddrinfo() lookups of this worker. One wakeup may carry many.
 * A pair torn down earlier in this batch still owns its entry, since the
 * teardown that cancels it runs after the batch; take it back here.
 */
static int handle_ev_dns_cq(struct gwp_wrk *w)
{
	struct gwp_dns_entry *e, *next;
	int r, ret = 0;

	e = gwp_dns_cq_pop(w->ctx->dns, w->idx);
	for (; e; e = next) {
		struct gwp_conn_pair *gcp = e->udata;

		next = e->next;
		/* Its pair was freed while an earlier entry was handled. */
		if (gwp_dns_entry_cancelled(e)) {
			gwp_dns_entry_free(e);
			continue;
		}

		assert(gcp->gde == e);
		if (gcp->flags & GWP_CONN_FLAG_IS_DYING) {
			gcp->gde = NULL;
			gwp_dns_entry_free(e);
			continue;
		}

		r = handle_ev_dns_query(w, gcp);
		if (r) {
			r = free_conn_pair(w, gcp);
			if (unlikely(r) && !ret)
				ret = r;
		}
	}

	return ret;
}

static bool is_ev_bit_conn_pair(uint64_t ev_bit)
{
	/* Every attempt slot of a Happy Eyeballs race points at the pair. */
	if (ev_bit >= EV_BIT_TARGET_ATTEMPT &&
	    ev_bit < EV_BIT_TARGET_ATTEMPT +
		     ((uint64_t)GWP_MAX_CONN_CAND << 48ull))
		return true;

	switch (ev_bit) {
	case EV_BIT_CLIENT:
	case EV_BIT_TARGET:
	case EV_BIT_CLIENT_SOCKS5:
	case EV_BIT_CLIENT_PROT:
	case EV_BIT_UDP_RELAY:
	case EV_BIT_RAW_DNS_QUERY:
		return true;
	default:
		return false;
	}
}

/*
 * SOCKS5 UDP relay: drain the per-connection relay socket. A datagram whose
 * source is (or, for the first one, becomes) the pinned client is unwrapped and
 * forwarded to its encapsulated target; one from a target the client has sent
 * to is a reply, which is wrapped with a SOCKS5 UDP header and sent back to the
 * client, and anything else is dropped (see gwp_udp_relay_classify()). UDP is
 * lossy, so individual datagram errors are dropped rather than failing the
 * association; only the TCP control connection's close tears it down.
 *
 * The relay socket is dual-stack, so IPv4 and IPv6 targets both work; an IPv4
 * target's address is carried v4-mapped internally and unmapped again for the
 * reply header (see gwp_socks5_addr_to_sockaddr / reply_addr_from_sockaddr).
 *
 * Known limitations, each a follow-up:
 *   - Domain-name (ATYP=0x03) encapsulated targets need DNS in the datagram
 *     path and are dropped for now.
 *   - Only the last GWP_UDP_MAX_PEERS targets the client sent to may reply;
 *     a reply from one evicted since is dropped like any other stranger's.
 */
static int handle_ev_udp_relay(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	const size_t off = GWP_SOCKS5_UDP_HDR_MAX;
	unsigned char *buf = w->udp_buf;
	int fd = gcp->udp_fd;
	int budget = 64;

	/*
	 * Drain in bounded batches rather than until EAGAIN: a flood on one
	 * association must not starve the rest of the worker. Any datagrams
	 * left unread keep the socket readable, so level-triggered epoll
	 * re-enters this handler on the next wakeup.
	 */
	while (budget-- > 0) {
		struct gwp_sockaddr src;
		socklen_t srclen = sizeof(src);
		struct gwp_udp_out out;
		ssize_t n;

		n = __sys_recvfrom(fd, buf + off, 65535, MSG_NOSIGNAL,
				   &src.sa, &srclen);
		if (n < 0) {
			if (n != -EAGAIN && n != -EINTR)
				pr_dbg(&w->ctx->lh, "UDP relay recvfrom: %s",
					strerror((int)-n));
			return 0;
		}

		if (gwp_udp_relay_classify(w, gcp, buf + off, (size_t)n, &src,
					   &out) == GWP_UDP_DROP)
			continue;

		__sys_sendto(fd, out.buf, out.len, MSG_NOSIGNAL, &out.dst.sa,
			     out.dstlen);
	}

	return 0;
}

/*
 * Register the freshly-bound UDP relay socket; its reply is flushed by the
 * generic prot path.
 */
static int handle_udp_associate(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct epoll_event ev;
	int r;

	/*
	 * The association is long-lived, so the protocol-handshake timeout
	 * that was armed for the negotiation must not fire and tear the relay
	 * down mid-session: it becomes the idle check, or goes.
	 */
	r = arm_idle_timer(w, gcp);
	if (unlikely(r))
		return r;

	ev.events = EPOLLIN;
	ev.data.u64 = PTR_TO_U64(gcp) | EV_BIT_UDP_RELAY;
	return __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, gcp->udp_fd, &ev);
}

static int chk_socks5(struct gwp_wrk *w, struct gwp_conn_pair *gcp, int r)
{
	if (r == -EINPROGRESS && gcp->conn_state == CONN_STATE_SOCKS5_DNS_QUERY)
		return chk_handle_dns_query(w, gcp);

	if (r == 0 && gcp->conn_state == CONN_STATE_SOCKS5_CONNECT)
		return handle_connect(w, gcp);

	if (r == 0 && gcp->conn_state == CONN_STATE_SOCKS5_UDP_ASSOCIATE)
		return handle_udp_associate(w, gcp);

	return r;
}

static int handle_conn_state_socks5(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	return chk_socks5(w, gcp, gwp_handle_conn_state_socks5(w, gcp));
}

static int chk_http(struct gwp_wrk *w, struct gwp_conn_pair *gcp, int r)
{
	if (r == -EINPROGRESS && gcp->conn_state == CONN_STATE_HTTP_DNS_QUERY)
		return chk_handle_dns_query(w, gcp);

	if (r == 0 && gcp->conn_state == CONN_STATE_HTTP_CONNECT)
		return handle_connect(w, gcp);

	return r;
}

static int handle_conn_state_http(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	return chk_http(w, gcp, gwp_handle_conn_state_http(w, gcp));
}

static int handle_conn_state_prot(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	int ct, r = gwp_handle_conn_state_prot(w, gcp);

	if (r == -EAGAIN)
		return r;

	ct = gcp->conn_state;
	if (ct == CONN_STATE_PROT) {
		/*
		 * Still undecided, so no state machine owns this connection
		 * yet and the ranges below do not describe it. It happens
		 * whenever every enabled front-end rejected the bytes: with
		 * only one of --as-socks5/--as-http on there is no fallback
		 * left, so gwp_handle_conn_state_prot() hands back -EINVAL
		 * with the state untouched. Report that rather than treating
		 * it as an impossible state -- it is ordinary garbage input,
		 * and asserting on it lets any client abort the process.
		 */
		return r < 0 ? r : -EINVAL;
	}
	if (CONN_STATE_HTTP_MIN < ct && ct < CONN_STATE_HTTP_MAX) {
		assert(w->ctx->cfg.as_http);
		return chk_http(w, gcp, r);
	} else if (CONN_STATE_SOCKS5_MIN < ct && ct < CONN_STATE_SOCKS5_MAX) {
		assert(w->ctx->cfg.as_socks5);
		return chk_socks5(w, gcp, r);
	} else {
		assert(0 && "Invalid connection state!");
		return -EINVAL;
	}
}

/*
 * Has the client's handshake handed over to the connect? handle_connect()
 * does not retag the client fd, so a client still registered under
 * EV_BIT_CLIENT_PROT belongs to handle_ev_client() from then on: it buffers
 * what the client sends until the target is up, and then forwards.
 */
static bool client_past_handshake(const struct gwp_conn_pair *gcp)
{
	int cs = gcp->conn_state;

	return cs == CONN_STATE_SOCKS5_CONNECT ||
	       cs == CONN_STATE_HTTP_CONNECT ||
	       cs == CONN_STATE_FORWARDING || gwp_in_upstream_hs(gcp);
}

/*
 * A FIN from the client during the handshake. Before its request is complete
 * the client has given up, and the pair goes. Once the request is complete and
 * only the lookup of its target's name is outstanding, the client has merely
 * finished sending: a client may well close its write side right after the
 * request and wait for the answer. The connect goes ahead and the FIN is
 * passed on once the target is up, as for a FIN during the connect (see
 * handle_ev_target_conn_result()); handle_ev_client_prot() stops watching
 * for input meanwhile, as there is no more of it.
 */
static int client_prot_eof(const struct gwp_conn_pair *gcp)
{
	int cs = gcp->conn_state;

	if (cs == CONN_STATE_SOCKS5_DNS_QUERY || cs == CONN_STATE_HTTP_DNS_QUERY ||
	    client_past_handshake(gcp))
		return 0;
	return -ECONNRESET;
}

/*
 * Keep EPOLLOUT on the client exactly while part of a reply to it is still
 * pending, so a short send is finished by handle_ev_client_prot_out() (or,
 * past the handshake, by handle_ev_client()).
 */
static int arm_client_prot_out(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct epoll_event evl;

	if (likely(!adj_epl_out(&gcp->target, &gcp->client)))
		return 0;

	pr_dbg(&w->ctx->lh, "Handling short send on client prot data");
	evl.events = gcp->client.ep_mask;
	evl.data.u64 = PTR_TO_U64(gcp) | EV_BIT_CLIENT_PROT;
	return __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, gcp->client.fd, &evl);
}

static int handle_ev_client_prot_in(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	uint32_t from = gcp->client.len;
	ssize_t ret;
	int r, ct;

	ret = __do_recv(&gcp->client);
	if (unlikely(ret < 0))
		return (int)ret;
	if (!ret)
		return gcp->client.rd_eof ? client_prot_eof(gcp) : 0;

	/*
	 * More of a forwarding request's body (or what follows it) arriving
	 * while the origin is still being resolved.
	 */
	if (gwp_http_fwd_active(gcp)) {
		r = gwp_http_fwd_in(w, gcp, &gcp->client, from);
		if (unlikely(r))
			return r;
	}

	ct = gcp->conn_state;
	if (ct == CONN_STATE_SOCKS5_UDP_ASSOCIATE) {
		/*
		 * The TCP control connection is idle once the UDP association is
		 * up (the relay runs on gcp->udp_fd). Discard any stray bytes;
		 * a peer close is turned into -ECONNRESET and tears the
		 * association down.
		 */
		gcp->client.len = 0;
		return gcp->client.rd_eof ? -ECONNRESET : 0;
	}
	if (ct == CONN_STATE_PROT) {
		r = handle_conn_state_prot(w, gcp);
	} else if (CONN_STATE_HTTP_MIN < ct && ct < CONN_STATE_HTTP_MAX) {
		assert(w->ctx->cfg.as_http);
		r = handle_conn_state_http(w, gcp);
	} else if (CONN_STATE_SOCKS5_MIN < ct && ct < CONN_STATE_SOCKS5_MAX) {
		assert(w->ctx->cfg.as_socks5);
		r = handle_conn_state_socks5(w, gcp);
	} else {
		assert(0 && "Invalid connection state!");
		return -EINVAL;
	}

	if (r == -EAGAIN)
		r = 0;

	if (gcp->target.len) {
		ret = __do_send(&gcp->target, &gcp->client);
		if (ret < 0)
			return (int)ret;
	}

	/*
	 * A reply the socket did not take whole must not wait for the client
	 * to send again: it is likely waiting for that very reply.
	 */
	if (!r) {
		r = arm_client_prot_out(w, gcp);
		if (unlikely(r))
			return r;
	}

	/* A TLS client's last records and its FIN can come in one recv(). */
	if (!r && unlikely(gcp->client.rd_eof))
		r = client_prot_eof(gcp);
	return r;
}

static int handle_ev_client_prot_out(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	ssize_t ret;

	ret = __do_send(&gcp->target, &gcp->client);
	if (ret < 0)
		return (int)ret;

	return arm_client_prot_out(w, gcp);
}

/*
 * Take in what the client sends during the handshake, and act on it. A TLS
 * client's records may already be off the socket, held by the engine: no
 * EPOLLIN brings them back, so work through them for as long as
 * client.buf has room and the handshake still owns the client. That goes
 * on past CONN_STATE_PROT: the client buffer may fill in the middle of a
 * SOCKS5 or HTTP handshake (a greeting followed by a long authentication
 * request, say), and the rest is only taken once that has been parsed.
 * Records left once the connect has started are taken when it completes
 * (see flush_early_data()).
 */
static int client_prot_in(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	int r = handle_ev_client_prot_in(w, gcp);

#ifdef CONFIG_HTTPS
	while (!r && gcp->client.tls && !client_past_handshake(gcp) &&
	       gcp->client.len < gcp->client.cap &&
	       gwp_ssl_rx_more(gcp->client.tls))
		r = handle_ev_client_prot_in(w, gcp);
#endif
	return r;
}

#ifdef CONFIG_HTTPS
/* Re-arm the client fd under EV_BIT_CLIENT_PROT with @mask. */
static int tls_arm_client(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			  uint32_t mask)
{
	struct epoll_event ev;

	gcp->client.ep_mask = mask;
	ev.events = mask;
	ev.data.u64 = PTR_TO_U64(gcp) | EV_BIT_CLIENT_PROT;
	return __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, gcp->client.fd, &ev);
}

/* Flush queued handshake/alert ciphertext to the client, best effort. */
static int tls_flush_hs(struct gwp_conn *c)
{
	const void *p;
	size_t plen;
	ssize_t n;

	while ((p = gwp_ssl_bio_peek(c->tls, &plen)) != NULL) {
		n = __sys_send(c->fd, p, plen, MSG_NOSIGNAL);
		if (n > 0) {
			gwp_ssl_bio_consume(c->tls, (size_t)n);
			if ((size_t)n < plen)
				break;
		} else if (n == -EAGAIN || n == -EINTR) {
			break;
		} else {
			return (n == 0) ? -ECONNRESET : (int)n;
		}
	}

	return 0;
}

/*
 * Drive the server-side TLS handshake: feed available ciphertext, step the
 * handshake, flush any records it produced. On completion, switch to
 * CONN_STATE_PROT and process any application data the same recv() already
 * buffered inside the engine (no further EPOLLIN would surface it).
 */
static int handle_ev_tls_handshake(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_conn *c = &gcp->client;
	uint32_t mask;
	size_t len;
	ssize_t n;
	int hs, r;
	void *p;

	p = gwp_ssl_rx_space(c->tls, GWP_SSL_RECORD_MAX, &len);
	if (unlikely(!p))
		return -ENOMEM;

	n = __sys_recv(c->fd, p, len, MSG_NOSIGNAL);
	if (n > 0) {
		gwp_ssl_rx_commit(c->tls, (size_t)n);
	} else if (n == 0) {
		return -ECONNRESET;		/* peer closed mid-handshake */
	} else if (n != -EAGAIN && n != -EINTR) {
		return (int)n;
	}

	hs = gwp_ssl_handshake(c->tls);
	if (hs == GWP_SSL_ERROR) {
		pr_dbg(&w->ctx->lh, "TLS handshake failed: %s", gwp_ssl_errstr());
		return -ECONNRESET;
	}

	r = tls_flush_hs(c);
	if (r)
		return r;

	if (hs != GWP_SSL_OK) {
		/* Still handshaking: want more ciphertext, and to flush ours. */
		mask = EPOLLIN | EPOLLRDHUP;
		if (gwp_ssl_bio_pending(c->tls) > 0)
			mask |= EPOLLOUT;
		return tls_arm_client(w, gcp, mask);
	}

	pr_dbg(&w->ctx->lh, "TLS handshake complete (cfd=%d, alpn=%s)", c->fd,
	       gwp_ssl_alpn(c->tls) ?: "none");
	gcp->conn_state = CONN_STATE_PROT;
	mask = EPOLLIN | EPOLLRDHUP;
	if (gwp_ssl_bio_pending(c->tls) > 0)
		mask |= EPOLLOUT;
	r = tls_arm_client(w, gcp, mask);
	if (r)
		return r;

	return client_prot_in(w, gcp);
}

/*
 * First-byte probe on a TLS-capable listener. A TLS record begins with 0x16
 * (handshake); SOCKS5 starts 0x05, SOCKS4 0x04 and HTTP with an ASCII letter,
 * so 0x16 is unambiguous. Non-TLS clients fall through to CONN_STATE_PROT with
 * the peeked byte left in the socket for the normal plaintext path.
 */
static int handle_ev_tls_detect(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	unsigned char b;
	ssize_t n;

	n = __sys_recv(gcp->client.fd, &b, 1, MSG_PEEK | MSG_NOSIGNAL);
	if (n < 0) {
		if (n == -EAGAIN || n == -EINTR)
			return 0;
		return (int)n;
	}
	if (n == 0)
		return -ECONNRESET;

	if (b != 0x16) {
		gcp->conn_state = CONN_STATE_PROT;
		return 0;
	}

	gcp->client.tls = gwp_ssl_server_new(ctx->ssl_ctx);
	if (!gcp->client.tls) {
		pr_err(&ctx->lh, "Failed to allocate TLS connection state");
		return -ENOMEM;
	}

	gcp->conn_state = CONN_STATE_TLS_HANDSHAKE;
	return handle_ev_tls_handshake(w, gcp);
}
#endif /* CONFIG_HTTPS */

static int handle_ev_client_prot(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				 struct epoll_event *ev)
{
	int r;

#ifdef CONFIG_HTTPS
	if (gcp->conn_state == CONN_STATE_TLS_DETECT) {
		r = handle_ev_tls_detect(w, gcp);
		if (r)
			return r;
		/* Only a plaintext fall-through continues to the PROT path. */
		if (gcp->conn_state != CONN_STATE_PROT)
			return 0;
	} else if (gcp->conn_state == CONN_STATE_TLS_HANDSHAKE) {
		return handle_ev_tls_handshake(w, gcp);
	}
#endif

	if (unlikely(!(ev->events & (EPOLLIN | EPOLLOUT))))
		return -EIO;

	if (ev->events & EPOLLOUT) {
		r = handle_ev_client_prot_out(w, gcp);
		if (r)
			return r;
	}

	if (ev->events & EPOLLIN) {
		r = client_prot_in(w, gcp);
		if (r)
			return r;
	}

	/*
	 * While the request waits on DNS or the connect, what the client
	 * sends behind it stays in client.buf. Once that is full, recv() is
	 * skipped, and a level-triggered EPOLLIN would report the same unread
	 * data on every epoll_wait(), spinning the worker for as long as the
	 * lookup takes. Park the fd as forwarding does (adj_epl_in());
	 * __adjust_epl_mask() takes it back once the target is up and the
	 * buffer drains.
	 */
	if (adj_epl_in(&gcp->client)) {
		struct epoll_event cev;

		cev.events = gcp->client.ep_mask;
		cev.data.u64 = PTR_TO_U64(gcp) | EV_BIT_CLIENT_PROT;
		return __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, gcp->client.fd,
				       &cev);
	}

	return 0;
}

static int handle_event(struct gwp_wrk *w, struct epoll_event *ev)
{
	uint64_t ev_bit;
	void *udata;
	int r;

	ev_bit = GET_EV_BIT(ev->data.u64);
	udata = U64_TO_PTR(CLEAR_EV_BIT(ev->data.u64));

	if (is_ev_bit_conn_pair(ev_bit)) {
		struct gwp_conn_pair *gcp = udata;

		/* Torn down earlier in this batch; see free_conn_pair(). */
		if (gcp->flags & GWP_CONN_FLAG_IS_DYING)
			return 0;
		/* Any event is activity (--idle-timeout). */
		gcp->last_act = w->now;
	}

	/*
	 * A racing connect attempt: the slot index rides in the tag, so the
	 * pair pointer in the low bits is untouched.
	 */
	if (ev_bit >= EV_BIT_TARGET_ATTEMPT &&
	    ev_bit < EV_BIT_TARGET_ATTEMPT +
		     ((uint64_t)GWP_MAX_CONN_CAND << 48ull)) {
		uint8_t slot = (ev_bit - EV_BIT_TARGET_ATTEMPT) >> 48ull;

		r = handle_ev_target_attempt(w, udata, slot);
		goto out;
	}

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
	case EV_BIT_CLIENT_PROT:
		if (client_past_handshake(udata))
			r = handle_ev_client(w, udata, ev);
		else
			r = handle_ev_client_prot(w, udata, ev);
		break;
	case EV_BIT_UDP_RELAY:
		r = handle_ev_udp_relay(w, udata);
		break;
	case EV_BIT_DNS_QUERY:
		r = handle_ev_dns_cq(w);
		break;
	case EV_BIT_RAW_DNS_QUERY:
		r = handle_ev_raw_dns_query(w, udata);
		break;
	default:
		pr_err(&w->ctx->lh, "Unknown event bit: %" PRIu64, ev_bit);
		return -EINVAL;
	}

out:
	if (r && is_ev_bit_conn_pair(ev_bit)) {
		struct gwp_conn_pair *gcp = udata;
		r = free_conn_pair(w, gcp);
	}

	return r;
}

/*
 * Run the timers that are due, at most a batch's worth (w->evsz) at a time,
 * as many as one epoll_wait() reports events: when more are due, the next
 * epoll_wait() does not block and they run after its events. A pair a timer
 * tears down is freed with the rest of the batch (free_conn_pair()).
 */
static int run_timers(struct gwp_wrk *w)
{
	uint32_t budget = w->evsz;
	const struct gwp_tmr *t;
	uint64_t now;
	int r;

	t = gwp_tmr_first(&w->tmrs);
	if (likely(!t))
		return 0;

	now = now_ms();
	for (; t && t->at_ms <= now && budget; t = gwp_tmr_first(&w->tmrs)) {
		struct gwp_conn_pair *gcp = t->gcp;
		uint32_t kind = t->kind;

		budget--;
		tmr_disarm(w, gcp, kind);
		if (kind == GWP_TMR_CONN)
			r = handle_conn_timer(w, gcp);
		else
			r = handle_attempt_timer(w, gcp);

		if (r) {
			r = free_conn_pair(w, gcp);
			if (unlikely(r))
				return r;
		}
	}

	return 0;
}

static int handle_events(struct gwp_wrk *w, int nr_events)
{
	struct epoll_event *events = w->events;
	struct gwp_ctx *ctx = w->ctx;
	int i, r = 0, x;

	for (i = 0; i < nr_events; i++) {
		if (unlikely(ctx->stop))
			break;

		r = handle_event(w, &events[i]);
		if (unlikely(r < 0))
			break;

		if (unlikely(w->ev_need_reload))
			break;
	}

	if (r >= 0 && likely(!ctx->stop)) {
		x = run_timers(w);
		if (unlikely(x))
			r = x;
	}

	if (r >= 0) {
		x = run_retries(w);
		if (unlikely(x))
			r = x;
	}

	x = reap_dead_pairs(w);
	if (unlikely(x) && r >= 0)
		r = x;

	return r;
}

static int fish_events(struct gwp_wrk *w)
{
	int r;

	w->ev_need_reload = false;
	r = __sys_epoll_wait(w->ep_fd, w->events, w->evsz, wait_timeout(w));
	w->now = gwp_now_sec();
	if (unlikely(r < 0)) {
		if (r != -EINTR)
			pr_err(&w->ctx->lh, "epoll_wait failed: %s", strerror(-r));
		else
			r = 0;
	}

	return r;
}

int gwp_ctx_thread_entry_epoll(struct gwp_wrk *w)
{
	struct gwp_ctx *ctx = w->ctx;
	int r = 0;

	pr_info(&ctx->lh, "Worker %u started (epoll)", w->idx);

	while (!ctx->stop) {
		r = fish_events(w);
		if (unlikely(r < 0))
			break;

		r = handle_events(w, r);
		if (unlikely(r < 0))
			break;
	}

	return r;
}

__cold
void gwp_ctx_signal_all_epoll(struct gwp_ctx *ctx)
{
	int i;

	ctx->stop = true;
	for (i = 0; i < ctx->cfg.nr_workers; i++) {
		struct gwp_wrk *w = &ctx->workers[i];
		const uint64_t one = 1;
		ssize_t r;

		if (w->ev_fd < 0)
			continue;

		/*
		 * __sys_write() returns -errno, so the EINTR retry works;
		 * glibc's eventfd_write() returns -1 and never matched it.
		 *
		 * The write needs no handling beyond that retry. Adding 1 to
		 * an eventfd fails only with EAGAIN, when the counter would
		 * pass 2^64 - 2, and here it counts stop requests, which the
		 * worker's read resets. Anything else (EBADF, EINVAL) would be
		 * a bug: ev_fd is -1 whenever the eventfd is not open.
		 */
		do {
			r = __sys_write(w->ev_fd, &one, sizeof(one));
		} while (r == -EINTR);
		assert(r == (ssize_t)sizeof(one));
	}
}
