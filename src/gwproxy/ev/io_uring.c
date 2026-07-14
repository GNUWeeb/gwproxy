// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifdef CONFIG_IO_URING

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <gwproxy/ev/io_uring.h>
#include <gwproxy/gwproxy.h>
#include <gwproxy/common.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/eventfd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <sys/inotify.h>
#include <liburing.h>
#include <poll.h>

#define USE_SEND_ZC 0

__cold
int gwp_ctx_init_thread_io_uring(struct gwp_wrk *w)
{
	struct iou *iou;
	int r;

	iou = calloc(1, sizeof(*iou));
	if (!iou)
		return -ENOMEM;

	r = io_uring_queue_init(1024, &iou->ring, 0);
	if (r < 0)
		goto err_free_iou;

	w->iou = iou;
	return 0;

err_free_iou:
	free(iou);
	return r;
}

static void log_submit_err(struct gwp_wrk *w, int r)
{
	pr_err(&w->ctx->lh, "io_uring_submit(): %s", strerror(-r));
}

static int io_uring_submit_eintr(struct io_uring *ring, size_t nr_attemps)
{
	int r = 0;

	while (nr_attemps--) {
		r = io_uring_submit(ring);
		if (likely(r >= 0 || r != -EINTR))
			break;
	}

	return r;
}

static struct io_uring_sqe *__get_sqe_nofail(struct io_uring *ring)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	if (unlikely(!sqe)) {
		int r = io_uring_submit_eintr(ring, 8);
		if (unlikely(r < 0))
			return NULL;

		sqe = io_uring_get_sqe(ring);
		if (unlikely(!sqe))
			return NULL;
	}

	return sqe;
}

static struct io_uring_sqe *get_sqe_nofail(struct gwp_wrk *w)
{
	struct io_uring_sqe *sqe = __get_sqe_nofail(&w->iou->ring);

	if (likely(sqe))
		return sqe;

	pr_err(&w->ctx->lh, "Failed to get io_uring sqe for worker %u", w->idx);
	abort();
}

__cold
void gwp_ctx_free_thread_io_uring(struct gwp_wrk *w)
{
	io_uring_queue_exit(&w->iou->ring);
	pr_dbg(&w->ctx->lh, "Worker %u io_uring queue exited", w->idx);
	free(w->iou);
	w->iou = NULL;
}

static int prep_nr_sqes(struct gwp_wrk *w, unsigned nr)
{
	if (io_uring_sq_space_left(&w->iou->ring) < nr) {
		int r = io_uring_submit_eintr(&w->iou->ring, 8);
		if (unlikely(r < 0)) {
			log_submit_err(w, r);
			return r;
		}
	}

	return 0;
}

static void arm_accept(struct gwp_wrk *w)
{
	struct io_uring_sqe *s = get_sqe_nofail(w);
	struct iou *iou = w->iou;
	struct sockaddr *addr = &iou->accept_addr.sa;
	socklen_t *addr_len = &iou->accept_addr_len;

	*addr_len = sizeof(iou->accept_addr);
	io_uring_prep_accept(s, w->tcp_fd, addr, addr_len, SOCK_CLOEXEC);
	s->user_data = EV_BIT_IOU_ACCEPT;
}

static void prep_close(struct gwp_wrk *w, int fd)
{
	struct io_uring_sqe *s = get_sqe_nofail(w);
	if (unlikely(!s)) {
		pr_err(&w->ctx->lh, "Failed to get io_uring sqe for close");
		__sys_close(fd);
		return;
	}

	io_uring_prep_close(s, fd);
	s->flags |= IOSQE_CQE_SKIP_SUCCESS;
	s->user_data = EV_BIT_IOU_CLOSE | (unsigned)fd;
	pr_dbg(&w->ctx->lh, "Prepared close for fd=%d", fd);
}

static void get_gcp(struct gwp_conn_pair *gcp)
{
	gcp->ref_cnt++;
}

static bool put_gcp(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	int x = gcp->ref_cnt--;
	int tg_fd, cl_fd;

	pr_dbg(&w->ctx->lh,
		"Put connection pair (idx=%u, cfd=%d, tfd=%d, tmfd=%d, ca=%s, ta=%s, ref_cnt=%d)",
		gcp->idx,
		gcp->client.fd,
		gcp->target.fd,
		gcp->timer_fd,
		ip_to_str(&gcp->client_addr),
		ip_to_str(&gcp->target_addr),
		x - 1);

	if (x > 1)
		return false;

	tg_fd = gcp->target.fd;
	cl_fd = gcp->client.fd;
	gcp->flags |= GWP_CONN_FLAG_NO_CLOSE_FD;
	gwp_free_conn_pair(w, gcp);

	if (tg_fd >= 0)
		prep_close(w, tg_fd);
	if (cl_fd >= 0)
		prep_close(w, cl_fd);

	return true;
}

static struct io_uring_sqe *prep_connect_target(struct gwp_wrk *w,
						struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	struct sockaddr *addr;
	int fd = gcp->target.fd;
	struct io_uring_sqe *s;
	socklen_t addr_len;

	/* Route through the upstream proxy when enabled. */
	if (ctx->upstream.enabled)
		addr = &ctx->upstream.addr.sa;
	else
		addr = &gcp->target_addr.sa;

	if (addr->sa_family == AF_INET)
		addr_len = sizeof(struct sockaddr_in);
	else
		addr_len = sizeof(struct sockaddr_in6);

	s = get_sqe_nofail(w);
	fd = gcp->target.fd;
	io_uring_prep_connect(s, fd, addr, addr_len);
	io_uring_sqe_set_data(s, gcp);
	s->user_data |= EV_BIT_IOU_TARGET_CONNECT;
	get_gcp(gcp);
	pr_dbg(&w->ctx->lh,
		"Prepared connect for target fd=%d, addr=%s, ref_cnt=%d",
		fd, ip_to_str(&gcp->target_addr), gcp->ref_cnt);
	return s;
}

static struct io_uring_sqe *prep_recv_target(struct gwp_wrk *w,
					     struct gwp_conn_pair *gcp)
{
	size_t len = gcp->target.cap - gcp->target.len;
	char *buf = gcp->target.buf + gcp->target.len;
	int fd = gcp->target.fd;
	struct io_uring_sqe *s;

	s = get_sqe_nofail(w);
	io_uring_prep_recv(s, fd, buf, len, MSG_NOSIGNAL);
	io_uring_sqe_set_data(s, gcp);
	s->user_data |= EV_BIT_IOU_TARGET_RECV;
	get_gcp(gcp);
	pr_dbg(&w->ctx->lh,
		"Prepared recv for target fd=%d, len=%zu, buf=%p, ref_cnt=%d",
		fd, len, buf, gcp->ref_cnt);
	return s;
}

static struct io_uring_sqe *prep_recv_client(struct gwp_wrk *w,
					     struct gwp_conn_pair *gcp)
{
	size_t len = gcp->client.cap - gcp->client.len;
	char *buf = gcp->client.buf + gcp->client.len;
	int fd = gcp->client.fd;
	struct io_uring_sqe *s;

	s = get_sqe_nofail(w);
	io_uring_prep_recv(s, fd, buf, len, MSG_NOSIGNAL);
	io_uring_sqe_set_data(s, gcp);
	s->user_data |= EV_BIT_IOU_CLIENT_RECV;
	get_gcp(gcp);
	pr_dbg(&w->ctx->lh,
		"Prepared recv for client fd=%d, len=%zu, buf=%p, ref_cnt=%d",
		fd, len, buf, gcp->ref_cnt);
	return s;
}

static struct io_uring_sqe *prep_send_target(struct gwp_wrk *w,
					     struct gwp_conn_pair *gcp)
{
	size_t len = gcp->client.len;
	char *buf = gcp->client.buf;
	int fd = gcp->target.fd;
	struct io_uring_sqe *s;

	s = get_sqe_nofail(w);
#if USE_SEND_ZC
	io_uring_prep_send_zc(s, fd, buf, len, MSG_NOSIGNAL, 0);
#else
	io_uring_prep_send(s, fd, buf, len, MSG_NOSIGNAL);
#endif
	io_uring_sqe_set_data(s, gcp);
	s->user_data |= EV_BIT_IOU_TARGET_SEND;
	get_gcp(gcp);
	pr_dbg(&w->ctx->lh,
		"Prepared send for target fd=%d, len=%zu, buf=%p, ref_cnt=%d",
		fd, len, buf, gcp->ref_cnt);
	return s;
}

static struct io_uring_sqe *__prep_send_client(struct gwp_wrk *w,
					       struct gwp_conn_pair *gcp)
{
	size_t len = gcp->target.len;
	char *buf = gcp->target.buf;
	int fd = gcp->client.fd;
	struct io_uring_sqe *s;

	s = get_sqe_nofail(w);
#if USE_SEND_ZC
	io_uring_prep_send_zc(s, fd, buf, len, MSG_NOSIGNAL, 0);
#else
	io_uring_prep_send(s, fd, buf, len, MSG_NOSIGNAL);
#endif
	io_uring_sqe_set_data(s, gcp);
	get_gcp(gcp);
	pr_dbg(&w->ctx->lh,
		"Prepared send for client fd=%d, len=%zu, buf=%p, ref_cnt=%d",
		fd, len, buf, gcp->ref_cnt);
	return s;
}

static struct io_uring_sqe *prep_send_client(struct gwp_wrk *w,
					     struct gwp_conn_pair *gcp)
{
	struct io_uring_sqe *s = __prep_send_client(w, gcp);
	s->user_data |= EV_BIT_IOU_CLIENT_SEND;
	return s;
}

static struct io_uring_sqe *prep_timer_target(struct gwp_wrk *w,
					      struct gwp_conn_pair *gcp,
					      int sec)
{
	struct io_uring_sqe *s = get_sqe_nofail(w);

	gcp->ts.tv_nsec = 0;
	gcp->ts.tv_sec = sec;
	io_uring_prep_timeout(s, &gcp->ts, 0, 0);
	io_uring_sqe_set_data(s, gcp);
	s->user_data |= EV_BIT_IOU_TIMER;
	get_gcp(gcp);
	pr_dbg(&w->ctx->lh,
		"Prepared timer for target fd=%d, ts=%lld.%09lld, ref_cnt=%d",
		gcp->target.fd, gcp->ts.tv_sec, gcp->ts.tv_nsec, gcp->ref_cnt);
	return s;
}

static void prep_timer_del_target(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct io_uring_sqe *s = get_sqe_nofail(w);

	io_uring_prep_timeout_remove(s, EV_BIT_IOU_TIMER | PTR_TO_U64(gcp), 0);
	io_uring_sqe_set_data(s, gcp);
	s->user_data |= EV_BIT_IOU_TIMER_DEL;
	get_gcp(gcp);
	pr_dbg(&w->ctx->lh,
		"Prepared del timer for target fd=%d, ref_cnt=%d",
		gcp->target.fd, gcp->ref_cnt);
}

static void shutdown_gcp(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	struct io_uring_sqe *s;

	if (gcp->flags & GWP_CONN_FLAG_IS_CANCEL)
		return;

	if (gcp->target.fd >= 0) {
		pr_dbg(&ctx->lh, "Cancelling target recv (fd=%d)", gcp->target.fd);
		s = get_sqe_nofail(w);
		io_uring_prep_cancel_fd(s, gcp->target.fd, 0);
		io_uring_sqe_set_data(s, gcp);
		s->user_data |= EV_BIT_IOU_TARGET_CANCEL;
		get_gcp(gcp);
	}

	if (gcp->client.fd >= 0) {
		pr_dbg(&ctx->lh, "Cancelling client recv (fd=%d)", gcp->client.fd);
		s = get_sqe_nofail(w);
		io_uring_prep_cancel_fd(s, gcp->client.fd, 0);
		io_uring_sqe_set_data(s, gcp);
		s->user_data |= EV_BIT_IOU_CLIENT_CANCEL;
		get_gcp(gcp);
	}

	gcp->flags |= GWP_CONN_FLAG_IS_CANCEL;
}

static struct io_uring_sqe *prep_recv_client_socks5(struct gwp_wrk *w,
						    struct gwp_conn_pair *gcp)
{
	struct io_uring_sqe *s = prep_recv_client(w, gcp);
	s->user_data &= ~EV_BIT_ALL;
	s->user_data |= EV_BIT_IOU_CLIENT_SOCKS5;
	return s;
}

static int arm_gcp_socks5(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	int r;

	gcp->s5_conn = gwp_socks5_conn_alloc(ctx->socks5);
	if (unlikely(!gcp->s5_conn))
		return -ENOMEM;

	r = prep_nr_sqes(w, 4);
	if (unlikely(r < 0)) {
		pr_err(&w->ctx->lh, "Failed to prepare sqes for connection pair");
		return r;
	}

	prep_recv_client_socks5(w, gcp);

	/*
	 * If we are running as a SOCKS5 proxy, the initial connection
	 * does not have a target socket. We will create the target
	 * socket later, when the client sends a CONNECT command.
	 */
	if (ctx->cfg.protocol_timeout > 0)
		prep_timer_target(w, gcp, ctx->cfg.protocol_timeout);

	return 0;
}

static int do_prep_connect(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	struct io_uring_sqe *s;
	int r;

	r = prep_nr_sqes(w, 4);
	if (unlikely(r < 0)) {
		pr_err(&w->ctx->lh, "Failed to prepare sqes for connection pair");
		return r;
	}

	s = prep_connect_target(w, gcp);

	/*
	 * With an upstream proxy we must not start forwarding yet: the target
	 * recv/send would collide with the SOCKS5 client handshake. Only arm
	 * the connect (+ timer); the handshake is driven from
	 * handle_ev_target_connect().
	 */
	if (!ctx->upstream.enabled) {
		s->flags |= IOSQE_IO_LINK;
		prep_recv_client(w, gcp);

		/*
		 * In SOCKS5 mode the CONNECT reply is written into target.buf
		 * after connect completes; arming the target recv here would
		 * race with it and splice stale reply bytes into the forwarded
		 * stream. Defer it until the reply has been flushed (see
		 * handle_ev_target_connect() -> handle_ev_client_send()).
		 */
		if (!ctx->cfg.as_socks5)
			prep_recv_target(w, gcp);
	}

	if (ctx->cfg.connect_timeout > 0)
		prep_timer_target(w, gcp, ctx->cfg.connect_timeout);

	return 0;
}

static int arm_gcp_no_socks5(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	return do_prep_connect(w, gcp);
}

static int arm_gcp(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;

	if (ctx->cfg.as_socks5)
		return arm_gcp_socks5(w, gcp);
	else
		return arm_gcp_no_socks5(w, gcp);
}

static int __handle_ev_accept(struct gwp_wrk *w, struct io_uring_cqe *cqe)
{
	bool transparent = w->ctx->cfg.as_transparent;
	struct gwp_ctx *ctx = w->ctx;
	int fd = cqe->res, tg_fd, r;
	struct gwp_conn_pair *gcp;
	struct gwp_sockaddr tdst;

	if (unlikely(fd < 0)) {
		if (fd == -EAGAIN || fd == -EINTR)
			return 0;

		/*
		 * TODO(ammarfaizi2): Handle -EMFILE and -ENFILE.
		 */
		pr_err(&ctx->lh, "accept() failed: %s", strerror(-fd));
		return fd;
	}

	/* Transparent proxy: take the target from SO_ORIGINAL_DST. */
	if (transparent) {
		r = gwp_get_orig_dst(fd, &w->iou->accept_addr, &tdst);
		if (r) {
			pr_warn(&ctx->lh, "No original destination for %s: %s (not a redirected connection?)",
				ip_to_str(&w->iou->accept_addr), strerror(-r));
			prep_close(w, fd);
			return 0;
		}
	}

	if (!ctx->cfg.as_socks5) {
		struct gwp_sockaddr *ca;

		/* Connect to the upstream proxy, the original dst, or --target. */
		if (ctx->upstream.enabled)
			ca = &ctx->upstream.addr;
		else if (transparent)
			ca = &tdst;
		else
			ca = &ctx->target_addr;

		tg_fd = gwp_create_sock_target(w, ca, NULL, false);
		if (unlikely(tg_fd < 0)) {
			pr_err(&ctx->lh, "Create target socket: %s", strerror(-tg_fd));
			goto out_close;
		}
	} else {
		tg_fd = -1;
	}

	gcp = gwp_alloc_conn_pair(w);
	if (unlikely(!gcp)) {
		pr_err(&ctx->lh, "Allocate connection pair: %s", strerror(ENOMEM));
		goto out_close_tg_fd;
	}

	gcp->ref_cnt = 0;

	gcp->client.fd = fd;
	gcp->target.fd = tg_fd;
	gcp->client_addr = w->iou->accept_addr;
	gcp->target_addr = transparent ? tdst : ctx->target_addr;
	gcp->is_target_alive = false;
	r = arm_gcp(w, gcp);
	if (unlikely(r))
		goto out_free_pair;

	log_conn_pair_created(w, gcp);
	return r;

out_free_pair:
	gcp->client.fd = gcp->target.fd = gcp->timer_fd = -1;
	gwp_free_conn_pair(w, gcp);
out_close_tg_fd:
	if (tg_fd >= 0)
		prep_close(w, tg_fd);
out_close:
	if (fd >= 0)
		prep_close(w, fd);
	return -ENOMEM;
}

static int handle_ev_accept(struct gwp_wrk *w, struct io_uring_cqe *cqe)
{
	int r = __handle_ev_accept(w, cqe);

	if (unlikely(r < 0)) {
		pr_err(&w->ctx->lh, "Failed to handle accept event: %s", strerror(-r));
		return r;
	}

	arm_accept(w);
	return 0;
}

/*
 * ------------------------------------------------------------------------
 * Upstream SOCKS5 proxy client handshake (io_uring).
 *
 * Mirrors the epoll implementation. gcp->target is connected to the upstream
 * proxy; we drive greeting -> [auth] -> CONNECT before starting to forward.
 * The normal client/target recv/send SQEs are NOT armed during the handshake
 * (see do_prep_connect); the handshake uses dedicated SQEs tagged with
 * EV_BIT_IOU_UPSTREAM_S5. gcp->up_tx distinguishes a send completion (request
 * still being flushed) from a recv completion (reply being read).
 * ------------------------------------------------------------------------
 */

static int handle_sock_ret(int r);

static struct io_uring_sqe *prep_upstream_send(struct gwp_wrk *w,
					       struct gwp_conn_pair *gcp)
{
	struct io_uring_sqe *s = get_sqe_nofail(w);

	io_uring_prep_send(s, gcp->target.fd, gcp->target.buf, gcp->target.len,
			   MSG_NOSIGNAL);
	io_uring_sqe_set_data(s, gcp);
	s->user_data |= EV_BIT_IOU_UPSTREAM_S5;
	get_gcp(gcp);
	return s;
}

static struct io_uring_sqe *prep_upstream_recv(struct gwp_wrk *w,
					       struct gwp_conn_pair *gcp)
{
	size_t len = gcp->target.cap - gcp->target.len;
	char *buf = gcp->target.buf + gcp->target.len;
	struct io_uring_sqe *s = get_sqe_nofail(w);

	io_uring_prep_recv(s, gcp->target.fd, buf, len, MSG_NOSIGNAL);
	io_uring_sqe_set_data(s, gcp);
	s->user_data |= EV_BIT_IOU_UPSTREAM_S5;
	get_gcp(gcp);
	return s;
}

static int upstream_iou_send_userpass(struct gwp_wrk *w,
				      struct gwp_conn_pair *gcp)
{
	struct gwp_upstream_s5 *up = &w->ctx->upstream;
	size_t len = gcp->target.cap;
	int r;

	gcp->target.len = 0;
	r = gwp_socks5_cli_build_userpass(up->user, up->ulen, up->pass, up->plen,
					  gcp->target.buf, &len);
	if (unlikely(r))
		return r;

	gcp->target.len = (uint32_t)len;
	gcp->up_tx = true;
	gcp->conn_state = CONN_STATE_UPSTREAM_S5_AUTH;
	prep_upstream_send(w, gcp);
	return 0;
}

static int upstream_iou_send_connect(struct gwp_wrk *w,
				     struct gwp_conn_pair *gcp)
{
	size_t len = gcp->target.cap;
	int r;

	gcp->target.len = 0;
	r = gwp_socks5_cli_build_connect(&gcp->up_dst, gcp->target.buf, &len);
	if (unlikely(r))
		return r;

	gcp->target.len = (uint32_t)len;
	gcp->up_tx = true;
	gcp->conn_state = CONN_STATE_UPSTREAM_S5_CONNECT;
	prep_upstream_send(w, gcp);
	return 0;
}

static int upstream_iou_complete(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				 uint8_t rep, size_t consumed)
{
	struct gwp_ctx *ctx = w->ctx;
	uint8_t rbuf[512];
	size_t rlen = 0;
	int r;

	if (rep != GWP_SOCKS5_REP_SUCCESS) {
		pr_err(&ctx->lh, "Upstream SOCKS5 CONNECT failed (rep=0x%02x, idx=%u)",
			rep, gcp->idx);
		return -ECONNREFUSED;
	}

	if (ctx->cfg.as_socks5) {
		rlen = sizeof(rbuf);
		r = gwp_socks5_build_connect_reply(w, gcp, 0, rbuf, &rlen);
		if (unlikely(r))
			return r;
	}

	/* Drop the proxy's CONNECT reply, keep any early destination data. */
	gwp_conn_buf_advance(&gcp->target, consumed);

	if (rlen) {
		if (gcp->target.len + rlen > gcp->target.cap)
			return -ENOBUFS;
		memmove(gcp->target.buf + rlen, gcp->target.buf, gcp->target.len);
		memcpy(gcp->target.buf, rbuf, rlen);
		gcp->target.len += (uint32_t)rlen;
	}

	prep_timer_del_target(w, gcp);
	gcp->up_tx = false;
	gcp->is_target_alive = true;
	gcp->conn_state = CONN_STATE_FORWARDING;

	pr_info(&ctx->lh, "Upstream SOCKS5 tunnel established (idx=%u, ca=%s)",
		gcp->idx, ip_to_str(&gcp->client_addr));

	/* Start forwarding. */
	if (gcp->target.len)
		prep_send_client(w, gcp);
	else
		prep_recv_target(w, gcp);
	prep_recv_client(w, gcp);
	return 0;
}

static int upstream_iou_parse(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	const uint8_t *buf = (const uint8_t *)gcp->target.buf;
	size_t len = gcp->target.len;
	int r;

	switch (gcp->conn_state) {
	case CONN_STATE_UPSTREAM_S5_METHOD: {
		uint8_t method;

		r = gwp_socks5_cli_parse_method(buf, len, &method);
		if (r)
			return r;

		gwp_conn_buf_advance(&gcp->target, 2);
		if (method == 0x00)
			return upstream_iou_send_connect(w, gcp);
		if (method == 0x02 && ctx->upstream.has_auth)
			return upstream_iou_send_userpass(w, gcp);

		pr_err(&ctx->lh, "Upstream SOCKS5 proxy selected no acceptable auth method (0x%02x)",
			method);
		return -EACCES;
	}
	case CONN_STATE_UPSTREAM_S5_AUTH: {
		uint8_t status;

		r = gwp_socks5_cli_parse_userpass(buf, len, &status);
		if (r)
			return r;

		gwp_conn_buf_advance(&gcp->target, 2);
		if (status != 0x00) {
			pr_err(&ctx->lh, "Upstream SOCKS5 authentication failed (idx=%u)",
				gcp->idx);
			return -EACCES;
		}
		return upstream_iou_send_connect(w, gcp);
	}
	case CONN_STATE_UPSTREAM_S5_CONNECT: {
		uint8_t rep;
		size_t consumed;

		r = gwp_socks5_cli_parse_connect(buf, len, &rep, &consumed);
		if (r)
			return r;

		return upstream_iou_complete(w, gcp, rep, consumed);
	}
	default:
		return -EINVAL;
	}
}

static int upstream_iou_start(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	size_t len = gcp->target.cap;
	int r;

	r = gwp_upstream_finalize_dst(w, gcp);
	if (unlikely(r)) {
		pr_err(&ctx->lh, "Failed to prepare upstream destination (idx=%u): %s",
			gcp->idx, strerror(-r));
		return r;
	}

	r = gwp_socks5_cli_build_greeting(ctx->upstream.has_auth,
					  gcp->target.buf, &len);
	if (unlikely(r))
		return r;

	gcp->target.len = (uint32_t)len;
	gcp->up_tx = true;
	gcp->conn_state = CONN_STATE_UPSTREAM_S5_METHOD;
	pr_dbg(&ctx->lh, "Upstream SOCKS5 handshake started (idx=%u)", gcp->idx);
	prep_upstream_send(w, gcp);
	return 0;
}

static int handle_ev_upstream_s5(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				 struct io_uring_cqe *cqe)
{
	int r = handle_sock_ret(cqe->res);

	if (r < 0)
		return r;

	if (gcp->up_tx) {
		/* A request send completed. */
		if (r > 0)
			gwp_conn_buf_advance(&gcp->target, (size_t)r);

		if (gcp->target.len > 0) {
			prep_upstream_send(w, gcp);
			return 0;
		}

		gcp->up_tx = false;
		prep_upstream_recv(w, gcp);
		return 0;
	}

	/* A reply recv completed. */
	if (r > 0)
		gcp->target.len += (uint32_t)r;

	r = upstream_iou_parse(w, gcp);
	if (r == -EAGAIN) {
		prep_upstream_recv(w, gcp);
		return 0;
	}

	return r;
}

static int handle_ev_target_connect(struct gwp_wrk *w, void *udata, int res)
{
	struct gwp_conn_pair *gcp = udata;
	int r;

	if (unlikely(res < 0)) {
		pr_err(&w->ctx->lh, "Target connect failed: %s", strerror(-res));
		return res;
	}

	/*
	 * Connected to the upstream proxy: run the client handshake before
	 * forwarding. The connect timer is kept to bound the handshake.
	 */
	if (w->ctx->upstream.enabled)
		return upstream_iou_start(w, gcp);

	prep_timer_del_target(w, gcp);
	gcp->is_target_alive = true;
	pr_info(&w->ctx->lh,
		"Target socket connected (fd=%d, idx=%u, ca=%s, ta=%s)",
		gcp->target.fd, gcp->idx,
		ip_to_str(&gcp->client_addr),
		ip_to_str(&gcp->target_addr));

	if (w->ctx->cfg.as_socks5) {
		r = gwp_socks5_prep_connect_reply(w, gcp, res);
		if (r)
			return r;

		/*
		 * Flush the reply with a completion callback (not _no_cb): its
		 * handler drains target.buf and only then arms the target recv,
		 * so the recv never overwrites the still-pending reply.
		 */
		if (gcp->target.len)
			prep_send_client(w, gcp);
		else
			prep_recv_target(w, gcp);
	}

	return 0;
}

static int handle_ev_timer(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			   bool is_timer_del, int res)
{
	struct gwp_ctx *ctx = w->ctx;
	int r = 0;

	if (!gcp->is_target_alive && res == -ETIME) {
		assert(is_timer_del == false);
		r = -ETIME;
		pr_warn(&ctx->lh,
			"Connection timeout! (idx=%u, cfd=%d, tfd=%d, ca=%s, ta=%s)",
			gcp->idx, gcp->client.fd, gcp->target.fd,
			ip_to_str(&gcp->client_addr),
			ip_to_str(&gcp->target_addr));
	}

	pr_dbg(&ctx->lh,
		"Timer event handled (idx=%u, cfd=%d, tfd=%d, tmfd=%d, ca=%s, ta=%s, itd=(b)%d, res=%d)",
		gcp->idx, gcp->client.fd, gcp->target.fd,
		gcp->timer_fd, ip_to_str(&gcp->client_addr),
		ip_to_str(&gcp->target_addr), is_timer_del, res);

	return r;
}

static int handle_sock_ret(int r)
{
	if (r < 0) {
		if (r == -EAGAIN || r == -EINTR)
			return 0;

		return r;
	}

	if (!r)
		return -ECONNRESET;

	return r;
}

/*
 * Half-close bookkeeping for the forwarding path, mirroring the epoll
 * forward_progress(). Once a direction's source is at EOF and its buffer has
 * been flushed to the peer, shut the peer's write side so it observes the FIN.
 * The pair is torn down only after both directions have been shut, so a client
 * that half-closes its write side still receives the whole response.
 */
static int iou_forward_progress(struct gwp_conn_pair *gcp)
{
	if (gcp->target.rd_eof && gcp->target.len == 0 && !gcp->client.wr_shut) {
		__sys_shutdown(gcp->client.fd, SHUT_WR);
		gcp->client.wr_shut = true;
	}

	if (gcp->client.rd_eof && gcp->client.len == 0 && !gcp->target.wr_shut) {
		__sys_shutdown(gcp->target.fd, SHUT_WR);
		gcp->target.wr_shut = true;
	}

	if (gcp->client.wr_shut && gcp->target.wr_shut)
		return -ECONNRESET;

	return 0;
}

static int handle_ev_client_recv(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				 struct io_uring_cqe *cqe)
{
	int r = cqe->res;

	if (r < 0) {
		if (r == -EAGAIN || r == -EINTR) {
			prep_recv_client(w, gcp);
			return 0;
		}
		return r;
	}

	if (r == 0) {
		/*
		 * Client closed its write side. Half-close: stop reading it,
		 * propagate the FIN to the target, and keep delivering the
		 * target's response until it too is done.
		 */
		gcp->client.rd_eof = true;
		return iou_forward_progress(gcp);
	}

	gcp->client.len += (uint32_t)r;
	prep_send_target(w, gcp);
	return 0;
}

static int handle_ev_target_recv(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				 struct io_uring_cqe *cqe)
{
	int r = cqe->res;

	if (r < 0) {
		if (r == -EAGAIN || r == -EINTR) {
			prep_recv_target(w, gcp);
			return 0;
		}
		return r;
	}

	if (r == 0) {
		gcp->target.rd_eof = true;
		return iou_forward_progress(gcp);
	}

	gcp->target.len += (uint32_t)r;
	prep_send_client(w, gcp);
	return 0;
}

static int handle_ev_client_send(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				 struct io_uring_cqe *cqe)
{
	int r = cqe->res;

	r = handle_sock_ret(r);
	if (r < 0)
		return r;

	if (r > 0)
		gwp_conn_buf_advance(&gcp->target, (size_t)r);

	/*
	 * A short send leaves unsent bytes in target.buf; flush the remainder
	 * before reading more from the target, otherwise the leftover data is
	 * overwritten by the next recv and the transfer stalls.
	 */
	if (gcp->target.len > 0) {
		prep_send_client(w, gcp);
		return 0;
	}

	if (gcp->target.fd >= 0)
		prep_recv_target(w, gcp);
	return 0;
}

static int handle_ev_target_send(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				 struct io_uring_cqe *cqe)
{
	int r = cqe->res;

	r = handle_sock_ret(r);
	if (r < 0)
		return r;

	if (r > 0)
		gwp_conn_buf_advance(&gcp->client, (size_t)r);

	/* Short send: flush the rest before reading more from the client. */
	if (gcp->client.len > 0) {
		prep_send_target(w, gcp);
		return 0;
	}

	prep_recv_client(w, gcp);
	return 0;
}

static int handle_socks5_connect_target(struct gwp_wrk *w,
					struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_sockaddr *ca = &gcp->target_addr;
	int r;

	/* The socket connects to the upstream proxy when enabled. */
	if (ctx->upstream.enabled)
		ca = &ctx->upstream.addr;

	r = gwp_create_sock_target(w, ca, NULL, false);
	if (r < 0) {
		pr_err(&w->ctx->lh, "Create target socket: %s", strerror(-r));
		return r;
	}

	gcp->target.fd = r;
	return do_prep_connect(w, gcp);
}

static int prep_domain_resolution(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_dns_entry *gde = gcp->gde;
	struct gwp_ctx *ctx = w->ctx;
	struct io_uring_sqe *s;

	assert(gde);
	s = get_sqe_nofail(w);
	io_uring_prep_poll_add(s, gde->ev_fd, POLLIN);
	io_uring_sqe_set_data(s, gcp);
	s->user_data |= EV_BIT_IOU_DNS_QUERY;
	get_gcp(gcp);
	pr_dbg(&ctx->lh,
		"Prepared DNS query for domain '%s' (fd=%d, idx=%u, ref_cnt=%d)",
		gde->name, gde->ev_fd, gcp->idx, gcp->ref_cnt);

	return 0;
}

static int handle_ev_client_socks5(struct gwp_wrk *w,
				   struct gwp_conn_pair *gcp,
				   struct io_uring_cqe *cqe)
{
	int r = cqe->res;

	r = handle_sock_ret(r);
	if (r < 0) {
		return r;
	} else if (!r) {
		prep_recv_client_socks5(w, gcp);
		return 0;
	}

	gcp->client.len += (uint32_t)r;
	r = gwp_socks5_handle_data(gcp);
	if (r)
		return r;

	if (gcp->target.len)
		prep_send_client(w, gcp);

	if (gcp->s5_conn->state == GWP_SOCKS5_ST_CMD_CONNECT) {
		r = gwp_socks5_prepare_target_addr(w, gcp);
		if (r == -EINPROGRESS)
			return prep_domain_resolution(w, gcp);

		if (r)
			return r;

		r = handle_socks5_connect_target(w, gcp);
	} else {
		prep_recv_client_socks5(w, gcp);
	}

	return r;
}

static int handle_ev_dns_query(struct gwp_wrk *w, void *udata)
{
	struct gwp_conn_pair *gcp = udata;
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_dns_entry *gde = gcp->gde;

	if (gde->res) {
		pr_info(&ctx->lh, "Failed to resolve domain '%s': %d",
			gde->name, gde->res);
		return gde->res;
	}

	gcp->target_addr = gde->addr;
	pr_info(&ctx->lh, "Domain '%s' resolved to %s (fd=%d, idx=%u)",
		gde->name, ip_to_str(&gcp->target_addr), gcp->target.fd,
		gcp->idx);

	gwp_dns_entry_put(gde);
	gcp->gde = NULL;
	return handle_socks5_connect_target(w, gcp);
}

static void prep_socks5_auth_reload(struct gwp_wrk *w)
{
	static const size_t l = sizeof(struct inotify_event) + NAME_MAX + 1;
	struct gwp_ctx *ctx = w->ctx;
	struct io_uring_sqe *s;

	assert(ctx->socks5);
	s = get_sqe_nofail(w);
	io_uring_prep_read(s, ctx->ino_fd, ctx->ino_buf, l, 0);
	s->user_data = EV_BIT_IOU_SOCKS5_AUTH_FILE;
}

static int handle_ev_socks5_auth_file(struct gwp_wrk *w)
{
	struct gwp_ctx *ctx = w->ctx;

	prep_socks5_auth_reload(w);
	gwp_socks5_auth_reload(ctx->socks5);
	pr_info(&ctx->lh, "Reloaded SOCKS5 authentication file");
	return 0;
}

static int handle_event(struct gwp_wrk *w, struct io_uring_cqe *cqe)
{
	void *udata = U64_TO_PTR(CLEAR_EV_BIT(cqe->user_data));
	uint64_t ev_bit = GET_EV_BIT(cqe->user_data);
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_conn_pair *gcp;
	const char *inv_op;
	int r;

	switch (ev_bit) {
	case EV_BIT_IOU_ACCEPT:
		pr_dbg(&ctx->lh, "Handling accept event: %d", cqe->res);
		return handle_ev_accept(w, cqe);
	case EV_BIT_IOU_TARGET_CONNECT:
		pr_dbg(&ctx->lh, "Handling target connect event: %d", cqe->res);
		r = handle_ev_target_connect(w, udata, cqe->res);
		break;
	case EV_BIT_IOU_TIMER:
		pr_dbg(&ctx->lh, "Handling timer event: %d", cqe->res);
		r = handle_ev_timer(w, udata, false, cqe->res);
		break;
	case EV_BIT_IOU_TIMER_DEL:
		pr_dbg(&ctx->lh, "Handling timer event delete: %d", cqe->res);
		r = handle_ev_timer(w, udata, true, cqe->res);
		break;
	case EV_BIT_IOU_CLIENT_RECV:
		pr_dbg(&ctx->lh, "Handling client recv event: %d", cqe->res);
		r = handle_ev_client_recv(w, udata, cqe);
		break;
	case EV_BIT_IOU_TARGET_RECV:
		pr_dbg(&ctx->lh, "Handling target recv event: %d", cqe->res);
		r = handle_ev_target_recv(w, udata, cqe);
		break;
	case EV_BIT_IOU_CLIENT_SEND:
		pr_dbg(&ctx->lh, "Handling client send event: %d", cqe->res);
		r = handle_ev_client_send(w, udata, cqe);
		break;
	case EV_BIT_IOU_TARGET_SEND:
		pr_dbg(&ctx->lh, "Handling target send event: %d", cqe->res);
		r = handle_ev_target_send(w, udata, cqe);
		break;
	case EV_BIT_IOU_CLIENT_SOCKS5:
		pr_dbg(&ctx->lh, "Handling client SOCKS5 event: %d", cqe->res);
		r = handle_ev_client_socks5(w, udata, cqe);
		break;
	case EV_BIT_IOU_UPSTREAM_S5:
		pr_dbg(&ctx->lh, "Handling upstream SOCKS5 handshake event: %d", cqe->res);
		r = handle_ev_upstream_s5(w, udata, cqe);
		break;
	case EV_BIT_IOU_SOCKS5_AUTH_FILE:
		pr_dbg(&ctx->lh, "Handling SOCKS5 auth file reload event: %d", cqe->res);
		return handle_ev_socks5_auth_file(w);
	case EV_BIT_IOU_TARGET_CANCEL:
		gcp = udata;
		pr_dbg(&ctx->lh, "Handling target cancel event: %d", cqe->res);
		assert(gcp->flags & GWP_CONN_FLAG_IS_CANCEL);
		r = 0;
		break;
	case EV_BIT_IOU_CLIENT_CANCEL:
		gcp = udata;
		pr_dbg(&ctx->lh, "Handling client cancel event: %d", cqe->res);
		assert(gcp->flags & GWP_CONN_FLAG_IS_CANCEL);
		r = 0;
		break;
	case EV_BIT_IOU_DNS_QUERY:
		pr_dbg(&ctx->lh, "Handling DNS query event: %d", cqe->res);
		r = handle_ev_dns_query(w, udata);
		break;
	case EV_BIT_IOU_MSG_RING:
		return 0;
	case EV_BIT_IOU_CLOSE:
		inv_op = "close";
		goto out_bug;
	default:
		pr_err(&ctx->lh, "Unknown event bit: %" PRIu64 "; res=%d", ev_bit, cqe->res);
		return -EINVAL;
	}

	gcp = udata;
	if (r && !(gcp->flags & GWP_CONN_FLAG_IS_CANCEL))
		shutdown_gcp(w, gcp);

	put_gcp(w, gcp);
	return 0;

out_bug:
	pr_err(&ctx->lh, "Bug, invalid %s: res=%d, udata=%" PRIu64 ", s=%s", inv_op,
		cqe->res, PTR_TO_U64(udata), strerror(-cqe->res));
	return cqe->res;
}

static int handle_events(struct gwp_wrk *w)
{
	struct iou *iou = w->iou;
	struct io_uring_cqe *cqe;
	unsigned head, i = 0;
	int r = 0;

	io_uring_for_each_cqe(&iou->ring, head, cqe) {
		i++;
		r = handle_event(w, cqe);
		if (unlikely(r))
			break;
	}

	if (i)
		io_uring_cq_advance(&iou->ring, i);

	return r;
}

static int fish_events(struct gwp_wrk *w)
{
	struct iou *iou = w->iou;
	int r;

	r = io_uring_submit_and_wait(&iou->ring, 1);
	if (unlikely(r < 0)) {
		if (r != -EINTR) {
			log_submit_err(w, r);
			return r;
		}

		pr_info(&w->ctx->lh, "io_uring_submit_and_wait() interrupted");
	}

	return 0;
}

static void submit_unconsumed_sqes(struct gwp_wrk *w)
{
	int r;

	if (io_uring_sq_ready(&w->iou->ring) > 0) {
		r = io_uring_submit_eintr(&w->iou->ring, 8);
		if (unlikely(r < 0))
			log_submit_err(w, r);
	}
}

int gwp_ctx_thread_entry_io_uring(struct gwp_wrk *w)
{
	struct gwp_ctx *ctx = w->ctx;
	int r = 0;

	pr_info(&ctx->lh, "Worker %u started (io_uring)", w->idx);

	if (w->idx == 0 && ctx->cfg.as_socks5 && ctx->ino_fd >= 0)
		prep_socks5_auth_reload(w);

	io_uring_set_iowait(&w->iou->ring, false);
	arm_accept(w);
	while (!ctx->stop) {
		r = fish_events(w);
		if (unlikely(r < 0))
			break;

		r = handle_events(w);
		if (unlikely(r < 0))
			break;
	}

	/*
	 * Just in case we errored out before prep_close() SQEs
	 * were submitted, we need to submit them now. Otherwise,
	 * we risk leaking file descriptors.
	 */
	submit_unconsumed_sqes(w);
	return r;
}

__cold
void gwp_ctx_signal_all_io_uring(struct gwp_ctx *ctx)
{
	struct gwp_wrk *we = &ctx->workers[0];
	int i;

	ctx->stop = true;
	for (i = 0; i < ctx->cfg.nr_workers; i++) {
		struct io_uring_sqe *s = __get_sqe_nofail(&we->iou->ring);
		struct gwp_wrk *wo = &ctx->workers[i];
		int fd = wo->iou->ring.ring_fd;
		io_uring_prep_msg_ring(s, fd, 0, EV_BIT_IOU_MSG_RING, 0);
		s->user_data = EV_BIT_IOU_MSG_RING;
	}

	io_uring_submit_eintr(&we->iou->ring, 8);
}

#endif // CONFIG_IO_URING
