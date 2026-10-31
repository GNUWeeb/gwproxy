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
#include <gwproxy/acl.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/eventfd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <liburing.h>
#include <poll.h>
#ifdef CONFIG_HTTPS
#include <gwproxy/ssl.h>
#endif

#define USE_SEND_ZC 0

#ifdef CONFIG_HTTPS
/*
 * Per-connection ciphertext scratch for a TLS client. The io_uring send is
 * asynchronous, so its buffer must persist for the whole operation: @tx holds
 * ciphertext pulled from the write BIO that is being sent, with
 * @tx_sent..@tx_len the not-yet-written tail. It holds a whole TLS record,
 * header and cipher overhead included, so a full record goes out in one send.
 * Received ciphertext needs no scratch: it lands in the engine's own input
 * queue (see __prep_recv_client()).
 */
#define GWP_TLS_CIPHER_CAP GWP_SSL_RECORD_MAX

struct gwp_iou_tls {
	uint32_t	tx_len;		/* ciphertext bytes queued in @tx  */
	uint32_t	tx_sent;	/* of those, already written       */
	bool		closing;	/* close_notify queued             */
	bool		prot_resume;	/* pump the protocol once tx is out */
	unsigned char	tx[GWP_TLS_CIPHER_CAP];
};

/* Defined further down but referenced by earlier prep/dispatch code. */
static int handle_sock_ret(int r);
static int chk_prot_result(struct gwp_wrk *w, struct gwp_conn_pair *gcp, int r);
static int iou_forward_progress(struct gwp_wrk *w, struct gwp_conn_pair *gcp);
static void prep_tls_detect(struct gwp_wrk *w, struct gwp_conn_pair *gcp);
static void send_client_tls(struct gwp_wrk *w, struct gwp_conn_pair *gcp);
static int tls_forward_pump(struct gwp_wrk *w, struct gwp_conn_pair *gcp);
static int process_client_prot(struct gwp_wrk *w, struct gwp_conn_pair *gcp);

static inline bool client_is_tls(const struct gwp_conn_pair *gcp)
{
	return gcp->client.tls != NULL;
}
#endif /* CONFIG_HTTPS */

/* Defined below handle_prot_*, but the connect path above needs it. */
static int connect_next_candidate(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				  int err);

/*
 * Per-connection scratch for the io_uring SOCKS5 UDP relay. An async recvmsg /
 * sendmsg must own a stable buffer and msghdr for the whole operation (epoll
 * relays synchronously into a per-worker buffer instead), so this is
 * per-connection. The relay runs serially - at most one recvmsg or sendmsg is
 * in flight at a time - so a single buffer/msghdr pair suffices. @buf receives
 * datagrams at offset GWP_SOCKS5_UDP_HDR_MAX so a reply header can be prepended
 * in place, exactly like the epoll path.
 */
struct gwp_iou_udp {
	struct msghdr		mh;
	struct iovec		iov;
	struct gwp_sockaddr	src;	/* recvmsg source of the last datagram */
	struct gwp_sockaddr	dst;	/* sendmsg destination                 */
	unsigned char		buf[GWP_UDP_RELAY_BUFSZ];
};

__cold
int gwp_ctx_init_thread_io_uring(struct gwp_wrk *w)
{
	struct iou *iou;
	int r;

	iou = calloc(1, sizeof(*iou));
	if (!iou)
		return -ENOMEM;

	/*
	 * Stop doorbell, see gwp_ctx_signal_all_io_uring(). Created before
	 * the ring so a worker never exists without one.
	 */
	r = __sys_eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (r < 0)
		goto err_free_iou;
	iou->stop_efd = r;

	r = io_uring_queue_init(1024, &iou->ring, 0);
	if (r < 0)
		goto err_close_efd;

	w->iou = iou;
	return 0;

err_close_efd:
	__sys_close(iou->stop_efd);
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
		if (likely(r != -EINTR))
			break;
	}

	return r;
}

/* How long get_sqe_nofail() keeps retrying a failing submit, in ms. */
#define GWP_SQE_RETRY_MS 1000

/*
 * Return a free SQE, submitting the queued ones to make room when the SQ is
 * full. Every caller has already committed to its operation (taken a pair
 * reference, moved buffers), so there is no "no SQE" result to hand back.
 *
 * A submit can fail for want of kernel memory (-EAGAIN, -ENOMEM), or, on
 * older kernels, while completions sit in the CQ overflow list (-EBUSY).
 * Those pass, so wait for them to: flush what overflowed into the CQ ring,
 * which handle_events() keeps clear of the completions it has handled
 * already, sleep a millisecond and submit again. Only an error that keeps
 * coming for GWP_SQE_RETRY_MS, or one that is not transient at all (a bad
 * ring fd, say), still aborts: the loop cannot go on without SQEs.
 */
static struct io_uring_sqe *get_sqe_nofail(struct gwp_wrk *w)
{
	struct io_uring *ring = &w->iou->ring;
	struct io_uring_sqe *sqe;
	unsigned int waited = 0;
	int r = 0;

	while (!(sqe = io_uring_get_sqe(ring))) {
		r = io_uring_submit(ring);
		if (likely(r > 0) || r == -EINTR)
			continue;

		if (r < 0 && r != -EAGAIN && r != -ENOMEM && r != -EBUSY)
			break;
		if (waited >= GWP_SQE_RETRY_MS)
			break;

		if (!waited)
			pr_warn(&w->ctx->lh,
				"Worker %u: io_uring_submit(): %s; retrying",
				w->idx, strerror(r < 0 ? -r : EAGAIN));
		io_uring_get_events(ring);
		usleep(1000);
		waited++;
	}

	if (likely(sqe))
		return sqe;

	pr_err(&w->ctx->lh, "Failed to get io_uring sqe for worker %u: %s",
	       w->idx, strerror(r < 0 ? -r : EAGAIN));
	abort();
}

/*
 * Requests still in flight point into memory the caller frees next: the
 * pairs' buffers, their sockets, this worker's iou. Closing a socket's fd
 * does not end them, the request holds its own reference to the file, and
 * neither does closing the ring: io_uring_queue_exit() returns while the
 * kernel cancels what is left in the background. So cancel everything
 * first. The synchronous cancel returns once the requests it found can no
 * longer touch user memory (a recv waiting for data is disarmed on the
 * spot), and it works from any thread, also for a worker that has already
 * exited. Kernels before 6.0 lack it; there, an async cancel of everything
 * does the same for the poll-driven socket I/O this loop uses, and its own
 * completion says when it is done.
 */
__cold
static void cancel_all_requests(struct gwp_wrk *w)
{
	struct io_uring_sync_cancel_reg reg = {
		.fd = -1,
		.flags = IORING_ASYNC_CANCEL_ANY,
		.timeout = { .tv_sec = -1, .tv_nsec = -1 },
	};
	/* Unlike the stop poll's, never a value any request carries. */
	const uint64_t tag = EV_BIT_IOU_STOP | 1;
	struct io_uring *ring = &w->iou->ring;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *s;
	int r;

	r = io_uring_register_sync_cancel(ring, &reg);
	if (r >= 0 || r == -ENOENT)
		return;

	io_uring_submit(ring);	/* never let a queued SQE go out after us */
	s = io_uring_get_sqe(ring);
	if (!s)
		goto out_err;
	io_uring_prep_cancel(s, NULL, IORING_ASYNC_CANCEL_ANY);
	s->user_data = tag;
	r = io_uring_submit(ring);
	if (r < 0)
		goto out_err;

	for (;;) {
		bool done;

		r = io_uring_wait_cqe(ring, &cqe);
		if (r == -EINTR)
			continue;
		if (r < 0)
			goto out_err;
		done = cqe->user_data == tag;
		io_uring_cqe_seen(ring, cqe);
		if (done)
			return;
	}

out_err:
	pr_err(&w->ctx->lh, "Worker %u: cannot cancel pending io_uring requests: %s",
	       w->idx, strerror(r < 0 ? -r : EAGAIN));
}

__cold
void gwp_ctx_free_thread_io_uring(struct gwp_wrk *w)
{
	cancel_all_requests(w);
	io_uring_queue_exit(&w->iou->ring);
	__sys_close(w->iou->stop_efd);
	pr_dbg(&w->ctx->lh, "Worker %u io_uring queue exited", w->idx);
	free(w->iou);
	w->iou = NULL;
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

/*
 * Watch this worker's stop doorbell. One-shot and never re-armed: the eventfd
 * is never read, so once rung it stays readable, and a poll armed after the
 * ring still completes at once -- a stop cannot slip in between the loop's
 * ctx->stop test and its wait.
 */
static void arm_stop_poll(struct gwp_wrk *w)
{
	struct io_uring_sqe *s = get_sqe_nofail(w);

	io_uring_prep_poll_add(s, w->iou->stop_efd, POLLIN);
	s->user_data = EV_BIT_IOU_STOP;
}

/*
 * accept() is paused because of fd exhaustion (EMFILE/ENFILE), or because it
 * keeps failing the same way (see handle_ev_accept()): arm a short one-shot
 * timer and retry the accept when it fires.
 * Polling this way decouples recovery from connection-teardown timing, so the
 * worker can never get permanently stuck with accepting disabled.
 */
static void arm_accept_retry(struct gwp_wrk *w)
{
	struct io_uring_sqe *s = get_sqe_nofail(w);
	struct iou *iou = w->iou;

	iou->accept_retry_ts.tv_sec = 0;
	iou->accept_retry_ts.tv_nsec = 100000000L;	/* 100 ms */
	io_uring_prep_timeout(s, &iou->accept_retry_ts, 0, 0);
	s->user_data = EV_BIT_IOU_ACCEPT_RETRY;
}

static void prep_close(struct gwp_wrk *w, int fd)
{
	struct io_uring_sqe *s = get_sqe_nofail(w);

	io_uring_prep_close(s, fd);
	s->flags |= IOSQE_CQE_SKIP_SUCCESS;
	s->user_data = EV_BIT_IOU_CLOSE | (unsigned)fd;
	pr_dbg(&w->ctx->lh, "Prepared close for fd=%d", fd);
}

static void get_gcp(struct gwp_conn_pair *gcp)
{
	gcp->ref_cnt++;
}

/*
 * The in-flight request count of the socket that requests with selector
 * @ev_bit operate on, or NULL when they are not I/O on one of the pair's
 * sockets (timeouts, cancels, connect attempts, the DNS poll). The same
 * mapping counts a request when it is queued and uncounts it when it
 * completes, so the two cannot disagree.
 */
static uint8_t *nr_ops_of(struct gwp_conn_pair *gcp, uint64_t ev_bit)
{
	switch (ev_bit) {
	case EV_BIT_IOU_CLIENT_RECV:
	case EV_BIT_IOU_CLIENT_SEND:
	case EV_BIT_IOU_CLIENT_PROT:
	case EV_BIT_IOU_TLS_DETECT:
	case EV_BIT_IOU_TLS_HS_RECV:
	case EV_BIT_IOU_TLS_HS_SEND:
		return &gcp->nr_ops_client;
	case EV_BIT_IOU_TARGET_RECV:
	case EV_BIT_IOU_TARGET_SEND:
	case EV_BIT_IOU_UPSTREAM_S5:
		return &gcp->nr_ops_target;
	case EV_BIT_IOU_UDP_RX:
	case EV_BIT_IOU_UDP_TX:
		return &gcp->nr_ops_udp;
	default:
		return NULL;
	}
}

/*
 * Take the pair reference for request @s, which does I/O on one of the pair's
 * sockets, and count it against that socket. Call it once @s->user_data
 * carries its selector.
 */
static void get_gcp_io(struct gwp_conn_pair *gcp, struct io_uring_sqe *s)
{
	uint8_t *nr = nr_ops_of(gcp, GET_EV_BIT(s->user_data));

	assert(nr);
	if (likely(nr))
		(*nr)++;
	get_gcp(gcp);
}

static bool put_gcp(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	int x = gcp->ref_cnt--;
	int tg_fd, cl_fd, ud_fd;

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
	ud_fd = gcp->udp_fd;
	gcp->flags |= GWP_CONN_FLAG_NO_CLOSE_FD;
	/*
	 * All relay SQEs have drained (ref_cnt hit 0), so the async recvmsg /
	 * sendmsg no longer touch the scratch or the fd; free/close them here.
	 */
	free(gcp->udp_iou);
	gcp->udp_iou = NULL;
	gwp_free_conn_pair(w, gcp);

	if (tg_fd >= 0)
		prep_close(w, tg_fd);
	if (cl_fd >= 0)
		prep_close(w, cl_fd);
	if (ud_fd >= 0)
		prep_close(w, ud_fd);

	return true;
}

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
 * its connect is tagged with the slot, so several attempts can be in flight at
 * once and each completion is attributable. The conn-pair pointer stays in the
 * low bits of user_data, as the completion dispatch requires.
 */
static int start_connect_attempt(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				 uint8_t slot)
{
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_sockaddr *ca;
	struct io_uring_sqe *s;
	socklen_t addr_len;
	int fd;

	ca = ctx->upstream.enabled ? &ctx->upstream.addr : &gcp->target_addr;

	fd = gwp_create_sock_target(w, ca, &gcp->acl_sockopt, NULL, false);
	if (unlikely(fd < 0))
		return fd;

	gcp->attempt_fd[slot] = fd;
	/* Post-ACL, so a -j DNAT rewrite is what gets recorded. */
	gcp->attempt_addr[slot] = gcp->target_addr;

	/*
	 * The kernel reads the address out of this pointer after submission,
	 * so it must not be gcp->target_addr: connect_next_candidate() rewrites
	 * that as soon as the next candidate joins the race. attempt_addr[] is
	 * per-slot and stays put for as long as the attempt is in flight.
	 */
	if (!ctx->upstream.enabled)
		ca = &gcp->attempt_addr[slot];

	if (ca->sa.sa_family == AF_INET)
		addr_len = sizeof(struct sockaddr_in);
	else
		addr_len = sizeof(struct sockaddr_in6);

	s = get_sqe_nofail(w);
	io_uring_prep_connect(s, fd, &ca->sa, addr_len);
	io_uring_sqe_set_data(s, gcp);
	s->user_data |= EV_BIT_TARGET_ATTEMPT + ((uint64_t)slot << 48ull);
	get_gcp(gcp);
	pr_dbg(&ctx->lh,
		"Prepared connect attempt %u (fd=%d, addr=%s, idx=%u, ref_cnt=%d)",
		slot, fd, ip_to_str(ca), gcp->idx, gcp->ref_cnt);
	return 0;
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
	get_gcp_io(gcp, s);
	pr_dbg(&w->ctx->lh,
		"Prepared recv for target fd=%d, len=%zu, buf=%p, ref_cnt=%d",
		fd, len, buf, gcp->ref_cnt);
	return s;
}

static int __prep_recv_client(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			      uint64_t ev_bit)
{
	size_t len = gcp->client.cap - gcp->client.len;
	char *buf = gcp->client.buf + gcp->client.len;
	int fd = gcp->client.fd;
	struct io_uring_sqe *s;

#ifdef CONFIG_HTTPS
	/*
	 * A TLS client receives ciphertext straight into the engine's input
	 * queue, with room for at least one whole record; the completion
	 * commits it and decrypts into client.buf. The space stays put until
	 * that commit (see gwp_ssl_rx_space()).
	 */
	if (client_is_tls(gcp)) {
		buf = gwp_ssl_rx_space(gcp->client.tls, GWP_SSL_RECORD_MAX, &len);
		if (unlikely(!buf))
			return -ENOMEM;
	}
#endif

	s = get_sqe_nofail(w);
	io_uring_prep_recv(s, fd, buf, len, MSG_NOSIGNAL);
	io_uring_sqe_set_data(s, gcp);
	s->user_data |= ev_bit;
	get_gcp_io(gcp, s);
	pr_dbg(&w->ctx->lh,
		"Prepared recv for client fd=%d, len=%zu, buf=%p, ref_cnt=%d",
		fd, len, buf, gcp->ref_cnt);
	return 0;
}

static int prep_recv_client(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	return __prep_recv_client(w, gcp, EV_BIT_IOU_CLIENT_RECV);
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
	get_gcp_io(gcp, s);
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

	/*
	 * A send already on its way covers the start of target.buf, and its
	 * completion (handle_ev_client_send()) sends the rest, including what
	 * has been appended since. In the protocol phase a client recv is
	 * armed alongside the reply's send and may complete first; queueing
	 * target.buf again from there would hand the client the reply twice.
	 */
	if (gcp->client_tx)
		return NULL;

	s = get_sqe_nofail(w);
#if USE_SEND_ZC
	io_uring_prep_send_zc(s, fd, buf, len, MSG_NOSIGNAL, 0);
#else
	io_uring_prep_send(s, fd, buf, len, MSG_NOSIGNAL);
#endif
	io_uring_sqe_set_data(s, gcp);
	s->user_data |= EV_BIT_IOU_CLIENT_SEND;
	gcp->client_tx = true;
	get_gcp_io(gcp, s);
	pr_dbg(&w->ctx->lh,
		"Prepared send for client fd=%d, len=%zu, buf=%p, ref_cnt=%d",
		fd, len, buf, gcp->ref_cnt);
	return s;
}

static struct io_uring_sqe *prep_send_client(struct gwp_wrk *w,
					     struct gwp_conn_pair *gcp)
{
#ifdef CONFIG_HTTPS
	/*
	 * A TLS client is fed encrypted bytes: send_client_tls() encrypts
	 * target.buf into the tx scratch and queues the ciphertext send. The
	 * sqe is owned there, so return NULL (all callers ignore the value).
	 */
	if (client_is_tls(gcp)) {
		send_client_tls(w, gcp);
		return NULL;
	}
#endif

	return __prep_send_client(w, gcp);
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
	gcp->nr_timers_armed++;
	pr_dbg(&w->ctx->lh,
		"Prepared timer for target fd=%d, ts=%lld.%09lld, ref_cnt=%d",
		gcp->target.fd, gcp->ts.tv_sec, gcp->ts.tv_nsec, gcp->ref_cnt);
	return s;
}

/*
 * The tunnel or UDP association is up and its handshake timer is being
 * removed: with --idle-timeout, arm the idle check in its place. Queued after
 * the removal, which matches by the same user_data but runs first.
 */
static void arm_idle_timer(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	int sec = w->ctx->cfg.idle_timeout;

	if (sec <= 0)
		return;
	gcp->idle_timer = true;
	gcp->last_act = w->now;
	prep_timer_target(w, gcp, sec);
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

static void prep_attempt_timer_del(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct io_uring_sqe *s;

	if (!gcp->attempt_timer_armed)
		return;

	s = get_sqe_nofail(w);
	io_uring_prep_timeout_remove(s,
				     EV_BIT_IOU_ATTEMPT_TIMER | PTR_TO_U64(gcp),
				     0);
	io_uring_sqe_set_data(s, gcp);
	s->user_data |= EV_BIT_IOU_ATTEMPT_TIMER_DEL;
	get_gcp(gcp);
	gcp->attempt_timer_armed = false;
}

/*
 * Arm the delay after which the next candidate joins the race. Racing is what
 * makes a black-holed address cheap: without it a target that silently drops
 * SYNs costs the whole connect timeout before anything else is tried.
 *
 * At most one attempt timeout is outstanding per pair -- it owns gcp->ats for
 * as long as it is armed, and a second one would be indistinguishable from the
 * first at removal time. An already-armed timer is left alone: it fires no
 * later than the deadline a fresh one would have had.
 */
static void __arm_attempt_timer(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				int ms)
{
	struct gwp_ctx *ctx = w->ctx;
	struct io_uring_sqe *s;

	gcp->ats.tv_sec = ms / 1000;
	gcp->ats.tv_nsec = (long long)(ms % 1000) * 1000000LL;

	s = get_sqe_nofail(w);
	io_uring_prep_timeout(s, &gcp->ats, 0, 0);
	io_uring_sqe_set_data(s, gcp);
	s->user_data |= EV_BIT_IOU_ATTEMPT_TIMER;
	get_gcp(gcp);
	gcp->attempt_timer_armed = true;
	pr_dbg(&ctx->lh,
		"Prepared attempt timer (idx=%u, ts=%lld.%09lld, ref_cnt=%d)",
		gcp->idx, gcp->ats.tv_sec, gcp->ats.tv_nsec, gcp->ref_cnt);
}

static void arm_attempt_timer(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;

	if (gcp->attempt_timer_armed)
		return;
	if (gcp->next_cand >= gcp->nr_cand)
		return;			/* nothing left to start */
	if (ctx->cfg.connect_attempt_delay <= 0)
		return;			/* racing disabled: fall back only */
	if (ctx->upstream.enabled)
		return;			/* one proxy, nothing to race */

	__arm_attempt_timer(w, gcp, ctx->cfg.connect_attempt_delay);
}

/* How long a connect waits for a free descriptor before it tries again, in ms. */
#define GWP_FD_RETRY_MS 100

/*
 * The target socket of a plain or transparent forwarding pair could not be
 * created because the descriptor table is full. That passes as connections
 * close, and the client, which has done nothing wrong, is already accepted:
 * keep it, and try the same candidate again once the attempt timer fires.
 * The connect timeout still bounds the wait. accept() itself runs out of
 * descriptors too, and pauses (handle_ev_accept()), so no further client
 * piles up behind this one in the meantime.
 *
 * Only while no other attempt is racing: one that is may well connect, and
 * the attempt timer is then needed for the race. Plain forwarding has a
 * single candidate, so this is the case there.
 */
static bool wait_for_fd(struct gwp_wrk *w, struct gwp_conn_pair *gcp, int err)
{
	if (err != -EMFILE && err != -ENFILE)
		return false;
	if (gcp->prot_type != GWP_PROT_TYPE_NONE)
		return false;
	if (has_inflight_attempt(gcp) || gcp->attempt_timer_armed)
		return false;

	if (!(gcp->flags & GWP_CONN_FLAG_FD_WAIT)) {
		gcp->flags |= GWP_CONN_FLAG_FD_WAIT;
		pr_warn(&w->ctx->lh,
			"Too many open files, retrying the target connect (idx=%u, ca=%s)",
			gcp->idx, ip_to_str(&gcp->client_addr));
	}

	gcp->next_cand--;
	__arm_attempt_timer(w, gcp, GWP_FD_RETRY_MS);
	return true;
}

/*
 * Retire an attempt socket that is not going to be the winner. The fd is not
 * closed here: its connect is still in flight and io_uring holds a reference to
 * the file, so the close is queued from the cancelled completion instead (see
 * handle_ev_target_attempt()), keeping fd lifetime tied to SQE completion as
 * the rest of this loop does.
 */
static void cancel_attempt(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			   uint8_t slot)
{
	struct io_uring_sqe *s = get_sqe_nofail(w);

	io_uring_prep_cancel_fd(s, gcp->attempt_fd[slot],
				IORING_ASYNC_CANCEL_ALL);
	io_uring_sqe_set_data(s, gcp);
	s->user_data |= EV_BIT_IOU_ATTEMPT_CANCEL;
	get_gcp(gcp);
	pr_dbg(&w->ctx->lh, "Cancelling losing attempt %u (fd=%d, idx=%u)",
		slot, gcp->attempt_fd[slot], gcp->idx);
}

static void shutdown_gcp(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	struct io_uring_sqe *s;
	uint8_t i;

	if (gcp->flags & GWP_CONN_FLAG_IS_CANCEL)
		return;

	/*
	 * Racing attempts that never resolved: their connects still hold a
	 * reference each, so the pair cannot be freed until they are reaped.
	 * The attempt timeout is dropped for the same reason -- unlike the
	 * connect timer it is not otherwise waited on.
	 */
	for (i = 0; i < GWP_MAX_CONN_CAND; i++) {
		if (gcp->attempt_fd[i] >= 0)
			cancel_attempt(w, gcp, i);
	}
	prep_attempt_timer_del(w, gcp);

	/*
	 * The protocol and connect timeouts hold a reference too. Left armed,
	 * they keep the pair -- and the client socket -- open until they
	 * expire, so a client that was just sent an error reply (a 407, say)
	 * would sit on an open connection for the whole protocol timeout. A
	 * removal that finds the timeout already gone completes with -ENOENT,
	 * which handle_ev_timer() ignores.
	 */
	for (i = 0; i < gcp->nr_timers_armed; i++)
		prep_timer_del_target(w, gcp);

	/*
	 * Cancel what is still in flight on the pair's sockets. Only where
	 * there is something: a pair usually ends because both directions
	 * hit EOF, with nothing armed on either socket, and a cancel then
	 * costs an SQE and a CQE for nothing. IORING_ASYNC_CANCEL_ALL, since
	 * a socket can carry more than one request -- a forwarding pair has a
	 * recv and a send outstanding on one fd at once, as may the UDP
	 * relay. Without it the kernel cancels exactly one, and every
	 * survivor keeps a reference that stops put_gcp() from ever reaching
	 * zero, leaking the pair and both fds for the process's life.
	 */
	if (gcp->target.fd >= 0 && gcp->nr_ops_target) {
		pr_dbg(&ctx->lh, "Cancelling target I/O (fd=%d, nr=%u)",
		       gcp->target.fd, gcp->nr_ops_target);
		s = get_sqe_nofail(w);
		io_uring_prep_cancel_fd(s, gcp->target.fd, IORING_ASYNC_CANCEL_ALL);
		io_uring_sqe_set_data(s, gcp);
		s->user_data |= EV_BIT_IOU_TARGET_CANCEL;
		get_gcp(gcp);
	}

	if (gcp->client.fd >= 0 && gcp->nr_ops_client) {
		pr_dbg(&ctx->lh, "Cancelling client I/O (fd=%d, nr=%u)",
		       gcp->client.fd, gcp->nr_ops_client);
		s = get_sqe_nofail(w);
		io_uring_prep_cancel_fd(s, gcp->client.fd, IORING_ASYNC_CANCEL_ALL);
		io_uring_sqe_set_data(s, gcp);
		s->user_data |= EV_BIT_IOU_CLIENT_CANCEL;
		get_gcp(gcp);
	}

	if (gcp->udp_fd >= 0 && gcp->nr_ops_udp) {
		pr_dbg(&ctx->lh, "Cancelling UDP relay (fd=%d, nr=%u)",
		       gcp->udp_fd, gcp->nr_ops_udp);
		s = get_sqe_nofail(w);
		io_uring_prep_cancel_fd(s, gcp->udp_fd, IORING_ASYNC_CANCEL_ALL);
		io_uring_sqe_set_data(s, gcp);
		s->user_data |= EV_BIT_IOU_UDP_CANCEL;
		get_gcp(gcp);
	}

	gcp->flags |= GWP_CONN_FLAG_IS_CANCEL;
}

static int prep_recv_client_prot(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	return __prep_recv_client(w, gcp, EV_BIT_IOU_CLIENT_PROT);
}

#ifdef CONFIG_HTTPS
/*
 * ------------------------------------------------------------------------
 * HTTPS proxy: client-side TLS termination on the io_uring loop.
 *
 * Only the client wire speaks TLS; the target side stays plaintext. Ciphertext
 * is received straight into the engine's input queue and sent from the
 * connection's gwp_iou_tls scratch, because an async send must own a stable
 * buffer for the whole operation. Once the handshake completes, the
 * connection runs the normal SOCKS5/HTTP logic on the decrypted client.buf,
 * exactly like the plaintext path. TLS is auto-detected from the
 * client's first byte so plaintext clients keep working on the same port.
 * ------------------------------------------------------------------------
 */

static void prep_send_client_cipher(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				    uint64_t ev_bit)
{
	struct gwp_iou_tls *t = gcp->tls_io;
	struct io_uring_sqe *s = get_sqe_nofail(w);

	io_uring_prep_send(s, gcp->client.fd, t->tx + t->tx_sent,
			   t->tx_len - t->tx_sent, MSG_NOSIGNAL);
	io_uring_sqe_set_data(s, gcp);
	s->user_data |= ev_bit;
	get_gcp_io(gcp, s);
}

/*
 * Encrypt as much of target.buf as the engine accepts, pull the resulting
 * ciphertext into the tx scratch, and queue it. With an in-memory write queue
 * SSL_write() never blocks, so target.buf drains fully; a record never exceeds
 * the scratch. If there is nothing to send (no plaintext, no queued
 * ciphertext), fall back to the plaintext post-send action (read the target).
 */
static void send_client_tls(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_iou_tls *t = gcp->tls_io;
	struct gwp_ssl *ssl = gcp->client.tls;
	int n;

	/*
	 * The tx scratch is still being sent. Its completion
	 * (handle_ev_client_send()) comes back here for what has been added
	 * to target.buf since, as for a plaintext client (__prep_send_client()).
	 */
	if (t->tx_sent < t->tx_len)
		return;

	while (gcp->target.len) {
		size_t consumed = 0;
		int sr = gwp_ssl_write(ssl, gcp->target.buf, gcp->target.len,
				       &consumed);

		if (sr == GWP_SSL_OK) {
			gwp_conn_buf_advance(&gcp->target, consumed);
			if (!consumed)
				break;
		} else {
			break;	/* ciphertext must drain first */
		}
	}

	n = gwp_ssl_bio_read(ssl, t->tx, sizeof(t->tx));
	t->tx_len = (n > 0) ? (uint32_t)n : 0;
	t->tx_sent = 0;

	if (t->tx_len)
		prep_send_client_cipher(w, gcp, EV_BIT_IOU_CLIENT_SEND);
	else if (gcp->target.fd >= 0 && !gcp->target.rd_eof)
		prep_recv_target(w, gcp);
}

/*
 * Post-recv forwarding pump: decrypt buffered plaintext into client.buf and
 * send it to the target; if the engine has none ready, read more ciphertext.
 * Used both after a client recv completes and after target.buf drains, so
 * plaintext the engine buffered beyond one client.buf-full is not stranded.
 */
static int tls_forward_pump(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_conn *c = &gcp->client;
	size_t space = c->cap - c->len, got = 0;
	uint32_t from = c->len;
	int sr;

	if (space) {
		sr = gwp_ssl_read(c->tls, c->buf + c->len, space, &got);
		if (sr == GWP_SSL_ERROR)
			return -EIO;
		if (sr == GWP_SSL_OK && got == 0) {	/* clean close_notify */
			c->rd_eof = true;
			return iou_forward_progress(w, gcp);
		}
		c->len += (uint32_t)got;
	}

	if (gwp_http_fwd_active(gcp)) {
		sr = gwp_http_fwd_in(w, gcp, c, from);
		if (sr)
			return sr;
	}

	if (!c->len)
		return prep_recv_client(w, gcp);
	prep_send_target(w, gcp);
	return 0;
}

/*
 * Decrypt what the engine holds into client.buf and run the protocol on it.
 * One gwp_ssl_read() yields at most one record, and records that arrived
 * together are all off the socket already: take every one of them now, as a
 * plaintext recv of the same segment would, since no completion will come
 * for them later.
 *
 * Not while a reply is on its way to the client, though: a protocol pass
 * may queue another reply, and the tx scratch it would be encrypted into is
 * still being sent. Neither is a recv armed then, since the records the
 * engine may hold would not complete one. handle_ev_client_send() picks the
 * pump up again once the reply is out.
 */
static int tls_prot_pump(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_conn *c = &gcp->client;
	struct gwp_iou_tls *t = gcp->tls_io;
	uint32_t from = c->len;
	size_t got;
	int sr;

	if (t->tx_sent < t->tx_len) {
		t->prot_resume = true;
		return 0;
	}

	while (c->len < c->cap) {
		got = 0;
		sr = gwp_ssl_read(c->tls, c->buf + c->len, c->cap - c->len,
				  &got);
		if (sr == GWP_SSL_ERROR)
			return -EIO;
		/* Need more ciphertext, or the client sent close_notify. */
		if (!got)
			break;
		c->len += (uint32_t)got;
	}

	/* Nothing new, and room for more: wait for the client. */
	if (c->len == from && c->len < c->cap)
		return prep_recv_client_prot(w, gcp);

	return process_client_prot(w, gcp);
}

/*
 * Whether the protocol should be fed from the engine rather than the socket:
 * it still holds records and client.buf has room for them. With a reply
 * still being sent, tls_prot_pump() waits for that send to complete.
 */
static bool tls_prot_more(struct gwp_conn_pair *gcp)
{
	struct gwp_conn *c = &gcp->client;

	return client_is_tls(gcp) && c->len < c->cap &&
	       gwp_ssl_rx_more(c->tls);
}

/* Handshake done: switch to the plaintext protocol path on the decrypted stream. */
static int tls_hs_finish(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	pr_dbg(&w->ctx->lh, "TLS handshake complete (cfd=%d, alpn=%s)",
	       gcp->client.fd, gwp_ssl_alpn(gcp->client.tls) ?: "none");
	gcp->conn_state = CONN_STATE_PROT;
	/* App data may already sit in the engine from the last handshake recv. */
	return tls_prot_pump(w, gcp);
}

/*
 * Advance the handshake: step it, flush any records it produced, and either
 * finish or wait for the peer's next flight. Called after each handshake recv
 * or send completes.
 */
static int tls_hs_step(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_iou_tls *t = gcp->tls_io;
	struct gwp_ssl *ssl = gcp->client.tls;
	int hs, n;

	hs = gwp_ssl_handshake(ssl);
	if (hs == GWP_SSL_ERROR) {
		pr_dbg(&w->ctx->lh, "TLS handshake failed: %s", gwp_ssl_errstr());
		return -ECONNRESET;
	}

	if (gwp_ssl_bio_pending(ssl) > 0) {
		n = gwp_ssl_bio_read(ssl, t->tx, sizeof(t->tx));
		t->tx_len = (n > 0) ? (uint32_t)n : 0;
		t->tx_sent = 0;
		if (t->tx_len) {
			prep_send_client_cipher(w, gcp, EV_BIT_IOU_TLS_HS_SEND);
			return 0;
		}
	}

	if (hs == GWP_SSL_OK)
		return tls_hs_finish(w, gcp);

	return __prep_recv_client(w, gcp, EV_BIT_IOU_TLS_HS_RECV);
}

static int handle_ev_tls_hs_recv(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				 struct io_uring_cqe *cqe)
{
	int r = cqe->res;

	if (r < 0) {
		if (r == -EAGAIN || r == -EINTR)
			return __prep_recv_client(w, gcp,
						  EV_BIT_IOU_TLS_HS_RECV);
		return r;
	}
	if (r == 0)
		return -ECONNRESET;	/* peer closed mid-handshake */

	gwp_ssl_rx_commit(gcp->client.tls, (size_t)r);
	return tls_hs_step(w, gcp);
}

static int handle_ev_tls_hs_send(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				 struct io_uring_cqe *cqe)
{
	struct gwp_iou_tls *t = gcp->tls_io;
	int r = handle_sock_ret(cqe->res);

	if (r < 0)
		return r;

	t->tx_sent += (uint32_t)r;
	if (t->tx_sent < t->tx_len) {
		prep_send_client_cipher(w, gcp, EV_BIT_IOU_TLS_HS_SEND);
		return 0;
	}

	/* Our flight is out; re-step to flush any remainder or await the peer. */
	return tls_hs_step(w, gcp);
}

/*
 * First-byte probe: a TLS ClientHello starts with 0x16, while SOCKS5 (0x05),
 * SOCKS4 (0x04) and HTTP (an ASCII letter) do not, so 0x16 is unambiguous. Peek
 * one byte without consuming it; the handshake/plaintext recv reads it for real.
 */
static void prep_tls_detect(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct io_uring_sqe *s = get_sqe_nofail(w);

	gcp->conn_state = CONN_STATE_TLS_DETECT;
	io_uring_prep_recv(s, gcp->client.fd, gcp->client.buf, 1,
			   MSG_PEEK | MSG_NOSIGNAL);
	io_uring_sqe_set_data(s, gcp);
	s->user_data |= EV_BIT_IOU_TLS_DETECT;
	get_gcp_io(gcp, s);
}

static int handle_ev_tls_detect(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				struct io_uring_cqe *cqe)
{
	struct gwp_ctx *ctx = w->ctx;
	int r = cqe->res;

	if (r < 0) {
		if (r == -EAGAIN || r == -EINTR) {
			prep_tls_detect(w, gcp);
			return 0;
		}
		return r;
	}
	if (r == 0)
		return -ECONNRESET;

	if ((unsigned char)gcp->client.buf[0] != 0x16) {
		/* Plaintext client: proceed as usual, peeked byte still queued. */
		gcp->conn_state = CONN_STATE_PROT;
		return prep_recv_client_prot(w, gcp);
	}

	/* Only the header needs zeroing; tx is scratch. */
	gcp->tls_io = malloc(sizeof(*gcp->tls_io));
	if (unlikely(!gcp->tls_io))
		return -ENOMEM;
	gcp->tls_io->tx_len = 0;
	gcp->tls_io->tx_sent = 0;
	gcp->tls_io->closing = false;
	gcp->tls_io->prot_resume = false;

	gcp->client.tls = gwp_ssl_server_new(ctx->ssl_ctx);
	if (unlikely(!gcp->client.tls))
		return -ENOMEM;

	gcp->conn_state = CONN_STATE_TLS_HANDSHAKE;
	return __prep_recv_client(w, gcp, EV_BIT_IOU_TLS_HS_RECV);
}
#endif /* CONFIG_HTTPS */

/*
 * SOCKS5/HTTP proxy mode. The initial connection has no target socket yet: read
 * the client's protocol handshake (SOCKS5 greeting/CONNECT or HTTP CONNECT)
 * first; the target socket is created once the destination is known. The
 * per-connection protocol state (s5_conn/http_conn) is allocated lazily by the
 * shared gwp_handle_conn_state_prot() the first time it runs.
 */
static int arm_gcp_prot(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;

	gcp->conn_state = CONN_STATE_PROT;
#ifdef CONFIG_HTTPS
	/*
	 * With a TLS listener, first-byte-probe the connection so plaintext and
	 * TLS clients share the port (see prep_tls_detect()).
	 */
	if (ctx->ssl_ctx)
		prep_tls_detect(w, gcp);
	else
#endif
		prep_recv_client_prot(w, gcp);

	if (ctx->cfg.protocol_timeout > 0)
		prep_timer_target(w, gcp, ctx->cfg.protocol_timeout);

	return 0;
}

/*
 * Start connecting to the target. Nothing but the connect itself is armed here:
 * with several attempts racing, the pair has no target fd yet, and the client
 * recv would have to be attributed to one of them. Both recvs are armed from
 * finish_target_connect() once an attempt has won.
 */
static int do_prep_connect(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	int r;

	/*
	 * Take the first candidate the ACL allows; the same helper walks the
	 * rest, so a candidate that cannot even be started is not fatal while
	 * others remain.
	 */
	r = connect_next_candidate(w, gcp, -EHOSTUNREACH);
	if (unlikely(r))
		return r;

	/*
	 * The connect timeout bounds the whole operation, across every
	 * candidate address, so it is armed once here rather than per attempt.
	 * Armed only after an attempt is actually running: on the failure path
	 * the pair is torn down immediately and a live timeout would pin it
	 * until it expired.
	 */
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

	if (ctx->cfg.as_socks5 || ctx->cfg.as_http)
		return arm_gcp_prot(w, gcp);
	else
		return arm_gcp_no_socks5(w, gcp);
}

static int __handle_ev_accept(struct gwp_wrk *w, struct io_uring_cqe *cqe)
{
	bool transparent = w->ctx->cfg.as_transparent;
	struct gwp_ctx *ctx = w->ctx;
	int fd = cqe->res, r;
	struct gwp_conn_pair *gcp;
	struct gwp_sockaddr tdst;
	/* The plain/transparent forwarding target. For SOCKS5/HTTP it stays the
	 * --target placeholder, replaced by the handshake's destination. */
	struct gwp_sockaddr fwd_target = ctx->target_addr;

	if (unlikely(fd < 0)) {
		if (fd == -EAGAIN || fd == -EINTR)
			return 0;

		/* Resource errors are classified and logged by handle_ev_accept(). */
		return fd;
	}

	if (!gwp_ctx_acl_client_allowed(ctx, &w->iou->accept_addr,
					GWP_ACL_PROTO_TCP)) {
		pr_info(&ctx->lh, "ACL denied client %s",
			ip_to_str(&w->iou->accept_addr));
		prep_close(w, fd);
		return 0;
	}

	/* --max-conns-per-ip: before anything is read or set up. */
	if (unlikely(ctx->iplim) &&
	    !gwp_ctx_iplim_get(w, &w->iou->accept_addr)) {
		prep_close(w, fd);
		return 0;
	}

	/* Transparent proxy: take the target from SO_ORIGINAL_DST. */
	if (transparent) {
		r = gwp_get_orig_dst(fd, &w->iou->accept_addr, &tdst);
		if (r) {
			pr_warn(&ctx->lh, "No original destination for %s: %s (not a redirected connection?)",
				ip_to_str(&w->iou->accept_addr),
				r == -ELOOP ? "it is this proxy" : strerror(-r));
			r = 0;
			goto out_uncount;
		}
	}

	/*
	 * Plain and transparent forwarding have no handshake to wait for, so
	 * their destination is known here. The OUTPUT chain is not evaluated
	 * yet: connect_next_candidate() runs it per candidate, which is where a
	 * -j DNAT rewrite and the -j MARK/BIND socket options are picked up.
	 */
	if (!ctx->cfg.as_socks5 && !ctx->cfg.as_http)
		fwd_target = transparent ? tdst : ctx->target_addr;

	gcp = gwp_alloc_conn_pair(w);
	if (unlikely(!gcp)) {
		pr_err(&ctx->lh, "Allocate connection pair: %s", strerror(ENOMEM));
		r = -ENOMEM;
		goto out_uncount;
	}

	gcp->ref_cnt = 0;

	gcp->client.fd = fd;
	gcp->client_addr = w->iou->accept_addr;
	/* From here on, freeing the pair uncounts the client. */
	if (ctx->iplim)
		gcp->flags |= GWP_CONN_FLAG_IPLIM;
	gwp_conn_set_single_candidate(gcp, &fwd_target);
	gcp->is_target_alive = false;
	r = arm_gcp(w, gcp);
	if (unlikely(r)) {
		/*
		 * The plain path now starts its connect from here, so the
		 * failure may come with SQEs already queued -- a rejection
		 * reply, or an attempt that did get going. Those hold a
		 * reference each, so the pair has to drain through put_gcp()
		 * rather than be freed underneath them.
		 */
		if (gcp->ref_cnt > 0)
			shutdown_gcp(w, gcp);
		else
			goto out_free_pair;

		/*
		 * A per-connection failure -- a target the ACL denied, an
		 * address that would not connect -- must not take the worker
		 * down with it. Only descriptor exhaustion is worth pausing
		 * accept for, which is what the caller does with it.
		 */
		if (r == -EMFILE || r == -ENFILE || r == -ENOMEM)
			return r;
		return 0;
	}

	log_conn_pair_created(w, gcp);
	return r;

out_free_pair:
	gcp->client.fd = gcp->target.fd = gcp->timer_fd = -1;
	gwp_free_conn_pair(w, gcp);
	goto out_close;
out_uncount:
	if (ctx->iplim)
		gwp_ctx_iplim_put(ctx, &w->iou->accept_addr);
out_close:
	prep_close(w, fd);
	return r;
}

/*
 * accept(2) errors that say the listening socket itself is unusable, as
 * opposed to the one connection being accepted.
 */
static bool is_listener_error(int r)
{
	switch (r) {
	case -EBADF:
	case -EFAULT:
	case -EINVAL:
	case -ENOTSOCK:
	case -EOPNOTSUPP:
		return true;
	default:
		return false;
	}
}

static int handle_ev_accept(struct gwp_wrk *w, struct io_uring_cqe *cqe)
{
	int r = __handle_ev_accept(w, cqe);

	if (unlikely(r < 0)) {
		/*
		 * Resource exhaustion is transient: pause accepting instead of
		 * killing the worker, and retry via a timer (arm_accept_retry())
		 * until descriptors free up. Analogous to the epoll
		 * handle_accept_error().
		 */
		if (r == -EMFILE || r == -ENFILE || r == -ENOMEM) {
			if (!w->accept_is_stopped) {
				w->accept_is_stopped = true;
				pr_warn(&w->ctx->lh,
					"Too many open files, pausing accept (tidx=%u)",
					w->idx);
			}
			arm_accept_retry(w);
			return 0;
		}

		/*
		 * Errors that come back the same at once if accept is simply
		 * re-armed: the kernel is short of socket memory (ENOBUFS), or
		 * a security module refuses the connection (EPERM, EACCES),
		 * which leaves it at the head of the backlog for the next
		 * accept to be refused again. Re-arming at once spins the
		 * worker and floods the log; pause on the retry timer instead,
		 * logged once until an accept succeeds.
		 */
		if (cqe->res < 0 &&
		    (r == -ENOBUFS || r == -EPERM || r == -EACCES)) {
			if (!w->accept_is_stopped) {
				w->accept_is_stopped = true;
				pr_warn(&w->ctx->lh,
					"Failed to accept new connection: %s, pausing accept (tidx=%u)",
					strerror(-r), w->idx);
			}
			arm_accept_retry(w);
			return 0;
		}

		/*
		 * Only a listener that is itself broken is worth stopping
		 * for: re-arming accept on it would fail the same way
		 * forever. Everything else concerns one connection -- an
		 * accept(2) the man page says to retry (ECONNABORTED and
		 * friends), or a pair that failed after a successful accept,
		 * such as a strict --bind-iface naming a device that is not
		 * there -- and has been logged and freed already. Returning
		 * it would stop this worker, and gwp_ctx_thread_entry() would
		 * then stop the whole proxy, so one client could take every
		 * live connection down with it. The epoll loop already keeps
		 * going in this case.
		 */
		if (cqe->res < 0 && is_listener_error(r)) {
			pr_err(&w->ctx->lh, "Failed to accept new connection: %s",
			       strerror(-r));
			return r;
		}

		if (cqe->res < 0)
			pr_warn(&w->ctx->lh, "Failed to accept new connection: %s",
				strerror(-r));
		arm_accept(w);
		return 0;
	}

	if (unlikely(w->accept_is_stopped)) {
		w->accept_is_stopped = false;
		pr_info(&w->ctx->lh, "Resumed accepting new connections (tidx=%u)",
			w->idx);
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
	get_gcp_io(gcp, s);
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
	get_gcp_io(gcp, s);
	return s;
}

/* The upstream tunnel is up (reply already spliced); start forwarding. */
static int upstream_iou_finish(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	int r;

	prep_timer_del_target(w, gcp);
	arm_idle_timer(w, gcp);
	gcp->up_tx = false;
	gcp->is_target_alive = true;
	gcp->conn_state = CONN_STATE_FORWARDING;

	r = gwp_http_fwd_begin(w, gcp);
	if (r)
		return r;

	pr_info(&ctx->lh, "Upstream tunnel established (idx=%u, ca=%s, dst=%s)",
		gcp->idx, ip_to_str(&gcp->client_addr),
		gwp_upstream_dst_str(gcp));

	/* Start forwarding. */
	if (gcp->target.len)
		prep_send_client(w, gcp);
	else
		prep_recv_target(w, gcp);

	/*
	 * Flush any client data buffered during the handshake to the target
	 * before reading more; an HTTP forwarding front queues its rewritten
	 * request in client.buf, which the origin must receive. The send
	 * completion arms the next client recv.
	 */
	if (!gcp->client.len)
		return prep_recv_client(w, gcp);
	prep_send_target(w, gcp);
	return 0;
}

/* Begin the upstream-proxy handshake and queue the first request send. */
static int upstream_iou_start(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	int r = gwp_upstream_hs_start(w, gcp);

	if (r == GWP_UPSTREAM_IO_SEND) {
		prep_upstream_send(w, gcp);
		return 0;
	}
	return r;	/* negative errno */
}

/*
 * Whether a send to the client is still on its way. The plaintext send reads
 * target.buf, a TLS client's the tx scratch; either way its completion
 * (handle_ev_client_send()) goes on to work on target.buf.
 */
static bool client_send_busy(struct gwp_conn_pair *gcp)
{
#ifdef CONFIG_HTTPS
	if (client_is_tls(gcp))
		return gcp->tls_io->tx_sent < gcp->tls_io->tx_len;
#endif
	return gcp->client_tx;
}

/*
 * Connected to the upstream proxy, but the handshake with it has not begun:
 * finish_target_connect() left that to the completion of a client send.
 */
static bool upstream_start_held(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	int cs = gcp->conn_state;

	return w->ctx->upstream.enabled && gcp->target.fd >= 0 &&
	       (cs == CONN_STATE_SOCKS5_CONNECT || cs == CONN_STATE_HTTP_CONNECT);
}

static int handle_ev_upstream_s5(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				 struct io_uring_cqe *cqe)
{
	int r = handle_sock_ret(cqe->res);
	bool notify;

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

	r = gwp_upstream_hs_on_reply(w, gcp, &notify);
	switch (r) {
	case GWP_UPSTREAM_IO_SEND:
		prep_upstream_send(w, gcp);
		return 0;
	case GWP_UPSTREAM_IO_RECV:
		prep_upstream_recv(w, gcp);
		return 0;
	case GWP_UPSTREAM_IO_DONE:
		return upstream_iou_finish(w, gcp);
	}

	/*
	 * Negative errno. Tell the client when the upstream turned us down;
	 * the reply's send goes out ahead of the teardown's cancels.
	 */
	if (notify && gwp_upstream_fail_reply(w, gcp, r) > 0)
		prep_send_client(w, gcp);
	return r;
}

/*
 * An attempt won the race. Adopt its socket as the pair's target and retire
 * every other attempt plus the attempt timer, so the rest of the loop sees an
 * ordinary connected target.
 */
static void adopt_winning_attempt(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				  uint8_t slot)
{
	uint8_t i;

	gcp->target.fd = gcp->attempt_fd[slot];
	gcp->attempt_fd[slot] = -1;
	/*
	 * Restore the address this attempt actually dialled: with a race the
	 * winner is often not the last one started, and target_addr currently
	 * holds whichever candidate was most recently set up. Using the
	 * recorded address also keeps a -j DNAT rewrite intact, which
	 * re-deriving from cand[] would silently undo.
	 */
	gcp->target_addr = gcp->attempt_addr[slot];

	for (i = 0; i < GWP_MAX_CONN_CAND; i++) {
		if (gcp->attempt_fd[i] >= 0)
			cancel_attempt(w, gcp, i);
	}

	/* The race is over; no further candidate should join it. */
	gcp->next_cand = gcp->nr_cand;
	prep_attempt_timer_del(w, gcp);
}

/*
 * The target is connected: arm the relay and, for SOCKS5/HTTP, hand the client
 * its connect reply.
 */
static int finish_target_connect(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				 int res)
{
	bool http_fwd;
	int r;

	/*
	 * Connected to the upstream proxy: run the client handshake before
	 * forwarding. The connect timer is kept to bound the handshake, and the
	 * normal recv/send SQEs stay unarmed so they cannot collide with it.
	 *
	 * The handshake builds its requests in target.buf, which a SOCKS5
	 * method or auth reply to the client may still be sent from: the
	 * client was answered and asked to connect in one go, and the send
	 * has not completed (out of socket memory, say). Its completion would
	 * also take the request for what is left of the reply. Leave the
	 * handshake to that completion (handle_ev_client_send()).
	 */
	if (w->ctx->upstream.enabled) {
		if (client_send_busy(gcp))
			return 0;
		return upstream_iou_start(w, gcp);
	}

	prep_timer_del_target(w, gcp);
	arm_idle_timer(w, gcp);
	gcp->is_target_alive = true;
	pr_info(&w->ctx->lh,
		"Target socket connected (fd=%d, idx=%u, ca=%s, ta=%s)",
		gcp->target.fd, gcp->idx,
		ip_to_str(&gcp->client_addr),
		ip_to_str(&gcp->target_addr));

	http_fwd = (gcp->prot_type == GWP_PROT_TYPE_HTTP && gcp->http_conn &&
		    gwp_http_conn_is_forward(gcp->http_conn));

	/*
	 * A forwarding-proxy request queues its rewritten request in
	 * client.buf; that goes to the origin below, and the client recv is
	 * armed only once it has drained (handle_ev_target_send()). Arming it
	 * here would race with that send on client.buf.
	 *
	 * Otherwise, what the client sent right behind its request is still in
	 * client.buf. Send it first, since the client may wait for an answer
	 * to it before it sends anything else; the send completion arms the
	 * client recv.
	 */
	if (!http_fwd && gcp->client.len) {
		prep_send_target(w, gcp);
#ifdef CONFIG_HTTPS
	} else if (!http_fwd && client_is_tls(gcp)) {
		/* The engine may hold more of it; tunnel that first. */
		r = tls_forward_pump(w, gcp);
		if (r)
			return r;
#endif
	} else if (!http_fwd) {
		r = prep_recv_client(w, gcp);
		if (r)
			return r;
	}

	/*
	 * SOCKS5/HTTP: write the connect reply into target.buf and flush it to
	 * the client with a completion callback. Its handler drains target.buf
	 * and only then arms the target recv, so the recv never overwrites the
	 * still-pending reply. Plain forwarding has no reply to get in the way.
	 */
	if (gcp->prot_type == GWP_PROT_TYPE_SOCKS5) {
		r = gwp_socks5_prep_connect_reply(w, gcp, res);
		if (r)
			return r;
	} else if (gcp->prot_type == GWP_PROT_TYPE_HTTP) {
		if (http_fwd) {
			/*
			 * Forwarding proxy: no reply to the client. Send the
			 * rewritten request (queued in client.buf) to the origin
			 * and read the response.
			 */
			gcp->conn_state = CONN_STATE_FORWARDING;
			r = gwp_http_fwd_begin(w, gcp);
			if (r)
				return r;
			prep_send_target(w, gcp);
			prep_recv_target(w, gcp);
			return 0;
		}

		r = gwp_http_build_connect_reply(gcp->http_conn, gcp->target.buf,
						 gcp->target.cap);
		if (r < 0)
			return r;
		gcp->target.len = (uint32_t)r;
	}

	if (gcp->prot_type != GWP_PROT_TYPE_NONE && gcp->target.len)
		prep_send_client(w, gcp);
	else
		prep_recv_target(w, gcp);

	return 0;
}

/*
 * One racing connect completed. Attempts are retired here rather than where
 * they are cancelled, so an attempt socket is closed only once io_uring is
 * done with it.
 */
static int handle_ev_target_attempt(struct gwp_wrk *w, void *udata,
				    uint8_t slot, int res)
{
	struct gwp_conn_pair *gcp = udata;
	struct gwp_ctx *ctx = w->ctx;
	int fd;

	if (unlikely(slot >= GWP_MAX_CONN_CAND))
		return -EINVAL;

	fd = gcp->attempt_fd[slot];
	if (unlikely(fd < 0))
		return 0;		/* already retired */

	/*
	 * A winner was already adopted, or the pair is being torn down: this is
	 * a loser being reaped, not a result to act on.
	 */
	if (res < 0 || gcp->target.fd >= 0 ||
	    (gcp->flags & GWP_CONN_FLAG_IS_CANCEL)) {
		gcp->attempt_fd[slot] = -1;
		prep_close(w, fd);

		if (res < 0 && res != -ECANCELED)
			pr_dbg(&ctx->lh,
				"Target attempt %u failed: %s (fd=%d, idx=%u, ta=%s)",
				slot, strerror(-res), fd, gcp->idx,
				ip_to_str(&gcp->attempt_addr[slot]));

		if (gcp->target.fd >= 0 || (gcp->flags & GWP_CONN_FLAG_IS_CANCEL))
			return 0;

		/*
		 * Another attempt may still be racing; only step to a new
		 * candidate once nothing is outstanding, so a slow-but-working
		 * address is not abandoned because a faster one was refused.
		 */
		if (has_inflight_attempt(gcp))
			return 0;

		return connect_next_candidate(w, gcp, res);
	}

	adopt_winning_attempt(w, gcp, slot);
	return finish_target_connect(w, gcp, res);
}

static int handle_ev_timer(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			   bool is_timer_del, int res)
{
	struct gwp_ctx *ctx = w->ctx;
	int r = 0;

	/* The timeout's own completion: it fired or was removed. */
	if (!is_timer_del && gcp->nr_timers_armed)
		gcp->nr_timers_armed--;

	/*
	 * Idle check: close the pair if nothing moved for the whole timeout,
	 * else look again once the rest of it has passed. Only one timeout
	 * may carry the check: a handshake timer that fired just as the
	 * tunnel came up arrives here too, and must not start a second one.
	 */
	if (gcp->idle_timer && !is_timer_del && res == -ETIME &&
	    !(gcp->flags & GWP_CONN_FLAG_IS_CANCEL)) {
		int sec = ctx->cfg.idle_timeout;
		uint32_t idle = w->now - gcp->last_act;

		if (idle >= (uint32_t)sec) {
			pr_info(&ctx->lh, "Idle timeout (idx=%u, ca=%s, ta=%s)",
				gcp->idx, ip_to_str(&gcp->client_addr),
				ip_to_str(&gcp->target_addr));
			return -ETIMEDOUT;
		}
		if (!gcp->nr_timers_armed)
			prep_timer_target(w, gcp, sec - (int)idle);
		return 0;
	}

	if (!gcp->is_target_alive && res == -ETIME) {
		assert(is_timer_del == false);
		r = -ETIME;
		pr_warn(&ctx->lh,
			"Connection timeout! (idx=%u, cfd=%d, tfd=%d, ca=%s, ta=%s)",
			gcp->idx, gcp->client.fd, gcp->target.fd,
			ip_to_str(&gcp->client_addr),
			ip_to_str(&gcp->target_addr));

		/*
		 * Tell the client the origin timed out (SOCKS5 REP 0x06, HTTP
		 * 504) rather than hanging up silently. Only once a target
		 * socket exists -- the other user of this timer is the protocol
		 * handshake, where nothing has been requested yet. During a
		 * race there is no target fd yet, so the in-flight attempts
		 * count as one.
		 *
		 * Send only what gwp_conn_fail_reply() added: plain forwarding
		 * has no reply to give, and a stalled upstream handshake leaves
		 * its own bytes in target.buf, which are dropped first.
		 */
		if (gcp->target.fd >= 0 || has_inflight_attempt(gcp)) {
			uint32_t len;

			if (gwp_in_upstream_hs(gcp)) {
				gcp->target.len = 0;
				gwp_conn_buf_compact(&gcp->target);
			}
			len = gcp->target.len;
			if (!gwp_conn_fail_reply(w, gcp, r) &&
			    gcp->target.len > len)
				prep_send_client(w, gcp);
		}
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
#ifdef CONFIG_HTTPS
/*
 * A TLS client is owed a close_notify before the FIN, as the epoll loop sends
 * one: without it the client cannot tell the end of a response that is
 * delimited by the connection closing from a truncation, and strict clients
 * (OpenSSL 3, curl) report the read as failed. Queue it through the normal
 * ciphertext send. Returns true once nothing of ours is left to send, so the
 * write side can be shut; false while ciphertext is still on its way, whose
 * send completion comes back through iou_forward_progress().
 */
static bool tls_close_client(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_iou_tls *t = gcp->tls_io;
	int n;

	if (t->tx_sent < t->tx_len)
		return false;
	if (t->closing)
		return true;

	t->closing = true;
	gwp_ssl_shutdown(gcp->client.tls);
	n = gwp_ssl_bio_read(gcp->client.tls, t->tx, sizeof(t->tx));
	if (n <= 0)
		return true;

	t->tx_len = (uint32_t)n;
	t->tx_sent = 0;
	prep_send_client_cipher(w, gcp, EV_BIT_IOU_CLIENT_SEND);
	return false;
}
#endif

static int iou_forward_progress(struct gwp_wrk __unused *w,
				struct gwp_conn_pair *gcp)
{
	bool shut_client = false, shut_target = false, done;

	if (gcp->target.rd_eof && gcp->target.len == 0 && !gcp->client.wr_shut) {
#ifdef CONFIG_HTTPS
		if (client_is_tls(gcp) && !tls_close_client(w, gcp))
			return 0;
#endif
		shut_client = true;
		gcp->client.wr_shut = true;
	}

	if (gcp->client.rd_eof && gcp->client.len == 0 && !gcp->target.wr_shut) {
		shut_target = true;
		gcp->target.wr_shut = true;
	}

	/*
	 * Once both directions are done the pair is torn down, and closing
	 * its sockets sends the FINs. A shutdown() right before that close
	 * only costs a syscall, provided nothing is left unread on the
	 * socket: close() answers unread data with an RST instead of a FIN.
	 * Here a write side is shut only after the other socket's read side
	 * reached EOF, so when both are done both sockets have been read to
	 * EOF; the test is kept explicit, as in the epoll loop.
	 */
	done = gcp->client.wr_shut && gcp->target.wr_shut;
	if (shut_client && !(done && gcp->client.rd_eof))
		__sys_shutdown(gcp->client.fd, SHUT_WR);
	if (shut_target && !(done && gcp->target.rd_eof))
		__sys_shutdown(gcp->target.fd, SHUT_WR);
	if (done)
		return -ECONNRESET;

	return 0;
}

static int handle_ev_client_recv(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				 struct io_uring_cqe *cqe)
{
	int r = cqe->res;
	uint32_t from;

	if (r < 0) {
		if (r == -EAGAIN || r == -EINTR)
			return prep_recv_client(w, gcp);
		return r;
	}

#ifdef CONFIG_HTTPS
	if (client_is_tls(gcp)) {
		if (r == 0) {
			gcp->client.rd_eof = true;
			return iou_forward_progress(w, gcp);
		}
		gwp_ssl_rx_commit(gcp->client.tls, (size_t)r);
		return tls_forward_pump(w, gcp);
	}
#endif

	if (r == 0) {
		/*
		 * Client closed its write side. Half-close: stop reading it,
		 * propagate the FIN to the target, and keep delivering the
		 * target's response until it too is done.
		 */
		gcp->client.rd_eof = true;
		return iou_forward_progress(w, gcp);
	}

	from = gcp->client.len;
	gcp->client.len += (uint32_t)r;
	if (gwp_http_fwd_active(gcp)) {
		r = gwp_http_fwd_in(w, gcp, &gcp->client, from);
		if (r)
			return r;
	}

	/* An HTTP forwarding filter may have dropped all of it. */
	if (!gcp->client.len)
		return prep_recv_client(w, gcp);
	prep_send_target(w, gcp);
	return 0;
}

static int handle_ev_target_recv(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				 struct io_uring_cqe *cqe)
{
	int r = cqe->res;
	uint32_t from;

	if (r < 0) {
		if (r == -EAGAIN || r == -EINTR) {
			prep_recv_target(w, gcp);
			return 0;
		}
		return r;
	}

	from = gcp->target.len;
	if (r == 0)
		gcp->target.rd_eof = true;
	else
		gcp->target.len += (uint32_t)r;

	if (gwp_http_fwd_active(gcp)) {
		r = gwp_http_fwd_in(w, gcp, &gcp->target, from);
		if (r)
			return r;
	}

	/*
	 * Usually what was read is sent on, but an HTTP forwarding filter may
	 * have held all of it back, and at EOF it may have a reply to deliver.
	 */
	if (gcp->target.len) {
		prep_send_client(w, gcp);
		return 0;
	}
	if (gcp->target.rd_eof)
		return iou_forward_progress(w, gcp);

	prep_recv_target(w, gcp);
	return 0;
}

static int handle_ev_client_send(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				 struct io_uring_cqe *cqe)
{
	int r = cqe->res;

	gcp->client_tx = false;
	r = handle_sock_ret(r);
	if (r < 0)
		return r;

#ifdef CONFIG_HTTPS
	if (client_is_tls(gcp)) {
		struct gwp_iou_tls *t = gcp->tls_io;

		t->tx_sent += (uint32_t)r;
		if (t->tx_sent < t->tx_len) {	/* short send: flush remainder */
			prep_send_client_cipher(w, gcp, EV_BIT_IOU_CLIENT_SEND);
			return 0;
		}
		/*
		 * Ciphertext flushed; encrypt/queue more, else go back to the
		 * protocol pass this reply held up, else read the target.
		 */
		if (gcp->target.len > 0 ||
		    gwp_ssl_bio_pending(gcp->client.tls) > 0) {
			send_client_tls(w, gcp);
		} else if (upstream_start_held(w, gcp)) {
			return upstream_iou_start(w, gcp);
		} else if (t->prot_resume) {
			t->prot_resume = false;
			return tls_prot_pump(w, gcp);
		} else if (gcp->target.rd_eof) {
			return iou_forward_progress(w, gcp);
		} else if (gcp->target.fd >= 0) {
			prep_recv_target(w, gcp);
		}
		return 0;
	}
#endif

	if (r > 0)
		gwp_conn_buf_consume(&gcp->target, (size_t)r);

	/*
	 * A short send leaves unsent bytes in target.buf; flush the remainder
	 * before reading more from the target, otherwise the leftover data is
	 * overwritten by the next recv and the transfer stalls.
	 */
	if (gcp->target.len > 0) {
		prep_send_client(w, gcp);
		return 0;
	}

	/* The reply is out; the upstream handshake may use target.buf now. */
	if (upstream_start_held(w, gcp))
		return upstream_iou_start(w, gcp);

	/*
	 * The target may have finished while this send was in flight: the HTTP
	 * forwarding filter delivers its own reply after the origin's EOF.
	 */
	if (gcp->target.rd_eof)
		return iou_forward_progress(w, gcp);

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
		gwp_conn_buf_consume(&gcp->client, (size_t)r);

	/* Short send: flush the rest before reading more from the client. */
	if (gcp->client.len > 0) {
		prep_send_target(w, gcp);
		return 0;
	}

#ifdef CONFIG_HTTPS
	/* Drain plaintext still buffered in the engine before reading the wire. */
	if (client_is_tls(gcp))
		return tls_forward_pump(w, gcp);
#endif

	return prep_recv_client(w, gcp);
}

/*
 * The ACL rejected this target: queue a client reply (SOCKS5 REP 0x02, or HTTP
 * 403) and return an error so the connection is torn down. The reply send is
 * best-effort (it may be cancelled by the teardown), matching the other
 * io_uring rejection paths.
 */
static int acl_reject_target(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	if (gwp_acl_reject_reply(w, gcp) == -EACCES)
		prep_send_client(w, gcp);

	return -EACCES;
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
			arm_attempt_timer(w, gcp);
			return 0;
		}

		pr_dbg(&w->ctx->lh, "Target %s did not start: %s (idx=%u)",
			ip_to_str(&gcp->target_addr), strerror(-err), gcp->idx);

		if (wait_for_fd(w, gcp, err))
			return 0;

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

	/*
	 * Report the failure instead of just hanging up, so the client learns
	 * the target refused rather than guessing: a SOCKS5 REP (RFC 1928 s6)
	 * or an HTTP 502. Queued before the error return tears the pair down,
	 * as acl_reject_target() does.
	 */
	if (!gwp_conn_fail_reply(w, gcp, err) && gcp->target.len)
		prep_send_client(w, gcp);

	return err;
}

/*
 * The Connection Attempt Delay expired: bring the next candidate into the race
 * alongside the ones already running. Nothing is cancelled here -- an attempt
 * that is merely slow may still win.
 */
static int handle_ev_attempt_timer(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				   int res)
{
	gcp->attempt_timer_armed = false;

	/* Removed by adopt_winning_attempt() or shutdown_gcp(); nothing to do. */
	if (res != -ETIME)
		return 0;

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
 * A lookup is pending; its result arrives on the worker's DNS completion
 * queue (handle_ev_dns_cq()). Hold a reference for it, as an SQE would, so
 * the pair outlives the wait.
 */
static int prep_domain_resolution(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_dns_entry *gde = gcp->gde;
	struct gwp_ctx *ctx = w->ctx;

	assert(gde);
	get_gcp(gcp);
	pr_dbg(&ctx->lh,
		"Queued DNS query for domain '%s' (idx=%u, ref_cnt=%d)",
		gde->name, gcp->idx, gcp->ref_cnt);

	return 0;
}

/* Watch the worker's DNS completion queue; one-shot, re-armed per wakeup. */
static void arm_dns_cq_poll(struct gwp_wrk *w)
{
	struct io_uring_sqe *s = get_sqe_nofail(w);

	io_uring_prep_poll_add(s, gwp_dns_cq_fd(w->ctx->dns, w->idx), POLLIN);
	s->user_data = EV_BIT_IOU_DNS_QUERY;
}

/* Arm the next relay recvmsg into the front-padded scratch buffer. */
static void prep_udp_recv(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_iou_udp *u = gcp->udp_iou;
	struct io_uring_sqe *s = get_sqe_nofail(w);

	u->iov.iov_base = u->buf + GWP_SOCKS5_UDP_HDR_MAX;
	u->iov.iov_len = 65535;
	memset(&u->mh, 0, sizeof(u->mh));
	u->mh.msg_name = &u->src;
	u->mh.msg_namelen = sizeof(u->src);
	u->mh.msg_iov = &u->iov;
	u->mh.msg_iovlen = 1;
	io_uring_prep_recvmsg(s, gcp->udp_fd, &u->mh, 0);
	io_uring_sqe_set_data(s, gcp);
	s->user_data |= EV_BIT_IOU_UDP_RX;
	get_gcp_io(gcp, s);
}

/* Arm a relay sendmsg of @buf[0..len) to @dst (part of the same scratch). */
static void prep_udp_send(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			  unsigned char *buf, size_t len,
			  const struct gwp_sockaddr *dst, socklen_t dstlen)
{
	struct gwp_iou_udp *u = gcp->udp_iou;
	struct io_uring_sqe *s = get_sqe_nofail(w);

	u->dst = *dst;
	u->iov.iov_base = buf;
	u->iov.iov_len = len;
	memset(&u->mh, 0, sizeof(u->mh));
	u->mh.msg_name = &u->dst;
	u->mh.msg_namelen = dstlen;
	u->mh.msg_iov = &u->iov;
	u->mh.msg_iovlen = 1;
	io_uring_prep_sendmsg(s, gcp->udp_fd, &u->mh, MSG_NOSIGNAL);
	io_uring_sqe_set_data(s, gcp);
	s->user_data |= EV_BIT_IOU_UDP_TX;
	get_gcp_io(gcp, s);
}

/*
 * A relay recvmsg completed. Decide direction by source (the same logic as the
 * epoll handle_ev_udp_relay): a datagram from the pinned client is unwrapped
 * and forwarded to its target; one from a target the client has sent to is a
 * reply, wrapped and sent to the client. A forwarded datagram issues one sendmsg
 * and the relay re-arms the recv only once that completes (handle_ev_udp_tx); a
 * dropped datagram re-arms the recv immediately. See the epoll handler for the
 * design limitations.
 */
static int handle_ev_udp_relay(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			       struct io_uring_cqe *cqe)
{
	struct gwp_iou_udp *u = gcp->udp_iou;
	unsigned char *base = u->buf + GWP_SOCKS5_UDP_HDR_MAX;
	int n = cqe->res;
	struct gwp_udp_out out;

	/*
	 * Once teardown has begun, let the ref drop instead of re-arming; a
	 * fresh recv would keep the association alive forever (see the
	 * udp_fd cancel in shutdown_gcp).
	 */
	if (gcp->flags & GWP_CONN_FLAG_IS_CANCEL)
		return -ECANCELED;

	if (n < 0) {
		/* Datagram-level error (e.g. a prior send bounced); keep going. */
		prep_udp_recv(w, gcp);
		return 0;
	}

	if (gwp_udp_relay_classify(w, gcp, base, (size_t)n, &u->src, &out) ==
	    GWP_UDP_DROP) {
		prep_udp_recv(w, gcp);
		return 0;
	}

	prep_udp_send(w, gcp, out.buf, out.len, &out.dst, out.dstlen);
	return 0;
}

/* A relay sendmsg completed; read the next datagram (errors are dropped). */
static int handle_ev_udp_tx(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			    struct io_uring_cqe *cqe)
{
	(void)cqe;
	if (gcp->flags & GWP_CONN_FLAG_IS_CANCEL)
		return -ECANCELED;
	prep_udp_recv(w, gcp);
	return 0;
}

/*
 * The SOCKS5 UDP ASSOCIATE reply has been queued to the client; bring the relay
 * online. The TCP control connection is now idle, so drop its handshake timeout
 * (else it fires and tears the association down) and keep only a recv on it to
 * notice the client closing. Then start relaying datagrams on udp_fd.
 */
static int arm_udp_relay(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	int r;

	gcp->udp_iou = calloc(1, sizeof(*gcp->udp_iou));
	if (unlikely(!gcp->udp_iou))
		return -ENOMEM;

	if (w->ctx->cfg.protocol_timeout > 0) {
		/*
		 * Mark the pair alive before removing the timer so a timeout
		 * that fires in the race window is treated as benign by
		 * handle_ev_timer() (mirrors the TCP connect path).
		 */
		gcp->is_target_alive = true;
		prep_timer_del_target(w, gcp);
	}
	arm_idle_timer(w, gcp);

	r = prep_recv_client_prot(w, gcp);
	if (r)
		return r;
	prep_udp_recv(w, gcp);
	return 0;
}

/*
 * Act on the result of a protocol handler (SOCKS5 or HTTP), mirroring the epoll
 * chk_socks5()/chk_http(): a pending DNS lookup arms a poll; a fully-decoded
 * destination creates and connects the target socket; anything else means the
 * handshake needs more client data.
 */
static int chk_prot_result(struct gwp_wrk *w, struct gwp_conn_pair *gcp, int r)
{
	int ct = gcp->conn_state;

	if (r == -EINPROGRESS &&
	    (ct == CONN_STATE_SOCKS5_DNS_QUERY || ct == CONN_STATE_HTTP_DNS_QUERY))
		return prep_domain_resolution(w, gcp);

	if (r == 0 &&
	    (ct == CONN_STATE_SOCKS5_CONNECT || ct == CONN_STATE_HTTP_CONNECT))
		return do_prep_connect(w, gcp);

	if (r == 0 && ct == CONN_STATE_SOCKS5_UDP_ASSOCIATE)
		return arm_udp_relay(w, gcp);

	/* Handshake incomplete; read more from the client. */
	if (r == 0 || r == -EAGAIN) {
#ifdef CONFIG_HTTPS
		if (tls_prot_more(gcp))
			return tls_prot_pump(w, gcp);
#endif
		return prep_recv_client_prot(w, gcp);
	}

	return r;
}

/*
 * Run the protocol state machine on the (decrypted) client.buf, flush any reply
 * to the client, and decide the next step. Shared by the plaintext and TLS
 * client-prot paths and, for TLS, by the post-handshake kick.
 */
static int process_client_prot(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	int ct = gcp->conn_state, r;

	if (ct == CONN_STATE_PROT)
		r = gwp_handle_conn_state_prot(w, gcp);
	else if (CONN_STATE_HTTP_MIN < ct && ct < CONN_STATE_HTTP_MAX)
		r = gwp_handle_conn_state_http(w, gcp);
	else if (CONN_STATE_SOCKS5_MIN < ct && ct < CONN_STATE_SOCKS5_MAX)
		r = gwp_handle_conn_state_socks5(w, gcp);
	else
		return -EINVAL;

	if (gcp->target.len)
		prep_send_client(w, gcp);

	return chk_prot_result(w, gcp, r);
}

static int handle_ev_client_prot(struct gwp_wrk *w,
				 struct gwp_conn_pair *gcp,
				 struct io_uring_cqe *cqe)
{
	int r = handle_sock_ret(cqe->res);

	if (r < 0)
		return r;
	else if (!r)
		return prep_recv_client_prot(w, gcp);

	/*
	 * Once the UDP association is up the TCP control connection is idle and
	 * only watched for close (r < 0, handled above). Discard any stray
	 * bytes and keep watching.
	 */
	if (gcp->conn_state == CONN_STATE_SOCKS5_UDP_ASSOCIATE) {
		gcp->client.len = 0;
		return prep_recv_client_prot(w, gcp);
	}

#ifdef CONFIG_HTTPS
	if (client_is_tls(gcp)) {
		/* Decrypt the ciphertext chunk, then run the protocol on it. */
		gwp_ssl_rx_commit(gcp->client.tls, (size_t)r);
		return tls_prot_pump(w, gcp);
	}
#endif

	gcp->client.len += (uint32_t)r;
	return process_client_prot(w, gcp);
}

static int handle_ev_dns_query(struct gwp_wrk *w, void *udata)
{
	struct gwp_conn_pair *gcp = udata;
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_dns_entry *gde = gcp->gde;

	if (gde->res) {
		int res = gde->res;

		pr_info(&ctx->lh, "Failed to resolve domain '%s': %d",
			gde->name, res);
		gwp_dns_entry_free(gde);
		gcp->gde = NULL;

		/*
		 * Answer before hanging up; without a reply the client cannot
		 * tell a name that does not resolve from a proxy that died.
		 * SOCKS5 gets a REP (RFC 1928 s6), HTTP a 502. The send is
		 * queued before the error return tears the pair down, exactly
		 * as acl_reject_target() does.
		 */
		if (!gwp_conn_fail_reply(w, gcp, res) && gcp->target.len)
			prep_send_client(w, gcp);
		return res;
	}

	gwp_conn_set_candidates(gcp, gde->addrs, gde->nr_addrs);
	pr_info(&ctx->lh, "Domain '%s' resolved to %s (%u addr, fd=%d, idx=%u)",
		gde->name, ip_to_str(&gcp->target_addr), gcp->nr_cand,
		gcp->target.fd, gcp->idx);

	gwp_dns_entry_free(gde);
	gcp->gde = NULL;
	return do_prep_connect(w, gcp);
}

/*
 * Finished getaddrinfo() lookups of this worker; one wakeup may carry many.
 * Each pair holds a reference for its lookup (prep_domain_resolution()),
 * dropped here once the result is used, exactly as an SQE's completion does.
 */
static int handle_ev_dns_cq(struct gwp_wrk *w)
{
	struct gwp_dns_entry *e, *next;
	int r;

	e = gwp_dns_cq_pop(w->ctx->dns, w->idx);
	for (; e; e = next) {
		struct gwp_conn_pair *gcp = e->udata;

		next = e->next;
		/* Defensive: the pair holds a reference until we put it. */
		if (unlikely(gwp_dns_entry_cancelled(e))) {
			gwp_dns_entry_free(e);
			continue;
		}

		assert(gcp->gde == e);
		if (gcp->flags & GWP_CONN_FLAG_IS_CANCEL) {
			gcp->gde = NULL;
			gwp_dns_entry_free(e);
		} else {
			r = handle_ev_dns_query(w, gcp);
			if (r && !(gcp->flags & GWP_CONN_FLAG_IS_CANCEL))
				shutdown_gcp(w, gcp);
		}
		put_gcp(w, gcp);
	}

	arm_dns_cq_poll(w);
	return 0;
}

static int handle_event(struct gwp_wrk *w, struct io_uring_cqe *cqe)
{
	void *udata = U64_TO_PTR(CLEAR_EV_BIT(cqe->user_data));
	uint64_t ev_bit = GET_EV_BIT(cqe->user_data);
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_conn_pair *gcp;
	uint8_t *nr_ops;
	int r;

	/* I/O on one of the pair's sockets: it is no longer in flight. */
	nr_ops = nr_ops_of(udata, ev_bit);
	if (nr_ops) {
		assert(*nr_ops);
		(*nr_ops)--;
		/* Activity, for --idle-timeout. */
		((struct gwp_conn_pair *)udata)->last_act = w->now;

		/*
		 * The pair is being torn down and its cancels are queued, so
		 * nothing may queue more I/O on it. Its handler would carry on
		 * with the connection regardless: the send of the reply to a
		 * timeout, completing, armed a recv on the upstream socket that
		 * no cancel would ever reach, and that recv's reference kept the
		 * pair and both sockets open for as long as the worker ran.
		 */
		gcp = udata;
		if (gcp->flags & GWP_CONN_FLAG_IS_CANCEL) {
			put_gcp(w, gcp);
			return 0;
		}
	}

	/*
	 * A racing connect carries its attempt slot in the selector, so the
	 * completion is attributable while the conn-pair pointer stays where
	 * the common teardown below expects it. A block of selectors rather
	 * than one value, hence the range test ahead of the switch.
	 */
	if (ev_bit >= EV_BIT_TARGET_ATTEMPT &&
	    ev_bit < EV_BIT_TARGET_ATTEMPT +
		     ((uint64_t)GWP_MAX_CONN_CAND << 48ull)) {
		uint8_t slot = (uint8_t)((ev_bit - EV_BIT_TARGET_ATTEMPT) >> 48ull);

		pr_dbg(&ctx->lh, "Handling target attempt %u event: %d", slot,
			cqe->res);
		r = handle_ev_target_attempt(w, udata, slot, cqe->res);
		goto out;
	}

	switch (ev_bit) {
	case EV_BIT_IOU_ACCEPT:
		pr_dbg(&ctx->lh, "Handling accept event: %d", cqe->res);
		return handle_ev_accept(w, cqe);
	case EV_BIT_IOU_ACCEPT_RETRY:
		pr_dbg(&ctx->lh, "Handling accept retry timer: %d", cqe->res);
		arm_accept(w);
		return 0;
	case EV_BIT_IOU_ATTEMPT_TIMER:
		pr_dbg(&ctx->lh, "Handling attempt timer event: %d", cqe->res);
		r = handle_ev_attempt_timer(w, udata, cqe->res);
		break;
	case EV_BIT_IOU_ATTEMPT_TIMER_DEL:
		pr_dbg(&ctx->lh, "Handling attempt timer delete: %d", cqe->res);
		r = 0;
		break;
	case EV_BIT_IOU_ATTEMPT_CANCEL:
		pr_dbg(&ctx->lh, "Handling attempt cancel event: %d", cqe->res);
		r = 0;
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
	case EV_BIT_IOU_CLIENT_PROT:
		pr_dbg(&ctx->lh, "Handling client protocol event: %d", cqe->res);
		r = handle_ev_client_prot(w, udata, cqe);
		break;
	case EV_BIT_IOU_UDP_RX:
		pr_dbg(&ctx->lh, "Handling UDP relay recv event: %d", cqe->res);
		r = handle_ev_udp_relay(w, udata, cqe);
		break;
	case EV_BIT_IOU_UDP_TX:
		pr_dbg(&ctx->lh, "Handling UDP relay send event: %d", cqe->res);
		r = handle_ev_udp_tx(w, udata, cqe);
		break;
	case EV_BIT_IOU_UDP_CANCEL:
		gcp = udata;
		pr_dbg(&ctx->lh, "Handling UDP relay cancel event: %d", cqe->res);
		assert(gcp->flags & GWP_CONN_FLAG_IS_CANCEL);
		r = 0;
		break;
#ifdef CONFIG_HTTPS
	case EV_BIT_IOU_TLS_DETECT:
		pr_dbg(&ctx->lh, "Handling TLS detect event: %d", cqe->res);
		r = handle_ev_tls_detect(w, udata, cqe);
		break;
	case EV_BIT_IOU_TLS_HS_RECV:
		pr_dbg(&ctx->lh, "Handling TLS handshake recv event: %d", cqe->res);
		r = handle_ev_tls_hs_recv(w, udata, cqe);
		break;
	case EV_BIT_IOU_TLS_HS_SEND:
		pr_dbg(&ctx->lh, "Handling TLS handshake send event: %d", cqe->res);
		r = handle_ev_tls_hs_send(w, udata, cqe);
		break;
#endif
	case EV_BIT_IOU_UPSTREAM_S5:
		pr_dbg(&ctx->lh, "Handling upstream SOCKS5 handshake event: %d", cqe->res);
		r = handle_ev_upstream_s5(w, udata, cqe);
		break;
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
		pr_dbg(&ctx->lh, "Handling DNS completion event: %d", cqe->res);
		return handle_ev_dns_cq(w);
	case EV_BIT_IOU_STOP:
		pr_dbg(&ctx->lh, "Handling stop doorbell: %d", cqe->res);
		return 0;
	case EV_BIT_IOU_CLOSE:
		/*
		 * Closes are queued with IOSQE_CQE_SKIP_SUCCESS, so only a
		 * failure gets here. The descriptor is gone either way (close
		 * releases it even when it reports an error), and nothing
		 * waits on it, so this concerns no connection but its own:
		 * report it and keep serving the others.
		 */
		pr_warn(&ctx->lh, "close(%u) failed: %s",
			(unsigned)CLEAR_EV_BIT(cqe->user_data),
			strerror(-cqe->res));
		return 0;
	default:
		pr_err(&ctx->lh, "Unknown event bit: %" PRIu64 "; res=%d", ev_bit, cqe->res);
		return -EINVAL;
	}

out:
	gcp = udata;
	if (r && !(gcp->flags & GWP_CONN_FLAG_IS_CANCEL))
		shutdown_gcp(w, gcp);

	put_gcp(w, gcp);
	return 0;
}

static int handle_events(struct gwp_wrk *w)
{
	struct iou *iou = w->iou;
	struct io_uring_cqe *cqe;
	unsigned head;
	int r = 0;

	/*
	 * Release each CQE before handling it, so the slots of the ones
	 * handled so far are free while a handler runs. A handler that
	 * finds the SQ full submits from inside this loop, and on kernels
	 * that refuse submission while completions are waiting in the CQ
	 * overflow list, get_sqe_nofail() needs that room to flush them.
	 */
	io_uring_for_each_cqe(&iou->ring, head, cqe) {
		struct io_uring_cqe c = *cqe;

		io_uring_cq_advance(&iou->ring, 1);
		r = handle_event(w, &c);
		if (unlikely(r))
			break;
	}

	return r;
}

/*
 * Submit what is queued and wait for a completion.
 *
 * The submit can fail for want of kernel memory (-EAGAIN, -ENOMEM), or, on
 * older kernels, while completions sit in the CQ overflow list (-EBUSY), as
 * get_sqe_nofail() describes. None of that is a reason to stop the worker,
 * which would stop the proxy and drop every live connection: flush what
 * overflowed into the CQ ring for handle_events() to reap, back off for a
 * millisecond and go round again. The queued SQEs stay in the SQ ring and go
 * out with the next submit.
 */
static int fish_events(struct gwp_wrk *w)
{
	struct iou *iou = w->iou;
	int r;

	r = io_uring_submit_and_wait(&iou->ring, 1);
	w->now = gwp_now_sec();
	if (likely(r >= 0)) {
		iou->submit_stalled = false;
		return 0;
	}

	if (r == -EINTR) {
		pr_info(&w->ctx->lh, "io_uring_submit_and_wait() interrupted");
		return 0;
	}

	if (r == -EAGAIN || r == -ENOMEM || r == -EBUSY) {
		if (!iou->submit_stalled)
			pr_warn(&w->ctx->lh,
				"Worker %u: io_uring_submit_and_wait(): %s; retrying",
				w->idx, strerror(-r));
		iou->submit_stalled = true;
		io_uring_get_events(&iou->ring);
		usleep(1000);
		return 0;
	}

	pr_err(&w->ctx->lh, "io_uring_submit_and_wait(): %s", strerror(-r));
	return r;
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

	io_uring_set_iowait(&w->iou->ring, false);
	arm_stop_poll(w);
	if (ctx->dns)
		arm_dns_cq_poll(w);
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

/*
 * Ask every worker to stop. Each worker is woken through its own eventfd,
 * which its own ring polls (arm_stop_poll()), so no thread ever touches another
 * thread's ring, and the only things done here are an atomic exchange and one
 * write(2) per worker: both async-signal-safe, so sig_handler() can call this.
 *
 * Every exiting worker calls this again, as do gwp_ctx_stop() and
 * gwp_ctx_free_threads(), so ring the doorbells only on the first call. That
 * also keeps a late signal away from the workers once gwp_ctx_free_threads()
 * has started tearing them down: by then the flag is set.
 */
__cold
void gwp_ctx_signal_all_io_uring(struct gwp_ctx *ctx)
{
	static const uint64_t one = 1;
	int i;

	ctx->stop = true;
	if (atomic_exchange(&ctx->stop_signalled, true))
		return;

	for (i = 0; i < ctx->cfg.nr_workers; i++) {
		int fd = ctx->workers[i].iou->stop_efd;
		ssize_t r;

		do {
			r = __sys_write(fd, &one, sizeof(one));
		} while (r == -EINTR);
	}
}

#endif // CONFIG_IO_URING
