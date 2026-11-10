#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <gwproxy/gwproxy.h>
#include <gwproxy/common.h>
#include <gwproxy/upstream.h>
#ifdef CONFIG_HTTPS
#include <gwproxy/ssl.h>
#endif

/*
 * Upstream proxy chaining: the SOCKS5/HTTP CONNECT handshake this proxy speaks
 * to an upstream proxy is the same logic in both event loops; only the send and
 * recv primitives differ. This file holds the transport-agnostic half so it
 * lives once. It references no io_uring symbols and is compiled into every
 * build (part of the base GWPROXY_CC_SOURCES).
 *
 * The request builders fill gcp->target.buf and set gcp->conn_state / up_tx;
 * the parser interprets the proxy's reply. Neither performs I/O: they return a
 * gwp_upstream_io step (arm a send / recv, or the tunnel is up) and each loop
 * issues the actual send/recv with its own primitive.
 */

/* The class of a handshake failure, as its log line names it. */
static const char *fail_class(enum gwp_upstream_end end, int val)
{
	return gwp_upstream_fail_class_str(gwp_upstream_fail_classify(end, val));
}

/*
 * While the reply to a CONNECT is awaited, target.cap leaves this much of the
 * buffer unused. gwp_upstream_splice_reply() puts the client's reply where the
 * upstream's was, and it can be the longer of the two: with no room held back,
 * a first read that fills the buffer with the upstream's reply and the
 * destination's early data would leave it nowhere to go. Plain forwarding owes
 * no reply, so it holds nothing back.
 */
static uint32_t client_reply_room(const struct gwp_conn_pair *gcp)
{
	if (gcp->prot_type == GWP_PROT_TYPE_NONE)
		return 0;
	return GWP_UPSTREAM_CLIENT_REPLY_MAX;
}

const char *gwp_upstream_dst_str(struct gwp_conn_pair *gcp)
{
	static __thread char buf[300];

	if (gcp->up_dst.ver == GWP_SOCKS5_ATYP_DOMAIN) {
		snprintf(buf, sizeof(buf), "%s:%u", gcp->up_dst.domain.str,
			 ntohs(gcp->up_dst.port));
		return buf;
	}

	/* What a UDP ASSOCIATE names: where its datagrams come from. */
	if ((gcp->flags & GWP_CONN_FLAG_UDP_UP) && gcp->up_dst.ver) {
		char ip[INET6_ADDRSTRLEN];
		bool v4 = gcp->up_dst.ver == GWP_SOCKS5_ATYP_IPV4;

		inet_ntop(v4 ? AF_INET : AF_INET6, gcp->up_dst.ip6, ip,
			  sizeof(ip));
		snprintf(buf, sizeof(buf), v4 ? "udp from %s:%u" :
			 "udp from [%s]:%u", ip, ntohs(gcp->up_dst.port));
		return buf;
	}

	return ip_to_str(&gcp->target_addr);
}

int gwp_upstream_splice_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			      size_t consumed)
{
	uint8_t rbuf[512];
	size_t rlen = 0;
	int r;

	gcp->target.cap += client_reply_room(gcp);

	/* Build the downstream reply for the client (before any early data). */
	if (gcp->prot_type == GWP_PROT_TYPE_SOCKS5) {
		rlen = sizeof(rbuf);
		r = gwp_socks5_build_connect_reply(w, gcp, 0, rbuf, &rlen);
		if (unlikely(r))
			return r;
	} else if (gcp->prot_type == GWP_PROT_TYPE_HTTP) {
		r = gwp_http_build_connect_reply(gcp->http_conn, rbuf,
						 sizeof(rbuf));
		if (unlikely(r < 0))
			return r;
		rlen = (size_t)r;
	}

	/* Drop the proxy's CONNECT reply, keep any early destination data. */
	gwp_conn_buf_advance(&gcp->target, consumed);

	if (rlen) {
		if (gcp->target.len + rlen > gcp->target.cap)
			return -ENOBUFS;
		memmove(gcp->target.buf + rlen, gcp->target.buf,
			gcp->target.len);
		memcpy(gcp->target.buf, rbuf, rlen);
		gcp->target.len += rlen;
	}
	return 0;
}

/* Build the SOCKS5 user/pass auth request; advance to the AUTH-reply state. */
static int build_userpass(struct gwp_conn_pair *gcp)
{
	struct gwp_upstream *up = gcp->upstream;
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
	return 0;
}

/*
 * Build the SOCKS5 CONNECT request, or the UDP ASSOCIATE of a UDP association
 * through the upstream; advance to the state that awaits its reply.
 */
static int build_connect(struct gwp_conn_pair *gcp)
{
	size_t len = gcp->target.cap;
	int r;

	gcp->target.len = 0;
	if (gcp->flags & GWP_CONN_FLAG_UDP_UP)
		r = gwp_socks5_cli_build_udp_associate(&gcp->up_dst,
						       gcp->target.buf, &len);
	else
		r = gwp_socks5_cli_build_connect(&gcp->up_dst, gcp->target.buf,
						 &len);
	if (unlikely(r))
		return r;

	gcp->target.len = (uint32_t)len;
	gcp->target.cap -= client_reply_room(gcp);
	gcp->up_tx = true;
	gcp->conn_state = CONN_STATE_UPSTREAM_S5_CONNECT;
	return 0;
}

/*
 * The error a non-zero SOCKS5 CONNECT REP from the upstream fails the attempt
 * with. The destination's own failures, 0x03 to 0x06, keep their meaning: a
 * SOCKS5 client gets the same REP back from the errno (an HTTP client a 502,
 * or a 504 for the TTL expiry). The rest (0x01 and 0x02, which may be the
 * upstream's own trouble or policy, 0x07 and 0x08, which are about our
 * request, and anything unassigned) say nothing about the destination: the
 * chain failed, REP 0x01.
 */
static int s5_rep_err(uint8_t rep)
{
	switch (rep) {
	case 0x03:
		return -ENETUNREACH;
	case 0x04:
		return -EHOSTUNREACH;
	case 0x05:
		return -ECONNREFUSED;
	case 0x06:
		return -ETIMEDOUT;
	default:
		return -EPROTO;
	}
}

/*
 * The reply to the UDP ASSOCIATE of a UDP association through the upstream.
 * A refusal fails it as a refused CONNECT would, with the same answer to the
 * client; gwp_conn_upstream_failed() neither counts it against the server,
 * which may serve TCP well, nor leaves it without its retry. Once granted,
 * the client gets its own reply, and whatever followed the server's on the
 * control connection is dropped: nothing more is to come on it.
 */
static int s5_parse_udp(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_socks5_addr bnd;
	size_t consumed;
	uint8_t rep;
	int r;

	r = gwp_socks5_cli_parse_reply(gcp->target.buf, gcp->target.len, &rep,
				       &bnd, &consumed);
	if (r)
		return r == -EAGAIN ? GWP_UPSTREAM_IO_RECV : r;

	if (rep != GWP_SOCKS5_REP_SUCCESS) {
		pr_err(&w->ctx->lh, "Upstream SOCKS5 UDP ASSOCIATE failed (rep=0x%02x, class=%s, idx=%u, up=%s)",
			rep, gwp_upstream_fail_class_str(GWP_UPSTREAM_FAIL_NEUTRAL),
			gcp->idx, ip_to_str(&gcp->upstream->addr));
		gwp_upstream_note_end(gcp, GWP_UPSTREAM_END_S5_REP, rep);
		return s5_rep_err(rep);
	}

	gcp->target.cap += client_reply_room(gcp);
	r = gwp_upstream_udp_ready(w, gcp, &bnd);
	return r ? r : GWP_UPSTREAM_IO_DONE;
}

static int s5_parse(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
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
			return r == -EAGAIN ? GWP_UPSTREAM_IO_RECV : r;

		gwp_conn_buf_advance(&gcp->target, 2);
		if (method == 0x00) {
			r = build_connect(gcp);
			return r ? r : GWP_UPSTREAM_IO_SEND;
		}
		if (method == 0x02 && gcp->upstream->has_auth) {
			r = build_userpass(gcp);
			return r ? r : GWP_UPSTREAM_IO_SEND;
		}

		pr_err(&ctx->lh, "Upstream SOCKS5 proxy selected no acceptable auth method (0x%02x, class=%s)",
			method, fail_class(GWP_UPSTREAM_END_S5_METHOD, method));
		gwp_upstream_note_end(gcp, GWP_UPSTREAM_END_S5_METHOD, method);
		return -EACCES;
	}
	case CONN_STATE_UPSTREAM_S5_AUTH: {
		uint8_t status;

		r = gwp_socks5_cli_parse_userpass(buf, len, &status);
		if (r)
			return r == -EAGAIN ? GWP_UPSTREAM_IO_RECV : r;

		gwp_conn_buf_advance(&gcp->target, 2);
		if (status != 0x00) {
			pr_err(&ctx->lh, "Upstream SOCKS5 authentication failed (status=0x%02x, class=%s, idx=%u)",
				status, fail_class(GWP_UPSTREAM_END_S5_AUTH, status),
				gcp->idx);
			gwp_upstream_note_end(gcp, GWP_UPSTREAM_END_S5_AUTH,
					      status);
			return -EACCES;
		}
		r = build_connect(gcp);
		return r ? r : GWP_UPSTREAM_IO_SEND;
	}
	case CONN_STATE_UPSTREAM_S5_CONNECT: {
		uint8_t rep;
		size_t consumed;

		if (gcp->flags & GWP_CONN_FLAG_UDP_UP)
			return s5_parse_udp(w, gcp);

		r = gwp_socks5_cli_parse_connect(buf, len, &rep, &consumed);
		if (r)
			return r == -EAGAIN ? GWP_UPSTREAM_IO_RECV : r;

		if (rep != GWP_SOCKS5_REP_SUCCESS) {
			pr_err(&ctx->lh, "Upstream SOCKS5 CONNECT failed (rep=0x%02x, class=%s, idx=%u, dst=%s)",
				rep, fail_class(GWP_UPSTREAM_END_S5_REP, rep),
				gcp->idx, gwp_upstream_dst_str(gcp));
			gwp_upstream_note_end(gcp, GWP_UPSTREAM_END_S5_REP, rep);
			return s5_rep_err(rep);
		}
		r = gwp_upstream_splice_reply(w, gcp, consumed);
		return r ? r : GWP_UPSTREAM_IO_DONE;
	}
	default:
		return -EINVAL;
	}
}

static int http_parse(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	size_t consumed, scan = gcp->up_scan;
	int status, r;

	r = gwp_http_cli_parse_connect_reply(gcp->target.buf, gcp->target.len,
					     &scan, &status, &consumed);
	gcp->up_scan = (uint32_t)scan;
	/*
	 * A reply header that fills the buffer without ending never will:
	 * there is no room left to receive the rest. Waiting for it only
	 * holds the client until the connect timeout, so fail it now.
	 */
	if (r == -EAGAIN && gcp->target.len >= gcp->target.cap) {
		pr_err(&w->ctx->lh, "Upstream HTTP CONNECT reply header too large (class=%s, idx=%u, dst=%s)",
			fail_class(GWP_UPSTREAM_END_MALFORMED, 0), gcp->idx,
			gwp_upstream_dst_str(gcp));
		gwp_upstream_note_end(gcp, GWP_UPSTREAM_END_MALFORMED, 0);
		return -EMSGSIZE;
	}
	if (r)
		return r == -EAGAIN ? GWP_UPSTREAM_IO_RECV : r;

	if (status < 200 || status >= 300) {
		pr_err(&w->ctx->lh, "Upstream HTTP CONNECT failed (status=%d, class=%s, idx=%u, dst=%s)",
			status, fail_class(GWP_UPSTREAM_END_HTTP, status),
			gcp->idx, gwp_upstream_dst_str(gcp));
		gwp_upstream_note_end(gcp, GWP_UPSTREAM_END_HTTP, status);
		/*
		 * Only a 502 or 504 says the destination could not be
		 * reached: that is the refused CONNECT a SOCKS5 client hears
		 * as REP 0x05. A 407 turned our credentials down, and a 403,
		 * 500, 503 or any other status says nothing about the
		 * destination: a failure of the chain, REP 0x01.
		 */
		if (gwp_upstream_http_class(status) ==
		    GWP_UPSTREAM_FAIL_DESTINATION)
			return -ECONNREFUSED;
		return -EPROTO;
	}
	r = gwp_upstream_splice_reply(w, gcp, consumed);
	return r ? r : GWP_UPSTREAM_IO_DONE;
}

int gwp_upstream_fail_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			    int err)
{
	int r;

	/*
	 * Answered already: the failure came back up through a second
	 * caller (upstream_start() inside the TLS step, say). What is left
	 * of that answer is still to be sent; nothing is added.
	 */
	if (gcp->flags & GWP_CONN_FLAG_FAIL_REPLIED)
		return 0;

	gcp->target.len = 0;
	gwp_conn_buf_compact(&gcp->target);

	/*
	 * Only a CONNECT the upstream says failed at the destination (SOCKS5
	 * REP 0x03 to 0x06, HTTP 502 or 504) says something about it, and
	 * its error (s5_rep_err(), http_parse()) goes on to the client. An
	 * upstream that turned down our credentials (SOCKS5 auth, HTTP 407),
	 * or answered something we cannot use, or hung up, is a failure of
	 * the proxy chain: REP 0x01, not the 0x02 "not allowed by ruleset"
	 * that -EACCES would map to, nor whatever an errno of the upstream's
	 * own socket would.
	 */
	if (!gwp_upstream_dst_failed(gcp))
		err = -EPROTO;

	r = gwp_conn_fail_reply(w, gcp, err);
	return r ? r : (int)gcp->target.len;
}

int gwp_upstream_hs_on_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	int r;

	if (gcp->conn_state >= CONN_STATE_UPSTREAM_HTTP_MIN &&
	    gcp->conn_state <= CONN_STATE_UPSTREAM_HTTP_MAX)
		r = http_parse(w, gcp);
	else
		r = s5_parse(w, gcp);

	if (r == -EINVAL) {
		pr_err(&w->ctx->lh, "Upstream proxy sent a malformed reply (class=%s, idx=%u, dst=%s)",
			fail_class(GWP_UPSTREAM_END_MALFORMED, 0), gcp->idx,
			gwp_upstream_dst_str(gcp));
		gwp_upstream_note_end(gcp, GWP_UPSTREAM_END_MALFORMED, 0);
	}
	return r;
}

static int s5_start(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	size_t len = gcp->target.cap;
	int r;

	/* Anew for each server: it is where the datagrams come from. */
	if (gcp->flags & GWP_CONN_FLAG_UDP_UP)
		r = gwp_upstream_udp_dst(w, gcp);
	else
		r = gwp_upstream_finalize_dst(gcp);
	if (unlikely(r)) {
		pr_err(&ctx->lh, "Failed to prepare upstream destination (idx=%u): %s",
			gcp->idx, strerror(-r));
		return r;
	}

	r = gwp_socks5_cli_build_greeting(gcp->upstream->has_auth,
					  gcp->target.buf, &len);
	if (unlikely(r))
		return r;

	gcp->target.len = (uint32_t)len;
	gcp->up_tx = true;
	gcp->conn_state = CONN_STATE_UPSTREAM_S5_METHOD;
	pr_dbg(&ctx->lh, "Upstream SOCKS5 handshake started (idx=%u, dst=%s)",
		gcp->idx, gwp_upstream_dst_str(gcp));
	return GWP_UPSTREAM_IO_SEND;
}

static int http_start(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_upstream *up = gcp->upstream;
	char authority[300];
	size_t len = 0;
	int r;

	r = gwp_upstream_finalize_dst(gcp);
	if (unlikely(r)) {
		pr_err(&w->ctx->lh, "Failed to prepare upstream destination (idx=%u): %s",
			gcp->idx, strerror(-r));
		return r;
	}

	r = gwp_upstream_authority(&gcp->up_dst, authority, sizeof(authority));
	if (unlikely(r))
		return r;

	r = gwp_http_cli_build_connect(authority,
				       up->has_auth ? up->user : NULL, up->ulen,
				       up->pass, up->plen, gcp->target.buf,
				       gcp->target.cap, &len);
	if (unlikely(r))
		return r;

	gcp->target.len = (uint32_t)len;
	gcp->target.cap -= client_reply_room(gcp);
	gcp->up_tx = true;
	gcp->up_scan = 0;
	gcp->conn_state = CONN_STATE_UPSTREAM_HTTP_CONNECT;
	pr_dbg(&w->ctx->lh, "Upstream HTTP CONNECT started (idx=%u, dst=%s)",
		gcp->idx, authority);
	return GWP_UPSTREAM_IO_SEND;
}

void gwp_upstream_hs_reset(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			   int state)
{
	if (gwp_in_upstream_hs(gcp))
		gcp->target.len = 0;
	gwp_conn_buf_compact(&gcp->target);
	/*
	 * The whole buffer again, as before the handshake: build_connect()
	 * and http_start() held the client's reply room back, and
	 * gwp_upstream_splice_reply() may or may not have given it back
	 * before it failed, so set it rather than add to it.
	 */
	gcp->target.cap = (uint32_t)w->ctx->cfg.target_buf_size;
	gcp->target.rd_eof = false;
	gcp->target.wr_shut = false;
#ifdef CONFIG_HTTPS
	if (gcp->target.tls) {
		gwp_ssl_free(gcp->target.tls);
		gcp->target.tls = NULL;
	}
#endif
	gcp->up_tx = false;
	gcp->up_scan = 0;
	gcp->conn_state = state;
}

int gwp_upstream_hs_start(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	if (gcp->upstream->type == GWP_UPSTREAM_HTTP)
		return http_start(w, gcp);
	return s5_start(w, gcp);
}

#ifdef CONFIG_HTTPS
int gwp_upstream_tls_start(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_upstream *up = gcp->upstream;
	struct gwp_ssl *s;

	s = gwp_ssl_client_new(w->ctx->up_ssl_ctx);
	if (unlikely(!s))
		return -ENOMEM;

	/* Tried when the server was made, at startup or as its pool loaded. */
	if (unlikely(gwp_ssl_set_peer_name(s, up->host, up->host_is_ip))) {
		gwp_ssl_free(s);
		return -ENOMEM;
	}

	gcp->target.tls = s;
	gcp->conn_state = CONN_STATE_UPSTREAM_TLS_HS;
	pr_dbg(&w->ctx->lh, "Upstream TLS handshake started (idx=%u, host=%s)",
		gcp->idx, up->host);
	return 0;
}

void gwp_upstream_tls_fail(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_upstream *up = gcp->upstream;
	const char *why = gwp_ssl_verify_errstr(gcp->target.tls);

	pr_err(&w->ctx->lh, "Upstream TLS handshake failed (class=%s, idx=%u, host=%s, up=%s): %s%s",
		fail_class(GWP_UPSTREAM_END_TLS, 0), gcp->idx, up->host,
		ip_to_str(&up->addr), why ? "certificate verify failed: " : "",
		why ? why : gwp_ssl_errstr());
	gwp_upstream_note_end(gcp, GWP_UPSTREAM_END_TLS, 0);
}

void gwp_upstream_tls_rx_fail(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_upstream *up = gcp->upstream;

	pr_err(&w->ctx->lh, "Upstream TLS failed before the CONNECT reply (class=%s, idx=%u, host=%s, up=%s): %s",
		fail_class(GWP_UPSTREAM_END_TLS, 0), gcp->idx, up->host,
		ip_to_str(&up->addr), gwp_ssl_errstr());
	gwp_upstream_note_end(gcp, GWP_UPSTREAM_END_TLS, 0);
}

bool gwp_upstream_tls_cut(struct gwp_conn_pair *gcp)
{
	if (!gcp->target.tls)
		return false;
	if (gwp_http_fwd_active(gcp) &&
	    gwp_http_fwd_res_state(gcp->http_conn) == GWP_HTTP_RES_FAILED)
		return false;
	return gwp_ssl_rx_cut(gcp->target.tls);
}
#endif /* CONFIG_HTTPS */
