#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <gwproxy/gwproxy.h>
#include <gwproxy/common.h>

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

const char *gwp_upstream_dst_str(struct gwp_conn_pair *gcp)
{
	static __thread char buf[300];

	if (gcp->up_dst.ver == GWP_SOCKS5_ATYP_DOMAIN) {
		snprintf(buf, sizeof(buf), "%s:%u", gcp->up_dst.domain.str,
			 ntohs(gcp->up_dst.port));
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
static int build_userpass(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_upstream *up = &w->ctx->upstream;
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

/* Build the SOCKS5 CONNECT request; advance to the CONNECT-reply state. */
static int build_connect(struct gwp_conn_pair *gcp)
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
	return 0;
}

static int s5_parse(struct gwp_wrk *w, struct gwp_conn_pair *gcp, bool *notify)
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
		if (method == 0x02 && ctx->upstream.has_auth) {
			r = build_userpass(w, gcp);
			return r ? r : GWP_UPSTREAM_IO_SEND;
		}

		pr_err(&ctx->lh, "Upstream SOCKS5 proxy selected no acceptable auth method (0x%02x)",
			method);
		*notify = true;
		return -EACCES;
	}
	case CONN_STATE_UPSTREAM_S5_AUTH: {
		uint8_t status;

		r = gwp_socks5_cli_parse_userpass(buf, len, &status);
		if (r)
			return r == -EAGAIN ? GWP_UPSTREAM_IO_RECV : r;

		gwp_conn_buf_advance(&gcp->target, 2);
		if (status != 0x00) {
			pr_err(&ctx->lh, "Upstream SOCKS5 authentication failed (idx=%u)",
				gcp->idx);
			*notify = true;
			return -EACCES;
		}
		r = build_connect(gcp);
		return r ? r : GWP_UPSTREAM_IO_SEND;
	}
	case CONN_STATE_UPSTREAM_S5_CONNECT: {
		uint8_t rep;
		size_t consumed;

		r = gwp_socks5_cli_parse_connect(buf, len, &rep, &consumed);
		if (r)
			return r == -EAGAIN ? GWP_UPSTREAM_IO_RECV : r;

		if (rep != GWP_SOCKS5_REP_SUCCESS) {
			pr_err(&ctx->lh, "Upstream SOCKS5 CONNECT failed (rep=0x%02x, idx=%u, dst=%s)",
				rep, gcp->idx, gwp_upstream_dst_str(gcp));
			*notify = true;
			return -ECONNREFUSED;
		}
		r = gwp_upstream_splice_reply(w, gcp, consumed);
		return r ? r : GWP_UPSTREAM_IO_DONE;
	}
	default:
		return -EINVAL;
	}
}

static int http_parse(struct gwp_wrk *w, struct gwp_conn_pair *gcp, bool *notify)
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
		pr_err(&w->ctx->lh, "Upstream HTTP CONNECT reply header too large (idx=%u, dst=%s)",
			gcp->idx, gwp_upstream_dst_str(gcp));
		*notify = true;
		return -EMSGSIZE;
	}
	if (r)
		return r == -EAGAIN ? GWP_UPSTREAM_IO_RECV : r;

	if (status < 200 || status >= 300) {
		pr_err(&w->ctx->lh, "Upstream HTTP CONNECT failed (status=%d, idx=%u, dst=%s)",
			status, gcp->idx, gwp_upstream_dst_str(gcp));
		*notify = true;
		return -ECONNREFUSED;
	}
	r = gwp_upstream_splice_reply(w, gcp, consumed);
	return r ? r : GWP_UPSTREAM_IO_DONE;
}

int gwp_upstream_fail_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			    int err)
{
	int r;

	gcp->target.len = 0;
	gwp_conn_buf_compact(&gcp->target);

	/*
	 * Only a refused CONNECT says something about the destination. An
	 * upstream that turned down our credentials, or answered something
	 * we cannot use, is a failure of the proxy chain: REP 0x01, not the
	 * 0x02 "not allowed by ruleset" that -EACCES would map to.
	 */
	if (err != -ECONNREFUSED)
		err = -EPROTO;

	r = gwp_conn_fail_reply(w, gcp, err);
	return r ? r : (int)gcp->target.len;
}

int gwp_upstream_hs_on_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			     bool *notify)
{
	bool n = false;
	int r;

	if (gcp->conn_state >= CONN_STATE_UPSTREAM_HTTP_MIN &&
	    gcp->conn_state <= CONN_STATE_UPSTREAM_HTTP_MAX)
		r = http_parse(w, gcp, &n);
	else
		r = s5_parse(w, gcp, &n);

	if (notify)
		*notify = n;
	return r;
}

static int s5_start(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
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
	pr_dbg(&ctx->lh, "Upstream SOCKS5 handshake started (idx=%u, dst=%s)",
		gcp->idx, gwp_upstream_dst_str(gcp));
	return GWP_UPSTREAM_IO_SEND;
}

static int http_start(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_upstream *up = &w->ctx->upstream;
	char authority[300];
	size_t len = 0;
	int r;

	r = gwp_upstream_finalize_dst(w, gcp);
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
	gcp->up_tx = true;
	gcp->up_scan = 0;
	gcp->conn_state = CONN_STATE_UPSTREAM_HTTP_CONNECT;
	pr_dbg(&w->ctx->lh, "Upstream HTTP CONNECT started (idx=%u, dst=%s)",
		gcp->idx, authority);
	return GWP_UPSTREAM_IO_SEND;
}

int gwp_upstream_hs_start(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	if (w->ctx->upstream.type == GWP_UPSTREAM_HTTP)
		return http_start(w, gcp);
	return s5_start(w, gcp);
}
