// SPDX-License-Identifier: GPL-2.0-only
/*
 * http.h - HTTP proxy protocol logic (CONNECT tunneling and forwarding).
 *
 * A self-contained, event-loop- and connection-agnostic module: it consumes
 * client request bytes, classifies the request (CONNECT vs forwarding),
 * enforces "Basic" proxy authentication and rewrites a forwarding request into
 * origin-form. It knows nothing about the connection pair, DNS or connect(2);
 * the caller (gwproxy.c) drives those from the returned decision.
 *
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */
#ifndef GWPROXY__HTTP_H
#define GWPROXY__HTTP_H

#include <stddef.h>
#include <stdbool.h>

struct gwp_auth;
struct gwp_http_conn;

/*
 * The classification returned by gwp_http_conn_process() once (and only once)
 * the request header is complete; NEED_MORE is returned until then.
 */
enum gwp_http_result {
	GWP_HTTP_NEED_MORE = 0,	/* Header incomplete; feed more client bytes. */
	GWP_HTTP_CONNECT,	/* CONNECT tunnel; host/port are set. */
	GWP_HTTP_FORWARD,	/* Forward request; host/port + rewritten req set. */
	GWP_HTTP_NEED_AUTH,	/* Proxy auth required/failed; reply 407. */
	GWP_HTTP_ERR,		/* Malformed or unsupported; tear the conn down. */
};

/* Allocate/free a per-connection HTTP proxy state. */
struct gwp_http_conn *gwp_http_conn_alloc(void);
void gwp_http_conn_free(struct gwp_http_conn *hc);

/* Whether the (already classified) request is a forwarding request. */
bool gwp_http_conn_is_forward(const struct gwp_http_conn *hc);

/**
 * Consume client request bytes and, once the header is complete, classify the
 * request.
 *
 * @hc		Per-connection state.
 * @auth	Credential store, or NULL to disable authentication.
 * @in		Client bytes to parse.
 * @in_len	In: number of bytes in @in. Out: number of bytes consumed.
 * @host_p	Out (CONNECT/FORWARD): target host, NUL-terminated, owned by @hc
 *		and valid until the next call or gwp_http_conn_free().
 * @port_p	Out (CONNECT/FORWARD): target port string, same lifetime.
 * @req_p	Out (FORWARD): the rewritten origin-form request header to send
 *		to the origin, owned by @hc.
 * @req_len_p	Out (FORWARD): length of *@req_p.
 * @return	One of enum gwp_http_result.
 */
int gwp_http_conn_process(struct gwp_http_conn *hc, struct gwp_auth *auth,
			  const void *in, size_t *in_len,
			  char **host_p, char **port_p,
			  const char **req_p, size_t *req_len_p);

/**
 * Build the client-bound reply written once the target is connected:
 * "HTTP/1.1 200 OK" for a CONNECT tunnel, nothing for a forwarding request.
 *
 * @return	Number of bytes written to @out (0 for a forwarding request),
 *		or -ENOBUFS if @out_cap is too small.
 */
int gwp_http_build_connect_reply(const struct gwp_http_conn *hc, void *out,
				 size_t out_cap);

/**
 * Build the "407 Proxy Authentication Required" reply.
 *
 * @return	Number of bytes written to @out, or -ENOBUFS if too small.
 */
int gwp_http_build_auth_required_reply(void *out, size_t out_cap);

#endif /* #ifndef GWPROXY__HTTP_H */
