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
#include <stdint.h>

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

/**
 * Build an upstream "CONNECT <authority> HTTP/1.1" request (used when chaining
 * through an upstream HTTP proxy), with an optional Basic Proxy-Authorization
 * header. @authority is a "host:port" or "[ipv6]:port" string.
 *
 * @return	0 with *out_len set on success, -ENOBUFS if @out_cap is too
 *		small, or -EINVAL on a formatting error.
 */
int gwp_http_cli_build_connect(const char *authority, const char *user,
			       uint8_t ulen, const char *pass, uint8_t plen,
			       void *out, size_t out_cap, size_t *out_len);

/**
 * Parse an upstream HTTP CONNECT reply.
 *
 * @return	0 with *status (HTTP code) and *consumed (bytes through the
 *		"\r\n\r\n") set once the header block has arrived; -EAGAIN if
 *		more data is needed; -EINVAL on a malformed status line.
 */
int gwp_http_cli_parse_connect_reply(const void *buf, size_t len, int *status,
				     size_t *consumed);

#endif /* #ifndef GWPROXY__HTTP_H */
