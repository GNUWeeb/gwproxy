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
	GWP_HTTP_FORWARD,	/* Forward request; host/port set, the request
				 * rewritten in place. */
	GWP_HTTP_NEED_AUTH,	/* Proxy auth required/failed; reply 407. */
	GWP_HTTP_ERR,		/* Malformed or unsupported; tear the conn down. */
	GWP_HTTP_BAD_REQUEST,	/* Well-formed but unacceptable (e.g. a field
				 * that may appear once is repeated); reply
				 * 400. */
	GWP_HTTP_TOO_LARGE,	/* Header too long or too many fields; 431. */
};

/* Allocate/free a per-connection HTTP proxy state. */
struct gwp_http_conn *gwp_http_conn_alloc(void);
void gwp_http_conn_free(struct gwp_http_conn *hc);

/* Whether the (already classified) request is a forwarding request. */
bool gwp_http_conn_is_forward(const struct gwp_http_conn *hc);

/*
 * The authenticated username (Basic proxy auth), or NULL if the request was not
 * authenticated. Valid until gwp_http_conn_free(); used for ACL "-m user".
 */
const char *gwp_http_conn_username(const struct gwp_http_conn *hc);

/*
 * After GWP_HTTP_NEED_AUTH: whether the request carried Proxy-Authorization,
 * that is, whether a login failed rather than credentials being asked for.
 * If so, *@user and *@len give the username it tried (any bytes, not
 * NUL-terminated, at most 255), *@user being NULL if the credentials did not
 * decode. Valid until gwp_http_conn_free().
 */
bool gwp_http_conn_auth_failed(const struct gwp_http_conn *hc,
			       const char **user, size_t *len);

/**
 * Parse the client's request header and, once it is complete, classify the
 * request; a forwarding request is rewritten in place.
 *
 * @hc		Per-connection state.
 * @auth	Credential store, or NULL to disable authentication.
 * @buf		The client's bytes, the request from its first byte. While the
 *		header is incomplete nothing is consumed, and the next call
 *		passes the same bytes again with more behind them (the parsed
 *		part is not copied, so it must be left unchanged).
 * @buf_len	In: number of bytes in @buf. Out (FORWARD): the number after
 *		the rewrite; otherwise unchanged.
 * @cap		Room in @buf, for the rewrite of a forwarding request.
 * @host_p	Out (CONNECT/FORWARD): target host, NUL-terminated, owned by @hc
 *		and valid until gwp_http_conn_free().
 * @port_p	Out (CONNECT/FORWARD): target port string, same lifetime.
 * @hdr_len_p	Out: 0 while the header is incomplete. FORWARD: the length of
 *		the origin-form request header that now starts @buf, to send to
 *		the origin, any body bytes already received following it.
 *		Otherwise: the length of the request header, to be dropped.
 * @return	One of enum gwp_http_result.
 */
int gwp_http_conn_process(struct gwp_http_conn *hc, struct gwp_auth *auth,
			  void *buf, size_t *buf_len, size_t cap,
			  char **host_p, char **port_p, size_t *hdr_len_p);

/**
 * Delimit the body of a forwarding request. Called with each run of client
 * bytes that follows the request header; returns in *@fwd_len how many of the
 * @len bytes at @in still belong to the request and go to the origin. The
 * rest, and everything after it, is not part of the request: this proxy
 * serves one request per connection, and whatever the client sends next is
 * meant for a server it has not been checked against.
 *
 * @return	0, or -EBADMSG for a malformed chunked body.
 */
int gwp_http_fwd_req_body(struct gwp_http_conn *hc, const void *in,
			  size_t len, size_t *fwd_len);

/*
 * Where the response to a forwarding request stands (gwp_http_fwd_res_state()).
 */
enum gwp_http_res_state {
	GWP_HTTP_RES_NONE = 0,	/* Not forwarding yet. */
	GWP_HTTP_RES_HDR,	/* Header still being collected. */
	GWP_HTTP_RES_BODY,	/* Header passed on; the rest is relayed as is. */
	GWP_HTTP_RES_FAILED,	/* Unusable; the client got a 502 instead. */
};

/**
 * Prepare to receive the origin's response to a forwarding request. Its
 * header, interim ones included, may take at most @max_hdr bytes.
 *
 * @return	0, or -ENOMEM.
 */
int gwp_http_fwd_res_init(struct gwp_http_conn *hc, size_t max_hdr);

/* One of enum gwp_http_res_state. */
int gwp_http_fwd_res_state(const struct gwp_http_conn *hc);

/* Origin bytes held back while the response header is incomplete. */
size_t gwp_http_fwd_res_pending(const struct gwp_http_conn *hc);

/**
 * Consume origin bytes while the response header is being collected
 * (GWP_HTTP_RES_HDR). Nothing is released until a header is complete; then it
 * is written to @out rewritten for the client: hop-by-hop fields and fields
 * named by Connection are dropped and a final response gains "Connection:
 * close". An interim (1xx) response is passed on the same way and the next
 * header awaited; after the final header, any body bytes that arrived with it
 * follow it in @out and the state moves to GWP_HTTP_RES_BODY.
 *
 * @hc		Per-connection state.
 * @in		Origin bytes; may alias @out (they are taken before @out is
 *		written).
 * @len		Number of bytes in @in.
 * @eof		The origin has closed; an incomplete header is an error.
 * @out		Where the bytes for the client go.
 * @out_cap	Capacity of @out.
 * @out_len	Out: number of bytes written to @out.
 * @return	0; or, with the state moved to GWP_HTTP_RES_FAILED and nothing
 *		written, a negative error the caller answers with 502:
 *		-EBADMSG (not a valid HTTP/1.x header, a 101, or the origin
 *		closed early), -E2BIG (header too large, or more than 256
 *		field lines or 32 Connection options), -EACCES (the origin
 *		answered 407), -ENOMEM.
 */
int gwp_http_fwd_res_input(struct gwp_http_conn *hc, const void *in,
			   size_t len, bool eof, void *out, size_t out_cap,
			   size_t *out_len);

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
 * Build a "400 Bad Request" reply, for a request the forwarding proxy refuses
 * to relay because the origin could frame it differently (see
 * GWP_HTTP_BAD_REQUEST).
 *
 * @return	Number of bytes written to @out, or -ENOBUFS if too small.
 */
int gwp_http_build_bad_request_reply(void *out, size_t out_cap);

/**
 * Build a "403 Forbidden" reply (used when an ACL rejects the target).
 *
 * @return	Number of bytes written to @out, or -ENOBUFS if too small.
 */
int gwp_http_build_forbidden_reply(void *out, size_t out_cap);

/**
 * Build a "502 Bad Gateway" reply, for when the origin could not be reached
 * at all (the connect was refused, or its name did not resolve).
 *
 * @return	Number of bytes written to @out, or -ENOBUFS if too small.
 */
int gwp_http_build_bad_gateway_reply(void *out, size_t out_cap);

/**
 * Build a "504 Gateway Timeout" reply, for when the connection to the origin
 * did not complete within --connect-timeout.
 *
 * @return	Number of bytes written to @out, or -ENOBUFS if too small.
 */
int gwp_http_build_gateway_timeout_reply(void *out, size_t out_cap);

/**
 * Build a "431 Request Header Fields Too Large" reply (RFC 6585 Section 5),
 * for a request header that does not fit in the client buffer or has too
 * many fields (GWP_HTTP_TOO_LARGE).
 *
 * @return	Number of bytes written to @out, or -ENOBUFS if too small.
 */
int gwp_http_build_too_large_reply(void *out, size_t out_cap);

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
 * Parse an upstream HTTP CONNECT reply, the @len bytes of it received so far
 * at @buf. *@scan is where the search for the end of its header resumes: 0
 * for a new reply, then left as the call leaves it, so that a reply received
 * in pieces is not searched from its start each time.
 *
 * @return	0 with *status (HTTP code) and *consumed (bytes through the
 *		blank line, CRLF or LF) set once the header block has arrived;
 *		-EAGAIN if more data is needed; -EINVAL on a malformed status
 *		line (not "HTTP/1.0" or "HTTP/1.1" SP 3DIGIT).
 */
int gwp_http_cli_parse_connect_reply(const void *buf, size_t len,
				     size_t *scan, int *status,
				     size_t *consumed);

#endif /* #ifndef GWPROXY__HTTP_H */
