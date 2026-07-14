// SPDX-License-Identifier: GPL-2.0-only
/*
 * http.c - HTTP proxy protocol logic (CONNECT tunneling and forwarding).
 *
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

#include "http.h"
#include "http1.h"
#include "auth.h"

struct gwp_http_conn {
	struct gwnet_http_hdr_pctx	ctx_hdr;
	struct gwnet_http_req_hdr	req_hdr;

	/*
	 * True for a forwarding request (absolute-form target, e.g.
	 * "GET http://host/path") as opposed to a CONNECT tunnel.
	 */
	bool				is_forward;

	/* Rewritten origin-form request header for a forwarding request. */
	char				*fwd_req;
	size_t				fwd_req_len;
};

struct gwp_http_conn *gwp_http_conn_alloc(void)
{
	struct gwp_http_conn *hc = calloc(1, sizeof(*hc));

	if (!hc)
		return NULL;

	if (gwnet_http_hdr_pctx_init(&hc->ctx_hdr) < 0) {
		free(hc);
		return NULL;
	}

	return hc;
}

void gwp_http_conn_free(struct gwp_http_conn *hc)
{
	if (!hc)
		return;

	gwnet_http_hdr_pctx_free(&hc->ctx_hdr);
	gwnet_http_req_hdr_free(&hc->req_hdr);
	free(hc->fwd_req);
	free(hc);
}

bool gwp_http_conn_is_forward(const struct gwp_http_conn *hc)
{
	return hc->is_forward;
}

/*
 * Map a parsed HTTP method code back to its request-line token. Returns NULL
 * for a method the forwarding proxy does not re-emit.
 */
static const char *http_method_str(uint8_t method)
{
	switch (method) {
	case GWNET_HTTP_METHOD_GET:	return "GET";
	case GWNET_HTTP_METHOD_POST:	return "POST";
	case GWNET_HTTP_METHOD_PUT:	return "PUT";
	case GWNET_HTTP_METHOD_DELETE:	return "DELETE";
	case GWNET_HTTP_METHOD_HEAD:	return "HEAD";
	case GWNET_HTTP_METHOD_OPTIONS:	return "OPTIONS";
	case GWNET_HTTP_METHOD_PATCH:	return "PATCH";
	case GWNET_HTTP_METHOD_TRACE:	return "TRACE";
	default:			return NULL;
	}
}

/*
 * Split a "host:port" authority (a CONNECT target, or the authority of an
 * absolute-form URI) into NUL-terminated @host_p/@port_p in place. IPv6
 * literals in brackets ("[::1]:80") are unwrapped. With no ":port",
 * @default_port is used; pass NULL to require an explicit port. Returns 0 on
 * success or -EINVAL on a malformed authority.
 */
static int split_authority(char *authority, char **host_p, char **port_p,
			   char *default_port)
{
	char *host = authority, *colon = NULL, *end;

	if (!*authority)
		return -EINVAL;

	if (*host == '[') {
		char *rb = strchr(host, ']');

		if (!rb || rb == host + 1)
			return -EINVAL;
		host++;			/* skip '[' */
		*rb = '\0';		/* terminate the host */
		end = rb + 1;
		if (*end == ':')
			colon = end;
		else if (*end != '\0')
			return -EINVAL;
	} else {
		colon = strrchr(host, ':');
	}

	if (colon) {
		*colon = '\0';
		*port_p = colon + 1;
		if (!**port_p)
			return -EINVAL;
	} else {
		if (!default_port)
			return -EINVAL;
		*port_p = default_port;
	}

	if (!*host)
		return -EINVAL;

	*host_p = host;
	return 0;
}

/*
 * Rebuild the request in origin-form into hc->fwd_req: the absolute-form
 * request-target is replaced by @path, hop-by-hop / proxy headers are dropped
 * and "Connection: close" is appended (this proxy handles one request per
 * connection). @hdr_len is the length of the parsed request header, used to
 * size the scratch buffer (the rewrite is never materially larger). Returns 0
 * or a negative error.
 */
static int build_forward_request(struct gwp_http_conn *hc, const char *path,
				 size_t hdr_len)
{
	struct gwnet_http_req_hdr *req = &hc->req_hdr;
	const char *method = http_method_str(req->method);
	const char *ver = (req->version == GWNET_HTTP_VER_1_0) ? "1.0" : "1.1";
	size_t cap = hdr_len * 2 + 64, n = 0, i;
	char *buf;
	int w;

	if (!method)
		return -EINVAL;

	buf = malloc(cap);
	if (!buf)
		return -ENOMEM;

	w = snprintf(buf, cap, "%s %s HTTP/%s\r\n", method, path, ver);
	if (w < 0 || (size_t)w >= cap)
		goto too_big;
	n = (size_t)w;

	for (i = 0; i < req->fields.nr; i++) {
		const char *k = req->fields.ff[i].key;
		const char *v = req->fields.ff[i].val;

		/* Drop hop-by-hop / proxy-only headers. */
		if (!strcasecmp(k, "Connection") ||
		    !strcasecmp(k, "Proxy-Connection") ||
		    !strcasecmp(k, "Proxy-Authorization"))
			continue;

		w = snprintf(buf + n, cap - n, "%s: %s\r\n", k, v);
		if (w < 0 || (size_t)w >= cap - n)
			goto too_big;
		n += (size_t)w;
	}

	w = snprintf(buf + n, cap - n, "Connection: close\r\n\r\n");
	if (w < 0 || (size_t)w >= cap - n)
		goto too_big;
	n += (size_t)w;

	free(hc->fwd_req);
	hc->fwd_req = buf;
	hc->fwd_req_len = n;
	return 0;

too_big:
	free(buf);
	return -E2BIG;
}

/*
 * Classify a fully-parsed forwarding request: rebuild it in origin-form and
 * split the http:// authority into host/port. Returns GWP_HTTP_FORWARD or
 * GWP_HTTP_ERR.
 */
static int classify_forward(struct gwp_http_conn *hc, size_t hdr_len,
			    char **host_p, char **port_p,
			    const char **req_p, size_t *req_len_p)
{
	static char default_port[] = "80";
	char *uri = hc->req_hdr.uri, *authority, *slash;
	const char *path;

	/* Only absolute-form http:// URIs are supported (no TLS termination). */
	if (!uri || strncasecmp(uri, "http://", 7))
		return GWP_HTTP_ERR;

	authority = uri + 7;

	/* The origin-form path is everything from the first '/', else "/". */
	slash = authority;
	while (*slash && *slash != '/')
		slash++;
	if (slash == authority)
		return GWP_HTTP_ERR;		/* empty authority */
	path = (*slash == '/') ? slash : "/";

	/*
	 * Build the rewritten request now, while @path is still intact; the
	 * authority is isolated (and the path's leading '/' overwritten) only
	 * afterwards.
	 */
	if (build_forward_request(hc, path, hdr_len) < 0)
		return GWP_HTTP_ERR;

	if (*slash == '/')
		*slash = '\0';
	if (split_authority(authority, host_p, port_p, default_port) < 0)
		return GWP_HTTP_ERR;

	hc->is_forward = true;
	*req_p = hc->fwd_req;
	*req_len_p = hc->fwd_req_len;
	return GWP_HTTP_FORWARD;
}

int gwp_http_conn_process(struct gwp_http_conn *hc, struct gwp_auth *auth,
			  const void *in, size_t *in_len,
			  char **host_p, char **port_p,
			  const char **req_p, size_t *req_len_p)
{
	struct gwnet_http_req_hdr *req = &hc->req_hdr;
	size_t hdr_len;
	int r;

	hc->ctx_hdr.buf = in;
	hc->ctx_hdr.len = *in_len;
	hc->ctx_hdr.off = 0;
	r = gwnet_http_req_hdr_parse(&hc->ctx_hdr, req);
	*in_len = hc->ctx_hdr.off;
	if (r < 0)
		return (r == -EAGAIN) ? GWP_HTTP_NEED_MORE : GWP_HTTP_ERR;

	/* Header complete. */
	hdr_len = hc->ctx_hdr.off;

	/*
	 * "Basic" proxy authentication (shared with SOCKS5) applies to CONNECT
	 * and forwarding requests alike.
	 */
	if (auth) {
		const char *cred = gwnet_http_hdr_fields_get(&req->fields,
							     "Proxy-Authorization");
		if (!gwp_auth_check_basic(auth, cred))
			return GWP_HTTP_NEED_AUTH;
	}

	/* A non-CONNECT method is a forwarding request (absolute-form target). */
	if (req->method != GWNET_HTTP_METHOD_CONNECT)
		return classify_forward(hc, hdr_len, host_p, port_p, req_p,
					req_len_p);

	/* CONNECT: the target is an authority-form "host:port" to tunnel to. */
	if (split_authority(req->uri, host_p, port_p, NULL) < 0)
		return GWP_HTTP_ERR;

	hc->is_forward = false;
	return GWP_HTTP_CONNECT;
}

int gwp_http_build_connect_reply(const struct gwp_http_conn *hc, void *out,
				 size_t out_cap)
{
	static const char ok[] = "HTTP/1.1 200 OK\r\n\r\n";
	size_t len = sizeof(ok) - 1;

	if (hc->is_forward)
		return 0;

	if (out_cap < len)
		return -ENOBUFS;

	memcpy(out, ok, len);
	return (int)len;
}

int gwp_http_build_auth_required_reply(void *out, size_t out_cap)
{
	static const char resp[] =
		"HTTP/1.1 407 Proxy Authentication Required\r\n"
		"Proxy-Authenticate: Basic realm=\"gwproxy\"\r\n"
		"Content-Length: 0\r\n"
		"Connection: close\r\n"
		"\r\n";
	size_t len = sizeof(resp) - 1;

	if (out_cap < len)
		return -ENOBUFS;

	memcpy(out, resp, len);
	return (int)len;
}
