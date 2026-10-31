// SPDX-License-Identifier: GPL-2.0-only
/*
 * Unit tests for the HTTP proxy module (src/gwproxy/http.c).
 *
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <gwproxy/http.h>
#include <gwproxy/auth.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>

#define PRTEST_OK()					\
do {							\
	static int __printed;				\
	if (!__printed) {				\
		printf("Test passed: %s\n", __func__);	\
		__printed = 1;				\
	}						\
} while (0)

/*
 * Create a unique temporary file from @tmpl (an mkstemp(3) template, rewritten
 * in place) and write @len bytes of @data to it. See tests/socks5.c for why
 * mkstemp() is used rather than a fixed path. The caller unlink()s @tmpl.
 */
static ssize_t write_temp_file(char *tmpl, const void *data, size_t len)
{
	ssize_t w;
	int fd;

	fd = mkstemp(tmpl);
	if (fd < 0)
		return -1;

	w = write(fd, data, len);
	close(fd);
	return w;
}

/*
 * Run gwp_http_conn_process() on a copy of @buf, a whole request, in one shot.
 * For a forwarding request *@req and *@req_len are set to the rewritten
 * header, which then starts the NUL-terminated copy (valid until the next
 * call); otherwise *@req_len is the length of the header. *@len is set to the
 * bytes in the copy afterwards, if @len is not NULL.
 */
static char proc_buf[65536];

static int proc(struct gwp_http_conn *hc, struct gwp_auth *auth,
		const char *buf, char **host, char **port, const char **req,
		size_t *req_len, size_t *len)
{
	size_t n = strlen(buf);
	int r;

	assert(n < sizeof(proc_buf));
	memcpy(proc_buf, buf, n);
	r = gwp_http_conn_process(hc, auth, proc_buf, &n, sizeof(proc_buf) - 1,
				  host, port, req_len);
	proc_buf[n] = '\0';	/* for strlen() and memmem() on it */
	*req = r == GWP_HTTP_FORWARD ? proc_buf : NULL;
	if (len)
		*len = n;
	return r;
}

static int run(struct gwp_http_conn *hc, struct gwp_auth *auth, const char *buf,
	       char **host, char **port, const char **req, size_t *req_len)
{
	size_t len;
	int r = proc(hc, auth, buf, host, port, req, req_len, &len);

	/*
	 * On a complete request the whole buffer is the header (the tests
	 * here send no body); a forwarding one is replaced by its rewrite.
	 */
	if (r == GWP_HTTP_FORWARD)
		assert(*req_len == len);
	else if (r != GWP_HTTP_NEED_MORE && r != GWP_HTTP_ERR)
		assert(*req_len == strlen(buf));
	return r;
}

static void test_connect_ipv4(void)
{
	static const char buf[] =
		"CONNECT example.com:443 HTTP/1.1\r\n"
		"Host: example.com:443\r\n"
		"\r\n";
	struct gwp_http_conn *hc = gwp_http_conn_alloc();
	char *host, *port;
	const char *req = NULL;
	size_t req_len = 0;
	uint8_t out[64];
	int r;

	assert(hc);
	r = run(hc, NULL, buf, &host, &port, &req, &req_len);
	assert(r == GWP_HTTP_CONNECT);
	assert(!gwp_http_conn_is_forward(hc));
	assert(!strcmp(host, "example.com"));
	assert(!strcmp(port, "443"));

	/* A CONNECT tunnel replies "200 OK" once connected. */
	r = gwp_http_build_connect_reply(hc, out, sizeof(out));
	assert(r == 19);
	assert(!memcmp(out, "HTTP/1.1 200 OK\r\n\r\n", 19));

	/* Too-small output buffer is rejected. */
	assert(gwp_http_build_connect_reply(hc, out, 5) == -ENOBUFS);

	gwp_http_conn_free(hc);
	PRTEST_OK();
}

static void test_connect_ipv6(void)
{
	static const char buf[] =
		"CONNECT [::1]:8080 HTTP/1.1\r\n"
		"\r\n";
	struct gwp_http_conn *hc = gwp_http_conn_alloc();
	char *host, *port;
	const char *req = NULL;
	size_t req_len = 0;
	int r;

	assert(hc);
	r = run(hc, NULL, buf, &host, &port, &req, &req_len);
	assert(r == GWP_HTTP_CONNECT);
	assert(!strcmp(host, "::1"));		/* brackets unwrapped */
	assert(!strcmp(port, "8080"));
	gwp_http_conn_free(hc);
	PRTEST_OK();
}

static void test_forward_get(void)
{
	static const char buf[] =
		"GET http://example.com:8080/a/b?q=1 HTTP/1.1\r\n"
		"Host: example.com:8080\r\n"
		"User-Agent: gwtest\r\n"
		"Proxy-Connection: keep-alive\r\n"
		"Proxy-Authorization: Basic Zm9v\r\n"
		"\r\n";
	struct gwp_http_conn *hc = gwp_http_conn_alloc();
	char *host, *port;
	const char *req = NULL;
	size_t req_len = 0;
	uint8_t out[64];
	int r;

	assert(hc);
	r = run(hc, NULL, buf, &host, &port, &req, &req_len);
	assert(r == GWP_HTTP_FORWARD);
	assert(gwp_http_conn_is_forward(hc));
	assert(!strcmp(host, "example.com"));
	assert(!strcmp(port, "8080"));

	/* The rewritten request is origin-form and NUL-friendly for strstr. */
	assert(req && req_len == strlen(req));
	assert(!strncmp(req, "GET /a/b?q=1 HTTP/1.1\r\n", 22));
	assert(strstr(req, "Host: example.com:8080\r\n"));
	assert(strstr(req, "User-Agent: gwtest\r\n"));
	/* Hop-by-hop / proxy-only headers are dropped. */
	assert(!strstr(req, "Proxy-Connection"));
	assert(!strstr(req, "Proxy-Authorization"));
	/* Exactly one Connection header, "close", and it ends the header. */
	assert(strstr(req, "\r\nConnection: close\r\n\r\n"));

	/* A forwarding request has no client reply once connected. */
	r = gwp_http_build_connect_reply(hc, out, sizeof(out));
	assert(r == 0);

	gwp_http_conn_free(hc);
	PRTEST_OK();
}

static void test_forward_default_port(void)
{
	static const char buf[] =
		"GET http://example.com HTTP/1.1\r\n"
		"\r\n";
	struct gwp_http_conn *hc = gwp_http_conn_alloc();
	char *host, *port;
	const char *req = NULL;
	size_t req_len = 0;
	int r;

	assert(hc);
	r = run(hc, NULL, buf, &host, &port, &req, &req_len);
	assert(r == GWP_HTTP_FORWARD);
	assert(!strcmp(host, "example.com"));
	assert(!strcmp(port, "80"));		/* default when absent */
	/* An empty URI path becomes "/". */
	assert(!strncmp(req, "GET / HTTP/1.1\r\n", 16));
	gwp_http_conn_free(hc);
	PRTEST_OK();
}

/*
 * The authority of an absolute-form target ends at the first '/', '?' or
 * '#': what follows a '?' or '#' is never the host, even past an '@'.
 */
static void test_forward_authority_end(void)
{
	static const char query[] =
		"GET http://example.com:8080?q=1 HTTP/1.1\r\n\r\n";
	static const char query_at[] =
		"GET http://evil.example?@127.0.0.1/ HTTP/1.1\r\n\r\n";
	static const char frag_at[] =
		"GET http://evil.example#@127.0.0.1/ HTTP/1.1\r\n\r\n";
	static const char path_at[] =
		"GET http://example.com/a@127.0.0.1/ HTTP/1.1\r\n\r\n";
	struct gwp_http_conn *hc;
	char *host, *port;
	const char *req = NULL;
	size_t req_len = 0;

	/* A query with an empty path: the path becomes "/". */
	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, NULL, query, &host, &port, &req, &req_len) == GWP_HTTP_FORWARD);
	assert(!strcmp(host, "example.com"));
	assert(!strcmp(port, "8080"));
	assert(!strncmp(req, "GET /?q=1 HTTP/1.1\r\n", 20));
	assert(strstr(req, "\r\nHost: example.com:8080\r\n"));
	gwp_http_conn_free(hc);

	/* An '@' in the query is not userinfo. */
	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, NULL, query_at, &host, &port, &req, &req_len) == GWP_HTTP_FORWARD);
	assert(!strcmp(host, "evil.example"));
	assert(!strcmp(port, "80"));
	assert(!strncmp(req, "GET /?@127.0.0.1/ HTTP/1.1\r\n", 28));
	assert(strstr(req, "\r\nHost: evil.example\r\n"));
	gwp_http_conn_free(hc);

	/* Nor is one in the path. */
	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, NULL, path_at, &host, &port, &req, &req_len) == GWP_HTTP_FORWARD);
	assert(!strcmp(host, "example.com"));
	assert(!strncmp(req, "GET /a@127.0.0.1/ HTTP/1.1\r\n", 28));
	gwp_http_conn_free(hc);

	/* A fragment straight after the authority leaves nothing to send. */
	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, NULL, frag_at, &host, &port, &req, &req_len) == GWP_HTTP_ERR);
	gwp_http_conn_free(hc);

	PRTEST_OK();
}

static void test_forward_hop_by_hop(void)
{
	/*
	 * Every hop-by-hop / connection-specific request header must be dropped
	 * from the forwarded request, including a field named by the Connection
	 * header (X-Custom). Expect (100-continue must be forwarded), the body-
	 * framing headers and end-to-end Authorization must be kept.
	 */
	static const char buf[] =
		"POST http://example.com/x HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"Authorization: Bearer tok\r\n"
		"Expect: 100-continue\r\n"
		"Transfer-Encoding: chunked\r\n"
		"Keep-Alive: timeout=5\r\n"
		"TE: trailers\r\n"
		"Trailer: X-Trace\r\n"
		"Upgrade: h2c\r\n"
		"X-Keep: keep-me\r\n"
		"X-Custom: drop-me\r\n"
		"Connection: keep-alive, X-Custom\r\n"
		"\r\n";
	struct gwp_http_conn *hc = gwp_http_conn_alloc();
	char *host, *port;
	const char *req = NULL;
	size_t req_len = 0;
	int r;

	assert(hc);
	r = run(hc, NULL, buf, &host, &port, &req, &req_len);
	assert(r == GWP_HTTP_FORWARD);
	assert(!strncmp(req, "POST /x HTTP/1.1\r\n", 17));

	/* Kept. */
	assert(strstr(req, "Host: example.com\r\n"));
	assert(strstr(req, "Authorization: Bearer tok\r\n"));
	assert(strstr(req, "Expect: 100-continue\r\n"));
	assert(strstr(req, "Transfer-Encoding: chunked\r\n"));
	assert(strstr(req, "X-Keep: keep-me\r\n"));

	/* Dropped (hop-by-hop). */
	assert(!strstr(req, "Keep-Alive"));
	assert(!strstr(req, "\r\nTE:"));
	assert(!strstr(req, "Trailer:"));
	assert(!strstr(req, "Upgrade"));
	/* Dropped (named by Connection). */
	assert(!strstr(req, "X-Custom"));
	/* The original Connection header is replaced by exactly "close". */
	assert(!strstr(req, "keep-alive"));
	assert(strstr(req, "\r\nConnection: close\r\n\r\n"));

	gwp_http_conn_free(hc);
	PRTEST_OK();
}

static void test_forward_conn_lists_framing(void)
{
	/*
	 * A Connection header naming a framing field (or Host) would make the
	 * rewrite drop it while the body is still relayed, so the origin would
	 * read the body as a second request. Such a request is refused with
	 * 400 rather than rewritten.
	 */
	static const char *const bad[] = {
		("POST http://example.com/a HTTP/1.1\r\n"
		 "Connection: Content-Length\r\n"
		 "Content-Length: 4\r\n\r\n"),
		("POST http://example.com/a HTTP/1.1\r\n"
		 "Connection: keep-alive, transfer-encoding\r\n"
		 "Transfer-Encoding: chunked\r\n\r\n"),
		("GET http://example.com/a HTTP/1.1\r\n"
		 "Connection: Host\r\n\r\n"),
	};
	struct gwp_http_conn *hc;
	char *host, *port;
	const char *req = NULL;
	size_t req_len = 0, i;
	uint8_t out[128];
	int r;

	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		hc = gwp_http_conn_alloc();
		assert(hc);
		r = run(hc, NULL, bad[i], &host, &port, &req, &req_len);
		assert(r == GWP_HTTP_BAD_REQUEST);
		gwp_http_conn_free(hc);
	}

	r = gwp_http_build_bad_request_reply(out, sizeof(out));
	assert(r > 0 && !strncmp((char *)out, "HTTP/1.1 400 ", 13));
	assert(gwp_http_build_bad_request_reply(out, 5) == -ENOBUFS);
	PRTEST_OK();
}

/*
 * Classify @hdr as a forwarding request, then pass @body through the request
 * body filter @step bytes at a time. Returns the filter's first error, or 0
 * with *@fwd set to how many body bytes it let through.
 */
static int req_body(const char *hdr, const char *body, size_t step,
		    size_t *fwd)
{
	struct gwp_http_conn *hc = gwp_http_conn_alloc();
	size_t len = strlen(body), i, n, f;
	char *host, *port;
	const char *req;
	size_t req_len;
	bool held = false;
	int r = 0;

	assert(hc);
	assert(run(hc, NULL, hdr, &host, &port, &req, &req_len) ==
	       GWP_HTTP_FORWARD);
	*fwd = 0;
	for (i = 0; i < len; i += n) {
		n = (len - i < step) ? len - i : step;
		r = gwp_http_fwd_req_body(hc, body + i, n, &f);
		if (r)
			break;
		/* Once something is held back, nothing more gets through. */
		assert(!held || !f);
		held = f < n;
		*fwd += f;
	}
	gwp_http_conn_free(hc);
	return r;
}

/*
 * The forwarded request drops what Connection names, checked against the
 * options split once; more than 32 distinct options is refused with 400.
 */
static void test_forward_conn_limit(void)
{
	static char buf[4096];
	struct gwp_http_conn *hc;
	char *host, *port;
	const char *req = NULL;
	size_t req_len = 0, n;
	int i;

	n = (size_t)sprintf(buf, "GET http://example.com/ HTTP/1.1\r\n"
			    "X-0: a\r\nConnection: ");
	for (i = 0; i < 32; i++)
		n += (size_t)sprintf(buf + n, "x-%d, X-%d,", i, i);
	n += (size_t)sprintf(buf + n, "\r\nX-31: b\r\nX-32: c\r\n\r\n");
	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, NULL, buf, &host, &port, &req, &req_len) ==
	       GWP_HTTP_FORWARD);
	{
		static const char want[] =
			"GET / HTTP/1.1\r\nHost: example.com\r\n"
			"X-32: c\r\nConnection: close\r\n\r\n";

		assert(req_len == strlen(want) && !memcmp(req, want, req_len));
	}
	gwp_http_conn_free(hc);

	sprintf(buf + n - 2, "Connection: X-32\r\n\r\n");
	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, NULL, buf, &host, &port, &req, &req_len) ==
	       GWP_HTTP_BAD_REQUEST);
	gwp_http_conn_free(hc);
	PRTEST_OK();
}

static void test_req_framing(void)
{
	static const char next[] = "GET http://other/ HTTP/1.1\r\n\r\n";
	static const char chunked[] =
		"5\r\nhello\r\n"
		"1A;ext=\"v\"\r\nabcdefghijklmnopqrstuvwxyz\r\n"
		"0003 ;x\r\nabc\r\n"
		"0\r\nX-Trailer: t\r\nX-T: v\r\n\r\n";
	static const char *const bad_hdr[] = {
		"POST http://h/ HTTP/1.1\r\nContent-Length: 1\r\n"
		"Transfer-Encoding: chunked\r\n\r\n",
		"POST http://h/ HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n",
		"POST http://h/ HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n",
		"POST http://h/ HTTP/1.1\r\nContent-Length: 1x\r\n\r\n",
		"POST http://h/ HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
		"POST http://h/ HTTP/1.1\r\n"
		"Content-Length: 99999999999999999999\r\n\r\n",
	};
	static const char *const bad_chunked[] = {
		"5\nhello\r\n0\r\n\r\n",	/* bare LF */
		"5\r\nhelloX\r\n0\r\n\r\n",	/* data longer than its size */
		"g\r\n",
		"\r\n",
		"11111111111111111\r\n",	/* more than 64 bits */
		"0\r\nX: a\nb\r\n\r\n",
		/* A request smuggled in as "trailers". */
		"0\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n",
		"0\r\nX\r\n\r\n",		/* no colon */
		"0\r\nX : v\r\n\r\n",	/* space before colon */
		"80000000\r\n",		/* chunk of 2 GiB */
		"100000005\r\nhello\r\n0\r\n\r\n",
		"5 6\r\nhello\r\n0\r\n\r\n",	/* bare-space extension */
		"5 \r\nhello\r\n0\r\n\r\n",
	};
	char body[256];
	size_t fwd, step, i;
	struct gwp_http_conn *hc;
	char *host, *port;
	const char *req;
	size_t req_len;

	for (step = 1; step <= 64; step *= 4) {
		/* Content-Length: exactly that many bytes, the rest dropped. */
		snprintf(body, sizeof(body), "hello%s", next);
		assert(!req_body("POST http://h/ HTTP/1.1\r\n"
				 "Content-Length: 5\r\n\r\n", body, step, &fwd));
		assert(fwd == 5);

		/* No framing: no body; a pipelined request goes nowhere. */
		assert(!req_body("GET http://h/ HTTP/1.1\r\n\r\n", next, step,
				 &fwd));
		assert(fwd == 0);

		/* Chunked, extensions and trailers included. */
		snprintf(body, sizeof(body), "%s%s", chunked, next);
		assert(!req_body("POST http://h/ HTTP/1.1\r\n"
				 "Transfer-Encoding: Chunked\r\n\r\n", body,
				 step, &fwd));
		assert(fwd == strlen(chunked));

		for (i = 0; i < sizeof(bad_chunked) / sizeof(bad_chunked[0]);
		     i++)
			assert(req_body("POST http://h/ HTTP/1.1\r\n"
					"Transfer-Encoding: chunked\r\n\r\n",
					bad_chunked[i], step, &fwd) == -EBADMSG);
	}

	for (i = 0; i < sizeof(bad_hdr) / sizeof(bad_hdr[0]); i++) {
		hc = gwp_http_conn_alloc();
		assert(hc);
		assert(run(hc, NULL, bad_hdr[i], &host, &port, &req,
			   &req_len) == GWP_HTTP_BAD_REQUEST);
		gwp_http_conn_free(hc);
	}
	PRTEST_OK();
}

/* Feed @in to a fresh response filter in one go; returns its result. */
static int res_feed(struct gwp_http_conn *hc, const char *in, bool eof,
		    char *out, size_t out_cap, size_t *out_len)
{
	assert(!gwp_http_fwd_res_init(hc, 1024));
	return gwp_http_fwd_res_input(hc, in, strlen(in), eof, out, out_cap,
				      out_len);
}

static void test_res_rewrite(void)
{
	/*
	 * The client must learn that the connection closes, whatever the
	 * origin claims, and must not see the origin's hop-by-hop fields. The
	 * framing fields stay even when Connection names them (the body is
	 * relayed as is), and so do duplicates such as Set-Cookie.
	 */
	static const char in[] =
		"HTTP/1.1 200 OK\r\n"
		"Connection: keep-alive, X-Drop, Content-Length\r\n"
		"Keep-Alive: timeout=100\r\n"
		"Proxy-Authenticate: Basic realm=\"evil\"\r\n"
		"X-Drop: 1\r\n"
		"Set-Cookie: a=1\r\n"
		"Set-Cookie: b=2\r\n"
		"Content-Length: 5\r\n"
		"\r\n"
		"hello";
	static const char want[] =
		"HTTP/1.1 200 OK\r\n"
		"Set-Cookie: a=1\r\n"
		"Set-Cookie: b=2\r\n"
		"Content-Length: 5\r\n"
		"Connection: close\r\n"
		"Proxy-Connection: close\r\n"
		"\r\n"
		"hello";
	struct gwp_http_conn *hc = gwp_http_conn_alloc();
	char out[1024];
	size_t out_len, i;

	assert(hc);
	assert(res_feed(hc, in, false, out, sizeof(out), &out_len) == 0);
	assert(gwp_http_fwd_res_state(hc) == GWP_HTTP_RES_BODY);
	assert(out_len == strlen(want) && !memcmp(out, want, out_len));

	/* Same, dribbled in a byte at a time, with LF-only line ends. */
	assert(!gwp_http_fwd_res_init(hc, 1024));
	{
		static const char lf[] =
			"HTTP/1.0 200 OK\nKeep-Alive: x\nA: b\n\nbody";
		static const char lf_want[] =
			"HTTP/1.0 200 OK\r\nA: b\r\n"
			"Connection: close\r\nProxy-Connection: close\r\n\r\n"
			"body";
		size_t o = 0;

		/* Nothing comes out until the blank line is in. */
		for (i = 0; gwp_http_fwd_res_state(hc) == GWP_HTTP_RES_HDR; i++) {
			assert(gwp_http_fwd_res_input(hc, lf + i, 1, false,
						      out, sizeof(out),
						      &out_len) == 0);
			if (i < strlen(lf) - 5)
				assert(!out_len);
		}
		/* From there on the body is the caller's to relay. */
		memcpy(out + out_len, lf + i, strlen(lf) - i);
		o = out_len + strlen(lf) - i;
		assert(o == strlen(lf_want) && !memcmp(out, lf_want, o));
	}

	gwp_http_conn_free(hc);
	PRTEST_OK();
}

static void test_res_interim(void)
{
	/* A 100 Continue is passed on at once, without "Connection: close". */
	static const char in[] = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 20";
	static const char rest[] = "4 No Content\r\n\r\n";
	struct gwp_http_conn *hc = gwp_http_conn_alloc();
	char out[1024];
	size_t out_len;

	assert(hc);
	assert(res_feed(hc, in, false, out, sizeof(out), &out_len) == 0);
	assert(gwp_http_fwd_res_state(hc) == GWP_HTTP_RES_HDR);
	assert(out_len == 25 && !memcmp(out, "HTTP/1.1 100 Continue\r\n\r\n", 25));
	assert(gwp_http_fwd_res_pending(hc) == 11);

	assert(gwp_http_fwd_res_input(hc, rest, strlen(rest), false, out,
				      sizeof(out), &out_len) == 0);
	assert(gwp_http_fwd_res_state(hc) == GWP_HTTP_RES_BODY);
	assert(strstr(out, "HTTP/1.1 204 No Content\r\nConnection: close\r\n"));

	gwp_http_conn_free(hc);
	PRTEST_OK();
}

/*
 * The response rewrite checks every field against the Connection options, so
 * both are bounded: at most 256 field lines and 32 distinct options, past
 * which the response is refused (the caller answers 502). Repeated options
 * count once, and the options may come from several Connection lines,
 * before or after the fields they name.
 */
static void test_res_limits(void)
{
	static char in[40000], out[40000];
	struct gwp_http_conn *hc = gwp_http_conn_alloc();
	size_t n, out_len;
	int i;

	assert(hc);

	/* 256 field lines: fine. 257: refused. */
	n = (size_t)sprintf(in, "HTTP/1.1 200 OK\r\n");
	for (i = 0; i < 256; i++)
		n += (size_t)sprintf(in + n, "X-%d: v\r\n", i);
	sprintf(in + n, "\r\n");
	assert(!gwp_http_fwd_res_init(hc, sizeof(in)));
	assert(gwp_http_fwd_res_input(hc, in, strlen(in), false, out,
				      sizeof(out), &out_len) == 0);
	assert(gwp_http_fwd_res_state(hc) == GWP_HTTP_RES_BODY);
	sprintf(in + n, "X-x: v\r\n\r\n");
	assert(!gwp_http_fwd_res_init(hc, sizeof(in)));
	assert(gwp_http_fwd_res_input(hc, in, strlen(in), false, out,
				      sizeof(out), &out_len) == -E2BIG);

	/* 32 distinct options over two lines, each repeated: fine. */
	n = (size_t)sprintf(in, "HTTP/1.1 200 OK\r\nX-0: drop\r\n"
			    "Connection: ");
	for (i = 0; i < 16; i++)
		n += (size_t)sprintf(in + n, "x-%d, X-%d ,", i, i);
	n += (size_t)sprintf(in + n, "\r\nKeep: me\r\nConnection: ");
	for (i = 16; i < 32; i++)
		n += (size_t)sprintf(in + n, ",, X-%d,x-%d", i, i);
	n += (size_t)sprintf(in + n, "\r\nX-31: drop\r\n");
	sprintf(in + n, "\r\n");
	assert(!gwp_http_fwd_res_init(hc, sizeof(in)));
	assert(gwp_http_fwd_res_input(hc, in, strlen(in), false, out,
				      sizeof(out), &out_len) == 0);
	{
		static const char want[] =
			"HTTP/1.1 200 OK\r\nKeep: me\r\n"
			"Connection: close\r\nProxy-Connection: close\r\n"
			"\r\n";

		assert(out_len == strlen(want) && !memcmp(out, want, out_len));
	}

	/* A 33rd distinct option: refused. */
	sprintf(in + n, "Connection: X-32\r\n\r\n");
	assert(!gwp_http_fwd_res_init(hc, sizeof(in)));
	assert(gwp_http_fwd_res_input(hc, in, strlen(in), false, out,
				      sizeof(out), &out_len) == -E2BIG);

	/* A long list of one repeated option is one option. */
	n = (size_t)sprintf(in, "HTTP/1.1 200 OK\r\nConnection: a");
	for (i = 0; i < 5000; i++)
		n += (size_t)sprintf(in + n, ",a");
	sprintf(in + n, "\r\nA: x\r\nB: y\r\n\r\n");
	assert(!gwp_http_fwd_res_init(hc, sizeof(in)));
	assert(gwp_http_fwd_res_input(hc, in, strlen(in), false, out,
				      sizeof(out), &out_len) == 0);
	assert(out_len == strlen("HTTP/1.1 200 OK\r\nB: y\r\n"
				 "Connection: close\r\n"
				 "Proxy-Connection: close\r\n\r\n"));

	gwp_http_conn_free(hc);
	PRTEST_OK();
}

/*
 * A final header that arrives whole is rewritten straight from the input;
 * the result must be the same as when it is collected in pieces, also when
 * the input and output share a buffer and the rewrite is longer than the
 * header (LF line ends become CRLF), and when the rewrite is too large for
 * the direct path.
 */
static void test_res_direct(void)
{
	static char in[20000], out[20000], buf[40000], want[40000];
	const char *cases[3];
	struct gwp_http_conn *hc = gwp_http_conn_alloc();
	size_t n, i, j, out_len, want_len;

	assert(hc);
	cases[0] = "HTTP/1.1 200 OK\nA: b\nConnection: x\nX: y\n\nbody bytes";
	cases[1] = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No\r\nA: b\r\n"
		   "\r\nrest";
	n = (size_t)sprintf(in, "HTTP/1.1 200 OK\r\n");
	for (i = 0; i < 200; i++)
		n += (size_t)sprintf(in + n, "X-%zu: %060zu\r\n", i, i);
	sprintf(in + n, "\r\ntail");
	cases[2] = in;

	for (i = 0; i < 3; i++) {
		size_t len = strlen(cases[i]);

		/* Reference: one byte at a time, through the hold-back. */
		assert(!gwp_http_fwd_res_init(hc, 16384));
		want_len = 0;
		for (j = 0; j < len &&
			    gwp_http_fwd_res_state(hc) == GWP_HTTP_RES_HDR; j++) {
			assert(!gwp_http_fwd_res_input(hc, cases[i] + j, 1,
						       false, want + want_len,
						       sizeof(want) - want_len,
						       &out_len));
			want_len += out_len;
		}
		memcpy(want + want_len, cases[i] + j, len - j);
		want_len += len - j;

		/* In one read, in place. */
		assert(!gwp_http_fwd_res_init(hc, 16384));
		memcpy(buf, cases[i], len);
		assert(!gwp_http_fwd_res_input(hc, buf, len, false, buf,
					       sizeof(buf), &out_len));
		assert(gwp_http_fwd_res_state(hc) == GWP_HTTP_RES_BODY);
		assert(out_len == want_len && !memcmp(buf, want, want_len));

		/* In one read, separate buffers. */
		assert(!gwp_http_fwd_res_init(hc, 16384));
		assert(!gwp_http_fwd_res_input(hc, cases[i], len, false, out,
					       sizeof(out), &out_len));
		assert(out_len == want_len && !memcmp(out, want, want_len));
	}

	/* Too little room for header and body: refused either way. */
	assert(!gwp_http_fwd_res_init(hc, 16384));
	assert(gwp_http_fwd_res_input(hc, cases[0], strlen(cases[0]), false,
				      out, 40, &out_len) == -E2BIG);
	gwp_http_conn_free(hc);
	PRTEST_OK();
}

static void test_res_reject(void)
{
	static const char *const bad[] = {
		("HTTP/1.1 407 Proxy Authentication Required\r\n"
		 "Proxy-Authenticate: Basic realm=\"x\"\r\n\r\n"),
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\n",
		"SSH-2.0-OpenSSH\r\n\r\n",
		"HTTP/1.1 200 OK\r\nX: a\rb\r\n\r\n",	/* bare CR */
		"HTTP/1.1 200 OK\r\nX: a\r\n b\r\n\r\n",	/* obs-fold */
		"HTTP/1.1 200 OK\r\nX : a\r\n\r\n",
		"HTTP/1.1 600 OK\r\n\r\n",
	};
	struct gwp_http_conn *hc = gwp_http_conn_alloc();
	char out[1024], big[1100];
	size_t out_len, i;

	assert(hc);
	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		assert(res_feed(hc, bad[i], false, out, sizeof(out),
				&out_len) < 0);
		assert(gwp_http_fwd_res_state(hc) == GWP_HTTP_RES_FAILED);
		assert(!out_len);
	}
	assert(res_feed(hc, bad[0], false, out, sizeof(out), &out_len) ==
	       -EACCES);

	/* The origin closing before the header is complete. */
	assert(res_feed(hc, "HTTP/1.1 200 OK\r\n", true, out, sizeof(out),
			&out_len) == -EBADMSG);

	/* A header that cannot fit in what the filter may hold back. */
	memset(big, 'a', sizeof(big) - 1);
	big[sizeof(big) - 1] = '\0';
	memcpy(big, "HTTP/1.1 200 OK\r\nX: ", 20);
	assert(res_feed(hc, big, false, out, sizeof(out), &out_len) == -E2BIG);

	gwp_http_conn_free(hc);
	PRTEST_OK();
}

static void test_need_more(void)
{
	/* Request line complete, header fields not yet terminated. */
	static const char part1[] = "CONNECT example.com:443 HTTP/1.1\r\n";
	static const char full[] = "CONNECT example.com:443 HTTP/1.1\r\n\r\n";
	struct gwp_http_conn *hc = gwp_http_conn_alloc();
	char *host, *port;
	const char *req = NULL;
	size_t req_len = 0, len;
	int r;

	assert(hc);
	r = proc(hc, NULL, part1, &host, &port, &req, &req_len, &len);
	assert(r == GWP_HTTP_NEED_MORE);
	/* Nothing consumed until complete. */
	assert(!req_len && len == strlen(part1));

	/*
	 * The terminating blank line completes the request: the caller hands
	 * over the whole header again, in another buffer here.
	 */
	r = proc(hc, NULL, full, &host, &port, &req, &req_len, &len);
	assert(r == GWP_HTTP_CONNECT);
	assert(req_len == strlen(full) && len == strlen(full));
	assert(!strcmp(host, "example.com"));
	assert(!strcmp(port, "443"));
	gwp_http_conn_free(hc);
	PRTEST_OK();
}

/*
 * Feed @req to a new connection @step bytes at a time, keeping unconsumed
 * bytes buffered the way gwp_handle_conn_state_http() does. Returns the
 * result; *@tail is set to how many bytes were left unconsumed, and the
 * rewritten request (if any) is copied to @fwd.
 */
static int feed_steps(const char *req, size_t len, size_t step, char *fwd,
		      size_t *fwd_len, char *hp, size_t *tail)
{
	static char buf[32768];
	struct gwp_http_conn *hc = gwp_http_conn_alloc();
	size_t have = 0, pos = 0, in, rl = 0;
	int r = GWP_HTTP_NEED_MORE;
	char *h, *p;

	assert(hc);
	while (r == GWP_HTTP_NEED_MORE && pos < len) {
		size_t n = (len - pos < step) ? len - pos : step;

		memcpy(buf + have, req + pos, n);
		have += n;
		pos += n;
		in = have;
		r = gwp_http_conn_process(hc, NULL, buf, &in, sizeof(buf), &h,
					  &p, &rl);
		/*
		 * A forwarding request is replaced by its rewrite, followed
		 * by what followed the header; take the rewrite. Any other
		 * header is dropped once complete, nothing before.
		 */
		if (r == GWP_HTTP_FORWARD) {
			assert(rl <= in);
			memcpy(fwd, buf, rl);
			have = in;
		} else {
			assert(in == have);
		}
		assert(rl <= have);
		have -= rl;
		memmove(buf, buf + rl, have);
	}
	*fwd_len = r == GWP_HTTP_FORWARD ? rl : 0;
	if (r == GWP_HTTP_FORWARD || r == GWP_HTTP_CONNECT)
		sprintf(hp, "%s|%s", h, p);
	else
		hp[0] = '\0';
	*tail = have + (len - pos);
	gwp_http_conn_free(hc);
	return r;
}

/*
 * The parser is only re-run once a line end has arrived, so whatever the
 * size of the reads the outcome must be exactly that of one read: the same
 * result, target, rewritten request and leftover body bytes.
 */
static void test_incremental(void)
{
	static char longline[17000], longfield[17000];
	const char *reqs[] = {
		"GET http://example.com:8080/a/b?q=1 HTTP/1.1\r\n"
		"Host: example.com\r\nUser-Agent: x\r\n"
		"Accept: a\r\nAccept: b\r\nContent-Length: 4\r\n\r\nbody",
		"CONNECT example.com:443 HTTP/1.1\nHost: x\n\nearly",
		"GET http://example.com/ HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
		"GET http://example.com/ HTTP/1.1\r\nX : bad\r\n\r\n",
		"WAT / HTTP/1.1\r\n\r\n",
		longline,
		longfield,
	};
	static char fwd1[40000], fwd2[40000];
	char hp1[300], hp2[300];
	size_t i, s, n, l1, l2, t1, t2;
	static const size_t steps[] = { 1, 2, 3, 7, 64, 1000 };
	int r1, r2;

	/* A request line, and then a field, past the 16 KiB limit. */
	n = (size_t)sprintf(longline, "GET http://example.com/");
	memset(longline + n, 'a', 16500);
	sprintf(longline + n + 16500, " HTTP/1.1\r\n\r\n");
	n = (size_t)sprintf(longfield, "GET http://example.com/ HTTP/1.1\r\n"
			    "X: ");
	memset(longfield + n, 'a', 16500);
	sprintf(longfield + n + 16500, "\r\n\r\n");

	for (i = 0; i < sizeof(reqs) / sizeof(reqs[0]); i++) {
		size_t len = strlen(reqs[i]);

		r1 = feed_steps(reqs[i], len, len, fwd1, &l1, hp1, &t1);
		for (s = 0; s < sizeof(steps) / sizeof(steps[0]); s++) {
			r2 = feed_steps(reqs[i], len, steps[s], fwd2, &l2,
					hp2, &t2);
			assert(r1 == r2);
			if (r1 == GWP_HTTP_ERR || r1 == GWP_HTTP_BAD_REQUEST ||
			    r1 == GWP_HTTP_TOO_LARGE)
				continue;
			assert(t1 == t2);
			assert(!strcmp(hp1, hp2));
			assert(l1 == l2 && !memcmp(fwd1, fwd2, l1));
		}
	}
	assert(feed_steps(reqs[0], strlen(reqs[0]), 1, fwd1, &l1, hp1, &t1) ==
	       GWP_HTTP_FORWARD && t1 == 4);
	assert(feed_steps(longline, strlen(longline), 1, fwd1, &l1, hp1,
			  &t1) == GWP_HTTP_TOO_LARGE);
	assert(feed_steps(longfield, strlen(longfield), 3, fwd1, &l1, hp1,
			  &t1) == GWP_HTTP_TOO_LARGE);
	PRTEST_OK();
}

static void test_errors(void)
{
	static const char https[] =	/* unsupported scheme (no TLS) */
		"GET https://example.com/ HTTP/1.1\r\n\r\n";
	static const char bare[] =	/* neither origin- nor absolute-form */
		"GET foo HTTP/1.1\r\n\r\n";
	static const char badmethod[] =
		"WAT http://example.com/ HTTP/1.1\r\n\r\n";
	struct gwp_http_conn *hc;
	char *host, *port;
	const char *req = NULL;
	size_t req_len = 0;

	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, NULL, https, &host, &port, &req, &req_len) == GWP_HTTP_ERR);
	gwp_http_conn_free(hc);

	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, NULL, bare, &host, &port, &req, &req_len) == GWP_HTTP_ERR);
	gwp_http_conn_free(hc);

	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, NULL, badmethod, &host, &port, &req, &req_len) == GWP_HTTP_ERR);
	gwp_http_conn_free(hc);

	PRTEST_OK();
}

/*
 * A field that may appear only once, sent twice, is answered with 400 rather
 * than a silent close; repeated list fields are still merged.
 */
static void test_duplicate_field(void)
{
	static const char *const dups[] = {
		"GET http://example.com/ HTTP/1.1\r\n"
		"Host: example.com\r\nHost: evil.example\r\n\r\n",
		"POST http://example.com/ HTTP/1.1\r\n"
		"Content-Length: 1\r\nContent-Length: 2\r\n\r\n",
		"CONNECT example.com:443 HTTP/1.1\r\n"
		"Proxy-Authorization: Basic a\r\n"
		"proxy-authorization: Basic b\r\n\r\n",
	};
	static const char list[] =
		"GET http://example.com/ HTTP/1.1\r\n"
		"Accept: a\r\nAccept: b\r\n\r\n";
	struct gwp_http_conn *hc;
	char *host, *port;
	const char *req = NULL;
	size_t req_len = 0, i;

	for (i = 0; i < sizeof(dups) / sizeof(dups[0]); i++) {
		/* Not run(): the request is refused before it is all read. */
		hc = gwp_http_conn_alloc();
		assert(hc);
		assert(proc(hc, NULL, dups[i], &host, &port, &req, &req_len,
			    NULL) == GWP_HTTP_BAD_REQUEST);
		gwp_http_conn_free(hc);
	}

	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, NULL, list, &host, &port, &req, &req_len) ==
	       GWP_HTTP_FORWARD);
	assert(memmem(req, req_len, "\r\nAccept: a, b\r\n", 16));
	gwp_http_conn_free(hc);
	PRTEST_OK();
}

/*
 * A forwarding request is rewritten where it lies: the rewrite takes the
 * header's place and the bytes behind the header follow it, whether the
 * rewrite is built on the stack or (past 4 KiB) in an allocated buffer. One
 * that does not fit the buffer leaves it alone and is refused with 431.
 */
static void test_forward_in_place(void)
{
	static const char body_req[] =
		"POST http://e/x HTTP/1.1\r\nContent-Length: 4\r\n\r\nbodyMORE";
	static const char body_want[] =
		"POST /x HTTP/1.1\r\nHost: e\r\nContent-Length: 4\r\n"
		"Connection: close\r\n\r\nbodyMORE";
	static const char grow[] = "GET http://e HTTP/1.1\r\nX: y\r\n\r\n";
	static char buf[16384], want[16384];
	struct gwp_http_conn *hc;
	size_t len, hl, n, wn;
	char *host, *port;

	hc = gwp_http_conn_alloc();
	assert(hc);
	len = strlen(body_req);
	memcpy(buf, body_req, len);
	assert(gwp_http_conn_process(hc, NULL, buf, &len, sizeof(buf), &host,
				     &port, &hl) == GWP_HTTP_FORWARD);
	assert(len == strlen(body_want) && !memcmp(buf, body_want, len));
	assert(hl == len - 8);
	assert(!strcmp(host, "e") && !strcmp(port, "80"));
	gwp_http_conn_free(hc);

	/* A rewrite past the 4 KiB stack buffer, with bytes behind it. */
	n = (size_t)sprintf(buf, "GET http://e/ HTTP/1.1\r\nCookie: ");
	wn = (size_t)sprintf(want, "GET / HTTP/1.1\r\nHost: e\r\nCookie: ");
	memset(buf + n, 'c', 6000);
	memset(want + wn, 'c', 6000);
	n += 6000;
	wn += 6000;
	n += (size_t)sprintf(buf + n, "\r\n\r\nTAIL");
	wn += (size_t)sprintf(want + wn, "\r\nConnection: close\r\n\r\nTAIL");
	hc = gwp_http_conn_alloc();
	assert(hc);
	len = n;
	assert(gwp_http_conn_process(hc, NULL, buf, &len, sizeof(buf), &host,
				     &port, &hl) == GWP_HTTP_FORWARD);
	assert(len == wn && !memcmp(buf, want, wn) && hl == wn - 4);
	gwp_http_conn_free(hc);

	/* The rewrite is longer than the request and the buffer is full. */
	hc = gwp_http_conn_alloc();
	assert(hc);
	len = strlen(grow);
	memcpy(buf, grow, len);
	assert(gwp_http_conn_process(hc, NULL, buf, &len, len, &host, &port,
				     &hl) == GWP_HTTP_TOO_LARGE);
	assert(len == strlen(grow) && !memcmp(buf, grow, len));
	gwp_http_conn_free(hc);
	PRTEST_OK();
}

/*
 * A request header may hold at most GWNET_HTTP_HDR_MAX_FIELDS (128) field
 * lines and 16 KiB; past either it is refused with 431 instead of being
 * parsed at a cost that grows with the square of the field count.
 */
static void test_header_limits(void)
{
	static char buf[20000];
	struct gwp_http_conn *hc;
	char *host, *port;
	const char *req = NULL;
	size_t req_len = 0, n;
	int i, r;

	/* Exactly at the limit: accepted. */
	n = (size_t)sprintf(buf, "GET http://example.com/ HTTP/1.1\r\n");
	for (i = 0; i < 128; i++)
		n += (size_t)sprintf(buf + n, "X-%d: v\r\n", i);
	n += (size_t)sprintf(buf + n, "\r\n");
	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, NULL, buf, &host, &port, &req, &req_len) ==
	       GWP_HTTP_FORWARD);
	gwp_http_conn_free(hc);

	/* One more field line, even a merged list field: refused. */
	sprintf(buf + n - 2, "Accept: a\r\n\r\n");
	hc = gwp_http_conn_alloc();
	assert(hc);
	r = proc(hc, NULL, buf, &host, &port, &req, &req_len, NULL);
	assert(r == GWP_HTTP_TOO_LARGE);
	gwp_http_conn_free(hc);

	/* A single field longer than 16 KiB: refused, not dropped. */
	n = (size_t)sprintf(buf, "GET http://example.com/ HTTP/1.1\r\nX: ");
	memset(buf + n, 'a', 17000);
	n += 17000;
	sprintf(buf + n, "\r\n\r\n");
	hc = gwp_http_conn_alloc();
	assert(hc);
	r = proc(hc, NULL, buf, &host, &port, &req, &req_len, NULL);
	assert(r == GWP_HTTP_TOO_LARGE);
	gwp_http_conn_free(hc);
	PRTEST_OK();
}

/*
 * The upstream proxy's CONNECT reply follows the same rules as an origin's
 * response: HTTP/1.0 or 1.1 only, a three-digit code ending at a space or
 * the line end, LF or CRLF line ends; bytes after the header are left alone.
 */
static void test_upstream_reply(void)
{
	static const struct {
		const char	*in;
		int		ret;
		int		status;
		size_t		consumed;
	} cases[] = {
		{ "HTTP/1.1 200 Connection established\r\n\r\n", 0, 200, 39 },
		{ "HTTP/1.0 200 OK\r\nVia: x\r\n\r\ntunnel", 0, 200, 27 },
		{ "HTTP/1.1 200\n\n", 0, 200, 14 },
		{ "HTTP/1.1 407 Auth\nX: y\r\n\r\n", 0, 407, 26 },
		{ "HTTP/1.1 200 OK\r\n", -EAGAIN, 0, 0 },
		{ "HTTP/1.1 200 OK\r\n\r", -EAGAIN, 0, 0 },
		{ "HTTP/1.x 200 OK\r\n\r\n", -EINVAL, 0, 0 },
		{ "HTTP/1.2 200 OK\r\n\r\n", -EINVAL, 0, 0 },
		{ "HTTP/1.1 2000 OK\r\n\r\n", -EINVAL, 0, 0 },
		{ "HTTP/1.1 20\r\n\r\n", -EINVAL, 0, 0 },
		{ "SSH-2.0-x\r\n\r\n", -EINVAL, 0, 0 },
	};
	size_t i, n, len, scan, consumed;
	int status, r;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		len = strlen(cases[i].in);
		consumed = 0;
		status = 0;
		scan = 0;
		r = gwp_http_cli_parse_connect_reply(cases[i].in, len, &scan,
						     &status, &consumed);
		assert(r == cases[i].ret);
		if (r == -EAGAIN)
			assert(scan <= len);
		if (r)
			continue;
		assert(status == cases[i].status);
		assert(consumed == cases[i].consumed);

		/*
		 * Received a byte at a time, the reply gives the same result
		 * the first time it is complete, and none before: the search
		 * resumes where it stopped and never passes the received
		 * bytes.
		 */
		scan = 0;
		for (n = 1; n <= len; n++) {
			consumed = 0;
			r = gwp_http_cli_parse_connect_reply(cases[i].in, n,
							     &scan, &status,
							     &consumed);
			if (n < cases[i].consumed) {
				assert(r == -EAGAIN && scan <= n);
				continue;
			}
			assert(!r && status == cases[i].status &&
			       consumed == cases[i].consumed);
			break;
		}
		assert(n == cases[i].consumed);
	}
	PRTEST_OK();
}

/*
 * The upstream CONNECT request carries the credentials as a Basic
 * Proxy-Authorization header. The URL parser accepts up to 255 bytes each
 * of user and password, so the longest pair must still build.
 */
static void test_upstream_connect(void)
{
	static const char hdr[] = "Proxy-Authorization: Basic ";
	static const char small[] =
		"CONNECT example.com:443 HTTP/1.1\r\n"
		"Host: example.com:443\r\n"
		"Proxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n"
		"\r\n";
	char user[255], pass[255], out[2048];
	const char *p;
	size_t len, i;
	int r;

	r = gwp_http_cli_build_connect("example.com:443", "Aladdin", 7,
				       "open sesame", 11, out, sizeof(out),
				       &len);
	assert(r == 0);
	assert(len == strlen(small));
	assert(!memcmp(out, small, len));

	memset(user, 'u', sizeof(user));
	memset(pass, 'p', sizeof(pass));
	r = gwp_http_cli_build_connect("h:1", user, sizeof(user), pass,
				       sizeof(pass), out, sizeof(out), &len);
	assert(r == 0);
	/* base64 of 255 + 1 + 255 = 511 bytes is 684 characters. */
	assert(len == strlen("CONNECT h:1 HTTP/1.1\r\nHost: h:1\r\n") +
		      strlen(hdr) + 684 + 2 + 2);
	p = memmem(out, len, hdr, strlen(hdr));
	assert(p);
	p += strlen(hdr);
	for (i = 0; i < 684; i++)
		assert(p[i] != '\r' && p[i] != '\n');
	assert(!memcmp(p + 684, "\r\n\r\n", 4));
	PRTEST_OK();
}

static void test_auth(void)
{
	static const char no_cred[] =
		"CONNECT example.com:443 HTTP/1.1\r\n\r\n";
	static const char good[] =	/* Basic base64("user:pass") */
		"CONNECT example.com:443 HTTP/1.1\r\n"
		"Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n";
	static const char bad[] =
		"CONNECT example.com:443 HTTP/1.1\r\n"
		"Proxy-Authorization: Basic dXNlcjp3cm9uZw==\r\n\r\n";
	static const char odd[] =	/* Basic base64("u\nx\0:wrong") */
		"CONNECT example.com:443 HTTP/1.1\r\n"
		"Proxy-Authorization: Basic dQp4ADp3cm9uZw==\r\n\r\n";
	static const char malformed[] =
		"CONNECT example.com:443 HTTP/1.1\r\n"
		"Proxy-Authorization: Basic !!!!\r\n\r\n";
	static const char cred_data[] = "user:pass\n";
	char cred_file[] = "/tmp/gwp_http_auth.XXXXXX";
	struct gwp_auth *auth = NULL;
	struct gwp_http_conn *hc;
	char *host, *port;
	const char *req = NULL, *user;
	size_t req_len = 0, ulen;
	uint8_t out[128];
	ssize_t w;
	int r;

	w = write_temp_file(cred_file, cred_data, sizeof(cred_data) - 1);
	assert(w == (ssize_t)(sizeof(cred_data) - 1));
	r = gwp_auth_create(&auth, cred_file);
	assert(!r);
	assert(auth);

	/* No credentials -> challenge. */
	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, auth, no_cred, &host, &port, &req, &req_len) == GWP_HTTP_NEED_AUTH);
	/* Not a failed login: nothing was tried. */
	assert(!gwp_http_conn_auth_failed(hc, &user, &ulen));
	gwp_http_conn_free(hc);

	/* Wrong credentials -> challenge, a failed login by "user". */
	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, auth, bad, &host, &port, &req, &req_len) == GWP_HTTP_NEED_AUTH);
	assert(gwp_http_conn_auth_failed(hc, &user, &ulen));
	assert(user && ulen == 4 && !memcmp(user, "user", 4));
	assert(!gwp_http_conn_username(hc));
	gwp_http_conn_free(hc);

	/* The username tried comes back whole, whatever its bytes. */
	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, auth, odd, &host, &port, &req, &req_len) == GWP_HTTP_NEED_AUTH);
	assert(gwp_http_conn_auth_failed(hc, &user, &ulen));
	assert(user && ulen == 4 && !memcmp(user, "u\nx\0", 4));
	gwp_http_conn_free(hc);

	/* Credentials that do not decode: a failure, with no username. */
	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, auth, malformed, &host, &port, &req, &req_len) == GWP_HTTP_NEED_AUTH);
	assert(gwp_http_conn_auth_failed(hc, &user, &ulen));
	assert(!user && !ulen);
	gwp_http_conn_free(hc);

	/* Correct credentials -> proceed. */
	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, auth, good, &host, &port, &req, &req_len) == GWP_HTTP_CONNECT);
	assert(!strcmp(host, "example.com"));
	assert(!gwp_http_conn_auth_failed(hc, &user, &ulen));
	gwp_http_conn_free(hc);

	/* The 407 challenge reply is well-formed and bounds-checked. */
	r = gwp_http_build_auth_required_reply(out, sizeof(out));
	assert(r > 0 && (size_t)r == strlen("HTTP/1.1 407 Proxy Authentication Required\r\n"
					    "Proxy-Authenticate: Basic realm=\"gwproxy\"\r\n"
					    "Content-Length: 0\r\n"
					    "Connection: close\r\n\r\n"));
	assert(!strncmp((char *)out, "HTTP/1.1 407 ", 13));
	assert(gwp_http_build_auth_required_reply(out, 5) == -ENOBUFS);

	gwp_auth_destroy(auth);
	unlink(cred_file);
	PRTEST_OK();
}

/*
 * The credential store indexes entries by username: every entry of a large
 * file must still be found, a duplicate username accepts each of its
 * passwords, and an empty password matches nobody.
 */
static void test_auth_store(void)
{
	char cred_file[] = "/tmp/gwp_http_auth.XXXXXX";
	struct gwp_auth *auth = NULL;
	char u[32], p[32], *data;
	size_t len = 0, cap = 64 * 1024;
	ssize_t w;
	int i;

	data = malloc(cap);
	assert(data);
	for (i = 0; i < 2000; i++)
		len += (size_t)snprintf(data + len, cap - len, "u%d:p%d\n", i, i);
	len += (size_t)snprintf(data + len, cap - len,
				"dup:one\ndup:two\n");
	w = write_temp_file(cred_file, data, len);
	assert(w == (ssize_t)len);
	free(data);
	assert(!gwp_auth_create(&auth, cred_file));

	for (i = 0; i < 2000; i++) {
		snprintf(u, sizeof(u), "u%d", i);
		snprintf(p, sizeof(p), "p%d", i);
		assert(gwp_auth_check(auth, u, strlen(u), p, strlen(p)));
		snprintf(p, sizeof(p), "p%d", i + 1);
		assert(!gwp_auth_check(auth, u, strlen(u), p, strlen(p)));
	}
	assert(!gwp_auth_check(auth, "u2000", 5, "p2000", 5));
	assert(!gwp_auth_check(auth, "u1", 2, "p10", 3));
	assert(!gwp_auth_check(auth, "u10", 3, "p1", 2));
	assert(gwp_auth_check(auth, "dup", 3, "one", 3));
	assert(gwp_auth_check(auth, "dup", 3, "two", 3));
	assert(!gwp_auth_check(auth, "dup", 3, "three", 5));
	assert(!gwp_auth_check(auth, "dup", 3, NULL, 0));
	assert(!gwp_auth_check(auth, "dup", 3, "", 0));
	assert(!gwp_auth_check(auth, "", 0, "", 0));

	gwp_auth_destroy(auth);
	unlink(cred_file);
	PRTEST_OK();
}

/*
 * The "Basic" token is base64 with optional padding and nothing after it: a
 * malformed token is refused even when its valid prefix decodes to the
 * right credentials.
 */
static void test_auth_basic_token(void)
{
	static const char cred_data[] = "user:pass\nab:c\nabc:d\n";
	static const struct {
		const char	*hdr;
		bool		ok;
	} cases[] = {
		{ "Basic dXNlcjpwYXNz",		true },	/* user:pass */
		{ "basic \tdXNlcjpwYXNz \t",	true },
		{ "Basic YWI6Yw==",		true },	/* ab:c */
		{ "Basic YWI6Yw",		true },	/* unpadded */
		{ "Basic YWJjOmQ=",		true },	/* abc:d */
		{ "Basic YWJjOmQ",		true },
		{ "Basic dXNlcjpwYXNz=",	false },
		{ "Basic dXNlcjpwYXNz==",	false },
		{ "Basic dXNlcjpwYXNz=x",	false },
		{ "Basic dXNlcjpwYXNzA",	false },
		{ "Basic dXNlcjpwYXNz x",	false },
		{ "Basic YWI6Yw==x",		false },
		{ "Basic YWI6Yw===",		false },
		{ "Basic YWI6Yw=",		false },
		{ "Basic YWI6Yw== YWI6Yw==",	false },
		{ "Basic YWJjOmQ==",		false },
		{ "Basic YWJjOmQ=dXNl",		false },
		{ "Basic =",			false },
		{ "Basic ",			false },
	};
	char cred_file[] = "/tmp/gwp_http_auth.XXXXXX";
	struct gwp_auth *auth = NULL;
	size_t i;
	ssize_t w;

	w = write_temp_file(cred_file, cred_data, sizeof(cred_data) - 1);
	assert(w == (ssize_t)(sizeof(cred_data) - 1));
	assert(!gwp_auth_create(&auth, cred_file));

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
		assert(gwp_auth_check_basic(auth, cases[i].hdr) == cases[i].ok);

	gwp_auth_destroy(auth);
	unlink(cred_file);
	PRTEST_OK();
}

int main(void)
{
	size_t i;

	for (i = 0; i < 1000; i++) {
		test_connect_ipv4();
		test_connect_ipv6();
		test_forward_get();
		test_forward_default_port();
		test_forward_authority_end();
		test_forward_hop_by_hop();
		test_forward_conn_lists_framing();
		test_forward_conn_limit();
		test_req_framing();
		test_res_rewrite();
		test_res_interim();
		test_res_reject();
		test_res_limits();
		test_res_direct();
		test_need_more();
		test_errors();
		test_duplicate_field();
		test_header_limits();
	test_forward_in_place();
		test_auth();
		test_upstream_reply();
		test_upstream_connect();
	}

	/* Byte-by-byte feeding of 17 KiB headers: once is enough. */
	test_incremental();
	test_auth_store();
	test_auth_basic_token();

	printf("All tests passed!\n");
	return 0;
}
