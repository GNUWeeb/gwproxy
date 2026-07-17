// SPDX-License-Identifier: GPL-2.0-only
/*
 * Unit tests for the HTTP proxy module (src/gwproxy/http.c).
 *
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */
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

/* Run gwp_http_conn_process() on a full request buffer in one shot. */
static int run(struct gwp_http_conn *hc, struct gwp_auth *auth, const char *buf,
	       char **host, char **port, const char **req, size_t *req_len)
{
	size_t in_len = strlen(buf);
	int r = gwp_http_conn_process(hc, auth, buf, &in_len, host, port, req,
				      req_len);

	/* On a complete request the whole buffer is consumed. */
	if (r != GWP_HTTP_NEED_MORE && r != GWP_HTTP_ERR)
		assert(in_len == strlen(buf));
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

static void test_need_more(void)
{
	/* Request line complete, header fields not yet terminated. */
	static const char part1[] = "CONNECT example.com:443 HTTP/1.1\r\n";
	static const char part2[] = "\r\n";
	struct gwp_http_conn *hc = gwp_http_conn_alloc();
	char *host, *port;
	const char *req = NULL;
	size_t req_len = 0, in_len;
	int r;

	assert(hc);
	in_len = strlen(part1);
	r = gwp_http_conn_process(hc, NULL, part1, &in_len, &host, &port, &req,
				  &req_len);
	assert(r == GWP_HTTP_NEED_MORE);
	assert(in_len == strlen(part1));	/* request line consumed */

	/* Feeding the terminating blank line completes the request. */
	in_len = strlen(part2);
	r = gwp_http_conn_process(hc, NULL, part2, &in_len, &host, &port, &req,
				  &req_len);
	assert(r == GWP_HTTP_CONNECT);
	assert(!strcmp(host, "example.com"));
	assert(!strcmp(port, "443"));
	gwp_http_conn_free(hc);
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
	static const char cred_data[] = "user:pass\n";
	char cred_file[] = "/tmp/gwp_http_auth.XXXXXX";
	struct gwp_auth *auth = NULL;
	struct gwp_http_conn *hc;
	char *host, *port;
	const char *req = NULL;
	size_t req_len = 0;
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
	gwp_http_conn_free(hc);

	/* Wrong credentials -> challenge. */
	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, auth, bad, &host, &port, &req, &req_len) == GWP_HTTP_NEED_AUTH);
	gwp_http_conn_free(hc);

	/* Correct credentials -> proceed. */
	hc = gwp_http_conn_alloc();
	assert(hc);
	assert(run(hc, auth, good, &host, &port, &req, &req_len) == GWP_HTTP_CONNECT);
	assert(!strcmp(host, "example.com"));
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

int main(void)
{
	size_t i;

	for (i = 0; i < 1000; i++) {
		test_connect_ipv4();
		test_connect_ipv6();
		test_forward_get();
		test_forward_default_port();
		test_forward_hop_by_hop();
		test_need_more();
		test_errors();
		test_auth();
	}

	printf("All tests passed!\n");
	return 0;
}
