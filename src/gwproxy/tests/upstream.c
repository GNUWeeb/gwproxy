// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * Unit tests for the upstream handshake failure classes (upstream.h): every
 * way a handshake can end, and whose fault it is. Also the host an upstream
 * URL names, as TLS checks it.
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <gwproxy/upstream.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define U	GWP_UPSTREAM_FAIL_UPSTREAM
#define D	GWP_UPSTREAM_FAIL_DESTINATION
#define N	GWP_UPSTREAM_FAIL_NEUTRAL

static unsigned nr_checks;

static void check(enum gwp_upstream_end end, int val,
		  enum gwp_upstream_fail_class want, int line)
{
	enum gwp_upstream_fail_class got = gwp_upstream_fail_classify(end, val);

	if (got != want) {
		fprintf(stderr, "line %d: end=%d val=%d: got %s, want %s\n",
			line, (int)end, val, gwp_upstream_fail_class_str(got),
			gwp_upstream_fail_class_str(want));
		assert(0);
	}
	nr_checks++;
}

#define CHECK(end, val, want) check(GWP_UPSTREAM_END_##end, (val), (want), \
				    __LINE__)

/* TCP connect to the upstream: refused, timed out or reset count. */
static void test_connect(void)
{
	static const int up[] = {
		ECONNREFUSED, ETIMEDOUT, ECONNRESET, ECONNABORTED, EPIPE,
		EHOSTUNREACH, ENETUNREACH, EHOSTDOWN, ENETDOWN,
	};
	static const int local[] = {
		ENOMEM, EMFILE, ENFILE, ENOBUFS, EADDRNOTAVAIL, EAFNOSUPPORT,
		EINVAL, 0,
	};
	size_t i;

	for (i = 0; i < sizeof(up) / sizeof(up[0]); i++) {
		CHECK(CONNECT, up[i], U);
		CHECK(CONNECT, -up[i], U);	/* either sign */
	}
	for (i = 0; i < sizeof(local) / sizeof(local[0]); i++) {
		CHECK(CONNECT, local[i], N);
		CHECK(CONNECT, -local[i], N);
	}
}

/*
 * Out of time waiting for the CONNECT's reply: the destination may be the
 * one that does not answer, so it does not count.
 */
static void test_timeout_reply(void)
{
	CHECK(TIMEOUT, 1, N);
}

/* The ends that always count, whatever @val holds. */
static void test_always_upstream(void)
{
	CHECK(TLS, 0, U);
	CHECK(MALFORMED, 0, U);
	CHECK(HUP, 0, U);
	/* Out of time before the CONNECT was out: the upstream's. */
	CHECK(TIMEOUT, 0, U);

	/* No acceptable method, or one we never offered. */
	CHECK(S5_METHOD, 0xff, U);
	CHECK(S5_METHOD, 0x01, U);
	CHECK(S5_METHOD, 0x02, U);
	CHECK(S5_METHOD, 0x80, U);
}

static void test_s5_auth(void)
{
	int st;

	CHECK(S5_AUTH, 0x00, N);	/* not a failure */
	for (st = 0x01; st <= 0xff; st++)
		CHECK(S5_AUTH, st, U);
}

static void test_s5_rep(void)
{
	int rep;

	CHECK(S5_REP, 0x00, N);		/* succeeded: not a failure */
	CHECK(S5_REP, 0x01, N);		/* general failure */
	CHECK(S5_REP, 0x02, N);		/* not allowed by ruleset */
	CHECK(S5_REP, 0x03, D);		/* network unreachable */
	CHECK(S5_REP, 0x04, D);		/* host unreachable */
	CHECK(S5_REP, 0x05, D);		/* connection refused */
	CHECK(S5_REP, 0x06, D);		/* TTL expired */
	CHECK(S5_REP, 0x07, U);		/* command not supported */
	CHECK(S5_REP, 0x08, U);		/* address type not supported */
	for (rep = 0x09; rep <= 0xff; rep++)
		CHECK(S5_REP, rep, U);	/* unassigned */
}

static void test_http(void)
{
	int st;

	CHECK(HTTP, 407, U);
	CHECK(HTTP, 502, D);
	CHECK(HTTP, 504, D);
	CHECK(HTTP, 403, N);
	CHECK(HTTP, 500, N);
	CHECK(HTTP, 503, N);

	/* Every other status, 2xx (not a failure) or not, is neutral. */
	for (st = 100; st <= 599; st++) {
		if (st == 407 || st == 502 || st == 504)
			continue;
		CHECK(HTTP, st, N);
	}

	/* Not a status code at all: the reply is garbage. */
	CHECK(HTTP, -1, U);
	CHECK(HTTP, 0, U);
	CHECK(HTTP, 99, U);
	CHECK(HTTP, 600, U);
	CHECK(HTTP, 999, U);
}

static void test_str(void)
{
	assert(!strcmp(gwp_upstream_fail_class_str(U), "upstream"));
	assert(!strcmp(gwp_upstream_fail_class_str(D), "destination"));
	assert(!strcmp(gwp_upstream_fail_class_str(N), "neutral"));
}

static void check_host(const char *hostport, int want_r, const char *want,
		       bool want_ip, int line)
{
	char out[16];
	bool is_ip = !want_ip;
	int r;

	memset(out, 'x', sizeof(out));
	r = gwp_upstream_url_host(hostport, out, sizeof(out), &is_ip);
	if (r != want_r || (!r && (strcmp(out, want) || is_ip != want_ip))) {
		fprintf(stderr, "line %d: '%s': got %d '%.*s' ip=%d, want %d '%s' ip=%d\n",
			line, hostport, r, (int)sizeof(out), out, is_ip,
			want_r, want ? want : "", want_ip);
		assert(0);
	}
	nr_checks++;
}

#define HOST(hp, name, ip)	check_host((hp), 0, (name), (ip), __LINE__)
#define BAD_HOST(hp)		check_host((hp), -EINVAL, NULL, false, __LINE__)

/*
 * The host an https:// upstream is checked against: a DNS name goes out as
 * SNI and is matched against the certificate's names, an address literal is
 * matched against its IP addresses only.
 */
static void test_url_host(void)
{
	HOST("proxy.example:443", "proxy.example", false);
	HOST("proxy.example", "proxy.example", false);
	HOST("localhost:8080", "localhost", false);
	HOST("127.0.0.1:3128", "127.0.0.1", true);
	HOST("127.0.0.1", "127.0.0.1", true);
	HOST("[::1]:443", "::1", true);
	HOST("[2001:db8::7]", "2001:db8::7", true);
	/* Not an address literal inet_pton() accepts: a name. */
	HOST("127.1:80", "127.1", false);
	HOST("1.2.3.4.5:80", "1.2.3.4.5", false);
	/* Just fits: 15 bytes and the NUL. */
	HOST("abcdefghijklmno:1", "abcdefghijklmno", false);

	BAD_HOST("");
	BAD_HOST(":443");
	BAD_HOST("[]:443");
	BAD_HOST("[::1:443");
	BAD_HOST("abcdefghijklmnop:1");
}

int main(void)
{
	test_connect();
	test_always_upstream();
	test_timeout_reply();
	test_s5_auth();
	test_s5_rep();
	test_http();
	test_str();
	test_url_host();
	printf("upstream: %u checks passed\n", nr_checks);
	return 0;
}
