// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <gwproxy/socks5.h>
#include <gwproxy/auth.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define test_socks5_init_ctx_no_auth(CTX)		\
do {							\
	struct gwp_socks5_ctx **__ctx = (CTX);		\
	int __r;					\
							\
	__r = gwp_socks5_ctx_init(__ctx, NULL);		\
	assert(!__r);					\
	assert(*__ctx);					\
	assert((*__ctx)->auth == NULL);			\
} while (0)

#define test_socks5_alloc_conn(CTX) ({			\
	struct gwp_socks5_ctx *__ctx = (CTX);		\
	struct gwp_socks5_conn *__conn;			\
							\
	__conn = gwp_socks5_conn_alloc(__ctx);		\
	assert(__conn);					\
	assert(__conn->state == GWP_SOCKS5_ST_INIT);	\
	assert(__conn->ctx == __ctx);			\
	(__conn);					\
})

#define test_socks5_do_handshake_no_auth(CTX, CONN)		\
do {								\
	static const uint8_t in[] = {				\
		0x05, 0x01, 0x00 /* VER, NMETHODS, METHOD */	\
	};							\
	struct gwp_socks5_conn *__conn = (CONN);		\
	size_t in_len, out_len;					\
	uint8_t out[10];					\
	int r;							\
								\
	in_len = sizeof(in);					\
	out_len = sizeof(out);					\
	r = gwp_socks5_conn_handle_data(__conn, in,		\
					&in_len, out,		\
					&out_len);		\
	assert(!r);						\
								\
	assert(in_len == 3);					\
	assert(out_len == 2);					\
	/* VER */						\
	assert(out[0] == 0x05);					\
	/* METHOD: NO AUTHENTICATION REQUIRED */		\
	assert(out[1] == 0x00);					\
	assert(conn->state == GWP_SOCKS5_ST_CMD);		\
} while (0)

static void test_connect_ipv4(void)
{
	/* Test connect to 127.0.0.1:80 */
	static const uint8_t in[] = {
		0x05, 0x01, 0x00, 0x01, /* VER, CMD, RSV, ATYP */
		0x7f, 0x00, 0x00, 0x01, /* DST.ADDR: 127.0.0.1 */
		0x00, 0x50              /* DST.PORT: 80 */
	};
	static const struct gwp_socks5_addr bind_addr = {
		.ver = GWP_SOCKS5_ATYP_IPV4,
		.port = 0xaaaa,
		.ip4 = { 0x7f, 0x00, 0x00, 0x01 }
	};
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;
	size_t in_len, out_len;
	uint8_t out[4096];
	int r;

	test_socks5_init_ctx_no_auth(&ctx);
	conn = test_socks5_alloc_conn(ctx);
	test_socks5_do_handshake_no_auth(ctx, conn);

	in_len = sizeof(in);
	out_len = sizeof(out);
	r = gwp_socks5_conn_handle_data(conn, in, &in_len, out, &out_len);
	assert(!r);
	assert(in_len == sizeof(in));
	assert(out_len == 0);
	assert(conn->state == GWP_SOCKS5_ST_CMD_CONNECT);
	assert(conn->dst_addr.ver == GWP_SOCKS5_ATYP_IPV4);
	assert(!memcmp(conn->dst_addr.ip4, "\x7f\x00\x00\x01", 4));
	assert(!memcmp(&conn->dst_addr.port, "\x00\x50", 2));

	/* Reply with connect success. */
	out_len = sizeof(out);
	r = gwp_socks5_conn_cmd_connect_res(conn, &bind_addr,
					    GWP_SOCKS5_REP_SUCCESS, out,
					    &out_len);
	assert(!r);
	assert(out_len == 10);
	/* VER */
	assert(out[0] == 0x05);
	/* REP: succeeded */
	assert(out[1] == 0x00);
	/* RSV */
	assert(out[2] == 0x00);
	/* ATYP: IPv4 address */
	assert(out[3] == GWP_SOCKS5_ATYP_IPV4);
	/* BND.ADDR */
	assert(!memcmp(&out[4], "\x7f\x00\x00\x01", 4));
	/* BND.PORT */
	assert(!memcmp(&out[8], "\xaa\xaa", 2));
	assert(conn->state == GWP_SOCKS5_ST_FORWARDING);

	/*
	 * All good!
	 *
	 * In a real application, we would start forwarding data
	 * between the client and the destination.
	 */
	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
}

static void test_connect_ipv6(void)
{
	/* Test connect to ::1:80 */
	static const uint8_t in[] = {
		0x05, 0x01, 0x00, 0x04, /* VER, CMD, RSV, ATYP */
		0x00, 0x00, 0x00, 0x00, /* DST.ADDR: ::1 */
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x50              /* DST.PORT: 80 */
	};
	static const struct gwp_socks5_addr bind_addr = {
		.ver = GWP_SOCKS5_ATYP_IPV6,
		.port = 0xaaaa,
		.ip6 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }
	};
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;
	size_t in_len, out_len;
	uint8_t out[4096];
	int r;

	test_socks5_init_ctx_no_auth(&ctx);
	conn = test_socks5_alloc_conn(ctx);
	test_socks5_do_handshake_no_auth(ctx, conn);

	in_len = sizeof(in);
	out_len = sizeof(out);
	r = gwp_socks5_conn_handle_data(conn, in, &in_len, out, &out_len);
	assert(!r);
	assert(in_len == sizeof(in));
	assert(out_len == 0);
	assert(conn->state == GWP_SOCKS5_ST_CMD_CONNECT);
	assert(conn->dst_addr.ver == GWP_SOCKS5_ATYP_IPV6);
	assert(!memcmp(conn->dst_addr.ip6, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 16));
	assert(!memcmp(&conn->dst_addr.port, "\x00\x50", 2));

	/* Reply with connect success. */
	out_len = sizeof(out);
	r = gwp_socks5_conn_cmd_connect_res(conn, &bind_addr,
					    GWP_SOCKS5_REP_SUCCESS, out,
					    &out_len);
	assert(!r);
	assert(out_len == 22);
	/* VER */
	assert(out[0] == 0x05);
	/* REP: succeeded */
	assert(out[1] == 0x00);
	/* RSV */
	assert(out[2] == 0x00);
	/* ATYP: IPv6 address */
	assert(out[3] == GWP_SOCKS5_ATYP_IPV6);
	/* BND.ADDR */
	assert(!memcmp(&out[4], "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 16));
	/* BND.PORT */
	assert(!memcmp(&out[20], "\xaa\xaa", 2));
	assert(conn->state == GWP_SOCKS5_ST_FORWARDING);

	/*
	 * All good!
	 *
	 * In a real application, we would start forwarding data
	 * between the client and the destination.
	 */
	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
}

static int test_connect_domain(void)
{
	static const uint8_t in[] = {
		0x05, 0x01, 0x00, 0x03, /* VER, CMD, RSV, ATYP */
		/* DST.ADDR: example.com */
		0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
		0x00, 0x50  /* DST.PORT: 80 */
	};
	static const struct gwp_socks5_addr bind_addr = {
		.ver = GWP_SOCKS5_ATYP_IPV4,
		.ip4 = { 0x7f, 0x00, 0x00, 0x01 },
		.port = 0xaaaa
	};
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;
	size_t in_len, out_len;
	uint8_t out[4096];
	int r;

	test_socks5_init_ctx_no_auth(&ctx);
	conn = test_socks5_alloc_conn(ctx);
	test_socks5_do_handshake_no_auth(ctx, conn);
	in_len = sizeof(in);
	out_len = sizeof(out);
	r = gwp_socks5_conn_handle_data(conn, in, &in_len, out, &out_len);
	assert(!r);
	assert(in_len == sizeof(in));
	assert(out_len == 0);
	assert(conn->state == GWP_SOCKS5_ST_CMD_CONNECT);
	assert(conn->dst_addr.ver == GWP_SOCKS5_ATYP_DOMAIN);
	assert(conn->dst_addr.domain.len == 11);
	assert(!memcmp(conn->dst_addr.domain.str, "example.com", 11));
	assert(!memcmp(&conn->dst_addr.port, "\x00\x50", 2));

	/* Reply with connect success. */
	out_len = sizeof(out);
	r = gwp_socks5_conn_cmd_connect_res(conn, &bind_addr,
					    GWP_SOCKS5_REP_SUCCESS, out,
					    &out_len);
	assert(!r);
	assert(out_len == 10);
	/* VER */
	assert(out[0] == 0x05);
	/* REP: succeeded */
	assert(out[1] == 0x00);
	/* RSV */
	assert(out[2] == 0x00);
	/* ATYP */
	assert(out[3] == GWP_SOCKS5_ATYP_IPV4);
	/* BND.ADDR */
	assert(!memcmp(&out[4], "\x7f\x00\x00\x01", 4));
	/* BND.PORT */
	assert(!memcmp(&out[8], "\xaa\xaa", 2));
	assert(conn->state == GWP_SOCKS5_ST_FORWARDING);

	/*
	 * All good!
	 *
	 * In a real application, we would start forwarding data
	 * between the client and the destination.
	 */
	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
	return 0;
}

static void test_short_recv(void)
{
	static const uint8_t in[] = {
		0x05, 0x01, 0x00, /* VER, NMETHODS, {NO AUTH} */

		0x05, 0x01, 0x00, 0x01, /* VER, CMD, RSV, ATYP */
		0x7f, 0x00, 0x00, 0x01, /* DST.ADDR: 127.0.0.1 */
		0x00, 0x50              /* DST.PORT: 80 */
	};
	static const struct gwp_socks5_addr bind_addr = {
		.ver = GWP_SOCKS5_ATYP_IPV4,
		.port = 0xaaaa,
		.ip4 = { 0x7f, 0x00, 0x00, 0x01 }
	};
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;
	size_t in_len, out_len;
	const uint8_t *inb;
	uint8_t out[4096];
	size_t i;
	int r;

	ctx = NULL;
	r = gwp_socks5_ctx_init(&ctx, NULL);
	assert(!r);
	assert(ctx);
	assert(ctx->auth == NULL);

	conn = gwp_socks5_conn_alloc(ctx);
	assert(conn);
	assert(conn->state == GWP_SOCKS5_ST_INIT);
	assert(conn->ctx == ctx);

	inb = in;
	for (i = 0; i < 3; i++) {
		in_len = i;
		out_len = sizeof(out);
		r = gwp_socks5_conn_handle_data(conn, inb, &in_len, out,
						&out_len);
		assert(r == -EAGAIN);
		assert(in_len == 0);
		assert(out_len == 0);
		assert(conn->state == GWP_SOCKS5_ST_INIT);
	}
	in_len = 3;
	out_len = sizeof(out);
	r = gwp_socks5_conn_handle_data(conn, inb, &in_len, out, &out_len);
	assert(!r);
	assert(in_len == 3);
	assert(out_len == 2);
	/* VER */
	assert(out[0] == 0x05);
	/* METHOD: NO AUTHENTICATION REQUIRED */
	assert(out[1] == 0x00);
	assert(conn->state == GWP_SOCKS5_ST_CMD);
	inb += in_len;

	for (i = 0; i < (sizeof(in) - 3); i++) {
		in_len = i;
		out_len = sizeof(out);
		r = gwp_socks5_conn_handle_data(conn, inb, &in_len, out,
						&out_len);
		assert(r == -EAGAIN);
		assert(in_len == 0);
		assert(out_len == 0);
		assert(conn->state == GWP_SOCKS5_ST_CMD);
	}
	out_len = sizeof(out);
	in_len = sizeof(in) - 3;
	r = gwp_socks5_conn_handle_data(conn, inb, &in_len, out, &out_len);
	assert(!r);
	assert(in_len == (sizeof(in) - 3));
	assert(out_len == 0);
	assert(conn->state == GWP_SOCKS5_ST_CMD_CONNECT);
	assert(conn->dst_addr.ver == GWP_SOCKS5_ATYP_IPV4);
	assert(!memcmp(conn->dst_addr.ip4, "\x7f\x00\x00\x01", 4));
	assert(!memcmp(&conn->dst_addr.port, "\x00\x50", 2));

	/* Reply with connect success. */
	out_len = sizeof(out);
	r = gwp_socks5_conn_cmd_connect_res(conn, &bind_addr,
					    GWP_SOCKS5_REP_SUCCESS, out,
					    &out_len);
	assert(!r);
	assert(out_len == 10);
	/* VER */
	assert(out[0] == 0x05);
	/* REP: succeeded */
	assert(out[1] == 0x00);
	/* RSV */
	assert(out[2] == 0x00);
	/* ATYP: IPv4 address */
	assert(out[3] == GWP_SOCKS5_ATYP_IPV4);
	/* BND.ADDR */
	assert(!memcmp(&out[4], "\x7f\x00\x00\x01", 4));
	/* BND.PORT */
	assert(!memcmp(&out[8], "\xaa\xaa", 2));
	assert(conn->state == GWP_SOCKS5_ST_FORWARDING);
	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
}

/*
 * Create a unique temporary file from @tmpl (an mkstemp(3) template, rewritten
 * in place with the chosen name) and write @len bytes of @data to it. Using
 * mkstemp() rather than opening a fixed path keeps each run's file unique and
 * owned by the current user; that matters under fs.protected_regular, where
 * (re)opening another user's file for writing in the sticky, world-writable
 * /tmp is denied even for root. The caller unlink()s @tmpl when done.
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

static void test_auth_userpass(void)
{
	static const uint8_t in[] = {
		0x05, 0x02, 0x01, 0x02,	/* VER, NMETHODS, {USER/PASS} */

		0x01,			/* VER  */
		0x04,			/* ULEN */
		'u', 's', 'e', 'r',	/* UNAME */
		0x04,			/* PLEN */
		'p', 'a', 's', 's',	/* PASSWD */

		0x05, 0x01, 0x00, 0x01, /* VER, CMD, RSV, ATYP */
		0x7f, 0x00, 0x00, 0x01, /* DST.ADDR: 127.0.0.1 */
		0x00, 0x50, /* DST.PORT: 80 */
	};
	static const char cred_data[] = "user:pass\n";
	char cred_file[] = "/tmp/gwp_socks5_auth.XXXXXX";
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;
	struct gwp_socks5_cfg cfg;
	struct gwp_auth *auth;
	size_t in_len, out_len;
	const uint8_t *inb;
	uint8_t out[4096];
	ssize_t r;

	r = write_temp_file(cred_file, cred_data, sizeof(cred_data) - 1);
	assert(r == (ssize_t)(sizeof(cred_data) - 1));

	r = gwp_auth_create(&auth, cred_file);
	assert(!r);
	assert(auth);
	cfg.auth = auth;
	cfg.udp_associate = true;
	r = gwp_socks5_ctx_init(&ctx, &cfg);
	assert(!r);
	assert(ctx);
	assert(ctx->auth == auth);

	conn = gwp_socks5_conn_alloc(ctx);
	assert(conn);
	assert(conn->state == GWP_SOCKS5_ST_INIT);
	assert(conn->ctx == ctx);

	inb = in;
	in_len = 4; /* VER, NMETHODS, {USER/PASS} */
	out_len = sizeof(out);
	r = gwp_socks5_conn_handle_data(conn, inb, &in_len, out, &out_len);
	assert(!r);
	assert(in_len == 4);
	assert(out_len == 2);

	/* VER, METHOD: USER/PASS */
	assert(out[0] == 0x05);
	assert(out[1] == 0x02);
	assert(conn->state == GWP_SOCKS5_ST_AUTH_USERPASS);

	inb += in_len;
	in_len = 11; /* VER, ULEN, UNAME, PLEN, PASSWD */
	out_len = sizeof(out);
	r = gwp_socks5_conn_handle_data(conn, inb, &in_len, out, &out_len);
	assert(!r);
	assert(in_len == 11);
	assert(out_len == 2);

	/* VER, REP: succeeded */
	assert(out[0] == 0x01);
	assert(out[1] == 0x00);
	assert(conn->state == GWP_SOCKS5_ST_CMD);
	inb += in_len;
	in_len = sizeof(in) - 15; /* Remaining data */
	out_len = sizeof(out);
	r = gwp_socks5_conn_handle_data(conn, inb, &in_len, out, &out_len);
	assert(!r);
	assert(in_len == (sizeof(in) - 15));
	assert(out_len == 0);
	assert(conn->state == GWP_SOCKS5_ST_CMD_CONNECT);
	assert(conn->dst_addr.ver == GWP_SOCKS5_ATYP_IPV4);
	assert(!memcmp(conn->dst_addr.ip4, "\x7f\x00\x00\x01", 4));
	assert(!memcmp(&conn->dst_addr.port, "\x00\x50", 2));

	/* Reply with connect success. */
	out_len = sizeof(out);
	r = gwp_socks5_conn_cmd_connect_res(conn, NULL,
					    GWP_SOCKS5_REP_SUCCESS, out,
					    &out_len);
	assert(!r);
	assert(out_len == 10);
	/* VER */
	assert(out[0] == 0x05);
	/* REP: succeeded */
	assert(out[1] == 0x00);
	/* RSV */
	assert(out[2] == 0x00);
	/* ATYP: IPv4 address */
	assert(out[3] == GWP_SOCKS5_ATYP_IPV4);
	/* BND.ADDR */
	assert(!memcmp(&out[4], "\x00\x00\x00", 4));
	/* BND.PORT */
	assert(!memcmp(&out[8], "\x00\x00", 2));
	assert(conn->state == GWP_SOCKS5_ST_FORWARDING);
	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
	gwp_auth_destroy(auth);
	unlink(cred_file);
}

/*
 * Load a credential file made of @data; returns gwp_auth_create()'s result
 * and destroys the store again.
 */
static int try_cred_file(const char *data)
{
	char cred_file[] = "/tmp/gwp_socks5_auth.XXXXXX";
	struct gwp_auth *auth = NULL;
	ssize_t w;
	int r;

	w = write_temp_file(cred_file, data, strlen(data));
	assert(w == (ssize_t)strlen(data));
	r = gwp_auth_create(&auth, cred_file);
	if (!r)
		gwp_auth_destroy(auth);
	unlink(cred_file);
	return r;
}

/*
 * The credential file takes "user:password" lines, both parts 1 to 255
 * bytes, plus comments and blank lines. A line with no colon used to become
 * a user with an empty password, which a client could log in as by sending
 * none (PLEN 0); a comment line did the same.
 */
/*
 * The password comparison walks a fixed number of positions whatever the
 * lengths; it must still match only the exact password: no prefix, no
 * extension, nothing longer than any stored password, and the longest one
 * a store can hold.
 */
static void test_auth_check_lengths(void)
{
	char cred_file[] = "/tmp/gwp_socks5_auth.XXXXXX";
	char data[16 + 256 + 1], pw[300];
	struct gwp_auth *auth;
	ssize_t r;
	int n;

	memset(pw, 'q', sizeof(pw));
	n = snprintf(data, sizeof(data), "user:pass\nlong:%.*s\n", 255, pw);
	assert(n > 0 && (size_t)n < sizeof(data));
	r = write_temp_file(cred_file, data, (size_t)n);
	assert(r == n);
	r = gwp_auth_create(&auth, cred_file);
	assert(!r);

	assert(gwp_auth_check(auth, "user", 4, "pass", 4));
	assert(!gwp_auth_check(auth, "user", 4, "pas", 3));
	assert(!gwp_auth_check(auth, "user", 4, "passs", 5));
	assert(!gwp_auth_check(auth, "user", 4, "pasS", 4));
	assert(!gwp_auth_check(auth, "user", 4, NULL, 0));
	assert(!gwp_auth_check(auth, "nouser", 6, "pass", 4));

	assert(gwp_auth_check(auth, "long", 4, pw, 255));
	assert(!gwp_auth_check(auth, "long", 4, pw, 254));
	assert(!gwp_auth_check(auth, "long", 4, pw, 256));
	assert(!gwp_auth_check(auth, "long", 4, pw, sizeof(pw)));
	pw[254] = 'r';
	assert(!gwp_auth_check(auth, "long", 4, pw, 255));

	gwp_auth_destroy(auth);
	unlink(cred_file);
}

static void test_auth_file_lines(void)
{
	char longline[5000];

	assert(!try_cred_file("# admins\n\nuser:pw\n  # indented\n"));
	assert(try_cred_file("user\n") == -EINVAL);
	assert(try_cred_file("user:pw\n#\nother\n") == -EINVAL);
	assert(try_cred_file("user:\n") == -EINVAL);
	assert(try_cred_file(":pw\n") == -EINVAL);

	/* Too long for one read: an error, not two entries. */
	memset(longline, 'a', sizeof(longline) - 2);
	longline[sizeof(longline) - 2] = '\n';
	longline[sizeof(longline) - 1] = '\0';
	memcpy(longline + 4100, ":pw", 3);
	assert(try_cred_file(longline) == -EINVAL);
}

/*
 * A client that sends no password (PLEN == 0) is refused, and the check is
 * made with p == NULL and plen == 0 without dereferencing the NULL password
 * pointer (a plain memcmp(NULL, ..., 0) is UB and trips UBSan).
 */
static void test_auth_userpass_empty_password(void)
{
	static const uint8_t in[] = {
		0x05, 0x01, 0x02,	/* VER, NMETHODS, {USER/PASS} */

		0x01,			/* VER  */
		0x04,			/* ULEN */
		'u', 's', 'e', 'r',	/* UNAME */
		0x00,			/* PLEN = 0 (no password) */
	};
	static const char cred_data[] = "user:pw\n";
	char cred_file[] = "/tmp/gwp_socks5_auth.XXXXXX";
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;
	struct gwp_socks5_cfg cfg;
	struct gwp_auth *auth;
	size_t in_len, out_len;
	const uint8_t *inb;
	uint8_t out[64];
	ssize_t r;

	r = write_temp_file(cred_file, cred_data, sizeof(cred_data) - 1);
	assert(r == (ssize_t)(sizeof(cred_data) - 1));

	r = gwp_auth_create(&auth, cred_file);
	assert(!r);
	assert(auth);
	cfg.auth = auth;
	cfg.udp_associate = true;
	r = gwp_socks5_ctx_init(&ctx, &cfg);
	assert(!r);
	assert(ctx);

	conn = gwp_socks5_conn_alloc(ctx);
	assert(conn);

	inb = in;
	in_len = 3; /* greeting */
	out_len = sizeof(out);
	r = gwp_socks5_conn_handle_data(conn, inb, &in_len, out, &out_len);
	assert(!r);
	assert(in_len == 3);
	assert(out_len == 2);
	assert(out[0] == 0x05);
	assert(out[1] == 0x02); /* METHOD: USER/PASS */
	assert(conn->state == GWP_SOCKS5_ST_AUTH_USERPASS);

	inb += in_len;
	in_len = 7; /* VER, ULEN, UNAME(4), PLEN */
	out_len = sizeof(out);
	r = gwp_socks5_conn_handle_data(conn, inb, &in_len, out, &out_len);
	assert(!r);
	assert(in_len == 7);
	assert(out_len == 2);
	assert(out[0] == 0x01);
	assert(out[1] == 0x01); /* STATUS: failure */
	assert(conn->state == GWP_SOCKS5_ST_ERR);
	/* The rejected name is kept for the log, not as the user. */
	assert(!gwp_socks5_conn_username(conn));
	{
		const char *bad;
		size_t blen = 0;

		bad = gwp_socks5_conn_rejected_user(conn, &blen);
		assert(bad && blen == 4 && !memcmp(bad, "user", 4));
	}

	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
	gwp_auth_destroy(auth);
	unlink(cred_file);
}

static void test_offered_methods_no_match(void)
{
	static const uint8_t in[] = {
		0x05, 0x05, /* VER, NMETHODS */
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e /* METHODS */
	};
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;
	size_t in_len, out_len;
	uint8_t out[10];
	int r;

	test_socks5_init_ctx_no_auth(&ctx);
	conn = test_socks5_alloc_conn(ctx);
	in_len = sizeof(in);
	out_len = sizeof(out);
	r = gwp_socks5_conn_handle_data(conn, in, &in_len, out, &out_len);
	assert(!r);
	assert(in_len == sizeof(in));
	assert(out_len == 2);
	/* VER */
	assert(out[0] == 0x05);
	/* REP: no acceptable methods */
	assert(out[1] == 0xff);
	assert(conn->state == GWP_SOCKS5_ST_ERR);
	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
}

/*
 * Regression test for the info-leak where the state driver's default case
 * returned without setting *out_len. A greeting with no acceptable method
 * moves the connection to ST_ERR while returning success; a byte pipelined
 * after it re-enters the driver in ST_ERR (the "default" case). The driver
 * must report the real number of bytes produced (2, the method reply), not
 * leave *out_len at the caller-supplied output buffer capacity -- otherwise
 * the caller flushes that many bytes of uninitialized heap to the client.
 */
static void test_err_state_pipelined_byte(void)
{
	static const uint8_t in[] = {
		0x05, 0x01, 0x02, /* VER, NMETHODS, {USER/PASS} -- unacceptable */
		0x00              /* one pipelined trailing byte */
	};
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;
	size_t in_len, out_len;
	uint8_t out[64];
	int r;

	test_socks5_init_ctx_no_auth(&ctx);
	conn = test_socks5_alloc_conn(ctx);
	in_len = sizeof(in);
	out_len = sizeof(out);
	r = gwp_socks5_conn_handle_data(conn, in, &in_len, out, &out_len);
	assert(r == -EINVAL);
	/* Only the 3 greeting bytes were consumed. */
	assert(in_len == 3);
	/* Only the 2-byte method reply was produced -- NOT sizeof(out). */
	assert(out_len == 2);
	/* VER */
	assert(out[0] == 0x05);
	/* METHOD: no acceptable methods */
	assert(out[1] == 0xff);
	assert(conn->state == GWP_SOCKS5_ST_ERR);
	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
}

static void test_invalid_version(void)
{
	static const uint8_t in[] = {
		0xaa, 0x02,	/* VER, NMETHODS */
		0x01, 0x02	/* METHODS */
	};
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;
	size_t in_len, out_len;
	uint8_t out[10];
	int r;

	test_socks5_init_ctx_no_auth(&ctx);
	conn = test_socks5_alloc_conn(ctx);
	in_len = sizeof(in);
	out_len = sizeof(out);
	r = gwp_socks5_conn_handle_data(conn, in, &in_len, out, &out_len);
	assert(r == -EINVAL);
	assert(in_len == 0);
	assert(out_len == 0);
	assert(conn->state == GWP_SOCKS5_ST_ERR);
	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
}

static void test_invalid_connect_addr_type(void)
{
	static const uint8_t in[] = {
		0x05, 0x01, 0x00, 0xff, /* VER, CMD, RSV, ATYP */
	};
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;
	size_t in_len, out_len;
	uint8_t out[10];
	int r;

	test_socks5_init_ctx_no_auth(&ctx);
	conn = test_socks5_alloc_conn(ctx);
	test_socks5_do_handshake_no_auth(ctx, conn);
	in_len = sizeof(in);
	out_len = sizeof(out);
	r = gwp_socks5_conn_handle_data(conn, in, &in_len, out, &out_len);
	assert(r == -EINVAL);
	assert(in_len == 0);
	assert(out_len == 10);
	/* VER */
	assert(out[0] == 0x05);
	/* REP: address type not supported */
	assert(out[1] == GWP_SOCKS5_REP_ATYP_NOT_SUPPORTED);
	/* RSV */
	assert(out[2] == 0x00);
	/* ATYP: IPv4 address */
	assert(out[3] == GWP_SOCKS5_ATYP_IPV4);
	/* BND.ADDR */
	assert(!memcmp(&out[4], "\x00\x00\x00\x00", 4));
	/* BND.PORT */
	assert(!memcmp(&out[8], "\x00\x00", 2));
	assert(conn->state == GWP_SOCKS5_ST_ERR);
	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
}

static void test_invalid_command(void)
{
	static const uint8_t in[] = {
		0x05, 0xff, 0x00, 0x01, /* VER, CMD, RSV, ATYP */
		0x7f, 0x00, 0x00, 0x01, /* DST.ADDR */
		0x00, 0x50              /* DST.PORT: 80 */
	};
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;
	size_t in_len, out_len;
	uint8_t out[10];
	int r;

	test_socks5_init_ctx_no_auth(&ctx);
	conn = test_socks5_alloc_conn(ctx);
	test_socks5_do_handshake_no_auth(ctx, conn);
	in_len = sizeof(in);
	out_len = sizeof(out);
	r = gwp_socks5_conn_handle_data(conn, in, &in_len, out, &out_len);
	assert(r == -EINVAL);
	assert(in_len == 0);
	assert(out_len == 10);
	/* VER */
	assert(out[0] == 0x05);
	/* REP: command not supported */
	assert(out[1] == GWP_SOCKS5_REP_COMMAND_NOT_SUPPORTED);
	/* RSV */
	assert(out[2] == 0x00);
	/* ATYP: IPv4 address */
	assert(out[3] == GWP_SOCKS5_ATYP_IPV4);
	/* BND.ADDR */
	assert(!memcmp(&out[4], "\x00\x00\x00\x00", 4));
	/* BND.PORT */
	assert(!memcmp(&out[8], "\x00\x00", 2));
	assert(conn->state == GWP_SOCKS5_ST_ERR);
	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
}

static void test_multi_state_at_once(void)
{
	static const uint8_t in[] = {
		0x05, 0x01, 0x00,	/* VER, NMETHODS, {NO AUTH} */

		0x05, 0x01, 0x00, 0x01, /* VER, CMD, RSV, ATYP */
		0x7f, 0x00, 0x00, 0x01, /* DST.ADDR: 127.0.0.1 */
		0x00, 0x50              /* DST.PORT: 80 */
	};
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;
	size_t in_len, out_len;
	uint8_t out[4096];
	int r;

	test_socks5_init_ctx_no_auth(&ctx);
	conn = test_socks5_alloc_conn(ctx);
	in_len = sizeof(in);
	out_len = sizeof(out);
	r = gwp_socks5_conn_handle_data(conn, in, &in_len, out, &out_len);
	assert(!r);
	assert(in_len == sizeof(in));
	assert(out_len == 2);
	/* VER */
	assert(out[0] == 0x05);
	/* METHOD: NO AUTHENTICATION REQUIRED */
	assert(out[1] == 0x00);
	assert(conn->state == GWP_SOCKS5_ST_CMD_CONNECT);
	assert(conn->dst_addr.ver == GWP_SOCKS5_ATYP_IPV4);
	assert(!memcmp(conn->dst_addr.ip4, "\x7f\x00\x00\x01", 4));
	assert(!memcmp(&conn->dst_addr.port, "\x00\x50", 2));

	out_len = sizeof(out);
	r = gwp_socks5_conn_cmd_connect_res(conn, NULL,
					    GWP_SOCKS5_REP_SUCCESS, out,
					    &out_len);
	assert(!r);
	assert(out_len == 10);
	/* VER */
	assert(out[0] == 0x05);
	/* REP: succeeded */
	assert(out[1] == 0x00);
	/* RSV */
	assert(out[2] == 0x00);
	/* ATYP: IPv4 address */
	assert(out[3] == GWP_SOCKS5_ATYP_IPV4);
	/* BND.ADDR */
	assert(!memcmp(&out[4], "\x00\x00\x00\x00", 4));
	/* BND.PORT */
	assert(!memcmp(&out[8], "\x00\x00", 2));
	assert(conn->state == GWP_SOCKS5_ST_FORWARDING);
	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
}

static void test_enobufs(void)
{
	static const uint8_t in[] = {
		0x05, 0x01, 0x00, /* VER, NMETHODS, {NO AUTH} */

		0x05, 0x01, 0x00, 0x01, /* VER, CMD, RSV, ATYP */
		0x7f, 0x00, 0x00, 0x01, /* DST.ADDR: 127.0.0.1 */
		0x00, 0x50              /* DST.PORT: 80 */
	};
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;
	size_t in_len, out_len;
	const uint8_t *inb = in;
	uint8_t out[4096];
	size_t i;
	int r;

	test_socks5_init_ctx_no_auth(&ctx);
	conn = test_socks5_alloc_conn(ctx);

	/*
	 * Prepare authentication data.
	 */
	in_len = 3;
	out_len = 1;
	r = gwp_socks5_conn_handle_data(conn, inb, &in_len, out, &out_len);
	assert(r == -ENOBUFS);
	assert(in_len == 0);
	assert(out_len == 0);

	in_len = 3;
	out_len = 2;
	r = gwp_socks5_conn_handle_data(conn, inb, &in_len, out, &out_len);
	assert(!r);
	assert(in_len == 3);
	assert(out_len == 2);
	assert(out[0] == 0x05); /* VER */
	assert(out[1] == 0x00); /* METHOD: NO AUTHENTICATION REQUIRED */
	assert(conn->state == GWP_SOCKS5_ST_CMD);
	inb += in_len;

	/*
	 * Prepare connect data.
	 */
	in_len = 10;
	out_len = 0;
	r = gwp_socks5_conn_handle_data(conn, inb, &in_len, out, &out_len);
	assert(!r);
	assert(in_len == 10);
	assert(out_len == 0);
	assert(conn->state == GWP_SOCKS5_ST_CMD_CONNECT);
	assert(conn->dst_addr.ver == GWP_SOCKS5_ATYP_IPV4);
	assert(!memcmp(conn->dst_addr.ip4, "\x7f\x00\x00\x01", 4));
	assert(!memcmp(&conn->dst_addr.port, "\x00\x50", 2));

	for (i = 0; i < 10; i++) {
		out_len = i;
		r = gwp_socks5_conn_cmd_connect_res(conn, NULL,
						    GWP_SOCKS5_REP_SUCCESS, out,
						    &out_len);
		assert(r == -ENOBUFS);
		assert(out_len == 0);
		assert(conn->state == GWP_SOCKS5_ST_CMD_CONNECT);
	}

	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
}

static void test_enobufs_combined_with_multi_state_at_once(void)
{
	static const uint8_t in[] = {
		0x05, 0x02, 0x01, 0x02,	/* VER, NMETHODS, {USER/PASS} */

		0x01,			/* VER  */
		0x04,			/* ULEN */
		'u', 's', 'e', 'r',	/* UNAME */
		0x04,			/* PLEN */
		'p', 'a', 's', 's',	/* PASSWD */

		0x05, 0x01, 0x00, 0x01, /* VER, CMD, RSV, ATYP */
		0x7f, 0x00, 0x00, 0x01, /* DST.ADDR: 127.0.0.1 */
		0x00, 0x50, /* DST.PORT: 80 */
	};
	static const char cred_data[] = "user:pass\n";
	char cred_file[] = "/tmp/gwp_socks5_auth.XXXXXX";
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;
	struct gwp_socks5_cfg cfg;
	struct gwp_auth *auth;
	size_t in_len, out_len;
	uint8_t out[4096];
	ssize_t r;
	size_t i;

	r = write_temp_file(cred_file, cred_data, sizeof(cred_data) - 1);
	assert(r == (ssize_t)(sizeof(cred_data) - 1));

	r = gwp_auth_create(&auth, cred_file);
	assert(!r);
	assert(auth);
	cfg.auth = auth;
	cfg.udp_associate = true;
	r = gwp_socks5_ctx_init(&ctx, &cfg);
	assert(!r);
	assert(ctx);
	assert(ctx->auth == auth);

	conn = gwp_socks5_conn_alloc(ctx);
	assert(conn);
	assert(conn->state == GWP_SOCKS5_ST_INIT);
	assert(conn->ctx == ctx);

	for (i = 0; i < 4; i++) {
		in_len = sizeof(in);
		out_len = i;
		r = gwp_socks5_conn_handle_data(conn, in, &in_len, out, &out_len);
		assert(r == -ENOBUFS);
		assert(in_len == 0);
		/* Nothing is consumed, so nothing is reported written. */
		assert(out_len == 0);
		assert(conn->state == GWP_SOCKS5_ST_INIT);
	}

	in_len = sizeof(in);
	out_len = 4;
	r = gwp_socks5_conn_handle_data(conn, in, &in_len, out, &out_len);
	assert(!r);
	assert(in_len == sizeof(in));
	assert(out_len == 4);
	assert(out[0] == 0x05); /* VER */
	assert(out[1] == 0x02); /* METHOD: USER/PASS */
	assert(conn->state == GWP_SOCKS5_ST_CMD_CONNECT);
	assert(!strcmp(gwp_socks5_conn_username(conn), "user"));
	assert(!gwp_socks5_conn_rejected_user(conn, &in_len));
	assert(conn->dst_addr.ver == GWP_SOCKS5_ATYP_IPV4);
	assert(!memcmp(conn->dst_addr.ip4, "\x7f\x00\x00\x01", 4));
	assert(!memcmp(&conn->dst_addr.port, "\x00\x50", 2));

	/* Reply with connect success. */
	for (i = 0; i < 10; i++) {
		out_len = i;
		r = gwp_socks5_conn_cmd_connect_res(conn, NULL,
						    GWP_SOCKS5_REP_SUCCESS, out,
						    &out_len);
		assert(r == -ENOBUFS);
		assert(out_len == 0);
		assert(conn->state == GWP_SOCKS5_ST_CMD_CONNECT);
	}

	out_len = sizeof(out);
	r = gwp_socks5_conn_cmd_connect_res(conn, NULL,
					    GWP_SOCKS5_REP_SUCCESS, out,
					    &out_len);
	assert(!r);
	assert(out_len == 10);
	/* VER */
	assert(out[0] == 0x05);
	/* REP: succeeded */
	assert(out[1] == 0x00);
	/* RSV */
	assert(out[2] == 0x00);
	/* ATYP: IPv4 address */
	assert(out[3] == GWP_SOCKS5_ATYP_IPV4);
	/* BND.ADDR */
	assert(!memcmp(&out[4], "\x00\x00\x00\x00", 4));
	/* BND.PORT */
	assert(!memcmp(&out[8], "\x00\x00", 2));
	assert(conn->state == GWP_SOCKS5_ST_FORWARDING);
	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
	gwp_auth_destroy(auth);
	unlink(cred_file);
}

static void test_udp_associate(void)
{
	/* UDP ASSOCIATE with DST 0.0.0.0:0 (client source not yet known). */
	static const uint8_t in[] = {
		0x05, 0x03, 0x00, 0x01, /* VER, CMD=UDP ASSOCIATE, RSV, ATYP */
		0x00, 0x00, 0x00, 0x00, /* DST.ADDR: 0.0.0.0 */
		0x00, 0x00              /* DST.PORT: 0 */
	};
	static const struct gwp_socks5_addr bind_addr = {
		.ver = GWP_SOCKS5_ATYP_IPV4,
		.port = 0xaaaa,
		.ip4 = { 0x7f, 0x00, 0x00, 0x01 }
	};
	struct gwp_socks5_conn *conn;
	struct gwp_socks5_ctx *ctx;
	size_t in_len, out_len;
	uint8_t out[64];
	int r;

	test_socks5_init_ctx_no_auth(&ctx);
	conn = test_socks5_alloc_conn(ctx);
	test_socks5_do_handshake_no_auth(ctx, conn);

	in_len = sizeof(in);
	out_len = sizeof(out);
	r = gwp_socks5_conn_handle_data(conn, in, &in_len, out, &out_len);
	assert(!r);
	assert(in_len == sizeof(in));
	assert(out_len == 0);
	assert(conn->state == GWP_SOCKS5_ST_CMD_UDP_ASSOCIATE);

	/* Reply with the relay endpoint. */
	out_len = sizeof(out);
	r = gwp_socks5_conn_cmd_udp_associate_res(conn, &bind_addr,
						  GWP_SOCKS5_REP_SUCCESS, out,
						  &out_len);
	assert(!r);
	assert(out_len == 10);
	assert(out[0] == 0x05);			/* VER */
	assert(out[1] == 0x00);			/* REP: success */
	assert(out[2] == 0x00);			/* RSV */
	assert(out[3] == GWP_SOCKS5_ATYP_IPV4);	/* ATYP */
	assert(!memcmp(&out[4], "\x7f\x00\x00\x01", 4));	/* BND.ADDR */
	assert(!memcmp(&out[8], "\xaa\xaa", 2));		/* BND.PORT */
	assert(conn->state == GWP_SOCKS5_ST_UDP_ASSOCIATED);

	gwp_socks5_conn_free(conn);
	gwp_socks5_ctx_free(ctx);
}

static void test_udp_hdr_codec(void)
{
	struct gwp_socks5_addr a, got;
	uint8_t buf[GWP_SOCKS5_UDP_HDR_MAX + 16];
	uint8_t dg[128];
	size_t hlen, plen;
	int r;

	/* IPv4 round-trip, with trailing DATA on parse. */
	memset(&a, 0, sizeof(a));
	a.ver = GWP_SOCKS5_ATYP_IPV4;
	memcpy(a.ip4, "\x08\x08\x08\x08", 4);
	memcpy(&a.port, "\x00\x35", 2);		/* 53 */
	r = gwp_socks5_udp_build_hdr(&a, buf, sizeof(buf), &hlen);
	assert(!r && hlen == 3 + 1 + 4 + 2);
	assert(buf[0] == 0 && buf[1] == 0 && buf[2] == 0);
	assert(buf[3] == GWP_SOCKS5_ATYP_IPV4);
	memcpy(dg, buf, hlen);
	memcpy(dg + hlen, "hello", 5);
	r = gwp_socks5_udp_parse_hdr(dg, hlen + 5, &got, &plen);
	assert(!r && plen == hlen);
	assert(got.ver == GWP_SOCKS5_ATYP_IPV4);
	assert(!memcmp(got.ip4, a.ip4, 4));
	assert(!memcmp(&got.port, &a.port, 2));
	assert(!memcmp(dg + plen, "hello", 5));

	/* IPv6 round-trip. */
	memset(&a, 0, sizeof(a));
	a.ver = GWP_SOCKS5_ATYP_IPV6;
	memcpy(a.ip6, "\x20\x01\x0d\xb8\x00\x00\x00\x00"
		      "\x00\x00\x00\x00\x00\x00\x00\x01", 16);
	memcpy(&a.port, "\x01\xbb", 2);		/* 443 */
	r = gwp_socks5_udp_build_hdr(&a, buf, sizeof(buf), &hlen);
	assert(!r && hlen == 3 + 1 + 16 + 2);
	r = gwp_socks5_udp_parse_hdr(buf, hlen, &got, &plen);
	assert(!r && plen == hlen && got.ver == GWP_SOCKS5_ATYP_IPV6);
	assert(!memcmp(got.ip6, a.ip6, 16));

	/* Domain round-trip. */
	memset(&a, 0, sizeof(a));
	a.ver = GWP_SOCKS5_ATYP_DOMAIN;
	a.domain.len = 11;
	memcpy(a.domain.str, "example.com", 12);
	memcpy(&a.port, "\x00\x50", 2);
	r = gwp_socks5_udp_build_hdr(&a, buf, sizeof(buf), &hlen);
	assert(!r && hlen == 3 + 1 + 1 + 11 + 2);
	r = gwp_socks5_udp_parse_hdr(buf, hlen, &got, &plen);
	assert(!r && got.ver == GWP_SOCKS5_ATYP_DOMAIN && got.domain.len == 11);
	assert(!memcmp(got.domain.str, "example.com", 11));

	/* FRAG != 0 -> unsupported. */
	memcpy(dg, "\x00\x00\x01\x01\x08\x08\x08\x08\x00\x35", 10);
	r = gwp_socks5_udp_parse_hdr(dg, 10, &got, &plen);
	assert(r == -ENOTSUP);

	/* Truncated header -> need more. */
	r = gwp_socks5_udp_parse_hdr(dg, 3, &got, &plen);
	assert(r == -EAGAIN);

	/* Unknown ATYP -> malformed. */
	memcpy(dg, "\x00\x00\x00\x09\x00\x00\x00\x00", 8);
	r = gwp_socks5_udp_parse_hdr(dg, 8, &got, &plen);
	assert(r == -EINVAL);

	/* Build into too small a buffer. */
	r = gwp_socks5_udp_build_hdr(&a, buf, 4, &hlen);
	assert(r == -ENOBUFS);
}

static void gwp_socks5_run_tests(void)
{
	size_t i;

	/* Once: each refused file prints its parse error. */
	test_auth_file_lines();
	test_auth_check_lengths();

	for (i = 0; i < 5000; i++) {
		test_udp_associate();
		test_udp_hdr_codec();
		test_connect_ipv4();
		test_connect_ipv6();
		test_connect_domain();
		test_short_recv();
		test_auth_userpass();
		test_auth_userpass_empty_password();
		test_offered_methods_no_match();
		test_err_state_pipelined_byte();
		test_invalid_version();
		test_invalid_connect_addr_type();
		test_invalid_command();
		test_multi_state_at_once();
		test_enobufs();
		test_enobufs_combined_with_multi_state_at_once();
	}

	printf("All tests passed!\n");
}

int main(void)
{
	gwp_socks5_run_tests();
	return 0;
}
