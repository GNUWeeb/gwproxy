// SPDX-License-Identifier: GPL-2.0-only
/*
 * Unit tests for the TLS wrapper (src/gwproxy/ssl.c).
 *
 * A server and a client gwp_ssl are driven entirely by shuttling ciphertext
 * between their BIOs (no sockets), verifying the handshake completes and
 * application data round-trips in both directions.
 *
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <gwproxy/ssl.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define PRTEST_OK()					\
do {							\
	static int __printed;				\
	if (!__printed) {				\
		printf("Test passed: %s\n", __func__);	\
		__printed = 1;				\
	}						\
} while (0)

/* A self-signed EC (P-256) cert for CN=localhost, valid until 2126. */
static const char TEST_CERT[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIBfzCCASWgAwIBAgIUPvYbMGhHdfIMP+X/E8o1e4VMb+gwCgYIKoZIzj0EAwIw\n"
"FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDcxNjA4NDgwNFoYDzIxMjYwNjIy\n"
"MDg0ODA0WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO\n"
"PQMBBwNCAAR6wF4KRXESxPLwqMguiJmwFPIZ8iVgTlIZaY/UgosFJXa/tUHwMIT3\n"
"hEKlMIPb/+ERhbYMdNsheDzzVbSqfMiqo1MwUTAdBgNVHQ4EFgQUP5HlkEkbJRH1\n"
"4enxbXvC7j/Ff5QwHwYDVR0jBBgwFoAUP5HlkEkbJRH14enxbXvC7j/Ff5QwDwYD\n"
"VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiBbe9xZmZ28FUwga7HbQj1T\n"
"t8X8v4sest0ur5TLXvoyLQIhAJ3v7q4XHONcNVhSXYO75YuGdGO9x8C4V0G82Yzz\n"
"7XW8\n"
"-----END CERTIFICATE-----\n";

static const char TEST_KEY[] =
"-----BEGIN PRIVATE KEY-----\n"
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg06tEro8+4H54N+6u\n"
"wTV6gRn6yqtpSjNe2b7OJQrnuiShRANCAAR6wF4KRXESxPLwqMguiJmwFPIZ8iVg\n"
"TlIZaY/UgosFJXa/tUHwMIT3hEKlMIPb/+ERhbYMdNsheDzzVbSqfMiq\n"
"-----END PRIVATE KEY-----\n";

static void write_file(const char *path, const char *data)
{
	FILE *f = fopen(path, "w");

	assert(f);
	assert(fwrite(data, 1, strlen(data), f) == strlen(data));
	fclose(f);
}

/* Move all pending ciphertext from @from's send BIO into @to's recv BIO. */
static void shuttle(struct gwp_ssl *from, struct gwp_ssl *to)
{
	static unsigned char buf[8192];	/* off-stack: keeps the frame small */
	int n;

	while ((n = gwp_ssl_bio_read(from, buf, sizeof(buf))) > 0)
		assert(gwp_ssl_bio_write(to, buf, (size_t)n) == n);
}

static void do_handshake(struct gwp_ssl *cli, struct gwp_ssl *srv)
{
	int cs, ss, rounds = 0;

	do {
		cs = gwp_ssl_handshake(cli);
		assert(cs != GWP_SSL_ERROR);
		shuttle(cli, srv);
		ss = gwp_ssl_handshake(srv);
		assert(ss != GWP_SSL_ERROR);
		shuttle(srv, cli);
		assert(++rounds < 32);
	} while (cs != GWP_SSL_OK || ss != GWP_SSL_OK);
}

/* Send @msg (@len bytes) as one plaintext write from @from and assert @to
 * decrypts exactly the same bytes. */
static void round_trip(struct gwp_ssl *from, struct gwp_ssl *to,
		       const char *msg, size_t len)
{
	static unsigned char out[65536];	/* off-stack: 64K is too big */
	size_t consumed = 0, got = 0, total = 0;
	int r;

	r = gwp_ssl_write(from, msg, len, &consumed);
	assert(r == GWP_SSL_OK && consumed == len);
	shuttle(from, to);

	/* One write may surface as several SSL_read()s. */
	while (total < len) {
		r = gwp_ssl_read(to, out + total, sizeof(out) - total, &got);
		assert(r == GWP_SSL_OK && got > 0);
		total += got;
	}
	assert(total == len);
	assert(!memcmp(out, msg, len));
}

static void test_handshake_and_roundtrip(void)
{
	char cert[] = "/tmp/gwp_ssl_cert.XXXXXX";
	char key[] = "/tmp/gwp_ssl_key.XXXXXX";
	struct gwp_ssl_ctx *sctx = NULL, *cctx = NULL;
	struct gwp_ssl *srv, *cli;
	char *big;
	size_t i;
	int fd, r;

	/* mkstemp to get unique names, then overwrite with the PEMs. */
	fd = mkstemp(cert); assert(fd >= 0); close(fd);
	fd = mkstemp(key); assert(fd >= 0); close(fd);
	write_file(cert, TEST_CERT);
	write_file(key, TEST_KEY);

	r = gwp_ssl_ctx_server_create(&sctx, cert, key);
	assert(!r && sctx);
	r = gwp_ssl_ctx_client_create(&cctx);
	assert(!r && cctx);

	srv = gwp_ssl_server_new(sctx);
	cli = gwp_ssl_client_new(cctx);
	assert(srv && cli);

	do_handshake(cli, srv);

	/* Small messages, both directions. */
	round_trip(cli, srv, "client -> server", strlen("client -> server"));
	round_trip(srv, cli, "server -> client reply", strlen("server -> client reply"));

	/* A large message spanning multiple TLS records. */
	big = malloc(40000);
	assert(big);
	for (i = 0; i < 40000; i++)
		big[i] = (char)(i * 31 + 7);
	round_trip(cli, srv, big, 40000);
	free(big);

	gwp_ssl_free(srv);
	gwp_ssl_free(cli);
	gwp_ssl_ctx_free(sctx);
	gwp_ssl_ctx_free(cctx);
	unlink(cert);
	unlink(key);
	PRTEST_OK();
}

/*
 * Move ciphertext the zero-copy way the epoll loop does: take it from the send
 * queue with peek/consume in small, uneven pieces, and hand it to the receive
 * queue through rx_space/rx_commit. Check that the plaintext arrives intact
 * when read with a small buffer, and that rx_more() reports exactly whether
 * another read can make progress.
 */
static void test_zero_copy_queues(void)
{
	char cert[] = "/tmp/gwp_ssl_cert.XXXXXX";
	char key[] = "/tmp/gwp_ssl_key.XXXXXX";
	struct gwp_ssl_ctx *sctx = NULL, *cctx = NULL;
	static unsigned char out[50000];
	size_t i, plen, len, consumed, got, total, chunk;
	struct gwp_ssl *srv, *cli;
	const unsigned char *p;
	unsigned char *dst;
	char *big;
	int fd, r;

	fd = mkstemp(cert); assert(fd >= 0); close(fd);
	fd = mkstemp(key); assert(fd >= 0); close(fd);
	write_file(cert, TEST_CERT);
	write_file(key, TEST_KEY);
	assert(!gwp_ssl_ctx_server_create(&sctx, cert, key));
	assert(!gwp_ssl_ctx_client_create(&cctx));
	srv = gwp_ssl_server_new(sctx);
	cli = gwp_ssl_client_new(cctx);
	assert(srv && cli);
	do_handshake(cli, srv);
	assert(!gwp_ssl_rx_more(srv));

	big = malloc(sizeof(out));
	assert(big);
	for (i = 0; i < sizeof(out); i++)
		big[i] = (char)(i * 13 + 5);
	r = gwp_ssl_write(cli, big, sizeof(out), &consumed);
	assert(r == GWP_SSL_OK && consumed == sizeof(out));
	assert(gwp_ssl_bio_pending(cli) > sizeof(out));

	for (chunk = 1; (p = gwp_ssl_bio_peek(cli, &plen)) != NULL; chunk++) {
		size_t n = (chunk * 977) % 3001 + 1;

		if (n > plen)
			n = plen;
		dst = gwp_ssl_rx_space(srv, n, &len);
		assert(dst && len >= n);
		memcpy(dst, p, n);
		gwp_ssl_rx_commit(srv, n);
		gwp_ssl_bio_consume(cli, n);
	}
	assert(gwp_ssl_bio_pending(cli) == 0);

	total = 0;
	while (gwp_ssl_rx_more(srv)) {
		size_t want = sizeof(out) - total;

		if (want > 1000)
			want = 1000;
		r = gwp_ssl_read(srv, out + total, want, &got);
		assert(r == GWP_SSL_OK || r == GWP_SSL_WANT_READ);
		total += got;
	}
	assert(total == sizeof(out));
	assert(!memcmp(out, big, sizeof(out)));
	free(big);

	gwp_ssl_free(srv);
	gwp_ssl_free(cli);
	gwp_ssl_ctx_free(sctx);
	gwp_ssl_ctx_free(cctx);
	unlink(cert);
	unlink(key);
	PRTEST_OK();
}

static void test_bad_cert_rejected(void)
{
	struct gwp_ssl_ctx *sctx = NULL;

	/* A nonexistent cert file must fail cleanly, not crash. */
	assert(gwp_ssl_ctx_server_create(&sctx, "/nonexistent/cert.pem",
					 "/nonexistent/key.pem") < 0);
	assert(sctx == NULL);
	PRTEST_OK();
}

static void test_alpn_negotiation(void)
{
	char cert[] = "/tmp/gwp_ssl_cert.XXXXXX";
	char key[] = "/tmp/gwp_ssl_key.XXXXXX";
	struct gwp_ssl_ctx *sctx = NULL, *cctx = NULL;
	/* h2 (preferred by the client) then http/1.1, in ALPN wire form. */
	static const unsigned char offer_both[] = {
		2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'
	};
	/* Only h2, which the server does not speak. */
	static const unsigned char offer_h2[] = { 2, 'h', '2' };
	struct gwp_ssl *srv, *cli;
	const char *sel;
	int fd, r;

	fd = mkstemp(cert); assert(fd >= 0); close(fd);
	fd = mkstemp(key); assert(fd >= 0); close(fd);
	write_file(cert, TEST_CERT);
	write_file(key, TEST_KEY);

	r = gwp_ssl_ctx_server_create(&sctx, cert, key); assert(!r && sctx);
	r = gwp_ssl_ctx_client_create(&cctx); assert(!r && cctx);

	/* Overlap: the server prefers and selects http/1.1 on both ends. */
	srv = gwp_ssl_server_new(sctx);
	cli = gwp_ssl_client_new(cctx);
	assert(srv && cli);
	assert(gwp_ssl_set_alpn(cli, offer_both, sizeof(offer_both)) == 0);
	do_handshake(cli, srv);
	sel = gwp_ssl_alpn(srv);
	assert(sel && !strcmp(sel, "http/1.1"));
	sel = gwp_ssl_alpn(cli);
	assert(sel && !strcmp(sel, "http/1.1"));
	gwp_ssl_free(srv);
	gwp_ssl_free(cli);

	/* No overlap: nothing is selected, but the handshake still succeeds. */
	srv = gwp_ssl_server_new(sctx);
	cli = gwp_ssl_client_new(cctx);
	assert(srv && cli);
	assert(gwp_ssl_set_alpn(cli, offer_h2, sizeof(offer_h2)) == 0);
	do_handshake(cli, srv);
	assert(gwp_ssl_alpn(srv) == NULL);
	gwp_ssl_free(srv);
	gwp_ssl_free(cli);

	gwp_ssl_ctx_free(sctx);
	gwp_ssl_ctx_free(cctx);
	unlink(cert);
	unlink(key);
	PRTEST_OK();
}

int main(void)
{
	size_t i;

	for (i = 0; i < 200; i++) {
		test_handshake_and_roundtrip();
		test_zero_copy_queues();
		test_bad_cert_rejected();
		test_alpn_negotiation();
	}

	printf("All tests passed!\n");
	return 0;
}
