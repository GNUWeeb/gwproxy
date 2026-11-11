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
#include <openssl/bio.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
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

/*
 * A test CA (CN=gwproxy test CA) and a certificate it issued for CN=localhost,
 * with the subject alternative names DNS:localhost and IP:127.0.0.1, all EC
 * P-256 and valid until 2126.
 */
static const char TEST_CA_CERT[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIBijCCATGgAwIBAgIUdmtgOZOQ6M2M87YcJo4bpomWILowCgYIKoZIzj0EAwIw\n"
"GjEYMBYGA1UEAwwPZ3dwcm94eSB0ZXN0IENBMCAXDTI2MTEwNDEyNTAxMVoYDzIx\n"
"MjYxMDExMTI1MDExWjAaMRgwFgYDVQQDDA9nd3Byb3h5IHRlc3QgQ0EwWTATBgcq\n"
"hkjOPQIBBggqhkjOPQMBBwNCAARCfbSzUzoN7AiHkpEaoV3y5+v3OuSAPElwr0B0\n"
"BiABNrQMZvD6jkHjebaoSCyjTwYgwjNBEr2XIItKhcBPQFCAo1MwUTAdBgNVHQ4E\n"
"FgQUEcmCb88puKbw6w+neIq+7ipd9CQwHwYDVR0jBBgwFoAUEcmCb88puKbw6w+n\n"
"eIq+7ipd9CQwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiADvTRt\n"
"ObPvNBLqk8KWgYhbz1hPpBBGOVxPQHY1mv/RgQIgVNo+hhS7j2nX8z39kif8jKKR\n"
"iK8uL+fmXmZICTBcSSM=\n"
"-----END CERTIFICATE-----\n";

static const char TEST_LEAF_CERT[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIBiDCCAS6gAwIBAgIBAjAKBggqhkjOPQQDAjAaMRgwFgYDVQQDDA9nd3Byb3h5\n"
"IHRlc3QgQ0EwIBcNMjYxMTA0MTI1MDExWhgPMjEyNjEwMTExMjUwMTFaMBQxEjAQ\n"
"BgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJwM6Xq7\n"
"MJtMwi+4QYRauLacxzASgvzc50wSJ+jhbxEn2MRFgJWYTprDTiHYXpyu1WEcjp+q\n"
"23uGG2S6xQvkaxejaTBnMBoGA1UdEQQTMBGCCWxvY2FsaG9zdIcEfwAAATAJBgNV\n"
"HRMEAjAAMB0GA1UdDgQWBBQ3BWRqk7adYz0iAlbomHqfNOcqtzAfBgNVHSMEGDAW\n"
"gBQRyYJvzym4pvDrD6d4ir7uKl30JDAKBggqhkjOPQQDAgNIADBFAiEA0wLDqAhQ\n"
"p1njFASQxnCQcYJUceVfWUxRzBAjs/OJWQACIBdrf6S5chcu7ot9fosmEvHNU/lM\n"
"gm26ye7zrIZL+BGE\n"
"-----END CERTIFICATE-----\n";

static const char TEST_LEAF_KEY[] =
"-----BEGIN PRIVATE KEY-----\n"
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJcGrlbi40+/sz75z\n"
"qTdjaKblRCSMdD9yltollifQqqShRANCAAScDOl6uzCbTMIvuEGEWri2nMcwEoL8\n"
"3OdMEifo4W8RJ9jERYCVmE6aw04h2F6crtVhHI6fqtt7hhtkusUL5GsX\n"
"-----END PRIVATE KEY-----\n";

/*
 * A certificate the same CA issued with CN=localhost and no subject
 * alternative names at all, valid until 2126: a name is checked against the
 * DNS names alone, never against the CN.
 */
static const char TEST_CN_ONLY_CERT[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIBbTCCARKgAwIBAgIBAzAKBggqhkjOPQQDAjAaMRgwFgYDVQQDDA9nd3Byb3h5\n"
"IHRlc3QgQ0EwIBcNMjYxMTA0MTQyNjIzWhgPMjEyNjEwMTExNDI2MjNaMBQxEjAQ\n"
"BgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIZlp+zf\n"
"A6y3jXmwoC1VXQyN/tTScHT4dcciyYWoEpUGCZkPQFMBF4TUJipp9GH/5hgf2eAk\n"
"CylQG3ZRXXg/L5KjTTBLMAkGA1UdEwQCMAAwHQYDVR0OBBYEFEw5/zCY8EFJEj4H\n"
"Mal79U7Bqyj0MB8GA1UdIwQYMBaAFBHJgm/PKbim8OsPp3iKvu4qXfQkMAoGCCqG\n"
"SM49BAMCA0kAMEYCIQCvojZsDGTxLE0PDMAX341i+6wGU/Xdg48B1QgG+YK7CgIh\n"
"ALJSAN7jencHiHEwfemfHNQMLS/hqbN2nS17gmWd/HS7\n"
"-----END CERTIFICATE-----\n";

static const char TEST_CN_ONLY_KEY[] =
"-----BEGIN PRIVATE KEY-----\n"
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/NcxJd1YMpavg1Ih\n"
"ZSfIM65ZBeNq28/NYawmPdPNIUyhRANCAASGZafs3wOst415sKAtVV0Mjf7U0nB0\n"
"+HXHIsmFqBKVBgmZD0BTAReE1CYqafRh/+YYH9ngJAspUBt2UV14Py+S\n"
"-----END PRIVATE KEY-----\n";

/* Linked with --wrap=BIO_meth_new, so that the call can be made to fail. */
static bool bio_meth_new_fails;
BIO_METHOD *__real_BIO_meth_new(int type, const char *name);
BIO_METHOD *__wrap_BIO_meth_new(int type, const char *name);

BIO_METHOD *__wrap_BIO_meth_new(int type, const char *name)
{
	if (bio_meth_new_fails)
		return NULL;
	return __real_BIO_meth_new(type, name);
}

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
 * A write that the engine cannot take before it has heard from the peer says
 * so until ciphertext has been received: a write before the handshake, which
 * sends the ClientHello and waits for the answer, is one.
 */
static void test_tx_starved(void)
{
	char cert[] = "/tmp/gwp_ssl_cert.XXXXXX";
	char key[] = "/tmp/gwp_ssl_key.XXXXXX";
	struct gwp_ssl_ctx *sctx = NULL, *cctx = NULL;
	struct gwp_ssl *srv, *cli;
	size_t consumed;
	int fd;

	fd = mkstemp(cert); assert(fd >= 0); close(fd);
	fd = mkstemp(key); assert(fd >= 0); close(fd);
	write_file(cert, TEST_CERT);
	write_file(key, TEST_KEY);
	assert(!gwp_ssl_ctx_server_create(&sctx, cert, key));
	assert(!gwp_ssl_ctx_client_create(&cctx));
	srv = gwp_ssl_server_new(sctx);
	cli = gwp_ssl_client_new(cctx);
	assert(srv && cli);

	assert(!gwp_ssl_tx_starved(cli));
	assert(gwp_ssl_write(cli, "x", 1, &consumed) == GWP_SSL_WANT_READ);
	assert(!consumed && gwp_ssl_tx_starved(cli));
	/* Nothing received: still so, however often it is asked. */
	assert(gwp_ssl_write(cli, "x", 1, &consumed) == GWP_SSL_WANT_READ);
	assert(gwp_ssl_tx_starved(cli));
	gwp_ssl_rx_commit(cli, 0);
	assert(gwp_ssl_tx_starved(cli));

	shuttle(cli, srv);
	assert(gwp_ssl_handshake(srv) == GWP_SSL_WANT_READ);
	assert(!gwp_ssl_tx_starved(srv));
	/* The server's answer has come: the next write may get somewhere. */
	shuttle(srv, cli);
	assert(!gwp_ssl_tx_starved(cli));

	do_handshake(cli, srv);
	round_trip(cli, srv, "after", 5);
	assert(!gwp_ssl_tx_starved(cli));

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

/* How the end of a peer's stream looks, for all that the engine has read. */
static void test_rx_cut(void)
{
	char cert[] = "/tmp/gwp_ssl_cert.XXXXXX";
	char key[] = "/tmp/gwp_ssl_key.XXXXXX";
	struct gwp_ssl_ctx *sctx = NULL, *cctx = NULL;
	static unsigned char wire[4096];
	struct gwp_ssl *srv, *cli;
	char out[64];
	size_t got;
	int fd, n;

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

	/* Nothing but whole records so far. */
	assert(gwp_ssl_read(srv, out, sizeof(out), &got) == GWP_SSL_WANT_READ);
	assert(!gwp_ssl_rx_cut(srv));

	/* A part of a record, in the queue or with the engine, then the rest. */
	assert(gwp_ssl_write(cli, "abc", 3, &got) == GWP_SSL_OK && got == 3);
	n = gwp_ssl_bio_read(cli, wire, sizeof(wire));
	assert(n > 8);
	assert(gwp_ssl_bio_write(srv, wire, 3) == 3);
	assert(gwp_ssl_rx_cut(srv));
	assert(gwp_ssl_read(srv, out, sizeof(out), &got) == GWP_SSL_WANT_READ);
	assert(gwp_ssl_rx_cut(srv));
	/* The header and not a byte more: the engine has it all, and waits. */
	assert(gwp_ssl_bio_write(srv, wire + 3, 2) == 2);
	assert(gwp_ssl_read(srv, out, sizeof(out), &got) == GWP_SSL_WANT_READ);
	assert(gwp_ssl_rx_cut(srv));
	assert(gwp_ssl_bio_write(srv, wire + 5, 3) == 3);
	assert(gwp_ssl_read(srv, out, sizeof(out), &got) == GWP_SSL_WANT_READ);
	assert(gwp_ssl_rx_cut(srv));
	assert(gwp_ssl_bio_write(srv, wire + 8, (size_t)n - 8) == n - 8);
	assert(gwp_ssl_read(srv, out, sizeof(out), &got) == GWP_SSL_OK && got == 3);
	assert(gwp_ssl_read(srv, out, sizeof(out), &got) == GWP_SSL_WANT_READ);
	assert(!gwp_ssl_rx_cut(srv));

	/* A close_notify is an end, whatever follows it. */
	assert(gwp_ssl_shutdown(cli) == GWP_SSL_OK);
	shuttle(cli, srv);
	assert(gwp_ssl_bio_write(srv, "junk", 4) == 4);
	assert(gwp_ssl_read(srv, out, sizeof(out), &got) == GWP_SSL_OK && !got);
	assert(!gwp_ssl_rx_cut(srv));

	gwp_ssl_free(srv);
	gwp_ssl_free(cli);

	/* A record that fails to verify, which goes for all later reads too. */
	srv = gwp_ssl_server_new(sctx);
	cli = gwp_ssl_client_new(cctx);
	assert(srv && cli);
	do_handshake(cli, srv);
	assert(gwp_ssl_write(cli, "abc", 3, &got) == GWP_SSL_OK && got == 3);
	n = gwp_ssl_bio_read(cli, wire, sizeof(wire));
	assert(n > 0);
	wire[n - 1] ^= 1;
	assert(gwp_ssl_bio_write(srv, wire, (size_t)n) == n);
	assert(gwp_ssl_bio_write(srv, wire, (size_t)n) == n);
	assert(gwp_ssl_read(srv, out, sizeof(out), &got) == GWP_SSL_ERROR);
	assert(!gwp_ssl_rx_more(srv));
	assert(gwp_ssl_rx_cut(srv));
	assert(gwp_ssl_read(srv, out, sizeof(out), &got) == GWP_SSL_ERROR);
	gwp_ssl_free(srv);
	gwp_ssl_free(cli);

	/* The socket failing under a stream that looked fine. */
	srv = gwp_ssl_server_new(sctx);
	cli = gwp_ssl_client_new(cctx);
	assert(srv && cli);
	do_handshake(cli, srv);
	assert(!gwp_ssl_rx_cut(srv));
	gwp_ssl_rx_fail(srv);
	assert(gwp_ssl_rx_cut(srv));
	gwp_ssl_free(srv);
	gwp_ssl_free(cli);

	gwp_ssl_ctx_free(sctx);
	gwp_ssl_ctx_free(cctx);
	unlink(cert);
	unlink(key);
	PRTEST_OK();
}

/*
 * Without the BIO method no connection can be set up. That must show when the
 * context is created, at startup, not as clients being reset later on. Goes
 * first: the method is only created once.
 */
static void test_bio_method_failure(void)
{
	char cert[] = "/tmp/gwp_ssl_cert.XXXXXX";
	char key[] = "/tmp/gwp_ssl_key.XXXXXX";
	struct gwp_ssl_ctx *sctx = NULL, *cctx = NULL;
	int fd;

	fd = mkstemp(cert); assert(fd >= 0); close(fd);
	fd = mkstemp(key); assert(fd >= 0); close(fd);
	write_file(cert, TEST_CERT);
	write_file(key, TEST_KEY);

	bio_meth_new_fails = true;
	assert(gwp_ssl_ctx_server_create(&sctx, cert, key) < 0);
	assert(gwp_ssl_ctx_client_create(&cctx) < 0);

	bio_meth_new_fails = false;
	assert(!gwp_ssl_ctx_server_create(&sctx, cert, key));
	assert(!gwp_ssl_ctx_client_create(&cctx));
	gwp_ssl_ctx_free(sctx);
	gwp_ssl_ctx_free(cctx);

	unlink(cert);
	unlink(key);
	PRTEST_OK();
}

/* A temporary file holding @data; its name goes to @path (a mkstemp template). */
static void temp_file(char *path, const char *data)
{
	int fd = mkstemp(path);

	assert(fd >= 0);
	close(fd);
	write_file(path, data);
}

/*
 * Run a handshake that may fail. Returns GWP_SSL_OK once both sides are done,
 * or GWP_SSL_ERROR as soon as either side fails.
 */
static int try_handshake(struct gwp_ssl *cli, struct gwp_ssl *srv)
{
	int cs, ss, rounds = 0;

	do {
		cs = gwp_ssl_handshake(cli);
		shuttle(cli, srv);
		if (cs == GWP_SSL_ERROR)
			return cs;
		ss = gwp_ssl_handshake(srv);
		shuttle(srv, cli);
		if (ss == GWP_SSL_ERROR)
			return ss;
		assert(++rounds < 32);
	} while (cs != GWP_SSL_OK || ss != GWP_SSL_OK);

	return GWP_SSL_OK;
}

/*
 * Connect a verifying client named @host to a server of @sctx. Check that the
 * ClientHello carries @host (as SNI) only when it is a name, that the handshake
 * ends as @want_ok says, and that a refusal says why, with @want_why in it.
 */
static void verify_case(struct gwp_ssl_ctx *sctx, struct gwp_ssl_ctx *cctx,
			const char *host, bool is_ip, bool want_ok,
			const char *want_why)
{
	struct gwp_ssl *srv, *cli;
	const char *why;
	const void *p;
	size_t len;
	bool sni;
	int r;

	srv = gwp_ssl_server_new(sctx);
	cli = gwp_ssl_client_new(cctx);
	assert(srv && cli);
	assert(!gwp_ssl_set_peer_name(cli, host, is_ip));

	/* The ClientHello goes out in the clear: look for the name in it. */
	assert(gwp_ssl_handshake(cli) == GWP_SSL_WANT_READ);
	p = gwp_ssl_bio_peek(cli, &len);
	assert(p && len);
	sni = memmem(p, len, host, strlen(host)) != NULL;
	assert(sni == !is_ip);

	r = try_handshake(cli, srv);
	why = gwp_ssl_verify_errstr(cli);
	if (want_ok) {
		assert(r == GWP_SSL_OK);
		assert(!why);
		round_trip(cli, srv, "CONNECT", 7);
		round_trip(srv, cli, "200", 3);
	} else {
		assert(r == GWP_SSL_ERROR);
		assert(why);
		if (!strstr(why, want_why)) {
			fprintf(stderr, "%s: refused for '%s', want '%s'\n",
				host, why, want_why);
			assert(0);
		}
	}

	gwp_ssl_free(srv);
	gwp_ssl_free(cli);
}

/*
 * The client an https:// upstream proxy is reached with: it verifies the
 * certificate chain against the CA file it is given and the name it is told,
 * a DNS name sent as SNI and an IP address not.
 */
static void test_client_verify(void)
{
	char ca[] = "/tmp/gwp_ssl_ca.XXXXXX";
	char leaf[] = "/tmp/gwp_ssl_leaf.XXXXXX";
	char lkey[] = "/tmp/gwp_ssl_lkey.XXXXXX";
	char self[] = "/tmp/gwp_ssl_cert.XXXXXX";
	char skey[] = "/tmp/gwp_ssl_key.XXXXXX";
	char empty[] = "/tmp/gwp_ssl_empty.XXXXXX";
	char cn[] = "/tmp/gwp_ssl_cn.XXXXXX";
	char cnkey[] = "/tmp/gwp_ssl_cnkey.XXXXXX";
	struct gwp_ssl_ctx *good = NULL, *selfs = NULL, *cctx = NULL;
	struct gwp_ssl_ctx *cnonly = NULL;
	struct gwp_ssl_ctx *sys = NULL, *bad = NULL;

	temp_file(ca, TEST_CA_CERT);
	temp_file(leaf, TEST_LEAF_CERT);
	temp_file(lkey, TEST_LEAF_KEY);
	temp_file(self, TEST_CERT);
	temp_file(skey, TEST_KEY);
	temp_file(empty, "");
	temp_file(cn, TEST_CN_ONLY_CERT);
	temp_file(cnkey, TEST_CN_ONLY_KEY);

	assert(!gwp_ssl_ctx_server_create(&good, leaf, lkey));
	assert(!gwp_ssl_ctx_server_create(&selfs, self, skey));
	assert(!gwp_ssl_ctx_server_create(&cnonly, cn, cnkey));
	assert(!gwp_ssl_ctx_client_verify_create(&cctx, ca));

	/* Issued by the CA, for the name or the address asked for. */
	verify_case(good, cctx, "localhost", false, true, NULL);
	verify_case(good, cctx, "127.0.0.1", true, true, NULL);

	/* Issued by the CA, but for another name or address. */
	verify_case(good, cctx, "proxy.example", false, false, "mismatch");
	verify_case(good, cctx, "127.0.0.2", true, false, "mismatch");
	verify_case(good, cctx, "::1", true, false, "mismatch");

	/* Issued by the CA, with the name only as the CN: not good enough. */
	verify_case(cnonly, cctx, "localhost", false, false, "mismatch");

	/* Right name, but nobody we trust vouches for it. */
	verify_case(selfs, cctx, "localhost", false, false, "self");

	/* The system's trust store does not know the test CA either. */
	assert(!gwp_ssl_ctx_client_verify_create(&sys, NULL));
	verify_case(good, sys, "localhost", false, false, "issuer");

	/* A CA file that cannot be read, or holds no certificate. */
	assert(gwp_ssl_ctx_client_verify_create(&bad, "/nonexistent/ca.pem") == -EINVAL);
	assert(gwp_ssl_ctx_client_verify_create(&bad, empty) == -EINVAL);
	assert(gwp_ssl_ctx_client_verify_create(&bad, lkey) == -EINVAL);
	assert(!bad);

	gwp_ssl_ctx_free(good);
	gwp_ssl_ctx_free(selfs);
	gwp_ssl_ctx_free(cnonly);
	gwp_ssl_ctx_free(cctx);
	gwp_ssl_ctx_free(sys);
	unlink(ca);
	unlink(leaf);
	unlink(lkey);
	unlink(self);
	unlink(skey);
	unlink(empty);
	unlink(cn);
	unlink(cnkey);
	PRTEST_OK();
}

int main(void)
{
	size_t i;

	test_bio_method_failure();
	for (i = 0; i < 200; i++) {
		test_handshake_and_roundtrip();
		test_zero_copy_queues();
		test_bad_cert_rejected();
		test_alpn_negotiation();
		test_rx_cut();
	}
	test_client_verify();
	test_tx_starved();

	printf("All tests passed!\n");
	return 0;
}
