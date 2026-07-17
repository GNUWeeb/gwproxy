// SPDX-License-Identifier: GPL-2.0-only
/*
 * ssl.c - Minimal OpenSSL TLS wrapper driven by memory BIOs.
 *
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "ssl.h"

struct gwp_ssl_ctx {
	SSL_CTX	*ctx;
};

struct gwp_ssl {
	SSL	*ssl;
	BIO	*rbio;	/* network -> SSL: we BIO_write received ciphertext here */
	BIO	*wbio;	/* SSL -> network: we BIO_read ciphertext to send here */
};

/* ALPN wire form of the one application protocol gwproxy speaks to clients. */
static const unsigned char alpn_http11[] = { 8, 'h','t','t','p','/','1','.','1' };

/*
 * Server ALPN: pick "http/1.1" when the client offers it (so an h2-preferring
 * client is correctly downgraded), and decline otherwise so plaintext-inside
 * SOCKS5-over-TLS and ALPN-less clients still complete the handshake.
 */
static int alpn_select_cb(SSL *ssl, const unsigned char **out,
			  unsigned char *outlen, const unsigned char *in,
			  unsigned int inlen, void *arg)
{
	(void)ssl;
	(void)arg;
	if (SSL_select_next_proto((unsigned char **)out, outlen, alpn_http11,
				  sizeof(alpn_http11), in,
				  inlen) == OPENSSL_NPN_NEGOTIATED)
		return SSL_TLSEXT_ERR_OK;
	return SSL_TLSEXT_ERR_NOACK;
}

int gwp_ssl_ctx_server_create(struct gwp_ssl_ctx **out, const char *cert_file,
			      const char *key_file)
{
	struct gwp_ssl_ctx *c = calloc(1, sizeof(*c));

	if (!c)
		return -ENOMEM;

	c->ctx = SSL_CTX_new(TLS_server_method());
	if (!c->ctx)
		goto err;

	SSL_CTX_set_min_proto_version(c->ctx, TLS1_2_VERSION);
	SSL_CTX_set_alpn_select_cb(c->ctx, alpn_select_cb, NULL);
	if (SSL_CTX_use_certificate_chain_file(c->ctx, cert_file) != 1)
		goto err;
	if (SSL_CTX_use_PrivateKey_file(c->ctx, key_file, SSL_FILETYPE_PEM) != 1)
		goto err;
	if (SSL_CTX_check_private_key(c->ctx) != 1)
		goto err;

	*out = c;
	return 0;

err:
	if (c->ctx)
		SSL_CTX_free(c->ctx);
	free(c);
	return -EINVAL;
}

int gwp_ssl_ctx_client_create(struct gwp_ssl_ctx **out)
{
	struct gwp_ssl_ctx *c = calloc(1, sizeof(*c));

	if (!c)
		return -ENOMEM;

	c->ctx = SSL_CTX_new(TLS_client_method());
	if (!c->ctx) {
		free(c);
		return -EINVAL;
	}

	SSL_CTX_set_min_proto_version(c->ctx, TLS1_2_VERSION);
	SSL_CTX_set_verify(c->ctx, SSL_VERIFY_NONE, NULL);
	*out = c;
	return 0;
}

void gwp_ssl_ctx_free(struct gwp_ssl_ctx *ctx)
{
	if (!ctx)
		return;
	SSL_CTX_free(ctx->ctx);
	free(ctx);
}

static struct gwp_ssl *ssl_new(struct gwp_ssl_ctx *ctx)
{
	struct gwp_ssl *s = calloc(1, sizeof(*s));

	if (!s)
		return NULL;

	s->ssl = SSL_new(ctx->ctx);
	if (!s->ssl) {
		free(s);
		return NULL;
	}

	s->rbio = BIO_new(BIO_s_mem());
	s->wbio = BIO_new(BIO_s_mem());
	if (!s->rbio || !s->wbio) {
		BIO_free(s->rbio);	/* BIO_free(NULL) is a no-op */
		BIO_free(s->wbio);
		SSL_free(s->ssl);
		free(s);
		return NULL;
	}

	/* SSL takes ownership of both BIOs; SSL_free() will release them. */
	SSL_set_bio(s->ssl, s->rbio, s->wbio);
	return s;
}

struct gwp_ssl *gwp_ssl_server_new(struct gwp_ssl_ctx *ctx)
{
	struct gwp_ssl *s = ssl_new(ctx);

	if (s)
		SSL_set_accept_state(s->ssl);
	return s;
}

struct gwp_ssl *gwp_ssl_client_new(struct gwp_ssl_ctx *ctx)
{
	struct gwp_ssl *s = ssl_new(ctx);

	if (s)
		SSL_set_connect_state(s->ssl);
	return s;
}

void gwp_ssl_free(struct gwp_ssl *s)
{
	if (!s)
		return;
	SSL_free(s->ssl);	/* also frees the two BIOs set via SSL_set_bio */
	free(s);
}

int gwp_ssl_set_alpn(struct gwp_ssl *s, const void *protos, size_t len)
{
	/* SSL_set_alpn_protos() returns 0 on success (note the inverted sense). */
	return SSL_set_alpn_protos(s->ssl, protos, (unsigned int)len) ? -EINVAL : 0;
}

const char *gwp_ssl_alpn(struct gwp_ssl *s)
{
	static __thread char buf[64];
	const unsigned char *p = NULL;
	unsigned int len = 0;

	SSL_get0_alpn_selected(s->ssl, &p, &len);
	if (!p || !len)
		return NULL;
	if (len >= sizeof(buf))
		len = sizeof(buf) - 1;
	memcpy(buf, p, len);
	buf[len] = '\0';
	return buf;
}

static int cap_int(size_t len)
{
	return (len > INT_MAX) ? INT_MAX : (int)len;
}

int gwp_ssl_bio_write(struct gwp_ssl *s, const void *buf, size_t len)
{
	int r;

	if (!len)
		return 0;
	r = BIO_write(s->rbio, buf, cap_int(len));
	return (r < 0) ? -EIO : r;
}

int gwp_ssl_bio_read(struct gwp_ssl *s, void *buf, size_t len)
{
	int r;

	if (!len)
		return 0;
	r = BIO_read(s->wbio, buf, cap_int(len));
	/* A memory BIO with nothing to give returns <=0 with should_retry set. */
	return (r > 0) ? r : 0;
}

size_t gwp_ssl_bio_pending(struct gwp_ssl *s)
{
	return BIO_ctrl_pending(s->wbio);
}

const void *gwp_ssl_bio_peek(struct gwp_ssl *s, size_t *len)
{
	BUF_MEM *bm = NULL;

	BIO_get_mem_ptr(s->wbio, &bm);
	if (!bm || bm->length == 0) {
		*len = 0;
		return NULL;
	}
	*len = bm->length;
	return bm->data;
}

void gwp_ssl_bio_consume(struct gwp_ssl *s, size_t len)
{
	unsigned char scratch[4096];

	while (len > 0) {
		int c = (len > sizeof(scratch)) ? (int)sizeof(scratch) : (int)len;
		int r = BIO_read(s->wbio, scratch, c);

		if (r <= 0)
			break;
		len -= (size_t)r;
	}
}

size_t gwp_ssl_pending(struct gwp_ssl *s)
{
	int r = SSL_pending(s->ssl);

	return (r > 0) ? (size_t)r : 0;
}

static int map_err(struct gwp_ssl *s, int ret)
{
	switch (SSL_get_error(s->ssl, ret)) {
	case SSL_ERROR_WANT_READ:
		return GWP_SSL_WANT_READ;
	case SSL_ERROR_WANT_WRITE:
		return GWP_SSL_WANT_WRITE;
	default:
		return GWP_SSL_ERROR;
	}
}

int gwp_ssl_handshake(struct gwp_ssl *s)
{
	int r = SSL_do_handshake(s->ssl);

	if (r == 1)
		return GWP_SSL_OK;
	return map_err(s, r);
}

int gwp_ssl_read(struct gwp_ssl *s, void *buf, size_t len, size_t *out_len)
{
	int r;

	*out_len = 0;
	if (!len)
		return GWP_SSL_OK;

	r = SSL_read(s->ssl, buf, cap_int(len));
	if (r > 0) {
		*out_len = (size_t)r;
		return GWP_SSL_OK;
	}
	/* A clean close_notify reports 0 bytes, not an error. */
	if (SSL_get_error(s->ssl, r) == SSL_ERROR_ZERO_RETURN)
		return GWP_SSL_OK;
	return map_err(s, r);
}

int gwp_ssl_write(struct gwp_ssl *s, const void *buf, size_t len,
		  size_t *consumed)
{
	int r;

	*consumed = 0;
	if (!len)
		return GWP_SSL_OK;

	r = SSL_write(s->ssl, buf, cap_int(len));
	if (r > 0) {
		*consumed = (size_t)r;
		return GWP_SSL_OK;
	}
	return map_err(s, r);
}

int gwp_ssl_shutdown(struct gwp_ssl *s)
{
	int r = SSL_shutdown(s->ssl);

	/*
	 * 0 = our close_notify was queued (peer's not yet seen), 1 = full
	 * bidirectional shutdown. Both are fine for a best-effort close; the
	 * caller just flushes the send BIO afterwards.
	 */
	if (r >= 0)
		return GWP_SSL_OK;
	return map_err(s, r);
}

const char *gwp_ssl_errstr(void)
{
	static __thread char buf[256];
	unsigned long e = ERR_get_error();

	if (!e)
		return "no TLS error";
	ERR_error_string_n(e, buf, sizeof(buf));
	return buf;
}
