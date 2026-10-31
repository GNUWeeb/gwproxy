// SPDX-License-Identifier: GPL-2.0-only
/*
 * ssl.c - Minimal OpenSSL TLS wrapper driven by in-memory queues.
 *
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>

#include "ssl.h"

struct gwp_ssl_ctx {
	SSL_CTX	*ctx;
};

/*
 * A byte queue: the bytes in [head, tail) of @buf are queued, the rest of the
 * @cap bytes is free. It backs one direction of a connection's ciphertext and
 * gives the caller direct access to both ends, which a memory BIO does not:
 * received ciphertext goes straight from the socket to its tail, and ciphertext
 * to send is taken from its head with no copy.
 */
struct gwp_ssl_q {
	unsigned char	*buf;
	size_t		head;
	size_t		tail;
	size_t		cap;
	/*
	 * Space past @tail was handed out by gwp_ssl_rx_space() and may be
	 * filled behind our back: keep @tail where it is until the commit.
	 */
	bool		pinned;
};

struct gwp_ssl {
	SSL		*ssl;
	BIO		*rbio;	/* network -> SSL, reads from @rq */
	BIO		*wbio;	/* SSL -> network, appends to @wq */
	struct gwp_ssl_q rq;	/* received ciphertext the engine has not read */
	struct gwp_ssl_q wq;	/* ciphertext waiting to be sent */
	/*
	 * The last SSL_read() asked for more ciphertext than @rq holds, and
	 * nothing has been received since: reading again cannot make progress.
	 */
	bool		rx_starved;
};

_Static_assert(GWP_SSL_RECORD_MAX >= SSL3_RT_HEADER_LENGTH +
	       SSL3_RT_MAX_PLAIN_LENGTH + SSL3_RT_MAX_ENCRYPTED_OVERHEAD,
	       "GWP_SSL_RECORD_MAX must hold a whole TLS record");

static size_t q_len(const struct gwp_ssl_q *q)
{
	return q->tail - q->head;
}

/* Make room for at least @n more bytes at the tail; NULL if out of memory. */
static unsigned char *q_reserve(struct gwp_ssl_q *q, size_t n)
{
	size_t used = q_len(q), ncap;
	unsigned char *p;

	if (q->cap - q->tail >= n)
		return q->buf + q->tail;

	if (q->head) {
		memmove(q->buf, q->buf + q->head, used);
		q->head = 0;
		q->tail = used;
		if (q->cap - used >= n)
			return q->buf + q->tail;
	}

	if (n > SIZE_MAX / 2 - used)
		return NULL;
	ncap = q->cap ? q->cap : 4096;
	while (ncap - used < n)
		ncap *= 2;
	p = realloc(q->buf, ncap);
	if (!p)
		return NULL;
	q->buf = p;
	q->cap = ncap;
	return q->buf + q->tail;
}

static void q_consume(struct gwp_ssl_q *q, size_t n)
{
	if (n > q_len(q))
		n = q_len(q);
	q->head += n;
	if (q->head == q->tail && !q->pinned)
		q->head = q->tail = 0;
}

/*
 * The BIO glue. OpenSSL reads ciphertext from the rbio and writes it to the
 * wbio; both go straight to the queues, whose memory gwp_ssl owns.
 */
static int q_bio_write(BIO *b, const char *in, int inl)
{
	struct gwp_ssl_q *q = BIO_get_data(b);
	unsigned char *p;

	BIO_clear_retry_flags(b);
	if (inl <= 0)
		return 0;
	p = q_reserve(q, (size_t)inl);
	if (!p)
		return -1;
	memcpy(p, in, (size_t)inl);
	q->tail += (size_t)inl;
	return inl;
}

static int q_bio_read(BIO *b, char *out, int outl)
{
	struct gwp_ssl_q *q = BIO_get_data(b);
	size_t n = q_len(q);

	BIO_clear_retry_flags(b);
	if (outl <= 0)
		return 0;
	if (!n) {
		/* Like an empty memory BIO: no data yet, try again later. */
		BIO_set_retry_read(b);
		return -1;
	}
	if (n > (size_t)outl)
		n = (size_t)outl;
	memcpy(out, q->buf + q->head, n);
	q_consume(q, n);
	return (int)n;
}

static long q_bio_ctrl(BIO *b, int cmd, long num, void *ptr)
{
	struct gwp_ssl_q *q = BIO_get_data(b);

	(void)num;
	(void)ptr;
	switch (cmd) {
	case BIO_CTRL_PENDING:
		return (long)q_len(q);
	case BIO_CTRL_EOF:
		return q_len(q) == 0;
	case BIO_CTRL_RESET:
		q->head = q->tail = 0;
		return 1;
	case BIO_CTRL_FLUSH:
	case BIO_CTRL_DUP:
		return 1;
	default:
		return 0;
	}
}

static int q_bio_create(BIO *b)
{
	BIO_set_init(b, 1);
	return 1;
}

static BIO_METHOD *q_bio_meth;
static CRYPTO_ONCE q_bio_once = CRYPTO_ONCE_STATIC_INIT;

static void q_bio_meth_init(void)
{
	BIO_METHOD *m;

	m = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK,
			 "gwproxy queue");
	if (!m)
		return;
	if (!BIO_meth_set_write(m, q_bio_write) ||
	    !BIO_meth_set_read(m, q_bio_read) ||
	    !BIO_meth_set_ctrl(m, q_bio_ctrl) ||
	    !BIO_meth_set_create(m, q_bio_create)) {
		BIO_meth_free(m);
		return;
	}
	q_bio_meth = m;
}

static BIO *q_bio_new(struct gwp_ssl_q *q)
{
	BIO *b;

	if (!CRYPTO_THREAD_run_once(&q_bio_once, q_bio_meth_init) ||
	    !q_bio_meth)
		return NULL;
	b = BIO_new(q_bio_meth);
	if (b)
		BIO_set_data(b, q);
	return b;
}

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
	/* Test-only, see ssl.h: no peer verification. */
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

	s->rbio = q_bio_new(&s->rq);
	s->wbio = q_bio_new(&s->wq);
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
	free(s->rq.buf);
	free(s->wq.buf);
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
	unsigned char *p;

	len = (size_t)cap_int(len);
	if (!len)
		return 0;
	p = q_reserve(&s->rq, len);
	if (!p)
		return -ENOMEM;
	memcpy(p, buf, len);
	gwp_ssl_rx_commit(s, len);
	return (int)len;
}

void *gwp_ssl_rx_space(struct gwp_ssl *s, size_t want, size_t *len)
{
	unsigned char *p = q_reserve(&s->rq, want);

	*len = p ? s->rq.cap - s->rq.tail : 0;
	s->rq.pinned = p != NULL;
	return p;
}

void gwp_ssl_rx_commit(struct gwp_ssl *s, size_t len)
{
	s->rq.pinned = false;
	s->rq.tail += len;
	if (len)
		s->rx_starved = false;
}

bool gwp_ssl_rx_more(struct gwp_ssl *s)
{
	if (SSL_pending(s->ssl) > 0)
		return true;
	return q_len(&s->rq) > 0 && !s->rx_starved;
}

int gwp_ssl_bio_read(struct gwp_ssl *s, void *buf, size_t len)
{
	size_t n = q_len(&s->wq);

	if (n > len)
		n = len;
	n = (size_t)cap_int(n);
	if (!n)
		return 0;
	memcpy(buf, s->wq.buf + s->wq.head, n);
	q_consume(&s->wq, n);
	return (int)n;
}

size_t gwp_ssl_bio_pending(struct gwp_ssl *s)
{
	return q_len(&s->wq);
}

const void *gwp_ssl_bio_peek(struct gwp_ssl *s, size_t *len)
{
	*len = q_len(&s->wq);
	return *len ? s->wq.buf + s->wq.head : NULL;
}

void gwp_ssl_bio_consume(struct gwp_ssl *s, size_t len)
{
	q_consume(&s->wq, len);
}

/*
 * SSL_get_error() consults this thread's OpenSSL error queue, which is shared
 * by every connection a worker serves: an entry left there by one session's
 * failure makes the next call on any other session look fatal. Start every
 * SSL call that is followed by SSL_get_error() with an empty queue. The
 * entries a failing call pushes stay queued for gwp_ssl_errstr().
 */
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
	int r;

	ERR_clear_error();
	r = SSL_do_handshake(s->ssl);
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

	ERR_clear_error();
	r = SSL_read(s->ssl, buf, cap_int(len));
	if (r > 0) {
		*out_len = (size_t)r;
		return GWP_SSL_OK;
	}
	/* A clean close_notify reports 0 bytes, not an error. */
	if (SSL_get_error(s->ssl, r) == SSL_ERROR_ZERO_RETURN)
		return GWP_SSL_OK;
	r = map_err(s, r);
	if (r == GWP_SSL_WANT_READ)
		s->rx_starved = true;
	return r;
}

int gwp_ssl_write(struct gwp_ssl *s, const void *buf, size_t len,
		  size_t *consumed)
{
	int r;

	*consumed = 0;
	if (!len)
		return GWP_SSL_OK;

	ERR_clear_error();
	r = SSL_write(s->ssl, buf, cap_int(len));
	if (r > 0) {
		*consumed = (size_t)r;
		return GWP_SSL_OK;
	}
	return map_err(s, r);
}

int gwp_ssl_shutdown(struct gwp_ssl *s)
{
	int r;

	/* Queue our close_notify only once; callers may retry the close. */
	if (SSL_get_shutdown(s->ssl) & SSL_SENT_SHUTDOWN)
		return GWP_SSL_OK;

	ERR_clear_error();
	r = SSL_shutdown(s->ssl);
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
