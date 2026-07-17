// SPDX-License-Identifier: GPL-2.0-only
/*
 * ssl.h - Minimal OpenSSL TLS wrapper driven by memory BIOs.
 *
 * The caller owns the socket and does all raw I/O; this module only transforms
 * buffers. Received ciphertext is fed in with gwp_ssl_bio_write(); ciphertext
 * the engine wants to send is pulled out with gwp_ssl_bio_read(); plaintext
 * crosses via gwp_ssl_read()/gwp_ssl_write(). It knows nothing about sockets or
 * the event loop, so the same code serves epoll and io_uring.
 *
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */
#ifndef GWPROXY__SSL_H
#define GWPROXY__SSL_H

#include <stddef.h>

struct gwp_ssl_ctx;
struct gwp_ssl;

/*
 * Result of a TLS operation. After any non-OK result the caller should also
 * drain gwp_ssl_bio_read() to the socket, since an operation can emit
 * ciphertext (handshake records, alerts) regardless of the WANT_* it returns.
 */
enum {
	GWP_SSL_OK = 0,		/* completed */
	GWP_SSL_WANT_READ,	/* needs more ciphertext fed in (bio_write) */
	GWP_SSL_WANT_WRITE,	/* needs its ciphertext flushed (bio_read) */
	GWP_SSL_ERROR,		/* fatal */
};

/* Create a server SSL_CTX from a PEM certificate chain + private key. */
int gwp_ssl_ctx_server_create(struct gwp_ssl_ctx **out, const char *cert_file,
			      const char *key_file);
/* Create a client SSL_CTX (no peer verification; for tests / future use). */
int gwp_ssl_ctx_client_create(struct gwp_ssl_ctx **out);
void gwp_ssl_ctx_free(struct gwp_ssl_ctx *ctx);

/*
 * Allocate a per-connection TLS state in server (accept) or client (connect)
 * role, wired to internal memory BIOs. Returns NULL on allocation failure.
 */
struct gwp_ssl *gwp_ssl_server_new(struct gwp_ssl_ctx *ctx);
struct gwp_ssl *gwp_ssl_client_new(struct gwp_ssl_ctx *ctx);
void gwp_ssl_free(struct gwp_ssl *s);

/*
 * Feed received ciphertext into the engine (network -> SSL). Returns the number
 * of bytes consumed (the memory BIO always accepts everything), or <0 on error.
 */
int gwp_ssl_bio_write(struct gwp_ssl *s, const void *buf, size_t len);
/*
 * Pull ciphertext the engine wants to send (SSL -> network) into @buf. Returns
 * the number of bytes read, 0 if none is pending, or <0 on error.
 */
int gwp_ssl_bio_read(struct gwp_ssl *s, void *buf, size_t len);
/* Number of ciphertext bytes currently queued to send. */
size_t gwp_ssl_bio_pending(struct gwp_ssl *s);
/*
 * Peek at the queued ciphertext without consuming it: returns a pointer to up
 * to *len contiguous bytes (NULL and *len == 0 when none). The pointer stays
 * valid only until the next BIO operation on this connection. After sending N
 * of those bytes, call gwp_ssl_bio_consume(s, N) to drop them. This lets the
 * caller consume exactly what a short socket write accepted, since a memory BIO
 * cannot push already-read bytes back.
 */
const void *gwp_ssl_bio_peek(struct gwp_ssl *s, size_t *len);
void gwp_ssl_bio_consume(struct gwp_ssl *s, size_t len);
/* Number of decrypted plaintext bytes buffered and immediately readable. */
size_t gwp_ssl_pending(struct gwp_ssl *s);

/* Drive the TLS handshake. Returns GWP_SSL_OK / WANT_READ / WANT_WRITE / ERROR. */
int gwp_ssl_handshake(struct gwp_ssl *s);

/*
 * Decrypt application data into @buf; *out_len receives the plaintext length
 * (0 means the peer sent a clean close_notify). Returns GWP_SSL_OK,
 * GWP_SSL_WANT_READ, GWP_SSL_WANT_WRITE, or GWP_SSL_ERROR.
 */
int gwp_ssl_read(struct gwp_ssl *s, void *buf, size_t len, size_t *out_len);
/*
 * Encrypt application data from @buf; *consumed receives how many plaintext
 * bytes were accepted. Returns GWP_SSL_OK, GWP_SSL_WANT_READ,
 * GWP_SSL_WANT_WRITE, or GWP_SSL_ERROR.
 */
int gwp_ssl_write(struct gwp_ssl *s, const void *buf, size_t len,
		  size_t *consumed);

/* Queue a close_notify into the send BIO (best effort). */
int gwp_ssl_shutdown(struct gwp_ssl *s);

/*
 * Set the client-side ALPN protocol list (@protos in ALPN wire form: each entry
 * a length byte followed by that many bytes). Returns 0 on success, <0 on error.
 * The server side advertises "http/1.1" automatically (see server ctx creation).
 */
int gwp_ssl_set_alpn(struct gwp_ssl *s, const void *protos, size_t len);

/*
 * The ALPN protocol negotiated for this connection as a NUL-terminated string,
 * or NULL if none was selected. Points at a per-thread buffer valid until the
 * next call on this thread.
 */
const char *gwp_ssl_alpn(struct gwp_ssl *s);

/*
 * A human-readable string for the most recent OpenSSL error on this thread
 * (drains one entry from the error queue). For logging by the caller.
 */
const char *gwp_ssl_errstr(void);

#endif /* #ifndef GWPROXY__SSL_H */
