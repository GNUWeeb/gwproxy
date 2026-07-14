// SPDX-License-Identifier: GPL-2.0-only
/*
 * auth.c - Shared username/password credential store.
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
#include <stdint.h>
#include <errno.h>
#include <pthread.h>

#include "auth.h"

struct auth_entry {
	char	*u, *p;
	uint8_t	ulen, plen;
};

struct gwp_auth {
	FILE			*fp;
	pthread_rwlock_t	lock;
	struct auth_entry	*entries;
	size_t			nr;
	size_t			cap;
};

/*
 * Upper bound on the decoded length of an HTTP "Basic" credential
 * ("user:password"). Usernames and passwords are each capped at 255 bytes
 * by add_auth_entry(), so the longest possible match is 255 + 1 + 255.
 */
#define GWP_AUTH_BASIC_DEC_MAX	(255 + 1 + 255)

static bool is_space(unsigned char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static char *trim_str(char *str)
{
	char *end;

	while (is_space((unsigned char)*str))
		str++;

	/*
	 * Nothing left after trimming leading whitespace. Return early so we
	 * don't form the pointer "str - 1" below, which is undefined behaviour
	 * when str already points at the start of the buffer.
	 */
	if (*str == '\0')
		return str;

	end = str + strlen(str) - 1;
	while (end > str && is_space((unsigned char)*end))
		end--;

	end[1] = '\0';
	return str;
}

static void free_auth_entries(struct gwp_auth *auth)
{
	size_t i;

	if (!auth)
		return;

	for (i = 0; i < auth->nr; i++)
		free(auth->entries[i].u);

	free(auth->entries);
	auth->entries = NULL;
	auth->nr = 0;
	auth->cap = 0;
}

static int add_auth_entry(struct gwp_auth *auth, const char *line, size_t len)
{
	struct auth_entry *ae;
	size_t ulen, plen;
	char *u, *p;

	if (auth->nr >= auth->cap) {
		size_t new_cap = auth->cap ? auth->cap * 2 : 16;
		struct auth_entry *new_entries;

		new_entries = realloc(auth->entries,
				      new_cap * sizeof(*new_entries));
		if (!new_entries)
			return -ENOMEM;

		auth->entries = new_entries;
		auth->cap = new_cap;
	}

	u = malloc(len + 1);
	if (!u)
		return -ENOMEM;

	memcpy(u, line, len);
	u[len] = '\0';

	p = strchr(u, ':');
	if (p)
		*p++ = '\0';

	ulen = strlen(u);
	if (ulen > 255)
		goto out_free_u;

	plen = p ? strlen(p) : 0;
	if (plen > 255)
		goto out_free_u;

	ae = &auth->entries[auth->nr++];
	ae->u = u;
	ae->p = p;
	ae->ulen = ulen;
	ae->plen = plen;
	return 0;

out_free_u:
	free(u);
	return -EINVAL;
}

/*
 * Constant-time byte comparison for credential checks. Unlike memcmp() it does
 * not short-circuit on the first mismatch, so it does not leak (via timing) how
 * many leading bytes of a supplied username/password are correct. A zero length
 * compares equal without dereferencing either pointer, which also makes the
 * empty-password case (p == NULL) well-defined rather than UB.
 */
static bool ct_bytes_eq(const void *a, const void *b, size_t len)
{
	const volatile unsigned char *pa = a;
	const volatile unsigned char *pb = b;
	unsigned char diff = 0;
	size_t i;

	for (i = 0; i < len; i++)
		diff |= pa[i] ^ pb[i];

	return diff == 0;
}

bool gwp_auth_check(struct gwp_auth *auth, const char *u, size_t ulen,
		    const char *p, size_t plen)
{
	bool ret = false;
	size_t i;

	if (!auth)
		return false;

	/*
	 * Read the entry set under the lock; a concurrent gwp_auth_reload()
	 * frees and rebuilds it under the write lock. When there are no
	 * entries nr is 0 and the loop simply does not run.
	 */
	pthread_rwlock_rdlock(&auth->lock);
	for (i = 0; i < auth->nr; i++) {
		const struct auth_entry *ae = &auth->entries[i];
		if (ulen != ae->ulen)
			continue;
		if (plen != ae->plen)
			continue;
		if (!ct_bytes_eq(u, ae->u, ulen))
			continue;
		if (!ct_bytes_eq(p, ae->p, plen))
			continue;
		ret = true;
		break;
	}
	pthread_rwlock_unlock(&auth->lock);
	return ret;
}

int gwp_auth_reload(struct gwp_auth *auth)
{
	char buf[4096], *t;
	size_t l;
	int r = 0;

	if (!auth || !auth->fp)
		return -ENOSYS;

	pthread_rwlock_wrlock(&auth->lock);
	free_auth_entries(auth);
	while (1) {
		t = fgets(buf, sizeof(buf), auth->fp);
		if (!t)
			break;

		t = trim_str(buf);
		l = strlen(t);
		if (!l)
			continue;

		r = add_auth_entry(auth, t, l);
		if (r < 0)
			break;
	}
	rewind(auth->fp);
	pthread_rwlock_unlock(&auth->lock);
	return r;
}

int gwp_auth_create(struct gwp_auth **out, const char *path)
{
	struct gwp_auth *auth;
	FILE *fp;
	int r;

	if (!path || !*path) {
		*out = NULL;
		return 0;
	}

	auth = calloc(1, sizeof(*auth));
	if (!auth)
		return -ENOMEM;

	r = pthread_rwlock_init(&auth->lock, NULL);
	if (r) {
		free(auth);
		return -r;
	}

	fp = fopen(path, "rb");
	if (!fp) {
		r = -errno;
		goto out_destroy_lock;
	}

	auth->fp = fp;
	r = gwp_auth_reload(auth);
	if (r < 0)
		goto out_free_ent;

	*out = auth;
	return 0;

out_free_ent:
	free_auth_entries(auth);
	fclose(auth->fp);
out_destroy_lock:
	pthread_rwlock_destroy(&auth->lock);
	free(auth);
	return r;
}

void gwp_auth_destroy(struct gwp_auth *auth)
{
	if (!auth)
		return;

	pthread_rwlock_destroy(&auth->lock);
	free_auth_entries(auth);
	fclose(auth->fp);
	free(auth);
}

static int b64_val(unsigned char c)
{
	if (c >= 'A' && c <= 'Z')
		return (int)(c - 'A');
	if (c >= 'a' && c <= 'z')
		return (int)(c - 'a') + 26;
	if (c >= '0' && c <= '9')
		return (int)(c - '0') + 52;
	if (c == '+')
		return 62;
	if (c == '/')
		return 63;
	return -1;
}

/*
 * Decode a base64 (RFC 4648) token into @out. Padding '=' and any trailing
 * whitespace terminate the token. Returns the decoded length on success, or
 * -1 on an invalid character or if the output would exceed @out_cap.
 */
static int base64_decode(const char *in, size_t inlen, unsigned char *out,
			 size_t out_cap)
{
	uint32_t acc = 0;
	size_t olen = 0, i;
	int nbits = 0;

	for (i = 0; i < inlen; i++) {
		unsigned char c = (unsigned char)in[i];
		int v;

		if (c == '=' || c == ' ' || c == '\t' || c == '\r' || c == '\n')
			break;

		v = b64_val(c);
		if (v < 0)
			return -1;

		acc = (acc << 6) | (uint32_t)v;
		nbits += 6;
		if (nbits >= 8) {
			nbits -= 8;
			if (olen >= out_cap)
				return -1;
			out[olen++] = (unsigned char)((acc >> nbits) & 0xffu);
		}
	}

	return (int)olen;
}

bool gwp_auth_check_basic(struct gwp_auth *auth, const char *hdr_val)
{
	unsigned char dec[GWP_AUTH_BASIC_DEC_MAX];
	const char *b64;
	const void *colon;
	size_t ulen, plen;
	int dlen;

	if (!auth || !hdr_val)
		return false;

	/* The scheme token is case-insensitive and followed by whitespace. */
	if (strncasecmp(hdr_val, "Basic", 5))
		return false;
	b64 = hdr_val + 5;
	if (*b64 != ' ' && *b64 != '\t')
		return false;
	while (*b64 == ' ' || *b64 == '\t')
		b64++;

	dlen = base64_decode(b64, strlen(b64), dec, sizeof(dec));
	if (dlen < 0)
		return false;

	/* RFC 7617: split on the first ':'; the password may contain ':'. */
	colon = memchr(dec, ':', (size_t)dlen);
	if (!colon)
		return false;

	ulen = (size_t)((const unsigned char *)colon - dec);
	plen = (size_t)dlen - ulen - 1;
	return gwp_auth_check(auth, (const char *)dec, ulen,
			      (const char *)colon + 1, plen);
}
