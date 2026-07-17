// SPDX-License-Identifier: GPL-2.0-only
/*
 * auth.h - Shared username/password credential store.
 *
 * The store is loaded from a colon-separated "user:password" file (one
 * entry per line) and is shared by the SOCKS5 (RFC 1929) and HTTP CONNECT
 * (RFC 7617 "Basic") proxy front-ends. It is safe for concurrent readers
 * across worker threads; reloads take a write lock.
 *
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */
#ifndef GWPROXY__AUTH_H
#define GWPROXY__AUTH_H

#include <stddef.h>
#include <stdbool.h>

struct gwp_auth;

/**
 * Create a credential store from the file at @path.
 *
 * If @path is NULL or empty, no store is created: *@out is set to NULL and
 * 0 is returned (i.e. authentication is disabled). Otherwise the file is
 * opened and parsed, and the resulting store is stored in *@out.
 *
 * @param out	Pointer that receives the new store (or NULL if @path is unset).
 * @param path	Path to the "user:password" credential file, or NULL.
 * @return	0 on success, or a negative error code on failure.
 */
int gwp_auth_create(struct gwp_auth **out, const char *path);

/**
 * Free a credential store. Does nothing if @auth is NULL.
 *
 * @param auth	The store to free.
 */
void gwp_auth_destroy(struct gwp_auth *auth);

/**
 * Re-read the credential file, atomically replacing the in-memory entries.
 *
 * @param auth	The store to reload. Must have been created from a file.
 * @return	0 on success, or a negative error code on failure.
 */
int gwp_auth_reload(struct gwp_auth *auth);

/**
 * Check a username/password pair against the store in constant time.
 *
 * @param auth	The store, or NULL. A NULL store never matches.
 * @param u	Username bytes.
 * @param ulen	Username length.
 * @param p	Password bytes (may be NULL when @plen is 0).
 * @param plen	Password length.
 * @return	true if the credentials match an entry, false otherwise.
 */
bool gwp_auth_check(struct gwp_auth *auth, const char *u, size_t ulen,
		    const char *p, size_t plen);

/**
 * Check an HTTP "Proxy-Authorization"/"Authorization" header value that uses
 * the "Basic" scheme (RFC 7617) against the store.
 *
 * @param auth		The store, or NULL. A NULL store never matches.
 * @param hdr_val	The raw header value, e.g. `Basic dXNlcjpwYXNz`. A NULL
 *			or malformed value never matches.
 * @return		true if the decoded credentials match, false otherwise.
 */
bool gwp_auth_check_basic(struct gwp_auth *auth, const char *hdr_val);

#endif /* #ifndef GWPROXY__AUTH_H */
