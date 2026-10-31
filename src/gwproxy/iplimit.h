// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * Per-client-address connection counter for --max-conns-per-ip. Every worker
 * accepts on its own listener, so the count is shared by all of them: a hash
 * table split into shards, each behind its own lock, so that workers taking
 * clients from different addresses rarely contend.
 *
 * Clients are grouped by gwp_iplim_key(): an IPv4 client (or an IPv4-mapped
 * IPv6 one, as a dual-stack listener sees it) by its full address, a native
 * IPv6 client by its /64 prefix, since one IPv6 host normally owns a whole
 * /64 and could otherwise pick a fresh address for every connection.
 *
 * Self-contained (net.h types and libc only) so it can be unit-tested alone.
 */
#ifndef GWP_IPLIMIT_H
#define GWP_IPLIMIT_H

#include <stdint.h>
#include <gwproxy/net.h>

struct gwp_iplim_key {
	uint8_t		b[16];
};

struct gwp_iplim;

enum {
	/* Admitted and counted; gwp_iplim_put() must follow. */
	GWP_IPLIM_ADMIT		= 0,
	/* Over the cap; not counted. */
	GWP_IPLIM_REFUSE	= 1,
	/* Over the cap and not counted; the first refusal this second. */
	GWP_IPLIM_REFUSE_LOG	= 2,
};

/*
 * The group @addr is counted in, as a ::ffff:a.b.c.d address for IPv4 and
 * IPv4-mapped IPv6, and as the /64 prefix with the rest zero for native IPv6.
 * The two cannot collide: a /64 key never has 0xffff in bytes 10..11.
 */
void gwp_iplim_key(const struct gwp_sockaddr *addr, struct gwp_iplim_key *key);

/* A table allowing @max connections per key (@max > 0); NULL without memory. */
struct gwp_iplim *gwp_iplim_create(uint32_t max);
void gwp_iplim_destroy(struct gwp_iplim *l);

/*
 * Count a new connection for @key, unless it already has the maximum. @now is
 * a monotonic second count, used to rate-limit refusal logging to one line per
 * key per second: GWP_IPLIM_REFUSE_LOG asks the caller to log this refusal,
 * and @nr_quiet (may be NULL) then receives the number of refusals for the key
 * that were not logged since the previous line. Returns -ENOMEM when a first
 * connection for a new key cannot get an entry.
 */
int gwp_iplim_get(struct gwp_iplim *l, const struct gwp_iplim_key *key,
		  uint32_t now, uint32_t *nr_quiet);

/* Uncount a connection gwp_iplim_get() admitted; the entry goes at zero. */
void gwp_iplim_put(struct gwp_iplim *l, const struct gwp_iplim_key *key);

/* The connections counted for @key (0 when it has no entry), and in total. */
uint32_t gwp_iplim_count(struct gwp_iplim *l, const struct gwp_iplim_key *key);
uint64_t gwp_iplim_nr_entries(struct gwp_iplim *l);

#endif /* #ifndef GWP_IPLIMIT_H */
