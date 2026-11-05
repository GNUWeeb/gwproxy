// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * What gwproxy keeps about an upstream proxy server beyond its parsed URL,
 * and how a pool picks one of its servers for a connection.
 *
 * An ACL reload rebuilds every pool and every server object in it, while
 * the connections that use the old objects carry on. What must outlive that
 * (how many connections a server has open now; later, its failures) belongs
 * to the server's identity, not to one object: its scheme, its resolved
 * address and port, and the user it logs in as (struct gwp_up_key). The
 * table (struct gwp_up_table) holds one entry (struct gwp_up_state) per
 * identity, shared by all workers. Each server object holds a reference to
 * its entry from when it is made until it is freed, so a rebuilt pool finds
 * the entries its predecessor used, counts and all, and an entry goes away
 * with the last server object of its identity.
 *
 * Self-contained (net.h types and libc only) so it can be unit-tested alone.
 */
#ifndef GWP_UPSTREAM_LB_H
#define GWP_UPSTREAM_LB_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <gwproxy/net.h>

enum gwp_up_scheme {
	GWP_UP_SCHEME_SOCKS5	= 0,	/* socks5:// */
	GWP_UP_SCHEME_SOCKS5H	= 1,	/* socks5h:// */
	GWP_UP_SCHEME_HTTP	= 2,	/* http:// */
	GWP_UP_SCHEME_HTTPS	= 3,	/* https:// */
};

/*
 * A server's identity. Built by gwp_up_key_init() only, which zeroes what
 * it does not set, so that two keys compare equal byte for byte. The
 * password is not part of it: changing it does not make another server.
 */
struct gwp_up_key {
	uint8_t		scheme;		/* enum gwp_up_scheme */
	uint8_t		family;		/* AF_INET or AF_INET6 */
	uint8_t		ulen;
	uint8_t		port[2];	/* network order */
	uint8_t		ip[16];		/* IPv4 in the first 4 bytes */
	uint8_t		scope[4];	/* IPv6 scope id, else 0 */
	char		user[255];	/* @ulen bytes, then zeroes */
};

/*
 * Make @key of @scheme, the address @addr (IPv4 or IPv6, with its port) and
 * the user name @user of @ulen bytes (0 for none; at most 255).
 */
void gwp_up_key_init(struct gwp_up_key *key, enum gwp_up_scheme scheme,
		     const struct gwp_sockaddr *addr, const char *user,
		     size_t ulen);

struct gwp_up_table;

/* One identity's shared state. Only @nr_open is for the caller to touch. */
struct gwp_up_state {
	/*
	 * Connection pairs that were given a server of this identity and
	 * have not given it back yet: gwp_up_state_take() and _give().
	 */
	_Atomic(uint32_t)	nr_open;

	/* The table's own: under its lock. */
	uint32_t		ref;
	struct gwp_up_table	*tab;
	struct gwp_up_state	*next;
	struct gwp_up_key	key;
};

/* An empty table, or NULL without memory. */
struct gwp_up_table *gwp_up_table_create(void);

/*
 * Free @t and any entry still in it, returning how many there were: each
 * one a server object that was never freed. 0 is what a clean exit leaves.
 * NULL is a no-op returning 0.
 */
uint32_t gwp_up_table_destroy(struct gwp_up_table *t);

/* How many identities @t has entries for now. */
uint32_t gwp_up_table_count(struct gwp_up_table *t);

/*
 * The entry for @key, made (with nothing open) if @t has none yet, with a
 * reference taken for the caller; NULL without memory. Any thread.
 */
struct gwp_up_state *gwp_up_state_get(struct gwp_up_table *t,
				      const struct gwp_up_key *key);

/* Drop a reference gwp_up_state_get() took; NULL is a no-op. Any thread. */
void gwp_up_state_put(struct gwp_up_state *s);

static inline uint32_t gwp_up_state_open(struct gwp_up_state *s)
{
	return atomic_load_explicit(&s->nr_open, memory_order_relaxed);
}

/* A pair takes a slot of @s: returns the count with it. */
static inline uint32_t gwp_up_state_take(struct gwp_up_state *s)
{
	return atomic_fetch_add_explicit(&s->nr_open, 1,
					 memory_order_relaxed) + 1;
}

/*
 * A pair gives its slot of @s back: returns the count without it, or
 * UINT32_MAX, leaving the count at 0, when there was no slot to give back
 * (a bug in the caller's accounting, for it to report).
 */
static inline uint32_t gwp_up_state_give(struct gwp_up_state *s)
{
	uint32_t old = atomic_load_explicit(&s->nr_open, memory_order_relaxed);

	do {
		if (!old)
			return UINT32_MAX;
	} while (!atomic_compare_exchange_weak_explicit(&s->nr_open, &old,
							old - 1,
							memory_order_relaxed,
							memory_order_relaxed));
	return old - 1;
}

/*
 * Which of a pool's @nr servers (@nr > 0) the next connection goes to. @rr
 * is the pool's round-robin cursor for this pick (it advances once per
 * pick, whatever the method). Round-robin takes server @rr % @nr.
 * Least-connections (@least_conn) takes the server with the fewest open
 * pairs in @open[] (one count per server, in pool order), and among equals
 * the first one from @rr % @nr on, wrapping: the cursor moving on rotates
 * the ties, so servers that are equally loaded share the new connections.
 */
uint32_t gwp_up_lb_pick(bool least_conn, uint32_t rr, const uint32_t *open,
			uint32_t nr);

#endif /* #ifndef GWP_UPSTREAM_LB_H */
