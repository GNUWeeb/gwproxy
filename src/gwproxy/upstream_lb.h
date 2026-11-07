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
 * The entry also holds the server's passive health: the times of its last
 * upstream-side failures, and whether it is ejected, and until when. Too
 * many failures in a short time take the server out of its pools' picks
 * for a while (gwp_up_state_fail(), gwp_up_lb_pick()). Like the counts, it
 * follows the identity across a reload, and starts fresh once the last
 * object of the identity is gone. Times are monotonic milliseconds, passed
 * in by the caller, so the rules can be tested without a clock. They are
 * 32 bits wide, as some 32-bit targets have no lock-free 64-bit atomics:
 * they wrap every 2^32 ms (about 49.7 days), and are only ever compared by
 * their difference as a signed 32-bit number, which is right across the
 * wrap for times less than 2^31 ms (about 24.8 days) apart; the window
 * and the ejection are far shorter. 0 is reserved for "none", and a time
 * that comes out as 0 is taken as 1.
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

/*
 * Passive health, fixed in this version: GWP_UP_EJECT_FAILS upstream-side
 * failures with no more than GWP_UP_EJECT_WINDOW_MS from the first to the
 * last eject a server for GWP_UP_EJECT_MS.
 */
#define GWP_UP_EJECT_FAILS	3u
#define GWP_UP_EJECT_WINDOW_MS	30000u
#define GWP_UP_EJECT_MS		300000u

struct gwp_up_table;

/* What false sharing is measured in. */
#define GWP_UP_CACHELINE	64

/*
 * One identity's shared state. Only @nr_open is for the caller to touch;
 * the health fields go through gwp_up_state_fail() and _ejected().
 *
 * @nr_open is written by every worker on every pair it opens or closes
 * through the server, so it has a cache line of its own: a round-robin
 * pick reads only the health fields, and they and the table's fields
 * must not be on the line those writes keep taking from the reader.
 */
struct gwp_up_state {
	/*
	 * Connection pairs that were given a server of this identity and
	 * have not given it back yet: gwp_up_state_take() and _give().
	 */
	_Alignas(GWP_UP_CACHELINE) _Atomic(uint32_t) nr_open;

	/* How many failures were ever recorded; picks the slot of the next. */
	_Alignas(GWP_UP_CACHELINE) _Atomic(uint32_t) fail_seq;
	/* When the last GWP_UP_EJECT_FAILS failures were, 0 for none. */
	_Atomic(uint32_t)	fail_at[GWP_UP_EJECT_FAILS];
	/* When the ejection ends, 0 while the server is in service. */
	_Atomic(uint32_t)	eject_end;

	/* The table's own: under its lock. */
	uint32_t		ref;
	uint32_t		hash;		/* of @key */
	struct gwp_up_table	*tab;
	struct gwp_up_state	*next;		/* in its bucket */
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
 * Record an upstream-side failure of @s at @now. Returns true when it is
 * the one that ejects the server: the last GWP_UP_EJECT_FAILS failures,
 * this one included, fall within GWP_UP_EJECT_WINDOW_MS, and the server
 * was in service. It is then ejected until @now + GWP_UP_EJECT_MS; the
 * caller logs that. Any thread, no lock.
 *
 * Concurrent failures each take a slot of their own, and the last one to
 * store its time sees all the others', so failures from several workers
 * that are enough to eject do; the ejection itself is a compare-and-swap,
 * so exactly one of them returns true. A failure while the server is
 * ejected is recorded but neither extends nor repeats the ejection; one
 * soon after the ejection ends can eject again, as the failures recorded
 * meanwhile still count. A success changes nothing: failures leave the
 * window by age only.
 *
 * A failure recorded a multiple of 2^32 ms ago, give or take the window,
 * reads as recent again; it takes three of them, or two and a new one, to
 * eject, so this is left as it is.
 */
bool gwp_up_state_fail(struct gwp_up_state *s, uint32_t now);

/*
 * Whether @s may be ejected, without a clock: false means it is in
 * service, true that gwp_up_state_ejected() has to tell.
 */
static inline bool gwp_up_state_may_be_ejected(struct gwp_up_state *s)
{
	return atomic_load_explicit(&s->eject_end, memory_order_relaxed) != 0;
}

/*
 * How many milliseconds the ejection of @s still has to run at @now, 0
 * when the server is in service. An ejection that has run out by @now is
 * ended here, and *@back, when not NULL, says whether it was this call that
 * ended it, so that exactly one caller logs the server's return. Any
 * thread, no lock. An ejection nobody looked at for 2^31 ms or more may
 * read as running again, for at most its 5 minutes.
 */
uint32_t gwp_up_state_ejected(struct gwp_up_state *s, uint32_t now,
			      bool *back);

/*
 * Which of a pool's @nr servers (@nr > 0) the next connection goes to. @rr
 * is the pool's round-robin cursor for this pick (it advances once per
 * pick, whatever the method). @eject[] holds, per server in pool order,
 * how long its ejection still runs (gwp_up_state_ejected()), 0 while it is
 * in service (NULL: all are); the
 * pick only takes a server in service, other than @skip (UINT32_MAX for
 * none). Round-robin takes the (@rr % n)-th of the n servers it may take,
 * in pool order, so an ejected server's share is spread evenly over the
 * rest. Least-connections (@least_conn) takes the one with the fewest
 * open pairs in @open[] (one count per server, in pool order), and among
 * equals the first one from that same server on, wrapping: the cursor
 * moving on rotates the ties, so servers that are equally loaded share
 * the new connections.
 *
 * When no server may be taken: with no @skip, every server is ejected,
 * and the one whose ejection ends soonest is taken (ties from @rr % @nr
 * on), so a pool is never left without a server; with a @skip (a retry,
 * which goes only to another server in service) UINT32_MAX.
 */
uint32_t gwp_up_lb_pick(bool least_conn, uint32_t rr, const uint32_t *open,
			const uint32_t *eject, uint32_t nr, uint32_t skip);

#endif /* #ifndef GWP_UPSTREAM_LB_H */
