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
 * upstream-side failures. Too many failures in a short time take the
 * server out of a pool's picks for a while (gwp_up_state_fail(),
 * gwp_up_lb_pick()). How many, how short and how long are a pool's own
 * settings for the server (struct gwp_up_opts): pools that list the same
 * server may differ. So the failures are the identity's, and what they
 * mean is decided per settings: one ejection state (struct gwp_up_health)
 * for each set of settings the identity is listed with, shared by the
 * pools that list it so. Like the counts, both follow the identity across
 * a reload (an ejection only while its settings stay the same), and start
 * fresh once the last object of the identity is gone. Times are monotonic
 * milliseconds, passed in by the caller, so the rules can be tested
 * without a clock. They are 32 bits wide, as some 32-bit targets have no
 * lock-free 64-bit atomics: they wrap every 2^32 ms (about 49.7 days), and
 * are only ever compared by their difference as a signed 32-bit number,
 * which is right across the wrap for times less than 2^31 ms (about 24.8
 * days) apart; the window and the ejection are far shorter (at most
 * GWP_UP_MAX_TIME_MS). 0 is reserved for "none", and a time that comes out
 * as 0 is taken as 1.
 *
 * Self-contained (net.h types and libc only) so it can be unit-tested alone.
 */
#ifndef GWP_UPSTREAM_LB_H
#define GWP_UPSTREAM_LB_H

#include <pthread.h>
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
 * Passive health, by default: GWP_UP_EJECT_FAILS upstream-side failures
 * with no more than GWP_UP_EJECT_WINDOW_MS from the first to the last
 * eject a server for GWP_UP_EJECT_MS. A pool may set its own for each of
 * its servers (struct gwp_up_opts).
 */
#define GWP_UP_EJECT_FAILS	3u
#define GWP_UP_EJECT_WINDOW_MS	30000u
#define GWP_UP_EJECT_MS		300000u

/*
 * The most failures a pool may ask for (max_fails=), and the longest window
 * or ejection (fail_timeout=, eject_time=): a day, far below the 2^31 ms
 * the 32-bit times can compare.
 */
#define GWP_UP_MAX_FAILS	100u
#define GWP_UP_MAX_TIME_MS	86400000u

/* The heaviest weight a pool may give a server (weight=). */
#define GWP_UP_MAX_WEIGHT	1000u

/* The longest ramp a pool may give a server back in service (slow_start=). */
#define GWP_UP_MAX_SLOW_START_MS	3600000u

/* The highest cap a pool may put on a server's open pairs (max_conns=). */
#define GWP_UP_MAX_CONNS	1000000u

/* What a pool sets for one of its servers. */
struct gwp_up_opts {
	/* Its share of the pool's connections, 1 to GWP_UP_MAX_WEIGHT. */
	uint32_t	weight;
	/*
	 * The most pairs it may have open (of its identity, through any
	 * pool) for this pool to give it another, up to GWP_UP_MAX_CONNS;
	 * 0 for no cap.
	 */
	uint32_t	max_conns;
	/* Taken only when no other server (no other backup) may be. */
	bool		backup;
	/* Never taken. */
	bool		down;
	/*
	 * The failures within @fail_timeout_ms that eject the server, for
	 * @eject_ms; 0 (at most GWP_UP_MAX_FAILS) never ejects it. Both
	 * times from 1 to GWP_UP_MAX_TIME_MS.
	 */
	uint32_t	max_fails;
	uint32_t	fail_timeout_ms;
	uint32_t	eject_ms;
	/*
	 * How long, up to GWP_UP_MAX_SLOW_START_MS, the server takes to grow
	 * from next to nothing to its full weight when it comes back into
	 * service (struct gwp_up_health); 0 for no ramp.
	 */
	uint32_t	slow_start_ms;
};

/* @o set to what a server has when its pool sets nothing. */
static inline void gwp_up_opts_default(struct gwp_up_opts *o)
{
	o->weight = 1;
	o->max_conns = 0;
	o->backup = false;
	o->down = false;
	o->max_fails = GWP_UP_EJECT_FAILS;
	o->fail_timeout_ms = GWP_UP_EJECT_WINDOW_MS;
	o->eject_ms = GWP_UP_EJECT_MS;
	o->slow_start_ms = 0;
}

struct gwp_up_table;

/* What false sharing is measured in. */
#define GWP_UP_CACHELINE	64

struct gwp_up_health;

/*
 * One identity's shared state. Only @nr_open is for the caller to touch;
 * the health fields go through gwp_up_state_fail() and gwp_up_health_*().
 *
 * @nr_open is written by every worker on every pair it opens or closes
 * through the server, so it has a cache line of its own: a round-robin
 * pick reads only the health, and it and the table's fields must not be on
 * the line those writes keep taking from the reader.
 */
struct gwp_up_state {
	/*
	 * Connection pairs that were given a server of this identity and
	 * have not given it back yet: gwp_up_state_take() and _give().
	 */
	_Alignas(GWP_UP_CACHELINE) _Atomic(uint32_t) nr_open;

	/*
	 * The health: under @hlock, which only failures and the making and
	 * freeing of server objects take, never a pick. @fail_at holds the
	 * times of the last @fail_nr failures (at most @fail_cap, as many as
	 * the largest max_fails of @health asked for), the next one going to
	 * @fail_next, wrapping. @health lists the ejection states of the
	 * settings the identity is listed with.
	 */
	_Alignas(GWP_UP_CACHELINE) pthread_mutex_t hlock;
	uint32_t		*fail_at;
	uint32_t		fail_cap;
	uint32_t		fail_nr;
	uint32_t		fail_next;
	struct gwp_up_health	*health;

	/* The table's own: under its lock. */
	uint32_t		ref;
	uint32_t		hash;		/* of @key */
	struct gwp_up_table	*tab;
	struct gwp_up_state	*next;		/* in its bucket */
	struct gwp_up_key	key;
};

/*
 * Whether an identity is ejected, and how far it is in its slow start, for
 * the pools that list it with one set of health settings (max_fails >= 1
 * or slow_start_ms >= 1). Only @eject_end and @ramp_end change once it is
 * made; they are read by every pick that looks at the server, side by side.
 *
 * The slow start: when the server comes back into service for these
 * settings, its weight grows linearly from next to nothing to the full
 * weight over @slow_ms (gwp_up_health_ramp()), so that it is not handed a
 * whole share of the new connections at once. It comes back so when an
 * ejection ends: the ramp is set to run from the end of the ejection when
 * the ejection is made, so an ejection during a ramp starts it again after
 * it. And when a pool comes to list it in service with these settings while
 * no other pool did (gwp_up_health_join()): a reload that adds it, or that
 * takes it out of down.
 */
struct gwp_up_health {
	/* When the ejection ends, 0 while the server is in service. */
	_Atomic(uint32_t)	eject_end;
	/* When the slow start ends, 0 when there is none to run. */
	_Atomic(uint32_t)	ramp_end;
	uint32_t		max_fails;
	uint32_t		window_ms;
	uint32_t		eject_ms;
	uint32_t		slow_ms;
	/* Under @st's hlock. */
	uint32_t		ref;
	/* Of @ref, those held for pools that list the server in service. */
	uint32_t		nr_joined;
	struct gwp_up_state	*st;
	struct gwp_up_health	*next;		/* in @st's list */
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
 * A pair takes a slot of @s if fewer than @max are taken: returns whether it
 * did. Exact under any concurrency, so @max is never passed.
 */
static inline bool gwp_up_state_take_max(struct gwp_up_state *s, uint32_t max)
{
	uint32_t old = atomic_load_explicit(&s->nr_open, memory_order_relaxed);

	do {
		if (old >= max)
			return false;
	} while (!atomic_compare_exchange_weak_explicit(&s->nr_open, &old,
							old + 1,
							memory_order_relaxed,
							memory_order_relaxed));
	return true;
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
 * The ejection state of @s for the settings @o (whose max_fails or
 * slow_start_ms is at least 1), shared with every other server object of
 * @s's identity listed with the same max_fails, fail_timeout, eject_time
 * and slow_start, made in service (and with no ramp) if there is none yet,
 * with a reference taken for the caller; NULL without memory. It is valid
 * while the caller holds both that reference and its reference to @s. Any
 * thread.
 */
struct gwp_up_health *gwp_up_health_get(struct gwp_up_state *s,
					const struct gwp_up_opts *o);

/* Drop a reference gwp_up_health_get() took; NULL is a no-op. Any thread. */
void gwp_up_health_put(struct gwp_up_health *h);

/*
 * A pool now lists @h's server in service (not down) with @h's settings:
 * count it, for as long as that pool lives (gwp_up_health_leave()). When no
 * pool did before and @now is not 0, the server comes into service for @h
 * at @now and starts its slow start, if @h has one: returns whether it
 * did. A first load passes 0, as nothing was in service before it to
 * protect the newcomer from; a reload its clock. A ramp under way is left
 * as it is. NULL is a no-op returning false. Any thread.
 */
bool gwp_up_health_join(struct gwp_up_health *h, uint32_t now);

/* Undo one gwp_up_health_join(); NULL is a no-op. Any thread. */
void gwp_up_health_leave(struct gwp_up_health *h);

/* The full weight in gwp_up_health_ramp()'s units. */
#define GWP_UP_RAMP_ONE		65536u

/*
 * Whether @h may be in a slow start, without a clock: false means it is
 * not (never with no @h), true that gwp_up_health_ramp() has to tell.
 */
static inline bool gwp_up_health_may_ramp(struct gwp_up_health *h)
{
	return h && atomic_load_explicit(&h->ramp_end,
					 memory_order_relaxed) != 0;
}

/*
 * How much of its weight @h's server has at @now, in 1/GWP_UP_RAMP_ONE:
 * GWP_UP_RAMP_ONE with no slow start running (always with no @h), else
 * the time the ramp has run over its length, linearly, at least 1 (also
 * before it starts, while the ejection it follows still runs). A ramp that
 * has run out by @now is ended here. Any thread, no lock. A ramp nobody
 * looked at for 2^31 ms or more may read as running again, for at most its
 * length.
 */
uint32_t gwp_up_health_ramp(struct gwp_up_health *h, uint32_t now);

/*
 * Record an upstream-side failure of @s at @now, and decide for each of its
 * ejection states whether it ejects the server: when the last max_fails
 * failures, this one included, fall within its fail_timeout, and the
 * server was in service for it. It is then ejected until @now plus its
 * eject_time. Returns whether @own (one of them, or NULL) was so ejected;
 * @ejected, when not NULL, is called with @arg for each other one that
 * was, for the caller to log, under a lock of @s: it must not call back
 * into @s's health. Any thread.
 *
 * Failures from several workers are recorded one at a time, so those that
 * are enough to eject do, and exactly one of them ejects the server for a
 * set of settings. A failure while the server is ejected is recorded but
 * neither extends nor repeats the ejection; one soon after the ejection
 * ends can eject again, as the failures recorded meanwhile still count. A
 * success changes nothing: failures leave the window by age only. The
 * failures recorded are the last that the largest max_fails of the
 * identity's current settings asks for; a set of settings made later, by
 * a reload, sees those that were kept for the settings before it.
 *
 * A failure recorded a multiple of 2^32 ms ago, give or take the window,
 * reads as recent again; it takes max_fails of them, or fewer and a new
 * one, to eject, so this is left as it is.
 */
bool gwp_up_state_fail(struct gwp_up_state *s, struct gwp_up_health *own,
		       uint32_t now,
		       void (*ejected)(void *arg, const struct gwp_up_health *h),
		       void *arg);

/*
 * Whether @h may be ejected, without a clock: false means it is in service
 * (as it always is with no @h), true that gwp_up_health_ejected() has to
 * tell.
 */
static inline bool gwp_up_health_may_be_ejected(struct gwp_up_health *h)
{
	return h && atomic_load_explicit(&h->eject_end,
					 memory_order_relaxed) != 0;
}

/*
 * How many milliseconds the ejection of @h still has to run at @now, 0
 * when the server is in service for it (always with no @h). An ejection
 * that has run out by @now is ended here, and *@back, when not NULL, says
 * whether it was this call that ended it, so that exactly one caller logs
 * the server's return. Any thread, no lock. An ejection nobody looked at
 * for 2^31 ms or more may read as running again, for at most its
 * eject_time.
 */
uint32_t gwp_up_health_ejected(struct gwp_up_health *h, uint32_t now,
			       bool *back);

/*
 * One server of a pool, as a pick sees it: the shared state of its
 * identity, and its ejection state for the pool's settings (NULL: the
 * pool never ejects it).
 */
struct gwp_up_member {
	struct gwp_up_state	*st;
	struct gwp_up_health	*h;
	/*
	 * The pool's cap on its open pairs (struct gwp_up_opts), 0 for
	 * none: at the cap it is full, and not taken.
	 */
	uint32_t		max_conns;
	/* The pool's weight for it, 1 to GWP_UP_MAX_WEIGHT; 0 is taken as 1. */
	uint16_t		weight;
	/* GWP_UP_MEMBER_*. */
	uint8_t			flags;
};

/* A backup (struct gwp_up_opts): in the plan's backup tier. */
#define GWP_UP_MEMBER_BACKUP	0x01u
/* Down: in no tier of the plan, never taken. */
#define GWP_UP_MEMBER_DOWN	0x02u

/*
 * The servers of a pool that a pick chooses among at a time (see struct
 * gwp_up_plan), and how their weights spread their turns.
 *
 * Each server owns as many consecutive units of [0, @total) as its weight:
 * the server at position p those from @cum[p - 1] (0 for the first) up to
 * @cum[p]. The cursor's turn r goes to the owner of the unit at the point
 * r takes in the van der Corput sequence (r's 32 bits reversed, as a
 * fraction of 2^32), scaled to @total. Every 2^b turns in a row that start
 * at a multiple of 2^b fall on 2^b evenly spaced points, so with 2^b >=
 * @total each server gets its weight's share of them, give or take one
 * turn; and as the sequence fills [0, 1) evenly at every length, the turns
 * of each server come at nearly even intervals (no gap more than about
 * three times its share's), not in a burst. The owner of a unit is found
 * by a binary search of @cum, narrowed first by @first: the point's top
 * bits name one of 2^k slices of [0, 1) (2^k the tier's size or more), and
 * @first[s] is the owner of the first unit of slice s, so the search is
 * over the few servers that share the slice, whatever the weights: a pick
 * costs O(1) for weights within a small factor of each other, and
 * O(log n) of the tier's n servers at worst.
 */
struct gwp_up_tier {
	/* How many servers; 0 for an empty tier. */
	uint32_t	n;
	/* The weights summed; 0 when all are equal: plain turns, no @cum. */
	uint32_t	total;
	/* 32 - k: a point's bits that do not choose its slice. */
	uint32_t	shift;
	/*
	 * The place in the pool of the server at each position, in pool
	 * order; NULL when they are the same (every server in this tier).
	 */
	const uint16_t	*idx;
	/* 2^k + 1 of them; the last is the last position. */
	const uint16_t	*first;
	const uint32_t	*cum;
};

/*
 * How a pool picks among its servers, made once from its members
 * (gwp_up_plan_build()) and read-only after: the main tier, of the servers
 * that are neither backups nor down, and the backup tier, of the backups
 * that are not down, each with its own turns by weight. The backups are
 * only looked at when no main server may be taken.
 */
struct gwp_up_plan {
	struct gwp_up_tier	tier[2];
	/*
	 * Each server's position in its tier, UINT16_MAX for one that is
	 * down; NULL when every server is in the main tier, in pool order.
	 */
	const uint16_t		*pos;
	uint32_t		nr;
};

/*
 * The plan of the @nr (at most 65536) members @m, by their weights and
 * flags, or NULL without memory. Free it with free(). A plan whose tiers
 * are both empty (every server down) never picks a server.
 */
struct gwp_up_plan *gwp_up_plan_build(const struct gwp_up_member *m,
				      uint32_t nr);

/* How a pool chooses among its servers (gwp_up_lb_pick()). */
enum gwp_up_method {
	GWP_UP_METHOD_RR		= 0,	/* round-robin, by weight */
	GWP_UP_METHOD_LEAST_CONN	= 1,	/* the fewest open per weight */
	GWP_UP_METHOD_RANDOM		= 2,	/* one drawn by weight */
	GWP_UP_METHOD_RANDOM_TWO	= 3,	/* the fewer open of two drawn */
};

/*
 * What a pool's choice of a server for a connection (gwp_up_lb_pick())
 * goes by.
 */
struct gwp_up_pick {
	/*
	 * The pool's servers, @nr of them in pool order; one whose state
	 * (@st) is NULL is never taken.
	 */
	const struct gwp_up_member	*m;
	uint32_t	nr;
	/*
	 * Made of @m by gwp_up_plan_build(), or NULL: every server in the
	 * main tier, all weights equal (plain turns), whatever @m says.
	 */
	const struct gwp_up_plan	*plan;
	/* enum gwp_up_method. */
	uint8_t		method;
	/*
	 * The pool's round-robin cursor for this pick; unused for a retry,
	 * and by the random methods, but where they fall back to with no
	 * @random.
	 */
	uint32_t	rr;
	/*
	 * For a retry, the server (< @nr) whose attempt failed, never taken
	 * again; UINT32_MAX (or any value from @nr on) for a first pick.
	 */
	uint32_t	skip;
	/*
	 * The monotonic clock in milliseconds, called at most once per pick
	 * and only when a server it looks at may be ejected or in its slow
	 * start.
	 */
	uint32_t	(*now)(void *arg);
	/*
	 * When not NULL, told that the pick ended the ejection of the @i-th
	 * server (gwp_up_health_ejected()'s *back), for the caller to log.
	 */
	void		(*back)(void *arg, uint32_t i);
	/*
	 * A uniformly distributed 32-bit random number, for the probes when
	 * the server whose turn it is (or where least_conn's ties start) is
	 * ejected, for the turns of servers in their slow start, and for the
	 * random methods' draws; called at most GWP_UP_PICK_MAX_RANDOM times
	 * per tier a pick looks at, and by round-robin and least_conn never
	 * when the server whose turn it is is in service and in no slow
	 * start. NULL: no probes, no draws (the random methods then take the
	 * next server in service from @rr on), and round-robin and the random
	 * methods give no thought to slow starts.
	 */
	uint32_t	(*random)(void *arg);
	void		*arg;
};

/*
 * How many random servers a pick tries when the one whose turn it is (or
 * where least_conn's ties start) is ejected, before it falls back to the
 * next in service after it.
 */
#define GWP_UP_PICK_PROBES	4u

/*
 * The most random numbers a pick asks for in a tier (gwp_up_pick::random):
 * a draw and a slow start's chance for each of "random two"'s two draws and
 * GWP_UP_PICK_PROBES more; round-robin asks for fewer.
 */
#define GWP_UP_PICK_MAX_RANDOM	(2u * (GWP_UP_PICK_PROBES + 2u))

/*
 * A small, fast generator for @random (xorshift32): advances *@state, which
 * must not be 0, and returns the new value. Not for anything secret.
 */
static inline uint32_t gwp_up_rand(uint32_t *state)
{
	uint32_t x = *state;

	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	*state = x;
	return x;
}

/*
 * Which of @pk's servers (from 0) the next connection goes to, read in place
 * with no copy and no allocation; only servers in service are taken: those
 * their pool's settings do not have ejected (gwp_up_health_ejected()), and
 * that are not full (as many pairs open as their max_conns). Full servers
 * are passed over as ejected ones are, probes included. The caller takes
 * a slot of a capped server with gwp_up_state_take_max(), and picks again
 * if that finds it full after all: picks on other threads may have filled
 * it meanwhile.
 *
 * The pick is made in the plan's main tier first, then, when no server
 * there may be taken, in its backup tier, in the same way; a server that
 * is down is in neither. Within a tier, in its servers' order (pool order):
 *
 * Round-robin (GWP_UP_METHOD_RR) takes the server whose turn the cursor
 * @rr is when it is in service: the tier's server @rr % n when the weights
 * are equal, else the tier's turns by weight (struct gwp_up_tier). With
 * none ejected that is the cursor's server, and the pick reads one
 * server's health only. When it is ejected, the pick
 * tries up to GWP_UP_PICK_PROBES servers drawn at random (@random; by
 * weight when the weights differ) and takes the first in service, so an
 * ejected server's turns are spread over the rest by their weights, a run
 * of ejected servers' turns too, instead of all going to the server after
 * them; only when every probe misses does it take the next in service
 * from the cursor's server on, in pool order, wrapping, preferring one in
 * no slow start.
 *
 * A server in its slow start, with a fraction f of its weight
 * (gwp_up_health_ramp()), takes a turn, its own or a probe's, only with
 * the chance f (@random); a turn it lets pass goes on as an ejected
 * server's does, so a probe lands on a server by its weight scaled by its
 * ramp, and the server takes about f of its share. Somewhat less when
 * much of the tier ramps at once: the turns that every probe lets pass,
 * too, go to the next server in service in no slow start. With no server
 * in a slow start, this costs one more load of a line the pick reads
 * anyway.
 *
 * Least-connections (GWP_UP_METHOD_LEAST_CONN) takes the server in service
 * with the fewest open pairs for its weight (open / weight, compared
 * exactly; a server in its slow start by its weight scaled by its ramp, so
 * it counts as busier, and takes about f of what it would), among equals
 * the first from the cursor's server on, so the cursor moving on rotates
 * the ties and servers that are equally loaded share the new connections. When the start's server is ejected, the same probes choose
 * another start among the servers in service, so among equals an ejected
 * server's turns are spread too; the choice of the fewest stays exact. It
 * reads every server's open count, stopping at the first idle one in
 * service (none can have fewer), and the health only of a server that
 * would be the best so far.
 *
 * Random (GWP_UP_METHOD_RANDOM) draws a server by weight (@random, as the
 * probes are drawn) and takes it when it may be taken; "random two"
 * (GWP_UP_METHOD_RANDOM_TWO) draws two different ones so and takes the one
 * with fewer open pairs for its weight (compared as least_conn does), the
 * first among equals. A server in its slow start is taken when drawn with
 * the chance its ramp has reached, as round-robin offers it a turn, and
 * compared at its scaled weight. A draw that cannot be taken is made
 * again, up to GWP_UP_PICK_PROBES extra draws in all; when they run out
 * with one server drawn, that one is taken, with none, the next in service
 * from the first one drawn on, in pool order, preferring one in no slow
 * start, as round-robin's fallback. Neither reads the cursor (the caller
 * need not advance it), nor more than the two servers drawn while those
 * may be taken: O(1) for equal weights, the same search as weighted
 * round-robin's turns otherwise.
 *
 * A retry (@skip) starts at the server after @skip in its tier instead of
 * the cursor (at the tier's first in another tier): that one when it is in
 * service, else (round-robin) the same probes and then the next in service
 * in pool order (least-connections: the fewest open, ties from there; the
 * random methods: their draws, then the next in service from there),
 * never @skip itself.
 *
 * When no server may be taken: for a first pick, the one whose ejection
 * ends soonest among the ejected servers that are not full is taken (ties
 * from the tier's @rr % n on), from the main tier if it has one, else from
 * the backups, so a pool is never left without a server for its ejections
 * alone; UINT32_MAX when they are all full (or down). For a retry, which
 * goes only to another server in service, UINT32_MAX. Also UINT32_MAX when
 * @nr is 0 or every state is NULL.
 */
uint32_t gwp_up_lb_pick(const struct gwp_up_pick *pk);

#endif /* #ifndef GWP_UPSTREAM_LB_H */
