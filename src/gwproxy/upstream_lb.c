// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * Shared upstream server state and the pool's choice of a server; see
 * upstream_lb.h.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <gwproxy/upstream_lb.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/*
 * A hash table behind one lock. Only making and freeing server objects takes
 * it (an ACL load, and the last reference to a server going), never a pick:
 * a connection reaches its entry through its server object. A rule set may
 * list many thousands of identities (pools of up to 8192 servers), and a
 * reload gets every one of them again and puts the old ones, so both are
 * O(1) expected: chained buckets, doubled when the entries outnumber them.
 * They never shrink; a table that once held many identities keeps the
 * bucket array (8 bytes a bucket) until it is destroyed. The keys come from
 * the ACL file, not from clients, so the hash need not be keyed.
 */
#define UP_TABLE_MIN_BUCKETS	64u

struct gwp_up_table {
	pthread_mutex_t		lock;
	struct gwp_up_state	**bucket;
	uint32_t		nr_bucket;	/* a power of 2 */
	uint32_t		nr;
};

/* FNV-1a over what makes @key, which is zero past it (gwp_up_key_init()). */
static uint32_t key_hash(const struct gwp_up_key *key)
{
	const uint8_t *p = (const uint8_t *)key;
	size_t len = offsetof(struct gwp_up_key, user) + key->ulen, i;
	uint32_t h = 2166136261u;

	for (i = 0; i < len; i++) {
		h ^= p[i];
		h *= 16777619u;
	}
	return h;
}

/*
 * Double @t's buckets, under its lock. Without memory the table keeps the
 * buckets it has: longer chains, still right.
 */
static void table_grow(struct gwp_up_table *t)
{
	uint32_t n = t->nr_bucket * 2, i;
	struct gwp_up_state **b, *s, *next;

	if (n < t->nr_bucket)
		return;
	b = calloc(n, sizeof(*b));
	if (!b)
		return;
	for (i = 0; i < t->nr_bucket; i++) {
		for (s = t->bucket[i]; s; s = next) {
			next = s->next;
			s->next = b[s->hash & (n - 1)];
			b[s->hash & (n - 1)] = s;
		}
	}
	free(t->bucket);
	t->bucket = b;
	t->nr_bucket = n;
}

void gwp_up_key_init(struct gwp_up_key *key, enum gwp_up_scheme scheme,
		     const struct gwp_sockaddr *addr, const char *user,
		     size_t ulen)
{
	memset(key, 0, sizeof(*key));
	key->scheme = (uint8_t)scheme;
	key->family = (uint8_t)addr->sa.sa_family;
	if (addr->sa.sa_family == AF_INET6) {
		memcpy(key->port, &addr->i6.sin6_port, 2);
		memcpy(key->ip, &addr->i6.sin6_addr, 16);
		memcpy(key->scope, &addr->i6.sin6_scope_id, 4);
	} else if (addr->sa.sa_family == AF_INET) {
		memcpy(key->port, &addr->i4.sin_port, 2);
		memcpy(key->ip, &addr->i4.sin_addr, 4);
	}
	if (ulen > sizeof(key->user))
		ulen = sizeof(key->user);
	key->ulen = (uint8_t)ulen;
	if (ulen)
		memcpy(key->user, user, ulen);
}

struct gwp_up_table *gwp_up_table_create(void)
{
	struct gwp_up_table *t = calloc(1, sizeof(*t));

	if (!t)
		return NULL;
	t->nr_bucket = UP_TABLE_MIN_BUCKETS;
	t->bucket = calloc(t->nr_bucket, sizeof(*t->bucket));
	if (!t->bucket || pthread_mutex_init(&t->lock, NULL)) {
		free(t->bucket);
		free(t);
		return NULL;
	}
	return t;
}

uint32_t gwp_up_table_destroy(struct gwp_up_table *t)
{
	struct gwp_up_state *s, *next;
	uint32_t left, i;

	if (!t)
		return 0;
	left = t->nr;
	for (i = 0; i < t->nr_bucket; i++) {
		for (s = t->bucket[i]; s; s = next) {
			next = s->next;
			/* The key holds a user name; leave none in freed memory. */
			explicit_bzero(s, sizeof(*s));
			free(s);
		}
	}
	pthread_mutex_destroy(&t->lock);
	free(t->bucket);
	free(t);
	return left;
}

uint32_t gwp_up_table_count(struct gwp_up_table *t)
{
	uint32_t nr;

	pthread_mutex_lock(&t->lock);
	nr = t->nr;
	pthread_mutex_unlock(&t->lock);
	return nr;
}

struct gwp_up_state *gwp_up_state_get(struct gwp_up_table *t,
				      const struct gwp_up_key *key)
{
	uint32_t h = key_hash(key);
	struct gwp_up_state *s, **b;
	void *mem;

	pthread_mutex_lock(&t->lock);
	b = &t->bucket[h & (t->nr_bucket - 1)];
	for (s = *b; s; s = s->next) {
		if (s->hash == h && !memcmp(&s->key, key, sizeof(*key))) {
			s->ref++;
			goto out;
		}
	}
	/* Aligned, for @nr_open's line to be its own. */
	if (posix_memalign(&mem, GWP_UP_CACHELINE, sizeof(*s)))
		mem = NULL;
	s = mem;
	if (s) {
		uint32_t i;

		memset(s, 0, sizeof(*s));
		atomic_init(&s->nr_open, 0);
		atomic_init(&s->fail_seq, 0);
		for (i = 0; i < GWP_UP_EJECT_FAILS; i++)
			atomic_init(&s->fail_at[i], 0);
		atomic_init(&s->eject_end, 0);
		s->ref = 1;
		s->tab = t;
		s->key = *key;
		s->hash = h;
		s->next = *b;
		*b = s;
		if (++t->nr > t->nr_bucket)
			table_grow(t);
	}
out:
	pthread_mutex_unlock(&t->lock);
	return s;
}

void gwp_up_state_put(struct gwp_up_state *s)
{
	struct gwp_up_table *t;
	struct gwp_up_state **pp;

	if (!s)
		return;
	t = s->tab;
	pthread_mutex_lock(&t->lock);
	if (--s->ref) {
		pthread_mutex_unlock(&t->lock);
		return;
	}
	for (pp = &t->bucket[s->hash & (t->nr_bucket - 1)]; *pp != s;
	     pp = &(*pp)->next)
		;
	*pp = s->next;
	t->nr--;
	pthread_mutex_unlock(&t->lock);
	explicit_bzero(s, sizeof(*s));
	free(s);
}

/* A time as stored: 0 means none, so a time that is 0 is taken as 1. */
static uint32_t stamp(uint32_t t)
{
	return t ? t : 1;
}

/*
 * How far @a is after @b, negative when it is before, right across the
 * 2^32 wrap as long as the two are less than 2^31 ms apart.
 */
static int32_t ms_after(uint32_t a, uint32_t b)
{
	return (int32_t)(a - b);
}

bool gwp_up_state_fail(struct gwp_up_state *s, uint32_t now)
{
	uint32_t seq = atomic_fetch_add(&s->fail_seq, 1);
	uint32_t t, end, i;

	/*
	 * Sequentially consistent, the store and the loads: whichever
	 * failure stores last sees every other one's time.
	 */
	atomic_store(&s->fail_at[seq % GWP_UP_EJECT_FAILS], stamp(now));
	for (i = 0; i < GWP_UP_EJECT_FAILS; i++) {
		t = atomic_load(&s->fail_at[i]);
		/* Another worker's clock may be a little ahead (< 0). */
		if (!t || ms_after(now, t) > (int32_t)GWP_UP_EJECT_WINDOW_MS)
			return false;
	}

	end = atomic_load(&s->eject_end);
	do {
		if (end && ms_after(end, now) > 0)
			return false;	/* ejected already */
	} while (!atomic_compare_exchange_weak(&s->eject_end, &end,
					       stamp(now + GWP_UP_EJECT_MS)));
	return true;
}

uint32_t gwp_up_state_ejected(struct gwp_up_state *s, uint32_t now,
			      bool *back)
{
	uint32_t end = atomic_load_explicit(&s->eject_end,
					    memory_order_relaxed);

	if (back)
		*back = false;
	if (!end)
		return 0;
	if (ms_after(end, now) > 0)
		return (uint32_t)ms_after(end, now);
	if (atomic_compare_exchange_strong(&s->eject_end, &end, 0)) {
		if (back)
			*back = true;
		return 0;
	}
	/* Ended by another caller, or ejected again meanwhile. */
	return end && ms_after(end, now) > 0 ? (uint32_t)ms_after(end, now) : 0;
}

/* A pick in progress: the clock, read once when first needed. */
struct pick {
	const struct gwp_up_pick	*pk;
	uint32_t			now;
	bool				have_now;
};

/*
 * How long the ejection of the @i-th server (non-NULL) still runs, 0 while
 * it is in service; reads the clock only for a server that may be ejected.
 */
static uint32_t pick_ejected(struct pick *c, struct gwp_up_state *s,
			     uint32_t i)
{
	const struct gwp_up_pick *pk = c->pk;
	uint32_t left;
	bool back;

	if (!gwp_up_state_may_be_ejected(s))
		return 0;
	if (!c->have_now) {
		c->now = pk->now(pk->arg);
		c->have_now = true;
	}
	left = gwp_up_state_ejected(s, c->now, &back);
	if (back && pk->back)
		pk->back(pk->arg, i);
	return left;
}

uint32_t gwp_up_lb_pick(const struct gwp_up_pick *pk)
{
	struct pick c = { .pk = pk };
	uint32_t nr = pk->nr, skip = pk->skip, best = UINT32_MAX;
	uint32_t best_val = UINT32_MAX, i, k, v;
	bool retry = skip < nr;
	struct gwp_up_state *s;

	if (!nr)
		return UINT32_MAX;
	if (retry)
		i = skip + 1 < nr ? skip + 1 : 0;
	else
		i = pk->rr % nr;

	for (k = 0; k < nr; k++, i = i + 1 < nr ? i + 1 : 0) {
		s = pk->st[i];
		if (i == skip || !s)
			continue;
		if (!pk->least_conn) {
			if (!pick_ejected(&c, s, i))
				return i;
			continue;
		}
		/* Not fewer than the best so far: its health does not matter. */
		v = gwp_up_state_open(s);
		if ((best != UINT32_MAX && v >= best_val) ||
		    pick_ejected(&c, s, i))
			continue;
		best = i;
		best_val = v;
		if (!v)
			break;
	}
	if (best != UINT32_MAX || retry)
		return best;

	/* All ejected: the one back soonest, ties in turn. */
	i = pk->rr % nr;
	for (k = 0; k < nr; k++, i = i + 1 < nr ? i + 1 : 0) {
		s = pk->st[i];
		if (!s)
			continue;
		v = pick_ejected(&c, s, i);
		/* Back meanwhile: in service again. */
		if (!v)
			return i;
		if (v < best_val) {
			best = i;
			best_val = v;
		}
	}
	return best;
}
