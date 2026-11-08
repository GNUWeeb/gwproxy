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

/*
 * Free @s, out of its table, with whatever health it still has: none, unless
 * server objects were leaked.
 */
static void state_free(struct gwp_up_state *s)
{
	struct gwp_up_health *h, *next;

	for (h = s->health; h; h = next) {
		next = h->next;
		free(h);
	}
	pthread_mutex_destroy(&s->hlock);
	free(s->fail_at);
	/* The key holds a user name; leave none in freed memory. */
	explicit_bzero(s, sizeof(*s));
	free(s);
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
			state_free(s);
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
		memset(s, 0, sizeof(*s));
		if (pthread_mutex_init(&s->hlock, NULL)) {
			free(s);
			s = NULL;
			goto out;
		}
		atomic_init(&s->nr_open, 0);
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
	state_free(s);
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

/*
 * Make room in @s's failure ring for the last @n failures, keeping those it
 * has, oldest first; under @s's hlock. False without memory.
 */
static bool fail_ring_grow(struct gwp_up_state *s, uint32_t n)
{
	uint32_t *v, i, k;

	if (n <= s->fail_cap)
		return true;
	v = calloc(n, sizeof(*v));
	if (!v)
		return false;
	for (i = 0; i < s->fail_nr; i++) {
		k = (s->fail_next + s->fail_cap - s->fail_nr + i) % s->fail_cap;
		v[i] = s->fail_at[k];
	}
	free(s->fail_at);
	s->fail_at = v;
	s->fail_cap = n;
	s->fail_next = s->fail_nr % n;
	return true;
}

struct gwp_up_health *gwp_up_health_get(struct gwp_up_state *s,
					const struct gwp_up_opts *o)
{
	struct gwp_up_health *h;

	pthread_mutex_lock(&s->hlock);
	for (h = s->health; h; h = h->next) {
		if (h->max_fails == o->max_fails &&
		    h->window_ms == o->fail_timeout_ms &&
		    h->eject_ms == o->eject_ms) {
			h->ref++;
			goto out;
		}
	}
	h = NULL;
	if (!fail_ring_grow(s, o->max_fails))
		goto out;
	h = calloc(1, sizeof(*h));
	if (!h)
		goto out;
	atomic_init(&h->eject_end, 0);
	h->max_fails = o->max_fails;
	h->window_ms = o->fail_timeout_ms;
	h->eject_ms = o->eject_ms;
	h->ref = 1;
	h->st = s;
	h->next = s->health;
	s->health = h;
out:
	pthread_mutex_unlock(&s->hlock);
	return h;
}

void gwp_up_health_put(struct gwp_up_health *h)
{
	struct gwp_up_state *s;
	struct gwp_up_health **pp;

	if (!h)
		return;
	s = h->st;
	pthread_mutex_lock(&s->hlock);
	if (--h->ref) {
		pthread_mutex_unlock(&s->hlock);
		return;
	}
	for (pp = &s->health; *pp != h; pp = &(*pp)->next)
		;
	*pp = h->next;
	pthread_mutex_unlock(&s->hlock);
	free(h);
}

/*
 * Whether the failure just recorded in @s, at @now, ejects the server for
 * @h: its last max_fails failures all fall within its window, and it was in
 * service. Under @s's hlock.
 */
static bool health_fail(struct gwp_up_state *s, struct gwp_up_health *h,
			uint32_t now)
{
	uint32_t t, end, i;

	if (s->fail_nr < h->max_fails)
		return false;
	for (i = 1; i <= h->max_fails; i++) {
		t = s->fail_at[(s->fail_next + s->fail_cap - i) % s->fail_cap];
		/* Another worker's clock may be a little ahead (< 0). */
		if (!t || ms_after(now, t) > (int32_t)h->window_ms)
			return false;
	}

	/* The ejection is ended by picks, which take no lock. */
	end = atomic_load(&h->eject_end);
	do {
		if (end && ms_after(end, now) > 0)
			return false;	/* ejected already */
	} while (!atomic_compare_exchange_weak(&h->eject_end, &end,
					       stamp(now + h->eject_ms)));
	return true;
}

bool gwp_up_state_fail(struct gwp_up_state *s, struct gwp_up_health *own,
		       uint32_t now,
		       void (*ejected)(void *arg, const struct gwp_up_health *h),
		       void *arg)
{
	struct gwp_up_health *h;
	bool ret = false;

	pthread_mutex_lock(&s->hlock);
	if (s->fail_cap) {
		s->fail_at[s->fail_next] = stamp(now);
		s->fail_next = (s->fail_next + 1) % s->fail_cap;
		if (s->fail_nr < s->fail_cap)
			s->fail_nr++;
	}
	for (h = s->health; h; h = h->next) {
		if (!health_fail(s, h, now))
			continue;
		if (h == own)
			ret = true;
		else if (ejected)
			ejected(arg, h);
	}
	pthread_mutex_unlock(&s->hlock);
	return ret;
}

uint32_t gwp_up_health_ejected(struct gwp_up_health *h, uint32_t now,
			       bool *back)
{
	uint32_t end;

	if (back)
		*back = false;
	if (!h)
		return 0;
	end = atomic_load_explicit(&h->eject_end, memory_order_relaxed);
	if (!end)
		return 0;
	if (ms_after(end, now) > 0)
		return (uint32_t)ms_after(end, now);
	if (atomic_compare_exchange_strong(&h->eject_end, &end, 0)) {
		if (back)
			*back = true;
		return 0;
	}
	/* Ended by another caller, or ejected again meanwhile. */
	return end && ms_after(end, now) > 0 ? (uint32_t)ms_after(end, now) : 0;
}

static uint32_t member_weight(const struct gwp_up_member *m)
{
	return m->weight ? m->weight : 1;
}

/*
 * The server that owns the unit at the point @x (a fraction of 2^32) of
 * the weights' sum: the first from @lo whose @cum is above it, among the
 * @n from @lo (which hold it). A binary search without branches to
 * mispredict, as the turns hop around the pool: the answer stays in
 * [lo, lo + n).
 */
static uint32_t owner_in(const struct gwp_up_plan *pl, uint32_t x,
			 uint32_t lo, uint32_t n)
{
	uint32_t u = (uint32_t)(((uint64_t)x * pl->total) >> 32), half;

	while (n > 1) {
		half = n / 2;
		lo = pl->cum[lo + half - 1] <= u ? lo + half : lo;
		n -= half;
	}
	return lo;
}

/* The server that owns the unit at the point @x, through @pl's slices. */
static uint32_t plan_owner(const struct gwp_up_plan *pl, uint32_t x)
{
	uint32_t s = x >> pl->shift;

	return owner_in(pl, x, pl->first[s],
			(uint32_t)pl->first[s + 1] - pl->first[s] + 1u);
}

struct gwp_up_plan *gwp_up_plan_build(const struct gwp_up_member *m,
				      uint32_t nr)
{
	uint32_t i, sum = 0, k = 1, nr_slice;
	struct gwp_up_plan *pl;
	bool equal = true;
	uint16_t *first;
	size_t size;

	for (i = 1; i < nr; i++)
		if (member_weight(&m[i]) != member_weight(&m[0]))
			equal = false;
	if (equal) {
		pl = calloc(1, sizeof(*pl));
		if (pl)
			pl->nr = nr;
		return pl;
	}

	/* 2^k slices, at least as many as servers (at least 2 of them). */
	while ((1u << k) < nr)
		k++;
	nr_slice = 1u << k;
	size = sizeof(*pl) + nr * sizeof(pl->cum[0]) +
	       (nr_slice + 1) * sizeof(*first);
	pl = calloc(1, size);
	if (!pl)
		return NULL;
	/* At most 8192 servers of weight 1000 at most: no overflow. */
	for (i = 0; i < nr; i++) {
		sum += member_weight(&m[i]);
		pl->cum[i] = sum;
	}
	pl->total = sum;
	pl->nr = nr;
	pl->shift = 32 - k;
	first = (uint16_t *)(void *)&pl->cum[nr];
	for (i = 0; i < nr_slice; i++)
		first[i] = (uint16_t)owner_in(pl, i << pl->shift, 0, nr);
	first[nr_slice] = (uint16_t)(nr - 1);
	pl->first = first;
	return pl;
}

/* @x's 32 bits in the reverse order. */
static uint32_t bit_reverse(uint32_t x)
{
	x = ((x >> 1) & 0x55555555u) | ((x & 0x55555555u) << 1);
	x = ((x >> 2) & 0x33333333u) | ((x & 0x33333333u) << 2);
	x = ((x >> 4) & 0x0f0f0f0fu) | ((x & 0x0f0f0f0fu) << 4);
	x = ((x >> 8) & 0x00ff00ffu) | ((x & 0x00ff00ffu) << 8);
	return (x >> 16) | (x << 16);
}

/* Whose turn the cursor @rr is in a pool of @nr servers planned by @pl. */
static uint32_t turn_of(const struct gwp_up_plan *pl, uint32_t nr, uint32_t rr)
{
	if (!pl || !pl->total)
		return rr % nr;
	return plan_owner(pl, bit_reverse(rr));
}

/* A server drawn by the random number @r: uniformly, or by weight. */
static uint32_t drawn_by(const struct gwp_up_plan *pl, uint32_t nr, uint32_t r)
{
	/* Uniform over [0, n), no division. */
	if (!pl || !pl->total)
		return (uint32_t)(((uint64_t)r * nr) >> 32);
	return plan_owner(pl, r);
}

/*
 * Whether @v open pairs on a server of weight @w are fewer for its weight
 * than @bv on one of weight @bw: exact, by cross-multiplying.
 */
static bool fewer_open(uint32_t v, uint32_t w, uint32_t bv, uint32_t bw)
{
	return (uint64_t)v * bw < (uint64_t)bv * w;
}

/* A pick in progress: the clock, read once when first needed. */
struct pick {
	const struct gwp_up_pick	*pk;
	uint32_t			now;
	bool				have_now;
};

/*
 * How long the ejection of the @i-th server still runs, 0 while it is in
 * service; reads the clock only for a server that may be ejected.
 */
static uint32_t pick_ejected(struct pick *c, uint32_t i)
{
	const struct gwp_up_pick *pk = c->pk;
	struct gwp_up_health *h = pk->m[i].h;
	uint32_t left;
	bool back;

	if (!gwp_up_health_may_be_ejected(h))
		return 0;
	if (!c->have_now) {
		c->now = pk->now(pk->arg);
		c->have_now = true;
	}
	left = gwp_up_health_ejected(h, c->now, &back);
	if (back && pk->back)
		pk->back(pk->arg, i);
	return left;
}

uint32_t gwp_up_lb_pick(const struct gwp_up_pick *pk)
{
	struct pick c = { .pk = pk };
	uint32_t nr = pk->nr, skip = pk->skip, best = UINT32_MAX;
	uint32_t best_val = UINT32_MAX, best_w = 1, i, k, v, w;
	const struct gwp_up_plan *pl = pk->plan;
	bool retry = skip < nr, weighted = pl && pl->total;
	struct gwp_up_state *s;

	if (!nr)
		return UINT32_MAX;
	if (retry)
		i = skip + 1 < nr ? skip + 1 : 0;
	else
		i = turn_of(pl, nr, pk->rr);

	/*
	 * The start's server is the pick (round-robin) or where the ties
	 * start (least_conn). When it cannot be taken, a random one in
	 * service replaces it, if a probe finds one, so its turns are
	 * spread; else round-robin takes the next in service, and
	 * least_conn's ties start where they would have.
	 */
	s = pk->m[i].st;
	if (i == skip || !s || pick_ejected(&c, i)) {
		uint32_t p, j;

		for (p = 0; pk->random && p < GWP_UP_PICK_PROBES; p++) {
			j = drawn_by(pl, nr, pk->random(pk->arg));
			s = pk->m[j].st;
			if (j != skip && s && !pick_ejected(&c, j)) {
				i = j;
				break;
			}
		}
	}
	if (!pk->least_conn) {
		s = pk->m[i].st;
		if (i != skip && s && !pick_ejected(&c, i))
			return i;
	}

	for (k = 0; k < nr; k++, i = i + 1 < nr ? i + 1 : 0) {
		s = pk->m[i].st;
		if (i == skip || !s)
			continue;
		if (!pk->least_conn) {
			if (!pick_ejected(&c, i))
				return i;
			continue;
		}
		/* Not fewer than the best so far: its health does not matter. */
		v = gwp_up_state_open(s);
		w = weighted ? member_weight(&pk->m[i]) : 1;
		if ((best != UINT32_MAX && !fewer_open(v, w, best_val, best_w)) ||
		    pick_ejected(&c, i))
			continue;
		best = i;
		best_val = v;
		best_w = w;
		if (!v)
			break;
	}
	if (best != UINT32_MAX || retry)
		return best;

	/* All ejected: the one back soonest, ties in turn. */
	best_val = UINT32_MAX;
	i = pk->rr % nr;
	for (k = 0; k < nr; k++, i = i + 1 < nr ? i + 1 : 0) {
		s = pk->m[i].st;
		if (!s)
			continue;
		v = pick_ejected(&c, i);
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
