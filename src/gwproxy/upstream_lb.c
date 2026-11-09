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
		    h->eject_ms == o->eject_ms &&
		    h->slow_ms == o->slow_start_ms) {
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
	atomic_init(&h->ramp_end, 0);
	h->max_fails = o->max_fails;
	h->window_ms = o->fail_timeout_ms;
	h->eject_ms = o->eject_ms;
	h->slow_ms = o->slow_start_ms;
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

bool gwp_up_health_join(struct gwp_up_health *h, uint32_t now)
{
	bool ramp = false;
	uint32_t end;

	if (!h)
		return false;
	pthread_mutex_lock(&h->st->hlock);
	end = atomic_load(&h->ramp_end);
	if (!h->nr_joined++ && now && h->slow_ms &&
	    (!end || ms_after(end, now) <= 0)) {
		atomic_store(&h->ramp_end, stamp(now + h->slow_ms));
		ramp = true;
	}
	pthread_mutex_unlock(&h->st->hlock);
	return ramp;
}

void gwp_up_health_leave(struct gwp_up_health *h)
{
	if (!h)
		return;
	pthread_mutex_lock(&h->st->hlock);
	if (h->nr_joined)
		h->nr_joined--;
	pthread_mutex_unlock(&h->st->hlock);
}

uint32_t gwp_up_health_ramp(struct gwp_up_health *h, uint32_t now)
{
	uint32_t end, f;
	int32_t left;

	if (!h)
		return GWP_UP_RAMP_ONE;
	end = atomic_load_explicit(&h->ramp_end, memory_order_relaxed);
	if (!end)
		return GWP_UP_RAMP_ONE;
	left = ms_after(end, now);
	if (left <= 0) {
		/* Over; a new ramp set meanwhile stays. */
		atomic_compare_exchange_strong(&h->ramp_end, &end, 0);
		return GWP_UP_RAMP_ONE;
	}
	/* Not started yet: the ejection before it still runs. */
	if ((uint32_t)left >= h->slow_ms)
		return 1;
	f = (uint32_t)(((uint64_t)(h->slow_ms - (uint32_t)left) *
			GWP_UP_RAMP_ONE) / h->slow_ms);
	return f ? f : 1;
}

/*
 * Whether the failure just recorded in @s, at @now, ejects the server for
 * @h: its last max_fails failures all fall within its window, and it was in
 * service. Under @s's hlock. An ejection sets the slow start that follows
 * it, from its end, replacing one under way.
 */
static bool health_fail(struct gwp_up_state *s, struct gwp_up_health *h,
			uint32_t now)
{
	uint32_t t, end, i;

	/* Never ejected: kept for its slow start only. */
	if (!h->max_fails || s->fail_nr < h->max_fails)
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
	if (h->slow_ms)
		atomic_store(&h->ramp_end,
			     stamp(now + h->eject_ms + h->slow_ms));
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

/* The place in the pool of the server at @p in the tier @t. */
static uint32_t tier_member(const struct gwp_up_tier *t, uint32_t p)
{
	return t->idx ? t->idx[p] : p;
}

/*
 * The position in @t of the server that owns the unit at the point @x (a
 * fraction of 2^32) of the tier's weights: the first from @lo whose @cum
 * is above it, among the @n from @lo (which hold it). A binary search
 * without branches to mispredict, as the turns hop around the tier: the
 * answer stays in [lo, lo + n).
 */
static uint32_t owner_in(const struct gwp_up_tier *t, uint32_t x,
			 uint32_t lo, uint32_t n)
{
	uint32_t u = (uint32_t)(((uint64_t)x * t->total) >> 32), half;

	while (n > 1) {
		half = n / 2;
		lo = t->cum[lo + half - 1] <= u ? lo + half : lo;
		n -= half;
	}
	return lo;
}

/* The owner of the unit at the point @x of @t, through its slices. */
static uint32_t tier_owner(const struct gwp_up_tier *t, uint32_t x)
{
	uint32_t s = x >> t->shift;

	return owner_in(t, x, t->first[s],
			(uint32_t)t->first[s + 1] - t->first[s] + 1u);
}

/* The flag bits of @m that choose its tier, 2 for none (down). */
static uint32_t member_tier(const struct gwp_up_member *m)
{
	if (m->flags & GWP_UP_MEMBER_DOWN)
		return 2;
	return (m->flags & GWP_UP_MEMBER_BACKUP) ? 1 : 0;
}

struct gwp_up_plan *gwp_up_plan_build(const struct gwp_up_member *m,
				      uint32_t nr)
{
	uint32_t n[2] = { 0, 0 }, w0[2] = { 0, 0 }, k[2] = { 0, 0 };
	uint32_t at[2] = { 0, 0 }, i, t, p, sum;
	bool eq[2] = { true, true }, ident;
	struct gwp_up_plan *pl;
	struct gwp_up_tier *tr;
	uint16_t *pos = NULL;
	size_t size, off;
	char *base;

	for (i = 0; i < nr; i++) {
		t = member_tier(&m[i]);
		if (t > 1)
			continue;
		if (!n[t])
			w0[t] = member_weight(&m[i]);
		else if (member_weight(&m[i]) != w0[t])
			eq[t] = false;
		n[t]++;
	}
	/* Every server in the main tier, in pool order: no maps needed. */
	ident = n[0] == nr;

	/* The 32-bit arrays first, then the 16-bit ones. */
	size = sizeof(*pl);
	for (t = 0; t < 2; t++)
		if (!eq[t])
			size += n[t] * sizeof(uint32_t);
	for (t = 0; t < 2; t++) {
		if (!ident)
			size += n[t] * sizeof(uint16_t);
		if (eq[t])
			continue;
		/* 2^k slices, at least as many as servers (2 at least). */
		k[t] = 1;
		while ((1u << k[t]) < n[t])
			k[t]++;
		size += ((1u << k[t]) + 1) * sizeof(uint16_t);
	}
	if (!ident)
		size += nr * sizeof(uint16_t);
	pl = calloc(1, size);
	if (!pl)
		return NULL;
	pl->nr = nr;
	base = (char *)pl;
	off = sizeof(*pl);
	for (t = 0; t < 2; t++) {
		pl->tier[t].n = n[t];
		if (eq[t])
			continue;
		pl->tier[t].cum = (uint32_t *)(void *)(base + off);
		off += n[t] * sizeof(uint32_t);
	}
	for (t = 0; t < 2; t++) {
		if (!ident) {
			pl->tier[t].idx = (uint16_t *)(void *)(base + off);
			off += n[t] * sizeof(uint16_t);
		}
		if (eq[t])
			continue;
		pl->tier[t].first = (uint16_t *)(void *)(base + off);
		off += ((1u << k[t]) + 1) * sizeof(uint16_t);
	}
	if (!ident) {
		pos = (uint16_t *)(void *)(base + off);
		pl->pos = pos;
	}

	for (i = 0; !ident && i < nr; i++) {
		t = member_tier(&m[i]);
		if (t > 1) {
			pos[i] = UINT16_MAX;
			continue;
		}
		((uint16_t *)pl->tier[t].idx)[at[t]] = (uint16_t)i;
		pos[i] = (uint16_t)at[t]++;
	}
	for (t = 0; t < 2; t++) {
		uint16_t *first = (uint16_t *)pl->tier[t].first;
		uint32_t *cum = (uint32_t *)pl->tier[t].cum;

		tr = &pl->tier[t];
		if (eq[t])
			continue;
		/* At most 8192 servers of weight 1000 at most: no overflow. */
		for (p = 0, sum = 0; p < n[t]; p++) {
			sum += member_weight(&m[tier_member(tr, p)]);
			cum[p] = sum;
		}
		tr->total = sum;
		tr->shift = 32 - k[t];
		for (i = 0; i < (1u << k[t]); i++)
			first[i] = (uint16_t)owner_in(tr, i << tr->shift, 0,
						      n[t]);
		first[1u << k[t]] = (uint16_t)(n[t] - 1);
	}
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

/* The position in @t whose turn the cursor @rr is. */
static uint32_t tier_turn(const struct gwp_up_tier *t, uint32_t rr)
{
	if (!t->total)
		return rr % t->n;
	return tier_owner(t, bit_reverse(rr));
}

/* A position in @t drawn by the random number @r: uniformly, or by weight. */
static uint32_t tier_drawn(const struct gwp_up_tier *t, uint32_t r)
{
	/* Uniform over [0, n), no division. */
	if (!t->total)
		return (uint32_t)(((uint64_t)r * t->n) >> 32);
	return tier_owner(t, r);
}

/* Whether the @i-th server has as many pairs open as its pool allows. */
static bool pick_full(const struct gwp_up_pick *pk, uint32_t i)
{
	const struct gwp_up_member *m = &pk->m[i];

	return m->max_conns && gwp_up_state_open(m->st) >= m->max_conns;
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

/* The clock, read on the pick's first call. */
static uint32_t pick_now(struct pick *c)
{
	if (!c->have_now) {
		c->now = c->pk->now(c->pk->arg);
		c->have_now = true;
	}
	return c->now;
}

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
	left = gwp_up_health_ejected(h, pick_now(c), &back);
	if (back && pk->back)
		pk->back(pk->arg, i);
	return left;
}

/* Whether the @i-th server may be taken: in service, not full, not @skip. */
static bool pick_usable(struct pick *c, uint32_t i)
{
	const struct gwp_up_pick *pk = c->pk;

	return i != pk->skip && pk->m[i].st && !pick_full(pk, i) &&
	       !pick_ejected(c, i);
}

/*
 * How much of its weight the @i-th server has now (gwp_up_health_ramp()),
 * GWP_UP_RAMP_ONE out of its slow start; reads the clock only for a server
 * that may be in one.
 */
static uint32_t pick_ramp(struct pick *c, uint32_t i)
{
	struct gwp_up_health *h = c->pk->m[i].h;

	if (!gwp_up_health_may_ramp(h))
		return GWP_UP_RAMP_ONE;
	return gwp_up_health_ramp(h, pick_now(c));
}

/*
 * Whether the @i-th server, which may be taken, takes the turn it was
 * offered: always out of its slow start (and with no @random), else with
 * the chance its ramp has reached.
 */
static bool pick_turn_taken(struct pick *c, uint32_t i)
{
	const struct gwp_up_pick *pk = c->pk;
	uint32_t f = pick_ramp(c, i);

	if (f >= GWP_UP_RAMP_ONE || !pk->random)
		return true;
	return (pk->random(pk->arg) >> 16) < f;
}

/*
 * The first server of the tier @t that may be taken, from its position @p
 * on in pool order, wrapping, one in no slow start before one in a slow
 * start; or UINT32_MAX.
 */
static uint32_t pick_next(struct pick *c, const struct gwp_up_tier *t,
			  uint32_t p)
{
	const struct gwp_up_pick *pk = c->pk;
	uint32_t ramping = UINT32_MAX, i, k;

	for (k = 0; k < t->n; k++, p = p + 1 < t->n ? p + 1 : 0) {
		i = tier_member(t, p);
		if (i == pk->skip || !pk->m[i].st || pick_full(pk, i) ||
		    pick_ejected(c, i))
			continue;
		if (pick_ramp(c, i) >= GWP_UP_RAMP_ONE)
			return i;
		if (ramping == UINT32_MAX)
			ramping = i;
	}
	return ramping;
}

/*
 * Round-robin among the servers of the tier @t, the turn at its position
 * @p (see gwp_up_lb_pick()): the place in the pool of the one taken, or
 * UINT32_MAX when none may be. A server whose turn it is takes it when it
 * may be taken and is not in a slow start that lets it pass; else up to
 * GWP_UP_PICK_PROBES random ones are offered it in the same way, so its
 * turns are spread by weight; else the next one in service.
 */
static uint32_t pick_rr(struct pick *c, const struct gwp_up_tier *t,
			uint32_t p)
{
	const struct gwp_up_pick *pk = c->pk;
	uint32_t i = tier_member(t, p), q;

	if (pick_usable(c, i) && pick_turn_taken(c, i))
		return i;
	for (q = 0; pk->random && q < GWP_UP_PICK_PROBES; q++) {
		i = tier_member(t, tier_drawn(t, pk->random(pk->arg)));
		if (pick_usable(c, i) && pick_turn_taken(c, i))
			return i;
	}
	return pick_next(c, t, p);
}

/*
 * Least-connections among the servers of the tier @t, ties from its
 * position @p on (see gwp_up_lb_pick()): the place in the pool of the one
 * taken, or UINT32_MAX when none may be.
 */
static uint32_t pick_lc(struct pick *c, const struct gwp_up_tier *t,
			uint32_t p)
{
	const struct gwp_up_pick *pk = c->pk;
	uint32_t n = t->n, best = UINT32_MAX, best_val = UINT32_MAX;
	uint32_t best_w = 1, i, k, v, w, f;
	bool weighted = t->total != 0;
	const struct gwp_up_member *m;

	/*
	 * Where the ties start. When that server cannot be taken, a random
	 * one in service takes its place, if a probe finds one, so its turns
	 * are spread; else the ties start where they would have.
	 */
	if (!pick_usable(c, tier_member(t, p))) {
		uint32_t q, j;

		for (q = 0; pk->random && q < GWP_UP_PICK_PROBES; q++) {
			j = tier_drawn(t, pk->random(pk->arg));
			if (pick_usable(c, tier_member(t, j))) {
				p = j;
				break;
			}
		}
	}

	/*
	 * The weights compared are scaled by GWP_UP_RAMP_ONE, and by the
	 * ramp of a server in its slow start: at most 1000 * 2^16, which
	 * times a count of 2^32 at most fits in 64 bits.
	 */
	for (k = 0; k < n; k++, p = p + 1 < n ? p + 1 : 0) {
		i = tier_member(t, p);
		m = &pk->m[i];
		if (i == pk->skip || !m->st)
			continue;
		/*
		 * Not fewer than the best so far at its full weight: neither
		 * at less, and its health does not matter.
		 */
		v = gwp_up_state_open(m->st);
		w = (weighted ? member_weight(m) : 1) * GWP_UP_RAMP_ONE;
		if ((m->max_conns && v >= m->max_conns) ||
		    (best != UINT32_MAX && !fewer_open(v, w, best_val, best_w)) ||
		    pick_ejected(c, i))
			continue;
		f = pick_ramp(c, i);
		if (f < GWP_UP_RAMP_ONE) {
			w = (w / GWP_UP_RAMP_ONE) * f;
			if (best != UINT32_MAX &&
			    !fewer_open(v, w, best_val, best_w))
				continue;
		}
		best = i;
		best_val = v;
		best_w = w;
		if (!v)
			break;
	}
	return best;
}

/*
 * Whether the @a-th server has fewer open pairs for its weight, scaled by
 * its ramp, than the @b-th, both in the tier @t.
 */
static bool pick_fewer(struct pick *c, const struct gwp_up_tier *t,
		       uint32_t a, uint32_t b)
{
	const struct gwp_up_member *m = c->pk->m;
	uint64_t wa = t->total ? member_weight(&m[a]) : 1;
	uint64_t wb = t->total ? member_weight(&m[b]) : 1;

	/* At most 1000 * 2^16 each: fits, times a count, in 64 bits. */
	wa *= pick_ramp(c, a);
	wb *= pick_ramp(c, b);
	return fewer_open(gwp_up_state_open(m[a].st), (uint32_t)wa,
			  gwp_up_state_open(m[b].st), (uint32_t)wb);
}

/*
 * "random" (@two false) or "random two" among the servers of the tier @t
 * (see gwp_up_lb_pick()), falling back to the next in service from the
 * first one drawn, or from its position @p with no draw: the place in the
 * pool of the one taken, or UINT32_MAX when none may be.
 */
static uint32_t pick_random(struct pick *c, const struct gwp_up_tier *t,
			    uint32_t p, bool two)
{
	const struct gwp_up_pick *pk = c->pk;
	uint32_t want = two ? 2 : 1, got = 0, first = UINT32_MAX, q, j, i;
	uint32_t a = UINT32_MAX;

	for (q = 0; pk->random && q < want + GWP_UP_PICK_PROBES; q++) {
		j = tier_drawn(t, pk->random(pk->arg));
		i = tier_member(t, j);
		if (first == UINT32_MAX && pk->skip >= pk->nr)
			first = j;
		if (i == a || !pick_usable(c, i) || !pick_turn_taken(c, i))
			continue;
		if (++got == want)
			break;
		a = i;
	}
	/* Of two, the second only when it has fewer; ties to the first. */
	if (got == want)
		return two && !pick_fewer(c, t, i, a) ? a : i;
	if (got)
		return a;
	return pick_next(c, t, first != UINT32_MAX ? first : p);
}

/*
 * The pick among the servers of the tier @t, from its position @p on (see
 * gwp_up_lb_pick()): the place in the pool of the one taken, or
 * UINT32_MAX when none may be.
 */
static uint32_t pick_tier(struct pick *c, const struct gwp_up_tier *t,
			  uint32_t p)
{
	switch (c->pk->method) {
	case GWP_UP_METHOD_LEAST_CONN:
		return pick_lc(c, t, p);
	case GWP_UP_METHOD_RANDOM:
		return pick_random(c, t, p, false);
	case GWP_UP_METHOD_RANDOM_TWO:
		return pick_random(c, t, p, true);
	default:
		return pick_rr(c, t, p);
	}
}

/*
 * With none in service in any tier, the server of @t, from its position
 * @p on, whose ejection ends soonest among those that are not full; or
 * UINT32_MAX.
 */
static uint32_t pick_soonest(struct pick *c, const struct gwp_up_tier *t,
			     uint32_t p)
{
	const struct gwp_up_pick *pk = c->pk;
	uint32_t best = UINT32_MAX, best_val = UINT32_MAX, i, k, v;

	for (k = 0; k < t->n; k++, p = p + 1 < t->n ? p + 1 : 0) {
		i = tier_member(t, p);
		if (!pk->m[i].st || pick_full(pk, i))
			continue;
		v = pick_ejected(c, i);
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

uint32_t gwp_up_lb_pick(const struct gwp_up_pick *pk)
{
	struct pick c = { .pk = pk };
	const struct gwp_up_plan *pl = pk->plan;
	uint32_t nr = pk->nr, skip = pk->skip, nr_tier = 2, t, p, i;
	struct gwp_up_tier all = { .n = nr };
	const struct gwp_up_tier *tier;
	bool retry = skip < nr;

	if (!nr)
		return UINT32_MAX;
	/* No plan: every server in one tier, in pool order, plain turns. */
	if (pl) {
		tier = pl->tier;
	} else {
		tier = &all;
		nr_tier = 1;
	}

	/* The backups only when no main server may be taken. */
	for (t = 0; t < nr_tier; t++) {
		if (!tier[t].n)
			continue;
		if (!retry) {
			p = tier_turn(&tier[t], pk->rr);
		} else if ((pl && pl->pos ? member_tier(&pk->m[skip]) : 0) ==
			   t) {
			/* After the server that failed. */
			p = pl && pl->pos ? pl->pos[skip] : skip;
			p = p + 1 < tier[t].n ? p + 1 : 0;
		} else {
			p = 0;
		}
		i = pick_tier(&c, &tier[t], p);
		if (i != UINT32_MAX)
			return i;
	}
	if (retry)
		return UINT32_MAX;

	/* All out: the one back soonest, ties in turn, backups last. */
	for (t = 0; t < nr_tier; t++) {
		if (!tier[t].n)
			continue;
		i = pick_soonest(&c, &tier[t], pk->rr % tier[t].n);
		if (i != UINT32_MAX)
			return i;
	}
	return UINT32_MAX;
}
