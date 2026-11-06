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
 * A list behind one lock. Only making and freeing server objects takes it
 * (an ACL load, and the last reference to a server going), never a pick:
 * a connection reaches its entry through its server object. A few hundred
 * identities at most (pools of up to 64 servers each), so no hashing.
 */
struct gwp_up_table {
	pthread_mutex_t		lock;
	struct gwp_up_state	*head;
	uint32_t		nr;
};

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
	if (pthread_mutex_init(&t->lock, NULL)) {
		free(t);
		return NULL;
	}
	return t;
}

uint32_t gwp_up_table_destroy(struct gwp_up_table *t)
{
	struct gwp_up_state *s, *next;
	uint32_t left;

	if (!t)
		return 0;
	left = t->nr;
	for (s = t->head; s; s = next) {
		next = s->next;
		/* The key holds a user name; leave none in freed memory. */
		explicit_bzero(s, sizeof(*s));
		free(s);
	}
	pthread_mutex_destroy(&t->lock);
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
	struct gwp_up_state *s;

	pthread_mutex_lock(&t->lock);
	for (s = t->head; s; s = s->next) {
		if (!memcmp(&s->key, key, sizeof(*key))) {
			s->ref++;
			goto out;
		}
	}
	s = calloc(1, sizeof(*s));
	if (s) {
		uint32_t i;

		atomic_init(&s->nr_open, 0);
		atomic_init(&s->fail_seq, 0);
		for (i = 0; i < GWP_UP_EJECT_FAILS; i++)
			atomic_init(&s->fail_at[i], 0);
		atomic_init(&s->eject_end, 0);
		s->ref = 1;
		s->tab = t;
		s->key = *key;
		s->next = t->head;
		t->head = s;
		t->nr++;
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
	for (pp = &t->head; *pp != s; pp = &(*pp)->next)
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

/* Whether a pick may take server @i. */
static bool pick_ok(const uint32_t *eject, uint32_t i, uint32_t skip)
{
	return i != skip && (!eject || !eject[i]);
}

uint32_t gwp_up_lb_pick(bool least_conn, uint32_t rr, const uint32_t *open,
			const uint32_t *eject, uint32_t nr, uint32_t skip)
{
	uint32_t n = 0, start, best, i, j, k;

	for (i = 0; i < nr; i++)
		n += pick_ok(eject, i, skip);

	if (!n) {
		if (skip != UINT32_MAX || !eject)
			return UINT32_MAX;
		/* All ejected: the one back soonest, ties in turn. */
		start = rr % nr;
		best = start;
		for (i = 1; i < nr; i++) {
			j = start + i;
			if (j >= nr)
				j -= nr;
			if (eject[j] < eject[best])
				best = j;
		}
		return best;
	}

	/* The (rr % n)-th server that may be taken. */
	k = rr % n;
	for (start = 0;; start++) {
		if (pick_ok(eject, start, skip) && !k--)
			break;
	}
	if (!least_conn)
		return start;

	best = start;
	for (i = 1; i < nr; i++) {
		j = start + i;
		if (j >= nr)
			j -= nr;
		if (pick_ok(eject, j, skip) && open[j] < open[best])
			best = j;
	}
	return best;
}
