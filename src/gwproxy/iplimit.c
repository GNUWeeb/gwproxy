// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * Per-client-address connection counter for --max-conns-per-ip; see
 * iplimit.h.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <gwproxy/iplimit.h>
#include <gwproxy/dns_hash.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/*
 * Shards, each with its own lock and bucket array. A power of two: the shard
 * is taken from the top bits of the hash, the bucket from the bottom ones.
 */
#define IPLIM_NR_SHARDS		32
#define IPLIM_MIN_BUCKETS	8

struct iplim_ent {
	struct iplim_ent	*next;
	struct gwp_iplim_key	key;
	uint32_t		count;
	/* When a refusal for this key was last logged, and how many since. */
	uint32_t		last_log;
	uint32_t		nr_quiet;
};

struct iplim_shard {
	pthread_mutex_t		lock;
	struct iplim_ent	**tab;
	uint32_t		nr_buckets;
	uint32_t		nr;
} __attribute__((__aligned__(64)));

struct gwp_iplim {
	struct iplim_shard	shards[IPLIM_NR_SHARDS];
	/*
	 * The table is keyed by addresses a client picks (any address of its
	 * /64 for IPv6), so the hash is keyed with a secret, as the DNS cache
	 * is, to keep a client from aiming at one bucket chain.
	 */
	uint64_t		hkey[2];
	uint32_t		max;
};

void gwp_iplim_key(const struct gwp_sockaddr *addr, struct gwp_iplim_key *key)
{
	const struct in6_addr *a6;

	memset(key, 0, sizeof(*key));
	switch (addr->sa.sa_family) {
	case AF_INET:
		key->b[10] = key->b[11] = 0xff;
		memcpy(&key->b[12], &addr->i4.sin_addr, 4);
		break;
	case AF_INET6:
		a6 = &addr->i6.sin6_addr;
		if (IN6_IS_ADDR_V4MAPPED(a6))
			memcpy(key->b, a6->s6_addr, 16);
		else
			memcpy(key->b, a6->s6_addr, 8);
		break;
	}
}

static uint64_t iplim_hash(const struct gwp_iplim *l,
			   const struct gwp_iplim_key *key)
{
	return gwp_siphash13(l->hkey, key->b, sizeof(key->b));
}

static struct iplim_shard *iplim_shard(struct gwp_iplim *l, uint64_t h)
{
	return &l->shards[h >> 59];	/* the top log2(IPLIM_NR_SHARDS) bits */
}

static struct iplim_ent **iplim_slot(struct iplim_shard *s,
				     const struct gwp_iplim_key *key,
				     uint64_t h)
{
	struct iplim_ent **pp = &s->tab[h & (s->nr_buckets - 1)];

	while (*pp && memcmp(&(*pp)->key, key, sizeof(*key)))
		pp = &(*pp)->next;
	return pp;
}

/*
 * Move every entry of @s to a bucket array of @nr_buckets. On allocation
 * failure the shard keeps its old array: chains get longer, nothing breaks.
 */
static void iplim_rehash(const struct gwp_iplim *l, struct iplim_shard *s,
			 uint32_t nr_buckets)
{
	struct iplim_ent **tab, *e, *next;
	uint32_t i;

	tab = calloc(nr_buckets, sizeof(*tab));
	if (!tab)
		return;

	for (i = 0; i < s->nr_buckets; i++) {
		for (e = s->tab[i]; e; e = next) {
			uint64_t h = iplim_hash(l, &e->key);

			next = e->next;
			e->next = tab[h & (nr_buckets - 1)];
			tab[h & (nr_buckets - 1)] = e;
		}
	}

	free(s->tab);
	s->tab = tab;
	s->nr_buckets = nr_buckets;
}

struct gwp_iplim *gwp_iplim_create(uint32_t max)
{
	struct gwp_iplim *l;
	uint32_t i;

	if (!max)
		return NULL;

	l = aligned_alloc(64, sizeof(*l));
	if (!l)
		return NULL;

	memset(l, 0, sizeof(*l));
	l->max = max;
	gwp_dns_gen_hash_key(l->hkey);
	for (i = 0; i < IPLIM_NR_SHARDS; i++) {
		struct iplim_shard *s = &l->shards[i];

		s->tab = calloc(IPLIM_MIN_BUCKETS, sizeof(*s->tab));
		if (!s->tab || pthread_mutex_init(&s->lock, NULL)) {
			free(s->tab);
			while (i--) {
				pthread_mutex_destroy(&l->shards[i].lock);
				free(l->shards[i].tab);
			}
			free(l);
			return NULL;
		}
		s->nr_buckets = IPLIM_MIN_BUCKETS;
	}

	return l;
}

void gwp_iplim_destroy(struct gwp_iplim *l)
{
	struct iplim_ent *e, *next;
	uint32_t i, j;

	if (!l)
		return;

	for (i = 0; i < IPLIM_NR_SHARDS; i++) {
		struct iplim_shard *s = &l->shards[i];

		for (j = 0; j < s->nr_buckets; j++) {
			for (e = s->tab[j]; e; e = next) {
				next = e->next;
				free(e);
			}
		}
		free(s->tab);
		pthread_mutex_destroy(&s->lock);
	}
	free(l);
}

int gwp_iplim_get(struct gwp_iplim *l, const struct gwp_iplim_key *key,
		  uint32_t now, uint32_t *nr_quiet)
{
	uint64_t h = iplim_hash(l, key);
	struct iplim_shard *s = iplim_shard(l, h);
	struct iplim_ent **pp, *e;
	int ret = GWP_IPLIM_ADMIT;

	pthread_mutex_lock(&s->lock);
	pp = iplim_slot(s, key, h);
	e = *pp;
	if (!e) {
		e = malloc(sizeof(*e));
		if (!e) {
			ret = -ENOMEM;
			goto out;
		}
		e->next = NULL;
		e->key = *key;
		e->count = 1;
		e->last_log = now - 1;
		e->nr_quiet = 0;
		*pp = e;
		if (++s->nr > s->nr_buckets)
			iplim_rehash(l, s, s->nr_buckets * 2);
	} else if (e->count < l->max) {
		e->count++;
	} else if ((int32_t)(now - e->last_log) <= 0) {
		/*
		 * Logged this second already. Not just "now == last_log": the
		 * workers' coarse clocks are their own, so @now may come from
		 * one that is still a second behind the worker that logged.
		 */
		e->nr_quiet++;
		ret = GWP_IPLIM_REFUSE;
	} else {
		if (nr_quiet)
			*nr_quiet = e->nr_quiet;
		e->nr_quiet = 0;
		e->last_log = now;
		ret = GWP_IPLIM_REFUSE_LOG;
	}
out:
	pthread_mutex_unlock(&s->lock);
	return ret;
}

void gwp_iplim_put(struct gwp_iplim *l, const struct gwp_iplim_key *key)
{
	uint64_t h = iplim_hash(l, key);
	struct iplim_shard *s = iplim_shard(l, h);
	struct iplim_ent **pp, *e;

	pthread_mutex_lock(&s->lock);
	pp = iplim_slot(s, key, h);
	e = *pp;
	/* Only a bug can put a key that was never got; do not go negative. */
	if (e && !--e->count) {
		*pp = e->next;
		free(e);
		s->nr--;
		/* Shrink with hysteresis: growing doubles at nr > nr_buckets. */
		if (s->nr_buckets > IPLIM_MIN_BUCKETS && s->nr < s->nr_buckets / 8)
			iplim_rehash(l, s, s->nr_buckets / 2);
	}
	pthread_mutex_unlock(&s->lock);
}

uint32_t gwp_iplim_count(struct gwp_iplim *l, const struct gwp_iplim_key *key)
{
	uint64_t h = iplim_hash(l, key);
	struct iplim_shard *s = iplim_shard(l, h);
	struct iplim_ent *e;
	uint32_t n;

	pthread_mutex_lock(&s->lock);
	e = *iplim_slot(s, key, h);
	n = e ? e->count : 0;
	pthread_mutex_unlock(&s->lock);
	return n;
}

uint64_t gwp_iplim_nr_entries(struct gwp_iplim *l)
{
	uint64_t n = 0;
	uint32_t i;

	for (i = 0; i < IPLIM_NR_SHARDS; i++) {
		struct iplim_shard *s = &l->shards[i];

		pthread_mutex_lock(&s->lock);
		n += s->nr;
		pthread_mutex_unlock(&s->lock);
	}
	return n;
}
