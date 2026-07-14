// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <time.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <assert.h>
#include <stdatomic.h>
#include <gwproxy/dns_cache.h>
#include <arpa/inet.h>

#ifndef container_of
#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))
#endif

struct dns_cache_entry {
	struct dns_cache_entry		*next;
	time_t				expired_at;
	_Atomic(int)			ref_cnt;
	struct gwp_dns_cache_entry	e;
};

struct dns_hash_map {
	struct dns_cache_entry	**table;
	size_t			nr_buckets;
	size_t			nr_entries;
};

struct gwp_dns_cache {
	pthread_rwlock_t	lock;
	struct dns_hash_map	map;
};

/**
 * DJB2 Hash function.
 */
static uint64_t hash_key(const unsigned char *key)
{
	uint64_t hash = 5381;
	int c;

	while ((c = *key++))
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

	return hash;
}

static int dns_map_init(struct dns_hash_map *map, size_t nr_buckets)
{
	map->table = calloc(nr_buckets, sizeof(*map->table));
	if (!map->table)
		return -ENOMEM;

	map->nr_buckets = nr_buckets;
	map->nr_entries = 0;
	return 0;
}

static void put_dns_entry(struct dns_cache_entry *e)
{
	int x = atomic_fetch_sub(&e->ref_cnt, 1);
	assert(x > 0);
	if (x == 1)
		free(e);
}

static void get_dns_entry(struct dns_cache_entry *e)
{
	int x = atomic_fetch_add(&e->ref_cnt, 1);
	assert(x >= 0);
	(void)x;
}

static void dns_map_free(struct dns_hash_map *map)
{
	size_t i;

	if (!map->table)
		return;

	for (i = 0; i < map->nr_buckets; i++) {
		struct dns_cache_entry *next, *e = map->table[i];

		while (e) {
			next = e->next;
			put_dns_entry(e);
			e = next;
		}
	}
	free(map->table);
	map->table = NULL;
	map->nr_buckets = 0;
}

static void count_addrinfo(const struct addrinfo *ai, size_t *nr_i4,
			   size_t *nr_i6)
{
	const struct addrinfo *cur;

	*nr_i4 = 0;
	*nr_i6 = 0;
	for (cur = ai; cur; cur = cur->ai_next) {
		if (cur->ai_family == AF_INET)
			(*nr_i4)++;
		else if (cur->ai_family == AF_INET6)
			(*nr_i6)++;
	}
}

static void extract_i4i6(struct dns_cache_entry *de, const struct addrinfo *ai)
{
	struct gwp_dns_cache_entry *e = &de->e;
	uint8_t *i4b = &e->block[e->name_len];
	uint8_t *i6b = &i4b[e->nr_i4 * 4];
	uint32_t nr_i4 = 0, nr_i6 = 0;
	const struct addrinfo *cur;

	for (cur = ai; cur; cur = cur->ai_next) {
		const struct sockaddr_in6 *i6;
		const struct sockaddr_in *i4;

		if (cur->ai_family == AF_INET)  {
			if (nr_i4 == e->nr_i4)
				continue;
			nr_i4++;
			i4 = (struct sockaddr_in *)cur->ai_addr;
			memcpy(i4b, &i4->sin_addr, 4);
			i4b += 4;
		} else if (cur->ai_family == AF_INET6) {
			if (nr_i6 == e->nr_i6)
				continue;
			nr_i6++;
			i6 = (struct sockaddr_in6 *)cur->ai_addr;
			memcpy(i6b, &i6->sin6_addr, 16);
			i6b += 16;
		}
	}
	assert(nr_i4 == e->nr_i4);
	assert(nr_i6 == e->nr_i6);
}

static int alloc_dns_entry(struct dns_cache_entry **ep, const char *key,
			   const struct addrinfo *ai, time_t expired_at)
{
	size_t name_len, nr_i4, nr_i6;
	struct dns_cache_entry *de;

	name_len = strlen(key) + 1;
	if (name_len <= 1 || name_len > 255)
		return -EINVAL;

	count_addrinfo(ai, &nr_i4, &nr_i6);
	if (nr_i4 == 0 && nr_i6 == 0)
		return -EINVAL;

	if (nr_i4 > 255)
		nr_i4 = 255;
	if (nr_i6 > 255)
		nr_i6 = 255;

	/*
	 * e->block is a variable length array that contains:
	 *   - The first name_len octets are the domain name.
	 *   - The next nr_i4 * 4 octets are IPv4 addresses.
	 *   - The next nr_i6 * 16 octets are IPv6 addresses.
	 */
	de = malloc(sizeof(*de) + name_len + (nr_i4 * 4) + (nr_i6 * 16));
	if (!de)
		return -ENOMEM;

	de->expired_at = expired_at;
	de->e.name_len = name_len;
	de->e.nr_i4 = nr_i4;
	de->e.nr_i6 = nr_i6;
	atomic_init(&de->ref_cnt, 1);
	memcpy(de->e.block, key, name_len);
	extract_i4i6(de, ai);
	*ep = de;
	return 0;
}

static int dns_map_insert(struct dns_hash_map *map, const char *key,
			  const struct addrinfo *ai, time_t expired_at)
{
	struct dns_cache_entry *de, *cur, *prev = NULL, *next;
	uint64_t hash, idx;
	int r;

	r = alloc_dns_entry(&de, key, ai, expired_at);
	if (r)
		return r;

	/*
	 * There are three cases:
	 *   1) No collision, insert the entry directly (best case).
	 *   2) Collision with the same key, replace the entry.
	 *   3) Collision with a different key, chain the entry.
	 */
	hash = hash_key((const unsigned char *)key);
	idx = hash % map->nr_buckets;
	cur = map->table[idx];
	if (!cur) {
		/*
		 * Case 1. Best case, no collision!
		 */
		map->table[idx] = de;
		de->next = NULL;
		map->nr_entries++;
		return 0;
	}

	/*
	 * Handle the collision cases. This is a slow path.
	 *
	 * We are killing two birds with one stone here:
	 *    1) Try finding an entry with the same key and replace it.
	 *    2) Remove expired entries during the traversal.
	 *
	 * [ No animals were harmed in writing this code. ]
	 *
	 * TODO(ammarafizi2): Review the traversal logic again.
	 */
	prev = NULL;
	cur = map->table[idx];

	while (cur) {
		/*
		 *	1) Expired `cur` when `prev` is NULL:
		 *		A -> B -> C -> D
		 *		prev = NULL; cur = A; next = cur->next = B;
		 *		cur is expired; free(cur);
		 *		cur = next = B;
		 *		prev is NULL; map->table[idx] = cur;
		 *		next = cur->next = C;
		 *		B -> C -> D
		 *		prev = NULL; cur = B; next = cur->next = C;
		 *
		 *	2) Expired `cur` when `prev` is not NULL:
		 *		A -> B -> C -> D
		 *		prev = A; cur = B; next = cur->next = C;
		 *		cur is expired; free(cur);
		 *		cur = next = C;
		 *		prev is A; prev->next = cur = C;
		 *		next = cur->next = D;
		 *		A -> C -> D
		 *		prev = A; cur = C; next = cur->next = D;
		 *
		 *	Conclusions:
		 *		- If @cur is expired and @prev is NULL, set
		 *		@map->table[idx] to @cur->next. Then free @cur.
		 *		- If @cur is expired and prev is not NULL, set
		 *		@prev->next to @cur->next. Then free @cur.
		 */
		while (cur && cur->expired_at <= time(NULL)) {
			/*
			 * Remove expired entries.
			 */
			map->nr_entries--;
			next = cur->next;
			put_dns_entry(cur);
			if (prev)
				prev->next = next;
			else
				map->table[idx] = next;

			cur = next;
		}

		if (!cur)
			break;

		if (cur->e.name_len == de->e.name_len &&
		    !memcmp(cur->e.block, de->e.block, de->e.name_len)) {
			/*
			 * Case 2. Collision with the same key
			 * Replace the entry.
			 */
			if (prev)
				prev->next = de;
			else
				map->table[idx] = de;

			de->next = cur->next;
			put_dns_entry(cur);
			return 0;
		}

		prev = cur;
		cur = cur->next;
	}

	/*
	 * Case 3. The worst case.
	 * Collision with a different key or an expired entry.
	 */
	map->nr_entries++;
	de->next = NULL;
	if (prev)
		prev->next = de;
	else
		map->table[idx] = de;

	return 0;
}

static int dns_map_lookup_and_get(struct dns_hash_map *map, const char *key,
				  struct dns_cache_entry **ep)
{
	struct dns_cache_entry *cur;
	uint64_t hash, idx;
	size_t nl;

	nl = strlen(key) + 1;
	if (nl <= 1 || nl > 255)
		return -EINVAL;

	hash = hash_key((const unsigned char *)key);
	idx = hash % map->nr_buckets;
	cur = map->table[idx];

	while (cur) {
		if (cur->e.name_len == nl && !memcmp(cur->e.block, key, nl)) {

			if (cur->expired_at <= time(NULL))
				return -ETIMEDOUT;

			get_dns_entry(cur);
			*ep = cur;
			return 0;
		}
		cur = cur->next;
	}

	return -ENOENT;
}

int gwp_dns_cache_init(struct gwp_dns_cache **cache_p, uint32_t nr_buckets)
{
	struct gwp_dns_cache *cache;
	int r;

	/* nr_buckets is used as a modulus; a zero would divide by zero. */
	if (!nr_buckets)
		return -EINVAL;

	cache = malloc(sizeof(*cache));
	if (!cache)
		return -ENOMEM;

	r = pthread_rwlock_init(&cache->lock, NULL);
	if (r) {
		r = -r;
		goto out_free_cache;
	}

	r = dns_map_init(&cache->map, nr_buckets);
	if (r)
		goto out_destroy_lock;

	*cache_p = cache;
	return 0;

out_destroy_lock:
	pthread_rwlock_destroy(&cache->lock);
out_free_cache:
	free(cache);
	return r;
}

void gwp_dns_cache_free(struct gwp_dns_cache *cache)
{
	if (!cache)
		return;

	dns_map_free(&cache->map);
	pthread_rwlock_destroy(&cache->lock);
	free(cache);
}

int gwp_dns_cache_insert(struct gwp_dns_cache *cache, const char *key,
			 const struct addrinfo *ai, time_t expired_at)
{
	int r;
	pthread_rwlock_wrlock(&cache->lock);
	r = dns_map_insert(&cache->map, key, ai, expired_at);
	pthread_rwlock_unlock(&cache->lock);
	return r;
}

int gwp_dns_cache_getent(struct gwp_dns_cache *cache, const char *key,
			 struct gwp_dns_cache_entry **ep)
{
	struct dns_cache_entry *de = NULL;
	int r;

	pthread_rwlock_rdlock(&cache->lock);
	r = dns_map_lookup_and_get(&cache->map, key, &de);
	pthread_rwlock_unlock(&cache->lock);
	if (de)
		*ep = &de->e;
	else if (r == -ETIMEDOUT)
		gwp_dns_cache_housekeep(cache);

	return r;
}

void gwp_dns_cache_putent(struct gwp_dns_cache_entry *e)
{
	if (e)
		put_dns_entry(container_of(e, struct dns_cache_entry, e));
}

static void dns_map_scan_and_remove_expired(struct dns_hash_map *map)
{
	struct dns_cache_entry *next, *cur;
	size_t i;

	for (i = 0; i < map->nr_buckets; i++) {
		cur = map->table[i];
		map->table[i] = NULL;
		while (cur) {
			next = cur->next;
			if (cur->expired_at <= time(NULL)) {
				map->nr_entries--;
				put_dns_entry(cur);
			} else {
				cur->next = map->table[i];
				map->table[i] = cur;
			}
			cur = next;
		}
	}
}

void gwp_dns_cache_housekeep(struct gwp_dns_cache *cache)
{
	pthread_rwlock_wrlock(&cache->lock);
	dns_map_scan_and_remove_expired(&cache->map);
	pthread_rwlock_unlock(&cache->lock);
}
