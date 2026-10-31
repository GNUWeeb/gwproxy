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
#include <unistd.h>
#include <gwproxy/dns_cache.h>
#include <gwproxy/dns_hash.h>
#include <arpa/inet.h>

struct gwp_dns_cache_entry {
	/**
	 * Super compact domain name and IP address list.
	 *
	 * - name_len: length of the domain name (including null terminator).
	 * - nr_i4: number of IPv4 addresses.
	 * - nr_i6: number of IPv6 addresses.
	 * - block: flexible array member that contains:
	 *     - The first name_len octets are the domain name.
	 *     - The next nr_i4 * 4 octets are IPv4 addresses.
	 *     - The next nr_i6 * 16 octets are IPv6 addresses.
	 */
	uint8_t		name_len;
	uint8_t		nr_i4;
	uint8_t		nr_i6;
	uint8_t		block[];
};

/*
 * Entries are only ever reached under the cache lock: a hit copies the
 * addresses out before unlocking, so an entry has no other owner than the
 * table and is freed as soon as it is unlinked.
 */
struct dns_cache_entry {
	struct dns_cache_entry		*next;
	time_t				expired_at;
	struct gwp_dns_cache_entry	e;
};

struct dns_hash_map {
	struct dns_cache_entry	**table;
	size_t			nr_buckets;
	size_t			nr_entries;
	size_t			max_entries;	/* 0 = unlimited */
	uint64_t		key[2];		/* per-cache random SipHash key */
};

struct gwp_dns_cache {
	pthread_rwlock_t	lock;
	struct dns_hash_map	map;
};

/*
 * Buckets swept per write-lock hold in gwp_dns_cache_housekeep(). Lookups
 * from the event loops get the lock between two chunks, so a sweep of a large
 * table never stalls them for the whole pass.
 */
#define GWP_DNS_HOUSEKEEP_CHUNK	1024

static uint64_t hash_key(const uint64_t key[2], const char *name, size_t len)
{
	return gwp_siphash13(key, name, len);
}

static int dns_map_init(struct dns_hash_map *map, size_t nr_buckets,
			size_t max_entries)
{
	map->table = calloc(nr_buckets, sizeof(*map->table));
	if (!map->table)
		return -ENOMEM;

	map->nr_buckets = nr_buckets;
	map->nr_entries = 0;
	map->max_entries = max_entries;
	gwp_dns_gen_hash_key(map->key);
	return 0;
}

static void put_dns_entry(struct dns_cache_entry *e)
{
	free(e);
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

	/* No address at all records that the name does not resolve. */
	count_addrinfo(ai, &nr_i4, &nr_i6);

	/*
	 * A lookup never hands back more than GWP_DNS_CACHE_MAX_ADDRS per
	 * family, so storing more only costs memory and insert time.
	 */
	if (nr_i4 > GWP_DNS_CACHE_MAX_ADDRS)
		nr_i4 = GWP_DNS_CACHE_MAX_ADDRS;
	if (nr_i6 > GWP_DNS_CACHE_MAX_ADDRS)
		nr_i6 = GWP_DNS_CACHE_MAX_ADDRS;

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
	memcpy(de->e.block, key, name_len);
	extract_i4i6(de, ai);
	*ep = de;
	return 0;
}

static int dns_map_insert(struct dns_hash_map *map, const char *key,
			  const struct addrinfo *ai, time_t expired_at)
{
	struct dns_cache_entry *de, *cur, *prev = NULL, *next;
	time_t now = time(NULL);
	uint64_t hash, idx;
	char lkey[256];
	int r;

	if (!gwp_dns_fold_name(key, lkey, sizeof(lkey)))
		return -EINVAL;

	r = alloc_dns_entry(&de, lkey, ai, expired_at);
	if (r)
		return r;

	/*
	 * There are three cases:
	 *   1) No collision, insert the entry directly (best case).
	 *   2) Collision with the same key, replace the entry.
	 *   3) Collision with a different key, chain the entry.
	 */
	hash = hash_key(map->key, lkey, de->e.name_len - 1);
	idx = hash % map->nr_buckets;
	cur = map->table[idx];
	if (!cur) {
		/*
		 * Case 1. Best case, no collision!
		 */
		if (map->max_entries && map->nr_entries >= map->max_entries) {
			free(de);	/* fresh, not linked anywhere yet */
			return -ENOSPC;
		}
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
		while (cur && cur->expired_at <= now) {
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
	 *
	 * The collision walk above already reclaimed any expired entries in this
	 * bucket, so the count reflects live + not-yet-swept entries. Bound the
	 * cache: once at capacity, refuse new keys (resolution still works, it is
	 * just not cached) rather than growing without limit.
	 */
	if (map->max_entries && map->nr_entries >= map->max_entries) {
		free(de);	/* fresh, not linked anywhere yet */
		return -ENOSPC;
	}
	map->nr_entries++;
	de->next = NULL;
	if (prev)
		prev->next = de;
	else
		map->table[idx] = de;

	return 0;
}

static void copy_addrs(const struct gwp_dns_cache_entry *e,
		       struct gwp_dns_cache_addrs *out)
{
	const uint8_t *i4b = &e->block[e->name_len];
	const uint8_t *i6b = &i4b[e->nr_i4 * 4];

	out->nr_i4 = e->nr_i4;
	out->nr_i6 = e->nr_i6;
	memcpy(out->i4, i4b, (size_t)out->nr_i4 * 4);
	memcpy(out->i6, i6b, (size_t)out->nr_i6 * 16);
}

static int dns_map_lookup(struct dns_hash_map *map, const char *key,
			  struct gwp_dns_cache_addrs *out)
{
	struct dns_cache_entry *cur;
	time_t now = time(NULL);
	uint64_t hash, idx;
	char lkey[256];
	size_t nl;

	nl = gwp_dns_fold_name(key, lkey, sizeof(lkey));
	if (nl <= 1 || nl > 255)
		return -EINVAL;

	hash = hash_key(map->key, lkey, nl - 1);
	idx = hash % map->nr_buckets;
	cur = map->table[idx];

	while (cur) {
		if (cur->e.name_len == nl && !memcmp(cur->e.block, lkey, nl)) {

			if (cur->expired_at <= now)
				return -ETIMEDOUT;

			copy_addrs(&cur->e, out);
			return 0;
		}
		cur = cur->next;
	}

	return -ENOENT;
}

int gwp_dns_cache_init(struct gwp_dns_cache **cache_p, uint32_t nr_buckets,
		       uint32_t max_entries)
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

	r = dns_map_init(&cache->map, nr_buckets, max_entries);
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

int gwp_dns_cache_lookup_addrs(struct gwp_dns_cache *cache, const char *key,
			       struct gwp_dns_cache_addrs *out)
{
	int r;

	pthread_rwlock_rdlock(&cache->lock);
	r = dns_map_lookup(&cache->map, key, out);
	pthread_rwlock_unlock(&cache->lock);
	return r;
}

/*
 * Unlink and free the expired entries of buckets [@start, @start + @nr), and
 * return the bucket after the last one swept. Chains with nothing expired are
 * only read.
 */
static size_t dns_map_remove_expired(struct dns_hash_map *map, size_t start,
				     size_t nr, time_t now)
{
	size_t i, end = start + nr;

	if (end > map->nr_buckets)
		end = map->nr_buckets;

	for (i = start; i < end; i++) {
		struct dns_cache_entry **pp = &map->table[i], *cur;

		while ((cur = *pp)) {
			if (cur->expired_at > now) {
				pp = &cur->next;
				continue;
			}
			*pp = cur->next;
			map->nr_entries--;
			put_dns_entry(cur);
		}
	}

	return end;
}

void gwp_dns_cache_housekeep(struct gwp_dns_cache *cache)
{
	size_t i = 0, nr_buckets = cache->map.nr_buckets;
	time_t now = time(NULL);

	while (i < nr_buckets) {
		pthread_rwlock_wrlock(&cache->lock);
		i = dns_map_remove_expired(&cache->map, i,
					   GWP_DNS_HOUSEKEEP_CHUNK, now);
		pthread_rwlock_unlock(&cache->lock);
	}
}
