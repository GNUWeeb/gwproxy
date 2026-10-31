// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWPROXY_DNS_CACHE_H
#define GWPROXY_DNS_CACHE_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

#include <netinet/in.h>

/*
 * The most addresses a lookup copies out per family. The connect path never
 * tries more than GWP_DNS_MAX_ADDRS in total.
 */
#define GWP_DNS_CACHE_MAX_ADDRS	8u

/*
 * What a cache hit hands back: a copy, taken under the read lock, so nothing
 * refers to the entry once the lock is dropped.
 */
struct gwp_dns_cache_addrs {
	uint8_t		nr_i4;
	uint8_t		nr_i6;
	struct in_addr	i4[GWP_DNS_CACHE_MAX_ADDRS];
	struct in6_addr	i6[GWP_DNS_CACHE_MAX_ADDRS];
};

struct gwp_dns_cache;

/**
 * Initialize a DNS cache and fills the provided pointer with a new cache
 * instance. When the cache is no longer needed, it should be freed using
 * `gwp_dns_cache_free()`.
 *
 * @param cache_p	Pointer to the cache pointer that will be initialized.
 * @param nr_buckets	Number of buckets for the hash map.
 * @param max_entries	Maximum number of entries to hold; once reached, inserts
 *			of new keys are refused (returning -ENOSPC) to bound
 *			memory. 0 means unlimited.
 * @return int		0 on success, negative error code on failure.
 */
int gwp_dns_cache_init(struct gwp_dns_cache **cache_p, uint32_t nr_buckets,
		       uint32_t max_entries);

/**
 * Free the DNS cache and all its resources.
 *
 * @param cache	The DNS cache to free.
 */
void gwp_dns_cache_free(struct gwp_dns_cache *cache);

/**
 * Scan and remove expired entries from the DNS cache. Expected to
 * be called periodically to reclaim memory from expired entries. The
 * write lock is taken for a bounded number of buckets at a time, so
 * lookups proceed between two steps; a lookup never sweeps by itself.
 *
 * @param cache	The DNS cache to perform housekeeping on.
 */
void gwp_dns_cache_housekeep(struct gwp_dns_cache *cache);

/**
 * Look up @key and copy up to GWP_DNS_CACHE_MAX_ADDRS addresses of each
 * family into @out.
 *
 * @param cache	The DNS cache to look up the entry in.
 * @param key 	The key to look up, typically a domain name.
 * @param out	Filled with the entry's addresses on a hit.
 * @return int	0 on success, negative error code on failure.
 *
 * Error codes:
 * -ENOENT:    Entry not found.
 * -ETIMEDOUT: Entry found but expired (treated as a miss).
 * -EINVAL:    Invalid key (empty or too long).
 */
int gwp_dns_cache_lookup_addrs(struct gwp_dns_cache *cache, const char *key,
			       struct gwp_dns_cache_addrs *out);

/**
 * Insert a new DNS entry into the cache. If an entry with the same key
 * already exists, it will be replaced.
 *
 * @param cache		The DNS cache to insert the entry into.
 * @param key		The key for the entry, typically a domain name.
 * @param ai		The address information to insert. NULL, or a list
 *			without IPv4 or IPv6 addresses, records that @key
 *			does not resolve: a lookup then succeeds with no
 *			addresses.
 * @param expired_at	The time when the entry expires.
 * @return int		0 on success, negative error code on failure.
 */
struct addrinfo;
int gwp_dns_cache_insert(struct gwp_dns_cache *cache, const char *key,
			 const struct addrinfo *ai, time_t expired_at);

#endif /* #ifndef GWPROXY_DNS_CACHE_H */
