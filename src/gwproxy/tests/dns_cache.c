// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <gwproxy/dns_cache.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

static void test_dns_cache_init_free(void)
{
	struct gwp_dns_cache *cache;
	int r;

	/* Test successful initialization */
	r = gwp_dns_cache_init(&cache, 128);
	assert(r == 0);
	assert(cache != NULL);

	/* Test freeing */
	gwp_dns_cache_free(cache);

	/* Test freeing NULL pointer (should not crash) */
	gwp_dns_cache_free(NULL);

	/* Test with different bucket sizes */
	r = gwp_dns_cache_init(&cache, 1);
	assert(r == 0);
	assert(cache != NULL);
	gwp_dns_cache_free(cache);

	r = gwp_dns_cache_init(&cache, 1024);
	assert(r == 0);
	assert(cache != NULL);
	gwp_dns_cache_free(cache);

	printf("test_dns_cache_init_free: passed\n");
}

static void test_dns_cache_basic_insert_lookup(void)
{
	struct gwp_dns_cache *cache;
	struct gwp_dns_cache_entry *entry;
	struct addrinfo *ai;
	struct addrinfo hints;
	time_t expire_time;
	uint8_t *i4_addrs;
	int r;

	r = gwp_dns_cache_init(&cache, 128);
	assert(r == 0);

	/* Create some test address info */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo("127.0.0.1", "80", &hints, &ai);
	assert(r == 0);
	assert(ai != NULL);

	/* Insert entry */
	expire_time = time(NULL) + 300; /* 5 minutes from now */
	r = gwp_dns_cache_insert(cache, "test.local", ai, expire_time);
	assert(r == 0);

	/* Lookup the entry */
	r = gwp_dns_cache_getent(cache, "test.local", &entry);
	assert(r == 0);
	assert(entry != NULL);

	/* Verify entry contents */
	assert(entry->name_len == strlen("test.local") + 1);
	assert(strcmp((char *)entry->block, "test.local") == 0);
	assert(entry->nr_i4 >= 1);

	/* Check IPv4 addresses */
	i4_addrs = gwp_dns_cache_entget_i4(entry);
	assert(i4_addrs != NULL);

	/* Put the entry back */
	gwp_dns_cache_putent(entry);

	/* Try to lookup non-existent entry */
	r = gwp_dns_cache_getent(cache, "nonexistent.local", &entry);
	assert(r == -ENOENT);

	freeaddrinfo(ai);
	gwp_dns_cache_free(cache);

	printf("test_dns_cache_basic_insert_lookup: passed\n");
}

static void test_dns_cache_ipv6_support(void)
{
	struct gwp_dns_cache *cache;
	struct gwp_dns_cache_entry *entry;
	struct addrinfo *ai;
	struct addrinfo hints;
	time_t expire_time;
	uint8_t *i6_addrs;
	int r;

	r = gwp_dns_cache_init(&cache, 128);
	assert(r == 0);

	/* Create IPv6 address info */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo("::1", "80", &hints, &ai);
	assert(r == 0);
	assert(ai != NULL);

	/* Insert IPv6 entry */
	expire_time = time(NULL) + 300;
	r = gwp_dns_cache_insert(cache, "ipv6test.local", ai, expire_time);
	assert(r == 0);

	/* Lookup the entry */
	r = gwp_dns_cache_getent(cache, "ipv6test.local", &entry);
	assert(r == 0);
	assert(entry != NULL);

	/* Verify IPv6 entry */
	assert(entry->nr_i6 >= 1);
	i6_addrs = gwp_dns_cache_entget_i6(entry);
	assert(i6_addrs != NULL);

	gwp_dns_cache_putent(entry);
	freeaddrinfo(ai);
	gwp_dns_cache_free(cache);

	printf("test_dns_cache_ipv6_support: passed\n");
}

static void test_dns_cache_mixed_ipv4_ipv6(void)
{
	struct gwp_dns_cache *cache;
	struct gwp_dns_cache_entry *entry;
	struct addrinfo *ai_v4, *ai_v6, *ai_mixed;
	struct addrinfo hints;
	time_t expire_time;
	uint8_t *i4_addrs;
	uint8_t *i6_addrs;
	int r;

	r = gwp_dns_cache_init(&cache, 128);
	assert(r == 0);

	/* Create mixed IPv4 + IPv6 address info */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo("127.0.0.1", "80", &hints, &ai_v4);
	assert(r == 0);

	hints.ai_family = AF_INET6;
	r = getaddrinfo("::1", "80", &hints, &ai_v6);
	assert(r == 0);

	/* Chain them together */
	ai_mixed = ai_v4;
	ai_v4->ai_next = ai_v6;

	/* Insert mixed entry */
	expire_time = time(NULL) + 300;
	r = gwp_dns_cache_insert(cache, "mixed.local", ai_mixed, expire_time);
	assert(r == 0);

	/* Lookup and verify */
	r = gwp_dns_cache_getent(cache, "mixed.local", &entry);
	assert(r == 0);
	assert(entry != NULL);

	/* Should have both IPv4 and IPv6 addresses */
	assert(entry->nr_i4 >= 1);
	assert(entry->nr_i6 >= 1);

	i4_addrs = gwp_dns_cache_entget_i4(entry);
	i6_addrs = gwp_dns_cache_entget_i6(entry);
	assert(i4_addrs != NULL);
	assert(i6_addrs != NULL);

	gwp_dns_cache_putent(entry);

	/* Clean up - unchain before freeing */
	ai_v4->ai_next = NULL;
	freeaddrinfo(ai_v4);
	freeaddrinfo(ai_v6);
	gwp_dns_cache_free(cache);

	printf("test_dns_cache_mixed_ipv4_ipv6: passed\n");
}

static void test_dns_cache_entry_replacement(void)
{
	struct gwp_dns_cache *cache;
	struct gwp_dns_cache_entry *entry1, *entry2;
	struct addrinfo *ai1, *ai2;
	struct addrinfo hints;
	time_t expire_time;
	int r;

	r = gwp_dns_cache_init(&cache, 128);
	assert(r == 0);

	/* Create first address info */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo("127.0.0.1", "80", &hints, &ai1);
	assert(r == 0);

	/* Create second address info */
	r = getaddrinfo("127.0.0.1", "443", &hints, &ai2);
	assert(r == 0);

	/* Insert first entry */
	expire_time = time(NULL) + 300;
	r = gwp_dns_cache_insert(cache, "replace.local", ai1, expire_time);
	assert(r == 0);

	/* Get reference to first entry */
	r = gwp_dns_cache_getent(cache, "replace.local", &entry1);
	assert(r == 0);
	assert(entry1 != NULL);

	/* Insert second entry with same key (should replace) */
	r = gwp_dns_cache_insert(cache, "replace.local", ai2, expire_time + 100);
	assert(r == 0);

	/* Get the new entry */
	r = gwp_dns_cache_getent(cache, "replace.local", &entry2);
	assert(r == 0);
	assert(entry2 != NULL);

	/* Entries should be different */
	assert(entry1 != entry2);

	/* Old entry should still be valid due to reference counting */
	gwp_dns_cache_putent(entry1);
	gwp_dns_cache_putent(entry2);

	freeaddrinfo(ai1);
	freeaddrinfo(ai2);
	gwp_dns_cache_free(cache);

	printf("test_dns_cache_entry_replacement: passed\n");
}

static void test_dns_cache_expiration(void)
{
	struct gwp_dns_cache *cache;
	struct gwp_dns_cache_entry *entry;
	struct addrinfo *ai;
	struct addrinfo hints;
	time_t expire_time;
	int r;

	r = gwp_dns_cache_init(&cache, 128);
	assert(r == 0);

	/* Create address info */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo("127.0.0.1", "80", &hints, &ai);
	assert(r == 0);

	/* Insert entry that expires immediately */
	expire_time = time(NULL) - 1; /* Already expired */
	r = gwp_dns_cache_insert(cache, "expired.local", ai, expire_time);
	assert(r == 0);

	/* Try to lookup expired entry */
	r = gwp_dns_cache_getent(cache, "expired.local", &entry);
	assert(r == -ETIMEDOUT);

	/* Insert entry that expires in future */
	expire_time = time(NULL) + 300;
	r = gwp_dns_cache_insert(cache, "future.local", ai, expire_time);
	assert(r == 0);

	/* Should be able to lookup */
	r = gwp_dns_cache_getent(cache, "future.local", &entry);
	assert(r == 0);
	assert(entry != NULL);
	gwp_dns_cache_putent(entry);

	freeaddrinfo(ai);
	gwp_dns_cache_free(cache);

	printf("test_dns_cache_expiration: passed\n");
}

static void test_dns_cache_housekeeping(void)
{
	struct gwp_dns_cache *cache;
	struct gwp_dns_cache_entry *entry;
	struct addrinfo *ai;
	struct addrinfo hints;
	time_t now;
	int r;

	r = gwp_dns_cache_init(&cache, 128);
	assert(r == 0);

	/* Create address info */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo("127.0.0.1", "80", &hints, &ai);
	assert(r == 0);

	/* Insert multiple entries, some expired */
	now = time(NULL);
	r = gwp_dns_cache_insert(cache, "expired1.local", ai, now - 10);
	assert(r == 0);
	r = gwp_dns_cache_insert(cache, "expired2.local", ai, now - 5);
	assert(r == 0);
	r = gwp_dns_cache_insert(cache, "valid1.local", ai, now + 300);
	assert(r == 0);
	r = gwp_dns_cache_insert(cache, "valid2.local", ai, now + 600);
	assert(r == 0);

	/* Run housekeeping */
	gwp_dns_cache_housekeep(cache);

	/* Expired entries should be gone */
	r = gwp_dns_cache_getent(cache, "expired1.local", &entry);
	assert(r == -ENOENT);
	r = gwp_dns_cache_getent(cache, "expired2.local", &entry);
	assert(r == -ENOENT);

	/* Valid entries should still be there */
	r = gwp_dns_cache_getent(cache, "valid1.local", &entry);
	assert(r == 0);
	gwp_dns_cache_putent(entry);
	r = gwp_dns_cache_getent(cache, "valid2.local", &entry);
	assert(r == 0);
	gwp_dns_cache_putent(entry);

	freeaddrinfo(ai);
	gwp_dns_cache_free(cache);

	printf("test_dns_cache_housekeeping: passed\n");
}

static void test_dns_cache_hash_collisions(void)
{
	struct gwp_dns_cache *cache;
	struct gwp_dns_cache_entry *entry;
	struct addrinfo *ai;
	struct addrinfo hints;
	time_t expire_time;
	int r, i;
	char key[64];

	/* Use small cache to force collisions */
	r = gwp_dns_cache_init(&cache, 4);
	assert(r == 0);

	/* Create address info */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo("127.0.0.1", "80", &hints, &ai);
	assert(r == 0);

	expire_time = time(NULL) + 300;

	/* Insert many entries to force hash collisions */
	for (i = 0; i < 20; i++) {
		snprintf(key, sizeof(key), "collision%d.local", i);
		r = gwp_dns_cache_insert(cache, key, ai, expire_time);
		assert(r == 0);
	}

	/* Verify all entries can be found */
	for (i = 0; i < 20; i++) {
		snprintf(key, sizeof(key), "collision%d.local", i);
		r = gwp_dns_cache_getent(cache, key, &entry);
		assert(r == 0);
		assert(entry != NULL);
		assert(strcmp((char *)entry->block, key) == 0);
		gwp_dns_cache_putent(entry);
	}

	freeaddrinfo(ai);
	gwp_dns_cache_free(cache);

	printf("test_dns_cache_hash_collisions: passed\n");
}

static void test_dns_cache_reference_counting(void)
{
	struct gwp_dns_cache *cache;
	struct gwp_dns_cache_entry *entry1, *entry2, *entry3;
	struct addrinfo *ai;
	struct addrinfo hints;
	time_t expire_time;
	int r;

	r = gwp_dns_cache_init(&cache, 128);
	assert(r == 0);

	/* Create address info */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo("127.0.0.1", "80", &hints, &ai);
	assert(r == 0);

	/* Insert entry */
	expire_time = time(NULL) + 300;
	r = gwp_dns_cache_insert(cache, "refcount.local", ai, expire_time);
	assert(r == 0);

	/* Get multiple references to the same entry */
	r = gwp_dns_cache_getent(cache, "refcount.local", &entry1);
	assert(r == 0);
	assert(entry1 != NULL);

	r = gwp_dns_cache_getent(cache, "refcount.local", &entry2);
	assert(r == 0);
	assert(entry2 != NULL);

	r = gwp_dns_cache_getent(cache, "refcount.local", &entry3);
	assert(r == 0);
	assert(entry3 != NULL);

	/* All should point to the same entry */
	assert(entry1 == entry2);
	assert(entry2 == entry3);

	/* Put references back */
	gwp_dns_cache_putent(entry1);
	gwp_dns_cache_putent(entry2);
	gwp_dns_cache_putent(entry3);

	/* Test putting NULL (should not crash) */
	gwp_dns_cache_putent(NULL);

	freeaddrinfo(ai);
	gwp_dns_cache_free(cache);

	printf("test_dns_cache_reference_counting: passed\n");
}

static void test_dns_cache_invalid_inputs(void)
{
	struct gwp_dns_cache *cache;
	struct gwp_dns_cache_entry *entry;
	struct addrinfo *ai, dummy_ai;
	struct addrinfo hints;
	time_t expire_time;
	int r;

	r = gwp_dns_cache_init(&cache, 128);
	assert(r == 0);

	/* Test invalid key lengths */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo("127.0.0.1", "80", &hints, &ai);
	assert(r == 0);

	expire_time = time(NULL) + 300;

	/* Empty key should fail */
	r = gwp_dns_cache_insert(cache, "", ai, expire_time);
	assert(r == -EINVAL);

	/* Very long key should fail (>255 chars) */
	char long_key[300];
	memset(long_key, 'a', sizeof(long_key) - 1);
	long_key[sizeof(long_key) - 1] = '\0';
	r = gwp_dns_cache_insert(cache, long_key, ai, expire_time);
	assert(r == -EINVAL);

	/* NULL addrinfo should fail */
	r = gwp_dns_cache_insert(cache, "valid.local", NULL, expire_time);
	assert(r == -EINVAL);

	/* Empty addrinfo (no addresses) should fail */
	memset(&dummy_ai, 0, sizeof(dummy_ai));
	dummy_ai.ai_family = AF_UNSPEC; /* Neither IPv4 nor IPv6 */
	r = gwp_dns_cache_insert(cache, "valid.local", &dummy_ai, expire_time);
	assert(r == -EINVAL);

	/* Test lookup with invalid keys */
	r = gwp_dns_cache_getent(cache, "", &entry);
	assert(r == -EINVAL);

	r = gwp_dns_cache_getent(cache, long_key, &entry);
	assert(r == -EINVAL);

	freeaddrinfo(ai);
	gwp_dns_cache_free(cache);

	printf("test_dns_cache_invalid_inputs: passed\n");
}

static void test_dns_cache_large_dataset(void)
{
	struct gwp_dns_cache *cache;
	struct gwp_dns_cache_entry *entry;
	struct addrinfo *ai;
	struct addrinfo hints;
	time_t expire_time;
	int r, i;
	char key[64];

	r = gwp_dns_cache_init(&cache, 1024);
	assert(r == 0);

	/* Create address info */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo("127.0.0.1", "80", &hints, &ai);
	assert(r == 0);

	expire_time = time(NULL) + 300;

	/* Insert many entries */
	for (i = 0; i < 1000; i++) {
		snprintf(key, sizeof(key), "large%04d.local", i);
		r = gwp_dns_cache_insert(cache, key, ai, expire_time);
		assert(r == 0);
	}

	/* Verify random entries can be found */
	for (i = 0; i < 100; i++) {
		int idx = rand() % 1000;
		snprintf(key, sizeof(key), "large%04d.local", idx);
		r = gwp_dns_cache_getent(cache, key, &entry);
		assert(r == 0);
		assert(entry != NULL);
		gwp_dns_cache_putent(entry);
	}

	freeaddrinfo(ai);
	gwp_dns_cache_free(cache);

	printf("test_dns_cache_large_dataset: passed\n");
}

int main(void)
{
	printf("Running DNS cache tests...\n");

	test_dns_cache_init_free();
	test_dns_cache_basic_insert_lookup();
	test_dns_cache_ipv6_support();
	test_dns_cache_mixed_ipv4_ipv6();
	test_dns_cache_entry_replacement();
	test_dns_cache_expiration();
	test_dns_cache_housekeeping();
	test_dns_cache_hash_collisions();
	test_dns_cache_reference_counting();
	test_dns_cache_invalid_inputs();
	test_dns_cache_large_dataset();

	printf("All DNS cache tests passed!\n");
	return 0;
}
