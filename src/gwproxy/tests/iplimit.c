// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * Unit tests for the per-client-address connection counter (iplimit.c).
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <gwproxy/iplimit.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static struct gwp_iplim_key key_of(const char *ip)
{
	struct gwp_iplim_key k;
	struct gwp_sockaddr s;

	memset(&s, 0, sizeof(s));
	if (strchr(ip, ':')) {
		s.i6.sin6_family = AF_INET6;
		s.i6.sin6_port = htons(1234);
		assert(inet_pton(AF_INET6, ip, &s.i6.sin6_addr) == 1);
	} else {
		s.i4.sin_family = AF_INET;
		s.i4.sin_port = htons(1234);
		assert(inet_pton(AF_INET, ip, &s.i4.sin_addr) == 1);
	}
	gwp_iplim_key(&s, &k);
	return k;
}

static bool same_key(const char *a, const char *b)
{
	struct gwp_iplim_key ka = key_of(a), kb = key_of(b);

	return !memcmp(&ka, &kb, sizeof(ka));
}

static void test_key(void)
{
	struct gwp_iplim_key k;
	struct gwp_sockaddr s;

	/* IPv4 by the full address, the same as its IPv4-mapped form. */
	assert(same_key("192.0.2.1", "192.0.2.1"));
	assert(same_key("192.0.2.1", "::ffff:192.0.2.1"));
	assert(!same_key("192.0.2.1", "192.0.2.2"));
	assert(!same_key("::ffff:192.0.2.1", "::ffff:192.0.2.2"));
	assert(!same_key("192.0.2.1", "193.0.2.1"));

	/* Native IPv6 by its /64: the interface identifier is ignored. */
	assert(same_key("2001:db8:1:2::1", "2001:db8:1:2::2"));
	assert(same_key("2001:db8:1:2::1",
			"2001:db8:1:2:ffff:ffff:ffff:ffff"));
	assert(!same_key("2001:db8:1:2::1", "2001:db8:1:3::1"));
	assert(!same_key("2001:db8:1:2::1", "2001:db9:1:2::1"));
	assert(same_key("::1", "::2"));
	assert(same_key("fe80::1", "fe80::abcd:1"));

	/* The families never share a key. */
	assert(!same_key("0.0.0.0", "::"));
	assert(!same_key("0.0.0.1", "::1"));
	assert(!same_key("192.0.2.1", "::c000:201"));
	assert(!same_key("192.0.2.1", "64:ff9b::192.0.2.1"));

	/* The exact layout iplimit.h documents. */
	k = key_of("192.0.2.1");
	assert(!memcmp(k.b, "\0\0\0\0\0\0\0\0\0\0\xff\xff\xc0\x00\x02\x01", 16));
	k = key_of("2001:db8:1:2:3:4:5:6");
	assert(!memcmp(k.b, "\x20\x01\x0d\xb8\x00\x01\x00\x02\0\0\0\0\0\0\0\0", 16));

	/* Neither IPv4 nor IPv6: one all-zero key, nothing read past sa. */
	memset(&s, 0xa5, sizeof(s));
	s.sa.sa_family = AF_UNIX;
	gwp_iplim_key(&s, &k);
	assert(!memcmp(k.b, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16));
}

static void test_cap(void)
{
	struct gwp_iplim_key a = key_of("192.0.2.1");
	struct gwp_iplim_key b = key_of("2001:db8::1");
	struct gwp_iplim_key b2 = key_of("2001:db8::2");
	struct gwp_iplim *l;
	uint32_t quiet;
	int i;

	assert(!gwp_iplim_create(0));
	l = gwp_iplim_create(3);
	assert(l);

	for (i = 0; i < 3; i++)
		assert(gwp_iplim_get(l, &a, 100, NULL) == GWP_IPLIM_ADMIT);
	assert(gwp_iplim_count(l, &a) == 3);

	/* Over the cap: the first refusal of a second is logged, then quiet. */
	quiet = 77;
	assert(gwp_iplim_get(l, &a, 100, &quiet) == GWP_IPLIM_REFUSE_LOG);
	assert(quiet == 0);
	assert(gwp_iplim_get(l, &a, 100, &quiet) == GWP_IPLIM_REFUSE);
	assert(gwp_iplim_get(l, &a, 100, &quiet) == GWP_IPLIM_REFUSE);
	assert(gwp_iplim_count(l, &a) == 3);
	assert(gwp_iplim_get(l, &a, 101, &quiet) == GWP_IPLIM_REFUSE_LOG);
	assert(quiet == 2);
	assert(gwp_iplim_get(l, &a, 101, NULL) == GWP_IPLIM_REFUSE);
	/*
	 * Each worker has its own coarse clock, so one may still be a second
	 * behind the worker that logged: that is not a new second either.
	 */
	assert(gwp_iplim_get(l, &a, 100, NULL) == GWP_IPLIM_REFUSE);
	assert(gwp_iplim_get(l, &a, 101, NULL) == GWP_IPLIM_REFUSE);

	/* Another key, and another address of the same /64, share nothing
	 * with @a, but the /64 is one group. */
	assert(gwp_iplim_get(l, &b, 101, NULL) == GWP_IPLIM_ADMIT);
	assert(gwp_iplim_get(l, &b2, 101, NULL) == GWP_IPLIM_ADMIT);
	assert(gwp_iplim_get(l, &b2, 101, NULL) == GWP_IPLIM_ADMIT);
	assert(gwp_iplim_count(l, &b) == 3);
	assert(gwp_iplim_get(l, &b, 101, NULL) == GWP_IPLIM_REFUSE_LOG);
	assert(gwp_iplim_nr_entries(l) == 2);

	/* Closing one makes room for exactly one more. */
	gwp_iplim_put(l, &a);
	assert(gwp_iplim_count(l, &a) == 2);
	assert(gwp_iplim_get(l, &a, 101, NULL) == GWP_IPLIM_ADMIT);
	assert(gwp_iplim_get(l, &a, 102, NULL) == GWP_IPLIM_REFUSE_LOG);

	/* At zero the entry goes, and a put without a get changes nothing. */
	for (i = 0; i < 3; i++) {
		gwp_iplim_put(l, &a);
		gwp_iplim_put(l, &b);
	}
	assert(gwp_iplim_count(l, &a) == 0);
	assert(gwp_iplim_count(l, &b) == 0);
	assert(gwp_iplim_nr_entries(l) == 0);
	gwp_iplim_put(l, &a);
	assert(gwp_iplim_count(l, &a) == 0);
	for (i = 0; i < 3; i++)
		assert(gwp_iplim_get(l, &a, 103, NULL) == GWP_IPLIM_ADMIT);
	assert(gwp_iplim_get(l, &a, 103, NULL) == GWP_IPLIM_REFUSE_LOG);

	/* Destroy copes with live entries. */
	gwp_iplim_destroy(l);
	gwp_iplim_destroy(NULL);
}

/* Enough keys to grow every shard several times, then shrink it back. */
static void test_many(void)
{
	enum { NR = 20000 };
	struct gwp_iplim *l = gwp_iplim_create(1);
	struct gwp_iplim_key k;
	uint32_t i;

	assert(l);
	memset(&k, 0, sizeof(k));
	for (i = 0; i < NR; i++) {
		memcpy(&k.b[12], &i, sizeof(i));
		assert(gwp_iplim_get(l, &k, 1, NULL) == GWP_IPLIM_ADMIT);
	}
	assert(gwp_iplim_nr_entries(l) == NR);
	for (i = 0; i < NR; i++) {
		memcpy(&k.b[12], &i, sizeof(i));
		assert(gwp_iplim_count(l, &k) == 1);
		assert(gwp_iplim_get(l, &k, 1, NULL) == GWP_IPLIM_REFUSE_LOG);
	}
	for (i = 0; i < NR; i++) {
		memcpy(&k.b[12], &i, sizeof(i));
		gwp_iplim_put(l, &k);
	}
	assert(gwp_iplim_nr_entries(l) == 0);
	gwp_iplim_destroy(l);
}

/*
 * Workers sharing one table: the cap holds under contention, and every
 * admitted connection is uncounted again.
 */
enum { MT_MAX = 3, MT_THREADS = 8, MT_ITERS = 20000, MT_KEYS = 4 };
static struct gwp_iplim *mt_l;
static _Atomic(int) mt_live[MT_KEYS];
static _Atomic(int) mt_over;

static void *mt_worker(void *arg)
{
	uintptr_t id = (uintptr_t)arg;
	struct gwp_iplim_key k;
	int i, n;

	memset(&k, 0, sizeof(k));
	for (i = 0; i < MT_ITERS; i++) {
		uint8_t idx = (uint8_t)((i + id) % MT_KEYS);

		k.b[0] = idx;
		if (gwp_iplim_get(mt_l, &k, (uint32_t)i, NULL) != GWP_IPLIM_ADMIT)
			continue;
		n = atomic_fetch_add(&mt_live[idx], 1) + 1;
		if (n > MT_MAX)
			atomic_fetch_add(&mt_over, 1);
		atomic_fetch_sub(&mt_live[idx], 1);
		gwp_iplim_put(mt_l, &k);
	}
	return NULL;
}

static void test_threads(void)
{
	pthread_t t[MT_THREADS];
	uintptr_t i;

	mt_l = gwp_iplim_create(MT_MAX);
	assert(mt_l);
	for (i = 0; i < MT_THREADS; i++)
		assert(!pthread_create(&t[i], NULL, mt_worker, (void *)i));
	for (i = 0; i < MT_THREADS; i++)
		assert(!pthread_join(t[i], NULL));
	assert(atomic_load(&mt_over) == 0);
	assert(gwp_iplim_nr_entries(mt_l) == 0);
	gwp_iplim_destroy(mt_l);
}

int main(void)
{
	test_key();
	test_cap();
	test_many();
	test_threads();
	printf("All iplimit tests passed.\n");
	return 0;
}
