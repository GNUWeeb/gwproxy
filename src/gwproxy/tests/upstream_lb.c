// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * Unit tests for the shared upstream server state and a pool's choice of a
 * server (upstream_lb.c).
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <gwproxy/upstream_lb.h>
#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

static struct gwp_sockaddr addr_of(const char *ip, uint16_t port)
{
	struct gwp_sockaddr s;

	memset(&s, 0, sizeof(s));
	if (strchr(ip, ':')) {
		s.i6.sin6_family = AF_INET6;
		s.i6.sin6_port = htons(port);
		assert(inet_pton(AF_INET6, ip, &s.i6.sin6_addr) == 1);
	} else {
		s.i4.sin_family = AF_INET;
		s.i4.sin_port = htons(port);
		assert(inet_pton(AF_INET, ip, &s.i4.sin_addr) == 1);
	}
	return s;
}

static struct gwp_up_key key_of(enum gwp_up_scheme scheme, const char *ip,
				uint16_t port, const char *user)
{
	struct gwp_sockaddr a = addr_of(ip, port);
	struct gwp_up_key k;

	/* Garbage first: the key must not depend on what was there. */
	memset(&k, 0xa5, sizeof(k));
	gwp_up_key_init(&k, scheme, &a, user, user ? strlen(user) : 0);
	return k;
}

/* Same identity, same key; any part that differs makes another one. */
static void test_key(void)
{
	struct gwp_up_key a, b;

	a = key_of(GWP_UP_SCHEME_SOCKS5, "127.0.0.1", 1080, "u");
	b = key_of(GWP_UP_SCHEME_SOCKS5, "127.0.0.1", 1080, "u");
	assert(!memcmp(&a, &b, sizeof(a)));

	b = key_of(GWP_UP_SCHEME_SOCKS5H, "127.0.0.1", 1080, "u");
	assert(memcmp(&a, &b, sizeof(a)));
	b = key_of(GWP_UP_SCHEME_SOCKS5, "127.0.0.2", 1080, "u");
	assert(memcmp(&a, &b, sizeof(a)));
	b = key_of(GWP_UP_SCHEME_SOCKS5, "127.0.0.1", 1081, "u");
	assert(memcmp(&a, &b, sizeof(a)));
	b = key_of(GWP_UP_SCHEME_SOCKS5, "127.0.0.1", 1080, "v");
	assert(memcmp(&a, &b, sizeof(a)));
	b = key_of(GWP_UP_SCHEME_SOCKS5, "127.0.0.1", 1080, NULL);
	assert(memcmp(&a, &b, sizeof(a)));
	b = key_of(GWP_UP_SCHEME_SOCKS5, "::1", 1080, "u");
	assert(memcmp(&a, &b, sizeof(a)));

	a = key_of(GWP_UP_SCHEME_HTTPS, "::1", 443, NULL);
	b = key_of(GWP_UP_SCHEME_HTTPS, "::1", 443, NULL);
	assert(!memcmp(&a, &b, sizeof(a)));
	b = key_of(GWP_UP_SCHEME_HTTP, "::1", 443, NULL);
	assert(memcmp(&a, &b, sizeof(a)));
}

/*
 * Entries are shared by identity and refcounted by the server objects that
 * use them; the open count is the entry's, so a pool rebuilt with the same
 * servers (an ACL reload) sees the counts the old one left.
 */
static void test_rebuild(void)
{
	struct gwp_up_key k1 = key_of(GWP_UP_SCHEME_HTTP, "10.0.0.1", 8080, "a");
	struct gwp_up_key k2 = key_of(GWP_UP_SCHEME_HTTP, "10.0.0.2", 8080, "a");
	struct gwp_up_table *t = gwp_up_table_create();
	struct gwp_up_state *old1, *old2, *new1, *new2, *new3;

	assert(t);
	/* The old pool's servers; pairs take slots. */
	old1 = gwp_up_state_get(t, &k1);
	old2 = gwp_up_state_get(t, &k2);
	assert(old1 && old2 && old1 != old2);
	assert(gwp_up_table_count(t) == 2);
	assert(gwp_up_state_take(old1) == 1);
	assert(gwp_up_state_take(old1) == 2);
	assert(gwp_up_state_take(old2) == 1);

	/* The reload builds the new pool while the old one still lives. */
	new1 = gwp_up_state_get(t, &k1);
	new2 = gwp_up_state_get(t, &k2);
	new3 = gwp_up_state_get(t, &(struct gwp_up_key){0});
	assert(new1 == old1 && new2 == old2 && new3 != old1);
	assert(gwp_up_table_count(t) == 3);
	assert(gwp_up_state_open(new1) == 2 && gwp_up_state_open(new2) == 1);
	assert(gwp_up_state_open(new3) == 0);

	/* The old pool goes; its pairs carry on, and later end. */
	gwp_up_state_put(old1);
	gwp_up_state_put(old2);
	assert(gwp_up_table_count(t) == 3);
	assert(gwp_up_state_open(new1) == 2);
	assert(gwp_up_state_take(new1) == 3);	/* a pair of the new pool */
	assert(gwp_up_state_give(new1) == 2);
	assert(gwp_up_state_give(new1) == 1);
	assert(gwp_up_state_give(new1) == 0);
	assert(gwp_up_state_give(new2) == 0);

	/* Giving back a slot never taken is reported, the count stays 0. */
	assert(gwp_up_state_give(new2) == UINT32_MAX);
	assert(gwp_up_state_open(new2) == 0);

	/* The last server of an identity takes its entry with it. */
	gwp_up_state_put(new3);
	assert(gwp_up_table_count(t) == 2);
	gwp_up_state_put(new2);
	gwp_up_state_put(new1);
	assert(gwp_up_table_count(t) == 0);

	/* A fresh entry for a gone identity starts from nothing. */
	new1 = gwp_up_state_get(t, &k1);
	assert(new1 && gwp_up_state_open(new1) == 0);
	gwp_up_state_put(new1);
	gwp_up_state_put(NULL);

	assert(gwp_up_table_destroy(t) == 0);

	/* What a leak would leave is counted (and freed) at the end. */
	t = gwp_up_table_create();
	assert(t);
	assert(gwp_up_state_get(t, &k1) && gwp_up_state_get(t, &k2));
	assert(gwp_up_table_destroy(t) == 2);
	assert(gwp_up_table_destroy(NULL) == 0);
}

/* Round-robin: the cursor's server, whatever the counts. */
static void test_round_robin(void)
{
	static const uint32_t open[3] = { 9, 0, 5 };
	uint32_t hits[3] = { 0 }, rr;

	for (rr = 0; rr < 9; rr++) {
		uint32_t i = gwp_up_lb_pick(false, rr, open, 3);

		assert(i == rr % 3);
		hits[i]++;
	}
	assert(hits[0] == 3 && hits[1] == 3 && hits[2] == 3);
	assert(gwp_up_lb_pick(false, 7, open, 1) == 0);
	/* The cursor wraps at 2^32 and the pick stays in range. */
	assert(gwp_up_lb_pick(false, UINT32_MAX, open, 3) == UINT32_MAX % 3);
}

/* Least-connections: the fewest open, ties from the cursor on. */
static void test_least_conn(void)
{
	uint32_t open[4] = { 3, 1, 4, 1 };
	uint32_t hits[4] = { 0 }, rr, i;

	/* Servers 1 and 3 tie: whichever comes first from the cursor on. */
	assert(gwp_up_lb_pick(true, 0, open, 4) == 1);
	assert(gwp_up_lb_pick(true, 1, open, 4) == 1);
	assert(gwp_up_lb_pick(true, 2, open, 4) == 3);
	assert(gwp_up_lb_pick(true, 3, open, 4) == 3);
	assert(gwp_up_lb_pick(true, 4, open, 4) == 1);

	/* A single least-loaded server wins from every cursor position. */
	open[3] = 0;
	for (rr = 0; rr < 8; rr++)
		assert(gwp_up_lb_pick(true, rr, open, 4) == 3);

	/*
	 * Fed back (each pick opens a pair on its server), new pairs fill the
	 * idle servers up to the busy one, then spread evenly.
	 */
	open[0] = 5;
	open[1] = open[2] = open[3] = 0;
	for (rr = 0; rr < 15; rr++)
		open[gwp_up_lb_pick(true, rr, open, 4)]++;
	assert(open[0] == 5 && open[1] == 5 && open[2] == 5 && open[3] == 5);

	/* All equal and nothing changing: the ties rotate with the cursor. */
	memset(open, 0, sizeof(open));
	for (rr = 0; rr < 400; rr++)
		hits[gwp_up_lb_pick(true, rr, open, 4)]++;
	for (i = 0; i < 4; i++)
		assert(hits[i] == 100);

	assert(gwp_up_lb_pick(true, 5, open, 1) == 0);
}

#define NR_THREADS	8
#define NR_ROUNDS	20000

static void *thread_fn(void *arg)
{
	struct gwp_up_state *s = arg;
	int i;

	for (i = 0; i < NR_ROUNDS; i++) {
		gwp_up_state_take(s);
		gwp_up_state_take(s);
		assert(gwp_up_state_give(s) != UINT32_MAX);
		assert(gwp_up_state_give(s) != UINT32_MAX);
	}
	return NULL;
}

/* Workers take and give slots at once; the count ends where it began. */
static void test_threads(void)
{
	struct gwp_up_key k = key_of(GWP_UP_SCHEME_SOCKS5, "::1", 1, NULL);
	struct gwp_up_table *t = gwp_up_table_create();
	pthread_t th[NR_THREADS];
	struct gwp_up_state *s;
	int i;

	assert(t);
	s = gwp_up_state_get(t, &k);
	assert(s);
	for (i = 0; i < NR_THREADS; i++)
		assert(!pthread_create(&th[i], NULL, thread_fn, s));
	for (i = 0; i < NR_THREADS; i++)
		assert(!pthread_join(th[i], NULL));
	assert(gwp_up_state_open(s) == 0);
	gwp_up_state_put(s);
	assert(gwp_up_table_destroy(t) == 0);
}

int main(void)
{
	test_key();
	test_rebuild();
	test_round_robin();
	test_least_conn();
	test_threads();
	printf("All upstream_lb tests passed.\n");
	return 0;
}
