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

#define NR_MANY	20000u

/* The @i-th of NR_MANY identities: addresses, ports and users all vary. */
static struct gwp_up_key many_key(uint32_t i)
{
	char ip[32], user[16];

	snprintf(ip, sizeof(ip), "10.%u.%u.%u", i >> 16, (i >> 8) & 255,
		 i & 255);
	snprintf(user, sizeof(user), "u%u", i % 7);
	return key_of(i % 3 ? GWP_UP_SCHEME_SOCKS5 : GWP_UP_SCHEME_HTTP, ip,
		      (uint16_t)(1000 + i % 5), i % 2 ? user : NULL);
}

/*
 * Many identities, as large pools make: each gets its own entry however
 * the table grows, finds it again by its key, and the last put of each
 * takes it out, in any order, leaving the others findable.
 */
static void test_many(void)
{
	struct gwp_up_table *t = gwp_up_table_create();
	static struct gwp_up_state *s[NR_MANY];
	struct gwp_up_key k;
	uint32_t i, j;

	assert(t);
	for (i = 0; i < NR_MANY; i++) {
		k = many_key(i);
		s[i] = gwp_up_state_get(t, &k);
		assert(s[i]);
		gwp_up_state_take(s[i]);
	}
	assert(gwp_up_table_count(t) == NR_MANY);
	/* A reload: every identity again, then the old references go. */
	for (i = 0; i < NR_MANY; i++) {
		k = many_key(i);
		assert(gwp_up_state_get(t, &k) == s[i]);
		assert(gwp_up_state_open(s[i]) == 1);
	}
	for (i = 0; i < NR_MANY; i++)
		gwp_up_state_put(s[i]);
	assert(gwp_up_table_count(t) == NR_MANY);

	/* Removed in a scattered order; the rest are still found. */
	for (i = 0; i < NR_MANY; i++) {
		j = (i * 7919u) % NR_MANY;
		assert(gwp_up_state_give(s[j]) == 0);
		gwp_up_state_put(s[j]);
		if (i % 1000 == 0) {
			k = many_key((j + 1) % NR_MANY);
			gwp_up_state_put(gwp_up_state_get(t, &k));
		}
	}
	assert(gwp_up_table_count(t) == 0);

	/* Gone identities come back fresh. */
	k = many_key(5);
	s[0] = gwp_up_state_get(t, &k);
	assert(s[0] && gwp_up_state_open(s[0]) == 0);
	assert(gwp_up_table_destroy(t) == 1);
}

#define NONE	UINT32_MAX

/* A pick with every server in service and none to skip. */
static uint32_t pick(bool least_conn, uint32_t rr, const uint32_t *open,
		     uint32_t nr)
{
	return gwp_up_lb_pick(least_conn, rr, open, NULL, nr, NONE);
}

/* Round-robin: the cursor's server, whatever the counts. */
static void test_round_robin(void)
{
	static const uint32_t open[3] = { 9, 0, 5 };
	uint32_t hits[3] = { 0 }, rr;

	for (rr = 0; rr < 9; rr++) {
		uint32_t i = pick(false, rr, open, 3);

		assert(i == rr % 3);
		hits[i]++;
	}
	assert(hits[0] == 3 && hits[1] == 3 && hits[2] == 3);
	assert(pick(false, 7, open, 1) == 0);
	/* The cursor wraps at 2^32 and the pick stays in range. */
	assert(pick(false, UINT32_MAX, open, 3) == UINT32_MAX % 3);
}

/* Least-connections: the fewest open, ties from the cursor on. */
static void test_least_conn(void)
{
	uint32_t open[4] = { 3, 1, 4, 1 };
	uint32_t hits[4] = { 0 }, rr, i;

	/* Servers 1 and 3 tie: whichever comes first from the cursor on. */
	assert(pick(true, 0, open, 4) == 1);
	assert(pick(true, 1, open, 4) == 1);
	assert(pick(true, 2, open, 4) == 3);
	assert(pick(true, 3, open, 4) == 3);
	assert(pick(true, 4, open, 4) == 1);

	/* A single least-loaded server wins from every cursor position. */
	open[3] = 0;
	for (rr = 0; rr < 8; rr++)
		assert(pick(true, rr, open, 4) == 3);

	/*
	 * Fed back (each pick opens a pair on its server), new pairs fill the
	 * idle servers up to the busy one, then spread evenly.
	 */
	open[0] = 5;
	open[1] = open[2] = open[3] = 0;
	for (rr = 0; rr < 15; rr++)
		open[pick(true, rr, open, 4)]++;
	assert(open[0] == 5 && open[1] == 5 && open[2] == 5 && open[3] == 5);

	/* All equal and nothing changing: the ties rotate with the cursor. */
	memset(open, 0, sizeof(open));
	for (rr = 0; rr < 400; rr++)
		hits[pick(true, rr, open, 4)]++;
	for (i = 0; i < 4; i++)
		assert(hits[i] == 100);

	assert(pick(true, 5, open, 1) == 0);
}

/*
 * The window: GWP_UP_EJECT_FAILS failures no more than
 * GWP_UP_EJECT_WINDOW_MS apart eject for GWP_UP_EJECT_MS, once; the
 * server returns when that has passed, and is ended exactly once. From
 * @t0 on, which the caller places so that the window or the ejection
 * straddles the 2^32 ms wrap of the 32-bit times.
 */
static void test_eject_window(uint32_t t0)
{
	struct gwp_up_key k = key_of(GWP_UP_SCHEME_HTTP, "10.0.0.9", 80, NULL);
	struct gwp_up_table *t = gwp_up_table_create();
	const uint32_t w = GWP_UP_EJECT_WINDOW_MS;
	struct gwp_up_state *s;
	uint32_t end;
	bool back;

	assert(GWP_UP_EJECT_FAILS == 3 && w == 30000 &&
	       GWP_UP_EJECT_MS == 300000);
	assert(t);
	s = gwp_up_state_get(t, &k);
	assert(s);
	assert(gwp_up_state_ejected(s, t0, &back) == 0 && !back);

	/* Two are not enough; the third, right at the window's edge, is. */
	assert(!gwp_up_state_fail(s, t0));
	assert(!gwp_up_state_fail(s, t0 + 1000));
	assert(gwp_up_state_ejected(s, t0 + 1000, NULL) == 0);
	assert(gwp_up_state_fail(s, t0 + w));
	end = t0 + w + GWP_UP_EJECT_MS;
	assert(gwp_up_state_ejected(s, t0 + w, &back) == GWP_UP_EJECT_MS &&
	       !back);

	/* Failures while ejected: recorded, but no second ejection. */
	assert(!gwp_up_state_fail(s, t0 + w + 1));
	assert(!gwp_up_state_fail(s, end - 1));
	assert(gwp_up_state_ejected(s, end - 1, &back) == 1 && !back);

	/* It returns when the time is up, and only one caller says so. */
	assert(gwp_up_state_ejected(s, end, &back) == 0 && back);
	assert(gwp_up_state_ejected(s, end, &back) == 0 && !back);
	assert(gwp_up_state_ejected(s, end + 5, &back) == 0 && !back);
	gwp_up_state_put(s);

	/* One millisecond too wide: no ejection, until a later one fits. */
	s = gwp_up_state_get(t, &k);
	assert(s && gwp_up_state_ejected(s, t0, NULL) == 0);
	assert(!gwp_up_state_fail(s, t0));
	assert(!gwp_up_state_fail(s, t0 + 2000));
	assert(!gwp_up_state_fail(s, t0 + w + 1));
	assert(gwp_up_state_ejected(s, t0 + w + 1, NULL) == 0);
	assert(gwp_up_state_fail(s, t0 + w + 2));
	assert(gwp_up_state_ejected(s, t0 + w + 2, NULL) == GWP_UP_EJECT_MS);

	/*
	 * Still failing when the ejection ends: what came in meanwhile
	 * counts, so the next failure ejects again at once.
	 */
	end = t0 + w + 2 + GWP_UP_EJECT_MS;
	assert(!gwp_up_state_fail(s, end - 2000));
	assert(!gwp_up_state_fail(s, end - 1000));
	assert(gwp_up_state_fail(s, end + 10));
	assert(gwp_up_state_ejected(s, end + 10, &back) == GWP_UP_EJECT_MS &&
	       !back);

	/* Old failures age out: a fresh run of three is needed. */
	end += 10 + GWP_UP_EJECT_MS;
	assert(gwp_up_state_ejected(s, end, &back) == 0 && back);
	assert(!gwp_up_state_fail(s, end + w));
	assert(!gwp_up_state_fail(s, end + w + 1));
	assert(gwp_up_state_fail(s, end + w + 2));
	gwp_up_state_put(s);

	/* A server whose identity was gone in between starts fresh. */
	s = gwp_up_state_get(t, &k);
	assert(s && gwp_up_state_ejected(s, 0, NULL) == 0);
	assert(!gwp_up_state_fail(s, end + w + 3));
	gwp_up_state_put(s);
	assert(gwp_up_table_destroy(t) == 0);
}

/*
 * A time that comes out as 0, which stands for "none": the failure and
 * the ejection still count, a millisecond later.
 */
static void test_eject_zero(void)
{
	struct gwp_up_key k = key_of(GWP_UP_SCHEME_HTTP, "10.0.0.8", 80, NULL);
	struct gwp_up_table *t = gwp_up_table_create();
	const uint32_t now = 0u - GWP_UP_EJECT_MS;	/* ends at 0 */
	struct gwp_up_state *s;
	bool back;

	assert(t);
	s = gwp_up_state_get(t, &k);
	assert(s);
	/* A failure at 0 is recorded, as 1. */
	assert(!gwp_up_state_fail(s, now - 2));
	assert(!gwp_up_state_fail(s, now - 1));
	assert(gwp_up_state_fail(s, now));
	assert(gwp_up_state_ejected(s, now, &back) == GWP_UP_EJECT_MS + 1 &&
	       !back);
	assert(gwp_up_state_ejected(s, 0, &back) == 1 && !back);
	assert(gwp_up_state_ejected(s, 1, &back) == 0 && back);
	gwp_up_state_put(s);

	s = gwp_up_state_get(t, &k);
	assert(s);
	assert(!gwp_up_state_fail(s, UINT32_MAX));
	assert(!gwp_up_state_fail(s, 0));
	assert(gwp_up_state_fail(s, 5));
	assert(gwp_up_state_ejected(s, 5, NULL) == GWP_UP_EJECT_MS);
	gwp_up_state_put(s);
	assert(gwp_up_table_destroy(t) == 0);
}

/*
 * The health is the identity's: a pool rebuilt by a reload sees its
 * servers ejected as long as some object kept the entry.
 */
static void test_eject_rebuild(void)
{
	struct gwp_up_key k = key_of(GWP_UP_SCHEME_SOCKS5H, "::1", 9, "u");
	struct gwp_up_table *t = gwp_up_table_create();
	struct gwp_up_state *old, *new;

	assert(t);
	old = gwp_up_state_get(t, &k);
	assert(old);
	assert(!gwp_up_state_fail(old, 10) && !gwp_up_state_fail(old, 20));
	assert(gwp_up_state_fail(old, 30));
	new = gwp_up_state_get(t, &k);
	gwp_up_state_put(old);
	assert(new == old);
	assert(gwp_up_state_ejected(new, 40, NULL) == GWP_UP_EJECT_MS - 10);
	gwp_up_state_put(new);
	assert(gwp_up_table_destroy(t) == 0);
}

/* The pick leaves ejected servers out, and spreads their share evenly. */
static void test_pick_ejected(void)
{
	uint32_t eject[4] = { 0, 5000, 0, 0 };
	uint32_t open[4] = { 0, 0, 0, 0 };
	uint32_t hits[4] = { 0 }, rr, i;

	/* Round-robin over 0, 2 and 3; 1 never. */
	for (rr = 0; rr < 300; rr++)
		hits[gwp_up_lb_pick(false, rr, open, eject, 4, NONE)]++;
	assert(hits[0] == 100 && hits[1] == 0 && hits[2] == 100 &&
	       hits[3] == 100);
	assert(gwp_up_lb_pick(false, 0, open, eject, 4, NONE) == 0);
	assert(gwp_up_lb_pick(false, 1, open, eject, 4, NONE) == 2);
	assert(gwp_up_lb_pick(false, 2, open, eject, 4, NONE) == 3);

	/* least_conn: an ejected server's low count does not draw pairs. */
	open[0] = 4;
	open[1] = 0;
	open[2] = 2;
	open[3] = 2;
	for (rr = 0; rr < 8; rr++) {
		i = gwp_up_lb_pick(true, rr, open, eject, 4, NONE);
		assert(i == 2 || i == 3);
	}
	/* Ties rotate from the cursor's server among those in service. */
	assert(gwp_up_lb_pick(true, 1, open, eject, 4, NONE) == 2);
	assert(gwp_up_lb_pick(true, 2, open, eject, 4, NONE) == 3);
	assert(gwp_up_lb_pick(true, 0, open, eject, 4, NONE) == 2);

	/* All ejected: the one back soonest, whatever the method. */
	eject[0] = 900;
	eject[1] = 700;
	eject[2] = 800;
	eject[3] = 701;
	for (rr = 0; rr < 8; rr++) {
		assert(gwp_up_lb_pick(false, rr, open, eject, 4, NONE) == 1);
		assert(gwp_up_lb_pick(true, rr, open, eject, 4, NONE) == 1);
	}
	/* Equal ends take turns. */
	eject[3] = 700;
	assert(gwp_up_lb_pick(false, 0, open, eject, 4, NONE) == 1);
	assert(gwp_up_lb_pick(false, 2, open, eject, 4, NONE) == 3);
	assert(gwp_up_lb_pick(false, 3, open, eject, 4, NONE) == 3);

	/* A pool of one is never left without its server. */
	assert(gwp_up_lb_pick(false, 3, open, eject, 1, NONE) == 0);
	assert(gwp_up_lb_pick(true, 3, open, eject, 1, NONE) == 0);
}

/* A retry: another server in service, or none at all. */
static void test_pick_retry(void)
{
	uint32_t eject[3] = { 0, 0, 0 };
	uint32_t open[3] = { 1, 1, 0 };
	uint32_t rr;

	for (rr = 0; rr < 6; rr++) {
		assert(gwp_up_lb_pick(false, rr, open, eject, 3, 0) != 0);
		assert(gwp_up_lb_pick(true, rr, open, eject, 3, 2) != 2);
	}
	assert(gwp_up_lb_pick(true, 0, open, eject, 3, 0) == 2);
	assert(gwp_up_lb_pick(false, 0, open, NULL, 3, 1) == 0);
	assert(gwp_up_lb_pick(false, 1, open, NULL, 3, 1) == 2);

	/* The only other server is ejected: no retry, though it exists. */
	eject[1] = 50;
	eject[2] = 40;
	assert(gwp_up_lb_pick(false, 0, open, eject, 3, 2) == 0);
	assert(gwp_up_lb_pick(false, 0, open, eject, 3, 0) == NONE);
	assert(gwp_up_lb_pick(true, 9, open, eject, 3, 0) == NONE);
	/* Nor in a pool of one, ejected or not. */
	assert(gwp_up_lb_pick(false, 0, open, NULL, 1, 0) == NONE);
	assert(gwp_up_lb_pick(false, 0, open, eject, 1, 0) == NONE);
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

#define NR_RACES	2000

struct race {
	pthread_barrier_t	go;
	struct gwp_up_state	*s;
	uint32_t		now;
	_Atomic(uint32_t)	ejected;
	uint32_t		per_thread;
};

static void *race_fn(void *arg)
{
	struct race *r = arg;
	uint32_t i;

	pthread_barrier_wait(&r->go);
	for (i = 0; i < r->per_thread; i++) {
		if (gwp_up_state_fail(r->s, r->now))
			atomic_fetch_add(&r->ejected, 1);
	}
	return NULL;
}

/*
 * Workers fail at once. Exactly as many failures as it takes, one per
 * thread: none of them may be lost, so the server is ejected, exactly
 * once. Many per thread: still one ejection.
 */
static void test_eject_threads(void)
{
	struct gwp_up_key k = key_of(GWP_UP_SCHEME_HTTP, "10.0.0.7", 80, NULL);
	struct gwp_up_table *t = gwp_up_table_create();
	pthread_t th[NR_THREADS];
	struct race r;
	int n, i;

	assert(t);
	for (n = 0; n < NR_RACES; n++) {
		r.s = gwp_up_state_get(t, &k);
		assert(r.s);
		r.now = 1000 + (uint32_t)n;
		r.per_thread = 1;
		atomic_init(&r.ejected, 0);
		assert(!pthread_barrier_init(&r.go, NULL, GWP_UP_EJECT_FAILS));
		for (i = 0; i < (int)GWP_UP_EJECT_FAILS; i++)
			assert(!pthread_create(&th[i], NULL, race_fn, &r));
		for (i = 0; i < (int)GWP_UP_EJECT_FAILS; i++)
			assert(!pthread_join(th[i], NULL));
		pthread_barrier_destroy(&r.go);
		assert(atomic_load(&r.ejected) == 1);
		assert(gwp_up_state_ejected(r.s, r.now, NULL) ==
		       GWP_UP_EJECT_MS);
		/* Its last reference: the next round starts fresh. */
		gwp_up_state_put(r.s);
	}

	r.s = gwp_up_state_get(t, &k);
	assert(r.s);
	r.now = 77;
	r.per_thread = 1000;
	atomic_init(&r.ejected, 0);
	assert(!pthread_barrier_init(&r.go, NULL, NR_THREADS));
	for (i = 0; i < NR_THREADS; i++)
		assert(!pthread_create(&th[i], NULL, race_fn, &r));
	for (i = 0; i < NR_THREADS; i++)
		assert(!pthread_join(th[i], NULL));
	pthread_barrier_destroy(&r.go);
	assert(atomic_load(&r.ejected) == 1);
	gwp_up_state_put(r.s);
	assert(gwp_up_table_destroy(t) == 0);
}

int main(void)
{
	test_key();
	test_rebuild();
	test_many();
	test_round_robin();
	test_least_conn();
	test_threads();
	test_eject_window(1000000);
	/* The window across the wrap, then the ejection across it. */
	test_eject_window(0u - 15000);
	test_eject_window(0u - 200000);
	/* Just past it. */
	test_eject_window(7);
	test_eject_zero();
	test_eject_rebuild();
	test_pick_ejected();
	test_pick_retry();
	test_eject_threads();
	printf("All upstream_lb tests passed.\n");
	return 0;
}
