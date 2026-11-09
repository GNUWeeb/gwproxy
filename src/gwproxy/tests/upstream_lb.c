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
#include <stdlib.h>
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

/* The ejection state of @s for the default health settings. */
static struct gwp_up_health *def_health(struct gwp_up_state *s)
{
	struct gwp_up_health *h;
	struct gwp_up_opts o;

	assert(s);
	gwp_up_opts_default(&o);
	h = gwp_up_health_get(s, &o);
	assert(h && h->st == s);
	return h;
}

/* A failure of @h's server, deciding for @h only (and any others silently). */
static bool fail(struct gwp_up_health *h, uint32_t now)
{
	return gwp_up_state_fail(h->st, h, now, NULL, NULL);
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
#define NR_THREADS	8

/*
 * A pool for the pick tests: @nr servers of distinct identities, whose open
 * counts and ejections a test sets, and a clock it moves.
 */
struct tpool {
	struct gwp_up_table	*t;
	struct gwp_up_state	**s;
	struct gwp_up_health	**h;
	struct gwp_up_member	*m;
	struct gwp_up_plan	*plan;
	uint32_t		nr;
	uint32_t		clock;
	uint32_t		clock_reads;
	uint32_t		nr_back;
	uint32_t		last_back;
	/*
	 * The random source: none (no probes) by default; the values of
	 * @fake[] in turn, or with @xs a real generator from that seed.
	 */
	const uint32_t		*fake;
	uint32_t		nr_fake;
	uint32_t		ifake;		/* the next of @fake[] */
	uint32_t		xs;
	uint32_t		nr_random;
};

static uint32_t tp_random(void *arg)
{
	struct tpool *p = arg;
	p->nr_random++;
	if (p->fake)
		return p->fake[p->ifake++ % p->nr_fake];
	return gwp_up_rand(&p->xs);
}

/* The random value whose probe lands on server @j of @nr. */
static uint32_t tp_at(uint32_t nr, uint32_t j)
{
	return (uint32_t)((((uint64_t)j << 32) + nr - 1) / nr);
}

static uint32_t tp_now(void *arg)
{
	struct tpool *p = arg;

	p->clock_reads++;
	return p->clock;
}

static void tp_back(void *arg, uint32_t i)
{
	struct tpool *p = arg;

	p->nr_back++;
	p->last_back = i;
}

static void tp_init(struct tpool *p, uint32_t nr)
{
	uint32_t i;

	memset(p, 0, sizeof(*p));
	p->t = gwp_up_table_create();
	p->s = calloc(nr, sizeof(*p->s));
	p->h = calloc(nr, sizeof(*p->h));
	p->m = calloc(nr, sizeof(*p->m));
	assert(p->t && p->s && p->h && p->m);
	p->nr = nr;
	p->clock = 1000000;
	for (i = 0; i < nr; i++) {
		struct gwp_up_key k = many_key(i);

		p->s[i] = gwp_up_state_get(p->t, &k);
		assert(p->s[i]);
		p->h[i] = def_health(p->s[i]);
		p->m[i].st = p->s[i];
		p->m[i].h = p->h[i];
	}
}

static void tp_free(struct tpool *p)
{
	uint32_t i;

	for (i = 0; i < p->nr; i++) {
		while (gwp_up_state_open(p->s[i]))
			gwp_up_state_give(p->s[i]);
		gwp_up_health_put(p->h[i]);
		gwp_up_state_put(p->s[i]);
	}
	assert(gwp_up_table_destroy(p->t) == 0);
	free(p->s);
	free(p->h);
	free(p->m);
	free(p->plan);
}

/* Give server @i @n open pairs. */
static void tp_open(struct tpool *p, uint32_t i, uint32_t n)
{
	while (gwp_up_state_open(p->s[i]) < n)
		gwp_up_state_take(p->s[i]);
	while (gwp_up_state_open(p->s[i]) > n)
		gwp_up_state_give(p->s[i]);
}

/* Eject server @i (in service) so that its ejection runs @left ms more. */
static void tp_eject(struct tpool *p, uint32_t i, uint32_t left)
{
	uint32_t at = p->clock + left - GWP_UP_EJECT_MS;

	assert(left && left <= GWP_UP_EJECT_MS);
	assert(!gwp_up_health_ejected(p->h[i], p->clock, NULL));
	assert(!fail(p->h[i], at - 2));
	assert(!fail(p->h[i], at - 1));
	assert(fail(p->h[i], at));
	assert(gwp_up_health_ejected(p->h[i], p->clock, NULL) == left);
}

/*
 * A pick by @method (enum gwp_up_method: false is round-robin, true
 * least_conn).
 */
static uint32_t tp_pick(struct tpool *p, uint32_t method, uint32_t rr,
			uint32_t skip)
{
	struct gwp_up_pick pk = {
		.m = p->m, .nr = p->nr, .plan = p->plan,
		.method = (uint8_t)method, .rr = rr,
		.skip = skip, .now = tp_now, .back = tp_back, .arg = p,
		.random = p->fake || p->xs ? tp_random : NULL,
	};
	uint32_t before = p->clock_reads, rnd = p->nr_random, i;

	i = gwp_up_lb_pick(&pk);
	/* The clock: once at most; probes: a few in each tier. */
	assert(p->clock_reads - before <= 1);
	assert(p->nr_random - rnd <= 2 * GWP_UP_PICK_MAX_RANDOM);
	return i;
}

/* A pick with every server in service and none to skip. */
static uint32_t pick(bool least_conn, uint32_t rr, const uint32_t *open,
		     uint32_t nr)
{
	struct tpool p;
	uint32_t i;

	tp_init(&p, nr);
	for (i = 0; i < nr; i++)
		tp_open(&p, i, open[i]);
	i = tp_pick(&p, least_conn, rr, NONE);
	/* None may be ejected: no clock needed. */
	assert(!p.clock_reads);
	tp_free(&p);
	return i;
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
	assert(pick(false, UINT32_MAX - 1, open, 3) == (UINT32_MAX - 1) % 3);
	assert(pick(false, 0, open, 3) == 0);
}

/* Least-connections: the fewest open, ties from the cursor on. */
static void test_least_conn(void)
{
	uint32_t open[4] = { 3, 1, 4, 1 };
	uint32_t hits[4] = { 0 }, rr, i;
	struct tpool p;

	/* Servers 1 and 3 tie: whichever comes first from the cursor on. */
	assert(pick(true, 0, open, 4) == 1);
	assert(pick(true, 1, open, 4) == 1);
	assert(pick(true, 2, open, 4) == 3);
	assert(pick(true, 3, open, 4) == 3);
	assert(pick(true, 4, open, 4) == 1);
	assert(pick(true, UINT32_MAX, open, 4) == 3);

	/* A single least-loaded server wins from every cursor position. */
	open[3] = 0;
	for (rr = 0; rr < 8; rr++)
		assert(pick(true, rr, open, 4) == 3);

	/*
	 * Fed back (each pick opens a pair on its server), new pairs fill the
	 * idle servers up to the busy one, then spread evenly.
	 */
	tp_init(&p, 4);
	tp_open(&p, 0, 5);
	for (rr = 0; rr < 15; rr++)
		gwp_up_state_take(p.s[tp_pick(&p, true, rr, NONE)]);
	for (i = 0; i < 4; i++)
		assert(gwp_up_state_open(p.s[i]) == 5);

	/* All equal and nothing changing: the ties rotate with the cursor. */
	for (i = 0; i < 4; i++)
		tp_open(&p, i, 0);
	for (rr = 0; rr < 400; rr++)
		hits[tp_pick(&p, true, rr, NONE)]++;
	for (i = 0; i < 4; i++)
		assert(hits[i] == 100);
	assert(!p.clock_reads);
	tp_free(&p);

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
	struct gwp_up_health *h;
	struct gwp_up_state *s;
	uint32_t end;
	bool back;

	assert(GWP_UP_EJECT_FAILS == 3 && w == 30000 &&
	       GWP_UP_EJECT_MS == 300000);
	assert(t);
	s = gwp_up_state_get(t, &k);
	h = def_health(s);
	assert(s);
	assert(gwp_up_health_ejected(h, t0, &back) == 0 && !back);

	/* Two are not enough; the third, right at the window's edge, is. */
	assert(!fail(h, t0));
	assert(!fail(h, t0 + 1000));
	assert(gwp_up_health_ejected(h, t0 + 1000, NULL) == 0);
	assert(fail(h, t0 + w));
	end = t0 + w + GWP_UP_EJECT_MS;
	assert(gwp_up_health_ejected(h, t0 + w, &back) == GWP_UP_EJECT_MS &&
	       !back);

	/* Failures while ejected: recorded, but no second ejection. */
	assert(!fail(h, t0 + w + 1));
	assert(!fail(h, end - 1));
	assert(gwp_up_health_ejected(h, end - 1, &back) == 1 && !back);

	/* It returns when the time is up, and only one caller says so. */
	assert(gwp_up_health_ejected(h, end, &back) == 0 && back);
	assert(gwp_up_health_ejected(h, end, &back) == 0 && !back);
	assert(gwp_up_health_ejected(h, end + 5, &back) == 0 && !back);
	gwp_up_health_put(h);
	gwp_up_state_put(s);

	/* One millisecond too wide: no ejection, until a later one fits. */
	s = gwp_up_state_get(t, &k);
	h = def_health(s);
	assert(s && gwp_up_health_ejected(h, t0, NULL) == 0);
	assert(!fail(h, t0));
	assert(!fail(h, t0 + 2000));
	assert(!fail(h, t0 + w + 1));
	assert(gwp_up_health_ejected(h, t0 + w + 1, NULL) == 0);
	assert(fail(h, t0 + w + 2));
	assert(gwp_up_health_ejected(h, t0 + w + 2, NULL) == GWP_UP_EJECT_MS);

	/*
	 * Still failing when the ejection ends: what came in meanwhile
	 * counts, so the next failure ejects again at once.
	 */
	end = t0 + w + 2 + GWP_UP_EJECT_MS;
	assert(!fail(h, end - 2000));
	assert(!fail(h, end - 1000));
	assert(fail(h, end + 10));
	assert(gwp_up_health_ejected(h, end + 10, &back) == GWP_UP_EJECT_MS &&
	       !back);

	/* Old failures age out: a fresh run of three is needed. */
	end += 10 + GWP_UP_EJECT_MS;
	assert(gwp_up_health_ejected(h, end, &back) == 0 && back);
	assert(!fail(h, end + w));
	assert(!fail(h, end + w + 1));
	assert(fail(h, end + w + 2));
	gwp_up_health_put(h);
	gwp_up_state_put(s);

	/* A server whose identity was gone in between starts fresh. */
	s = gwp_up_state_get(t, &k);
	h = def_health(s);
	assert(s && gwp_up_health_ejected(h, 0, NULL) == 0);
	assert(!fail(h, end + w + 3));
	gwp_up_health_put(h);
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
	struct gwp_up_health *h;
	struct gwp_up_state *s;
	bool back;

	assert(t);
	s = gwp_up_state_get(t, &k);
	h = def_health(s);
	assert(s);
	/* A failure at 0 is recorded, as 1. */
	assert(!fail(h, now - 2));
	assert(!fail(h, now - 1));
	assert(fail(h, now));
	assert(gwp_up_health_ejected(h, now, &back) == GWP_UP_EJECT_MS + 1 &&
	       !back);
	assert(gwp_up_health_ejected(h, 0, &back) == 1 && !back);
	assert(gwp_up_health_ejected(h, 1, &back) == 0 && back);
	gwp_up_health_put(h);
	gwp_up_state_put(s);

	s = gwp_up_state_get(t, &k);
	h = def_health(s);
	assert(s);
	assert(!fail(h, UINT32_MAX));
	assert(!fail(h, 0));
	assert(fail(h, 5));
	assert(gwp_up_health_ejected(h, 5, NULL) == GWP_UP_EJECT_MS);
	gwp_up_health_put(h);
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
	struct gwp_up_health *ho, *hn;
	struct gwp_up_state *old, *new;

	assert(t);
	old = gwp_up_state_get(t, &k);
	ho = def_health(old);
	assert(!fail(ho, 10) && !fail(ho, 20));
	assert(fail(ho, 30));
	new = gwp_up_state_get(t, &k);
	hn = def_health(new);
	gwp_up_health_put(ho);
	gwp_up_state_put(old);
	assert(new == old && hn == ho);
	assert(gwp_up_health_ejected(hn, 40, NULL) == GWP_UP_EJECT_MS - 10);
	gwp_up_health_put(hn);
	gwp_up_state_put(new);
	assert(gwp_up_table_destroy(t) == 0);
}

/* What the ejected callback of gwp_up_state_fail() was told. */
struct told {
	const struct gwp_up_health	*h[4];
	uint32_t			nr;
};

static void tell(void *arg, const struct gwp_up_health *h)
{
	struct told *t = arg;

	assert(t->nr < 4);
	t->h[t->nr++] = h;
}

static struct gwp_up_health *health_of(struct gwp_up_state *s, uint32_t fails,
				       uint32_t window, uint32_t eject)
{
	struct gwp_up_opts o = {
		.max_fails = fails, .fail_timeout_ms = window,
		.eject_ms = eject,
	};
	struct gwp_up_health *h = gwp_up_health_get(s, &o);

	assert(h && h->st == s);
	return h;
}

/*
 * Pools that list one identity with different health settings: the
 * failures are the identity's, and each set of settings decides from them
 * on its own whether the server is out for it, and for how long. Equal
 * settings share one ejection state; a failure through a server whose
 * pool never ejects it (no state of its own) still counts for the others.
 */
static void test_health_settings(void)
{
	struct gwp_up_key k = key_of(GWP_UP_SCHEME_SOCKS5H, "10.0.0.5", 1080,
				     "u");
	struct gwp_up_table *t = gwp_up_table_create();
	struct gwp_up_health *a, *a2, *b, *c;
	struct gwp_up_state *s;
	struct told told = { .nr = 0 };
	uint32_t t0 = 1000000;

	assert(t);
	s = gwp_up_state_get(t, &k);
	assert(s);
	a = def_health(s);
	a2 = def_health(s);
	b = health_of(s, 5, 60000, 600000);
	assert(a == a2 && a != b);
	assert(s->fail_cap == 5);
	gwp_up_health_put(a2);

	/* Three in 30 s: out for a's pools, not for b's, which is told. */
	assert(!gwp_up_state_fail(s, a, t0, tell, &told));
	assert(!gwp_up_state_fail(s, b, t0 + 10000, tell, &told));
	assert(gwp_up_state_fail(s, b, t0 + 20000, tell, &told) == false);
	assert(told.nr == 1 && told.h[0] == a);
	assert(gwp_up_health_ejected(a, t0 + 20000, NULL) == GWP_UP_EJECT_MS);
	assert(!gwp_up_health_ejected(b, t0 + 20000, NULL));
	told.nr = 0;
	/* Two more within 60 s of the first: b's turn, for 10 min. */
	assert(!gwp_up_state_fail(s, NULL, t0 + 40000, tell, &told));
	assert(!told.nr);
	assert(gwp_up_state_fail(s, b, t0 + 50000, tell, &told));
	assert(!told.nr);
	assert(gwp_up_health_ejected(b, t0 + 50000, NULL) == 600000);
	/* a's ejection runs on unchanged: failures during it do not extend. */
	assert(gwp_up_health_ejected(a, t0 + 50000, NULL) ==
	       GWP_UP_EJECT_MS - 30000);

	/*
	 * A reload lists the server with new settings: a fresh state, in
	 * service, which sees the failures kept so far (the ring grows to
	 * its max_fails, keeping them).
	 */
	c = health_of(s, 7, 200000, 1000);
	assert(s->fail_cap == 7 && s->fail_nr == 5);
	assert(!gwp_up_health_ejected(c, t0 + 60000, NULL));
	assert(!gwp_up_state_fail(s, NULL, t0 + 60000, tell, &told));
	assert(!told.nr);
	/* The seventh, all within 200 s: c's ejection, for 1 s. */
	assert(gwp_up_state_fail(s, c, t0 + 70000, tell, &told));
	assert(!told.nr);
	assert(gwp_up_health_ejected(c, t0 + 70500, NULL) == 500);
	/* Over before a's and b's; the next failure ejects c again. */
	assert(gwp_up_state_fail(s, c, t0 + 80000, tell, &told));
	assert(!told.nr);
	/* a's and b's run out on their own clocks. */
	assert(!gwp_up_health_ejected(a, t0 + 20000 + GWP_UP_EJECT_MS, NULL));
	assert(gwp_up_health_ejected(b, t0 + 20000 + GWP_UP_EJECT_MS, NULL) ==
	       600000 - GWP_UP_EJECT_MS + 30000);

	/* The old settings go; the ring keeps its size, the rest go on. */
	gwp_up_health_put(b);
	assert(s->fail_cap == 7);
	gwp_up_health_put(a);
	assert(s->health == c && !c->next);
	gwp_up_health_put(c);
	assert(!s->health);
	/* No settings left: failures go nowhere and eject nothing. */
	assert(!gwp_up_state_fail(s, NULL, t0 + 300000, tell, &told));
	gwp_up_health_put(NULL);
	assert(!gwp_up_health_may_be_ejected(NULL));
	assert(!gwp_up_health_ejected(NULL, 5, NULL));
	gwp_up_state_put(s);

	/* A ring made for one failure: max_fails=1 ejects on each. */
	s = gwp_up_state_get(t, &k);
	a = health_of(s, 1, 1, 50);
	assert(s->fail_cap == 1);
	assert(gwp_up_state_fail(s, a, 10, NULL, NULL));
	assert(!gwp_up_state_fail(s, a, 59, NULL, NULL));
	assert(gwp_up_state_fail(s, a, 60, NULL, NULL));
	gwp_up_health_put(a);
	gwp_up_state_put(s);
	assert(gwp_up_table_destroy(t) == 0);
}

/*
 * The pick steps past ejected servers: round-robin gives an ejected
 * server's turns to the next one in service, least_conn never takes one
 * for its low count.
 */
static void test_pick_ejected(void)
{
	uint32_t hits[4] = { 0 }, rr, i;
	struct tpool p;

	tp_init(&p, 4);
	tp_eject(&p, 1, 5000);
	/* Round-robin over 0, 2 and 3; 1's turns go to 2. */
	for (rr = 0; rr < 400; rr++)
		hits[tp_pick(&p, false, rr, NONE)]++;
	assert(hits[0] == 100 && hits[1] == 0 && hits[2] == 200 &&
	       hits[3] == 100);
	assert(tp_pick(&p, false, 0, NONE) == 0);
	assert(tp_pick(&p, false, 1, NONE) == 2);
	assert(tp_pick(&p, false, 2, NONE) == 2);
	assert(tp_pick(&p, false, 3, NONE) == 3);

	/* least_conn: an ejected server's low count does not draw pairs. */
	tp_open(&p, 0, 4);
	tp_open(&p, 2, 2);
	tp_open(&p, 3, 2);
	for (rr = 0; rr < 8; rr++) {
		i = tp_pick(&p, true, rr, NONE);
		assert(i == 2 || i == 3);
	}
	/* Ties rotate from the cursor's place, past the ejected one. */
	assert(tp_pick(&p, true, 1, NONE) == 2);
	assert(tp_pick(&p, true, 2, NONE) == 2);
	assert(tp_pick(&p, true, 3, NONE) == 3);
	assert(tp_pick(&p, true, 0, NONE) == 2);
	/* An idle one in service ends the scan; equal later ones lose. */
	tp_open(&p, 2, 0);
	tp_open(&p, 3, 0);
	assert(tp_pick(&p, true, 3, NONE) == 3);
	assert(tp_pick(&p, true, 1, NONE) == 2);

	/* Its ejection ends: back in its turn, and told once. */
	p.clock += 5000;
	assert(tp_pick(&p, false, 1, NONE) == 1);
	assert(p.nr_back == 1 && p.last_back == 1);
	assert(tp_pick(&p, false, 1, NONE) == 1);
	assert(p.nr_back == 1);
	tp_free(&p);
}

/* A run of ejected servers at the cursor: the first in service after it. */
static void test_pick_ejected_run(void)
{
	uint32_t rr;
	struct tpool p;

	tp_init(&p, 6);
	tp_eject(&p, 2, 100);
	tp_eject(&p, 3, 100);
	tp_eject(&p, 4, 100);
	for (rr = 2; rr <= 4; rr++) {
		assert(tp_pick(&p, false, rr, NONE) == 5);
		assert(tp_pick(&p, true, rr, NONE) == 5);
	}
	/* The run reaches the end: wrap to the start. */
	tp_eject(&p, 5, 100);
	assert(tp_pick(&p, false, 3, NONE) == 0);
	assert(tp_pick(&p, true, 3, NONE) == 0);
	tp_open(&p, 0, 1);
	assert(tp_pick(&p, true, 3, NONE) == 1);
	assert(tp_pick(&p, false, 1, NONE) == 1);
	assert(!p.nr_back);
	tp_free(&p);
}

/* All ejected: the one back soonest, whatever the method. */
static void test_pick_all_ejected(void)
{
	uint32_t rr;
	struct tpool p;

	tp_init(&p, 4);
	tp_eject(&p, 0, 900);
	tp_eject(&p, 1, 700);
	tp_eject(&p, 2, 800);
	tp_eject(&p, 3, 701);
	for (rr = 0; rr < 8; rr++) {
		assert(tp_pick(&p, false, rr, NONE) == 1);
		assert(tp_pick(&p, true, rr, NONE) == 1);
	}
	tp_free(&p);

	/* Equal ends take turns from the cursor. */
	tp_init(&p, 4);
	tp_eject(&p, 0, 900);
	tp_eject(&p, 1, 700);
	tp_eject(&p, 2, 800);
	tp_eject(&p, 3, 700);
	assert(tp_pick(&p, false, 0, NONE) == 1);
	assert(tp_pick(&p, false, 2, NONE) == 3);
	assert(tp_pick(&p, false, 3, NONE) == 3);
	assert(tp_pick(&p, true, 2, NONE) == 3);
	/* A retry goes only to another server in service: none. */
	assert(tp_pick(&p, false, 0, 1) == NONE);
	assert(tp_pick(&p, true, 0, 1) == NONE);
	/* One back by the time of the pick is taken in its turn. */
	p.clock += 700;
	assert(tp_pick(&p, false, 0, NONE) == 1);
	assert(p.nr_back == 1);
	tp_free(&p);

	/* A pool of one is never left without its server. */
	tp_init(&p, 1);
	tp_eject(&p, 0, 300);
	assert(tp_pick(&p, false, 3, NONE) == 0);
	assert(tp_pick(&p, true, 3, NONE) == 0);
	tp_free(&p);
}

/* A retry: the next server in service after the failed one, or none. */
static void test_pick_retry(void)
{
	struct tpool p;
	uint32_t rr;

	tp_init(&p, 3);
	tp_open(&p, 0, 1);
	tp_open(&p, 1, 1);
	for (rr = 0; rr < 6; rr++) {
		/* The cursor plays no part in a retry. */
		assert(tp_pick(&p, false, rr, 0) == 1);
		assert(tp_pick(&p, false, rr, 1) == 2);
		assert(tp_pick(&p, false, rr, 2) == 0);
		assert(tp_pick(&p, true, rr, 2) == 0);
		assert(tp_pick(&p, true, rr, 0) == 2);
	}
	/* least_conn: ties from the one after the failed one. */
	tp_open(&p, 2, 1);
	assert(tp_pick(&p, true, 0, 0) == 1);
	assert(tp_pick(&p, true, 0, 1) == 2);
	assert(tp_pick(&p, true, 0, 2) == 0);

	/* The next one is ejected: the one after it. */
	tp_eject(&p, 1, 50);
	assert(tp_pick(&p, false, 0, 0) == 2);
	assert(tp_pick(&p, true, 0, 0) == 2);
	/* The only other server is ejected: no retry, though it exists. */
	tp_eject(&p, 2, 40);
	assert(tp_pick(&p, false, 0, 2) == 0);
	assert(tp_pick(&p, false, 0, 0) == NONE);
	assert(tp_pick(&p, true, 9, 0) == NONE);
	/* A skip past the pool is no skip: a first pick. */
	assert(tp_pick(&p, false, 4, 3) == 0);
	tp_free(&p);

	/* Nor in a pool of one, ejected or not. */
	tp_init(&p, 1);
	assert(tp_pick(&p, false, 0, 0) == NONE);
	assert(tp_pick(&p, true, 0, 0) == NONE);
	tp_eject(&p, 0, 10);
	assert(tp_pick(&p, false, 0, 0) == NONE);
	tp_free(&p);
}

/* Servers with no state are never taken; no pool at all, no server. */
static void test_pick_missing(void)
{
	struct gwp_up_pick pk = { .now = tp_now };
	struct tpool p;

	assert(gwp_up_lb_pick(&pk) == NONE);
	tp_init(&p, 3);
	p.m[1].st = NULL;
	assert(tp_pick(&p, false, 1, NONE) == 2);
	assert(tp_pick(&p, true, 1, NONE) == 2);
	assert(tp_pick(&p, false, 1, 0) == 2);
	p.m[0].st = p.m[2].st = NULL;
	assert(tp_pick(&p, false, 1, NONE) == NONE);
	assert(tp_pick(&p, true, 1, NONE) == NONE);
	p.m[0].st = p.s[0];
	p.m[1].st = p.s[1];
	p.m[2].st = p.s[2];
	tp_free(&p);
}

/*
 * Round-robin's probes, driven by a fake random source: none while the
 * cursor's server is in service; on a miss the first probe that lands on a
 * server in service wins; probes landing on an ejected server, on the one
 * a retry skips or on a missing one go on to the next; GWP_UP_PICK_PROBES
 * misses fall back to the next in service from the cursor.
 */
static void test_pick_probe(void)
{
	uint32_t vals[GWP_UP_PICK_PROBES];
	struct tpool p;
	uint32_t n;

	assert(GWP_UP_PICK_PROBES == 4);
	tp_init(&p, 8);
	vals[0] = tp_at(8, 6);
	p.fake = vals;
	p.nr_fake = 1;
	p.ifake = 0;
	assert(tp_pick(&p, false, 2, NONE) == 2);
	assert(!p.nr_random);

	tp_eject(&p, 2, 100);
	tp_eject(&p, 5, 100);
	assert(tp_pick(&p, false, 2, NONE) == 6);
	assert(p.nr_random == 1);
	assert(tp_at(8, 0) == 0 && tp_at(8, 7) > tp_at(8, 6));

	/* Misses: ejected 5, the cursor's own 2, then 7 is in service. */
	vals[0] = tp_at(8, 5);
	vals[1] = tp_at(8, 2);
	vals[2] = tp_at(8, 7);
	p.nr_fake = 3;
	p.ifake = 0;
	n = p.nr_random;
	assert(tp_pick(&p, false, 10, NONE) == 7);
	assert(p.nr_random - n == 3);

	/* Every probe misses: the next in service after the cursor. */
	vals[0] = vals[1] = vals[2] = vals[3] = tp_at(8, 5);
	p.nr_fake = 4;
	p.ifake = 0;
	n = p.nr_random;
	assert(tp_pick(&p, false, 2, NONE) == 3);
	assert(p.nr_random - n == GWP_UP_PICK_PROBES);

	/* A retry: the one after the failed server, else probes, never it. */
	vals[0] = tp_at(8, 1);
	vals[1] = tp_at(8, 4);
	p.nr_fake = 2;
	p.ifake = 0;
	n = p.nr_random;
	assert(tp_pick(&p, false, 99, 0) == 1);
	assert(p.nr_random == n);
	assert(tp_pick(&p, false, 99, 1) == 4);
	vals[0] = vals[1] = tp_at(8, 0);
	p.ifake = 0;
	assert(tp_pick(&p, false, 99, 0) == 1);
	tp_eject(&p, 1, 100);
	p.ifake = 0;
	assert(tp_pick(&p, false, 99, 0) == 3);
	/* A missing state is a miss too. */
	vals[0] = tp_at(8, 6);
	vals[1] = tp_at(8, 4);
	p.ifake = 0;
	p.m[6].st = NULL;
	assert(tp_pick(&p, false, 2, NONE) == 4);
	p.m[6].st = p.s[6];

	/*
	 * least_conn: the start's server ejected, a probe moves where the
	 * ties start; with all tied (0 open) the probed one wins. All
	 * probes missing: the ties start at the cursor as before.
	 */
	vals[0] = tp_at(8, 5);
	vals[1] = tp_at(8, 6);
	p.nr_fake = 2;
	p.ifake = 0;
	n = p.nr_random;
	assert(tp_pick(&p, true, 2, NONE) == 6);
	assert(p.nr_random - n == 2);
	vals[0] = vals[1] = tp_at(8, 5);
	p.ifake = 0;
	assert(tp_pick(&p, true, 2, NONE) == 3);
	/* The fewest still wins wherever the ties start (1 is ejected). */
	tp_open(&p, 6, 1);
	tp_open(&p, 7, 1);
	tp_open(&p, 0, 1);
	tp_open(&p, 4, 1);
	vals[0] = tp_at(8, 6);
	p.ifake = 0;
	assert(tp_pick(&p, true, 2, NONE) == 3);
	tp_open(&p, 3, 1);
	p.ifake = 0;
	assert(tp_pick(&p, true, 2, NONE) == 6);
	/* With its start in service, least_conn draws nothing. */
	n = p.nr_random;
	assert(tp_pick(&p, true, 3, NONE) == 3);
	assert(p.nr_random == n);
	/* A retry: never the skipped one, wherever the ties start. */
	vals[0] = tp_at(8, 0);
	vals[1] = tp_at(8, 7);
	p.ifake = 0;
	assert(tp_pick(&p, true, 0, 0) == 7);
	for (n = 0; n < 8; n++)
		if (n != 2 && n != 5)
			tp_open(&p, n, 0);

	/* All ejected: probes all miss, the one back soonest as before. */
	tp_free(&p);
	tp_init(&p, 3);
	vals[0] = tp_at(3, 1);
	p.fake = vals;
	p.nr_fake = 1;
	p.ifake = 0;
	tp_eject(&p, 0, 300);
	tp_eject(&p, 1, 100);
	tp_eject(&p, 2, 200);
	assert(tp_pick(&p, false, 0, NONE) == 1);
	assert(tp_pick(&p, false, 0, 2) == NONE);
	tp_free(&p);
}

#define NR_DIST		10u
#define NR_DIST_PICKS	200000u

/*
 * With a real generator, the turns of ejected servers are spread evenly:
 * every server in service gets its equal share of the picks within 3%,
 * the one right after the ejected ones included (it would get k + 1 shares
 * if the turns went to the next in service). One ejected server, then a
 * run of 3 at the cursor's path. The share of a server in service is
 * NR_DIST_PICKS / in-service; the ejected turns (a tenth or three tenths)
 * are binomial over it, so 3% is several standard deviations wide.
 */
static void test_pick_spread(uint32_t first, uint32_t run, uint32_t seed)
{
	uint32_t hits[NR_DIST] = { 0 }, rr, i, want, tol;
	struct tpool p;

	tp_init(&p, NR_DIST);
	p.xs = seed;
	for (i = first; i < first + run; i++)
		tp_eject(&p, i, 1000);
	for (rr = 0; rr < NR_DIST_PICKS; rr++)
		hits[tp_pick(&p, false, rr, NONE)]++;
	want = NR_DIST_PICKS / (NR_DIST - run);
	tol = want * 3 / 100;
	for (i = 0; i < NR_DIST; i++) {
		if (i >= first && i < first + run) {
			assert(!hits[i]);
			continue;
		}
		if (hits[i] + tol < want || hits[i] > want + tol) {
			fprintf(stderr, "server %u: %u picks, want %u +- %u\n",
				i, hits[i], want, tol);
			assert(0);
		}
	}
	/* Each ejected turn took one or a few draws, never more than 4. */
	assert(p.nr_random >= run * (NR_DIST_PICKS / NR_DIST));
	assert(p.nr_random <= GWP_UP_PICK_PROBES * run *
			      (NR_DIST_PICKS / NR_DIST));
	tp_free(&p);
}

/*
 * test_pick_spread() for least_conn with every count tied (connections
 * short enough to have ended before the next pick): the ties' start
 * moves off an ejected server by the same probes, so each server in
 * service gets its equal share within 3%, the one after the run too.
 */
static void test_pick_spread_lc(uint32_t first, uint32_t run, uint32_t seed)
{
	uint32_t hits[NR_DIST] = { 0 }, rr, i, want, tol;
	struct tpool p;

	tp_init(&p, NR_DIST);
	p.xs = seed;
	for (i = first; i < first + run; i++)
		tp_eject(&p, i, 1000);
	for (rr = 0; rr < NR_DIST_PICKS; rr++)
		hits[tp_pick(&p, true, rr, NONE)]++;
	want = NR_DIST_PICKS / (NR_DIST - run);
	tol = want * 3 / 100;
	for (i = 0; i < NR_DIST; i++) {
		if (i >= first && i < first + run) {
			assert(!hits[i]);
			continue;
		}
		if (hits[i] + tol < want || hits[i] > want + tol) {
			fprintf(stderr, "least_conn server %u: %u picks, want %u +- %u\n",
				i, hits[i], want, tol);
			assert(0);
		}
	}
	tp_free(&p);
}

#define NR_BIG	8192u

/*
 * The largest pool: round-robin visits every server once per round, and
 * least_conn finds the one server with the fewest anywhere in it, also
 * the last, across the cursor's wrap; runs of ejected servers at the end
 * are stepped over to the start.
 */
static void test_pick_big(void)
{
	struct tpool p;
	uint32_t rr, i;

	tp_init(&p, NR_BIG);
	for (rr = 0; rr < 2 * NR_BIG; rr++)
		assert(tp_pick(&p, false, rr, NONE) == rr % NR_BIG);
	assert(tp_pick(&p, false, UINT32_MAX, NONE) == UINT32_MAX % NR_BIG);
	for (i = 0; i < NR_BIG; i++)
		tp_open(&p, i, 2);
	tp_open(&p, NR_BIG - 1, 1);
	assert(tp_pick(&p, true, 0, NONE) == NR_BIG - 1);
	assert(tp_pick(&p, true, NR_BIG - 1, NONE) == NR_BIG - 1);
	tp_open(&p, NR_BIG / 2, 1);
	assert(tp_pick(&p, true, NR_BIG - 1, NONE) == NR_BIG - 1);
	assert(tp_pick(&p, true, NR_BIG, NONE) == NR_BIG / 2);
	tp_open(&p, 0, 0);
	assert(tp_pick(&p, true, 7, NONE) == 0);
	assert(tp_pick(&p, true, 7, 0) == NR_BIG / 2);
	assert(!p.clock_reads);

	for (i = NR_BIG - 100; i < NR_BIG; i++)
		tp_eject(&p, i, 1000);
	assert(tp_pick(&p, false, NR_BIG - 100, NONE) == 0);
	assert(tp_pick(&p, false, 0, NR_BIG - 101) == 0);
	tp_open(&p, NR_BIG - 50, 0);
	assert(tp_pick(&p, true, NR_BIG - 60, NONE) == 0);
	tp_free(&p);
}

/* Give @p's servers the weights @w and plan the pool by them. */
static void tp_weights(struct tpool *p, const uint32_t *w)
{
	uint32_t i;

	for (i = 0; i < p->nr; i++)
		p->m[i].weight = (uint16_t)w[i];
	free(p->plan);
	p->plan = gwp_up_plan_build(p->m, p->nr);
	assert(p->plan && p->plan->nr == p->nr);
}

/*
 * Weighted round-robin: in any 2^b turns in a row from a multiple of 2^b,
 * with 2^b at least the weights' sum, each server gets its share within one
 * turn; and no server waits much longer than its share between turns.
 * Equal weights, whatever they are, are plain turns.
 */
static void test_weights(void)
{
	static const uint32_t w3[3] = { 5, 1, 1 }, eq[3] = { 7, 7, 7 };
	static const uint32_t w4[4] = { 1, 2, 3, 1000 };
	uint32_t hits[4], last[4], gap[4], rr, i, n;
	struct tpool p;

	tp_init(&p, 3);
	tp_weights(&p, eq);
	assert(!p.plan->tier[0].total);
	for (rr = 0; rr < 9; rr++)
		assert(tp_pick(&p, false, rr, NONE) == rr % 3);

	tp_weights(&p, w3);
	assert(p.plan->tier[0].total == 7);
	assert(p.plan->tier[0].cum[0] == 5 && p.plan->tier[0].cum[2] == 7);
	for (n = 8; n <= (1u << 16); n <<= 4) {
		memset(hits, 0, sizeof(hits));
		for (rr = 3 * n; rr < 4 * n; rr++)
			hits[tp_pick(&p, false, rr, NONE)]++;
		for (i = 0; i < 3; i++)
			assert(hits[i] * 7 + 7 >= n * w3[i] &&
			       hits[i] * 7 <= n * w3[i] + 7);
	}
	/* Across the cursor's wrap too. */
	memset(hits, 0, sizeof(hits));
	for (rr = 0u - 4096; rr != 4096; rr++)
		hits[tp_pick(&p, false, rr, NONE)]++;
	assert(hits[0] * 7 + 7 >= 8192 * 5 && hits[0] * 7 <= 8192 * 5 + 7);
	/* The light ones never wait for the heavy one's turns in a burst. */
	memset(last, 0, sizeof(last));
	memset(gap, 0, sizeof(gap));
	for (rr = 1; rr < 7000; rr++) {
		i = tp_pick(&p, false, rr, NONE);
		if (rr - last[i] > gap[i])
			gap[i] = rr - last[i];
		last[i] = rr;
	}
	assert(gap[0] <= 3 && gap[1] <= 3 * 7 && gap[2] <= 3 * 7);
	tp_free(&p);

	tp_init(&p, 4);
	tp_weights(&p, w4);
	memset(last, 0, sizeof(last));
	memset(gap, 0, sizeof(gap));
	memset(hits, 0, sizeof(hits));
	for (rr = 1; rr <= 1u << 14; rr++) {
		i = tp_pick(&p, false, rr, NONE);
		hits[i]++;
		if (rr - last[i] > gap[i])
			gap[i] = rr - last[i];
		last[i] = rr;
	}
	for (i = 0; i < 4; i++) {
		assert(hits[i] * 1006 + 1006 >= (1u << 14) * w4[i] &&
		       hits[i] * 1006 <= (1u << 14) * w4[i] + 2 * 1006);
		assert(gap[i] <= 3 * 1006 / w4[i] + 1);
	}

	/* A retry: the next in pool order, weights or not. */
	assert(tp_pick(&p, false, 5, 0) == 1);
	assert(tp_pick(&p, false, 5, 3) == 0);
	assert(tp_pick(&p, true, 5, 2) == 3);
	tp_free(&p);
}

/*
 * least_conn with weights: the fewest open for the weight, exactly; fed
 * back, the open counts follow the weights.
 */
static void test_weights_least_conn(void)
{
	static const uint32_t w[3] = { 1, 3, 2 };
	struct tpool p;
	uint32_t rr;

	tp_init(&p, 3);
	tp_weights(&p, w);
	tp_open(&p, 0, 1);
	tp_open(&p, 1, 2);
	tp_open(&p, 2, 1);
	/* 2/3 < 1/2 < 1/1. */
	assert(tp_pick(&p, true, 0, NONE) == 2);
	tp_open(&p, 2, 2);
	assert(tp_pick(&p, true, 0, NONE) == 1);
	/* 3/3 = 2/2 = 1/1: ties from the cursor's turn on. */
	tp_open(&p, 1, 3);
	for (rr = 0; rr < 64; rr++) {
		uint32_t t = tp_pick(&p, false, rr, NONE);

		assert(tp_pick(&p, true, rr, NONE) == t);
	}
	/* An idle one wins at once, whatever its weight. */
	tp_open(&p, 0, 0);
	assert(tp_pick(&p, true, 1, NONE) == 0);

	for (rr = 0; rr < 3; rr++)
		tp_open(&p, rr, 0);
	for (rr = 0; rr < 600; rr++)
		gwp_up_state_take(p.s[tp_pick(&p, true, rr, NONE)]);
	assert(gwp_up_state_open(p.s[0]) == 100);
	assert(gwp_up_state_open(p.s[1]) == 300);
	assert(gwp_up_state_open(p.s[2]) == 200);
	tp_free(&p);
}

/*
 * An ejected server's turns in a weighted pool go to the others by their
 * weights: the probes draw by weight. (Its turns that all probes miss go
 * to the next in pool order, (2/10)^4 of them here.)
 */
static void test_weights_spread(void)
{
	static const uint32_t w[4] = { 1, 2, 3, 4 };
	uint32_t hits[4] = { 0 }, rr, i, want, tol;
	struct tpool p;

	tp_init(&p, 4);
	tp_weights(&p, w);
	p.xs = 31337;
	tp_eject(&p, 1, 1000);
	for (rr = 0; rr < NR_DIST_PICKS; rr++)
		hits[tp_pick(&p, false, rr, NONE)]++;
	assert(!hits[1]);
	for (i = 0; i < 4; i++) {
		if (i == 1)
			continue;
		want = NR_DIST_PICKS / 8 * w[i];
		tol = want * 3 / 100;
		if (hits[i] + tol < want || hits[i] > want + tol) {
			fprintf(stderr, "weighted server %u: %u picks, want %u +- %u\n",
				i, hits[i], want, tol);
			assert(0);
		}
	}
	tp_free(&p);
}

/*
 * The largest pool, weighted: in 2^23 turns each server gets its share
 * within a turn, the pick a binary search away.
 */
static void test_weights_big(void)
{
	static uint32_t w[NR_BIG], hits[NR_BIG];
	struct gwp_up_pick pk;
	struct tpool p;
	uint64_t total = 0;
	uint32_t rr, i;

	tp_init(&p, NR_BIG);
	for (i = 0; i < NR_BIG; i++) {
		w[i] = i % GWP_UP_MAX_WEIGHT + 1;
		total += w[i];
	}
	tp_weights(&p, w);
	assert(p.plan->tier[0].total == total);
	memset(&pk, 0, sizeof(pk));
	pk.m = p.m;
	pk.nr = p.nr;
	pk.plan = p.plan;
	pk.skip = NONE;
	pk.now = tp_now;
	pk.arg = &p;
	for (rr = 0; rr < 1u << 23; rr++) {
		pk.rr = rr;
		hits[gwp_up_lb_pick(&pk)]++;
	}
	for (i = 0; i < NR_BIG; i++) {
		uint64_t share = (uint64_t)w[i] << 23;

		assert((uint64_t)hits[i] * total + total >= share &&
		       (uint64_t)hits[i] * total <= share + total);
	}
	tp_free(&p);
}

/*
 * max_conns: a server with as many pairs open as its cap is full, and
 * passed over like an ejected one, by round-robin (probes included) and
 * least_conn alike; with every server full, or full and ejected, none is
 * taken, while ejected ones that are not full still stand in as before.
 */
static void test_max_conns(void)
{
	uint32_t vals[1];
	struct tpool p;
	uint32_t rr;

	tp_init(&p, 4);
	p.m[1].max_conns = 2;
	tp_open(&p, 1, 1);
	assert(tp_pick(&p, false, 1, NONE) == 1);
	tp_open(&p, 1, 2);
	assert(tp_pick(&p, false, 1, NONE) == 2);
	assert(tp_pick(&p, false, 0, 0) == 2);
	/* A probe that lands on it misses. */
	vals[0] = tp_at(4, 1);
	p.fake = vals;
	p.nr_fake = 1;
	assert(tp_pick(&p, false, 1, NONE) == 2);
	assert(p.nr_random == GWP_UP_PICK_PROBES);
	vals[0] = tp_at(4, 3);
	assert(tp_pick(&p, false, 1, NONE) == 3);
	p.fake = NULL;
	/* least_conn: its 2 are the fewest, but it is full. */
	tp_open(&p, 0, 5);
	tp_open(&p, 2, 3);
	tp_open(&p, 3, 4);
	assert(tp_pick(&p, true, 1, NONE) == 2);
	/* Over its cap (a cap lowered by a reload): still full. */
	tp_open(&p, 1, 3);
	assert(tp_pick(&p, true, 1, NONE) == 2);
	assert(tp_pick(&p, false, 1, NONE) == 2);
	tp_open(&p, 1, 1);
	assert(tp_pick(&p, true, 1, NONE) == 1);

	/* All full: none, for a first pick and a retry. */
	for (rr = 0; rr < 4; rr++) {
		p.m[rr].max_conns = 1;
		tp_open(&p, rr, 1);
	}
	assert(tp_pick(&p, false, 0, NONE) == NONE);
	assert(tp_pick(&p, true, 0, NONE) == NONE);
	assert(tp_pick(&p, false, 0, 2) == NONE);
	/* Full or ejected: the ejected one with room stands in. */
	tp_open(&p, 2, 0);
	tp_eject(&p, 2, 100);
	assert(tp_pick(&p, false, 0, NONE) == 2);
	assert(tp_pick(&p, true, 0, NONE) == 2);
	/* Ejected and full: none again. */
	tp_open(&p, 2, 1);
	assert(tp_pick(&p, false, 0, NONE) == NONE);
	/* A cap of 0 is none. */
	p.m[3].max_conns = 0;
	assert(tp_pick(&p, false, 0, NONE) == 3);
	tp_free(&p);
}

/* Give @p's servers the flags @f and plan the pool by them. */
static void tp_flags(struct tpool *p, const uint8_t *f)
{
	uint32_t i;

	for (i = 0; i < p->nr; i++)
		p->m[i].flags = f[i];
	free(p->plan);
	p->plan = gwp_up_plan_build(p->m, p->nr);
	assert(p->plan && p->plan->nr == p->nr);
}

/*
 * backup and down: the tiers the plan makes of them, the backups taken
 * only when no main server may be, by either method and on a retry, down
 * servers never; with everything out, the main server back soonest, a
 * backup only when no main server stands.
 */
static void test_backup_down(void)
{
	static const uint8_t f[5] = {
		0, GWP_UP_MEMBER_BACKUP, GWP_UP_MEMBER_DOWN, 0,
		GWP_UP_MEMBER_BACKUP,
	};
	uint32_t hits[5] = { 0 }, rr, i;
	struct tpool p;

	tp_init(&p, 5);
	tp_flags(&p, f);
	assert(p.plan->tier[0].n == 2 && p.plan->tier[1].n == 2);
	assert(p.plan->tier[0].idx[0] == 0 && p.plan->tier[0].idx[1] == 3);
	assert(p.plan->tier[1].idx[0] == 1 && p.plan->tier[1].idx[1] == 4);
	assert(p.plan->pos[3] == 1 && p.plan->pos[4] == 1 &&
	       p.plan->pos[2] == UINT16_MAX);
	assert(!p.plan->tier[0].total && !p.plan->tier[1].total);

	/* The main servers in turn; the others idle, least_conn too. */
	for (rr = 0; rr < 8; rr++)
		hits[tp_pick(&p, false, rr, NONE)]++;
	assert(hits[0] == 4 && hits[3] == 4);
	tp_open(&p, 0, 3);
	tp_open(&p, 3, 3);
	assert(tp_pick(&p, true, 0, NONE) == 0);
	assert(tp_pick(&p, true, 1, NONE) == 3);
	/* A retry goes to the other main server. */
	assert(tp_pick(&p, false, 7, 0) == 3);
	assert(tp_pick(&p, false, 7, 3) == 0);

	/* One main server out: the other takes all. */
	tp_eject(&p, 0, 500);
	for (rr = 0; rr < 4; rr++)
		assert(tp_pick(&p, false, rr, NONE) == 3);
	assert(tp_pick(&p, false, 0, 3) == 1);
	/* Both out (one full): the backups, in turn; least_conn's fewest. */
	p.m[3].max_conns = 3;
	for (rr = 0; rr < 4; rr++)
		assert(tp_pick(&p, false, rr, NONE) == (rr % 2 ? 4 : 1));
	tp_open(&p, 1, 2);
	assert(tp_pick(&p, true, 0, NONE) == 4);
	/* A backup that fails: the other backup. */
	assert(tp_pick(&p, false, 0, 4) == 1);
	assert(tp_pick(&p, true, 0, 1) == 4);

	/* Everything out: the main server back soonest, not a backup. */
	tp_eject(&p, 1, 100);
	tp_eject(&p, 4, 100);
	assert(tp_pick(&p, false, 0, NONE) == 0);
	assert(tp_pick(&p, false, 0, 0) == NONE);
	/* The main ones full too: a backup, ties in turn. */
	p.m[0].max_conns = 3;
	assert(tp_pick(&p, false, 0, NONE) == 1);
	assert(tp_pick(&p, false, 1, NONE) == 4);
	assert(tp_pick(&p, true, 1, NONE) == 4);
	/* Down is never taken, even then. */
	for (i = 0; i < 5; i++)
		assert(tp_pick(&p, false, i, NONE) != 2);
	tp_free(&p);

	/* Every server down: nothing to pick. */
	tp_init(&p, 2);
	p.m[0].flags = p.m[1].flags = GWP_UP_MEMBER_DOWN;
	p.plan = gwp_up_plan_build(p.m, p.nr);
	assert(p.plan && !p.plan->tier[0].n && !p.plan->tier[1].n);
	assert(tp_pick(&p, false, 0, NONE) == NONE);
	assert(tp_pick(&p, true, 0, NONE) == NONE);
	tp_free(&p);
}

/* Weights in each tier on their own: the backups' turns by theirs. */
static void test_backup_weights(void)
{
	static const uint8_t f[5] = {
		GWP_UP_MEMBER_BACKUP, 0, GWP_UP_MEMBER_BACKUP, 0,
		GWP_UP_MEMBER_DOWN,
	};
	static const uint32_t w[5] = { 1, 1, 3, 1, 9 };
	uint32_t hits[5] = { 0 }, rr;
	struct tpool p;

	tp_init(&p, 5);
	for (rr = 0; rr < 5; rr++)
		p.m[rr].flags = f[rr];
	tp_weights(&p, w);
	assert(!p.plan->tier[0].total && p.plan->tier[1].total == 4);
	for (rr = 0; rr < 16; rr++)
		hits[tp_pick(&p, false, rr, NONE)]++;
	assert(hits[1] == 8 && hits[3] == 8);
	tp_eject(&p, 1, 100);
	tp_eject(&p, 3, 100);
	memset(hits, 0, sizeof(hits));
	for (rr = 0; rr < 16; rr++)
		hits[tp_pick(&p, false, rr, NONE)]++;
	assert(hits[0] == 4 && hits[2] == 12 && !hits[4]);
	tp_free(&p);
}

/* The slow start's ejection state, by its settings. */
static struct gwp_up_health *slow_of(struct gwp_up_state *s, uint32_t fails,
				     uint32_t eject, uint32_t slow)
{
	struct gwp_up_opts o;
	struct gwp_up_health *h;

	gwp_up_opts_default(&o);
	o.max_fails = fails;
	o.fail_timeout_ms = 1000;
	o.eject_ms = eject;
	o.slow_start_ms = slow;
	h = gwp_up_health_get(s, &o);
	assert(h && h->st == s);
	return h;
}

/*
 * The ramp of the slow start, on an injected clock from @t0: none at a
 * first load or with no slow_start, linear from a join that no other pool
 * already made; from the end of an ejection, which restarts it; its own
 * state per slow_start; with max_fails=0 it ramps but is never ejected.
 */
static void test_slow_ramp(uint32_t t0)
{
	struct gwp_up_key k = key_of(GWP_UP_SCHEME_SOCKS5H, "10.0.0.9", 1080,
				     NULL);
	struct gwp_up_table *t = gwp_up_table_create();
	struct gwp_up_health *h, *h2, *z, *d;
	const uint32_t one = GWP_UP_RAMP_ONE;
	struct gwp_up_state *s;
	uint32_t i;

	assert(t);
	s = gwp_up_state_get(t, &k);
	assert(s);
	h = slow_of(s, 1, 5000, 10000);
	d = def_health(s);
	assert(h != d && h->slow_ms == 10000 && !d->slow_ms);
	h2 = slow_of(s, 1, 5000, 10000);
	assert(h2 == h);
	gwp_up_health_put(h2);
	z = slow_of(s, 0, 5000, 10000);
	assert(z != h);

	/* Nothing yet: full weight, no clock needed. */
	assert(!gwp_up_health_may_ramp(h));
	assert(gwp_up_health_ramp(h, t0) == one);
	assert(gwp_up_health_ramp(NULL, t0) == one);
	assert(!gwp_up_health_join(NULL, t0));

	/* A first load: no ramp; nor without slow_start. */
	assert(!gwp_up_health_join(h, 0));
	assert(!gwp_up_health_may_ramp(h));
	assert(!gwp_up_health_join(d, t0));
	assert(!gwp_up_health_may_ramp(d));
	gwp_up_health_leave(d);
	/* Joined by one pool already: another one changes nothing. */
	assert(!gwp_up_health_join(h, t0));
	assert(!gwp_up_health_may_ramp(h));
	gwp_up_health_leave(h);
	gwp_up_health_leave(h);

	/* A reload brings it in: linear over 10 s, at least 1. */
	assert(gwp_up_health_join(h, t0));
	assert(gwp_up_health_may_ramp(h));
	assert(gwp_up_health_ramp(h, t0) == 1);
	assert(gwp_up_health_ramp(h, t0 + 1) == one / 10000);
	assert(gwp_up_health_ramp(h, t0 + 2500) == one / 4);
	assert(gwp_up_health_ramp(h, t0 + 5000) == one / 2);
	assert(gwp_up_health_ramp(h, t0 + 9999) == one - one / 10000 - 1);
	/* A clock a little behind (another worker's): the least. */
	assert(gwp_up_health_ramp(h, t0 - 5) == 1);
	/* A second pool joining meanwhile leaves the ramp as it is. */
	assert(!gwp_up_health_join(h, t0 + 5000));
	assert(gwp_up_health_ramp(h, t0 + 5000) == one / 2);
	gwp_up_health_leave(h);
	/* Over: ended, the cheap test says so again. */
	assert(gwp_up_health_ramp(h, t0 + 10000) == one);
	assert(!gwp_up_health_may_ramp(h));
	assert(gwp_up_health_ramp(h, t0 + 5000) == one);
	gwp_up_health_leave(h);

	/* Left by every pool, then back: a ramp again. */
	assert(gwp_up_health_join(h, t0 + 20000));
	assert(gwp_up_health_ramp(h, t0 + 25000) == one / 2);
	/* An ejection mid-ramp: out, then the ramp again from its end. */
	assert(fail(h, t0 + 25000));
	assert(gwp_up_health_ejected(h, t0 + 26000, NULL) == 4000);
	assert(gwp_up_health_ramp(h, t0 + 26000) == 1);
	assert(gwp_up_health_ramp(h, t0 + 30000) == 1);
	assert(!gwp_up_health_ejected(h, t0 + 30000, NULL));
	assert(gwp_up_health_ramp(h, t0 + 32500) == one / 4);
	/* Ejected again during it: from the end of that one. */
	assert(fail(h, t0 + 32500));
	assert(gwp_up_health_ramp(h, t0 + 37500) == 1);
	assert(gwp_up_health_ramp(h, t0 + 42500) == one / 2);
	assert(gwp_up_health_ramp(h, t0 + 47500) == one);
	/* An ended ramp read late: still over, not wrapped. */
	assert(!gwp_up_health_may_ramp(h));
	gwp_up_health_leave(h);

	/*
	 * A ramp ended but never looked at since does not keep the next
	 * join from starting one.
	 */
	assert(gwp_up_health_join(h, t0 + 50000));
	gwp_up_health_leave(h);
	assert(gwp_up_health_may_ramp(h));
	assert(gwp_up_health_join(h, t0 + 70000));
	assert(gwp_up_health_ramp(h, t0 + 75000) == one / 2);
	gwp_up_health_leave(h);

	/* max_fails=0: a ramp on joining, never an ejection. */
	assert(gwp_up_health_join(z, t0));
	for (i = 0; i < 5; i++)
		assert(!fail(z, t0 + i));
	assert(!gwp_up_health_may_be_ejected(z));
	assert(gwp_up_health_ramp(z, t0 + 5000) == one / 2);
	gwp_up_health_leave(z);

	gwp_up_health_put(z);
	gwp_up_health_put(d);
	gwp_up_health_put(h);
	gwp_up_state_put(s);
	assert(gwp_up_table_destroy(t) == 0);
}

/*
 * Give @p's server @i the slow start @slow (with the default ejection),
 * at the fraction @num / @den of it, from a join at the right time.
 */
static void tp_ramp(struct tpool *p, uint32_t i, uint32_t slow, uint32_t num,
		    uint32_t den)
{
	gwp_up_health_put(p->h[i]);
	p->h[i] = slow_of(p->s[i], GWP_UP_EJECT_FAILS, GWP_UP_EJECT_MS, slow);
	p->m[i].h = p->h[i];
	assert(gwp_up_health_join(p->h[i], p->clock - slow / den * num));
	assert(gwp_up_health_ramp(p->h[i], p->clock) ==
	       (uint32_t)((uint64_t)GWP_UP_RAMP_ONE * num / den));
}

/* Undo tp_ramp(): back to the default health. */
static void tp_unramp(struct tpool *p, uint32_t i)
{
	gwp_up_health_leave(p->h[i]);
	gwp_up_health_put(p->h[i]);
	p->h[i] = def_health(p->s[i]);
	p->m[i].h = p->h[i];
}

/*
 * Round-robin with a server in its slow start, by a real generator: each
 * server gets the share of its weight scaled by its ramp, within 3%. The
 * ramping server's own turns are taken by chance, and those it lets pass
 * go by the probes, which accept one in a slow start by chance too. The
 * probes are bounded: the turns that every probe lets pass (the chance of
 * a pass to the power GWP_UP_PICK_PROBES + 1, a tenth of a percent here)
 * go to a server in no slow start.
 */
static void test_slow_rr(const uint32_t *w, const uint32_t *num, uint32_t nr,
			 uint32_t seed)
{
	uint32_t hits[8] = { 0 }, rr, i;
	uint64_t sum = 0, sw[8];
	struct tpool p;

	assert(nr <= 8);
	tp_init(&p, nr);
	p.xs = seed;
	if (w)
		tp_weights(&p, w);
	for (i = 0; i < nr; i++) {
		if (num[i] < 8)
			tp_ramp(&p, i, 80000, num[i], 8);
		sw[i] = (uint64_t)(w ? w[i] : 1) * num[i];
		sum += sw[i];
	}
	for (rr = 0; rr < NR_DIST_PICKS; rr++)
		hits[tp_pick(&p, false, rr, NONE)]++;
	for (i = 0; i < nr; i++) {
		uint64_t want = NR_DIST_PICKS * sw[i] / sum;
		uint64_t tol = NR_DIST_PICKS * 3 / 100;

		if (hits[i] + tol < want || hits[i] > want + tol) {
			fprintf(stderr, "slow rr server %u: %u picks, want %llu +- %llu\n",
				i, hits[i], (unsigned long long)want,
				(unsigned long long)tol);
			assert(0);
		}
		if (num[i] < 8)
			tp_unramp(&p, i);
	}
	tp_free(&p);
}

/*
 * The slow start in the picks, one at a time: a ramping server's turn
 * taken or passed by the random number; one passed and every probe
 * missing goes to the next one in service in no slow start, and with every
 * server in one, to the first in service; least_conn counts a ramping
 * server's open pairs against its scaled weight, exactly; with no random
 * source, round-robin ignores the ramp; the clock is read once.
 */
static void test_slow_pick(void)
{
	uint32_t vals[2 * GWP_UP_PICK_PROBES + 1];
	struct tpool p;
	uint32_t i, n;

	tp_init(&p, 4);
	/* Server 1 at a quarter of its weight. */
	tp_ramp(&p, 1, 40000, 1, 4);
	/* No random source: its turns as usual. */
	assert(tp_pick(&p, false, 1, NONE) == 1);
	p.fake = vals;
	/* A number under a quarter takes the turn, over it lets it pass. */
	vals[0] = 0x3fff0000u;
	p.nr_fake = 1;
	p.ifake = 0;
	n = p.nr_random;
	assert(tp_pick(&p, false, 1, NONE) == 1);
	assert(p.nr_random - n == 1);
	/* Passed, then a probe on 3, in service. */
	vals[0] = 0x40000000u;
	vals[1] = tp_at(4, 3);
	p.nr_fake = 2;
	p.ifake = 0;
	assert(tp_pick(&p, false, 1, NONE) == 3);
	/* The others' turns draw nothing. */
	n = p.nr_random;
	assert(tp_pick(&p, false, 2, NONE) == 2);
	assert(p.nr_random == n);
	/* Passed, every probe back on 1 and passed: the next, 2. */
	vals[0] = 0xffffffffu;
	for (i = 0; i < GWP_UP_PICK_PROBES; i++) {
		vals[1 + 2 * i] = tp_at(4, 1);
		vals[2 + 2 * i] = 0xffffffffu;
	}
	p.nr_fake = 2 * GWP_UP_PICK_PROBES + 1;
	p.ifake = 0;
	n = p.nr_random;
	assert(tp_pick(&p, false, 1, NONE) == 2);
	assert(p.nr_random - n == 2 * GWP_UP_PICK_PROBES + 1);
	/* Every server ramping: the first in service from the turn on. */
	tp_ramp(&p, 0, 40000, 1, 4);
	tp_ramp(&p, 2, 40000, 1, 4);
	tp_ramp(&p, 3, 40000, 1, 4);
	for (i = 0; i < GWP_UP_PICK_PROBES; i++)
		vals[1 + 2 * i] = tp_at(4, i);
	p.ifake = 0;
	assert(tp_pick(&p, false, 1, NONE) == 1);
	/* ... one that may be taken: 1 ejected, then 2. */
	tp_unramp(&p, 1);
	tp_eject(&p, 1, 100);
	vals[0] = tp_at(4, 1);
	for (i = 0; i < GWP_UP_PICK_PROBES; i++) {
		vals[2 * i + 1] = 0xffffffffu;
		vals[2 * i + 2] = tp_at(4, 1);
	}
	p.ifake = 0;
	p.clock_reads = 0;
	assert(tp_pick(&p, false, 1, NONE) == 2);
	assert(p.clock_reads == 1);
	for (i = 0; i < 4; i++)
		if (i != 1)
			tp_unramp(&p, i);
	tp_free(&p);

	/*
	 * least_conn: 10 open on 0 to 2; 3 has 2 open at an eighth of its
	 * weight (16 for its weight), so it is the busiest; at a quarter (8)
	 * the least busy; at its full weight it would be from the start.
	 */
	tp_init(&p, 4);
	for (i = 0; i < 3; i++)
		tp_open(&p, i, 10);
	tp_open(&p, 3, 2);
	assert(tp_pick(&p, true, 1, NONE) == 3);
	tp_ramp(&p, 3, 80000, 1, 8);
	assert(tp_pick(&p, true, 1, NONE) == 1);
	assert(tp_pick(&p, true, 3, NONE) == 0);
	tp_unramp(&p, 3);
	tp_ramp(&p, 3, 80000, 2, 8);
	assert(tp_pick(&p, true, 1, NONE) == 3);
	/* Exactly: 2 at a quarter (8 for its weight) ties 8, from the cursor. */
	for (i = 0; i < 3; i++)
		tp_open(&p, i, 8);
	tp_unramp(&p, 3);
	tp_ramp(&p, 3, 80000, 2, 8);
	assert(tp_pick(&p, true, 1, NONE) == 1);
	assert(tp_pick(&p, true, 3, NONE) == 3);
	/* Idle, it ties the idle ones in turn. */
	tp_open(&p, 3, 0);
	tp_open(&p, 2, 0);
	assert(tp_pick(&p, true, 2, NONE) == 2);
	assert(tp_pick(&p, true, 3, NONE) == 3);
	tp_unramp(&p, 3);
	/* With weights: 3 open on weight 3 at half (2 per unit) vs 2 on 1. */
	{
		static const uint32_t w[4] = { 1, 1, 1, 3 };

		tp_weights(&p, w);
		tp_open(&p, 0, 2);
		tp_open(&p, 1, 2);
		tp_open(&p, 2, 2);
		tp_open(&p, 3, 3);
		assert(tp_pick(&p, true, 0, NONE) == 3);
		tp_ramp(&p, 3, 80000, 4, 8);
		assert(tp_pick(&p, true, 0, NONE) == 0);
		assert(tp_pick(&p, true, 3, NONE) == 3);
		tp_open(&p, 3, 4);
		assert(tp_pick(&p, true, 3, NONE) == 0);
		tp_unramp(&p, 3);
	}
	tp_free(&p);
}

#define RND	GWP_UP_METHOD_RANDOM
#define RND2	GWP_UP_METHOD_RANDOM_TWO

/*
 * "random" by a real generator: each server in service gets the share of
 * its weight (scaled by a slow start's ramp) within 3%; servers ejected,
 * full or down are never taken; the cursor makes no difference.
 */
static void test_random_spread(const uint32_t *w, uint32_t nr, uint32_t seed,
			       uint32_t eject, uint32_t full, uint32_t ramp)
{
	uint32_t hits[8] = { 0 }, rr, i;
	uint64_t sum = 0, sw[8];
	struct tpool p;

	assert(nr <= 8);
	tp_init(&p, nr);
	p.xs = seed;
	if (w)
		tp_weights(&p, w);
	if (eject < nr)
		tp_eject(&p, eject, 1000);
	if (full < nr) {
		p.m[full].max_conns = 2;
		tp_open(&p, full, 2);
	}
	if (ramp < nr)
		tp_ramp(&p, ramp, 80000, 4, 8);
	for (i = 0; i < nr; i++) {
		sw[i] = i == eject || i == full ? 0 :
			(uint64_t)(w ? w[i] : 1) * (i == ramp ? 4 : 8);
		sum += sw[i];
	}
	for (rr = 0; rr < NR_DIST_PICKS; rr++)
		hits[tp_pick(&p, RND, rr * 7919, NONE)]++;
	for (i = 0; i < nr; i++) {
		uint64_t want = NR_DIST_PICKS * sw[i] / sum;
		uint64_t tol = NR_DIST_PICKS * 3 / 100;

		if (!sw[i]) {
			assert(!hits[i]);
			continue;
		}
		if (hits[i] + tol < want || hits[i] > want + tol) {
			fprintf(stderr, "random server %u: %u picks, want %llu +- %llu\n",
				i, hits[i], (unsigned long long)want,
				(unsigned long long)tol);
			assert(0);
		}
	}
	if (ramp < nr)
		tp_unramp(&p, ramp);
	tp_open(&p, full < nr ? full : 0, 0);
	tp_free(&p);
}

/*
 * "random" and "random two" one pick at a time, by a fake random source:
 * the draws, the better of two, ties to the first, the same server or one
 * that cannot be taken drawn again, the budget of draws and the fallback,
 * a retry, the backups.
 */
static void test_random_pick(void)
{
	uint32_t vals[GWP_UP_PICK_MAX_RANDOM];
	static const uint32_t w[4] = { 1, 1, 1, 3 };
	static const uint8_t f[5] = { 0, 0, 0, GWP_UP_MEMBER_BACKUP,
				      GWP_UP_MEMBER_BACKUP };
	struct tpool p;
	uint32_t i, n;

	tp_init(&p, 4);
	p.fake = vals;

	/* random: the one drawn, whatever the counts and the cursor. */
	vals[0] = tp_at(4, 2);
	p.nr_fake = 1;
	tp_open(&p, 2, 9);
	for (i = 0; i < 3; i++) {
		p.ifake = 0;
		n = p.nr_random;
		assert(tp_pick(&p, RND, i * 1000, NONE) == 2);
		assert(p.nr_random - n == 1);
	}
	/* random two: the fewer open of the two drawn; ties to the first. */
	vals[0] = tp_at(4, 2);
	vals[1] = tp_at(4, 1);
	p.nr_fake = 2;
	p.ifake = 0;
	assert(tp_pick(&p, RND2, 0, NONE) == 1);
	assert(p.nr_random == 5);
	tp_open(&p, 1, 9);
	p.ifake = 0;
	assert(tp_pick(&p, RND2, 0, NONE) == 2);
	tp_open(&p, 1, 10);
	p.ifake = 0;
	assert(tp_pick(&p, RND2, 0, NONE) == 2);
	/* The same one twice: drawn again. */
	vals[0] = vals[1] = tp_at(4, 1);
	vals[2] = tp_at(4, 3);
	p.nr_fake = 3;
	p.ifake = 0;
	n = p.nr_random;
	assert(tp_pick(&p, RND2, 0, NONE) == 3);
	assert(p.nr_random - n == 3);
	/* One that cannot be taken (ejected, full): drawn again. */
	tp_eject(&p, 3, 100);
	p.m[0].max_conns = 1;
	tp_open(&p, 0, 1);
	vals[0] = tp_at(4, 3);
	vals[1] = tp_at(4, 0);
	vals[2] = tp_at(4, 2);
	p.ifake = 0;
	assert(tp_pick(&p, RND, 0, NONE) == 2);
	vals[3] = tp_at(4, 1);
	p.nr_fake = 4;
	p.ifake = 0;
	assert(tp_pick(&p, RND2, 0, NONE) == 2);
	/*
	 * With weights: 10 open on weight 3 are fewer per weight than 9 on
	 * 1, more than 2 on 1.
	 */
	p.m[0].max_conns = 0;
	tp_weights(&p, w);
	vals[0] = tp_at(6, 0);		/* by weight: 0 1 2 3 3 3 */
	vals[1] = tp_at(6, 1);
	p.nr_fake = 2;
	p.ifake = 0;
	assert(tp_pick(&p, RND2, 0, NONE) == 0);
	p.ifake = 0;
	tp_open(&p, 0, 0);
	tp_open(&p, 2, 2);
	assert(tp_pick(&p, RND2, 0, NONE) == 0);
	gwp_up_health_ejected(p.h[3], p.clock + 100, NULL);
	tp_open(&p, 3, 10);
	tp_open(&p, 1, 9);
	vals[0] = tp_at(6, 1);
	vals[1] = tp_at(6, 4);
	p.ifake = 0;
	assert(tp_pick(&p, RND2, 0, NONE) == 3);
	vals[0] = tp_at(6, 2);
	p.ifake = 0;
	assert(tp_pick(&p, RND2, 0, NONE) == 2);
	tp_free(&p);

	/*
	 * The budget: two draws and GWP_UP_PICK_PROBES more. Every one on
	 * a server out: the next in service from the first one drawn; one
	 * good one for random two: that one.
	 */
	tp_init(&p, 6);
	p.fake = vals;
	tp_eject(&p, 1, 100);
	tp_eject(&p, 2, 100);
	tp_eject(&p, 4, 100);
	for (i = 0; i < 2 + GWP_UP_PICK_PROBES; i++)
		vals[i] = tp_at(6, i % 2 ? 2 : 1);
	p.nr_fake = 2 + GWP_UP_PICK_PROBES;
	p.ifake = 0;
	n = p.nr_random;
	assert(tp_pick(&p, RND2, 0, NONE) == 3);
	assert(p.nr_random - n == 2 + GWP_UP_PICK_PROBES);
	p.ifake = 0;
	n = p.nr_random;
	assert(tp_pick(&p, RND, 4, NONE) == 3);
	assert(p.nr_random - n == 1 + GWP_UP_PICK_PROBES);
	vals[0] = tp_at(6, 4);
	p.ifake = 0;
	assert(tp_pick(&p, RND, 0, NONE) == 5);
	vals[3] = tp_at(6, 0);
	p.ifake = 0;
	assert(tp_pick(&p, RND2, 0, NONE) == 0);
	/* The fallback prefers a server in no slow start. */
	tp_ramp(&p, 5, 80000, 1, 8);
	for (i = 0; i < 2 + GWP_UP_PICK_PROBES; i++)
		vals[i] = tp_at(6, 4);
	p.ifake = 0;
	assert(tp_pick(&p, RND, 0, NONE) == 0);
	tp_unramp(&p, 5);
	/* A server in its slow start, drawn, passed by its chance. */
	tp_ramp(&p, 0, 80000, 2, 8);
	vals[0] = tp_at(6, 0);
	vals[1] = 0x40000000u;		/* over a quarter: passed */
	vals[2] = tp_at(6, 0);
	vals[3] = 0x3fff0000u;		/* under it: taken */
	p.nr_fake = 4;
	p.ifake = 0;
	n = p.nr_random;
	assert(tp_pick(&p, RND, 0, NONE) == 0);
	assert(p.nr_random - n == 4);
	/* random two: compared at its scaled weight, 1 open as 4. */
	tp_open(&p, 0, 1);
	tp_open(&p, 3, 3);
	vals[0] = tp_at(6, 3);
	vals[1] = tp_at(6, 0);
	vals[2] = 0;
	p.nr_fake = 3;
	p.ifake = 0;
	assert(tp_pick(&p, RND2, 0, NONE) == 3);
	tp_open(&p, 3, 4);
	p.ifake = 0;
	assert(tp_pick(&p, RND2, 0, NONE) == 3);
	tp_open(&p, 3, 5);
	p.ifake = 0;
	assert(tp_pick(&p, RND2, 0, NONE) == 0);
	tp_unramp(&p, 0);
	tp_open(&p, 0, 0);
	tp_open(&p, 3, 0);

	/* A retry: never the failed one, though drawn. */
	vals[0] = tp_at(6, 3);
	vals[1] = tp_at(6, 5);
	p.nr_fake = 2;
	p.ifake = 0;
	assert(tp_pick(&p, RND, 0, 3) == 5);
	p.ifake = 0;
	assert(tp_pick(&p, RND2, 0, 3) == 5);
	/* Drawn every time: the next in service after it. */
	p.nr_fake = 1;
	p.ifake = 0;
	assert(tp_pick(&p, RND, 0, 3) == 5);
	/* One other drawn, every time: that one. */
	p.ifake = 0;
	assert(tp_pick(&p, RND2, 0, 5) == 3);
	/* With every other one out: none for a retry. */
	tp_eject(&p, 0, 100);
	tp_eject(&p, 5, 100);
	p.ifake = 0;
	assert(tp_pick(&p, RND2, 0, 3) == NONE);
	/* For a first pick, all out: the one back soonest, as ever. */
	tp_eject(&p, 3, 50);
	p.ifake = 0;
	assert(tp_pick(&p, RND2, 0, NONE) == 3);
	/* No random source: from the cursor, the next in service. */
	tp_free(&p);
	tp_init(&p, 4);
	tp_eject(&p, 1, 100);
	assert(tp_pick(&p, RND, 1, NONE) == 2);
	assert(tp_pick(&p, RND2, 0, NONE) == 0);
	tp_free(&p);

	/* The backups: drawn only when no main server may be taken. */
	tp_init(&p, 5);
	tp_flags(&p, f);
	p.xs = 99;
	for (i = 0; i < 1000; i++)
		assert(tp_pick(&p, i % 2 ? RND : RND2, 0, NONE) < 3);
	tp_eject(&p, 0, 100);
	tp_eject(&p, 1, 100);
	tp_eject(&p, 2, 100);
	for (i = 0; i < 1000; i++) {
		n = tp_pick(&p, i % 2 ? RND : RND2, 0, NONE);
		assert(n == 3 || n == 4);
	}
	assert(tp_pick(&p, RND2, 0, 3) == 4);
	tp_free(&p);
}

/*
 * "random two" fed back (each pick opens a pair, some close): the open
 * counts stay within a few of each other, as least_conn's would, where
 * "random" lets them drift apart by the hundreds.
 */
static void test_random_two_balance(void)
{
	uint32_t open[16], k, i, lo, hi, d[2];
	struct tpool p;
	int two;

	for (two = 0; two < 2; two++) {
		tp_init(&p, 16);
		p.xs = 0x1234567;
		memset(open, 0, sizeof(open));
		for (k = 0; k < 64000; k++) {
			i = tp_pick(&p, two ? RND2 : RND, 0, NONE);
			gwp_up_state_take(p.s[i]);
			/* A random one closes, half the time. */
			if (k % 2) {
				i = gwp_up_rand(&p.xs) % 16;
				if (gwp_up_state_open(p.s[i]))
					gwp_up_state_give(p.s[i]);
			}
		}
		lo = UINT32_MAX;
		hi = 0;
		for (i = 0; i < 16; i++) {
			open[i] = gwp_up_state_open(p.s[i]);
			lo = open[i] < lo ? open[i] : lo;
			hi = open[i] > hi ? open[i] : hi;
		}
		d[two] = hi - lo;
		tp_free(&p);
	}
	if (d[1] > 8 || d[0] < 4 * d[1]) {
		fprintf(stderr, "random two: spread %u, random: %u\n", d[1],
			d[0]);
		assert(0);
	}
}

#define NR_CAP		7u
#define NR_CAP_ROUNDS	20000

struct cap_race {
	struct gwp_up_state	*s;
	_Atomic(uint32_t)	over;
};

static void *cap_fn(void *arg)
{
	struct cap_race *r = arg;
	int i;

	for (i = 0; i < NR_CAP_ROUNDS; i++) {
		if (!gwp_up_state_take_max(r->s, NR_CAP))
			continue;
		if (gwp_up_state_open(r->s) > NR_CAP)
			atomic_fetch_add(&r->over, 1);
		assert(gwp_up_state_give(r->s) != UINT32_MAX);
	}
	return NULL;
}

/* Taking a capped slot is exact, however many workers take at once. */
static void test_take_max_threads(void)
{
	struct gwp_up_key k = key_of(GWP_UP_SCHEME_SOCKS5, "::1", 2, NULL);
	struct gwp_up_table *t = gwp_up_table_create();
	pthread_t th[NR_THREADS];
	struct cap_race r;
	int i;

	assert(t);
	r.s = gwp_up_state_get(t, &k);
	assert(r.s);
	atomic_init(&r.over, 0);
	assert(gwp_up_state_take_max(r.s, 1));
	assert(!gwp_up_state_take_max(r.s, 1));
	assert(!gwp_up_state_take_max(r.s, 0));
	assert(gwp_up_state_give(r.s) == 0);
	for (i = 0; i < NR_THREADS; i++)
		assert(!pthread_create(&th[i], NULL, cap_fn, &r));
	for (i = 0; i < NR_THREADS; i++)
		assert(!pthread_join(th[i], NULL));
	assert(!atomic_load(&r.over));
	assert(gwp_up_state_open(r.s) == 0);
	gwp_up_state_put(r.s);
	assert(gwp_up_table_destroy(t) == 0);
}

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
	struct gwp_up_health	*h;
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
		if (fail(r->h, r->now))
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
		r.h = def_health(r.s);
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
		assert(gwp_up_health_ejected(r.h, r.now, NULL) ==
		       GWP_UP_EJECT_MS);
		/* Its last reference: the next round starts fresh. */
		gwp_up_health_put(r.h);
		gwp_up_state_put(r.s);
	}

	r.s = gwp_up_state_get(t, &k);
	r.h = def_health(r.s);
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
	gwp_up_health_put(r.h);
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
	test_health_settings();
	test_pick_ejected();
	test_pick_ejected_run();
	test_pick_all_ejected();
	test_pick_retry();
	test_pick_missing();
	test_pick_big();
	test_pick_probe();
	test_pick_spread(3, 1, 12345);
	test_pick_spread(3, 3, 777);
	test_pick_spread(7, 3, 0x9e3779b9);
	test_pick_spread_lc(3, 1, 4242);
	test_pick_spread_lc(3, 3, 99);
	test_pick_spread_lc(7, 3, 0x2545f491);
	test_weights();
	test_weights_least_conn();
	test_weights_spread();
	test_weights_big();
	test_max_conns();
	test_backup_down();
	test_backup_weights();
	test_take_max_threads();
	test_eject_threads();
	test_slow_ramp(1000000);
	/* Across the wrap. */
	test_slow_ramp(0u - 30001);
	test_slow_pick();
	{
		static const uint32_t one[4] = { 8, 2, 8, 8 };
		static const uint32_t two[3] = { 8, 4, 8 };
		static const uint32_t last[3] = { 8, 8, 1 };
		static const uint32_t w[3] = { 1, 3, 2 };

		test_slow_rr(NULL, one, 4, 31337);
		test_slow_rr(NULL, two, 3, 4711);
		test_slow_rr(w, two, 3, 0xdeadbeef);
		test_slow_rr(w, last, 3, 1234567);
	}
	{
		static const uint32_t w[3] = { 1, 3, 2 };

		test_random_spread(NULL, 4, 1, NONE, NONE, NONE);
		test_random_spread(w, 3, 2, NONE, NONE, NONE);
		test_random_spread(NULL, 5, 3, 1, 3, NONE);
		test_random_spread(w, 3, 4, NONE, NONE, 1);
		test_random_spread(NULL, 4, 5, 3, NONE, 0);
	}
	test_random_pick();
	test_random_two_balance();
	printf("All upstream_lb tests passed.\n");
	return 0;
}
