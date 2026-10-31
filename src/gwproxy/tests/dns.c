// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <stdio.h>
#include <assert.h>
#include <gwproxy/dns.h>
#include <gwproxy/dns_cache.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

struct req_template {
	const char *domain;
	uint16_t port;
	bool needs_ipv6;	/* requires a resolvable IPv6, see has_ipv6() */
};

/*
 * Names that resolve from /etc/hosts alone. A unit test must not depend on
 * public DNS: on an offline or filtered builder every one of these lookups
 * fails, the assertion below aborts, and `make test-unit` stops before the
 * socks5/http1/http/acl binaries ever run -- indistinguishable from a real
 * regression in gwp_dns_queue(). Repeating a handful of local names keeps the
 * many-requests shape (queue, workers, eventfd, refcounts, cache inserts) that
 * this test is actually about, and covers both address families.
 *
 * Only "localhost" is used as a name. "ip6-localhost" is a Debian default
 * that other hosts files leave out, and "::1" already covers IPv6.
 *
 * The entries marked needs_ipv6 are requested only where the host can serve
 * them; /etc/hosts is not enough on its own. See has_ipv6().
 */
static const struct req_template req_template[] = {
	{ "localhost",		80,	false },
	{ "127.0.0.1",		80,	false },
	{ "::1",		443,	true },
	{ "localhost",		1080,	false },
	{ "localhost",		443,	false },
	{ "127.0.0.1",		443,	false },
	{ "::1",		80,	true },
	{ "localhost",		3128,	false },
	{ "localhost",		8080,	false },
	{ "127.0.0.1",		8080,	false },
	{ "::1",		8080,	true },
	{ "localhost",		8443,	false },
	{ "localhost",		9090,	false },
	{ "127.0.0.1",		9090,	false },
	{ "::1",		9090,	true },
};

/*
 * Wait until all @n entries in @want have come back on completion queue 0,
 * the way an event loop would: poll the queue's eventfd, then pop.
 */
static int wait_entries(struct gwp_dns_ctx *ctx, struct gwp_dns_entry **want,
			int n, int timeout)
{
	struct pollfd pfd = { .fd = gwp_dns_cq_fd(ctx, 0), .events = POLLIN };
	struct gwp_dns_entry *e;
	int ret, i, got = 0;

	while (got < n) {
		ret = poll(&pfd, 1, timeout);
		if (ret < 0) {
			perror("poll");
			return -1;
		}
		if (ret == 0) {
			fprintf(stderr, "poll timed out\n");
			return -ETIMEDOUT;
		}

		for (e = gwp_dns_cq_pop(ctx, 0); e; e = e->next) {
			for (i = 0; i < n; i++) {
				if (want[i] == e)
					break;
			}
			assert(i < n);
			/* udata comes back as given. */
			assert(e->udata == &want[i]);
			got++;
		}
	}

	return 0;
}

/*
 * The resolver hands a result to its client before it inserts it into the
 * cache, so a lookup right after the result arrived may still miss. Wait for
 * the insert, giving up after a second.
 */
static void wait_cached(struct gwp_dns_ctx *ctx, const char *name)
{
	struct gwp_sockaddr addr;
	int i;

	for (i = 0; i < 1000; i++) {
		if (!gwp_dns_cache_lookup(ctx, name, 0, &addr))
			return;
		usleep(1000);
	}
	assert(0 && "the result never reached the cache");
}

/*
 * Can this host resolve an IPv6 name at all, using the flags the resolver
 * itself uses?
 *
 * gwp_dns_queue() resolves with AI_ADDRCONFIG (prep_hints() in dns.c), and
 * glibc only enables AF_INET6 lookups when a NON-LOOPBACK IPv6 address is
 * configured -- "::1/128 scope host" on lo does not count. So on a v4-only
 * host, and in most containers, even the literal "::1" fails with
 * EAI_ADDRFAMILY, which the resolver reports as -EHOSTUNREACH. That is the
 * resolver behaving correctly, not a regression, so the IPv6 names are
 * requested only where they can succeed. Probing beats parsing /etc/hosts or
 * poking at interfaces: it asks exactly the question the code under test asks.
 */
static bool has_ipv6(void)
{
	struct addrinfo hints, *res = NULL;
	int r;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG;
	r = getaddrinfo("::1", "80", &hints, &res);
	if (res)
		freeaddrinfo(res);

	return r == 0;
}

static void test_basic_dns_multiple_requests(void)
{
	struct gwp_dns_cfg cfg = { .nr_workers = 1, .nr_cqs = 1 };
	struct gwp_dns_entry *earr[ARRAY_SIZE(req_template)];
	uint16_t ports[ARRAY_SIZE(req_template)];
	bool v6 = has_ipv6();
	struct gwp_dns_ctx *ctx;
	int i, n, skipped = 0;
	int r;

	r = gwp_dns_ctx_init(&ctx, &cfg);
	assert(!r);
	assert(ctx != NULL);

	n = 0;
	for (i = 0; i < (int)ARRAY_SIZE(req_template); i++) {
		const struct req_template *rt = &req_template[i];

		if (rt->needs_ipv6 && !v6) {
			skipped++;
			continue;
		}
		earr[n] = gwp_dns_queue(ctx, 0, rt->domain, rt->port,
					&earr[n]);
		ports[n] = rt->port;
		assert(earr[n]);
		n++;
	}
	assert(n > 0);

	/*
	 * Say so rather than quietly running a smaller test: a reader who sees
	 * a pass here must not conclude that IPv6 resolution was covered.
	 */
	if (skipped)
		printf("dns: no non-loopback IPv6 on this host, skipped %d of %zu requests\n",
		       skipped, ARRAY_SIZE(req_template));

	r = wait_entries(ctx, earr, n, 5000);
	assert(!r);

	for (i = 0; i < n; i++) {
		assert(earr[i]->res == 0);
		r = earr[i]->addrs[0].sa.sa_family;
		assert(r == AF_INET || r == AF_INET6);
		/* sin_port and sin6_port share an offset. */
		assert(earr[i]->addrs[0].i4.sin_port == htons(ports[i]));
	}

	for (i = 0; i < n; i++)
		gwp_dns_entry_free(earr[i]);
	gwp_dns_ctx_free(ctx);
}

static void test_dns_cache(void)
{
	struct gwp_dns_cfg cfg = { .nr_workers = 1, .cache_expiry = 10,
				   .nr_cqs = 1 };
	struct gwp_sockaddr addr;
	struct gwp_dns_ctx *ctx;
	struct gwp_dns_entry *e;
	int r;

	r = gwp_dns_ctx_init(&ctx, &cfg);
	assert(!r);
	assert(ctx != NULL);

	e = gwp_dns_queue(ctx, 0, "localhost", 80, &e);
	assert(e != NULL);
	r = wait_entries(ctx, &e, 1, 5000);
	assert(r == 0);
	assert(e->res == 0);
	r = e->addrs[0].sa.sa_family;
	assert(r == AF_INET || r == AF_INET6);
	gwp_dns_entry_free(e);

	wait_cached(ctx, "localhost");
	r = gwp_dns_cache_lookup(ctx, "localhost", 8080, &addr);
	assert(!r);
	r = addr.sa.sa_family;
	assert(r == AF_INET || r == AF_INET6);
	/* A hit carries the port asked for, not the one first resolved. */
	assert(addr.i4.sin_port == htons(8080));
	r = gwp_dns_cache_lookup(ctx, "aaaa.com", 80, &addr);
	assert(r == -ENOENT);
	gwp_dns_ctx_free(ctx);
}

/* A throwaway one-address (IPv4) addrinfo for direct cache-layer tests. */
static void fill_ai_v4(struct addrinfo *ai, struct sockaddr_in *sa)
{
	memset(sa, 0, sizeof(*sa));
	sa->sin_family = AF_INET;
	sa->sin_addr.s_addr = htonl(0x7f000001);	/* 127.0.0.1 */
	memset(ai, 0, sizeof(*ai));
	ai->ai_family = AF_INET;
	ai->ai_addr = (struct sockaddr *)sa;
	ai->ai_addrlen = sizeof(*sa);
}

/*
 * Exercise the cache layer directly (no network): the max-entries cap must
 * refuse new keys once full while still allowing same-key replacement.
 */
static void test_dns_cache_cap(void)
{
	struct gwp_dns_cache *cache = NULL;
	struct gwp_dns_cache_addrs ca;
	struct sockaddr_in sa;
	struct addrinfo ai;
	char key[32];
	int r, i;

	fill_ai_v4(&ai, &sa);

	r = gwp_dns_cache_init(&cache, 16, 4);	/* cap = 4 entries */
	assert(!r && cache);

	/* Fill to capacity: four distinct keys are accepted. */
	for (i = 0; i < 4; i++) {
		snprintf(key, sizeof(key), "host%d.example", i);
		r = gwp_dns_cache_insert(cache, key, &ai, time(NULL) + 100);
		assert(!r);
	}

	/* A fifth distinct key is refused and not cached. */
	r = gwp_dns_cache_insert(cache, "host4.example", &ai, time(NULL) + 100);
	assert(r == -ENOSPC);
	r = gwp_dns_cache_lookup_addrs(cache, "host4.example", &ca);
	assert(r == -ENOENT);

	/* Existing keys remain; replacing one (same key) is allowed when full. */
	r = gwp_dns_cache_lookup_addrs(cache, "host0.example", &ca);
	assert(!r);
	r = gwp_dns_cache_insert(cache, "host0.example", &ai, time(NULL) + 100);
	assert(!r);

	gwp_dns_cache_free(cache);
}

/* Keys are case-insensitive: a mixed-case insert is found by any case. */
static void test_dns_cache_case(void)
{
	struct gwp_dns_cache *cache = NULL;
	struct gwp_dns_cache_addrs ca;
	struct sockaddr_in sa;
	struct addrinfo ai;
	int r;

	fill_ai_v4(&ai, &sa);
	r = gwp_dns_cache_init(&cache, 16, 0);
	assert(!r && cache);

	r = gwp_dns_cache_insert(cache, "MixedCase.Example", &ai, time(NULL) + 100);
	assert(!r);
	r = gwp_dns_cache_lookup_addrs(cache, "mixedcase.example", &ca);
	assert(!r);
	r = gwp_dns_cache_lookup_addrs(cache, "MIXEDCASE.EXAMPLE", &ca);
	assert(!r);

	/* A differently-cased insert replaces, not duplicates, the same key. */
	r = gwp_dns_cache_insert(cache, "MIXEDCASE.example", &ai, time(NULL) + 100);
	assert(!r);
	r = gwp_dns_cache_lookup_addrs(cache, "mixedcase.example", &ca);
	assert(!r);

	gwp_dns_cache_free(cache);
}

/*
 * An already-expired entry is not returned, and a same-key replace is what the
 * next lookup sees. A hit copies the addresses out under the lock, so there is
 * no reference to outlive the replaced entry (run under ASan this also checks
 * there is no use-after-free).
 */
static void test_dns_cache_expiry_replace(void)
{
	struct gwp_dns_cache *cache = NULL;
	struct gwp_dns_cache_addrs ca;
	struct sockaddr_in sa;
	struct addrinfo ai;
	int r;

	fill_ai_v4(&ai, &sa);
	r = gwp_dns_cache_init(&cache, 16, 0);
	assert(!r && cache);

	/* Expired-on-insert: lookup reports a miss, not the stale entry. */
	r = gwp_dns_cache_insert(cache, "old.example", &ai, time(NULL) - 1);
	assert(!r);
	r = gwp_dns_cache_lookup_addrs(cache, "old.example", &ca);
	assert(r == -ETIMEDOUT || r == -ENOENT);

	r = gwp_dns_cache_insert(cache, "live.example", &ai, time(NULL) + 100);
	assert(!r);
	r = gwp_dns_cache_lookup_addrs(cache, "live.example", &ca);
	assert(!r);
	assert(ca.nr_i4 == 1 && ca.nr_i6 == 0);
	assert(ca.i4[0].s_addr == htonl(0x7f000001));

	sa.sin_addr.s_addr = htonl(0x7f000002);
	r = gwp_dns_cache_insert(cache, "live.example", &ai, time(NULL) + 100);
	assert(!r);
	r = gwp_dns_cache_lookup_addrs(cache, "live.example", &ca);
	assert(!r);
	assert(ca.nr_i4 == 1 && ca.i4[0].s_addr == htonl(0x7f000002));

	gwp_dns_cache_free(cache);
}

/* A long answer is cut to what a lookup can return, keeping the first ones. */
static void test_dns_cache_many_addrs(void)
{
	struct gwp_dns_cache *cache = NULL;
	struct gwp_dns_cache_addrs ca;
	struct sockaddr_in sa[20];
	struct addrinfo ai[20];
	int r, i;

	for (i = 0; i < 20; i++) {
		fill_ai_v4(&ai[i], &sa[i]);
		sa[i].sin_addr.s_addr = htonl(0x0a000001 + i);
		ai[i].ai_next = i < 19 ? &ai[i + 1] : NULL;
	}

	r = gwp_dns_cache_init(&cache, 16, 0);
	assert(!r && cache);
	r = gwp_dns_cache_insert(cache, "many.example", ai, time(NULL) + 100);
	assert(!r);
	r = gwp_dns_cache_lookup_addrs(cache, "many.example", &ca);
	assert(!r);
	assert(ca.nr_i4 == GWP_DNS_CACHE_MAX_ADDRS && ca.nr_i6 == 0);
	for (i = 0; i < (int)GWP_DNS_CACHE_MAX_ADDRS; i++)
		assert(ca.i4[i].s_addr == htonl(0x0a000001 + i));

	gwp_dns_cache_free(cache);
}

/*
 * The resolver must hand back every usable address, not just the one it would
 * have connected to, and the cache must agree with a fresh lookup -- both on
 * the leading address and on the ordering. "localhost" is the useful case here
 * because it is normally dual stack (127.0.0.1 and ::1).
 */
static void test_addr_list(void)
{
	struct gwp_dns_cfg cfg = { .nr_workers = 1, .cache_expiry = 10,
				   .nr_cqs = 1 };
	struct gwp_sockaddr one, list[GWP_DNS_MAX_ADDRS];
	struct gwp_dns_ctx *ctx;
	struct gwp_dns_entry *e;
	uint8_t nr = 0, i;
	int r;

	r = gwp_dns_ctx_init(&ctx, &cfg);
	assert(!r);

	e = gwp_dns_queue(ctx, 0, "localhost", 80, &e);
	assert(e != NULL);
	r = wait_entries(ctx, &e, 1, 5000);
	assert(r == 0);
	assert(e->res == 0);

	/* At least one address, and the count must match what was filled in. */
	assert(e->nr_addrs >= 1);
	assert(e->nr_addrs <= GWP_DNS_MAX_ADDRS);
	for (i = 0; i < e->nr_addrs; i++) {
		r = e->addrs[i].sa.sa_family;
		assert(r == AF_INET || r == AF_INET6);
	}

	/*
	 * Families must alternate while both are still available, so a broken
	 * family costs one attempt rather than every attempt.
	 */
	for (i = 1; i < e->nr_addrs; i++) {
		int prev = e->addrs[i - 1].sa.sa_family;
		int cur = e->addrs[i].sa.sa_family;
		uint8_t j, same_as_cur = 0;

		if (prev != cur)
			continue;
		/*
		 * Two in a row is only legal once the other family is
		 * exhausted, i.e. every remaining entry has this family.
		 */
		for (j = i; j < e->nr_addrs; j++)
			if (e->addrs[j].sa.sa_family == cur)
				same_as_cur++;
		assert(same_as_cur == (uint8_t)(e->nr_addrs - i));
	}
	gwp_dns_entry_free(e);

	/* The cache stores every record; its list must match the resolver's. */
	wait_cached(ctx, "localhost");
	r = gwp_dns_cache_lookup_list(ctx, "localhost", 80, list,
				      GWP_DNS_MAX_ADDRS, &nr);
	assert(!r);
	assert(nr >= 1);

	/* ... and its first address must equal the single-address lookup. */
	r = gwp_dns_cache_lookup(ctx, "localhost", 80, &one);
	assert(!r);
	assert(one.sa.sa_family == list[0].sa.sa_family);

	r = gwp_dns_cache_lookup_list(ctx, "aaaa.com", 80, list,
				      GWP_DNS_MAX_ADDRS, &nr);
	assert(r == -ENOENT);

	gwp_dns_ctx_free(ctx);
}

/*
 * A cancelled request never comes back from the completion queue, and the
 * context frees whatever is still queued or undelivered when it goes away
 * (run under ASan this checks nothing leaks).
 */
static void test_cancel(void)
{
	struct gwp_dns_cfg cfg = { .nr_workers = 1, .nr_cqs = 2 };
	struct gwp_dns_entry *c1, *c2, *e;
	struct gwp_dns_ctx *ctx;
	int r;

	r = gwp_dns_ctx_init(&ctx, &cfg);
	assert(!r);

	c1 = gwp_dns_queue(ctx, 0, "localhost", 80, NULL);
	c2 = gwp_dns_queue(ctx, 0, "127.0.0.1", 80, NULL);
	assert(c1 && c2);
	gwp_dns_entry_cancel(c1);
	gwp_dns_entry_cancel(c2);

	/* Queued after them, so it finishes after them on the one thread. */
	e = gwp_dns_queue(ctx, 0, "localhost", 81, &e);
	assert(e);
	r = wait_entries(ctx, &e, 1, 5000);
	assert(!r);
	assert(e->res == 0 && e->addrs[0].i4.sin_port == htons(81));
	gwp_dns_entry_free(e);

	/* Left for gwp_dns_ctx_free(): one delivered on queue 1, unpopped. */
	e = gwp_dns_queue(ctx, 1, "localhost", 80, NULL);
	assert(e);
	gwp_dns_queue(ctx, 1, "localhost", 80, NULL);
	gwp_dns_ctx_free(ctx);
}

/*
 * Requests for one name share one lookup, but each gets the port it asked
 * for. A name no resolver could take fails through the queue like any other.
 */
static void test_shared_lookup(void)
{
	struct gwp_dns_cfg cfg = { .nr_workers = 1, .nr_cqs = 1 };
	struct gwp_dns_entry *earr[20], *bad;
	struct gwp_dns_ctx *ctx;
	char longname[300];
	int i, r;

	r = gwp_dns_ctx_init(&ctx, &cfg);
	assert(!r);

	for (i = 0; i < 20; i++) {
		earr[i] = gwp_dns_queue(ctx, 0, i & 1 ? "LocalHost" : "localhost",
					(uint16_t)(1000 + i), &earr[i]);
		assert(earr[i]);
	}
	r = wait_entries(ctx, earr, 20, 5000);
	assert(!r);
	for (i = 0; i < 20; i++) {
		assert(earr[i]->res == 0);
		assert(earr[i]->nr_addrs >= 1);
		assert(earr[i]->addrs[earr[i]->nr_addrs - 1].i4.sin_port ==
		       htons(1000 + i));
		gwp_dns_entry_free(earr[i]);
	}

	memset(longname, 'a', sizeof(longname) - 1);
	longname[sizeof(longname) - 1] = '\0';
	bad = gwp_dns_queue(ctx, 0, longname, 80, &bad);
	assert(bad);
	r = wait_entries(ctx, &bad, 1, 5000);
	assert(!r);
	assert(bad->res == -EHOSTUNREACH);
	gwp_dns_entry_free(bad);

	gwp_dns_ctx_free(ctx);
}

/*
 * A name that does not resolve is remembered for a while, so the next request
 * for it fails from the cache instead of resolving again.
 */
static void test_negative_cache(void)
{
	struct gwp_dns_cfg cfg = { .nr_workers = 1, .cache_expiry = 10,
				   .nr_cqs = 1 };
	struct gwp_dns_cache_addrs ca;
	struct gwp_sockaddr addr;
	struct gwp_dns_cache *cache;
	struct gwp_dns_ctx *ctx;
	struct gwp_dns_entry *e;
	int r, i;

	r = gwp_dns_cache_init(&cache, 16, 0);
	assert(!r);
	r = gwp_dns_cache_insert(cache, "gone.example", NULL, time(NULL) + 100);
	assert(!r);
	r = gwp_dns_cache_lookup_addrs(cache, "gone.example", &ca);
	assert(!r && !ca.nr_i4 && !ca.nr_i6);
	gwp_dns_cache_free(cache);

	r = gwp_dns_ctx_init(&ctx, &cfg);
	assert(!r);
	r = gwp_dns_cache_lookup(ctx, "no-such-host.invalid", 80, &addr);
	assert(r == -ENOENT);

	/* .invalid never resolves (RFC 2606), online or not. */
	e = gwp_dns_queue(ctx, 0, "no-such-host.invalid", 80, &e);
	assert(e);
	r = wait_entries(ctx, &e, 1, 30000);
	assert(!r);
	assert(e->res == -EHOSTUNREACH);
	gwp_dns_entry_free(e);

	/* Inserted after delivery; wait for it. */
	for (i = 0; i < 1000; i++) {
		r = gwp_dns_cache_lookup(ctx, "no-such-host.invalid", 80, &addr);
		if (r != -ENOENT)
			break;
		usleep(1000);
	}
	assert(r == -EHOSTUNREACH);

	/* A remembered failure comes back through the queue like any other. */
	e = gwp_dns_queue_result(ctx, 0, "no-such-host.invalid", 80, &e, r);
	assert(e);
	r = wait_entries(ctx, &e, 1, 5000);
	assert(!r);
	assert(e->res == -EHOSTUNREACH);
	gwp_dns_entry_free(e);

	gwp_dns_ctx_free(ctx);
}

int main(void)
{
	test_basic_dns_multiple_requests();
	test_dns_cache();
	test_dns_cache_cap();
	test_dns_cache_case();
	test_dns_cache_expiry_replace();
	test_dns_cache_many_addrs();
	test_addr_list();
	test_cancel();
	test_shared_lookup();
	test_negative_cache();
	printf("All tests passed.\n");
	return 0;
}
