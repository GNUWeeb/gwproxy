// SPDX-License-Identifier: GPL-2.0-only
/*
 * How the DNS threads are shared between clients: a client's share of them,
 * the ones kept for clients with nothing running, the order clients are served
 * in and the limits on what may wait.
 *
 * getaddrinfo() is replaced with one that blocks on names starting with "hold"
 * until the test lets them through, so what is running at any moment is up to
 * the test, and no name goes to a real resolver.
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

static int fake_getaddrinfo(const char *name, const char *service,
			    const struct addrinfo *hints,
			    struct addrinfo **res);
static void fake_freeaddrinfo(struct addrinfo *ai);

#define getaddrinfo	fake_getaddrinfo
#define freeaddrinfo	fake_freeaddrinfo
#include "../dns.c"
#undef getaddrinfo
#undef freeaddrinfo

#define MAX_STARTED	(GWP_DNS_MAX_QUEUED + 1024)

static pthread_mutex_t fake_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t fake_cond = PTHREAD_COND_INITIALIZER;
static char (*started)[64];	/* names getaddrinfo() was called for, in order */
static uint32_t nr_started;
static uint32_t tokens;		/* held lookups that may go on */
static bool release_all;

static int fake_getaddrinfo(const char *name, const char *service,
			    const struct addrinfo *hints,
			    struct addrinfo **res)
{
	struct {
		struct addrinfo ai;
		struct sockaddr_in sin;
	} *p;

	(void)service;
	(void)hints;

	pthread_mutex_lock(&fake_lock);
	assert(nr_started < MAX_STARTED);
	snprintf(started[nr_started++], sizeof(started[0]), "%s", name);
	pthread_cond_broadcast(&fake_cond);
	if (!strncmp(name, "hold", 4)) {
		while (!release_all && !tokens)
			pthread_cond_wait(&fake_cond, &fake_lock);
		if (!release_all)
			tokens--;
	}
	pthread_mutex_unlock(&fake_lock);

	p = calloc(1, sizeof(*p));
	assert(p);
	p->sin.sin_family = AF_INET;
	p->sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	p->ai.ai_family = AF_INET;
	p->ai.ai_addr = (struct sockaddr *)&p->sin;
	p->ai.ai_addrlen = sizeof(p->sin);
	*res = &p->ai;
	return 0;
}

static void fake_freeaddrinfo(struct addrinfo *ai)
{
	free(ai);
}

static void fake_reset(void)
{
	pthread_mutex_lock(&fake_lock);
	nr_started = 0;
	tokens = 0;
	release_all = false;
	pthread_mutex_unlock(&fake_lock);
}

static void let_through(uint32_t nr)
{
	pthread_mutex_lock(&fake_lock);
	tokens += nr;
	pthread_cond_broadcast(&fake_cond);
	pthread_mutex_unlock(&fake_lock);
}

static void let_all_through(void)
{
	pthread_mutex_lock(&fake_lock);
	release_all = true;
	pthread_cond_broadcast(&fake_cond);
	pthread_mutex_unlock(&fake_lock);
}

static uint32_t count_started(void)
{
	uint32_t n;

	pthread_mutex_lock(&fake_lock);
	n = nr_started;
	pthread_mutex_unlock(&fake_lock);
	return n;
}

/* Wait for @want lookups to have started in total. */
static void wait_started(uint32_t want)
{
	int i;

	for (i = 0; i < 60000 && count_started() < want; i++)
		usleep(1000);
	assert(count_started() >= want);
}

/* Long enough for a thread that was going to start something to have done so. */
static void settle_down(void)
{
	usleep(200000);
}

static bool was_started(const char *name)
{
	bool found = false;
	uint32_t i;

	pthread_mutex_lock(&fake_lock);
	for (i = 0; i < nr_started && !found; i++)
		found = !strcmp(started[i], name);
	pthread_mutex_unlock(&fake_lock);
	return found;
}

struct req {
	bool	done;
	int	res;
};

/* A client address; distinct for distinct @id. */
static struct gwp_iplim_key client_key(uint32_t id)
{
	struct gwp_iplim_key k;

	memset(&k, 0, sizeof(k));
	memcpy(k.b, &id, sizeof(id));
	return k;
}

static void ask(struct gwp_dns_ctx *ctx, uint32_t client, const char *fmt,
		uint32_t i, struct req *r)
{
	struct gwp_iplim_key k = client_key(client);
	char name[64];

	snprintf(name, sizeof(name), fmt, i);
	r->done = false;
	assert(gwp_dns_queue(ctx, 0, name, 80, &k, r));
}

/* Take what has finished; true when @nr requests have, in total. */
static uint32_t nr_collected;

static void collect(struct gwp_dns_ctx *ctx, uint32_t nr)
{
	struct pollfd pfd = { .fd = gwp_dns_cq_fd(ctx, 0), .events = POLLIN };
	struct gwp_dns_entry *e, *next;

	while (nr_collected < nr) {
		assert(poll(&pfd, 1, 60000) == 1);
		for (e = gwp_dns_cq_pop(ctx, 0); e; e = next) {
			struct req *r = e->udata;

			next = e->next;
			r->done = true;
			r->res = e->res;
			gwp_dns_entry_free(e);
			nr_collected++;
		}
	}
}

/* A completion is there to be taken; none of this waits for one. */
static bool cq_ready(struct gwp_dns_ctx *ctx)
{
	struct pollfd pfd = { .fd = gwp_dns_cq_fd(ctx, 0), .events = POLLIN };

	return poll(&pfd, 1, 0) == 1;
}

static struct gwp_dns_ctx *new_ctx(void)
{
	struct gwp_dns_cfg cfg = { .nr_workers = 1, .nr_cqs = 1 };
	struct gwp_dns_ctx *ctx;

	fake_reset();
	nr_collected = 0;
	assert(!gwp_dns_ctx_init(&ctx, &cfg));
	return ctx;
}

/*
 * Everything asked for has been answered: a thread lets go of its lookup just
 * after that, and then nothing at all may be left of any client.
 */
static void assert_drained(struct gwp_dns_ctx *ctx)
{
	uint32_t b, nr_clients = 0;
	int i;

	for (i = 0; i < 60000; i++) {
		pthread_mutex_lock(&ctx->lock);
		nr_clients = 0;
		for (b = 0; b < GWP_DNS_CLIENT_BUCKETS; b++) {
			struct dns_client *c;

			for (c = ctx->clients[b]; c; c = c->hnext)
				nr_clients++;
		}
		pthread_mutex_unlock(&ctx->lock);
		if (!nr_clients)
			break;
		usleep(1000);
	}
	assert(!nr_clients);

	pthread_mutex_lock(&ctx->lock);
	assert(!ctx->nr_entries && !ctx->nr_ready && !ctx->nr_first);
	assert(!ctx->nr_running);
	assert(!ctx->turns[DNS_TURN_FIRST].head);
	assert(!ctx->turns[DNS_TURN_FIRST].tail);
	assert(!ctx->turns[DNS_TURN_ANY].head);
	assert(!ctx->turns[DNS_TURN_ANY].tail);
	pthread_mutex_unlock(&ctx->lock);
}

#define PER_CLIENT	(GWP_DNS_MAX_THREADS / 2)
#define KEPT		(GWP_DNS_MAX_THREADS / 4)
#define NOT_KEPT	(GWP_DNS_MAX_THREADS - KEPT)

/* One client asking for slow names leaves threads for the others. */
static void test_client_share(void)
{
	struct gwp_dns_ctx *ctx = new_ctx();
	struct req a[PER_CLIENT + 8], b;
	uint32_t i;

	for (i = 0; i < PER_CLIENT + 8; i++)
		ask(ctx, 1, "hold-a-%u", i, &a[i]);
	wait_started(PER_CLIENT);
	settle_down();
	assert(count_started() == PER_CLIENT);

	/* Answered with all of the other client's lookups still blocked. */
	ask(ctx, 2, "other-%u", 0, &b);
	collect(ctx, 1);
	assert(b.done && !b.res);

	let_all_through();
	collect(ctx, PER_CLIENT + 9);
	for (i = 0; i < PER_CLIENT + 8; i++)
		assert(a[i].done && !a[i].res);
	assert_drained(ctx);
	gwp_dns_ctx_free(ctx);
}

/*
 * Two clients together cannot take the threads kept for a client with nothing
 * running, and with even those taken, the next free thread goes to a newcomer
 * ahead of everything others have queued.
 */
static void test_kept_threads(void)
{
	struct gwp_dns_ctx *ctx = new_ctx();
	struct req a[PER_CLIENT + 4], b[PER_CLIENT + 4], c[2], d[KEPT - 1], e;
	uint32_t i;

	for (i = 0; i < PER_CLIENT + 4; i++)
		ask(ctx, 1, "hold-a-%u", i, &a[i]);
	for (i = 0; i < PER_CLIENT + 4; i++)
		ask(ctx, 2, "hold-b-%u", i, &b[i]);
	wait_started(NOT_KEPT);
	settle_down();
	assert(count_started() == NOT_KEPT);

	/* A client's first lookup goes ahead, and its second does not. */
	ask(ctx, 3, "hold-c-%u", 0, &c[0]);
	ask(ctx, 3, "hold-c-%u", 1, &c[1]);
	wait_started(NOT_KEPT + 1);
	settle_down();
	assert(count_started() == NOT_KEPT + 1);
	assert(was_started("hold-c-0"));

	/* It takes one more client per thread to use up the rest. */
	for (i = 0; i < KEPT - 1; i++)
		ask(ctx, 4 + i, "hold-d-%u", i, &d[i]);
	wait_started(GWP_DNS_MAX_THREADS);
	settle_down();
	assert(count_started() == GWP_DNS_MAX_THREADS);

	ask(ctx, 100, "hold-e-%u", 0, &e);
	settle_down();
	assert(!was_started("hold-e-0"));

	/* Whichever thread this frees, the next lookup is the newcomer's. */
	let_through(1);
	wait_started(GWP_DNS_MAX_THREADS + 1);
	assert(was_started("hold-e-0"));

	let_all_through();
	collect(ctx, 2 * (PER_CLIENT + 4) + 2 + KEPT - 1 + 1);
	assert_drained(ctx);
	gwp_dns_ctx_free(ctx);
}

/*
 * With threads short for a reason other than the limit on them, a client with
 * nothing running still goes ahead of a client that has plenty running.
 */
static void test_first_goes_first(void)
{
	struct gwp_dns_ctx *ctx = new_ctx();
	struct req a[8], b;
	uint32_t i;

	/* Two threads at most, and the worker has not gone near this yet. */
	pthread_mutex_lock(&ctx->lock);
	ctx->max_threads = 2;
	pthread_mutex_unlock(&ctx->lock);

	for (i = 0; i < 8; i++)
		ask(ctx, 1, "hold-a-%u", i, &a[i]);
	wait_started(2);
	settle_down();
	assert(count_started() == 2);

	ask(ctx, 2, "hold-b-%u", 0, &b);
	let_through(1);
	wait_started(3);
	assert(was_started("hold-b-0"));

	let_all_through();
	collect(ctx, 9);
	assert_drained(ctx);
	gwp_dns_ctx_free(ctx);
}

/* Clients that already have lookups running take turns, one lookup each. */
static void test_turns(void)
{
	static const char * const order[] = {
		"a-0", "b-0", "a-1", "b-1", "a-2", "b-2",
	};
	struct gwp_dns_ctx *ctx = new_ctx();
	struct req hold[5], q[6];
	uint32_t i;

	/* All the threads there are, with two clients left with one each. */
	pthread_mutex_lock(&ctx->lock);
	ctx->max_threads = 5;
	pthread_mutex_unlock(&ctx->lock);

	for (i = 0; i < 2; i++) {
		ask(ctx, 1, "hold-a-%u", i, &hold[2 * i]);
		ask(ctx, 2, "hold-b-%u", i, &hold[2 * i + 1]);
	}
	ask(ctx, 3, "hold-c-%u", 0, &hold[4]);
	wait_started(5);

	for (i = 0; i < 3; i++)
		ask(ctx, 1, "a-%u", i, &q[2 * i]);
	for (i = 0; i < 3; i++)
		ask(ctx, 2, "b-%u", i, &q[2 * i + 1]);

	/* Whichever thread this frees, it gets through them all, in turn. */
	let_through(1);
	wait_started(5 + 6);
	pthread_mutex_lock(&fake_lock);
	for (i = 0; i < 6; i++)
		assert(!strcmp(started[5 + i], order[i]));
	pthread_mutex_unlock(&fake_lock);

	let_all_through();
	collect(ctx, 5 + 6);
	assert_drained(ctx);
	gwp_dns_ctx_free(ctx);
}

/* What may wait is bounded, per client and in all, and a refusal is at once. */
static void test_limits(void)
{
	static struct req q[GWP_DNS_MAX_QUEUED + 2 * PER_CLIENT + GWP_DNS_MAX_THREADS];
	struct gwp_dns_ctx *ctx = new_ctx();
	struct req over, same, other;
	uint32_t i, n = 0, client;

	/* Give one client all the threads it may have, then fill its queue. */
	for (i = 0; i < PER_CLIENT; i++)
		ask(ctx, 1, "hold-a-%u", i, &q[n++]);
	wait_started(PER_CLIENT);
	for (; i < PER_CLIENT + GWP_DNS_MAX_QUEUED_PER_CLIENT; i++)
		ask(ctx, 1, "hold-a-%u", i, &q[n++]);

	/* One more is refused at once, and nobody else is. */
	ask(ctx, 1, "hold-over-%u", 0, &over);
	collect(ctx, 1);
	assert(over.done && over.res == -EHOSTUNREACH);
	assert(!was_started("hold-over-0"));
	pthread_mutex_lock(&ctx->lock);
	assert(!find_lookup(ctx, "hold-over-0", strlen("hold-over-0"),
			    gwp_siphash13(ctx->hash_key, "hold-over-0",
					  strlen("hold-over-0"))));
	pthread_mutex_unlock(&ctx->lock);

	/* A name already queued costs nothing more, so it is not limited. */
	ask(ctx, 1, "hold-a-%u", PER_CLIENT + 1, &same);
	assert(!same.done);

	ask(ctx, 2, "hold-other-%u", 0, &other);
	wait_started(PER_CLIENT + 1);
	assert(was_started("hold-other-0"));

	/* Fill the global limit with enough clients, leaving room per client. */
	for (client = 10; ; client++) {
		bool full = false;

		for (i = 0; i < GWP_DNS_MAX_QUEUED_PER_CLIENT; i++) {
			pthread_mutex_lock(&ctx->lock);
			full = ctx->nr_entries >= GWP_DNS_MAX_QUEUED;
			pthread_mutex_unlock(&ctx->lock);
			if (full)
				break;
			assert(n < sizeof(q) / sizeof(q[0]));
			ask(ctx, client, "hold-fill-%u", n, &q[n]);
			n++;
		}
		if (full)
			break;
	}

	/*
	 * A client with nothing queued is refused now as well. The fill just
	 * started threads that may not have taken their lookup yet, and each
	 * one that does makes room for one more, so being full a moment ago
	 * says nothing about this request. Every lookup is held, so only a
	 * refusal can complete, and there are few threads to make room.
	 */
	for (client++; ; client++) {
		assert(n < sizeof(q) / sizeof(q[0]));
		ask(ctx, client, "hold-late-%u", client, &q[n]);
		if (cq_ready(ctx))
			break;
		n++;
	}
	collect(ctx, 2);
	assert(q[n].done && q[n].res == -EHOSTUNREACH);

	let_all_through();
	collect(ctx, n + 4);
	for (i = 0; i < n; i++)
		assert(q[i].done && !q[i].res);
	assert(same.done && !same.res);
	assert(other.done && !other.res);
	assert_drained(ctx);
	gwp_dns_ctx_free(ctx);
}

/*
 * A name queued by a client with a long queue must not make another client
 * wait behind that queue, and a client with a long queue must not be able to
 * pull a name out of a short one.
 */
static void test_attach_moves(void)
{
	struct gwp_dns_ctx *ctx = new_ctx();
	struct req a[PER_CLIENT + 8], b[PER_CLIENT + 1], v, w;
	const char *moved = "hold-a-39";
	uint32_t i;
	struct dns_lookup *l;
	const char *name = "hold-b-32";
	size_t len = strlen(name);

	for (i = 0; i < PER_CLIENT + 8; i++)
		ask(ctx, 1, "hold-a-%u", i, &a[i]);
	wait_started(PER_CLIENT);
	settle_down();
	assert(!was_started(moved));

	/* Client 2 wants the last name of client 1's queue: it runs for it. */
	ask(ctx, 2, moved, 0, &v);
	wait_started(PER_CLIENT + 1);
	assert(was_started(moved));
	settle_down();
	assert(count_started() == PER_CLIENT + 1);

	/* Client 2 takes the rest it may, with lookups left in its queue. */
	for (i = 0; i < PER_CLIENT; i++)
		ask(ctx, 2, "hold-b-%u", i + 1, &b[i]);
	wait_started(NOT_KEPT);
	settle_down();

	/* Client 1 has more outstanding, so the name stays where it is. */
	ask(ctx, 1, name, 0, &w);
	pthread_mutex_lock(&ctx->lock);
	l = find_lookup(ctx, name, len, gwp_siphash13(ctx->hash_key, name, len));
	assert(l && !l->running);
	{
		struct gwp_iplim_key k = client_key(2);

		assert(!memcmp(&l->client->key, &k, sizeof(k)));
	}
	pthread_mutex_unlock(&ctx->lock);

	let_all_through();
	collect(ctx, PER_CLIENT + 8 + PER_CLIENT + 2);
	assert_drained(ctx);
	gwp_dns_ctx_free(ctx);
}

/*
 * A client is gone with its last lookup, so what is kept does not grow with
 * every address ever seen. Each of these clients has one lookup and is done
 * with it before the next one asks.
 */
static void test_client_goes_away(void)
{
	struct gwp_dns_ctx *ctx = new_ctx();
	struct req r;
	uint32_t i;

	for (i = 0; i < 16; i++) {
		ask(ctx, i + 1, "name-%u", i, &r);
		collect(ctx, i + 1);
		assert(r.done && !r.res);
		assert_drained(ctx);
	}
	gwp_dns_ctx_free(ctx);
}

/* A queued lookup all of whose requesters gave up never reaches the resolver. */
static void test_cancelled_never_runs(void)
{
	struct gwp_dns_ctx *ctx = new_ctx();
	struct gwp_iplim_key k = client_key(1);
	struct gwp_dns_entry *dead[4];
	struct req a[PER_CLIENT], after;
	uint32_t i;
	char name[32];

	for (i = 0; i < PER_CLIENT; i++)
		ask(ctx, 1, "hold-a-%u", i, &a[i]);
	wait_started(PER_CLIENT);

	for (i = 0; i < 4; i++) {
		snprintf(name, sizeof(name), "hold-dead-%u", i);
		dead[i] = gwp_dns_queue(ctx, 0, name, 80, &k, NULL);
		assert(dead[i]);
		gwp_dns_entry_cancel(dead[i]);
	}
	ask(ctx, 1, "hold-after-%u", 0, &after);

	let_all_through();
	collect(ctx, PER_CLIENT + 1);
	assert(after.done && !after.res);
	for (i = 0; i < 4; i++) {
		snprintf(name, sizeof(name), "hold-dead-%u", i);
		assert(!was_started(name));
	}
	assert_drained(ctx);
	gwp_dns_ctx_free(ctx);
}

/* Freeing the context with lookups queued leaves nothing behind (ASan). */
static void test_free_with_queued(void)
{
	struct gwp_dns_ctx *ctx = new_ctx();
	static struct req a[PER_CLIENT + 100];
	uint32_t i;

	for (i = 0; i < PER_CLIENT + 100; i++)
		ask(ctx, 1, "hold-a-%u", i, &a[i]);
	wait_started(PER_CLIENT);
	let_all_through();
	gwp_dns_ctx_free(ctx);
}

int main(void)
{
	started = calloc(MAX_STARTED, sizeof(*started));
	assert(started);

	test_client_share();
	test_kept_threads();
	test_first_goes_first();
	test_turns();
	test_limits();
	test_attach_moves();
	test_client_goes_away();
	test_cancelled_never_runs();
	test_free_with_queued();

	free(started);
	printf("All tests passed!\n");
	return 0;
}
