// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "dns.h"
#include "dns_cache.h"
#include "dns_hash.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>

#include <pthread.h>
#include <sys/eventfd.h>
#include <gwproxy/syscall.h>

/*
 * The resolver threads. @nr_workers of them (--nr-dns-workers) are started
 * with the context and stay; more are started when lookups queue up with no
 * thread free to take them, up to GWP_DNS_MAX_THREADS, and those exit again
 * after GWP_DNS_IDLE_SECS without work.
 *
 * Each thread runs one blocking getaddrinfo() at a time and hands its result
 * to the waiting client as soon as it returns, so how many lookups are in
 * flight follows the load.
 *
 * A lookup can block for many seconds, and a client picks the names, so the
 * threads are shared out by client address (see struct dns_client), or one
 * client asking for names that never answer would stop name lookups for all
 * the others: a client runs at most half of the threads at a time, and the
 * clients with lookups waiting take turns. A quarter of the threads are kept
 * for clients with nothing running, who also go first, so it takes more than
 * a couple of client addresses to make a newcomer wait: lookups that started
 * together end together, and without this the threads two clients hold would
 * only come free to go straight back to them. Waiting is bounded too; a request
 * over a limit fails at once, as a name that does not resolve would.
 */
#define GWP_DNS_MAX_THREADS		64u
#define GWP_DNS_IDLE_SECS		10
#define GWP_DNS_MAX_QUEUED_PER_CLIENT	1024u
#define GWP_DNS_MAX_QUEUED		16384u

enum {
	GWP_DNS_THR_FREE	= 0,	/* slot unused */
	GWP_DNS_THR_RUNNING	= 1,
	GWP_DNS_THR_EXITED	= 2,	/* exited on idle, not joined yet */
};

struct gwp_dns_ctx;

struct gwp_dns_thr {
	struct gwp_dns_ctx	*ctx;
	pthread_t		thread;
	uint32_t		id;
	uint8_t			state;
	bool			join;	/* free_threads() only */
};

/*
 * A completion queue: a lock-free LIFO the resolver threads push finished
 * entries onto, drained in one go by the event loop that owns it. The
 * eventfd is written only when the list goes from empty to non-empty.
 */
struct gwp_dns_cq {
	_Atomic(struct gwp_dns_entry *)	head;
	int				efd;
};

/*
 * One name being resolved, with every request waiting for it. Requests for a
 * name already queued or being resolved attach to its lookup instead of
 * starting another, so N clients opening connections to one host at once cost
 * one resolution, not N. The resolver type is per process, so the folded name
 * is the whole key.
 */
struct dns_lookup {
	struct dns_lookup	*hnext;		/* in-flight table chain */
	struct dns_lookup	*qnext;		/* @client's queue */
	struct dns_lookup	*qprev;
	struct dns_client	*client;	/* who it is counted against */
	struct gwp_dns_entry	*waiters;	/* linked through ->next */
	bool			running;	/* left the queue for a thread */
	uint64_t		hash;
	size_t			len;		/* of @key, without the NUL */
	char			key[];		/* folded name */
};

/*
 * The clients waiting for a thread, in the order they are served, one lookup
 * per client each time:
 *
 * DNS_TURN_FIRST: those with a lookup queued and none running. They go first
 * and may take any thread.
 *
 * DNS_TURN_ANY: those a thread may take a lookup from (dns_client.nr_ready),
 * as long as it is not one of the threads kept for the list above.
 *
 * A client is on a list for exactly as long as that holds, so it can be on both,
 * and whatever is at the head of a list can be served.
 */
enum {
	DNS_TURN_FIRST,
	DNS_TURN_ANY,
	DNS_NR_TURNS,
};

struct dns_turns {
	struct dns_client	*head;
	struct dns_client	*tail;
};

/*
 * A client address with lookups queued or running; it goes away with the last
 * of them. @nr_ready is how many of its queued lookups a thread may take right
 * now, within its share of the threads.
 */
struct dns_client {
	struct dns_client	*hnext;		/* client table chain */
	struct dns_client	*tnext[DNS_NR_TURNS];
	struct dns_client	*tprev[DNS_NR_TURNS];
	struct dns_lookup	*qhead;		/* queued lookups, oldest first */
	struct dns_lookup	*qtail;
	uint32_t		nr_queued;
	uint32_t		nr_running;
	uint32_t		nr_ready;
	bool			on_turn[DNS_NR_TURNS];
	bool			first;		/* queued, and none running */
	uint64_t		hash;
	struct gwp_iplim_key	key;
};

/* Buckets of the in-flight and client tables; powers of two. */
#define GWP_DNS_INFLIGHT_BUCKETS	4096u
#define GWP_DNS_CLIENT_BUCKETS		1024u

struct gwp_dns_ctx {
	bool			should_stop;
	pthread_mutex_t		lock;
	pthread_cond_t		cond;
	uint32_t		nr_sleeping;
	uint32_t		nr_entries;	/* queued lookups */
	uint32_t		nr_ready;	/* sum of the clients' @nr_ready */
	uint32_t		nr_first;	/* clients with @first set */
	uint32_t		nr_running;	/* lookups with a thread */
	uint32_t		nr_threads;	/* RUNNING slots */
	uint32_t		max_threads;
	uint32_t		max_client_running;
	uint32_t		max_any_running; /* with DNS_TURN_ANY's lookups */
	struct dns_turns	turns[DNS_NR_TURNS];
	struct dns_client	**clients;	/* GWP_DNS_CLIENT_BUCKETS */
	struct dns_lookup	**inflight;	/* GWP_DNS_INFLIGHT_BUCKETS */
	uint64_t		hash_key[2];
	struct gwp_dns_thr	*threads;	/* @max_threads slots */
	struct gwp_dns_cache	*cache;
	struct gwp_dns_cq	*cqs;		/* @cfg.nr_cqs of them */
	time_t			last_scan;
	struct gwp_dns_cfg	cfg;
};

static void free_all_entries(struct gwp_dns_entry *head)
{
	struct gwp_dns_entry *e, *next;

	for (e = head; e; e = next) {
		next = e->next;
		gwp_dns_entry_free(e);
	}
}

static void copy_ai_addr(struct gwp_sockaddr *gs, const struct addrinfo *ai,
			 uint16_t port)
{
	if (ai->ai_family == AF_INET) {
		gs->i4 = *(struct sockaddr_in *)ai->ai_addr;
		gs->i4.sin_port = htons(port);
	} else {
		gs->i6 = *(struct sockaddr_in6 *)ai->ai_addr;
		gs->i6.sin6_port = htons(port);
	}
}

/*
 * Collect up to @cap addresses from @res into @out, ordered the way the connect
 * path wants to try them: the preferred family first, then the two families
 * alternating. Alternating matters -- when a family is broken end to end (a
 * black-holed IPv6 route is the usual case), interleaving costs one failed
 * attempt instead of one per address before the working family is reached.
 *
 * Within a family the resolver's own order is preserved; glibc already sorts
 * that per RFC 6724, and the previous code discarded that ordering by scanning
 * for a family.
 *
 * @out[0] is the address the old single-shot selection would have returned, so
 * callers that only look at the first entry keep their existing behaviour.
 *
 * The names are resolved without a service, so @port is filled in here.
 *
 * Returns the number of addresses written.
 */
static uint8_t collect_addr_list(struct addrinfo *res, struct gwp_sockaddr *out,
				 uint8_t cap, uint32_t rt, uint16_t port)
{
	const struct addrinfo *v4[GWP_DNS_MAX_ADDRS];
	const struct addrinfo *v6[GWP_DNS_MAX_ADDRS];
	uint8_t nr_v4 = 0, nr_v6 = 0, n = 0, i;
	const struct addrinfo *ai;
	bool v6_first;

	if (!res || !cap)
		return 0;

	if (cap > GWP_DNS_MAX_ADDRS)
		cap = GWP_DNS_MAX_ADDRS;

	for (ai = res; ai; ai = ai->ai_next) {
		if (ai->ai_family == AF_INET) {
			if (rt != GWP_DNS_RESTYP_IPV6_ONLY && nr_v4 < cap)
				v4[nr_v4++] = ai;
		} else if (ai->ai_family == AF_INET6) {
			if (rt != GWP_DNS_RESTYP_IPV4_ONLY && nr_v6 < cap)
				v6[nr_v6++] = ai;
		}
	}

	/*
	 * DEFAULT leads with IPv4 to match fetch_addr()'s DEFAULT handling, so
	 * a cache hit and a cache miss agree on the first address.
	 */
	v6_first = (rt == GWP_DNS_RESTYP_PREFER_IPV6);

	for (i = 0; n < cap && (i < nr_v4 || i < nr_v6); i++) {
		const struct addrinfo *a, *b;

		a = v6_first ? (i < nr_v6 ? v6[i] : NULL)
			     : (i < nr_v4 ? v4[i] : NULL);
		b = v6_first ? (i < nr_v4 ? v4[i] : NULL)
			     : (i < nr_v6 ? v6[i] : NULL);

		if (a)
			copy_ai_addr(&out[n++], a, port);
		if (b && n < cap)
			copy_ai_addr(&out[n++], b, port);
	}

	return n;
}

static void prep_hints(struct addrinfo *hints, uint32_t restyp)
{
	memset(hints, 0, sizeof(*hints));
	hints->ai_family = AF_UNSPEC;
	hints->ai_socktype = SOCK_STREAM;
	hints->ai_flags = AI_ADDRCONFIG;

	if (restyp == GWP_DNS_RESTYP_IPV4_ONLY)
		hints->ai_family = AF_INET;
	else if (restyp == GWP_DNS_RESTYP_IPV6_ONLY)
		hints->ai_family = AF_INET6;
}

static void try_pass_result_to_cache(struct gwp_dns_ctx *ctx, const char *name,
				     const struct addrinfo *ai)
{
	int x;

	if (!ctx->cache)
		return;

	x = ctx->cfg.cache_expiry;
	gwp_dns_cache_insert(ctx->cache, name, ai, time(NULL) + x);
}

/*
 * Remember for a short while that @name does not resolve, so a client that
 * retries, or a page full of links to a dead host, does not cost a full
 * resolution each time. Never longer than positive answers are kept.
 */
#define GWP_DNS_NEG_TTL			30
#define GWP_DNS_NEG_TTL_TRANSIENT	5

static void cache_failure(struct gwp_dns_ctx *ctx, const char *name,
			  bool transient)
{
	int ttl = transient ? GWP_DNS_NEG_TTL_TRANSIENT : GWP_DNS_NEG_TTL;

	if (!ctx->cache)
		return;

	if (ttl > ctx->cfg.cache_expiry)
		ttl = ctx->cfg.cache_expiry;
	gwp_dns_cache_insert(ctx->cache, name, NULL, time(NULL) + ttl);
}

/*
 * Resolve @name into @addrs/@nr_addrs. On success *@res_p holds the
 * getaddrinfo() result, which the caller passes to the cache and frees.
 */
static int resolve(const char *name, uint16_t port, struct gwp_sockaddr *addrs,
		   uint8_t cap, uint8_t *nr_addrs, uint32_t restyp,
		   struct addrinfo **res_p, bool *transient)
{
	struct addrinfo *res = NULL, hints;
	uint8_t n;
	int r;

	*res_p = NULL;
	*nr_addrs = 0;
	*transient = false;
	prep_hints(&hints, restyp);
	r = getaddrinfo(name, NULL, &hints, &res);
	if (r) {
		/*
		 * "No such name" and "no address of the family asked for"
		 * are answers; anything else (a timeout, SERVFAIL, a local
		 * error) may well go away by itself.
		 */
		*transient = r != EAI_NONAME && r != EAI_NODATA &&
			     r != EAI_ADDRFAMILY;
		return -EHOSTUNREACH;
	}

	n = collect_addr_list(res, addrs, cap, restyp, port);
	if (!n) {
		freeaddrinfo(res);
		return -EHOSTUNREACH;
	}

	*res_p = res;
	*nr_addrs = n;
	return 0;
}

int gwp_dns_resolve(struct gwp_dns_ctx *ctx, const char *name,
		    uint16_t port, struct gwp_sockaddr *addrs,
		    uint8_t cap, uint8_t *nr_addrs, uint32_t restyp)
{
	struct addrinfo *res;
	bool transient;
	int r;

	r = resolve(name, port, addrs, cap, nr_addrs, restyp, &res, &transient);
	if (r)
		return r;

	try_pass_result_to_cache(ctx, name, res);
	freeaddrinfo(res);
	return 0;
}

void gwp_dns_entry_free(struct gwp_dns_entry *e)
{
	free(e);
}

void gwp_dns_entry_cancel(struct gwp_dns_entry *e)
{
	if (e)
		atomic_store_explicit(&e->cancelled, true, memory_order_relaxed);
}

/*
 * Hand a finished entry to its event loop, or free it if nobody waits for it
 * any more. The release CAS publishes the result fields along with it.
 */
static void deliver_entry(struct gwp_dns_entry *e)
{
	struct gwp_dns_cq *cq = e->cq;
	struct gwp_dns_entry *old;
	static const uint64_t one = 1;
	ssize_t r;

	if (gwp_dns_entry_cancelled(e)) {
		gwp_dns_entry_free(e);
		return;
	}

	old = atomic_load_explicit(&cq->head, memory_order_relaxed);
	do {
		e->next = old;
	} while (!atomic_compare_exchange_weak_explicit(&cq->head, &old, e,
							memory_order_release,
							memory_order_relaxed));

	/*
	 * Only the push onto an empty list signals: until the loop takes the
	 * list, that one wakeup covers whatever is pushed after it.
	 *
	 * The write needs no handling beyond the EINTR retry. Adding 1 to an
	 * eventfd fails only with EAGAIN, when the counter would pass
	 * 2^64 - 2, and here it stays tiny: it is written only on this
	 * transition and reset by every gwp_dns_cq_pop(). Anything else
	 * (EBADF, EINVAL) would be a bug, not a runtime condition: the
	 * eventfd lives until gwp_dns_ctx_free(), after the resolver threads
	 * are joined.
	 */
	if (!old) {
		do {
			r = __sys_write(cq->efd, &one, sizeof(one));
		} while (r == -EINTR);
		assert(r == (ssize_t)sizeof(one));
	}
}

struct gwp_dns_entry *gwp_dns_cq_pop(struct gwp_dns_ctx *ctx, uint32_t cq_idx)
{
	struct gwp_dns_cq *cq = &ctx->cqs[cq_idx];
	struct gwp_dns_entry *e, *next, *head = NULL;
	uint64_t val;
	ssize_t r;

	/*
	 * Clear the eventfd before taking the list: a push that lands after
	 * the exchange finds the list empty and writes it again.
	 */
	do {
		r = __sys_read(cq->efd, &val, sizeof(val));
	} while (r == -EINTR);

	e = atomic_exchange_explicit(&cq->head, NULL, memory_order_acquire);

	/* Reverse into completion order, dropping what was cancelled. */
	for (; e; e = next) {
		next = e->next;
		if (gwp_dns_entry_cancelled(e)) {
			gwp_dns_entry_free(e);
			continue;
		}
		e->next = head;
		head = e;
	}

	return head;
}

int gwp_dns_cq_fd(struct gwp_dns_ctx *ctx, uint32_t cq_idx)
{
	return ctx->cqs[cq_idx].efd;
}

/*
 * Must be called with ctx->lock held. May release the lock, but it
 * will reacquire it before returning.
 *
 * If the DNS cache is enabled, do:
 *   - Compare the last scan time with the current time.
 *   - If it's more than ctx->cfg.cache_expiry seconds ago, scan the
 *     cache to find expired entries and delete them.
 *   - Save the current time as the last scan time.
 */
static void cond_scan_cache(struct gwp_dns_ctx *ctx)
{
	if (!ctx->cache)
		return;

	if (time(NULL) - ctx->last_scan < ctx->cfg.cache_expiry)
		return;

	/* Claim this round, so no other thread starts one meanwhile. */
	ctx->last_scan = time(NULL);
	pthread_mutex_unlock(&ctx->lock);
	gwp_dns_cache_housekeep(ctx->cache);
	pthread_mutex_lock(&ctx->lock);

	/*
	 * Call time(NULL) again because the scan might have taken
	 * several seconds if the number of entries is large or
	 * it got contended by other threads.
	 */
	ctx->last_scan = time(NULL);
}

/*
 * Must be called with ctx->lock held. How many queued lookups a thread could
 * take right now. A client's first lookup can take any thread; the others only
 * those not kept for such a lookup.
 */
static uint32_t nr_takeable(const struct gwp_dns_ctx *ctx)
{
	return ctx->nr_running < ctx->max_any_running ? ctx->nr_ready
						      : ctx->nr_first;
}

static bool is_persistent(const struct gwp_dns_thr *t)
{
	return t->id < t->ctx->cfg.nr_workers;
}

/*
 * Must be called with ctx->lock held. Sleep until there is work or a stop.
 * Returns false when the calling thread should exit because it was idle for
 * too long; only the threads started on demand do.
 *
 * With the cache on, the persistent threads also wake on their own to sweep
 * it (cond_scan_cache()), so expired entries are reclaimed without traffic.
 */
static bool wait_for_queue_entry(struct gwp_dns_thr *t)
{
	struct gwp_dns_ctx *ctx = t->ctx;
	bool persistent = is_persistent(t);
	struct timespec ts;
	int r = 0;

	ctx->nr_sleeping++;
	if (persistent && !ctx->cache) {
		pthread_cond_wait(&ctx->cond, &ctx->lock);
	} else {
		clock_gettime(CLOCK_MONOTONIC, &ts);
		ts.tv_sec += persistent ? ctx->cfg.cache_expiry : GWP_DNS_IDLE_SECS;
		r = pthread_cond_timedwait(&ctx->cond, &ctx->lock, &ts);
	}
	ctx->nr_sleeping--;

	if (r == ETIMEDOUT && !persistent && !nr_takeable(ctx))
		return false;

	cond_scan_cache(ctx);
	return true;
}

static bool all_cancelled(const struct gwp_dns_entry *e)
{
	for (; e; e = e->next) {
		if (!gwp_dns_entry_cancelled((struct gwp_dns_entry *)e))
			return false;
	}
	return true;
}

static void unhash_lookup(struct gwp_dns_ctx *ctx, struct dns_lookup *l)
{
	struct dns_lookup **pp;

	pp = &ctx->inflight[l->hash & (GWP_DNS_INFLIGHT_BUCKETS - 1)];
	while (*pp != l)
		pp = &(*pp)->hnext;
	*pp = l->hnext;
}

static void turn_add(struct gwp_dns_ctx *ctx, struct dns_client *c, int t)
{
	struct dns_turns *turns = &ctx->turns[t];

	if (c->on_turn[t])
		return;

	c->on_turn[t] = true;
	c->tnext[t] = NULL;
	c->tprev[t] = turns->tail;
	if (turns->tail)
		turns->tail->tnext[t] = c;
	else
		turns->head = c;
	turns->tail = c;
}

static void turn_del(struct gwp_dns_ctx *ctx, struct dns_client *c, int t)
{
	struct dns_turns *turns = &ctx->turns[t];

	if (!c->on_turn[t])
		return;

	c->on_turn[t] = false;
	if (c->tprev[t])
		c->tprev[t]->tnext[t] = c->tnext[t];
	else
		turns->head = c->tnext[t];
	if (c->tnext[t])
		c->tnext[t]->tprev[t] = c->tprev[t];
	else
		turns->tail = c->tprev[t];
}

/*
 * Must be called with ctx->lock held, after any change to @c's counts: bring
 * its share of ctx->nr_ready and ctx->nr_first and its place on the lists up to
 * date, and free it if nothing is left of it. @c must not be used afterwards
 * unless it is known to still have a lookup.
 */
static void settle_client(struct gwp_dns_ctx *ctx, struct dns_client *c)
{
	uint32_t room = 0, ready;
	struct dns_client **pp;
	bool first;

	if (c->nr_running < ctx->max_client_running)
		room = ctx->max_client_running - c->nr_running;
	ready = c->nr_queued < room ? c->nr_queued : room;
	ctx->nr_ready += ready;
	ctx->nr_ready -= c->nr_ready;
	c->nr_ready = ready;

	first = c->nr_queued && !c->nr_running;
	ctx->nr_first += first;
	ctx->nr_first -= c->first;
	c->first = first;

	if (ready)
		turn_add(ctx, c, DNS_TURN_ANY);
	else
		turn_del(ctx, c, DNS_TURN_ANY);
	if (first)
		turn_add(ctx, c, DNS_TURN_FIRST);
	else
		turn_del(ctx, c, DNS_TURN_FIRST);

	if (c->nr_queued || c->nr_running)
		return;

	pp = &ctx->clients[c->hash & (GWP_DNS_CLIENT_BUCKETS - 1)];
	while (*pp != c)
		pp = &(*pp)->hnext;
	*pp = c->hnext;
	free(c);
}

static void enqueue_lookup(struct dns_client *c, struct dns_lookup *l)
{
	l->client = c;
	l->qnext = NULL;
	l->qprev = c->qtail;
	if (c->qtail)
		c->qtail->qnext = l;
	else
		c->qhead = l;
	c->qtail = l;
	c->nr_queued++;
}

static void dequeue_lookup(struct dns_lookup *l)
{
	struct dns_client *c = l->client;

	if (l->qprev)
		l->qprev->qnext = l->qnext;
	else
		c->qhead = l->qnext;
	if (l->qnext)
		l->qnext->qprev = l->qprev;
	else
		c->qtail = l->qprev;
	c->nr_queued--;
}

/*
 * Must be called with ctx->lock held and nr_takeable() non-zero. Take the next
 * lookup, from the client whose turn it is.
 */
static struct dns_lookup *take_lookup(struct gwp_dns_ctx *ctx)
{
	int t = ctx->nr_first ? DNS_TURN_FIRST : DNS_TURN_ANY;
	struct dns_client *c = ctx->turns[t].head;
	struct dns_lookup *l;

	/* To the end of the list by settle_client(), if it has more to take. */
	turn_del(ctx, c, t);

	l = c->qhead;
	dequeue_lookup(l);
	l->running = true;
	c->nr_running++;
	ctx->nr_running++;
	ctx->nr_entries--;
	settle_client(ctx, c);
	return l;
}

/* Must be called with ctx->lock held. A thread is done with @l. */
static void finish_lookup(struct gwp_dns_ctx *ctx, struct dns_lookup *l)
{
	unhash_lookup(ctx, l);
	l->client->nr_running--;
	ctx->nr_running--;
	settle_client(ctx, l->client);
}

/*
 * Give every waiter in @e its copy of the result, with its own port, and
 * deliver it.
 */
static void deliver_waiters(struct gwp_dns_entry *e, int res,
			    const struct gwp_sockaddr *addrs, uint8_t nr)
{
	struct gwp_dns_entry *next;
	uint8_t i;

	for (; e; e = next) {
		next = e->next;
		e->res = res;
		e->nr_addrs = nr;
		for (i = 0; i < nr; i++) {
			e->addrs[i] = addrs[i];
			/* sin_port and sin6_port share an offset. */
			e->addrs[i].i4.sin_port = htons(e->port);
		}
		deliver_entry(e);
	}
}

/*
 * Must be called with ctx->lock held. May release the lock, but
 * it will reacquire it before returning.
 */
static void process_queue_entry(struct gwp_dns_ctx *ctx)
{
	struct gwp_sockaddr addrs[GWP_DNS_MAX_ADDRS];
	struct dns_lookup *l = take_lookup(ctx);
	struct gwp_dns_entry *w;
	struct addrinfo *res;
	bool transient;
	uint8_t nr;
	int r;

	if (all_cancelled(l->waiters)) {
		/*
		 * Nobody cares about the result any more. Drop the lookup
		 * without resolving the name.
		 */
		finish_lookup(ctx, l);
		pthread_mutex_unlock(&ctx->lock);
		free_all_entries(l->waiters);
		free(l);
		pthread_mutex_lock(&ctx->lock);
		return;
	}
	pthread_mutex_unlock(&ctx->lock);

	r = resolve(l->key, 0, addrs, GWP_DNS_MAX_ADDRS, &nr,
		    ctx->cfg.restyp, &res, &transient);

	/*
	 * Deliver first: the cache insert takes the write lock and
	 * allocates, and the clients have no reason to wait for either.
	 * The lookup stays in the table meanwhile, so requests arriving
	 * now still attach to it rather than miss both it and the cache;
	 * they are delivered in the second round.
	 */
	pthread_mutex_lock(&ctx->lock);
	w = l->waiters;
	l->waiters = NULL;
	pthread_mutex_unlock(&ctx->lock);
	deliver_waiters(w, r, addrs, nr);

	if (!r) {
		try_pass_result_to_cache(ctx, l->key, res);
		freeaddrinfo(res);
	} else {
		cache_failure(ctx, l->key, transient);
	}

	pthread_mutex_lock(&ctx->lock);
	w = l->waiters;
	finish_lookup(ctx, l);
	pthread_mutex_unlock(&ctx->lock);
	deliver_waiters(w, r, addrs, nr);
	free(l);

	pthread_mutex_lock(&ctx->lock);
}

static void *gwp_dns_thread_entry(void *arg)
{
	struct gwp_dns_thr *t = arg;
	struct gwp_dns_ctx *ctx = t->ctx;

	pthread_mutex_lock(&ctx->lock);
	while (!ctx->should_stop) {
		if (nr_takeable(ctx)) {
			process_queue_entry(ctx);
			continue;
		}

		if (!wait_for_queue_entry(t)) {
			t->state = GWP_DNS_THR_EXITED;
			break;
		}
	}
	ctx->nr_threads--;
	pthread_mutex_unlock(&ctx->lock);

	return NULL;
}

/*
 * Must be called with ctx->lock held. Start a thread in slot @t, reaping the
 * one that exited there before.
 */
static int start_thread(struct gwp_dns_ctx *ctx, struct gwp_dns_thr *t)
{
	int r;

	/*
	 * It marked itself EXITED under the lock and only has to return,
	 * which needs no lock, so this does not wait for long.
	 */
	if (t->state == GWP_DNS_THR_EXITED) {
		pthread_join(t->thread, NULL);
		t->state = GWP_DNS_THR_FREE;
	}

	t->ctx = ctx;
	r = pthread_create(&t->thread, NULL, gwp_dns_thread_entry, t);
	if (r)
		return -r;

	t->state = GWP_DNS_THR_RUNNING;
	ctx->nr_threads++;
	return 0;
}

/*
 * Must be called with ctx->lock held. More lookups are queued than threads
 * are free to take them: start one more thread, unless all are running. A
 * failure is not fatal; the threads already running serve the queue.
 */
static void maybe_grow(struct gwp_dns_ctx *ctx)
{
	uint32_t i;

	if (nr_takeable(ctx) <= ctx->nr_sleeping)
		return;
	if (ctx->nr_threads >= ctx->max_threads)
		return;

	for (i = ctx->cfg.nr_workers; i < ctx->max_threads; i++) {
		struct gwp_dns_thr *t = &ctx->threads[i];

		if (t->state != GWP_DNS_THR_RUNNING) {
			start_thread(ctx, t);
			return;
		}
	}
}

static void free_threads(struct gwp_dns_ctx *ctx)
{
	uint32_t i;

	if (!ctx->threads)
		return;

	/*
	 * Nothing queues lookups any more, so no slot leaves FREE from here
	 * on; a RUNNING one may still turn EXITED, which needs joining too.
	 */
	pthread_mutex_lock(&ctx->lock);
	ctx->should_stop = true;
	pthread_cond_broadcast(&ctx->cond);
	for (i = 0; i < ctx->max_threads; i++)
		ctx->threads[i].join = ctx->threads[i].state != GWP_DNS_THR_FREE;
	pthread_mutex_unlock(&ctx->lock);

	for (i = 0; i < ctx->max_threads; i++) {
		if (ctx->threads[i].join)
			pthread_join(ctx->threads[i].thread, NULL);
	}

	free(ctx->threads);
	ctx->threads = NULL;
}

static int init_threads(struct gwp_dns_ctx *ctx)
{
	uint32_t i;
	int r = 0;

	if (ctx->cfg.nr_workers == 0)
		return -EINVAL;

	ctx->max_threads = ctx->cfg.nr_workers;
	if (ctx->max_threads < GWP_DNS_MAX_THREADS)
		ctx->max_threads = GWP_DNS_MAX_THREADS;
	ctx->max_client_running = ctx->max_threads / 2;
	ctx->max_any_running = ctx->max_threads - ctx->max_threads / 4;

	ctx->threads = calloc(ctx->max_threads, sizeof(*ctx->threads));
	if (!ctx->threads)
		return -ENOMEM;

	for (i = 0; i < ctx->max_threads; i++)
		ctx->threads[i].id = i;

	pthread_mutex_lock(&ctx->lock);
	for (i = 0; i < ctx->cfg.nr_workers; i++) {
		r = start_thread(ctx, &ctx->threads[i]);
		if (r)
			break;
	}
	pthread_mutex_unlock(&ctx->lock);

	if (r)
		free_threads(ctx);

	return r;
}

int gwp_dns_cache_lookup(struct gwp_dns_ctx *ctx, const char *name,
			 uint16_t port, struct gwp_sockaddr *addr)
{
	uint8_t nr;

	return gwp_dns_cache_lookup_list(ctx, name, port, addr, 1, &nr);
}

/* Size the bucket array from the entry cap for a ~1.0 load factor, clamped to
 * a sane range; fall back to a fixed size when the cap is unlimited (0). */
static uint32_t cache_bucket_count(uint32_t max_entries)
{
	uint32_t n = max_entries ? max_entries : 65536;

	if (n < 1024)
		n = 1024;
	else if (n > (1u << 20))
		n = (1u << 20);
	return n;
}

/* A hit must be able to fill a whole list from one family. */
_Static_assert(GWP_DNS_CACHE_MAX_ADDRS >= GWP_DNS_MAX_ADDRS,
	       "the cache hands back fewer addresses than a lookup returns");

static void fill_i4(struct gwp_sockaddr *addr, const struct in_addr *a,
		    uint16_t port)
{
	memset(addr, 0, sizeof(*addr));
	addr->i4.sin_family = AF_INET;
	addr->i4.sin_port = htons(port);
	addr->i4.sin_addr = *a;
}

static void fill_i6(struct gwp_sockaddr *addr, const struct in6_addr *a,
		    uint16_t port)
{
	memset(addr, 0, sizeof(*addr));
	addr->i6.sin6_family = AF_INET6;
	addr->i6.sin6_port = htons(port);
	addr->i6.sin6_addr = *a;
}

int gwp_dns_cache_lookup_list(struct gwp_dns_ctx *ctx, const char *name,
			      uint16_t port, struct gwp_sockaddr *addrs,
			      uint8_t cap, uint8_t *nr_addrs)
{
	struct gwp_dns_cache_addrs ca;
	uint8_t nr_v4, nr_v6, n = 0, i;
	uint32_t rt = ctx->cfg.restyp;
	bool v6_first;
	int r;

	if (!ctx->cache)
		return -ENOSYS;
	if (!cap)
		return -EINVAL;
	if (cap > GWP_DNS_MAX_ADDRS)
		cap = GWP_DNS_MAX_ADDRS;

	r = gwp_dns_cache_lookup_addrs(ctx->cache, name, &ca);
	if (r)
		return r;

	nr_v4 = (rt == GWP_DNS_RESTYP_IPV6_ONLY) ? 0 : ca.nr_i4;
	nr_v6 = (rt == GWP_DNS_RESTYP_IPV4_ONLY) ? 0 : ca.nr_i6;

	/* Same interleave and the same leading family as collect_addr_list(). */
	v6_first = (rt == GWP_DNS_RESTYP_PREFER_IPV6);

	for (i = 0; n < cap && (i < nr_v4 || i < nr_v6); i++) {
		if (v6_first) {
			if (i < nr_v6)
				fill_i6(&addrs[n++], &ca.i6[i], port);
			if (i < nr_v4 && n < cap)
				fill_i4(&addrs[n++], &ca.i4[i], port);
		} else {
			if (i < nr_v4)
				fill_i4(&addrs[n++], &ca.i4[i], port);
			if (i < nr_v6 && n < cap)
				fill_i6(&addrs[n++], &ca.i6[i], port);
		}
	}

	*nr_addrs = n;
	return n ? 0 : -EHOSTUNREACH;
}

static int init_cache(struct gwp_dns_ctx *ctx)
{
	uint32_t max = ctx->cfg.max_entries;
	struct gwp_dns_cache *cache;
	int r;

	if (ctx->cfg.cache_expiry <= 0) {
		/*
		 * Cache is disabled.
		 */
		ctx->cache = NULL;
		return 0;
	}

	r = gwp_dns_cache_init(&cache, cache_bucket_count(max), max);
	if (r)
		return r;

	ctx->cache = cache;
	return 0;
}

static void free_cache(struct gwp_dns_cache *cache)
{
	if (!cache)
		return;

	gwp_dns_cache_free(cache);
}

static inline bool validate_restyp(int restyp)
{
	switch (restyp) {
	case GWP_DNS_RESTYP_DEFAULT:
	case GWP_DNS_RESTYP_IPV4_ONLY:
	case GWP_DNS_RESTYP_IPV6_ONLY:
	case GWP_DNS_RESTYP_PREFER_IPV4:
	case GWP_DNS_RESTYP_PREFER_IPV6:
		return true;
	default:
		return false;
	}
}

static void free_cqs(struct gwp_dns_ctx *ctx)
{
	uint32_t i;

	if (!ctx->cqs)
		return;

	for (i = 0; i < ctx->cfg.nr_cqs; i++) {
		struct gwp_dns_cq *cq = &ctx->cqs[i];

		free_all_entries(atomic_load(&cq->head));
		if (cq->efd >= 0)
			__sys_close(cq->efd);
	}

	free(ctx->cqs);
	ctx->cqs = NULL;
}

static int init_cqs(struct gwp_dns_ctx *ctx)
{
	uint32_t i;
	int fd;

	if (!ctx->cfg.nr_cqs)
		return -EINVAL;

	ctx->cqs = calloc(ctx->cfg.nr_cqs, sizeof(*ctx->cqs));
	if (!ctx->cqs)
		return -ENOMEM;

	for (i = 0; i < ctx->cfg.nr_cqs; i++)
		ctx->cqs[i].efd = -1;

	for (i = 0; i < ctx->cfg.nr_cqs; i++) {
		atomic_init(&ctx->cqs[i].head, NULL);
		fd = __sys_eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
		if (fd < 0) {
			free_cqs(ctx);
			return fd;
		}
		ctx->cqs[i].efd = fd;
	}

	return 0;
}

static void free_all_queued_entries(struct gwp_dns_ctx *ctx)
{
	struct dns_client *c, *cnext;
	struct dns_lookup *l, *next;
	uint32_t i;

	for (i = 0; i < GWP_DNS_CLIENT_BUCKETS; i++) {
		for (c = ctx->clients[i]; c; c = cnext) {
			cnext = c->hnext;
			for (l = c->qhead; l; l = next) {
				next = l->qnext;
				free_all_entries(l->waiters);
				free(l);
			}
			free(c);
		}
	}
	free(ctx->clients);
	ctx->clients = NULL;
	free(ctx->inflight);
	ctx->inflight = NULL;
}

/* The idle timeouts are intervals, so measure them on the monotonic clock. */
static int init_cond(pthread_cond_t *cond)
{
	pthread_condattr_t attr;
	int r;

	r = pthread_condattr_init(&attr);
	if (r)
		return -r;

	r = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
	if (!r)
		r = pthread_cond_init(cond, &attr);

	pthread_condattr_destroy(&attr);
	return -r;
}

int gwp_dns_ctx_init(struct gwp_dns_ctx **ctx_p, const struct gwp_dns_cfg *cfg)
{
	struct gwp_dns_ctx *ctx;
	int r;

	if (!validate_restyp(cfg->restyp))
		return -EINVAL;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return -ENOMEM;

	ctx->cfg = *cfg;
	r = pthread_mutex_init(&ctx->lock, NULL);
	if (r) {
		r = -r;
		goto out_free_ctx;
	}

	r = init_cond(&ctx->cond);
	if (r)
		goto out_destroy_mutex;

	r = init_cqs(ctx);
	if (r)
		goto out_destroy_cond;

	ctx->inflight = calloc(GWP_DNS_INFLIGHT_BUCKETS, sizeof(*ctx->inflight));
	ctx->clients = calloc(GWP_DNS_CLIENT_BUCKETS, sizeof(*ctx->clients));
	if (!ctx->inflight || !ctx->clients) {
		r = -ENOMEM;
		goto out_free_cqs;
	}
	gwp_dns_gen_hash_key(ctx->hash_key);

	r = init_cache(ctx);
	if (r)
		goto out_free_cqs;

	ctx->nr_sleeping = 0;
	ctx->nr_entries = 0;
	ctx->nr_threads = 0;
	ctx->threads = NULL;
	ctx->should_stop = false;
	ctx->last_scan = time(NULL);
	r = init_threads(ctx);
	if (r)
		goto out_free_cache;

	*ctx_p = ctx;
	return 0;
out_free_cache:
	free_cache(ctx->cache);
out_free_cqs:
	free(ctx->clients);
	free(ctx->inflight);
	free_cqs(ctx);
out_destroy_cond:
	pthread_cond_destroy(&ctx->cond);
out_destroy_mutex:
	pthread_mutex_destroy(&ctx->lock);
out_free_ctx:
	free(ctx);
	*ctx_p = NULL;
	return r;
}

void gwp_dns_ctx_free(struct gwp_dns_ctx *ctx)
{
	free_threads(ctx);
	pthread_mutex_destroy(&ctx->lock);
	pthread_cond_destroy(&ctx->cond);
	free_all_queued_entries(ctx);
	free_cqs(ctx);
	free_cache(ctx->cache);
	free(ctx);
}

static struct dns_lookup *find_lookup(struct gwp_dns_ctx *ctx,
				      const char *key, size_t len,
				      uint64_t hash)
{
	struct dns_lookup *l;

	l = ctx->inflight[hash & (GWP_DNS_INFLIGHT_BUCKETS - 1)];
	for (; l; l = l->hnext) {
		if (l->hash == hash && l->len == len && !memcmp(l->key, key, len))
			return l;
	}
	return NULL;
}

static struct gwp_dns_entry *alloc_entry(struct gwp_dns_ctx *ctx,
					 uint32_t cq_idx, const char *name,
					 uint16_t port, void *udata)
{
	struct gwp_dns_entry *e;
	size_t nlen;

	if (cq_idx >= ctx->cfg.nr_cqs)
		return NULL;

	/* The name lives in the same allocation. */
	nlen = strlen(name);
	e = malloc(sizeof(*e) + nlen + 1);
	if (!e)
		return NULL;

	e->name = (char *)(e + 1);
	memcpy(e->name, name, nlen + 1);
	e->port = port;
	atomic_init(&e->cancelled, false);
	e->res = 0;
	e->nr_addrs = 0;
	e->cq = &ctx->cqs[cq_idx];
	e->udata = udata;
	return e;
}

struct gwp_dns_entry *gwp_dns_queue_result(struct gwp_dns_ctx *ctx,
					   uint32_t cq_idx, const char *name,
					   uint16_t port, void *udata, int res)
{
	struct gwp_dns_entry *e;

	e = alloc_entry(ctx, cq_idx, name, port, udata);
	if (!e)
		return NULL;

	e->res = res;
	deliver_entry(e);
	return e;
}

/* Must be called with ctx->lock held. */
static struct dns_client *get_client(struct gwp_dns_ctx *ctx,
				     const struct gwp_iplim_key *key)
{
	uint64_t hash = gwp_siphash13(ctx->hash_key, key->b, sizeof(key->b));
	struct dns_client **bucket, *c;

	bucket = &ctx->clients[hash & (GWP_DNS_CLIENT_BUCKETS - 1)];
	for (c = *bucket; c; c = c->hnext) {
		if (c->hash == hash && !memcmp(&c->key, key, sizeof(*key)))
			return c;
	}

	c = calloc(1, sizeof(*c));
	if (!c)
		return NULL;

	c->hash = hash;
	c->key = *key;
	c->hnext = *bucket;
	*bucket = c;
	return c;
}

/*
 * Must be called with ctx->lock held. @e joins @l, the lookup of the name it
 * asks for. Client @c gets no new lookup out of this, so it is not limited.
 *
 * A lookup is queued with the client that asked first, but it now serves @c
 * as well, and that client may have a long queue: left there, one client could
 * make another wait behind its own slow names just by asking for a name the
 * other is about to want. So a lookup still queued moves to the client with
 * less outstanding, which also means that a client with a long queue cannot
 * take one away from a client with a short one.
 */
static void attach_lookup(struct gwp_dns_ctx *ctx, struct dns_lookup *l,
			  struct gwp_dns_entry *e, struct dns_client *c)
{
	struct dns_client *owner = l->client;

	e->next = l->waiters;
	l->waiters = e;

	if (l->running || owner == c ||
	    c->nr_queued + c->nr_running >= owner->nr_queued + owner->nr_running) {
		settle_client(ctx, c);
		return;
	}

	dequeue_lookup(l);
	enqueue_lookup(c, l);
	settle_client(ctx, owner);
	settle_client(ctx, c);
}

struct gwp_dns_entry *gwp_dns_queue(struct gwp_dns_ctx *ctx, uint32_t cq_idx,
				    const char *name, uint16_t port,
				    const struct gwp_iplim_key *client,
				    void *udata)
{
	static const struct gwp_iplim_key no_client;
	struct dns_lookup *l, *nl = NULL;
	struct gwp_dns_entry *e;
	struct dns_client *c;
	char key[256];
	uint64_t hash;
	size_t len;

	e = alloc_entry(ctx, cq_idx, name, port, udata);
	if (!e)
		return NULL;

	/*
	 * No name this long (or empty) resolves, and the cache refuses them
	 * too: fail it at once, through the queue like any other result.
	 */
	len = gwp_dns_fold_name(name, key, sizeof(key));
	if (len <= 1) {
		e->res = -EHOSTUNREACH;
		deliver_entry(e);
		return e;
	}
	len--;
	hash = gwp_siphash13(ctx->hash_key, key, len);

	pthread_mutex_lock(&ctx->lock);
	c = get_client(ctx, client ? client : &no_client);
	if (!c)
		goto out_nomem;

	l = find_lookup(ctx, key, len, hash);
	if (l) {
		attach_lookup(ctx, l, e, c);
		goto out_kick;
	}

	/*
	 * Not cached as a failure: nothing is known about the name, and the
	 * next client to ask for it may well get an answer.
	 */
	if (c->nr_queued >= GWP_DNS_MAX_QUEUED_PER_CLIENT ||
	    ctx->nr_entries >= GWP_DNS_MAX_QUEUED) {
		settle_client(ctx, c);
		pthread_mutex_unlock(&ctx->lock);
		e->res = -EHOSTUNREACH;
		deliver_entry(e);
		return e;
	}

	nl = malloc(sizeof(*nl) + len + 1);
	if (!nl) {
		settle_client(ctx, c);
		goto out_nomem;
	}

	memcpy(nl->key, key, len + 1);
	nl->len = len;
	nl->hash = hash;
	nl->running = false;
	e->next = NULL;
	nl->waiters = e;
	nl->hnext = ctx->inflight[hash & (GWP_DNS_INFLIGHT_BUCKETS - 1)];
	ctx->inflight[hash & (GWP_DNS_INFLIGHT_BUCKETS - 1)] = nl;

	enqueue_lookup(c, nl);
	ctx->nr_entries++;
	settle_client(ctx, c);
out_kick:
	if (nr_takeable(ctx)) {
		if (ctx->nr_sleeping)
			pthread_cond_signal(&ctx->cond);
		maybe_grow(ctx);
	}
	pthread_mutex_unlock(&ctx->lock);
	return e;

out_nomem:
	pthread_mutex_unlock(&ctx->lock);
	free(e);
	return NULL;
}
