// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "dns.h"

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
#include <signal.h>

#include <pthread.h>
#include <sys/eventfd.h>

struct gwp_dns_ctx;

struct gwp_dns_wrk {
	struct gwp_dns_ctx	*ctx;
	uint32_t		id;
	pthread_t		thread;
};

struct cache_entry {
	char			*name;
	char			*service;
	struct addrinfo		*res;		/* Cached result.   */
	time_t			expired_at;	/* Expiration time. */
};

struct gwp_dns_cache {
	pthread_rwlock_t	lock;		/* Lock for the cache. */
	struct cache_entry	*entries;	/* Array of entries. */
	uint32_t		nr;		/* Number of entries. */
	uint32_t		cap;		/* Capacity of the array. */
	time_t			last_scan;	/* Last scan time. */
};

struct gwp_dns_ctx {
	volatile bool		should_stop;
	pthread_mutex_t		lock;
	pthread_cond_t		cond;
	uint32_t		nr_sleeping;
	uint32_t		nr_entries;
	struct gwp_dns_entry	*head;
	struct gwp_dns_entry	*tail;
	struct gwp_dns_wrk	*workers;
	struct gwp_dns_cache	*cache;
	struct gwp_dns_cfg	cfg;
};

static void put_all_entries(struct gwp_dns_entry *head)
{
	struct gwp_dns_entry *e, *next;

	for (e = head; e; e = next) {
		next = e->next;
		gwp_dns_entry_put(e);
	}
}

static bool iterate_addr_list(struct addrinfo *res, struct gwp_sockaddr *gs,
			      uint32_t rt)
{
	struct addrinfo *ai;

	if (!res)
		return false;

	/*
	 * Handle IPV4_ONLY and IPV6_ONLY cases together.
	 */
	if (rt == GWP_DNS_RESTYP_IPV4_ONLY ||
	    rt == GWP_DNS_RESTYP_IPV6_ONLY) {
		int fm = (rt == GWP_DNS_RESTYP_IPV4_ONLY) ? AF_INET : AF_INET6;

		for (ai = res; ai; ai = ai->ai_next) {
			if (ai->ai_family != fm)
				continue;
			if (fm == AF_INET)
				gs->i4 = *(struct sockaddr_in *)ai->ai_addr;
			else
				gs->i6 = *(struct sockaddr_in6 *)ai->ai_addr;
			return true;
		}
		return false;
	}

	/*
	 * Handle PREFER_IPV6 and PREFER_IPV4 cases together.
	 */
	if (rt == GWP_DNS_RESTYP_PREFER_IPV6 ||
	    rt == GWP_DNS_RESTYP_PREFER_IPV4) {
		int prm = (rt == GWP_DNS_RESTYP_PREFER_IPV6) ? AF_INET6
							     : AF_INET;
		int sec = (prm == AF_INET6) ? AF_INET : AF_INET6;
		struct sockaddr *fallback = NULL;

		for (ai = res; ai; ai = ai->ai_next) {
			if (ai->ai_family != prm) {
				if (ai->ai_family == sec && !fallback)
					fallback = ai->ai_addr;
				continue;
			}

			if (prm == AF_INET)
				gs->i4 = *(struct sockaddr_in *)ai->ai_addr;
			else
				gs->i6 = *(struct sockaddr_in6 *)ai->ai_addr;
			return true;
		}

		if (!fallback)
			return false;

		if (sec == AF_INET)
			gs->i4 = *(struct sockaddr_in *)fallback;
		else
			gs->i6 = *(struct sockaddr_in6 *)fallback;

		return true;
	}

	/*
	 * Default case: first available address (IPv4 or IPv6).
	 */
	for (ai = res; ai; ai = ai->ai_next) {
		if (ai->ai_family == AF_INET) {
			gs->i4 = *(struct sockaddr_in *)ai->ai_addr;
			return true;
		} else if (ai->ai_family == AF_INET6) {
			gs->i6 = *(struct sockaddr_in6 *)ai->ai_addr;
			return true;
		}
	}

	return false;
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

static void free_cache_entry(struct cache_entry *e)
{
	if (!e)
		return;

	free(e->name);
	if (e->res)
		freeaddrinfo(e->res);
}

static void gwp_dns_cache_scan_and_delete_expired_entries(struct gwp_dns_cache *cache)
{
	uint32_t i;

	pthread_rwlock_wrlock(&cache->lock);
	for (i = 0; i < cache->nr; i++) {
		struct cache_entry *last, *e = &cache->entries[i];
		time_t now = time(NULL);

		if (e->expired_at > now)
			continue;

		free_cache_entry(e);
		last = &cache->entries[--cache->nr];
		if (e != last) {
			/*
			 * Move the last entry to the current position
			 * to avoid holes in the array.
			 */
			*e = *last;
		} else {
			/*
			 * If the last entry is the one we are deleting,
			 * just clear it.
			 */
			memset(e, 0, sizeof(*e));
		}

		/*
		 * The next iteration will check the current index
		 * again as it now contains an untraversed entry
		 * that may also be expired.
		 */
		i--;
	}
	pthread_rwlock_unlock(&cache->lock);
}

static int gwp_dns_cache_insert(struct gwp_dns_ctx *ctx, const char *name,
				const char *service, struct addrinfo *res)
{
	struct gwp_dns_cache *cache = ctx->cache;
	char *cname, *cservice;
	struct cache_entry *e;
	size_t nl, sl;
	int r;

	if (!cache)
		return -ENOSYS;

	pthread_rwlock_wrlock(&cache->lock);
	if (cache->nr >= cache->cap) {
		size_t new_cap = cache->cap ? cache->cap * 2 : 16;
		struct cache_entry *nentries;

		nentries = realloc(cache->entries, new_cap * sizeof(*nentries));
		if (!nentries) {
			r = -ENOMEM;
			goto out;
		}

		cache->entries = nentries;
		cache->cap = new_cap;
	}

	nl = strlen(name);
	sl = service ? strlen(service) : 0;
	cname = malloc(nl + 1 + sl + 1);
	if (!cname) {
		r = -ENOMEM;
		goto out;
	}

	cservice = cname + nl + 1;
	memcpy(cname, name, nl + 1);
	if (service)
		memcpy(cservice, service, sl + 1);
	else
		cservice[0] = '\0';

	e = &cache->entries[cache->nr++];
	e->name = cname;
	e->service = cservice;
	e->res = res;
	e->expired_at = time(NULL) + ctx->cfg.cache_expiry;
	r = 0;
out:
	pthread_rwlock_unlock(&cache->lock);
	return r;
}

/**
 * Try to pass the result of the DNS resolution to the cache. If successful,
 * the `ai` pointer is owned by the cache and the caller MUST not free it.
 *
 * @param ctx		The DNS context.
 * @param name		Name of the DNS entry.
 * @param service	Service of the DNS entry.
 * @param ai		The addrinfo result to be cached.
 * @return		True if the result was successfully passed to the
 *			cache, false otherwise.
 */
static bool try_pass_result_to_cache(struct gwp_dns_ctx *ctx, const char *name,
				     const char *service, struct addrinfo *ai)
{
	if (!ctx->cache)
		return false;

	return gwp_dns_cache_insert(ctx, name, service, ai) == 0;
}

int gwp_dns_resolve(struct gwp_dns_ctx *ctx, const char *name,
		    const char *service, struct gwp_sockaddr *addr,
		    uint32_t restyp)
{
	struct addrinfo *res = NULL, hints;
	bool found;
	int r;

	prep_hints(&hints, restyp);
	r = getaddrinfo(name, service, &hints, &res);
	if (r)
		return -r;

	found = iterate_addr_list(res, addr, restyp);
	if (found) {
		if (try_pass_result_to_cache(ctx, name, service, res))
			res = NULL;
	}

	if (res)
		freeaddrinfo(res);

	return found ? 0 : -EHOSTUNREACH;
}

static void gwp_dns_entry_free(struct gwp_dns_entry *e)
{
	if (!e)
		return;

	assert(e->ev_fd >= 0);
	close(e->ev_fd);
	free(e->name);
	free(e);
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

	if (time(NULL) - ctx->cache->last_scan < ctx->cfg.cache_expiry)
		return;

	pthread_mutex_unlock(&ctx->lock);
	gwp_dns_cache_scan_and_delete_expired_entries(ctx->cache);
	pthread_mutex_lock(&ctx->lock);

	/*
	 * Call time(NULL) again because the scan might have taken
	 * several seconds if the number of entries is large or
	 * it got contended by other threads.
	 */
	ctx->cache->last_scan = time(NULL);
}

/*
 * Must be called with ctx->lock held.
 */
static void wait_for_queue_entry(struct gwp_dns_ctx *ctx)
{
	ctx->nr_sleeping++;
	pthread_cond_wait(&ctx->cond, &ctx->lock);
	ctx->nr_sleeping--;
	cond_scan_cache(ctx);
}

/*
 * Must be called with ctx->lock held.
 */
static struct gwp_dns_entry *unplug_queue_list(struct gwp_dns_ctx *ctx)
{
	struct gwp_dns_entry *head = ctx->head;

	ctx->head = ctx->tail = NULL;
	ctx->nr_entries = 0;
	return head;
}

struct dbq_entry {
	struct gwp_dns_entry	*e;
	struct gaicb		cb;
};

struct dns_batch_query {
	struct dbq_entry	*entries;
	struct gaicb		**reqs;
	struct addrinfo		hints;
	uint32_t		nr_entries;
	uint32_t		cap;
};

static void dbq_free(struct dns_batch_query *dbq)
{
	uint32_t i;

	if (!dbq)
		return;

	if (dbq->reqs) {
		for (i = 0; i < dbq->nr_entries; i++) {
			if (dbq->reqs[i]->ar_result)
				freeaddrinfo(dbq->reqs[i]->ar_result);
		}
	}

	free(dbq->entries);
	free(dbq->reqs);
	free(dbq);
}

static int dbq_add_entry(struct dns_batch_query *dbq, struct gwp_dns_entry *e)
{
	struct dbq_entry *de;

	if (dbq->nr_entries >= dbq->cap) {
		uint32_t new_cap = dbq->cap ? dbq->cap * 2 : 16;
		struct dbq_entry *nentries;

		nentries = realloc(dbq->entries, new_cap * sizeof(*nentries));
		if (!nentries)
			return -ENOMEM;
		dbq->entries = nentries;
		dbq->cap = new_cap;
	}

	de = &dbq->entries[dbq->nr_entries];
	de->e = e;
	memset(&de->cb, 0, sizeof(de->cb));
	de->cb.ar_name = e->name;
	de->cb.ar_service = e->service;
	de->cb.ar_request = &dbq->hints;
	de->cb.ar_result = NULL;
	dbq->nr_entries++;

	return 0;
}

static int collect_active_queries(struct gwp_dns_ctx *ctx,
				  struct gwp_dns_entry **head_p,
				  struct dns_batch_query **dbq_p)
{
	struct gwp_dns_entry *e, *next, *prev = NULL, *head = *head_p;
	struct dns_batch_query *dbq;

	dbq = calloc(1, sizeof(*dbq));
	if (!dbq)
		return -ENOMEM;

	assert(head);
	prep_hints(&dbq->hints, ctx->cfg.restyp);
	for (e = head; e; e = next) {
		int x = atomic_load(&e->refcnt);
		next = e->next;
		if (x > 1) {

			if (dbq_add_entry(dbq, e)) {
				dbq_free(dbq);
				return -ENOMEM;
			}

			prev = e;
			continue;
		}

		assert(x == 1);
		/*
		 * If the refcnt is 1, it means we are the last reference
		 * to this entry. The client no longer cares about the
		 * result. We can free it immediately. No need to resolve
		 * the query nor to signal the eventfd.
		 */
		if (prev)
			prev->next = next;
		else
			head = next;

		gwp_dns_entry_free(e);
	}

	*head_p = head;
	*dbq_p = dbq;
	return 0;
}

static void dispatch_batch_result(int r, struct gwp_dns_ctx *ctx,
				  struct dns_batch_query *dbq,
				  uint32_t restyp)
{
	struct gwp_dns_entry *e;
	struct addrinfo *ai;
	uint32_t i;

	for (i = 0; i < dbq->nr_entries; i++) {
		e = dbq->entries[i].e;
		ai = dbq->reqs[i]->ar_result;

		if (!r) {
			e->res = gai_error(dbq->reqs[i]);
			if (!e->res) {
				if (!iterate_addr_list(ai, &e->addr, restyp))
					e->res = -EHOSTUNREACH;
			}
		} else {
			e->res = r;
		}

		eventfd_write(e->ev_fd, 1);
		if (!e->res) {
			if (try_pass_result_to_cache(ctx, e->name, e->service, ai))
				dbq->reqs[i]->ar_result = NULL;
		}
	}
}

/*
 * Filling dbq->reqs[n] cannot be done in dbq_add_entry() because
 * the reallocation of dbq->entries may change the address of
 * dbq->entries[n].cb.
 */
static int prep_reqs(struct dns_batch_query *dbq)
{
	uint32_t i;

	dbq->reqs = malloc(dbq->nr_entries * sizeof(*dbq->reqs));
	if (!dbq->reqs)
		return -ENOMEM;

	for (i = 0; i < dbq->nr_entries; i++)
		dbq->reqs[i] = &dbq->entries[i].cb;

	return 0;
}

/*
 * Must be called with ctx->lock held. May release the lock, but
 * it will reacquire it before returning.
 */
static void process_queue_entry_batch(struct gwp_dns_ctx *ctx)
{
	struct gwp_dns_entry *head = unplug_queue_list(ctx);
	struct dns_batch_query *dbq = NULL;

	if (!head)
		return;

	pthread_mutex_unlock(&ctx->lock);

	if (!collect_active_queries(ctx, &head, &dbq)) {
		if (!prep_reqs(dbq)) {
			struct sigevent ev;
			int r;

			memset(&ev, 0, sizeof(ev));
			ev.sigev_notify = SIGEV_NONE;
			r = getaddrinfo_a(GAI_WAIT, dbq->reqs, dbq->nr_entries, &ev);
			dispatch_batch_result(r, ctx, dbq, ctx->cfg.restyp);
		}
	}

	dbq_free(dbq);
	put_all_entries(head);
	pthread_mutex_lock(&ctx->lock);
}

/*
 * Must be called with ctx->lock held. May release the lock, but
 * it will reacquire it before returning.
 */
static void process_queue_entry_single(struct gwp_dns_ctx *ctx)
{
	struct gwp_dns_entry *e = ctx->head;

	if (!e)
		return;

	e = ctx->head;
	ctx->head = e->next;
	if (!ctx->head) {
		ctx->tail = NULL;
		assert(ctx->nr_entries == 1);
	}

	ctx->nr_entries--;
	pthread_mutex_unlock(&ctx->lock);

	if (atomic_load(&e->refcnt) == 1) {
		/*
		 * If the refcnt is 1, it means we are the last reference
		 * to this entry. The client no longer cares about the
		 * result. We can free it immediately. No need to resolve
		 * the query nor to signal the eventfd.
		 */
		gwp_dns_entry_free(e);
		goto out;
	}

	e->res = gwp_dns_resolve(ctx, e->name, e->service, &e->addr, ctx->cfg.restyp);
	eventfd_write(e->ev_fd, 1);
	gwp_dns_entry_put(e);
out:
	pthread_mutex_lock(&ctx->lock);
}

/*
 * Must be called with ctx->lock held. May release the lock, but
 * it will reacquire it before returning.
 */
static void process_queue_entry(struct gwp_dns_ctx *ctx)
{
	/*
	 * There are two cases here:
	 *
	 * 1. All of the DNS threads are busy, and there are still a lot
	 *    of queued entries. Process them in batch via getaddrinfo_a().
	 *
	 * 2. The number of threads is sufficient to handle the queued
	 *    entries, so process them one by one.
	 *
	 * Why not always getaddrinfo_a()? Because getaddrinfo_a() has
	 * a higher overhead than processing entries individually as it
	 * will spawn a new thread for each query. Don't bother invoking
	 * clone() for each entry if we can process them in the current
	 * thread.
	 */
	if ((ctx->nr_entries + 16) > ctx->nr_sleeping)
		process_queue_entry_batch(ctx);
	else
		process_queue_entry_single(ctx);
}

static void *gwp_dns_thread_entry(void *arg)
{
	struct gwp_dns_wrk *w = arg;
	struct gwp_dns_ctx *ctx = w->ctx;

	pthread_mutex_lock(&ctx->lock);
	while (!ctx->should_stop) {
		if (ctx->head)
			process_queue_entry(ctx);
		else
			wait_for_queue_entry(ctx);
	}
	pthread_mutex_unlock(&ctx->lock);

	return NULL;
}

static void free_worker(struct gwp_dns_wrk *w)
{
	struct gwp_dns_ctx *ctx;

	if (!w)
		return;

	ctx = w->ctx;
	pthread_mutex_lock(&ctx->lock);
	ctx->should_stop = true;
	pthread_cond_broadcast(&ctx->cond);
	pthread_mutex_unlock(&ctx->lock);
	pthread_join(w->thread, NULL);
}

static void free_workers(struct gwp_dns_ctx *ctx)
{
	uint32_t i;

	if (!ctx->workers)
		return;

	for (i = 0; i < ctx->cfg.nr_workers; i++)
		free_worker(&ctx->workers[i]);

	free(ctx->workers);
	ctx->workers = NULL;
}

static int init_workers(struct gwp_dns_ctx *ctx)
{
	struct gwp_dns_wrk *workers, *w;
	uint32_t i;
	int r;

	if (ctx->cfg.nr_workers == 0)
		return -EINVAL;

	workers = calloc(ctx->cfg.nr_workers, sizeof(*workers));
	if (!workers)
		return -ENOMEM;

	ctx->workers = workers;
	for (i = 0; i < ctx->cfg.nr_workers; i++) {
		w = &workers[i];
		w->ctx = ctx;
		w->id = i;
		r = pthread_create(&w->thread, NULL, gwp_dns_thread_entry, w);
		if (r) {
			r = -r;
			goto out_err;
		}
	}

	return 0;

out_err:
	while (i--)
		free_worker(&workers[i]);
	free(workers);
	ctx->workers = NULL;
	return r;
}

int gwp_dns_cache_lookup(struct gwp_dns_ctx *ctx, const char *name,
			 const char *service, struct gwp_sockaddr *addr)
{
	struct gwp_dns_cache *cache;
	bool found_expired;
	time_t now;
	uint32_t i;
	int r;

	if (!ctx->cache)
		return -ENOSYS;

	cache = ctx->cache;
	pthread_rwlock_rdlock(&cache->lock);
	r = -ENOENT;
	now = time(NULL);
	found_expired = false;
	for (i = 0; i < cache->nr; i++) {
		struct cache_entry *e = &cache->entries[i];
		bool exp = (e->expired_at <= now);

		found_expired |= exp;

		if (exp)
			continue;

		if (strcmp(e->name, name))
			continue;

		if (service && strcmp(e->service, service))
			continue;
		else if (!service && e->service[0] != '\0')
			continue;

		if (iterate_addr_list(e->res, addr, ctx->cfg.restyp)) {
			r = 0;
			break;
		}
	}
	pthread_rwlock_unlock(&cache->lock);
	if (found_expired)
		gwp_dns_cache_scan_and_delete_expired_entries(cache);

	return r;
}

static int init_cache(struct gwp_dns_ctx *ctx)
{
	struct gwp_dns_cache *cache;
	int r;

	if (ctx->cfg.cache_expiry <= 0) {
		/*
		 * Cache is disabled.
		 */
		ctx->cache = NULL;
		return 0;
	}

	cache = calloc(1, sizeof(*cache));
	if (!cache)
		return -ENOMEM;

	r = pthread_rwlock_init(&cache->lock, NULL);
	if (r) {
		r = -r;
		free(cache);
		return r;
	}

	ctx->cache = cache;
	return 0;
}

static void free_cache(struct gwp_dns_cache *cache)
{
	uint32_t i;

	if (!cache)
		return;

	pthread_rwlock_destroy(&cache->lock);
	for (i = 0; i < cache->nr; i++) {
		struct cache_entry *e = &cache->entries[i];
		free(e->name);
		if (e->res)
			freeaddrinfo(e->res);
	}
	free(cache->entries);
	free(cache);
}

int gwp_dns_ctx_init(struct gwp_dns_ctx **ctx_p, const struct gwp_dns_cfg *cfg)
{
	struct gwp_dns_ctx *ctx;
	int r;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return -ENOMEM;

	ctx->cfg = *cfg;
	r = pthread_mutex_init(&ctx->lock, NULL);
	if (r) {
		r = -r;
		goto out_free_ctx;
	}

	r = pthread_cond_init(&ctx->cond, NULL);
	if (r) {
		r = -r;
		goto out_destroy_mutex;
	}

	r = init_cache(ctx);
	if (r)
		goto out_destroy_cond;

	ctx->nr_sleeping = 0;
	ctx->nr_entries = 0;
	ctx->workers = NULL;
	ctx->head = NULL;
	ctx->tail = NULL;
	ctx->should_stop = false;
	r = init_workers(ctx);
	if (r)
		goto out_free_cache;

	*ctx_p = ctx;
	return 0;
out_free_cache:
	free_cache(ctx->cache);
out_destroy_cond:
	pthread_cond_destroy(&ctx->cond);
out_destroy_mutex:
	pthread_mutex_destroy(&ctx->lock);
out_free_ctx:
	free(ctx);
	*ctx_p = NULL;
	return r;
}

static void put_all_queued_entries(struct gwp_dns_ctx *ctx)
{
	put_all_entries(ctx->head);
	ctx->head = ctx->tail = NULL;
}

void gwp_dns_ctx_free(struct gwp_dns_ctx *ctx)
{
	free_workers(ctx);
	pthread_mutex_destroy(&ctx->lock);
	pthread_cond_destroy(&ctx->cond);
	put_all_queued_entries(ctx);
	free_cache(ctx->cache);
	free(ctx);
}

static void push_queue(struct gwp_dns_ctx *ctx, struct gwp_dns_entry *e)
{
	pthread_mutex_lock(&ctx->lock);
	if (ctx->tail)
		ctx->tail->next = e;
	else
		ctx->head = e;
	ctx->tail = e;
	e->next = NULL;

	ctx->nr_entries++;
	if (ctx->nr_sleeping)
		pthread_cond_signal(&ctx->cond);
	pthread_mutex_unlock(&ctx->lock);
}

struct gwp_dns_entry *gwp_dns_queue(struct gwp_dns_ctx *ctx,
				    const char *name, const char *service)
{
	struct gwp_dns_entry *e;
	size_t nl, sl;

	e = malloc(sizeof(*e));
	if (!e)
		return NULL;

	e->ev_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (e->ev_fd < 0)
		goto out_free_e;

	/*
	 * Merge name and service into a single allocated string to
	 * avoid multiple allocations.
	 *
	 * The format is: "<name>\0<service>\0" where both name and
	 * service are null-terminated strings.
	 */
	nl = strlen(name);
	sl = service ? strlen(service) : 0;
	e->name = malloc(nl + 1 + sl + 1);
	if (!e->name)
		goto out_close_ev_fd;

	e->service = e->name + nl + 1;
	memcpy(e->name, name, nl + 1);
	if (service)
		memcpy(e->service, service, sl + 1);
	else
		e->service[0] = '\0';

	atomic_init(&e->refcnt, 2);
	e->res = 0;
	push_queue(ctx, e);
	return e;

out_close_ev_fd:
	close(e->ev_fd);
out_free_e:
	free(e);
	return NULL;
}

bool gwp_dns_entry_put(struct gwp_dns_entry *e)
{
	int x;

	if (!e)
		return false;

	x = atomic_fetch_sub(&e->refcnt, 1);
	assert(x > 0);
	if (x == 1) {
		gwp_dns_entry_free(e);
		return true;
	}

	return false;
}
