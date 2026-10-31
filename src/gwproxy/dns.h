// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWP_DNS_H
#define GWP_DNS_H

#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <gwproxy/net.h>
#include <gwproxy/syscall.h>

/*
 * How many addresses a single name may contribute. A resolver can return far
 * more; the connect path only ever tries a handful before giving up, so the
 * rest are dropped rather than carried around per connection.
 */
#define GWP_DNS_MAX_ADDRS	8u

struct gwp_dns_cq;

/*
 * One lookup request. It belongs to the resolver from gwp_dns_queue() until
 * it is handed back by gwp_dns_cq_pop(), and to the caller from then on, who
 * frees it with gwp_dns_entry_free(). A caller that loses interest earlier
 * calls gwp_dns_entry_cancel() instead and must not touch it again.
 */
struct gwp_dns_entry {
	char			*name;
	uint16_t		port;	/* host byte order */
	_Atomic(bool)		cancelled;
	int			res;
	struct gwp_dns_cq	*cq;
	void			*udata;
	/*
	 * Every usable address for @name, ordered the way they should be
	 * tried: preferred family first, then families alternating, so a
	 * family that is broken end to end costs one attempt rather than all
	 * of them. @addrs[0] is the address a single-shot selection would have
	 * picked.
	 */
	struct gwp_sockaddr	addrs[GWP_DNS_MAX_ADDRS];
	uint8_t			nr_addrs;
	struct gwp_dns_entry	*next;
};

enum {
	GWP_DNS_RESTYP_DEFAULT		= 0,
	GWP_DNS_RESTYP_IPV4_ONLY	= 1,
	GWP_DNS_RESTYP_IPV6_ONLY	= 2,
	GWP_DNS_RESTYP_PREFER_IPV4	= 3,
	GWP_DNS_RESTYP_PREFER_IPV6	= 4,
};

struct gwp_dns_cfg {
	int		cache_expiry;	/* In seconds. <= 0 to disable cache. */
	uint32_t	max_entries;	/* Max cache entries; 0 = unlimited. */
	uint32_t	nr_workers;
	uint32_t	restyp;
	uint32_t	nr_cqs;		/* completion queues, one per event loop */
};

struct gwp_dns_ctx;

/**
 * Initialize the DNS context. Stores the context in `*ctx_p`. When
 * the context is no longer needed, it should be freed using
 * gwp_dns_ctx_free().
 *
 * @param ctx_p	Pointer to a pointer where the context will be stored.
 * @param cfg	Pointer to the configuration structure.
 * @return	0 on success, negative error code on failure.
 *
 * Error values:
 * -ENOMEM: Memory allocation failed.
 * -EINVAL: Invalid configuration parameters.
 */
int gwp_dns_ctx_init(struct gwp_dns_ctx **ctx_p, const struct gwp_dns_cfg *cfg);

/**
 * Free the DNS context.
 *
 * @param ctx	Pointer to the context to be freed.
 */
void gwp_dns_ctx_free(struct gwp_dns_ctx *ctx);

/**
 * Queue a DNS resolution request. The finished entry is delivered on
 * completion queue @cq_idx: it is pushed there and the queue's eventfd
 * (gwp_dns_cq_fd()) becomes readable, then gwp_dns_cq_pop() hands it back.
 *
 * @param ctx		Pointer to the DNS context.
 * @param cq_idx	Completion queue to deliver the result on.
 * @param name		Name to resolve.
 * @param port 		Port to put in the resolved addresses (host byte order).
 * @param udata		Caller's cookie, kept in entry->udata.
 * @return		Pointer to a gwp_dns_entry on success, NULL on failure.
 */
struct gwp_dns_entry *gwp_dns_queue(struct gwp_dns_ctx *ctx, uint32_t cq_idx,
				    const char *name, uint16_t port,
				    void *udata);

/*
 * As gwp_dns_queue(), but for an outcome already known (a failure the cache
 * remembered): the entry is finished with result @res and delivered at once,
 * so the caller handles it like any other result.
 */
struct gwp_dns_entry *gwp_dns_queue_result(struct gwp_dns_ctx *ctx,
					   uint32_t cq_idx, const char *name,
					   uint16_t port, void *udata, int res);

/*
 * The non-blocking eventfd that signals completions on queue @cq_idx. It is
 * written once when the queue goes from empty to non-empty, so a wakeup can
 * stand for many entries.
 */
int gwp_dns_cq_fd(struct gwp_dns_ctx *ctx, uint32_t cq_idx);

/*
 * Take every finished entry off queue @cq_idx, in completion order, linked
 * through ->next; NULL when there is none. Clears the eventfd first, so an
 * entry finishing meanwhile signals it again. Entries cancelled in the
 * meantime are freed here and not returned. Only the queue's own event loop
 * may call this.
 */
struct gwp_dns_entry *gwp_dns_cq_pop(struct gwp_dns_ctx *ctx, uint32_t cq_idx);

/*
 * The caller no longer wants @e's result (its connection went away). The
 * resolver, or gwp_dns_cq_pop(), frees it.
 */
void gwp_dns_entry_cancel(struct gwp_dns_entry *e);

static inline bool gwp_dns_entry_cancelled(struct gwp_dns_entry *e)
{
	return atomic_load_explicit(&e->cancelled, memory_order_relaxed);
}

/* Free an entry handed back by gwp_dns_cq_pop(). NULL is fine. */
void gwp_dns_entry_free(struct gwp_dns_entry *e);

/**
 * Lookup a DNS entry in the cache. If the entry is found, it fills the
 * `addr` structure with the resolved address and returns 0. If the entry is
 * not found, it returns -ENOENT.
 *
 * @param ctx		Pointer to the DNS context.
 * @param name		Pointer to the name to look up.
 * @param port		Port to put in the address (host byte order).
 * @param addr		Pointer to the sockaddr structure to fill in.
 * @return		0 on success, negative error code on failure.
 *
 * Error values:
 * -ENOSYS: Cache is disabled.
 * -ENOENT: Entry not found in the cache.
 * -EHOSTUNREACH: The cache remembers that the name does not resolve.
 * -EINVAL: Invalid parameters.
 */
int gwp_dns_cache_lookup(struct gwp_dns_ctx *ctx, const char *name,
			 uint16_t port, struct gwp_sockaddr *addr);

/*
 * As gwp_dns_cache_lookup(), but returns up to @cap addresses in the order they
 * should be tried, matching what a cache miss would have produced. *@nr_addrs
 * receives the count. The cache already stores every A and AAAA record, so this
 * reads the same entry -- no extra lookup cost.
 */
int gwp_dns_cache_lookup_list(struct gwp_dns_ctx *ctx, const char *name,
			      uint16_t port, struct gwp_sockaddr *addrs,
			      uint8_t cap, uint8_t *nr_addrs);


/*
 * Resolve @name into up to @cap addresses with port @port, written to @addrs in the
 * order they should be tried (see struct gwp_dns_entry). *@nr_addrs receives
 * the count. Returns 0 on success, or -EHOSTUNREACH when nothing resolved.
 */
int gwp_dns_resolve(struct gwp_dns_ctx *ctx, const char *name,
		    uint16_t port, struct gwp_sockaddr *addrs,
		    uint8_t cap, uint8_t *nr_addrs, uint32_t restyp);

#endif /* #ifndef GWP_DNS_H */
