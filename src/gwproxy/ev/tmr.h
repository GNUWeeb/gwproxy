// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * The epoll loop's per-worker timers: a binary min-heap on the expiry time.
 * Each pair records where its timers sit (gwp_conn_pair::tmr_pos), so that
 * re-arming one moves its entry instead of adding a second, and dropping one
 * takes it out wherever it is, both in O(log n).
 */
#ifndef GWPROXY__EV__TMR_H
#define GWPROXY__EV__TMR_H

#include <gwproxy/gwproxy.h>
#include <errno.h>
#include <stdlib.h>

static inline void gwp_tmr_place(struct gwp_tmr_heap *h, uint32_t i,
				 const struct gwp_tmr *t)
{
	h->tmr[i] = *t;
	t->gcp->tmr_pos[t->kind] = i + 1;
}

/*
 * Put @t into the free slot @i of a heap of h->nr entries, moving entries up
 * or down until the heap is in order again. @t may point at an entry past
 * h->nr, which nothing here writes.
 */
static inline void gwp_tmr_settle(struct gwp_tmr_heap *h, uint32_t i,
				  const struct gwp_tmr *t)
{
	uint32_t c, n = h->nr;

	while (i) {
		uint32_t p = (i - 1) / 2;

		if (h->tmr[p].at_ms <= t->at_ms)
			break;
		gwp_tmr_place(h, i, &h->tmr[p]);
		i = p;
	}

	while ((c = 2 * i + 1) < n) {
		if (c + 1 < n && h->tmr[c + 1].at_ms < h->tmr[c].at_ms)
			c++;
		if (t->at_ms <= h->tmr[c].at_ms)
			break;
		gwp_tmr_place(h, i, &h->tmr[c]);
		i = c;
	}

	gwp_tmr_place(h, i, t);
}

/*
 * Have timer @kind of @gcp expire at @at_ms, replacing what it was armed
 * for. Fails only with -ENOMEM, when the heap cannot grow.
 */
static inline int gwp_tmr_arm(struct gwp_tmr_heap *h,
			      struct gwp_conn_pair *gcp, uint32_t kind,
			      uint64_t at_ms)
{
	struct gwp_tmr t = { .at_ms = at_ms, .gcp = gcp, .kind = kind };
	uint32_t pos = gcp->tmr_pos[kind];

	if (pos) {
		gwp_tmr_settle(h, pos - 1, &t);
		return 0;
	}

	if (h->nr == h->cap) {
		uint32_t cap = h->cap ? h->cap * 2 : 64;
		struct gwp_tmr *p;

		p = realloc(h->tmr, cap * sizeof(*p));
		if (!p)
			return -ENOMEM;
		h->tmr = p;
		h->cap = cap;
	}

	gwp_tmr_settle(h, h->nr++, &t);
	return 0;
}

/* Drop timer @kind of @gcp, if it is armed. */
static inline void gwp_tmr_disarm(struct gwp_tmr_heap *h,
				  struct gwp_conn_pair *gcp, uint32_t kind)
{
	uint32_t pos = gcp->tmr_pos[kind];

	if (!pos)
		return;

	gcp->tmr_pos[kind] = 0;
	if (pos == h->nr--)
		return;

	/* The last entry takes the free slot; it may move up or down. */
	gwp_tmr_settle(h, pos - 1, &h->tmr[h->nr]);
}

/* The timer that expires first, or NULL if none is armed. */
static inline const struct gwp_tmr *gwp_tmr_first(const struct gwp_tmr_heap *h)
{
	return h->nr ? &h->tmr[0] : NULL;
}

static inline void gwp_tmr_free(struct gwp_tmr_heap *h)
{
	free(h->tmr);
	h->tmr = NULL;
	h->nr = h->cap = 0;
}

#endif /* #ifndef GWPROXY__EV__TMR_H */
