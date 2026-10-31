// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * Unit tests for the epoll loop's timer heap (ev/tmr.h): arming, re-arming
 * to an earlier or a later time, disarming from any position, and expiry
 * order, checked against a plain array after every operation.
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <gwproxy/ev/tmr.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NR_PAIRS	97
#define NR_KINDS	2

static struct gwp_conn_pair pairs[NR_PAIRS];

/* The reference: when each timer expires, 0 while it is not armed. */
static uint64_t ref[NR_PAIRS][NR_KINDS];

static unsigned long long rnd_state = 0x9e3779b97f4a7c15ull;

static uint32_t rnd(uint32_t n)
{
	rnd_state ^= rnd_state << 13;
	rnd_state ^= rnd_state >> 7;
	rnd_state ^= rnd_state << 17;
	return (uint32_t)(rnd_state % n);
}

/* The heap order holds, and every entry and every pair agree where it is. */
static void check(const struct gwp_tmr_heap *h)
{
	uint32_t i, k, nr = 0;

	for (i = 0; i < h->nr; i++) {
		const struct gwp_tmr *t = &h->tmr[i];
		uint32_t idx = (uint32_t)(t->gcp - pairs);

		if (i)
			assert(h->tmr[(i - 1) / 2].at_ms <= t->at_ms);
		assert(idx < NR_PAIRS && t->kind < NR_KINDS);
		assert(t->gcp->tmr_pos[t->kind] == i + 1);
		assert(ref[idx][t->kind] == t->at_ms);
	}

	for (i = 0; i < NR_PAIRS; i++) {
		for (k = 0; k < NR_KINDS; k++) {
			assert(!ref[i][k] == !pairs[i].tmr_pos[k]);
			nr += !!ref[i][k];
		}
	}
	assert(nr == h->nr);
}

static void arm(struct gwp_tmr_heap *h, uint32_t i, uint32_t k, uint64_t at)
{
	assert(!gwp_tmr_arm(h, &pairs[i], k, at));
	ref[i][k] = at;
	check(h);
}

static void disarm(struct gwp_tmr_heap *h, uint32_t i, uint32_t k)
{
	gwp_tmr_disarm(h, &pairs[i], k);
	ref[i][k] = 0;
	check(h);
}

/* Expire everything due by @now, in order, as the epoll loop does. */
static void expire(struct gwp_tmr_heap *h, uint64_t now)
{
	const struct gwp_tmr *t;
	uint64_t last = 0;
	uint32_t i, k;

	while ((t = gwp_tmr_first(h)) && t->at_ms <= now) {
		uint32_t j, l;

		i = (uint32_t)(t->gcp - pairs);
		k = t->kind;

		/* Nothing that is armed expires before the first entry. */
		for (j = 0; j < NR_PAIRS; j++)
			for (l = 0; l < NR_KINDS; l++)
				assert(!ref[j][l] || ref[j][l] >= t->at_ms);
		assert(t->at_ms >= last);
		last = t->at_ms;
		disarm(h, i, k);
	}

	for (i = 0; i < NR_PAIRS; i++)
		for (k = 0; k < NR_KINDS; k++)
			assert(!ref[i][k] || ref[i][k] > now);
}

static void test_basic(void)
{
	struct gwp_tmr_heap h;

	memset(&h, 0, sizeof(h));
	assert(!gwp_tmr_first(&h));

	arm(&h, 0, 0, 300);
	arm(&h, 1, 0, 100);
	arm(&h, 2, 1, 200);
	arm(&h, 2, 0, 50);
	assert(gwp_tmr_first(&h)->gcp == &pairs[2]);
	assert(gwp_tmr_first(&h)->kind == 0);

	/* Re-arming moves the entry, later or earlier; it never adds one. */
	arm(&h, 2, 0, 400);
	assert(h.nr == 4);
	assert(gwp_tmr_first(&h)->gcp == &pairs[1]);
	arm(&h, 0, 0, 10);
	assert(h.nr == 4);
	assert(gwp_tmr_first(&h)->gcp == &pairs[0]);

	/* Disarming twice, or a timer never armed, is harmless. */
	disarm(&h, 1, 0);
	disarm(&h, 1, 0);
	disarm(&h, 3, 1);
	assert(h.nr == 3);

	expire(&h, 250);
	assert(h.nr == 1);
	assert(gwp_tmr_first(&h)->gcp == &pairs[2]);
	expire(&h, 1000);
	assert(!gwp_tmr_first(&h));

	gwp_tmr_free(&h);
	assert(!h.tmr && !h.nr && !h.cap);
}

/*
 * Random operations, with many equal times: a disarmed entry in the middle
 * is replaced by the last one, which may have to move up as well as down.
 */
static void test_random(void)
{
	struct gwp_tmr_heap h;
	uint64_t now = 1;
	uint32_t n;

	memset(&h, 0, sizeof(h));
	for (n = 0; n < 200000; n++) {
		uint32_t i = rnd(NR_PAIRS), k = rnd(NR_KINDS);

		switch (rnd(8)) {
		case 0:
		case 1:
		case 2:
		case 3:
			arm(&h, i, k, now + 1 + rnd(n % 3 ? 1000 : 8));
			break;
		case 4:
		case 5:
			disarm(&h, i, k);
			break;
		case 6:
			now += rnd(50);
			expire(&h, now);
			break;
		default:
			/* Disarm whatever sits at a random heap position. */
			if (h.nr) {
				const struct gwp_tmr *t = &h.tmr[rnd(h.nr)];

				disarm(&h, (uint32_t)(t->gcp - pairs), t->kind);
			}
			break;
		}
	}

	expire(&h, UINT64_MAX);
	assert(!h.nr);
	gwp_tmr_free(&h);
}

int main(void)
{
	test_basic();
	test_random();
	printf("All tmr tests passed!\n");
	return 0;
}
