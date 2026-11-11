// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * Lingering closes; see linger.h.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <gwproxy/linger.h>
#include <gwproxy/syscall.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

/*
 * A socket's checks (linger_chk()) come 10 ms after it was handed over, then
 * at twice the interval each time, up to 200 ms apart: most peers have taken
 * everything within a round trip or two, and a socket that waits longer is
 * not worth more than a few system calls a second.
 */
#define LINGER_CHK_MIN_MS	10u
#define LINGER_CHK_MAX_MS	200u

/*
 * A peer that has sent nothing for this long has stopped sending, rather than
 * paused between two writes of an upload.
 */
#define LINGER_QUIET_MS		250u

/*
 * At most this much input is discarded per socket: a peer that sends more
 * is cut off, as one that sends for longer than the bound is. Per readiness
 * event, at most LINGER_RX_BURST reads, so that a fast sender cannot hold
 * the worker; the level-triggered set reports the rest again.
 */
#define LINGER_MAX_RX		(16u << 20)
#define LINGER_RX_BURST		16

/* Events taken per epoll_wait() of the set, and rounds of it per run. */
#define LINGER_NR_EV		64
#define LINGER_MAX_ROUNDS	16

struct gwp_linger {
	int		fd;
	/* Where it sits in gwp_linger_set::ent. */
	uint32_t	idx;
	uint8_t		mode;
	uint8_t		nr_chk;
	/* Input came in since the last check (rx), and when it last did. */
	bool		rx;
	uint32_t	nr_rx;
	uint64_t	rx_ms;
	uint64_t	end_ms;
	uint64_t	chk_ms;
};

struct gwp_linger_set {
	int			ep_fd;
	/* When the earliest check is due, 0 while there is none. */
	uint64_t		next_ms;
	struct gwp_linger	**ent;
	uint32_t		nr;
	uint32_t		cap;
	uint32_t		max;
};

/*
 * Discarded input lands here. MSG_TRUNC has TCP drop the data without
 * copying it, so the threads that share this buffer never write to it; it
 * only has to be a valid destination.
 */
static char linger_sink[65536];

static uint64_t linger_now_ms(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * 1000ull + (uint64_t)t.tv_nsec / 1000000ull;
}

/* Bytes on @fd's send queue not yet acknowledged by the peer; 0 on error. */
static int linger_outq(int fd)
{
	int n = 0;

	if (ioctl(fd, TIOCOUTQ, &n) < 0)
		return 0;
	return n;
}

/*
 * Read and discard what has come in on @l. Returns true once there is
 * nothing more to wait for: the peer's EOF, an error (a reset, say), or more
 * input than LINGER_MAX_RX.
 */
static bool linger_rx(struct gwp_linger *l)
{
	ssize_t n;
	int i;

	for (i = 0; i < LINGER_RX_BURST; i++) {
		n = __sys_recv(l->fd, linger_sink, sizeof(linger_sink),
			       MSG_TRUNC | MSG_DONTWAIT | MSG_NOSIGNAL);
		if (n == -EAGAIN || n == -EINTR)
			return false;
		if (n <= 0)
			return true;
		l->rx = true;
		if ((uint64_t)l->nr_rx + (uint64_t)n >= LINGER_MAX_RX)
			return true;
		l->nr_rx += (uint32_t)n;
	}
	return false;
}

static void linger_reset(int fd)
{
	static const struct linger lg = { .l_onoff = 1, .l_linger = 0 };

	__sys_setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
}

/*
 * The end of the wait: an RST for GWP_LINGER_RST, else a close with nothing
 * left unread, so that it is no reset as long as the peer sends no more.
 */
static void linger_close(int fd, int mode)
{
	if (mode == GWP_LINGER_RST) {
		linger_reset(fd);
	} else {
		struct gwp_linger l = { .fd = fd };

		linger_rx(&l);
	}
	__sys_close(fd);
}

/*
 * Is @l done at @now? If not, when to look at it again. A FIN socket is done
 * once everything sent to it has been acknowledged, its own FIN included, and
 * the peer has sent nothing for LINGER_QUIET_MS: a peer that is still
 * sending (an upload that was refused) is read on, as a close would reset
 * it, and a peer stack that drops what it has received on a reset may then
 * lose the very reply it was sent. An RST socket is done once its queue is
 * empty: the peer then has all of the data, and the reset cannot take any
 * of it away. It is not watched for input, so a peer that resets it first
 * shows in its pending error instead; the queue never empties then.
 */
static bool linger_chk(struct gwp_linger *l, uint64_t now)
{
	socklen_t len = sizeof(int);
	uint32_t ms;
	int err = 0;

	if (now >= l->end_ms)
		return true;
	if (l->mode == GWP_LINGER_RST &&
	    (__sys_getsockopt(l->fd, SOL_SOCKET, SO_ERROR, &err, &len) || err))
		return true;
	if (l->rx) {
		l->rx = false;
		l->rx_ms = now;
	}
	if (linger_outq(l->fd) == 0 && (l->mode == GWP_LINGER_RST ||
					now - l->rx_ms >= LINGER_QUIET_MS))
		return true;

	ms = LINGER_CHK_MIN_MS << (l->nr_chk < 5 ? l->nr_chk : 5);
	if (ms > LINGER_CHK_MAX_MS)
		ms = LINGER_CHK_MAX_MS;
	l->nr_chk++;
	l->chk_ms = now + ms;
	if (l->chk_ms > l->end_ms)
		l->chk_ms = l->end_ms;
	return false;
}

/* Drop @l from @s and close its socket. */
static void linger_done(struct gwp_linger_set *s, struct gwp_linger *l)
{
	struct gwp_linger *last = s->ent[--s->nr];

	s->ent[l->idx] = last;
	last->idx = l->idx;

	/* Out of the set first, see ep_del() in ev/epoll.c. */
	if (l->mode == GWP_LINGER_FIN)
		__sys_epoll_ctl(s->ep_fd, EPOLL_CTL_DEL, l->fd, NULL);
	linger_close(l->fd, l->mode);
	free(l);
}

/* When the earliest check is due now. */
static void linger_next(struct gwp_linger_set *s)
{
	uint64_t at = 0;
	uint32_t i;

	for (i = 0; i < s->nr; i++) {
		if (!at || s->ent[i]->chk_ms < at)
			at = s->ent[i]->chk_ms;
	}
	s->next_ms = at;
}

struct gwp_linger_set *gwp_linger_new(uint32_t max)
{
	struct gwp_linger_set *s = calloc(1, sizeof(*s));
	int fd;

	if (!s)
		return NULL;

	fd = __sys_epoll_create1(EPOLL_CLOEXEC);
	if (fd < 0) {
		free(s);
		errno = -fd;
		return NULL;
	}
	s->ep_fd = fd;
	s->max = max;
	return s;
}

void gwp_linger_free(struct gwp_linger_set *s)
{
	if (!s)
		return;

	while (s->nr)
		linger_done(s, s->ent[s->nr - 1]);
	free(s->ent);
	__sys_close(s->ep_fd);
	free(s);
}

int gwp_linger_fd(const struct gwp_linger_set *s)
{
	return s->ep_fd;
}

uint32_t gwp_linger_nr(const struct gwp_linger_set *s)
{
	return s->nr;
}

uint64_t gwp_linger_next_ms(const struct gwp_linger_set *s)
{
	return s->next_ms;
}

static bool linger_grow(struct gwp_linger_set *s)
{
	struct gwp_linger **ent;
	uint32_t cap;

	if (s->nr < s->cap)
		return true;

	cap = s->cap ? s->cap * 2 : 16;
	ent = realloc(s->ent, cap * sizeof(*ent));
	if (!ent)
		return false;
	s->ent = ent;
	s->cap = cap;
	return true;
}

int gwp_linger_add(struct gwp_linger_set *s, int fd, int mode,
		   uint32_t bound_ms)
{
	struct gwp_linger *l = NULL;
	struct epoll_event ev;
	uint64_t now;

	if (mode == GWP_LINGER_FIN)
		__sys_shutdown(fd, SHUT_WR);

	/*
	 * Past the limit, or out of memory: closed at once, as before there
	 * was a linger set. A reset is passed on as one all the same.
	 */
	if (s->nr >= s->max || !linger_grow(s) || !(l = calloc(1, sizeof(*l)))) {
		linger_close(fd, mode);
		return 1;
	}

	now = linger_now_ms();
	l->fd = fd;
	l->mode = (uint8_t)mode;
	l->end_ms = now + bound_ms;
	/* Quiet from here on, not since whenever it sent last. */
	l->rx_ms = now;

	if ((mode == GWP_LINGER_FIN && linger_rx(l)) || linger_chk(l, now))
		goto out_close;

	if (mode == GWP_LINGER_FIN) {
		memset(&ev, 0, sizeof(ev));
		ev.events = EPOLLIN | EPOLLRDHUP;
		ev.data.ptr = l;
		if (__sys_epoll_ctl(s->ep_fd, EPOLL_CTL_ADD, fd, &ev))
			goto out_close;
	}

	l->idx = s->nr;
	s->ent[s->nr++] = l;
	if (!s->next_ms || l->chk_ms < s->next_ms)
		s->next_ms = l->chk_ms;
	return 0;

out_close:
	linger_close(fd, mode);
	free(l);
	return 1;
}

int gwp_linger_run(struct gwp_linger_set *s)
{
	struct epoll_event ev[LINGER_NR_EV];
	int i, n, rounds = 0, nr_closed = 0;
	uint64_t now;
	uint32_t j;

	do {
		n = __sys_epoll_wait(s->ep_fd, ev, LINGER_NR_EV, 0);
		for (i = 0; i < n; i++) {
			struct gwp_linger *l = ev[i].data.ptr;

			if (linger_rx(l)) {
				linger_done(s, l);
				nr_closed++;
			}
		}
	} while (n == LINGER_NR_EV && ++rounds < LINGER_MAX_ROUNDS);

	now = linger_now_ms();
	for (j = 0; j < s->nr;) {
		struct gwp_linger *l = s->ent[j];

		if (l->chk_ms > now || !linger_chk(l, now)) {
			j++;
			continue;
		}
		/* The last entry moves into slot @j: look at it next. */
		linger_done(s, l);
		nr_closed++;
	}

	linger_next(s);
	return nr_closed;
}
