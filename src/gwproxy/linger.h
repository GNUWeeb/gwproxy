// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * Lingering closes. A socket that is closed with unread input, or that the
 * peer keeps sending to after the close, answers with an RST, and the kernel
 * then throws away whatever the socket still had queued to send: a failure
 * reply, the end of a response. A peer that has not read what it was sent
 * yet may lose it too, on stacks that drop received data on a reset. So a
 * socket that may still get input is not closed at once once its pair is
 * done: it is handed to its worker's linger set, which shuts its write side
 * (the FIN goes out behind what is queued), reads and discards its input,
 * and closes it once the peer has closed too, or has taken everything and
 * gone quiet, or a short bound has passed (GWP_LINGER_FIN).
 *
 * The set can also pass a reset on (GWP_LINGER_RST): it waits until
 * everything queued on the socket has been acknowledged, and only then
 * resets the connection, as a reset at once would destroy what is still in
 * flight. That too has a bound, after which the connection is reset anyway.
 *
 * Each worker owns a set; nothing in here is shared between threads. The
 * set's own epoll descriptor (gwp_linger_fd()) becomes readable when one of
 * its sockets has input, and its sockets are looked at again from time to
 * time (gwp_linger_next_ms()): an event loop watches that descriptor, keeps
 * a timer for the next look, and calls gwp_linger_run() for either.
 *
 * Self-contained (libc and the syscall wrappers only), so it can be
 * unit-tested alone.
 */
#ifndef GWP_LINGER_H
#define GWP_LINGER_H

#include <stdint.h>
#include <stdbool.h>

enum {
	/* Shut the write side, discard input, close on EOF or when quiet. */
	GWP_LINGER_FIN = 0,
	/* Reset the connection once its send queue has drained. */
	GWP_LINGER_RST = 1,
};

struct gwp_linger_set;

/*
 * A set that holds at most @max sockets at once; sockets beyond that are
 * closed (or reset) at once. NULL, with errno set, on failure.
 */
struct gwp_linger_set *gwp_linger_new(uint32_t max);

/* Close every socket still held (or reset it, as its mode says), then @s. */
void gwp_linger_free(struct gwp_linger_set *s);

/* The descriptor to watch for readability. */
int gwp_linger_fd(const struct gwp_linger_set *s);

/* How many sockets @s holds. */
uint32_t gwp_linger_nr(const struct gwp_linger_set *s);

/*
 * Hand @fd over to @s, with GWP_LINGER_FIN or GWP_LINGER_RST as @mode, for at
 * most @bound_ms. @fd must be a connected TCP socket that nothing else uses
 * any more (no I/O in flight on it, out of every other epoll set): from here
 * on @s owns it. For GWP_LINGER_FIN, everything to be sent must have been
 * written to it already. Returns 1 when @fd was closed at once, else 0.
 */
int gwp_linger_add(struct gwp_linger_set *s, int fd, int mode,
		   uint32_t bound_ms);

/*
 * When gwp_linger_run() is to be called next, in CLOCK_MONOTONIC milliseconds,
 * or 0 when @s holds nothing. It moves with every gwp_linger_add() and
 * gwp_linger_run().
 */
uint64_t gwp_linger_next_ms(const struct gwp_linger_set *s);

/*
 * Discard what came in and close what is done. Call it when gwp_linger_fd()
 * is readable, and once gwp_linger_next_ms() is due; it never blocks. Returns
 * the number of descriptors it closed.
 */
int gwp_linger_run(struct gwp_linger_set *s);

#endif /* #ifndef GWP_LINGER_H */
