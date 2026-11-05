// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * Shared upstream server state and the pool's choice of a server; see
 * upstream_lb.h.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <gwproxy/upstream_lb.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/*
 * A list behind one lock. Only making and freeing server objects takes it
 * (an ACL load, and the last reference to a server going), never a pick:
 * a connection reaches its entry through its server object. A few hundred
 * identities at most (pools of up to 64 servers each), so no hashing.
 */
struct gwp_up_table {
	pthread_mutex_t		lock;
	struct gwp_up_state	*head;
	uint32_t		nr;
};

void gwp_up_key_init(struct gwp_up_key *key, enum gwp_up_scheme scheme,
		     const struct gwp_sockaddr *addr, const char *user,
		     size_t ulen)
{
	memset(key, 0, sizeof(*key));
	key->scheme = (uint8_t)scheme;
	key->family = (uint8_t)addr->sa.sa_family;
	if (addr->sa.sa_family == AF_INET6) {
		memcpy(key->port, &addr->i6.sin6_port, 2);
		memcpy(key->ip, &addr->i6.sin6_addr, 16);
		memcpy(key->scope, &addr->i6.sin6_scope_id, 4);
	} else if (addr->sa.sa_family == AF_INET) {
		memcpy(key->port, &addr->i4.sin_port, 2);
		memcpy(key->ip, &addr->i4.sin_addr, 4);
	}
	if (ulen > sizeof(key->user))
		ulen = sizeof(key->user);
	key->ulen = (uint8_t)ulen;
	if (ulen)
		memcpy(key->user, user, ulen);
}

struct gwp_up_table *gwp_up_table_create(void)
{
	struct gwp_up_table *t = calloc(1, sizeof(*t));

	if (!t)
		return NULL;
	if (pthread_mutex_init(&t->lock, NULL)) {
		free(t);
		return NULL;
	}
	return t;
}

uint32_t gwp_up_table_destroy(struct gwp_up_table *t)
{
	struct gwp_up_state *s, *next;
	uint32_t left;

	if (!t)
		return 0;
	left = t->nr;
	for (s = t->head; s; s = next) {
		next = s->next;
		/* The key holds a user name; leave none in freed memory. */
		explicit_bzero(s, sizeof(*s));
		free(s);
	}
	pthread_mutex_destroy(&t->lock);
	free(t);
	return left;
}

uint32_t gwp_up_table_count(struct gwp_up_table *t)
{
	uint32_t nr;

	pthread_mutex_lock(&t->lock);
	nr = t->nr;
	pthread_mutex_unlock(&t->lock);
	return nr;
}

struct gwp_up_state *gwp_up_state_get(struct gwp_up_table *t,
				      const struct gwp_up_key *key)
{
	struct gwp_up_state *s;

	pthread_mutex_lock(&t->lock);
	for (s = t->head; s; s = s->next) {
		if (!memcmp(&s->key, key, sizeof(*key))) {
			s->ref++;
			goto out;
		}
	}
	s = calloc(1, sizeof(*s));
	if (s) {
		atomic_init(&s->nr_open, 0);
		s->ref = 1;
		s->tab = t;
		s->key = *key;
		s->next = t->head;
		t->head = s;
		t->nr++;
	}
out:
	pthread_mutex_unlock(&t->lock);
	return s;
}

void gwp_up_state_put(struct gwp_up_state *s)
{
	struct gwp_up_table *t;
	struct gwp_up_state **pp;

	if (!s)
		return;
	t = s->tab;
	pthread_mutex_lock(&t->lock);
	if (--s->ref) {
		pthread_mutex_unlock(&t->lock);
		return;
	}
	for (pp = &t->head; *pp != s; pp = &(*pp)->next)
		;
	*pp = s->next;
	t->nr--;
	pthread_mutex_unlock(&t->lock);
	explicit_bzero(s, sizeof(*s));
	free(s);
}

uint32_t gwp_up_lb_pick(bool least_conn, uint32_t rr, const uint32_t *open,
			uint32_t nr)
{
	uint32_t start = rr % nr, best = start, i, j;

	if (!least_conn)
		return start;
	for (i = 1; i < nr; i++) {
		j = start + i;
		if (j >= nr)
			j -= nr;
		if (open[j] < open[best])
			best = j;
	}
	return best;
}
