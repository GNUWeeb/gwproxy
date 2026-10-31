// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * iptables-style access-control list for gwproxy. Rules are read from a file
 * (see gwp_acl_create) and evaluated top-to-bottom, first-match-wins, against
 * incoming clients (the INPUT chain) and outgoing targets (the OUTPUT chain);
 * a chain's -P policy applies when no rule matches.
 *
 * This module is self-contained (depends only on net.h types and libc) so it
 * can be unit-tested in isolation.
 */
#ifndef GWP_ACL_H
#define GWP_ACL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <netinet/in.h>
#include <gwproxy/net.h>

enum gwp_acl_verdict {
	GWP_ACL_ACCEPT	= 0,
	GWP_ACL_REJECT	= 1,
};

enum gwp_acl_proto {
	GWP_ACL_PROTO_TCP	= 0,
	GWP_ACL_PROTO_UDP	= 1,
};

struct gwp_acl;

/*
 * A -j BIND request: pin the outgoing connection to a source address (and/or
 * port) and/or a network interface. At least one of @have_src / a non-empty
 * @iface is present. @set marks that a BIND rule matched. The 16-byte @iface is
 * IFNAMSIZ (SO_BINDTODEVICE); "" means "no interface".
 */
struct gwp_acl_bind {
	bool			set;
	bool			have_src;
	struct gwp_sockaddr	src;
	char			iface[16];
};

/*
 * Parse a -j BIND source spec -- "ip", "ip:port", "[v6]", "[v6]:port", or a
 * bare IPv6 literal -- into @out. Literal addresses only, no DNS (acl.c stays
 * self-contained). Returns 0, or -EINVAL on a malformed spec.
 *
 * Exported because the global default for -j BIND (the --bind-source option)
 * must accept exactly the syntax a rule's --to-source does; sharing the parser
 * is what keeps the two from drifting apart.
 */
int gwp_acl_parse_bind_source(const char *s, struct gwp_sockaddr *out);

/*
 * Parse an ACL rule file at @path into a new ACL. Returns 0 and stores the ACL
 * in *@out on success; a negative errno on failure (a bad rule is reported to
 * stderr with its line number). An empty/NULL @path yields *@out == NULL,
 * meaning "no ACL" (everything allowed) -- callers treat that as disabled.
 */
int gwp_acl_create(struct gwp_acl **out, const char *path);

/* Parse an ACL from an in-memory NUL-terminated rule text (used by tests). */
int gwp_acl_parse_str(struct gwp_acl **out, const char *text);

/*
 * Re-read the file the ACL was created from and atomically swap in the new
 * rules. On any parse error the previous rules are kept and a negative errno is
 * returned.
 */
int gwp_acl_reload(struct gwp_acl *acl);

/* Free an ACL (NULL is a no-op). */
void gwp_acl_destroy(struct gwp_acl *acl);

/*
 * Per-connection memo of the address-independent (-m domain / -m user)
 * results of the first GWP_ACL_MEMO_RULES such OUTPUT rules, so evaluating
 * the same request against several candidate addresses does that work once.
 * Owned by one connection; zero-initialise it, and reset it (gwp_acl_memo_reset)
 * whenever the request's domain or user may change. gwp_acl_eval_output()
 * discards it by itself when the ruleset is reloaded.
 */
#define GWP_ACL_MEMO_RULES	64
struct gwp_acl_memo {
	uint64_t	known;	/* bit i: slot i computed */
	uint64_t	ok;	/* bit i: slot i's criteria hold */
	uint32_t	gen;	/* ruleset generation of the slots */
	bool		valid;
};

static inline void gwp_acl_memo_reset(struct gwp_acl_memo *m)
{
	m->valid = false;
}

/*
 * A single evaluation request, passed by pointer to the eval helpers. Bundling
 * the parameters (and results) in one struct keeps the call sites stable as new
 * match criteria are added -- extend this struct and the matcher, not every
 * caller's argument list.
 *
 * Inputs (fields not relevant to a chain are ignored, so zero-initialise and
 * set only what applies):
 *   @client  source/client address, for -s and (via @sport) --sports; may be NULL.
 *   @target  resolved destination address, for -d; NULL when only @domain is
 *            known (e.g. socks5h remote-DNS upstream).
 *   @domain  client-requested destination hostname for -m domain, or NULL.
 *   @user    authenticated username for -m user (OUTPUT), or NULL when the
 *            connection is unauthenticated (no -m user rule then matches).
 *   @sport   client source port, host byte order (both chains).
 *   @dport   destination port, host byte order (OUTPUT).
 *   @proto   GWP_ACL_PROTO_TCP / _UDP.
 *   @memo    optional struct gwp_acl_memo (OUTPUT only), or NULL.
 *
 * Outputs (set by gwp_acl_eval_output()):
 *   @dnat_applied  true if a -j DNAT rule matched; @dnat then holds the rewrite.
 *   @mark_set/@mark  true and the fwmark from the last matched -j MARK rule.
 *                    MARK is a composable modifier: it records state and eval
 *                    keeps matching, so a later rule (or the policy) decides
 *                    the verdict -- unless that rule carries --accept, which
 *                    makes it terminal and accept on the spot.
 *   @bind    the source/interface from the last matched -j BIND rule (also a
 *            composable modifier, and likewise terminal with --accept);
 *            @bind.set is false when none matched.
 *   @gen     the ruleset generation the verdict was computed against (see
 *            gwp_acl_generation()).
 *   @cacheable  false when the verdict must not be reused for an identical
 *            request: the chain has a -m statistic rule, whose answer
 *            changes from one evaluation to the next.
 */
struct gwp_acl_req {
	/* Inputs (pointer-sized members first). */
	const struct gwp_sockaddr	*client;
	const struct gwp_sockaddr	*target;
	const char			*domain;
	const char			*user;
	struct gwp_acl_memo		*memo;

	/*
	 * Outputs. DNAT, MARK and BIND are independent, composable modifiers: a
	 * single eval can set any combination (a -j MARK, then a -j BIND, then a
	 * terminal -j DNAT can all match one connection), so they cannot share a
	 * union. Ordered largest-first to avoid padding.
	 */
	struct gwp_sockaddr		dnat;	/* rewrite; valid iff @dnat_applied */
	struct gwp_acl_bind		bind;	/* bind spec; valid iff @bind.set */
	uint32_t			mark;	/* fwmark; valid iff @mark_set */
	uint32_t			gen;

	/* Small scalars: inputs, then output flags, grouped to pack tightly. */
	uint16_t			sport;
	uint16_t			dport;
	uint8_t				proto;	/* enum gwp_acl_proto */
	bool				dnat_applied;
	bool				mark_set;
	bool				cacheable;
};

/*
 * Evaluate the OUTPUT chain (outgoing target) for @req. Returns GWP_ACL_ACCEPT
 * or GWP_ACL_REJECT; a NULL @acl returns ACCEPT. Sets @req->dnat_applied.
 */
enum gwp_acl_verdict gwp_acl_eval_output(struct gwp_acl *acl,
					 struct gwp_acl_req *req);

/*
 * The ACL's ruleset generation: it changes with every successful reload, so a
 * caller that caches an OUTPUT verdict (with the @gen and @cacheable it came
 * with) can tell whether the verdict is still current. 0 for a NULL @acl.
 */
uint32_t gwp_acl_generation(struct gwp_acl *acl);

/*
 * Evaluate the INPUT chain (incoming client) for @req. Returns GWP_ACL_ACCEPT
 * or GWP_ACL_REJECT; a NULL @acl returns ACCEPT.
 */
enum gwp_acl_verdict gwp_acl_eval_input(struct gwp_acl *acl,
					struct gwp_acl_req *req);

/*
 * How many rules of @acl's current ruleset are looked up through an index
 * instead of tested one by one: those in runs of at least 8 consecutive
 * rules that each test only an exact -m domain, a -d or a -s (not negated)
 * and end the evaluation when they match. For diagnostics and tests.
 */
uint32_t gwp_acl_nr_indexed(struct gwp_acl *acl);

#endif /* #ifndef GWP_ACL_H */
