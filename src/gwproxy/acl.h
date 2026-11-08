// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * iptables-style access-control list for gwproxy. Rules are read from a file
 * (see gwp_acl_create) and evaluated top-to-bottom, first-match-wins, against
 * incoming clients (the INPUT chain) and outgoing targets (the OUTPUT chain);
 * a chain's -P policy applies when no rule matches.
 *
 * This module is self-contained (depends only on net.h types, the upstream
 * pool types of upstream_lb.h and libc) so it can be unit-tested in
 * isolation.
 */
#ifndef GWP_ACL_H
#define GWP_ACL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <gwproxy/net.h>
#include <gwproxy/upstream_lb.h>

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
 * An upstream pool, defined in the rule file by a block:
 *
 *	upstream NAME {
 *		server URL [OPTION ...];
 *		least_conn;
 *	}
 *
 * and chosen by an OUTPUT rule's "-j UPSTREAM --to NAME". A pool belongs to
 * the ruleset that defined it, and is read-only once loaded. It is reference
 * counted, so it can outlive that ruleset after a reload: an evaluation that
 * names a pool hands the caller a reference (see struct gwp_acl_req).
 */
struct gwp_acl_pool;

/* How a pool spreads connections over its servers. */
enum gwp_acl_pool_method {
	GWP_ACL_POOL_ROUND_ROBIN	= 0,	/* the default */
	GWP_ACL_POOL_LEAST_CONN		= 1,	/* "least_conn;" */
};

/* What the OUTPUT chain chose as the upstream of a connection. */
enum gwp_acl_upstream {
	GWP_ACL_UPSTREAM_NONE	= 0,	/* no -j UPSTREAM rule matched */
	GWP_ACL_UPSTREAM_DIRECT	= 1,	/* "--to DIRECT": no upstream at all */
	GWP_ACL_UPSTREAM_POOL	= 2,	/* a pool: gwp_acl_req.upstream_pool */
	/*
	 * gwp_acl_eval_upstream() only: the choice cannot be told, and might
	 * be a pool; the caller must refuse the request rather than send it
	 * anywhere else. See there.
	 */
	GWP_ACL_UPSTREAM_UNSURE	= 3,
};

/* The pool's name, as written after "upstream". */
const char *gwp_acl_pool_name(const struct gwp_acl_pool *p);

enum gwp_acl_pool_method gwp_acl_pool_method(const struct gwp_acl_pool *p);

/*
 * True when the pool's servers resolve the target's name (socks5h://,
 * http://, https://), false when gwproxy resolves it (socks5://). Every
 * server of a pool has the same mode.
 */
bool gwp_acl_pool_remote_dns(const struct gwp_acl_pool *p);

/*
 * The most servers a pool may have; one more is a load error. A pick reads
 * the pool in place (see gwp_up_lb_pick()), whatever its size.
 */
#define GWP_ACL_POOL_MAX_SERVERS	8192u

/* How many servers the pool has: at least 1, at most the above. */
uint32_t gwp_acl_pool_nr_servers(const struct gwp_acl_pool *p);

/*
 * The URL of the pool's @i-th server (from 0, in file order), exactly as
 * written, credentials included: never log it, log gwp_acl_url_redact()'s
 * form instead. NULL when @i is out of range.
 */
const char *gwp_acl_pool_server_url(const struct gwp_acl_pool *p, uint32_t i);

/*
 * The options written after the pool's @i-th server URL (from 0), the
 * defaults for those that were not, or NULL when @i is out of range.
 */
const struct gwp_up_opts *gwp_acl_pool_server_opts(const struct gwp_acl_pool *p,
						   uint32_t i);

/*
 * The object made of the pool's @i-th server URL when the rule set loaded
 * (see struct gwp_acl_server_ops), or NULL when @i is out of range or the
 * ACL was created without ops. The pool holds a reference to it for as long
 * as the pool lives; take your own to keep it longer.
 */
void *gwp_acl_pool_server(const struct gwp_acl_pool *p, uint32_t i);

/*
 * The pool's servers as a pick sees them (struct gwp_up_member), in pool
 * order, each filled in by @ops->member (all zero without it), or NULL when
 * the ACL was created without ops. Read-only, as long as the pool lives.
 */
const struct gwp_up_member *gwp_acl_pool_members(const struct gwp_acl_pool *p);

/*
 * The pool's round-robin cursor: the value before this call's increment,
 * from 0 on, shared by every thread and wrapping at 2^32. A reload makes
 * new pools, whose cursors start again from 0.
 */
uint32_t gwp_acl_pool_next(struct gwp_acl_pool *p);

/* Take another reference to @p. */
void gwp_acl_pool_get(struct gwp_acl_pool *p);

/* Drop a reference to @p, freeing it on the last one (NULL is a no-op). */
void gwp_acl_pool_put(struct gwp_acl_pool *p);

/*
 * Copy the upstream URL @url to @buf (of @size bytes, NUL-terminated) with
 * its "user:pass@" part, if any, left out, so it can be logged. When @url
 * has an '@', everything up to and including the last one is dropped, but
 * for a leading "SCHEME://" made of scheme characters only; so a malformed
 * URL is cut too, whatever its shape. Returns 0, or -ENAMETOOLONG when the
 * result did not fit (@buf then holds as much as fits, still without
 * credentials).
 */
int gwp_acl_url_redact(const char *url, char *buf, size_t size);

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
 * stderr with its file and line number). An empty/NULL @path yields
 * *@out == NULL, meaning "no ACL" (everything allowed) -- callers treat that
 * as disabled.
 *
 * A line "include PATH;" parses the file PATH in its place: a relative PATH is
 * taken from the directory of the file that holds the line. Includes nest up
 * to 8 levels below @path, one load reads at most 64 files (a file included
 * twice counts twice), a file may not include itself (directly or through
 * others), only regular files are read, and every file must load, or nothing
 * does.
 *
 * "upstream NAME {" ... "}" defines an upstream pool (see struct
 * gwp_acl_pool) for "-j UPSTREAM --to NAME" rules anywhere in the set. A
 * file holding a server URL with credentials that group or others can read
 * is warned about on stderr; no message shows the credentials.
 */
int gwp_acl_create(struct gwp_acl **out, const char *path);

/*
 * What makes a pool server's object out of its URL, for a caller that wants
 * every server checked and set up when the rule set loads, not when a
 * connection first uses it (acl.c itself only checks the URL's shape).
 *
 * @make parses @url (it passed the shape check) into a new object with one
 * reference, stored in *@srv, and returns 0; or returns a negative errno and
 * may put the reason in @why (@size bytes), which then fails the load with
 * the file and line of the server. Neither @why nor any message may show the
 * URL's credentials. @opts are what the pool sets for the server (struct
 * gwp_up_opts). @put drops a reference @make handed out. Both get @arg, and
 * are called from the thread that loads or reloads, or (@put) from whichever
 * drops the last reference to a pool.
 *
 * @member, when set, is called once for each object @make made, with @arg,
 * and fills in what the pool keeps beside the object for the caller's picks
 * (gwp_acl_pool_members()): things the object holds for as long as it
 * lives, so a pick that scans a large pool need not reach every object.
 */
struct gwp_acl_server_ops {
	int	(*make)(void *arg, const char *url,
			const struct gwp_up_opts *opts, void **srv, char *why,
			size_t size);
	void	(*put)(void *arg, void *srv);
	void	(*member)(void *arg, void *srv, struct gwp_up_member *m);
	void	*arg;
};

/*
 * gwp_acl_create(), and every server of every pool of this load and of the
 * reloads to come is made with @ops (NULL: none, as gwp_acl_create()). @ops
 * must outlive the ACL and every pool reference taken from it.
 */
int gwp_acl_create_ops(struct gwp_acl **out, const char *path,
		       const struct gwp_acl_server_ops *ops);

/*
 * Parse an ACL from an in-memory NUL-terminated rule text (the built-in
 * default and tests). It has no directory, so "include" is refused.
 */
int gwp_acl_parse_str(struct gwp_acl **out, const char *text);

/*
 * Re-read the file the ACL was created from, and the files it includes, and
 * atomically swap in the new rules. On any error the previous rules are kept
 * and a negative errno is returned.
 */
int gwp_acl_reload(struct gwp_acl *acl);

/*
 * The @i-th file the last gwp_acl_create() or gwp_acl_reload() of @acl read
 * or tried to read, the file it was created from first and the included ones
 * after it, each once; NULL past the last one, and for an ACL from text. A
 * reload replaces the list even when it fails (a change to any of those files
 * can make the next one succeed), so these are the files to watch. Valid
 * until the next reload; call it only from the thread that reloads.
 */
const char *gwp_acl_file(const struct gwp_acl *acl, size_t i);

/*
 * What fstat() said about the @i-th file of gwp_acl_file() right before it was
 * read: returns 0 and fills *@st, or the negative errno that opening it failed
 * with (-ENOENT past the last file). A change made to the file after that
 * differs from *@st, even one made while the load was still running, which a
 * stat() taken after the load could not tell from what was read.
 */
int gwp_acl_file_stat(const struct gwp_acl *acl, size_t i, struct stat *st);

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
 *            connection is unauthenticated. No user is not any name: --user
 *            and --user-regexp do not match, and so their negations do.
 *   @sport   client source port, host byte order (both chains).
 *   @dport   destination port, host byte order (OUTPUT).
 *   @proto   GWP_ACL_PROTO_TCP / _UDP.
 *   @memo    optional struct gwp_acl_memo (OUTPUT only), or NULL.
 *   @no_target  the request has no target at all, not even a port (only
 *            for gwp_acl_eval_upstream()): a rule that tests the target,
 *            -d, --dports or -m domain in either polarity, cannot be
 *            decided and never matches. Unlike a request whose target is
 *            an address and so has no name, where "! --domain" matches.
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
 *   @upstream/@upstream_pool  the choice of the last matched -j UPSTREAM
 *            rule (a composable modifier too, terminal with --accept): an
 *            enum gwp_acl_upstream, and with GWP_ACL_UPSTREAM_POOL the pool,
 *            of which the caller then holds a reference and must drop it
 *            (gwp_acl_req_release()), or take it over (gwp_acl_req_take_pool()).
 *            Set only on an ACCEPT verdict; NONE and NULL otherwise.
 *
 * A request is a value, but after an OUTPUT evaluation it may hold an owning
 * pointer (@upstream_pool). Do not copy it while it holds one: both copies
 * would drop the same reference. Move the reference out with
 * gwp_acl_req_take_pool() instead.
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
	 * Outputs. DNAT, MARK, BIND and UPSTREAM are independent, composable
	 * modifiers: a single eval can set any combination (a -j MARK, then a
	 * -j BIND, then a terminal -j DNAT can all match one connection), so
	 * they cannot share a union. Ordered largest-first to avoid padding.
	 */
	struct gwp_acl_pool		*upstream_pool;
	struct gwp_sockaddr		dnat;	/* rewrite; valid iff @dnat_applied */
	struct gwp_acl_bind		bind;	/* bind spec; valid iff @bind.set */
	uint32_t			mark;	/* fwmark; valid iff @mark_set */
	uint32_t			gen;

	/* Small scalars: inputs, then output flags, grouped to pack tightly. */
	uint16_t			sport;
	uint16_t			dport;
	/* The rule's port, or 0; set only with @dnat_applied. */
	uint16_t			dnat_port;
	uint8_t				proto;	/* enum gwp_acl_proto */
	/* Set by gwp_acl_eval_upstream() while it runs; leave it false. */
	bool				upstream_only;
	bool				no_target;
	/* gwp_acl_eval_upstream()'s own: a pool rule could not be decided. */
	bool				upstream_unsure;
	uint8_t				upstream; /* enum gwp_acl_upstream */
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
 * Evaluate the OUTPUT chain for @req only to learn the upstream it chooses,
 * as gwp_acl_eval_output() reports it in @req->upstream(_pool), which this
 * returns too; the verdict and the other outputs are not to be used. The
 * choice is that of the last -j UPSTREAM rule met before the walk ends,
 * whether it ends on ACCEPT or REJECT: the verdict of a request that only
 * has a name is not that of its addresses, since no -d rule matches it, so
 * a REJECT here must not cost the request its pool.
 *
 * The choice is GWP_ACL_UPSTREAM_UNSURE, with no pool, when it cannot be
 * told: a regexp the walk met could not be decided, or, with @no_target, a
 * -j UPSTREAM rule to a pool was passed over only because it tests the
 * target (all its other criteria hold), as it might send the request to
 * that pool. A -j UPSTREAM --to DIRECT rule passed over that way is just
 * ignored. The caller refuses an UNSURE request. It is meant to run once
 * per connection before its real evaluations, which decide the verdict, so
 * it leaves no trace on them: a -m statistic rule says what the next real
 * evaluation would, without taking its turn. A ruleset without a
 * -j UPSTREAM rule answers GWP_ACL_UPSTREAM_NONE without an evaluation.
 */
enum gwp_acl_upstream gwp_acl_eval_upstream(struct gwp_acl *acl,
					    struct gwp_acl_req *req);

/*
 * Drop what an OUTPUT evaluation left @req holding (its pool reference) and
 * reset @req->upstream to GWP_ACL_UPSTREAM_NONE. Safe to call more than once.
 */
static inline void gwp_acl_req_release(struct gwp_acl_req *req)
{
	gwp_acl_pool_put(req->upstream_pool);
	req->upstream_pool = NULL;
	req->upstream = GWP_ACL_UPSTREAM_NONE;
}

/*
 * Hand the pool reference @req holds over to the caller, who then drops it
 * with gwp_acl_pool_put(); NULL when it holds none. @req->upstream_pool is
 * cleared, so releasing @req afterwards drops nothing, while @req->upstream
 * still tells what the evaluation chose.
 */
static inline struct gwp_acl_pool *
gwp_acl_req_take_pool(struct gwp_acl_req *req)
{
	struct gwp_acl_pool *p = req->upstream_pool;

	req->upstream_pool = NULL;
	return p;
}

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
