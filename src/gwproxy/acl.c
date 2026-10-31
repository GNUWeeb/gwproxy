// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * iptables-style ACL: parser, in-memory rule model, and matcher. See acl.h.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <gwproxy/acl.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdatomic.h>
#include <sched.h>
#include <time.h>
#include <sys/random.h>

#ifdef CONFIG_PCRE
#include <pcre2.h>
#endif

enum gwp_acl_action {
	GWP_ACL_ACT_ACCEPT	= 0,
	GWP_ACL_ACT_REJECT	= 1,
	GWP_ACL_ACT_DNAT	= 2,
	/*
	 * Composable modifiers: they record connection state (fwmark, source
	 * bind) and eval keeps matching. Only ACCEPT/REJECT/DNAT terminate.
	 */
	GWP_ACL_ACT_MARK	= 3,
	GWP_ACL_ACT_BIND	= 4,
};

enum gwp_acl_chain {
	GWP_ACL_INPUT		= 0,
	GWP_ACL_OUTPUT		= 1,
};

/* A canonicalised address prefix. IPv4 and v4-mapped IPv6 collapse to is_v4. */
struct gwp_acl_cidr {
	bool		is_v4 : 1;
	uint8_t		bits;
	uint8_t		addr[16];
};

struct gwp_acl_prange {
	uint16_t	lo;
	uint16_t	hi;
};

struct gwp_acl_ports {
	struct gwp_acl_prange	*v;
	size_t			nr;
};

/*
 * A -j DNAT rewrite. The address and port are independent: "--to 1.2.3.4:80"
 * sets both, "--to 1.2.3.4" only the address, and "--to :4444" only the port
 * (leaving the matched target's address untouched).
 */
struct gwp_acl_dnat {
	bool		set_addr : 1;
	bool		set_port : 1;
	uint8_t		family;		/* AF_INET/AF_INET6 when set_addr */
	uint16_t	port;		/* host byte order when set_port */
	uint8_t		addr[16];	/* network bytes when set_addr */
};

/*
 * The rules of a chain are kept in one array, in file order.
 *
 * Ordered to minimise padding: the pointer-aligned members lead, then the
 * address prefixes, then the action payload, then a single bit-field block.
 * Three sets of mutually exclusive fields share unions to keep the struct
 * compact as criteria grow:
 *   - the -m domain value is either an exact string or (on a PCRE build) a
 *     compiled regex, selected by @domain_is_re; likewise -m user / @user_is_re;
 *   - a rule carries exactly one -j action payload -- a DNAT rewrite, a MARK
 *     value, or a BIND spec -- selected by @action (ACCEPT/REJECT carry none).
 * The per-criterion present/negated flags and the small proto/action selectors
 * live in one bit-field block. proto/action use uint8_t so their values
 * round-trip safely (a signed 1-bit field would turn value 1 into -1).
 */
struct gwp_acl_rule {
	/* -m domain: exact .str, or compiled .re when @domain_is_re (PCRE). */
	union {
		char		*str;
#ifdef CONFIG_PCRE
		pcre2_code	*re;
#endif
	} domain;
	/* -m user: exact .str, or compiled .re when @user_is_re (PCRE). */
	union {
		char		*str;
#ifdef CONFIG_PCRE
		pcre2_code	*re;
#endif
	} user;
	struct gwp_acl_ports	sports, dports;
	struct gwp_acl_cidr	src, dst;
	/*
	 * -m statistic --mode nth: match one evaluation in @st_every, the one
	 * at offset @st_packet. @st_count is the running counter and is the
	 * only mutable state a rule carries -- see statistic_match().
	 *
	 * uint32_t, not a wider type, deliberately: an 8-byte _Atomic is not
	 * lock-free on the 32-bit targets this cross-builds for, and GCC then
	 * emits __atomic_*_8 calls that do not link.
	 */
	_Atomic(uint32_t)	st_count;
	uint32_t		st_every;
	uint32_t		st_packet;
	/* -j action payload; the live member is selected by @action. */
	union {
		struct gwp_acl_dnat	dnat;	 /* GWP_ACL_ACT_DNAT (--to) */
		uint32_t		setmark; /* GWP_ACL_ACT_MARK (--set-mark) */
		struct gwp_acl_bind	bind;	 /* GWP_ACL_ACT_BIND (--to-*) */
	} act;

	bool			has_src : 1, has_dst : 1, has_domain : 1,
				has_proto : 1, has_sports : 1, has_dports : 1;
	bool			neg_src : 1, neg_dst : 1, neg_domain : 1,
				neg_proto : 1, neg_sports : 1, neg_dports : 1;
	bool			has_user : 1, neg_user : 1;
	bool			has_statistic : 1, neg_statistic : 1;
	bool			domain_is_re : 1;	/* --domain-regexp */
	bool			user_is_re : 1;		/* --user-regexp */
	/*
	 * --accept on a MARK/BIND rule: apply the modifier, then stop and
	 * accept. Saves writing the same match twice (once to set the mark or
	 * bind, once for a following -j ACCEPT) when the rule is known to be
	 * the final word for the connections it matches.
	 */
	bool			then_accept : 1;
	uint8_t			proto : 1;	/* enum gwp_acl_proto */
	uint8_t			action : 3;	/* enum gwp_acl_action */
	/*
	 * Slot of this rule's -m domain/-m user result in a struct
	 * gwp_acl_memo, or ACL_NO_MEMO (INPUT rules, rules without those
	 * criteria, and OUTPUT rules past the memo's capacity).
	 */
	uint8_t			memo_idx;
};

#define ACL_NO_MEMO	0xff

/*
 * An index over a run of consecutive rules that each test exactly one
 * criterion out of exact -m domain, -d and -s (not negated) and end the
 * evaluation when they match (see rule_indexable()). Such a run is
 * equivalent to "the first rule in it whose value matches": every rule
 * before the run has been tested already, and no rule in it can let the
 * evaluation continue to a later one. So the run is answered with hash
 * lookups returning the lowest matching position, instead of testing its
 * rules one by one; a blocklist of thousands of hosts, networks or
 * domains costs a few lookups instead of thousands of compares.
 *
 * @dst and @src hold one entry per distinct (family, prefix length,
 * masked address), keeping the lowest position. A lookup masks the
 * address to each prefix length present in the run (@len4/@len6) and
 * takes the lowest position found. @dom holds the exact domains.
 */
#define ACL_NO_POS	UINT32_MAX

struct acl_cidr_ent {
	uint8_t		addr[16];
	uint8_t		bits;
	bool		is_v4;
	uint32_t	pos;		/* ACL_NO_POS: free entry */
};

struct acl_cidr_tab {
	struct acl_cidr_ent	*v;
	uint32_t		mask;	/* number of entries - 1 */
	uint8_t			nr_len4, nr_len6;
	uint8_t			len4[33], len6[129];
};

struct acl_dom_ent {
	const char	*str;		/* the rule's own domain string */
	uint64_t	hash;
	uint32_t	pos;		/* ACL_NO_POS: free entry */
};

struct acl_dom_tab {
	struct acl_dom_ent	*v;
	uint32_t		mask;
};

struct acl_run {
	uint32_t		start, end;	/* rule positions [start, end) */
	struct acl_cidr_tab	dst, src;
	struct acl_dom_tab	dom;
};

/* Runs shorter than this are tested rule by rule, which is as fast. */
#define ACL_INDEX_MIN	8

struct acl_chain {
	struct gwp_acl_rule	*rules;
	uint32_t		nr, cap;
	/* Indexed runs, in rule order. */
	struct acl_run		*runs;
	uint32_t		nr_runs;
	enum gwp_acl_verdict	policy;
};

struct gwp_acl_ruleset {
	struct acl_chain	in, out;
	/* Hash seed of the run indexes. */
	uint64_t		seed;
	/* The ACL generation this ruleset was published as. */
	uint32_t		gen;
	/* Rules covered by the run indexes, both chains. */
	uint32_t		nr_indexed;
	/* OUTPUT has a -m statistic rule: its verdicts must not be cached. */
	bool			out_has_stat;
};

/*
 * The rules in force are the ruleset @rs points to. A reload builds a new
 * ruleset aside and publishes it by swapping the pointer; evaluations load
 * the pointer without a lock (see rs_get()), and the replaced ruleset is
 * freed once no evaluation can still be reading it (see rs_retire()).
 */
struct gwp_acl {
	_Atomic(struct gwp_acl_ruleset *) rs;
	char			*path;
	/* Serialises reloads; evaluations never take it. */
	pthread_mutex_t		reload_lock;
	/* Bumped by every successful reload; see gwp_acl_generation(). */
	_Atomic(uint32_t)	gen;
	/*
	 * ACL_SUM_* summary of @rs, published with it: an empty chain's
	 * verdict is its policy, and the evaluators answer that from here
	 * without touching the ruleset (the built-in default ACL has no INPUT
	 * rules, so that is every accepted connection).
	 */
	_Atomic(uint8_t)	sum;
};

#define ACL_SUM_IN_EMPTY	(1u << 0)
#define ACL_SUM_OUT_EMPTY	(1u << 1)
#define ACL_SUM_IN_REJECT	(1u << 2)
#define ACL_SUM_OUT_REJECT	(1u << 3)

#define ACL_MAX_TOKENS	32

#ifdef CONFIG_PCRE
/*
 * ------------------------------------------------------------------------
 * PCRE2 regexp helpers (--domain-regexp / --user-regexp)
 * ------------------------------------------------------------------------
 *
 * Patterns are matched raw/unanchored -- the user writes ^...$ if they want a
 * full-string match. Matching runs against attacker-influenced hostnames and
 * usernames, so a shared match context caps the work to keep a pathological
 * pattern from becoming a ReDoS. The match limit bounds both the interpreter
 * and JIT-compiled code. The depth limit only bounds the interpreter: JIT
 * ignores it (pcre2api(3)), and a JIT match is bounded instead by JIT's own
 * default 32 KiB machine stack, whose exhaustion fails the match like any
 * other limit does. Every pattern is JIT-compiled when JIT is available, so
 * in practice that stack, not the depth limit, is the recursion bound.
 */
static pthread_once_t g_regex_once = PTHREAD_ONCE_INIT;
static pcre2_match_context *g_regex_mctx;

/*
 * Match data is scratch space for one pcre2_match() call. Keep one per thread
 * instead of a malloc/free pair per match (about a third of the cost of a
 * simple JIT match); the key's destructor frees it when the thread exits.
 */
static pthread_key_t g_regex_md_key;
static bool g_regex_md_key_ok;
static __thread pcre2_match_data *t_regex_md;
/* A match in this thread's current evaluation failed; see eval_chain(). */
static __thread bool t_regex_err;

static void regex_md_free(void *md)
{
	pcre2_match_data_free(md);
}

static void regex_ctx_init(void)
{
	g_regex_mctx = pcre2_match_context_create(NULL);
	if (g_regex_mctx) {
		pcre2_set_match_limit(g_regex_mctx, 100000);
		pcre2_set_depth_limit(g_regex_mctx, 1000);
	}
	g_regex_md_key_ok = !pthread_key_create(&g_regex_md_key, regex_md_free);
}

/*
 * Compile @pat, JIT-compiling it when supported. Returns NULL on error,
 * including when the limit-carrying match context could not be allocated:
 * matching would fall back to PCRE2's far larger default limits.
 */
static pcre2_code *regex_compile(const char *pat, bool caseless)
{
	uint32_t opts = caseless ? PCRE2_CASELESS : 0;
	PCRE2_SIZE erroff;
	pcre2_code *re;
	int errcode;

	pthread_once(&g_regex_once, regex_ctx_init);
	if (!g_regex_mctx)
		return NULL;
	re = pcre2_compile((PCRE2_SPTR)pat, PCRE2_ZERO_TERMINATED, opts,
			   &errcode, &erroff, NULL);
	if (!re)
		return NULL;
	pcre2_jit_compile(re, PCRE2_JIT_COMPLETE);	/* best effort */
	return re;
}

/* This thread's match data, created on first use; NULL on OOM. */
static pcre2_match_data *regex_md(void)
{
	pcre2_match_data *md = t_regex_md;

	if (md)
		return md;
	md = pcre2_match_data_create(1, NULL);
	if (!md)
		return NULL;
	if (!g_regex_md_key_ok || pthread_setspecific(g_regex_md_key, md)) {
		/* Nothing would free it at thread exit; do not cache it. */
		return md;
	}
	t_regex_md = md;
	return md;
}

/*
 * True if @re matches @subj. A match that could not be decided -- out of
 * memory, or the configured limits hit, which is what a backtracking-prone
 * pattern does on a crafted subject -- is not a non-match: it sets
 * t_regex_err, and eval_chain() turns the whole evaluation into a REJECT.
 * Read as "no match", it let such a subject straight past a REJECT rule.
 */
static bool regex_match(const pcre2_code *re, const char *subj)
{
	pcre2_match_data *md;
	int rc;

	if (!subj)
		return false;
	md = regex_md();
	if (!md) {
		t_regex_err = true;
		return false;
	}
	rc = pcre2_match(re, (PCRE2_SPTR)subj, PCRE2_ZERO_TERMINATED, 0, 0,
			 md, g_regex_mctx);
	if (md != t_regex_md)
		pcre2_match_data_free(md);
	if (rc < 0 && rc != PCRE2_ERROR_NOMATCH)
		t_regex_err = true;
	return rc >= 0;
}

static bool regex_failed(void)
{
	return t_regex_err;
}

static void regex_err_clear(void)
{
	t_regex_err = false;
}
#else
static bool regex_failed(void)
{
	return false;
}

static void regex_err_clear(void)
{
}
#endif /* CONFIG_PCRE */

/*
 * ------------------------------------------------------------------------
 * Address / port helpers
 * ------------------------------------------------------------------------
 */

/* Canonicalise a sockaddr to (is_v4, pointer to its 4- or 16-byte IP). */
static void canon_ip(const struct gwp_sockaddr *a, bool *is_v4,
		     const uint8_t **ip)
{
	if (a->sa.sa_family == AF_INET) {
		*is_v4 = true;
		*ip = (const uint8_t *)&a->i4.sin_addr;
		return;
	}
	if (IN6_IS_ADDR_V4MAPPED(&a->i6.sin6_addr)) {
		*is_v4 = true;
		*ip = &a->i6.sin6_addr.s6_addr[12];
		return;
	}
	*is_v4 = false;
	*ip = a->i6.sin6_addr.s6_addr;
}

/* Does @ip match the first @bits bits of network prefix @net? */
static bool prefix_match(const uint8_t *ip, const uint8_t *net, uint8_t bits)
{
	uint8_t full = bits / 8, rem = bits % 8;

	if (full && memcmp(ip, net, full))
		return false;
	if (rem) {
		uint8_t mask = (uint8_t)(0xffu << (8 - rem));
		if ((ip[full] & mask) != (net[full] & mask))
			return false;
	}
	return true;
}

/* Zero every bit of @addr beyond the first @bits, over @len bytes. */
static void mask_addr(uint8_t *addr, uint8_t bits, size_t len)
{
	size_t full = bits / 8, i;
	uint8_t rem = bits % 8;

	if (rem)
		addr[full++] &= (uint8_t)(0xffu << (8 - rem));
	for (i = full; i < len; i++)
		addr[i] = 0;
}

/* Parse "IP" or "IP/prefixlen" into a canonicalised prefix. */
static int parse_cidr(const char *s, struct gwp_acl_cidr *c)
{
	char buf[INET6_ADDRSTRLEN + 8];
	unsigned long bits;
	char *slash;
	struct in6_addr v6;
	uint8_t v4[4];

	if (strlen(s) >= sizeof(buf))
		return -EINVAL;
	strcpy(buf, s);

	slash = strchr(buf, '/');
	if (slash)
		*slash = '\0';

	memset(c, 0, sizeof(*c));
	if (inet_pton(AF_INET, buf, v4) == 1) {
		c->is_v4 = true;
		memcpy(c->addr, v4, 4);
		bits = 32;
	} else if (inet_pton(AF_INET6, buf, &v6) == 1) {
		c->is_v4 = false;
		memcpy(c->addr, v6.s6_addr, 16);
		bits = 128;
	} else {
		return -EINVAL;
	}

	if (slash) {
		char *end;

		errno = 0;
		bits = strtoul(slash + 1, &end, 10);
		if (errno || *end || slash[1] == '\0')
			return -EINVAL;
		if (bits > (c->is_v4 ? 32u : 128u))
			return -EINVAL;
	}

	/*
	 * cidr_match() folds a v4-mapped target (::ffff:a.b.c.d) into IPv4, so
	 * a v4-mapped rule prefix has to be folded the same way or it never
	 * matches anything. A mapped address with a prefix shorter than /96
	 * reaches outside the mapped range; that cannot be expressed as one
	 * IPv4 prefix and is most likely a mistake, so refuse it.
	 */
	if (!c->is_v4 && IN6_IS_ADDR_V4MAPPED(&v6)) {
		if (bits < 96)
			return -EINVAL;
		c->is_v4 = true;
		memcpy(c->addr, &v6.s6_addr[12], 4);
		memset(&c->addr[4], 0, 12);
		bits -= 96;
	}

	c->bits = (uint8_t)bits;
	mask_addr(c->addr, c->bits, c->is_v4 ? 4 : 16);
	return 0;
}

static bool cidr_match(const struct gwp_acl_cidr *c,
		       const struct gwp_sockaddr *addr)
{
	const uint8_t *ip;
	bool is_v4;

	canon_ip(addr, &is_v4, &ip);
	if (is_v4 != c->is_v4)
		return false;
	return prefix_match(ip, c->addr, c->bits);
}

/* Parse a port set: "80" | "1000-2000" | "80,443,1000-2000". */
static int parse_ports(const char *s, struct gwp_acl_ports *p)
{
	char buf[256];
	char *save = NULL, *tok;
	size_t cap = 0;

	if (strlen(s) >= sizeof(buf))
		return -EINVAL;
	strcpy(buf, s);

	p->v = NULL;
	p->nr = 0;
	for (tok = strtok_r(buf, ",", &save); tok;
	     tok = strtok_r(NULL, ",", &save)) {
		unsigned long lo, hi;
		char *dash, *end;

		dash = strchr(tok, '-');
		if (dash)
			*dash = '\0';

		errno = 0;
		lo = strtoul(tok, &end, 10);
		if (errno || *end || tok[0] == '\0' || lo > 65535)
			goto einval;
		if (dash) {
			errno = 0;
			hi = strtoul(dash + 1, &end, 10);
			if (errno || *end || dash[1] == '\0' || hi > 65535 ||
			    hi < lo)
				goto einval;
		} else {
			hi = lo;
		}

		if (p->nr == cap) {
			struct gwp_acl_prange *nv;

			cap = cap ? cap * 2 : 4;
			nv = realloc(p->v, cap * sizeof(*nv));
			if (!nv)
				goto enomem;
			p->v = nv;
		}
		p->v[p->nr].lo = (uint16_t)lo;
		p->v[p->nr].hi = (uint16_t)hi;
		p->nr++;
	}

	if (!p->nr)
		goto einval;
	return 0;

einval:
	free(p->v);
	p->v = NULL;
	p->nr = 0;
	return -EINVAL;
enomem:
	free(p->v);
	p->v = NULL;
	p->nr = 0;
	return -ENOMEM;
}

static bool ports_match(const struct gwp_acl_ports *p, uint16_t port)
{
	size_t i;

	for (i = 0; i < p->nr; i++)
		if (port >= p->v[i].lo && port <= p->v[i].hi)
			return true;
	return false;
}

/*
 * Parse a -j DNAT target. The address is optional, so all of these are valid:
 *   "1.2.3.4"        rewrite the address, keep the port
 *   "1.2.3.4:5678"   rewrite both
 *   ":4444"          rewrite only the port, keep the address
 *   "[2001:db8::1]:5678" / "2001:db8::1"   IPv6 forms (brackets to add a port)
 */
static int parse_dnat(const char *s, struct gwp_acl_dnat *d)
{
	char buf[INET6_ADDRSTRLEN + 8];
	char *colon = NULL, *host = buf;
	bool have_port = false;

	memset(d, 0, sizeof(*d));
	if (strlen(s) >= sizeof(buf))
		return -EINVAL;
	strcpy(buf, s);

	if (buf[0] == '[') {			/* [v6] or [v6]:port */
		char *rb = strchr(buf, ']');

		if (!rb)
			return -EINVAL;
		*rb = '\0';
		host = buf + 1;
		if (rb[1] == ':') {
			colon = rb + 1;
			have_port = true;
		} else if (rb[1] != '\0') {
			return -EINVAL;
		}
	} else {
		colon = strrchr(buf, ':');
		/*
		 * A single ':' is a "host:port" (or ":port") separator; a bare
		 * IPv6 literal has several colons and needs brackets for a port,
		 * so treat multiple colons as part of the address.
		 */
		if (colon && strchr(buf, ':') == colon)
			have_port = true;
		else
			colon = NULL;
	}

	if (have_port) {
		unsigned long port;
		char *end;

		*colon = '\0';
		errno = 0;
		port = strtoul(colon + 1, &end, 10);
		if (errno || *end || colon[1] == '\0' || port > 65535)
			return -EINVAL;
		d->port = (uint16_t)port;
		d->set_port = true;
	}

	if (host[0] == '\0')		/* port-only rewrite: address unchanged */
		return d->set_port ? 0 : -EINVAL;

	if (inet_pton(AF_INET, host, d->addr) == 1)
		d->family = AF_INET;
	else if (inet_pton(AF_INET6, host, d->addr) == 1)
		d->family = AF_INET6;
	else
		return -EINVAL;
	d->set_addr = true;
	return 0;
}

/*
 * ------------------------------------------------------------------------
 * Parser
 * ------------------------------------------------------------------------
 */

/* Free what @r points to; @r itself lives in its chain's array. */
static void free_rule(struct gwp_acl_rule *r)
{
#ifdef CONFIG_PCRE
	if (r->domain_is_re)
		pcre2_code_free(r->domain.re);
	else
		free(r->domain.str);
	if (r->user_is_re)
		pcre2_code_free(r->user.re);
	else
		free(r->user.str);
#else
	free(r->domain.str);
	free(r->user.str);
#endif
	free(r->sports.v);
	free(r->dports.v);
}

static void chain_free(struct acl_chain *c)
{
	uint32_t i;

	for (i = 0; i < c->nr; i++)
		free_rule(&c->rules[i]);
	for (i = 0; i < c->nr_runs; i++) {
		free(c->runs[i].dst.v);
		free(c->runs[i].src.v);
		free(c->runs[i].dom.v);
	}
	free(c->rules);
	free(c->runs);
	memset(c, 0, sizeof(*c));
	c->policy = GWP_ACL_ACCEPT;
}

static void ruleset_init(struct gwp_acl_ruleset *rs)
{
	memset(rs, 0, sizeof(*rs));
	rs->in.policy = GWP_ACL_ACCEPT;
	rs->out.policy = GWP_ACL_ACCEPT;
}

static void ruleset_free(struct gwp_acl_ruleset *rs)
{
	chain_free(&rs->in);
	chain_free(&rs->out);
	ruleset_init(rs);
}

/* Append a copy of @r to @c, which then owns what @r points to. */
static int chain_append(struct acl_chain *c, const struct gwp_acl_rule *r)
{
	if (c->nr == c->cap) {
		struct gwp_acl_rule *nv;
		uint32_t cap = c->cap ? c->cap * 2 : 16;

		if (cap < c->cap)
			return -ENOMEM;
		nv = realloc(c->rules, (size_t)cap * sizeof(*nv));
		if (!nv)
			return -ENOMEM;
		c->rules = nv;
		c->cap = cap;
	}
	memcpy(&c->rules[c->nr++], r, sizeof(*r));
	return 0;
}

static bool eq(const char *a, const char *b1, const char *b2)
{
	return !strcmp(a, b1) || (b2 && !strcmp(a, b2));
}

/* Parse a 32-bit unsigned value (decimal, or 0x hex) into @out; -1 on error. */
static int parse_u32(const char *s, uint32_t *out)
{
	unsigned long v;
	char *end;

	if (!*s)
		return -1;
	errno = 0;
	v = strtoul(s, &end, 0);
	if (errno || *end || v > 0xffffffffUL)
		return -1;
	*out = (uint32_t)v;
	return 0;
}

/* Parse a decimal port (1..65535, or 0 for "ephemeral") into @out; -1 bad. */
static int parse_port_num(const char *s, uint16_t *out)
{
	unsigned long v;
	char *end;

	if (!*s)
		return -1;
	errno = 0;
	v = strtoul(s, &end, 10);
	if (errno || *end || v > 65535)
		return -1;
	*out = (uint16_t)v;
	return 0;
}

/*
 * Parse a -j BIND --to-source argument (a literal source address, optionally
 * with a port) into @out: "ip", "ip:port", "[v6]:port", or a bare IPv6 literal.
 * No DNS -- acl.c is self-contained. Returns 0 on success, -EINVAL on error.
 * Also used by the global --bind-source default (see acl.h).
 */
int gwp_acl_parse_bind_source(const char *s, struct gwp_sockaddr *out)
{
	char host[64];
	const char *colon;
	uint16_t port = 0;
	struct in6_addr a6;
	struct in_addr a4;

	memset(out, 0, sizeof(*out));

	if (*s == '[') {			/* [v6] or [v6]:port */
		const char *end = strchr(s, ']');
		size_t n;

		if (!end)
			return -EINVAL;
		n = (size_t)(end - s - 1);
		if (n >= sizeof(host))
			return -EINVAL;
		memcpy(host, s + 1, n);
		host[n] = '\0';
		if (inet_pton(AF_INET6, host, &a6) != 1)
			return -EINVAL;
		s = end + 1;
		if (*s == ':') {
			if (parse_port_num(s + 1, &port))
				return -EINVAL;
		} else if (*s) {
			return -EINVAL;
		}
		out->i6.sin6_family = AF_INET6;
		out->i6.sin6_addr = a6;
		out->i6.sin6_port = htons(port);
		return 0;
	}

	if (inet_pton(AF_INET6, s, &a6) == 1) {	/* bare IPv6 literal, no port */
		out->i6.sin6_family = AF_INET6;
		out->i6.sin6_addr = a6;
		return 0;
	}

	colon = strchr(s, ':');			/* IPv4, optional :port */
	if (colon) {
		size_t n = (size_t)(colon - s);

		if (n >= sizeof(host))
			return -EINVAL;
		memcpy(host, s, n);
		host[n] = '\0';
		if (parse_port_num(colon + 1, &port))
			return -EINVAL;
	} else {
		if (strlen(s) >= sizeof(host))
			return -EINVAL;
		strcpy(host, s);
	}
	if (inet_pton(AF_INET, host, &a4) != 1)
		return -EINVAL;
	out->i4.sin_family = AF_INET;
	out->i4.sin_addr = a4;
	out->i4.sin_port = htons(port);
	return 0;
}

/* Tokenise @line in place on whitespace into @tok; returns token count or -1. */
static int tokenise(char *line, char **tok)
{
	char *save = NULL, *t;
	int n = 0;

	for (t = strtok_r(line, " \t\r", &save); t;
	     t = strtok_r(NULL, " \t\r", &save)) {
		if (n == ACL_MAX_TOKENS)
			return -1;
		tok[n++] = t;
	}
	return n;
}

static int parse_policy(struct gwp_acl_ruleset *rs, char **tok, int n)
{
	enum gwp_acl_verdict v;

	if (n != 3)
		return -EINVAL;
	if (!strcmp(tok[2], "ACCEPT"))
		v = GWP_ACL_ACCEPT;
	else if (!strcmp(tok[2], "REJECT"))
		v = GWP_ACL_REJECT;
	else
		return -EINVAL;

	if (!strcmp(tok[1], "INPUT"))
		rs->in.policy = v;
	else if (!strcmp(tok[1], "OUTPUT"))
		rs->out.policy = v;
	else
		return -EINVAL;
	return 0;
}

/* Consume the value token following an option; advances *i. */
static const char *next_val(char **tok, int n, int *i)
{
	if (*i + 1 >= n)
		return NULL;
	*i += 1;
	return tok[*i];
}

static int parse_rule(struct gwp_acl_ruleset *rs, char **tok, int n)
{
	struct gwp_acl_rule rule, *r = &rule;
	enum gwp_acl_chain chain;
	bool neg = false, m_domain = false, m_user = false, have_jump = false;
	/* -m statistic: the module, and each of its options, seen separately. */
	bool m_stat = false, have_mode = false, have_every = false;
	bool have_packet = false;
	/* At most one -j action payload group may be present (they share a union). */
	bool have_to = false, have_setmark = false;
	bool have_src = false, have_iface = false;
	bool have_accept = false;	/* --accept: MARK/BIND become terminal */
	const char *v;
	int i, ret = -EINVAL;

	if (n < 2)
		return -EINVAL;
	if (!strcmp(tok[1], "INPUT"))
		chain = GWP_ACL_INPUT;
	else if (!strcmp(tok[1], "OUTPUT"))
		chain = GWP_ACL_OUTPUT;
	else
		return -EINVAL;

	memset(r, 0, sizeof(*r));
	for (i = 2; i < n; i++) {
		const char *o = tok[i];

		if (!strcmp(o, "!")) {
			if (neg)
				goto out;
			neg = true;
			continue;
		}

		if (eq(o, "-s", "--source")) {
			v = next_val(tok, n, &i);
			if (!v || r->has_src || parse_cidr(v, &r->src))
				goto out;
			r->has_src = true;
			r->neg_src = neg;
		} else if (eq(o, "-d", "--destination")) {
			v = next_val(tok, n, &i);
			if (chain != GWP_ACL_OUTPUT || !v || r->has_dst ||
			    r->has_domain || parse_cidr(v, &r->dst))
				goto out;
			r->has_dst = true;
			r->neg_dst = neg;
		} else if (!strcmp(o, "-m")) {
			v = next_val(tok, n, &i);
			if (!v || neg)
				goto out;
			if (!strcmp(v, "domain")) {
				m_domain = true;
			} else if (!strcmp(v, "user")) {
				if (chain != GWP_ACL_OUTPUT)
					goto out;	/* -m user is OUTPUT-only */
				m_user = true;
			} else if (!strcmp(v, "statistic")) {
				m_stat = true;
			} else {
				goto out;
			}
			continue;	/* -m is not itself negatable */
		} else if (!strcmp(o, "--domain")) {
			v = next_val(tok, n, &i);
			if (chain != GWP_ACL_OUTPUT || !m_domain || !v ||
			    r->has_domain || r->has_dst)
				goto out;
			r->domain.str = strdup(v);
			if (!r->domain.str) {
				ret = -ENOMEM;
				goto out;
			}
			r->has_domain = true;
			r->neg_domain = neg;
		} else if (!strcmp(o, "--domain-regexp")) {
			v = next_val(tok, n, &i);
			if (chain != GWP_ACL_OUTPUT || !m_domain || !v ||
			    r->has_domain || r->has_dst)
				goto out;
#ifdef CONFIG_PCRE
			r->domain.re = regex_compile(v, /*caseless=*/true);
			if (!r->domain.re)
				goto out;
			r->domain_is_re = true;
			r->has_domain = true;
			r->neg_domain = neg;
#else
			/* --domain-regexp requires a --use-pcre build. */
			ret = -ENOSYS;
			goto out;
#endif
		} else if (!strcmp(o, "--user")) {
			v = next_val(tok, n, &i);
			if (chain != GWP_ACL_OUTPUT || !m_user || !v ||
			    r->has_user)
				goto out;
			r->user.str = strdup(v);
			if (!r->user.str) {
				ret = -ENOMEM;
				goto out;
			}
			r->has_user = true;
			r->neg_user = neg;
		} else if (!strcmp(o, "--user-regexp")) {
			v = next_val(tok, n, &i);
			if (chain != GWP_ACL_OUTPUT || !m_user || !v ||
			    r->has_user)
				goto out;
#ifdef CONFIG_PCRE
			/* Usernames are case-sensitive, unlike hostnames. */
			r->user.re = regex_compile(v, /*caseless=*/false);
			if (!r->user.re)
				goto out;
			r->user_is_re = true;
			r->has_user = true;
			r->neg_user = neg;
#else
			/* --user-regexp requires a --use-pcre build. */
			ret = -ENOSYS;
			goto out;
#endif
		} else if (!strcmp(o, "--mode")) {
			v = next_val(tok, n, &i);
			/*
			 * Neither --mode nor --packet is negatable, and both
			 * "continue" past the neg reset at the foot of the
			 * loop. Were they to accept a "!" it would not stop
			 * there: it would slide onto the option after them and
			 * silently invert a criterion written plainly.
			 */
			if (!m_stat || !v || have_mode || neg)
				goto out;
			/*
			 * Only nth for now. "random" is the other iptables mode
			 * and would need --probability; rejecting it by name
			 * keeps the door open without pretending to implement
			 * it -- a rule asking for it fails loudly at startup
			 * rather than silently behaving like nth.
			 */
			if (strcmp(v, "nth"))
				goto out;
			have_mode = true;
			continue;	/* --mode selects, it does not match */
		} else if (!strcmp(o, "--every")) {
			v = next_val(tok, n, &i);
			if (!m_stat || !v || have_every ||
			    parse_u32(v, &r->st_every) || r->st_every < 1)
				goto out;
			have_every = true;
			r->neg_statistic = neg;
		} else if (!strcmp(o, "--packet")) {
			v = next_val(tok, n, &i);
			if (!m_stat || !v || have_packet || neg ||
			    parse_u32(v, &r->st_packet))
				goto out;
			have_packet = true;
			continue;	/* offset only; --every carries the negation */
		} else if (eq(o, "-p", "--protocol")) {
			v = next_val(tok, n, &i);
			if (!v || r->has_proto)
				goto out;
			if (!strcmp(v, "tcp"))
				r->proto = GWP_ACL_PROTO_TCP;
			else if (!strcmp(v, "udp"))
				r->proto = GWP_ACL_PROTO_UDP;
			else
				goto out;
			r->has_proto = true;
			r->neg_proto = neg;
		} else if (!strcmp(o, "--sports")) {
			v = next_val(tok, n, &i);
			if (!v || r->has_sports || parse_ports(v, &r->sports))
				goto out;
			r->has_sports = true;
			r->neg_sports = neg;
		} else if (!strcmp(o, "--dports")) {
			v = next_val(tok, n, &i);
			if (chain != GWP_ACL_OUTPUT || !v || r->has_dports ||
			    parse_ports(v, &r->dports))
				goto out;
			r->has_dports = true;
			r->neg_dports = neg;
		} else if (eq(o, "-j", "--jump")) {
			if (neg || have_jump)
				goto out;
			v = next_val(tok, n, &i);
			if (!v)
				goto out;
			if (!strcmp(v, "ACCEPT")) {
				r->action = GWP_ACL_ACT_ACCEPT;
			} else if (!strcmp(v, "REJECT")) {
				r->action = GWP_ACL_ACT_REJECT;
			} else if (!strcmp(v, "DNAT")) {
				r->action = GWP_ACL_ACT_DNAT;
			} else if (!strcmp(v, "MARK")) {
				if (chain != GWP_ACL_OUTPUT)  /* egress sockets */
					goto out;
				r->action = GWP_ACL_ACT_MARK;
			} else if (!strcmp(v, "BIND")) {
				if (chain != GWP_ACL_OUTPUT)  /* egress sockets */
					goto out;
				r->action = GWP_ACL_ACT_BIND;
			} else {
				goto out;
			}
			have_jump = true;
		} else if (eq(o, "--to-destination", "--to")) {
			/* DNAT payload: no other action group may share the union. */
			v = next_val(tok, n, &i);
			if (neg || !v || have_to || have_setmark || have_src ||
			    have_iface || parse_dnat(v, &r->act.dnat))
				goto out;
			have_to = true;
		} else if (!strcmp(o, "--set-mark")) {
			/* MARK payload: mutually exclusive with DNAT/BIND. */
			v = next_val(tok, n, &i);
			if (neg || !v || have_to || have_setmark || have_src ||
			    have_iface || parse_u32(v, &r->act.setmark))
				goto out;
			have_setmark = true;
		} else if (!strcmp(o, "--to-source")) {
			/* BIND payload: may pair with --to-iface, not DNAT/MARK. */
			v = next_val(tok, n, &i);
			if (neg || !v || have_to || have_setmark || have_src ||
			    gwp_acl_parse_bind_source(v, &r->act.bind.src))
				goto out;
			r->act.bind.have_src = true;
			have_src = true;
		} else if (!strcmp(o, "--to-iface")) {
			v = next_val(tok, n, &i);
			if (neg || !v || have_to || have_setmark || have_iface ||
			    strlen(v) >= sizeof(r->act.bind.iface))
				goto out;
			memcpy(r->act.bind.iface, v, strlen(v) + 1);
			have_iface = true;
		} else if (!strcmp(o, "--accept")) {
			/*
			 * Takes no value, so no next_val() here -- a following
			 * token is the next option, not this one's argument.
			 * Which actions may carry it is checked after the loop,
			 * where -j is known regardless of token order.
			 */
			if (neg || have_accept)
				goto out;
			have_accept = true;
		} else {
			goto out;		/* unknown option */
		}

		neg = false;
	}

	if (neg || !have_jump)
		goto out;

	/*
	 * A declared match module must be followed by its value option: "-m
	 * domain" needs --domain/--domain-regexp, "-m user" needs
	 * --user/--user-regexp. Otherwise the module is a no-op and the rule
	 * silently matches everything (a typo like "--domian" would become an
	 * unconditional ACCEPT/REJECT).
	 */
	if (m_domain && !r->has_domain)
		goto out;
	if (m_user && !r->has_user)
		goto out;

	/*
	 * Same rule for -m statistic: without both --mode and --every it would
	 * be a no-op that matches everything. --packet on its own is likewise
	 * meaningless, and a --packet at or beyond --every can never come up,
	 * so the rule would be dead -- both are far more likely to be typos
	 * than intent.
	 */
	if (m_stat != (have_mode && have_every))
		goto out;
	if (have_packet && !m_stat)
		goto out;
	if (m_stat) {
		if (r->st_packet >= r->st_every)
			goto out;
		r->has_statistic = true;
	}

	/*
	 * Exactly the action's own payload group may be present. The cross-group
	 * guards above already reject mixing DNAT/MARK/BIND options, so here we
	 * only require the matching group and forbid a stray one on an action
	 * that takes no payload (ACCEPT/REJECT).
	 */
	switch (r->action) {
	case GWP_ACL_ACT_DNAT:
		if (chain != GWP_ACL_OUTPUT)	/* DNAT rewrites targets */
			goto out;
		if (!have_to)			/* DNAT needs --to */
			goto out;
		if (have_accept)		/* DNAT already terminates */
			goto out;
		break;
	case GWP_ACL_ACT_MARK:
		if (!have_setmark)		/* MARK needs --set-mark */
			goto out;
		r->then_accept = have_accept;
		break;
	case GWP_ACL_ACT_BIND:
		if (!have_src && !have_iface)	/* BIND needs a source or iface */
			goto out;
		r->act.bind.set = true;
		r->then_accept = have_accept;
		break;
	default:				/* ACCEPT / REJECT: no payload */
		if (have_to || have_setmark || have_src || have_iface)
			goto out;
		/*
		 * --accept only means something on a modifier. On ACCEPT it is
		 * redundant and on REJECT it contradicts the action, so take it
		 * as a mistake rather than silently ignoring it.
		 */
		if (have_accept)
			goto out;
		break;
	}

	/* Slots are handed out once the indexes are known; see index_chain(). */
	r->memo_idx = ACL_NO_MEMO;
	ret = chain_append(chain == GWP_ACL_INPUT ? &rs->in : &rs->out, r);
	if (ret)
		goto out;
	if (chain == GWP_ACL_OUTPUT && r->has_statistic)
		rs->out_has_stat = true;
	return 0;

out:
	free_rule(r);
	return ret;
}

static int parse_line(struct gwp_acl_ruleset *rs, char *line)
{
	char *tok[ACL_MAX_TOKENS];
	char *hash;
	int n;

	/*
	 * A comment starts with a '#' that begins a token. A '#' inside a
	 * token is part of its value: a regexp such as "^[^#]+$" must not be
	 * cut short into a different, broader pattern.
	 */
	for (hash = strchr(line, '#'); hash; hash = strchr(hash + 1, '#')) {
		if (hash == line || strchr(" \t\r", hash[-1])) {
			*hash = '\0';
			break;
		}
	}

	n = tokenise(line, tok);
	if (n < 0)
		return -EINVAL;
	if (n == 0)
		return 0;		/* blank / comment-only */

	if (!strcmp(tok[0], "-P"))
		return parse_policy(rs, tok, n);
	if (!strcmp(tok[0], "-A"))
		return parse_rule(rs, tok, n);
	return -EINVAL;
}

/*
 * ------------------------------------------------------------------------
 * Run indexes (see struct acl_run)
 * ------------------------------------------------------------------------
 */

/*
 * ASCII-only case-insensitive compare and hash for -m domain. strcasecmp()
 * follows the locale; the proxy runs in the C locale, where the two agree,
 * and the index needs the compare and the hash to fold exactly the same
 * bytes, so neither may depend on it.
 */
static unsigned char ascii_lower(unsigned char c)
{
	return (c >= 'A' && c <= 'Z') ? (unsigned char)(c | 0x20) : c;
}

static int ascii_casecmp(const char *a, const char *b)
{
	const unsigned char *x = (const unsigned char *)a;
	const unsigned char *y = (const unsigned char *)b;

	while (*x && ascii_lower(*x) == ascii_lower(*y)) {
		x++;
		y++;
	}
	return ascii_lower(*x) - ascii_lower(*y);
}

static uint64_t mix64(uint64_t x)
{
	x ^= x >> 33;
	x *= 0xff51afd7ed558ccdULL;
	x ^= x >> 33;
	x *= 0xc4ceb9fe1a85ec53ULL;
	x ^= x >> 33;
	return x;
}

static uint64_t dom_hash(uint64_t seed, const char *s)
{
	const unsigned char *p = (const unsigned char *)s;
	uint64_t h = seed ^ 0xcbf29ce484222325ULL;

	for (; *p; p++) {
		h ^= ascii_lower(*p);
		h *= 0x100000001b3ULL;
	}
	return mix64(h);
}

/* @addr is the masked 16-byte key: zero beyond the prefix and the family. */
static uint64_t cidr_hash(uint64_t seed, const uint8_t *addr, uint8_t bits,
			  bool is_v4)
{
	uint64_t a, b;

	memcpy(&a, addr, 8);
	memcpy(&b, addr + 8, 8);
	return mix64(mix64(mix64(seed ^ ((uint64_t)bits << 1 | is_v4)) ^ a) ^ b);
}

/* Power-of-two table size for @nr entries, at most half full. */
static uint32_t tab_size(uint32_t nr)
{
	uint32_t n = 16;

	while (n < nr * 2)
		n *= 2;
	return n;
}

static void cidr_key(uint8_t key[16], const uint8_t *ip, bool is_v4,
		     uint8_t bits)
{
	size_t len = is_v4 ? 4 : 16;

	memset(key, 0, 16);
	memcpy(key, ip, len);
	mask_addr(key, bits, len);
}

static int cidr_tab_init(struct acl_cidr_tab *t, uint32_t nr)
{
	uint32_t i, size;

	if (!nr)
		return 0;
	size = tab_size(nr);
	t->v = malloc((size_t)size * sizeof(*t->v));
	if (!t->v)
		return -ENOMEM;
	for (i = 0; i < size; i++)
		t->v[i].pos = ACL_NO_POS;
	t->mask = size - 1;
	return 0;
}

static void cidr_tab_add(struct acl_cidr_tab *t, uint64_t seed,
			 const struct gwp_acl_cidr *c, uint32_t pos)
{
	uint8_t *lens = c->is_v4 ? t->len4 : t->len6;
	uint8_t *nr_len = c->is_v4 ? &t->nr_len4 : &t->nr_len6;
	uint32_t i;
	uint8_t k;

	for (k = 0; k < *nr_len; k++)
		if (lens[k] == c->bits)
			break;
	if (k == *nr_len)
		lens[(*nr_len)++] = c->bits;

	/* c->addr is already masked by parse_cidr(). */
	i = (uint32_t)cidr_hash(seed, c->addr, c->bits, c->is_v4) & t->mask;
	for (; t->v[i].pos != ACL_NO_POS; i = (i + 1) & t->mask) {
		struct acl_cidr_ent *e = &t->v[i];

		/* An earlier rule with the same prefix shadows this one. */
		if (e->bits == c->bits && e->is_v4 == c->is_v4 &&
		    !memcmp(e->addr, c->addr, 16))
			return;
	}
	memcpy(t->v[i].addr, c->addr, 16);
	t->v[i].bits = c->bits;
	t->v[i].is_v4 = c->is_v4;
	t->v[i].pos = pos;
}

/* Lowest position in @t whose prefix contains @a, or ACL_NO_POS. */
static uint32_t cidr_tab_find(const struct acl_cidr_tab *t, uint64_t seed,
			      const struct gwp_sockaddr *a)
{
	const uint8_t *lens, *ip;
	uint32_t best = ACL_NO_POS;
	uint8_t k, nr_len;
	bool is_v4;

	canon_ip(a, &is_v4, &ip);
	lens = is_v4 ? t->len4 : t->len6;
	nr_len = is_v4 ? t->nr_len4 : t->nr_len6;
	for (k = 0; k < nr_len; k++) {
		uint8_t key[16];
		uint32_t i;

		cidr_key(key, ip, is_v4, lens[k]);
		i = (uint32_t)cidr_hash(seed, key, lens[k], is_v4) & t->mask;
		for (; t->v[i].pos != ACL_NO_POS; i = (i + 1) & t->mask) {
			const struct acl_cidr_ent *e = &t->v[i];

			if (e->bits == lens[k] && e->is_v4 == is_v4 &&
			    !memcmp(e->addr, key, 16)) {
				if (e->pos < best)
					best = e->pos;
				break;
			}
		}
	}
	return best;
}

static int dom_tab_init(struct acl_dom_tab *t, uint32_t nr)
{
	uint32_t i, size;

	if (!nr)
		return 0;
	size = tab_size(nr);
	t->v = malloc((size_t)size * sizeof(*t->v));
	if (!t->v)
		return -ENOMEM;
	for (i = 0; i < size; i++)
		t->v[i].pos = ACL_NO_POS;
	t->mask = size - 1;
	return 0;
}

static void dom_tab_add(struct acl_dom_tab *t, uint64_t seed, const char *str,
			uint32_t pos)
{
	uint64_t h = dom_hash(seed, str);
	uint32_t i = (uint32_t)h & t->mask;

	for (; t->v[i].pos != ACL_NO_POS; i = (i + 1) & t->mask) {
		/* An earlier rule with the same domain shadows this one. */
		if (t->v[i].hash == h && !ascii_casecmp(t->v[i].str, str))
			return;
	}
	t->v[i].str = str;
	t->v[i].hash = h;
	t->v[i].pos = pos;
}

static uint32_t dom_tab_find(const struct acl_dom_tab *t, uint64_t seed,
			     const char *str)
{
	uint64_t h = dom_hash(seed, str);
	uint32_t i = (uint32_t)h & t->mask;

	for (; t->v[i].pos != ACL_NO_POS; i = (i + 1) & t->mask) {
		if (t->v[i].hash == h && !ascii_casecmp(t->v[i].str, str))
			return t->v[i].pos;
	}
	return ACL_NO_POS;
}

/*
 * Can @r be answered by a run index? It must test exactly one criterion,
 * an exact -m domain, a -d or a -s, not negated; and a match must end the
 * evaluation, so that the first matching rule of the run decides it and
 * nothing after it can matter. MARK and BIND without --accept let the
 * evaluation go on (and the last one wins), so they are tested rule by
 * rule.
 */
static bool rule_indexable(const struct gwp_acl_rule *r)
{
	unsigned nr_crit;

	switch (r->action) {
	case GWP_ACL_ACT_ACCEPT:
	case GWP_ACL_ACT_REJECT:
	case GWP_ACL_ACT_DNAT:
		break;
	default:
		if (!r->then_accept)
			return false;
		break;
	}
	if (r->has_proto || r->has_sports || r->has_dports || r->has_user ||
	    r->has_statistic)
		return false;
	nr_crit = r->has_dst + r->has_src + r->has_domain;
	if (nr_crit != 1)
		return false;
	if (r->has_dst)
		return !r->neg_dst;
	if (r->has_src)
		return !r->neg_src;
	return !r->neg_domain && !r->domain_is_re;
}

static int run_build(struct acl_run *run, const struct acl_chain *c,
		     uint64_t seed)
{
	uint32_t nr_dst = 0, nr_src = 0, nr_dom = 0, i;

	for (i = run->start; i < run->end; i++) {
		const struct gwp_acl_rule *r = &c->rules[i];

		nr_dst += r->has_dst;
		nr_src += r->has_src;
		nr_dom += r->has_domain;
	}
	if (cidr_tab_init(&run->dst, nr_dst) ||
	    cidr_tab_init(&run->src, nr_src) ||
	    dom_tab_init(&run->dom, nr_dom))
		return -ENOMEM;

	for (i = run->start; i < run->end; i++) {
		const struct gwp_acl_rule *r = &c->rules[i];

		if (r->has_dst)
			cidr_tab_add(&run->dst, seed, &r->dst, i);
		else if (r->has_src)
			cidr_tab_add(&run->src, seed, &r->src, i);
		else
			dom_tab_add(&run->dom, seed, r->domain.str, i);
	}
	return 0;
}

/*
 * Position of the first rule of @run that matches @q, or ACL_NO_POS. The
 * same answers rule_matches() gives each rule of the run: -d needs a
 * resolved target, -s a client address and -m domain a requested name.
 */
static uint32_t run_find(const struct acl_run *run, uint64_t seed,
			 const struct gwp_acl_req *q)
{
	uint32_t best = ACL_NO_POS, pos;

	if (run->dst.v && q->target)
		best = cidr_tab_find(&run->dst, seed, q->target);
	if (run->src.v && q->client) {
		pos = cidr_tab_find(&run->src, seed, q->client);
		if (pos < best)
			best = pos;
	}
	if (run->dom.v && q->domain) {
		pos = dom_tab_find(&run->dom, seed, q->domain);
		if (pos < best)
			best = pos;
	}
	return best;
}

/* Index the long runs of @c, then hand out the memo slots (OUTPUT). */
static int index_chain(struct gwp_acl_ruleset *rs, struct acl_chain *c,
		       bool memo)
{
	uint32_t i = 0, start, nr_memo = 0;
	struct acl_run *run;
	int ret;

	while (i < c->nr) {
		if (!rule_indexable(&c->rules[i])) {
			i++;
			continue;
		}
		start = i;
		while (i < c->nr && rule_indexable(&c->rules[i]))
			i++;
		if (i - start < ACL_INDEX_MIN)
			continue;

		run = realloc(c->runs, (size_t)(c->nr_runs + 1) * sizeof(*run));
		if (!run)
			return -ENOMEM;
		c->runs = run;
		run = &c->runs[c->nr_runs++];
		memset(run, 0, sizeof(*run));
		run->start = start;
		run->end = i;
		ret = run_build(run, c, rs->seed);
		if (ret)
			return ret;
		rs->nr_indexed += i - start;
	}

	if (!memo)
		return 0;

	/*
	 * An indexed rule's -m domain is one hash lookup, so the memo's
	 * slots go to the rules that are tested one by one.
	 */
	run = c->runs;
	for (i = 0; i < c->nr && nr_memo < GWP_ACL_MEMO_RULES; i++) {
		struct gwp_acl_rule *r = &c->rules[i];

		if (run != c->runs + c->nr_runs && i == run->start) {
			i = run->end - 1;
			run++;
			continue;
		}
		if (r->has_domain || r->has_user)
			r->memo_idx = (uint8_t)nr_memo++;
	}
	return 0;
}

static uint64_t index_seed(const void *salt)
{
	struct timespec ts;
	uint64_t seed;

	if (getrandom(&seed, sizeof(seed), GRND_NONBLOCK) == sizeof(seed))
		return seed;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return mix64((uint64_t)ts.tv_nsec ^ ((uint64_t)ts.tv_sec << 32) ^
		     (uint64_t)(uintptr_t)salt);
}

static int ruleset_index(struct gwp_acl_ruleset *rs)
{
	int ret;

	rs->seed = index_seed(rs);
	ret = index_chain(rs, &rs->in, false);
	if (!ret)
		ret = index_chain(rs, &rs->out, true);
	return ret;
}

static int parse_text(struct gwp_acl_ruleset *rs, const char *text)
{
	char *copy, *cursor, *line;
	unsigned lineno = 0;
	int r = 0;

	ruleset_init(rs);

	copy = strdup(text);
	if (!copy)
		return -ENOMEM;

	cursor = copy;
	while ((line = strsep(&cursor, "\n")) != NULL) {
		lineno++;
		r = parse_line(rs, line);
		if (r) {
			fprintf(stderr, "acl: parse error on line %u: %s\n",
				lineno, strerror(-r));
			break;
		}
	}
	if (!r)
		r = ruleset_index(rs);
	if (r)
		ruleset_free(rs);

	free(copy);
	return r;
}

static int read_file(const char *path, char **out)
{
	long sz;
	char *buf;
	size_t rd;
	FILE *fp;

	fp = fopen(path, "rb");
	if (!fp)
		return -errno;

	if (fseek(fp, 0, SEEK_END) || (sz = ftell(fp)) < 0 ||
	    fseek(fp, 0, SEEK_SET)) {
		fclose(fp);
		return -EIO;
	}

	/*
	 * An empty file is what a writer that truncates the file and then
	 * fills it leaves in between, and loading it would replace every rule
	 * with two ACCEPT policies. A file meant to have no rules still needs
	 * a line (a comment will do), so refuse an empty one.
	 */
	if (!sz) {
		fprintf(stderr, "acl: %s: file is empty\n", path);
		fclose(fp);
		return -ENODATA;
	}

	buf = malloc((size_t)sz + 1);
	if (!buf) {
		fclose(fp);
		return -ENOMEM;
	}

	/*
	 * The text is parsed as a C string, so a NUL byte would silently end
	 * the file there and drop every rule after it. And a file that is
	 * shorter or longer than its size said was changed while being read:
	 * what was read is not the whole of any version of it. Refuse both
	 * rather than load a partial rule set. Asking for one byte more than
	 * the size is what notices a file that grew.
	 */
	rd = fread(buf, 1, (size_t)sz + 1, fp);
	if (ferror(fp) || rd != (size_t)sz) {
		fprintf(stderr, "acl: %s: changed while being read\n", path);
		free(buf);
		fclose(fp);
		return -EIO;
	}
	fclose(fp);
	if (memchr(buf, '\0', rd)) {
		fprintf(stderr, "acl: %s: contains a NUL byte\n", path);
		free(buf);
		return -EINVAL;
	}
	buf[rd] = '\0';
	*out = buf;
	return 0;
}

/*
 * ------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------
 */

static uint8_t ruleset_summary(const struct gwp_acl_ruleset *rs)
{
	uint8_t sum = 0;

	if (!rs->in.nr)
		sum |= ACL_SUM_IN_EMPTY;
	if (!rs->out.nr)
		sum |= ACL_SUM_OUT_EMPTY;
	if (rs->in.policy == GWP_ACL_REJECT)
		sum |= ACL_SUM_IN_REJECT;
	if (rs->out.policy == GWP_ACL_REJECT)
		sum |= ACL_SUM_OUT_REJECT;
	return sum;
}

static void ruleset_destroy(struct gwp_acl_ruleset *rs)
{
	if (!rs)
		return;
	ruleset_free(rs);
	free(rs);
}

/*
 * ------------------------------------------------------------------------
 * Ruleset publication
 * ------------------------------------------------------------------------
 *
 * Every worker evaluates the rules for every connection, and a reload may
 * replace them at any time. A lock around each evaluation, even a read
 * lock, makes every evaluation on every worker write the same lock word,
 * so its cache line bounces between all of them and the throughput of the
 * whole proxy stays at what one core manages; the reload also had to wait
 * for the readers to let it in.
 *
 * Instead the ruleset is published RCU-style through one pointer, and its
 * memory is reclaimed with hazard pointers. Each thread that evaluates
 * owns a reader slot on a cache line of its own. To read, it stores the
 * ruleset pointer it loaded in its slot and loads the pointer again; when
 * both agree, the ruleset cannot be freed until the slot is cleared, which
 * it is at the end of the evaluation. A reload swaps the pointer, then
 * waits until no slot still holds the old ruleset, then frees it. Readers
 * write only their own line and never wait; the reload waits for at most
 * the evaluations that had already started on the old rules, because any
 * later one finds the new pointer.
 *
 * Why not the alternatives:
 *   - a reference count in the ruleset is again one shared word that every
 *     evaluation writes, twice;
 *   - quiescent-state counters bumped by each worker at the top of its
 *     event loop would make the read side free of fences, but acl.c would
 *     have to know about the workers and both event loops would have to
 *     report to it, and a thread that is not a worker (the unit tests, a
 *     reload helper) or a worker blocked in its loop would hold up or
 *     escape the grace period;
 *   - a per-thread epoch counter costs the reader the same fence as a
 *     hazard pointer, but makes the reload wait for any evaluation in
 *     progress, not only those on the rules being replaced.
 * The price here is one sequentially consistent store, to the thread's own
 * slot, per evaluation.
 *
 * The slots form a list that only grows; a thread's slot goes back to the
 * pool when it exits (a pthread key destructor) and the next new thread
 * reuses it, so the list is as long as the most threads that ever
 * evaluated at once. If a slot cannot be allocated, the thread borrows the
 * one static fallback slot under a mutex instead, so an evaluation never
 * fails for want of memory.
 */
struct acl_reader {
	_Atomic(struct gwp_acl_ruleset *) hazard;
	_Atomic(bool)		in_use;
	/* Set before the slot is published; never changes afterwards. */
	struct acl_reader	*next;
} __attribute__((__aligned__(64)));

static struct acl_reader g_reader_fallback;
static pthread_mutex_t g_reader_fallback_lock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic(struct acl_reader *) g_readers = &g_reader_fallback;
static pthread_once_t g_reader_once = PTHREAD_ONCE_INIT;
static pthread_key_t g_reader_key;
static bool g_reader_key_ok;
static __thread struct acl_reader *t_reader;

static void reader_release(void *p)
{
	struct acl_reader *r = p;

	t_reader = NULL;
	atomic_store_explicit(&r->in_use, false, memory_order_release);
}

static void reader_key_init(void)
{
	g_reader_key_ok = !pthread_key_create(&g_reader_key, reader_release);
}

/* This thread's reader slot, claimed or allocated on first use; NULL on OOM. */
static struct acl_reader *reader_get(void)
{
	struct acl_reader *r = t_reader, *head;
	void *mem;

	if (r)
		return r;

	pthread_once(&g_reader_once, reader_key_init);
	head = atomic_load_explicit(&g_readers, memory_order_acquire);
	for (r = head; r; r = r->next) {
		bool free_slot = false;

		if (r == &g_reader_fallback)
			continue;
		if (atomic_compare_exchange_strong_explicit(&r->in_use,
							    &free_slot, true,
							    memory_order_acquire,
							    memory_order_relaxed))
			goto claimed;
	}

	if (posix_memalign(&mem, 64, sizeof(*r)))
		return NULL;
	r = mem;
	atomic_init(&r->hazard, NULL);
	atomic_init(&r->in_use, true);
	/*
	 * Sequentially consistent, like the reload's swap and its load of
	 * the list head: a reload whose scan misses this slot swapped the
	 * pointer before the push, so this thread's first rs_get() already
	 * finds the new ruleset.
	 */
	r->next = head;
	while (!atomic_compare_exchange_weak_explicit(&g_readers, &head, r,
						      memory_order_seq_cst,
						      memory_order_acquire))
		r->next = head;

claimed:
	/*
	 * Without the key the slot is not returned at thread exit; that
	 * leaks one slot per thread, which is still correct.
	 */
	if (g_reader_key_ok)
		pthread_setspecific(g_reader_key, r);
	t_reader = r;
	return r;
}

/*
 * Enter a read section on @acl's current ruleset and return it. It stays
 * valid until the matching rs_put(@*slot). Read sections do not nest.
 */
static struct gwp_acl_ruleset *rs_get(struct gwp_acl *acl,
				      struct acl_reader **slot)
{
	struct gwp_acl_ruleset *rs, *again;
	struct acl_reader *r = reader_get();

	if (!r) {
		pthread_mutex_lock(&g_reader_fallback_lock);
		r = &g_reader_fallback;
	}

	rs = atomic_load_explicit(&acl->rs, memory_order_relaxed);
	for (;;) {
		/*
		 * The store must be visible before the pointer is checked
		 * again (store-load order, hence seq_cst on both): a reload
		 * that swaps after the check sees the hazard in its scan.
		 */
		atomic_store_explicit(&r->hazard, rs, memory_order_seq_cst);
		again = atomic_load_explicit(&acl->rs, memory_order_seq_cst);
		if (again == rs)
			break;
		rs = again;
	}
	*slot = r;
	return rs;
}

static void rs_put(struct acl_reader *r)
{
	atomic_store_explicit(&r->hazard, NULL, memory_order_release);
	if (r == &g_reader_fallback)
		pthread_mutex_unlock(&g_reader_fallback_lock);
}

/*
 * Free @old, which is no longer published, once no read section can still
 * be using it. Only the evaluations that loaded @old before it was swapped
 * out are waited for, and each of them is one evaluation long.
 */
static void rs_retire(struct gwp_acl_ruleset *old)
{
	struct acl_reader *r;

	r = atomic_load_explicit(&g_readers, memory_order_seq_cst);
	for (; r; r = r->next) {
		while (atomic_load_explicit(&r->hazard,
					    memory_order_seq_cst) == old)
			sched_yield();
	}
	ruleset_destroy(old);
}

int gwp_acl_parse_str(struct gwp_acl **out, const char *text)
{
	struct gwp_acl_ruleset *rs;
	struct gwp_acl *acl;
	int r;

	acl = calloc(1, sizeof(*acl));
	rs = malloc(sizeof(*rs));
	if (!acl || !rs) {
		free(acl);
		free(rs);
		return -ENOMEM;
	}

	r = pthread_mutex_init(&acl->reload_lock, NULL);
	if (r) {
		free(acl);
		free(rs);
		return -r;
	}

	r = parse_text(rs, text);
	if (r) {
		pthread_mutex_destroy(&acl->reload_lock);
		free(acl);
		free(rs);
		return r;
	}
	rs->gen = 0;
	atomic_init(&acl->rs, rs);
	atomic_init(&acl->gen, 0);
	atomic_init(&acl->sum, ruleset_summary(rs));

	*out = acl;
	return 0;
}

int gwp_acl_create(struct gwp_acl **out, const char *path)
{
	struct gwp_acl *acl;
	char *text;
	int r;

	if (!path || !path[0]) {
		*out = NULL;
		return 0;
	}

	r = read_file(path, &text);
	if (r)
		return r;

	r = gwp_acl_parse_str(&acl, text);
	free(text);
	if (r)
		return r;

	acl->path = strdup(path);
	if (!acl->path) {
		gwp_acl_destroy(acl);
		return -ENOMEM;
	}

	*out = acl;
	return 0;
}

int gwp_acl_reload(struct gwp_acl *acl)
{
	struct gwp_acl_ruleset *rs, *old;
	uint32_t gen;
	char *text;
	int r;

	if (!acl || !acl->path)
		return -EINVAL;

	r = read_file(acl->path, &text);
	if (r)
		return r;

	rs = malloc(sizeof(*rs));
	if (!rs) {
		free(text);
		return -ENOMEM;
	}
	r = parse_text(rs, text);
	free(text);
	if (r) {
		free(rs);
		return r;			/* keep the old rules */
	}

	pthread_mutex_lock(&acl->reload_lock);
	gen = atomic_load_explicit(&acl->gen, memory_order_relaxed) + 1;
	rs->gen = gen;
	old = atomic_exchange_explicit(&acl->rs, rs, memory_order_seq_cst);
	/*
	 * Summary before generation: a reader on the empty-chain path loads
	 * the generation first, so one that sees the new generation also sees
	 * the new summary, and a verdict is never tagged newer than its rules.
	 * A verdict from the ruleset itself is tagged with its own @gen.
	 */
	atomic_store_explicit(&acl->sum, ruleset_summary(rs),
			      memory_order_release);
	atomic_store_explicit(&acl->gen, gen, memory_order_release);
	pthread_mutex_unlock(&acl->reload_lock);

	rs_retire(old);
	return 0;
}

/* The caller guarantees that no evaluation is running or will start. */
void gwp_acl_destroy(struct gwp_acl *acl)
{
	if (!acl)
		return;
	ruleset_destroy(atomic_load_explicit(&acl->rs, memory_order_relaxed));
	pthread_mutex_destroy(&acl->reload_lock);
	free(acl->path);
	free(acl);
}

/*
 * ------------------------------------------------------------------------
 * Matcher
 * ------------------------------------------------------------------------
 */

/*
 * A single match criterion fails the rule when it is present and its match
 * result equals its negation flag (a present criterion is satisfied by
 * matched XOR negated). Only evaluated behind the rule's has_* flag, so a
 * criterion the rule does not use costs one bit test.
 */
#define CRIT_FAILS(r, has, neg, matched) ((r)->has && ((matched) == (r)->neg))

/*
 * True if rule @r's -m domain criterion matches the requested hostname @dom
 * (exact, case-insensitive; or PCRE when --domain-regexp was used). Returns
 * false for a NULL @dom so a literal-IP request never matches a domain rule.
 */
static bool domain_match(const struct gwp_acl_rule *r, const char *dom)
{
	if (!dom)
		return false;
#ifdef CONFIG_PCRE
	if (r->domain_is_re)
		return r->domain.re && regex_match(r->domain.re, dom);
#endif
	return r->domain.str && !ascii_casecmp(dom, r->domain.str);
}

/*
 * True if rule @r's -m user criterion matches the authenticated username @user
 * (exact, case-sensitive; or PCRE when --user-regexp was used). Returns false
 * for a NULL @user so an unauthenticated connection never matches a user rule.
 */
static bool user_match(const struct gwp_acl_rule *r, const char *user)
{
	if (!user)
		return false;
#ifdef CONFIG_PCRE
	if (r->user_is_re)
		return r->user.re && regex_match(r->user.re, user);
#endif
	return r->user.str && !strcmp(user, r->user.str);
}

/*
 * -m statistic --mode nth: match one evaluation in @st_every, the one whose
 * index modulo @st_every equals @st_packet.
 *
 * fetch_add rather than a read-modify-write loop, so concurrent workers each
 * take a distinct ticket and the split stays exact under load instead of
 * degrading into "whoever raced". Relaxed ordering: the counter is not
 * synchronising anything, it only has to be handed out without duplicates.
 *
 * The rule is shared by every thread that evaluates the ruleset, so this is
 * the one place a rule is written to; @st_count being atomic is what makes
 * that safe while rules are otherwise read-only.
 *
 * Note the counter counts EVALUATIONS, not connections. A target with several
 * candidate addresses is evaluated once per candidate (Happy Eyeballs), so a
 * split across such targets is by attempt rather than by connection.
 *
 * Only ever call this behind a @has_statistic test: @st_every is 0 on a rule
 * that does not use the module, so an unguarded call divides by zero.
 */
static bool statistic_match(struct gwp_acl_rule *r)
{
	uint32_t n;

	n = atomic_fetch_add_explicit(&r->st_count, 1, memory_order_relaxed);
	return (n % r->st_every) == r->st_packet;
}

/*
 * The -m user and -m domain criteria of @r. They depend only on the request's
 * username and domain, which stay the same across a connection's candidate
 * addresses, so with a memo in @q each rule's result is computed for the
 * first candidate and reused for the rest.
 */
static bool name_crit_ok(const struct gwp_acl_rule *r,
			 const struct gwp_acl_req *q)
{
	struct gwp_acl_memo *m = q->memo;
	uint64_t bit = 0;
	bool ok;

	if (m && r->memo_idx != ACL_NO_MEMO) {
		bit = 1ull << r->memo_idx;
		if (m->known & bit)
			return m->ok & bit;
	}

	ok = !CRIT_FAILS(r, has_user, neg_user, user_match(r, q->user)) &&
	     !CRIT_FAILS(r, has_domain, neg_domain, domain_match(r, q->domain));

	/* An undecided match is no answer to remember for the next candidate. */
	if (bit && !regex_failed()) {
		m->known |= bit;
		if (ok)
			m->ok |= bit;
	}
	return ok;
}

static bool rule_matches(struct gwp_acl_rule *r,
			 const struct gwp_acl_req *q)
{
	/*
	 * -d cannot be evaluated for a domain-only request (remote-DNS
	 * upstream: no resolved IP), and neither can --dports when the port is
	 * unknown too. Such a rule matches NEITHER polarity -- otherwise a
	 * negated "! -d"/"! --dports" would flip the unknown into a match and
	 * fail open (e.g. an allow-by-exclusion rule bypassing an
	 * internal-range REJECT). The requested port is known, though, so
	 * --dports is evaluated against it; -m domain / -m user evaluate here
	 * as well.
	 */
	if (!q->target && (r->has_dst || (r->has_dports && !q->dport)))
		return false;

	/*
	 * Cheapest test first: a rule is rejected by its first failing
	 * criterion, and every criterion below the statistic is a pure
	 * predicate, so the order changes the cost and never the result.
	 */
	if (CRIT_FAILS(r, has_proto, neg_proto, q->proto == r->proto))
		return false;
	if (CRIT_FAILS(r, has_dports, neg_dports,
		       ports_match(&r->dports, q->dport)))
		return false;
	if (CRIT_FAILS(r, has_sports, neg_sports,
		       ports_match(&r->sports, q->sport)))
		return false;
	if (CRIT_FAILS(r, has_dst, neg_dst,
		       q->target && cidr_match(&r->dst, q->target)))
		return false;
	if (CRIT_FAILS(r, has_src, neg_src,
		       q->client && cidr_match(&r->src, q->client)))
		return false;
	if ((r->has_user || r->has_domain) && !name_crit_ok(r, q))
		return false;

	/*
	 * LAST, and it has to stay last. Every criterion above is a pure
	 * predicate; this one advances the rule's counter, so a rule must only
	 * consume a slot once everything else about it has matched --
	 * otherwise "-d 10.0.0.0/8 -m statistic ..." would count the
	 * connections it does not select and the split would be against the
	 * wrong population.
	 */
	return !CRIT_FAILS(r, has_statistic, neg_statistic, statistic_match(r));
}

/* Read a sockaddr's port (host byte order) regardless of family. */
static uint16_t sa_port(const struct gwp_sockaddr *sa)
{
	return ntohs(sa->sa.sa_family == AF_INET ? sa->i4.sin_port
						 : sa->i6.sin6_port);
}

/*
 * Compute the effective rewritten destination for a matched DNAT rule into
 * @req->dnat. The address and port are taken from the rule where set, otherwise
 * carried over from the matched target (@req->target); a port-only rewrite thus
 * keeps the original address. If neither the rule nor the request supplies an
 * address, @req->dnat is left with family 0 (no usable rewrite -- the caller,
 * which only DNATs concrete targets, ignores it).
 */
static void apply_dnat(struct gwp_acl_req *req, const struct gwp_acl_dnat *d)
{
	const struct gwp_sockaddr *base = req->target;
	struct gwp_sockaddr out;
	uint16_t port;
	int fam;

	memset(&out, 0, sizeof(out));
	fam = d->set_addr ? d->family : (base ? base->sa.sa_family : 0);
	if (d->set_port)
		port = d->port;
	else
		port = base ? sa_port(base) : 0;

	if (fam == AF_INET) {
		out.i4.sin_family = AF_INET;
		if (d->set_addr)
			memcpy(&out.i4.sin_addr, d->addr, 4);
		else
			out.i4.sin_addr = base->i4.sin_addr;
		out.i4.sin_port = htons(port);
	} else if (fam == AF_INET6) {
		out.i6.sin6_family = AF_INET6;
		if (d->set_addr)
			memcpy(&out.i6.sin6_addr, d->addr, 16);
		else
			out.i6.sin6_addr = base->i6.sin6_addr;
		out.i6.sin6_port = htons(port);
	}

	req->dnat = out;
	req->dnat_applied = true;
}

/*
 * Walk chain @c, returning the first terminal verdict. DNAT rewrites
 * @req->dnat; MARK is a composable modifier that records @req->mark and
 * keeps matching. An indexed run is answered by its first matching rule,
 * found by lookup instead of testing each of its rules.
 */
static enum gwp_acl_verdict __eval_chain(const struct acl_chain *c,
					 uint64_t seed,
					 struct gwp_acl_req *req)
{
	const struct acl_run *run = c->runs, *run_end = c->runs + c->nr_runs;
	uint32_t i = 0;

	while (i < c->nr) {
		struct gwp_acl_rule *r;

		if (run != run_end && i == run->start) {
			uint32_t pos = run_find(run, seed, req);

			i = run->end;
			run++;
			if (pos == ACL_NO_POS)
				continue;
			r = &c->rules[pos];
		} else {
			r = &c->rules[i++];
			if (!rule_matches(r, req))
				continue;
		}

		switch (r->action) {
		case GWP_ACL_ACT_MARK:
			/*
			 * Modifier: record the fwmark and keep matching. A later
			 * MARK overrides it; a terminal rule (or the policy) then
			 * decides the verdict. With --accept the rule is terminal
			 * itself, so nothing below it can override or re-match.
			 */
			req->mark = r->act.setmark;
			req->mark_set = true;
			if (r->then_accept)
				return GWP_ACL_ACCEPT;
			continue;
		case GWP_ACL_ACT_BIND:
			/* Modifier: record the source/iface bind, keep matching. */
			req->bind = r->act.bind;
			if (r->then_accept)
				return GWP_ACL_ACCEPT;
			continue;
		case GWP_ACL_ACT_DNAT:
			/*
			 * DNAT is terminal (like iptables' nat table): record
			 * the rewrite and accept, so later rules cannot re-match
			 * or override it.
			 */
			apply_dnat(req, &r->act.dnat);
			return GWP_ACL_ACCEPT;
		case GWP_ACL_ACT_REJECT:
			return GWP_ACL_REJECT;
		default: /* GWP_ACL_ACT_ACCEPT */
			return GWP_ACL_ACCEPT;
		}
	}
	return c->policy;
}

/*
 * __eval_chain(), failing closed: if any regexp along the way could not be
 * decided (regex_match()), the rules this request met are not known, so it
 * is refused, whatever they would have said, and the verdict is not cached.
 */
static enum gwp_acl_verdict eval_chain(const struct gwp_acl_ruleset *rs,
				       const struct acl_chain *c,
				       struct gwp_acl_req *req)
{
	enum gwp_acl_verdict v;

	regex_err_clear();
	v = __eval_chain(c, rs->seed, req);
	if (!regex_failed())
		return v;

	req->dnat_applied = false;
	req->mark_set = false;
	req->bind.set = false;
	req->cacheable = false;
	return GWP_ACL_REJECT;
}

enum gwp_acl_verdict gwp_acl_eval_output(struct gwp_acl *acl,
					 struct gwp_acl_req *req)
{
	struct gwp_acl_ruleset *rs;
	enum gwp_acl_verdict verdict;
	struct acl_reader *slot;
	uint32_t gen;
	uint8_t sum;

	req->dnat_applied = false;
	req->mark_set = false;
	req->bind.set = false;
	req->gen = 0;
	req->cacheable = true;
	if (!acl)
		return GWP_ACL_ACCEPT;

	gen = gwp_acl_generation(acl);
	sum = atomic_load_explicit(&acl->sum, memory_order_acquire);
	if (sum & ACL_SUM_OUT_EMPTY) {
		req->gen = gen;
		return (sum & ACL_SUM_OUT_REJECT) ? GWP_ACL_REJECT
						  : GWP_ACL_ACCEPT;
	}

	rs = rs_get(acl, &slot);
	req->gen = rs->gen;
	req->cacheable = !rs->out_has_stat;
	/* Memo slots are only meaningful for the ruleset that filled them. */
	if (req->memo && (!req->memo->valid || req->memo->gen != req->gen)) {
		req->memo->valid = true;
		req->memo->gen = req->gen;
		req->memo->known = 0;
		req->memo->ok = 0;
	}
	verdict = eval_chain(rs, &rs->out, req);
	rs_put(slot);
	return verdict;
}

uint32_t gwp_acl_generation(struct gwp_acl *acl)
{
	if (!acl)
		return 0;
	return atomic_load_explicit(&acl->gen, memory_order_acquire);
}

enum gwp_acl_verdict gwp_acl_eval_input(struct gwp_acl *acl,
					struct gwp_acl_req *req)
{
	struct gwp_acl_ruleset *rs;
	enum gwp_acl_verdict verdict;
	struct acl_reader *slot;
	uint8_t sum;

	if (!acl)
		return GWP_ACL_ACCEPT;

	sum = atomic_load_explicit(&acl->sum, memory_order_acquire);
	if (sum & ACL_SUM_IN_EMPTY)
		return (sum & ACL_SUM_IN_REJECT) ? GWP_ACL_REJECT
						 : GWP_ACL_ACCEPT;

	rs = rs_get(acl, &slot);
	verdict = eval_chain(rs, &rs->in, req);
	rs_put(slot);
	return verdict;
}

uint32_t gwp_acl_nr_indexed(struct gwp_acl *acl)
{
	struct gwp_acl_ruleset *rs;
	struct acl_reader *slot;
	uint32_t nr;

	if (!acl)
		return 0;
	rs = rs_get(acl, &slot);
	nr = rs->nr_indexed;
	rs_put(slot);
	return nr;
}
