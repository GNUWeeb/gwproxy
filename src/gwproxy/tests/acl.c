// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * Unit tests for the iptables-style ACL parser and matcher (acl.c).
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
/* Before common.h: musl's struct stat has a field named __unused. */
#include <sys/stat.h>
#include <gwproxy/acl.h>
#include <gwproxy/common.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <limits.h>

static struct gwp_sockaddr sa4(const char *ip, uint16_t port)
{
	struct gwp_sockaddr s;

	memset(&s, 0, sizeof(s));
	s.i4.sin_family = AF_INET;
	assert(inet_pton(AF_INET, ip, &s.i4.sin_addr) == 1);
	s.i4.sin_port = htons(port);
	return s;
}

static struct gwp_sockaddr sa6(const char *ip, uint16_t port)
{
	struct gwp_sockaddr s;

	memset(&s, 0, sizeof(s));
	s.i6.sin6_family = AF_INET6;
	assert(inet_pton(AF_INET6, ip, &s.i6.sin6_addr) == 1);
	s.i6.sin6_port = htons(port);
	return s;
}

/* An IPv4 address as the v4-mapped IPv6 the dual-stack UDP relay would see. */
static struct gwp_sockaddr sa4mapped(const char *ip, uint16_t port)
{
	struct gwp_sockaddr s;
	uint8_t v4[4];

	memset(&s, 0, sizeof(s));
	s.i6.sin6_family = AF_INET6;
	assert(inet_pton(AF_INET, ip, v4) == 1);
	s.i6.sin6_addr.s6_addr[10] = 0xff;
	s.i6.sin6_addr.s6_addr[11] = 0xff;
	memcpy(&s.i6.sin6_addr.s6_addr[12], v4, 4);
	s.i6.sin6_port = htons(port);
	return s;
}

static enum gwp_acl_verdict out(struct gwp_acl *a, struct gwp_sockaddr *t,
				const char *dom, uint16_t dport,
				enum gwp_acl_proto p)
{
	struct gwp_acl_req req = {
		.target = t, .domain = dom, .dport = dport, .proto = p,
	};

	return gwp_acl_eval_output(a, &req);
}

static enum gwp_acl_verdict out_user(struct gwp_acl *a, struct gwp_sockaddr *t,
				     const char *user, uint16_t dport)
{
	struct gwp_acl_req req = {
		.target = t, .user = user, .dport = dport,
		.proto = GWP_ACL_PROTO_TCP,
	};

	return gwp_acl_eval_output(a, &req);
}

static enum gwp_acl_verdict in(struct gwp_acl *a, struct gwp_sockaddr *c,
			       uint16_t sport, enum gwp_acl_proto p)
{
	struct gwp_acl_req req = {
		.client = c, .sport = sport, .proto = p,
	};

	return gwp_acl_eval_input(a, &req);
}

static const char DEFAULT_RULES[] =
	"-P INPUT ACCEPT\n"
	"-A OUTPUT ! --dports 80,443 -j REJECT\n"
	"-A OUTPUT -d 10.0.0.0/8 -j REJECT\n"
	"-A OUTPUT -d 127.0.0.0/8 -j REJECT\n"
	"-A OUTPUT -d 192.168.0.0/16 -j REJECT\n"
	"-A OUTPUT -d 172.16.0.0/12 -j REJECT\n"
	"-A OUTPUT -d fe80::/10 -j REJECT\n"
	"-A OUTPUT -d fc00::/7 -j REJECT\n"
	"-P OUTPUT ACCEPT\n";

static noinline void test_default_ruleset(void)
{
	struct gwp_acl *a = NULL;
	struct gwp_sockaddr s;
	int r;

	r = gwp_acl_parse_str(&a, DEFAULT_RULES);
	assert(!r && a);

	/* Public IP on an allowed port is accepted. */
	s = sa4("8.8.8.8", 80);
	assert(out(a, &s, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	s = sa4("8.8.8.8", 443);
	assert(out(a, &s, NULL, 443, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);

	/* Public IP on a disallowed port is rejected (! --dports). */
	s = sa4("8.8.8.8", 22);
	assert(out(a, &s, NULL, 22, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);

	/* Private / loopback ranges rejected even on an allowed port. */
	s = sa4("127.0.0.1", 80);
	assert(out(a, &s, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	s = sa4("10.1.2.3", 443);
	assert(out(a, &s, NULL, 443, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	s = sa4("192.168.5.5", 80);
	assert(out(a, &s, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	s = sa4("172.16.0.1", 80);
	assert(out(a, &s, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	s = sa4("172.31.255.255", 80);
	assert(out(a, &s, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);

	/* 172.15/16 is just outside 172.16.0.0/12 -> allowed. */
	s = sa4("172.15.0.1", 80);
	assert(out(a, &s, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);

	/* v4-mapped loopback must also hit the 127.0.0.0/8 rule. */
	s = sa4mapped("127.0.0.1", 80);
	assert(out(a, &s, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);

	/* IPv6 link-local / ULA rejected; public v6 allowed. */
	s = sa6("fe80::1", 80);
	assert(out(a, &s, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	s = sa6("fc00::1", 80);
	assert(out(a, &s, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	s = sa6("2606:4700::1", 80);
	assert(out(a, &s, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	s = sa6("2606:4700::1", 22);
	assert(out(a, &s, NULL, 22, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);

	gwp_acl_destroy(a);
}

/*
 * A v4-mapped prefix in a rule must match like the IPv4 prefix it carries:
 * targets are matched with v4-mapped addresses folded into IPv4, so a rule
 * left as IPv6 never matched anything, mapped or not.
 */
static noinline void test_v4mapped_cidr(void)
{
	struct gwp_acl *a = NULL;
	struct gwp_sockaddr s;

	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -d ::ffff:10.0.0.0/104 -j REJECT\n"
		"-A OUTPUT -d ::ffff:192.0.2.7 -j REJECT\n"
		"-A INPUT -s ::ffff:198.51.100.0/120 -j REJECT\n"));
	s = sa4("10.1.2.3", 80);
	assert(out(a, &s, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	s = sa4mapped("10.1.2.3", 80);
	assert(out(a, &s, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	s = sa4("11.1.2.3", 80);
	assert(out(a, &s, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	s = sa4("192.0.2.7", 80);
	assert(out(a, &s, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	s = sa4("192.0.2.8", 80);
	assert(out(a, &s, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	/* The rule is IPv4 now: a non-mapped IPv6 target is not caught. */
	s = sa6("::10.1.2.3", 80);
	assert(out(a, &s, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	s = sa4mapped("198.51.100.9", 1234);
	assert(in(a, &s, 1234, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	s = sa4("198.51.101.9", 1234);
	assert(in(a, &s, 1234, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	gwp_acl_destroy(a);

	/* All of ::ffff:0:0/96 is all of IPv4. */
	assert(!gwp_acl_parse_str(&a, "-A OUTPUT -d ::ffff:0:0/96 -j REJECT\n"));
	s = sa4("93.184.216.34", 443);
	assert(out(a, &s, NULL, 443, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	s = sa6("2606:4700::1", 443);
	assert(out(a, &s, NULL, 443, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	gwp_acl_destroy(a);
}

static noinline void test_ports_and_negation(void)
{
	struct gwp_acl *a = NULL;
	struct gwp_sockaddr s;

	/* Port ranges and lists. */
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -d 1.2.3.4 --dports 1000-2000,8080 -j REJECT\n"));
	s = sa4("1.2.3.4", 1500);
	assert(out(a, &s, NULL, 1500, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	s = sa4("1.2.3.4", 8080);
	assert(out(a, &s, NULL, 8080, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	s = sa4("1.2.3.4", 3000);
	assert(out(a, &s, NULL, 3000, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	gwp_acl_destroy(a);

	/* Negated source: reject everything except 10.0.0.0/8. */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A INPUT ! -s 10.0.0.0/8 -j REJECT\n"));
	s = sa4("10.5.5.5", 0);
	assert(in(a, &s, 0, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	s = sa4("8.8.8.8", 0);
	assert(in(a, &s, 0, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	gwp_acl_destroy(a);
}

static noinline void test_input_and_proto(void)
{
	struct gwp_acl *a = NULL;
	struct gwp_sockaddr s;

	assert(!gwp_acl_parse_str(&a,
		"-P INPUT REJECT\n"
		"-A INPUT -s 192.168.0.0/16 -p tcp -j ACCEPT\n"));
	s = sa4("192.168.1.1", 0);
	assert(in(a, &s, 0, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	/* Same source but udp: the tcp rule does not match -> default REJECT. */
	assert(in(a, &s, 0, GWP_ACL_PROTO_UDP) == GWP_ACL_REJECT);
	s = sa4("8.8.8.8", 0);
	assert(in(a, &s, 0, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	gwp_acl_destroy(a);
}

static noinline void test_domain(void)
{
	struct gwp_acl *a = NULL;
	struct gwp_sockaddr s;

	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -m domain --domain example.com -j REJECT\n"));
	assert(out(a, NULL, "example.com", 443, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	assert(out(a, NULL, "EXAMPLE.COM", 443, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	assert(out(a, NULL, "other.com", 443, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	/* A literal-IP target (no domain) does not match a domain rule. */
	assert(out(a, NULL, NULL, 443, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	gwp_acl_destroy(a);

	/* One trailing dot in a rule is the same name without it. */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -m domain --domain Example.Com. -j REJECT\n"));
	assert(out(a, NULL, "example.com", 443, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	assert(out(a, NULL, "other.com", 443, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	gwp_acl_destroy(a);

	/*
	 * A rule WITHOUT a domain match, evaluated against a query that DOES
	 * carry a domain, must not deref the rule's NULL domain (regression:
	 * crit_ok evaluates its matched argument eagerly).
	 */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT --dports 80 -j REJECT\n-P OUTPUT ACCEPT\n"));
	s = sa4("1.2.3.4", 80);
	assert(out(a, &s, "example.com", 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	assert(out(a, &s, "example.com", 81, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	gwp_acl_destroy(a);
}

static noinline void test_domain_regexp(void)
{
#ifdef CONFIG_PCRE
	struct gwp_acl *a = NULL;

	/* Raw/unanchored, case-insensitive PCRE against the requested host. */
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -m domain --domain-regexp \\.example\\.com$ -j REJECT\n"
		"-P OUTPUT ACCEPT\n"));
	assert(out(a, NULL, "a.example.com", 443, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	assert(out(a, NULL, "A.EXAMPLE.COM", 443, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	/* Unanchored on the left, anchored on the right by the pattern. */
	assert(out(a, NULL, "example.com.evil.net", 443, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	assert(out(a, NULL, "other.org", 443, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	/* A literal-IP target (no hostname) never matches a domain regexp. */
	assert(out(a, NULL, NULL, 443, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	gwp_acl_destroy(a);
#endif
}

/*
 * A regexp that cannot be decided -- a backtracking-prone pattern meeting a
 * subject crafted to exhaust the match limit -- refuses the request rather
 * than reading as "no match", which let it past a REJECT rule.
 */
static enum gwp_acl_verdict out_memo(struct gwp_acl *a, struct gwp_acl_memo *m,
				     const char *dom, const char *ip,
				     uint16_t port);

static noinline void test_regexp_limit(void)
{
#ifdef CONFIG_PCRE
	struct gwp_acl_memo memo = { 0 };
	struct gwp_acl *a = NULL;
	char host[64];

	memset(host, 'a', 30);
	strcpy(host + 30, "!internal.example");

	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -m domain --domain-regexp (\\w+\\.?)+internal\\.example$ -j REJECT\n"
		"-P OUTPUT ACCEPT\n"));
	assert(out(a, NULL, host, 443, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	assert(out(a, NULL, "a.b.internal.example", 443, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	assert(out(a, NULL, "other.org", 443, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);

	/* Undecided is not remembered as "no match" for the next candidate. */
	assert(out_memo(a, &memo, host, "1.2.3.4", 443) == GWP_ACL_REJECT);
	assert(out_memo(a, &memo, host, "1.2.3.5", 443) == GWP_ACL_REJECT);
	gwp_acl_destroy(a);
#endif
}

static noinline void test_user(void)
{
	struct gwp_acl *a = NULL;
	struct gwp_sockaddr s = sa4("1.2.3.4", 80);

	/* Exact, case-sensitive username; unauthenticated never matches. */
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -m user --user alice -j REJECT\n"
		"-P OUTPUT ACCEPT\n"));
	assert(out_user(a, &s, "alice", 80) == GWP_ACL_REJECT);
	assert(out_user(a, &s, "ALICE", 80) == GWP_ACL_ACCEPT);
	assert(out_user(a, &s, "bob", 80) == GWP_ACL_ACCEPT);
	assert(out_user(a, &s, NULL, 80) == GWP_ACL_ACCEPT);
	gwp_acl_destroy(a);

	/* Negated: everyone but alice, including an absent (NULL) username. */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -m user ! --user alice -j REJECT\n"
		"-P OUTPUT ACCEPT\n"));
	assert(out_user(a, &s, "bob", 80) == GWP_ACL_REJECT);
	assert(out_user(a, &s, "alice", 80) == GWP_ACL_ACCEPT);
	assert(out_user(a, &s, NULL, 80) == GWP_ACL_REJECT);
	gwp_acl_destroy(a);

#ifdef CONFIG_PCRE
	/* --user-regexp is case-sensitive (no PCRE2_CASELESS for usernames). */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -m user --user-regexp ^team- -j REJECT\n"
		"-P OUTPUT ACCEPT\n"));
	assert(out_user(a, &s, "team-a", 80) == GWP_ACL_REJECT);
	assert(out_user(a, &s, "user001", 80) == GWP_ACL_ACCEPT);
	assert(out_user(a, &s, "TEAM-a", 80) == GWP_ACL_ACCEPT);
	gwp_acl_destroy(a);
#endif
}

static noinline void test_mark(void)
{
	struct gwp_sockaddr t = sa4("1.2.3.4", 80);
	struct gwp_acl *a = NULL;
	struct gwp_acl_req req;

	/* MARK is a composable modifier: it records the fwmark (hex accepted)
	 * and eval keeps matching to reach a terminal rule / the policy. */
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -d 1.2.3.4 -j MARK --set-mark 0x64\n"
		"-P OUTPUT ACCEPT\n"));
	memset(&req, 0, sizeof(req));
	req.target = &t; req.dport = 80; req.proto = GWP_ACL_PROTO_TCP;
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_ACCEPT);
	assert(req.mark_set && req.mark == 100);
	gwp_acl_destroy(a);

	/* A non-matching MARK rule leaves the request unmarked. */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -d 9.9.9.9 -j MARK --set-mark 7\n"
		"-P OUTPUT ACCEPT\n"));
	memset(&req, 0, sizeof(req));
	req.target = &t; req.dport = 80; req.proto = GWP_ACL_PROTO_TCP;
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_ACCEPT);
	assert(!req.mark_set);
	gwp_acl_destroy(a);

	/* Last MARK wins; a later terminal REJECT still decides the verdict. */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -d 1.2.3.4 -j MARK --set-mark 1\n"
		"-A OUTPUT -d 1.2.3.4 -j MARK --set-mark 2\n"
		"-A OUTPUT -d 1.2.3.4 -j REJECT\n"
		"-P OUTPUT ACCEPT\n"));
	memset(&req, 0, sizeof(req));
	req.target = &t; req.dport = 80; req.proto = GWP_ACL_PROTO_TCP;
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_REJECT);
	assert(req.mark_set && req.mark == 2);
	gwp_acl_destroy(a);

	/*
	 * --accept makes MARK terminal: the mark is recorded and traversal
	 * stops, so the REJECT below it -- which decides the verdict in the
	 * case above -- is never reached.
	 */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -d 1.2.3.4 -j MARK --set-mark 1 --accept\n"
		"-A OUTPUT -d 1.2.3.4 -j MARK --set-mark 2\n"
		"-A OUTPUT -d 1.2.3.4 -j REJECT\n"
		"-P OUTPUT ACCEPT\n"));
	memset(&req, 0, sizeof(req));
	req.target = &t; req.dport = 80; req.proto = GWP_ACL_PROTO_TCP;
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_ACCEPT);
	assert(req.mark_set && req.mark == 1);	/* not overridden by the 2 */
	gwp_acl_destroy(a);

	/* Token order is free: --accept may come before its -j. */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -d 1.2.3.4 --accept -j MARK --set-mark 9\n"
		"-A OUTPUT -d 1.2.3.4 -j REJECT\n"
		"-P OUTPUT ACCEPT\n"));
	memset(&req, 0, sizeof(req));
	req.target = &t; req.dport = 80; req.proto = GWP_ACL_PROTO_TCP;
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_ACCEPT);
	assert(req.mark_set && req.mark == 9);
	gwp_acl_destroy(a);

	/* --accept only fires when the rule actually matches. */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -d 9.9.9.9 -j MARK --set-mark 5 --accept\n"
		"-A OUTPUT -d 1.2.3.4 -j REJECT\n"
		"-P OUTPUT ACCEPT\n"));
	memset(&req, 0, sizeof(req));
	req.target = &t; req.dport = 80; req.proto = GWP_ACL_PROTO_TCP;
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_REJECT);
	assert(!req.mark_set);
	gwp_acl_destroy(a);
}

static noinline void test_bind(void)
{
	struct gwp_sockaddr t = sa4("1.2.3.4", 80);
	struct gwp_acl *a = NULL;
	struct gwp_acl_req req;
	char ip[64];

	/* BIND records a source address (with port) and interface, and keeps
	 * matching (composable modifier). */
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -d 1.2.3.4 -j BIND --to-source 10.0.0.2:5000 --to-iface wg0\n"
		"-P OUTPUT ACCEPT\n"));
	memset(&req, 0, sizeof(req));
	req.target = &t; req.dport = 80; req.proto = GWP_ACL_PROTO_TCP;
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_ACCEPT);
	assert(req.bind.set && req.bind.have_src);
	assert(!strcmp(req.bind.iface, "wg0"));
	assert(req.bind.src.i4.sin_family == AF_INET);
	assert(inet_ntop(AF_INET, &req.bind.src.i4.sin_addr, ip, sizeof(ip)));
	assert(!strcmp(ip, "10.0.0.2") && ntohs(req.bind.src.i4.sin_port) == 5000);
	gwp_acl_destroy(a);

	/* Interface-only bind. */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -j BIND --to-iface eth1\n-P OUTPUT ACCEPT\n"));
	memset(&req, 0, sizeof(req));
	req.target = &t; req.dport = 80; req.proto = GWP_ACL_PROTO_TCP;
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_ACCEPT);
	assert(req.bind.set && !req.bind.have_src && !strcmp(req.bind.iface, "eth1"));
	gwp_acl_destroy(a);

	/* Bracketed IPv6 source with a port; source-only bind. */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -j BIND --to-source [2001:db8::1]:443\n"
		"-P OUTPUT ACCEPT\n"));
	memset(&req, 0, sizeof(req));
	req.target = &t; req.dport = 80; req.proto = GWP_ACL_PROTO_TCP;
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_ACCEPT);
	assert(req.bind.set && req.bind.have_src && req.bind.iface[0] == '\0');
	assert(req.bind.src.i6.sin6_family == AF_INET6);
	assert(ntohs(req.bind.src.i6.sin6_port) == 443);
	gwp_acl_destroy(a);

	/* Composable: BIND then a terminal REJECT still records the bind. */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -d 1.2.3.4 -j BIND --to-iface eth0\n"
		"-A OUTPUT -d 1.2.3.4 -j REJECT\n-P OUTPUT ACCEPT\n"));
	memset(&req, 0, sizeof(req));
	req.target = &t; req.dport = 80; req.proto = GWP_ACL_PROTO_TCP;
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_REJECT);
	assert(req.bind.set && !strcmp(req.bind.iface, "eth0"));
	gwp_acl_destroy(a);

	/*
	 * The same pair with --accept: identical rules, opposite verdict,
	 * because BIND now terminates instead of falling through.
	 */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -d 1.2.3.4 -j BIND --to-iface eth0 --accept\n"
		"-A OUTPUT -d 1.2.3.4 -j REJECT\n-P OUTPUT ACCEPT\n"));
	memset(&req, 0, sizeof(req));
	req.target = &t; req.dport = 80; req.proto = GWP_ACL_PROTO_TCP;
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_ACCEPT);
	assert(req.bind.set && !strcmp(req.bind.iface, "eth0"));
	gwp_acl_destroy(a);

	/* --accept alongside a source spec, and against a REJECT policy. */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -d 1.2.3.4 -j BIND --to-source 10.0.0.9 --accept\n"
		"-P OUTPUT REJECT\n"));
	memset(&req, 0, sizeof(req));
	req.target = &t; req.dport = 80; req.proto = GWP_ACL_PROTO_TCP;
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_ACCEPT);
	assert(req.bind.set && req.bind.have_src);
	gwp_acl_destroy(a);
}

/* Evaluate one OUTPUT DNAT rule against target @ip:@port; return the req. */
static noinline struct gwp_acl_req dnat_eval(const char *rule, const char *ip,
				    uint16_t port, bool v6)
{
	struct gwp_acl *a = NULL;
	struct gwp_sockaddr t = v6 ? sa6(ip, port) : sa4(ip, port);
	struct gwp_acl_req req = { .target = &t, .dport = port,
				  .proto = GWP_ACL_PROTO_TCP };

	assert(!gwp_acl_parse_str(&a, rule));
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_ACCEPT);
	gwp_acl_destroy(a);
	return req;
}

static noinline void test_dnat(void)
{
	struct gwp_acl_req req;
	char ip[64];

	/* Rewrite both address and port. */
	req = dnat_eval("-A OUTPUT -d 1.2.3.4 -j DNAT --to 5.6.7.8:9999\n",
			"1.2.3.4", 80, false);
	assert(req.dnat_applied && req.dnat.i4.sin_family == AF_INET);
	assert(inet_ntop(AF_INET, &req.dnat.i4.sin_addr, ip, sizeof(ip)));
	assert(!strcmp(ip, "5.6.7.8") && ntohs(req.dnat.i4.sin_port) == 9999);

	/* Address only: port carried over from the target. */
	req = dnat_eval("-A OUTPUT -d 1.2.3.4 -j DNAT --to 5.6.7.8\n",
			"1.2.3.4", 80, false);
	assert(req.dnat_applied);
	assert(inet_ntop(AF_INET, &req.dnat.i4.sin_addr, ip, sizeof(ip)));
	assert(!strcmp(ip, "5.6.7.8") && ntohs(req.dnat.i4.sin_port) == 80);

	/* Port only: address carried over from the target. */
	req = dnat_eval("-A OUTPUT -d 1.2.3.4 -j DNAT --to :4444\n",
			"1.2.3.4", 80, false);
	assert(req.dnat_applied);
	assert(inet_ntop(AF_INET, &req.dnat.i4.sin_addr, ip, sizeof(ip)));
	assert(!strcmp(ip, "1.2.3.4") && ntohs(req.dnat.i4.sin_port) == 4444);

	/* Port only on an IPv6 target: address preserved, family stays v6. */
	req = dnat_eval("-A OUTPUT -d 2001:db8::1 -j DNAT --to :4444\n",
			"2001:db8::1", 443, true);
	assert(req.dnat_applied && req.dnat.i6.sin6_family == AF_INET6);
	assert(inet_ntop(AF_INET6, &req.dnat.i6.sin6_addr, ip, sizeof(ip)));
	assert(!strcmp(ip, "2001:db8::1") && ntohs(req.dnat.i6.sin6_port) == 4444);

	/* IPv6 address+port rewrite via bracket form. */
	req = dnat_eval("-A OUTPUT -d 1.2.3.4 -j DNAT --to [2001:db8::2]:5555\n",
			"1.2.3.4", 80, false);
	assert(req.dnat_applied && req.dnat.i6.sin6_family == AF_INET6);
	assert(inet_ntop(AF_INET6, &req.dnat.i6.sin6_addr, ip, sizeof(ip)));
	assert(!strcmp(ip, "2001:db8::2") && ntohs(req.dnat.i6.sin6_port) == 5555);

	/* A non-matching target is not rewritten. */
	req = dnat_eval("-A OUTPUT -d 1.2.3.4 -j DNAT --to :4444\n"
			"-P OUTPUT ACCEPT\n", "9.9.9.9", 80, false);
	assert(!req.dnat_applied);

	/*
	 * DNAT is terminal: a later matching REJECT must not be reached, so the
	 * verdict is ACCEPT and the rewrite still applies.
	 */
	req = dnat_eval("-A OUTPUT -d 1.2.3.4 -j DNAT --to 5.6.7.8\n"
			"-A OUTPUT -d 1.2.3.4 -j REJECT\n"
			"-P OUTPUT REJECT\n", "1.2.3.4", 80, false);
	assert(req.dnat_applied);
	assert(inet_ntop(AF_INET, &req.dnat.i4.sin_addr, ip, sizeof(ip)));
	assert(!strcmp(ip, "5.6.7.8"));

	/*
	 * A domain-only request (no resolved IP, as with a socks5h upstream) can
	 * still be DNAT'd to an explicit address; the rewrite yields that IP even
	 * with no base target. The caller then redirects the upstream to it.
	 */
	{
		struct gwp_acl *a = NULL;
		struct gwp_acl_req q;

		assert(!gwp_acl_parse_str(&a,
			"-A OUTPUT -m domain --domain blocked.invalid -j DNAT --to 10.1.2.3:8443\n"
			"-P OUTPUT ACCEPT\n"));
		memset(&q, 0, sizeof(q));
		q.domain = "blocked.invalid";
		q.proto = GWP_ACL_PROTO_TCP;
		assert(gwp_acl_eval_output(a, &q) == GWP_ACL_ACCEPT);
		assert(q.dnat_applied && q.dnat.i4.sin_family == AF_INET);
		assert(inet_ntop(AF_INET, &q.dnat.i4.sin_addr, ip, sizeof(ip)));
		assert(!strcmp(ip, "10.1.2.3") && ntohs(q.dnat.i4.sin_port) == 8443);
		gwp_acl_destroy(a);
	}
}

static noinline void test_comments_and_default_policy(void)
{
	struct gwp_acl *a = NULL;
	struct gwp_sockaddr s;

	assert(!gwp_acl_parse_str(&a,
		"# leading comment\n"
		"\n"
		"   \n"
		"-P OUTPUT REJECT   # trailing comment\n"
		"-A OUTPUT -d 8.8.8.8/32 -j ACCEPT\n"));
	s = sa4("8.8.8.8", 53);
	assert(out(a, &s, NULL, 53, GWP_ACL_PROTO_UDP) == GWP_ACL_ACCEPT);
	s = sa4("1.1.1.1", 53);		/* no match -> default REJECT */
	assert(out(a, &s, NULL, 53, GWP_ACL_PROTO_UDP) == GWP_ACL_REJECT);
	gwp_acl_destroy(a);

	/*
	 * Only a '#' that starts a token begins a comment; inside a value it
	 * is part of the value and must not cut the rule short.
	 */
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -m user --user ops#1 -j REJECT #ops#1 only\n"
		"#-A OUTPUT -j REJECT\n"
		"\t# indented comment\n"));
	s = sa4("1.2.3.4", 80);
	assert(out_user(a, &s, "ops#1", 80) == GWP_ACL_REJECT);
	assert(out_user(a, &s, "ops", 80) == GWP_ACL_ACCEPT);
	gwp_acl_destroy(a);
#ifdef CONFIG_PCRE
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -m domain --domain-regexp ^[^#]+$ -j ACCEPT\n"
		"-P OUTPUT REJECT\n"));
	assert(out(a, NULL, "a.example", 443, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	assert(out(a, NULL, "a#b.example", 443, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	gwp_acl_destroy(a);
#endif

	/* NULL ACL and empty ruleset both allow everything. */
	s = sa4("1.2.3.4", 1);
	assert(out(NULL, &s, NULL, 1, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	assert(in(NULL, &s, 1, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
}

static noinline void test_parse_errors(void)
{
	struct gwp_acl *a;
	static const char *bad[] = {
		"-A INPUT -d 1.2.3.4 -j ACCEPT\n",	    /* -d in INPUT */
		"-A INPUT --dports 80 -j ACCEPT\n",	    /* --dports in INPUT */
		"-A OUTPUT -d 1.2.3.4 -m domain --domain x -j ACCEPT\n", /* d+domain */
		"-A OUTPUT -m domain -j REJECT\n",	    /* -m domain w/o --domain */
		"-A OUTPUT -m domain --domain . -j REJECT\n",	    /* no name */
		"-A OUTPUT -m domain --domain x.. -j REJECT\n",   /* never matches */
		"-A OUTPUT -m user -j REJECT\n",	    /* -m user w/o --user */
		"-A OUTPUT -j BOGUS\n",			    /* bad target */
		"-A OUTPUT -x -j ACCEPT\n",		    /* unknown option */
		"-A OUTPUT -d 1.2.3.4\n",		    /* no -j */
		"-A OUTPUT ! -j REJECT\n",		    /* negate before -j */
		"-P OUTPUT MAYBE\n",			    /* bad policy */
		"-P BOGUS ACCEPT\n",			    /* bad chain */
		"-A OUTPUT -d ::ffff:0:0/95 -j REJECT\n",	    /* mapped, < /96 */
		"-A OUTPUT -j DNAT\n",			    /* DNAT w/o --to */
		"-A OUTPUT -d 1.2.3.4 -j DNAT --to :\n",	    /* empty port */
		"-A OUTPUT -d 1.2.3.4 -j ACCEPT --to :80\n",	    /* --to w/o DNAT */
		"-A OUTPUT -j MARK\n",				    /* MARK w/o --set-mark */
		"-A OUTPUT -j ACCEPT --set-mark 5\n",		    /* --set-mark w/o MARK */
		"-A INPUT -j MARK --set-mark 5\n",		    /* MARK in INPUT */
		"-A OUTPUT -j MARK --set-mark nope\n",		    /* bad mark value */
		"-A OUTPUT -j MARK --set-mark 5 --set-mark 6\n",    /* dup --set-mark */
		"-A OUTPUT -j BIND\n",				    /* BIND w/o src|iface */
		"-A OUTPUT -j DNAT --to 1.2.3.4 --set-mark 5\n",    /* DNAT+MARK payloads */
		"-A OUTPUT -j BIND --to-iface eth0 --to 1.2.3.4\n", /* BIND+DNAT payloads */
		"-A OUTPUT -j MARK --set-mark 5 --to-source 10.0.0.1\n", /* MARK+BIND */
		"-A OUTPUT -j ACCEPT --to-source 10.0.0.1\n",	    /* --to-source w/o BIND */
		"-A OUTPUT -j ACCEPT --to-iface eth0\n",	    /* --to-iface w/o BIND */
		"-A INPUT -j BIND --to-iface eth0\n",		    /* BIND in INPUT */
		"-A OUTPUT -j BIND --to-source notanip\n",	    /* bad source */
		"-A OUTPUT -j BIND --to-source 10.0.0.1:80x\n",   /* port junk */
		"-A OUTPUT -j BIND --to-source 10.0.0.1:65536\n", /* port range */
		"-A OUTPUT -j BIND --to-source 10.0.0.1:+80\n",   /* port sign */
		"-A OUTPUT -j BIND --to-source [::1]:-18446744073709551535\n", /* 81 */
		"-A OUTPUT -j BIND --to-source 10.0.0.1:\n",	    /* empty port */
		"-A OUTPUT -j BIND --to-source 1.1.1.1 --to-source 2.2.2.2\n", /* dup src */
		"-A OUTPUT -j BIND --to-iface toolonginterfacename0\n", /* iface >= 16 */
		"-A OUTPUT -j ACCEPT --accept\n",		    /* --accept on ACCEPT */
		"-A OUTPUT -j REJECT --accept\n",		    /* --accept on REJECT */
		"-A OUTPUT -j DNAT --to 1.2.3.4 --accept\n",	    /* DNAT already terminal */
		/* -m statistic */
		"-A OUTPUT -m statistic -j ACCEPT\n",		    /* module, no options */
		"-A OUTPUT -m statistic --mode nth -j ACCEPT\n",   /* --mode w/o --every */
		"-A OUTPUT -m statistic --every 2 -j ACCEPT\n",    /* --every w/o --mode */
		"-A OUTPUT --mode nth --every 2 -j ACCEPT\n",	    /* options w/o -m */
		"-A OUTPUT -m statistic --mode random --probability 0.5 -j ACCEPT\n", /* unsupported mode */
		"-A OUTPUT -m statistic --mode nth --every 0 -j ACCEPT\n",  /* --every 0 */
		"-A OUTPUT -m statistic --mode nth --every 2 --packet 2 -j ACCEPT\n", /* packet >= every */
		"-A OUTPUT -m statistic --mode nth --every 2 --packet 9 -j ACCEPT\n", /* packet >= every */
		"-A OUTPUT -m statistic --mode nth --every 2 --every 3 -j ACCEPT\n",  /* dup --every */
		"-A OUTPUT -m statistic --mode nth --mode nth --every 2 -j ACCEPT\n", /* dup --mode */
		"-A OUTPUT -m statistic --mode nth --every 2 --packet 0 --packet 1 -j ACCEPT\n", /* dup --packet */
		"-A OUTPUT -m statistic --mode nth --every nope -j ACCEPT\n",	      /* bad --every */
		"-A OUTPUT --packet 0 -j ACCEPT\n",		    /* --packet w/o -m */
		/*
		 * Only --every takes the "!". The other two must refuse it
		 * rather than pass it along to the option that follows: the
		 * second line here would otherwise parse as "! -d", the exact
		 * inverse of the rule as written.
		 */
		"-A OUTPUT -m statistic ! --mode nth --every 2 -j ACCEPT\n",	      /* negated --mode */
		"-A OUTPUT -m statistic --mode nth --every 2 ! --packet 0 -d 10.0.0.0/8 -j REJECT\n", /* negated --packet */
		"-A OUTPUT -j MARK --set-mark 5 --accept --accept\n", /* dup --accept */
		"-A OUTPUT -j MARK --set-mark 5 ! --accept\n",	    /* negated --accept */
		"-A OUTPUT -d 1.2.3.4 --accept\n",		    /* --accept w/o -j */
		"-A INPUT -s 1.2.3.4 -j DNAT --to-destination 5.6.7.8\n", /* DNAT in INPUT */
		"-A OUTPUT -d 999.0.0.1 -j REJECT\n",	    /* bad CIDR */
		"-A OUTPUT -d 1.2.3.4/33 -j REJECT\n",	    /* bad prefix */
		"-A OUTPUT --dports 70000 -j REJECT\n",	    /* port range */
		/*
		 * Every number starts with a digit: strtoul() alone takes a
		 * sign, and wraps a "-" value around, so the last --dports
		 * here would load as 80-81.
		 */
		"-A OUTPUT --dports +80 -j REJECT\n",	    /* port sign */
		"-A OUTPUT --dports -80 -j REJECT\n",	    /* empty lo */
		"-A OUTPUT --sports +80 -j REJECT\n",	    /* port sign */
		"-A OUTPUT --dports 80,+443 -j REJECT\n",	    /* sign in list */
		"-A OUTPUT --dports 80-+90 -j REJECT\n",	    /* sign on hi */
		"-A OUTPUT --dports 80--18446744073709551535 -j REJECT\n", /* 80-81 */
		"-A OUTPUT -d 10.0.0.0/+8 -j REJECT\n",	    /* prefix sign */
		"-A OUTPUT -s 10.0.0.0/-0 -j REJECT\n",	    /* prefix sign */
		"-A OUTPUT -d ::/+64 -j REJECT\n",		    /* v6 prefix sign */
		"-A OUTPUT -d 10.0.0.0/ -j REJECT\n",	    /* empty prefix */
		"-A OUTPUT -d 1.2.3.4 -j DNAT --to 5.6.7.8:+80\n",	    /* DNAT sign */
		"-A OUTPUT -d 1.2.3.4 -j DNAT --to :+80\n",		    /* DNAT sign */
		"-A OUTPUT -d 1.2.3.4 -j DNAT --to [::1]:+80\n",	    /* DNAT sign */
		"-A OUTPUT -d 1.2.3.4 -j DNAT --to :-18446744073709551535\n", /* 81 */
		"-A OUTPUT -j MARK --set-mark +5\n",		    /* mark sign */
		"-A OUTPUT -j MARK --set-mark -1\n",		    /* mark wraps */
		"-A OUTPUT -j MARK --set-mark 0x\n",		    /* empty hex */
		"-A OUTPUT -m statistic --mode nth --every +2 -j ACCEPT\n",	      /* --every sign */
		"-A OUTPUT -m statistic --mode nth --every 2 --packet +1 -j ACCEPT\n", /* --packet sign */
		"-A OUTPUT -m statistic --mode nth --every 2 --packet -0 -j ACCEPT\n", /* --packet sign */
		/*
		 * A mark, --every and --packet are decimal or 0x hexadecimal,
		 * and nothing else: strtoul() with base 0 read "010" as octal
		 * 8, so a leading 0 before a decimal digit is refused rather
		 * than read differently now; so are other prefixes, a second
		 * "0x" and overflow.
		 */
		"-A OUTPUT -j MARK --set-mark 010\n",		    /* was octal */
		"-A OUTPUT -j MARK --set-mark 00\n",		    /* was octal */
		"-A OUTPUT -j MARK --set-mark 08\n",		    /* leading 0 */
		"-A OUTPUT -j MARK --set-mark 0b1\n",		    /* binary */
		"-A OUTPUT -j MARK --set-mark 0o7\n",		    /* octal */
		"-A OUTPUT -j MARK --set-mark 0x0x10\n",	    /* two prefixes */
		"-A OUTPUT -j MARK --set-mark 0x+1\n",		    /* sign after 0x */
		"-A OUTPUT -j MARK --set-mark 0x-1\n",		    /* sign after 0x */
		"-A OUTPUT -j MARK --set-mark 0xg\n",		    /* not hex */
		"-A OUTPUT -j MARK --set-mark 0x1g\n",		    /* hex junk */
		"-A OUTPUT -j MARK --set-mark 12a\n",		    /* hex w/o 0x */
		"-A OUTPUT -j MARK --set-mark 0x100000000\n",	    /* > 32 bits */
		"-A OUTPUT -j MARK --set-mark 4294967296\n",	    /* > 32 bits */
		"-A OUTPUT -j MARK --set-mark 0x10000000000000000\n", /* > 64 bits */
		"-A OUTPUT -j MARK --set-mark 18446744073709551616\n", /* > 64 bits */
		"-A OUTPUT -m statistic --mode nth --every 010 -j ACCEPT\n",	      /* was octal */
		"-A OUTPUT -m statistic --mode nth --every 9 --packet 07 -j ACCEPT\n", /* was octal */
		"-A OUTPUT -m statistic --mode nth --every 0x -j ACCEPT\n",	      /* empty hex */
		"-A OUTPUT -m statistic --mode nth --every 4294967296 -j ACCEPT\n",  /* > 32 bits */
		/* Ports and prefixes are decimal only: no 0x. */
		"-A OUTPUT --dports 0x50 -j REJECT\n",	    /* hex port */
		"-A OUTPUT -d 10.0.0.0/0x8 -j REJECT\n",	    /* hex prefix */
		"-A OUTPUT -d 1.2.3.4 -j DNAT --to 5.6.7.8:0x50\n", /* hex DNAT port */
		"-A WEIRD -d 1.2.3.4 -j REJECT\n",	    /* bad chain */
		"garbage line\n",			    /* not -P/-A */
	};
	size_t i;
	int saved, devnull;

	/*
	 * These cases are meant to fail parsing, and the parser logs each bad
	 * line to stderr. Silence stderr for the loop so the expected
	 * diagnostics do not look like test failures in "make test" output.
	 */
	fflush(stderr);
	saved = dup(STDERR_FILENO);
	devnull = open("/dev/null", O_WRONLY);
	if (saved >= 0 && devnull >= 0)
		dup2(devnull, STDERR_FILENO);

	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		a = (void *)0x1;
		assert(gwp_acl_parse_str(&a, bad[i]) < 0);
	}

	/* --domain-regexp still needs the -m domain module loaded first. */
	a = (void *)0x1;
	assert(gwp_acl_parse_str(&a,
		"-A OUTPUT --domain-regexp x -j REJECT\n") < 0);

	/* -m user is OUTPUT-only; --user needs the module and rejects dupes. */
	a = (void *)0x1;
	assert(gwp_acl_parse_str(&a,
		"-A OUTPUT --user alice -j REJECT\n") < 0);		/* no -m user */
	a = (void *)0x1;
	assert(gwp_acl_parse_str(&a,
		"-A INPUT -m user --user alice -j REJECT\n") < 0);	/* INPUT */
	a = (void *)0x1;
	assert(gwp_acl_parse_str(&a,
		"-A OUTPUT -m user --user a --user b -j REJECT\n") < 0);	/* dup */
#ifndef CONFIG_PCRE
	a = (void *)0x1;
	assert(gwp_acl_parse_str(&a,
		"-A OUTPUT -m user --user-regexp x -j REJECT\n") < 0);	/* no pcre */
#endif
#ifdef CONFIG_PCRE
	/* A malformed pattern, and mixing exact + regexp for one field, fail. */
	a = (void *)0x1;
	assert(gwp_acl_parse_str(&a,
		"-A OUTPUT -m domain --domain-regexp ( -j REJECT\n") < 0);
	a = (void *)0x1;
	assert(gwp_acl_parse_str(&a,
		"-A OUTPUT -m domain --domain a --domain-regexp b -j REJECT\n") < 0);
#else
	/* Without --use-pcre the regexp option is rejected outright. */
	a = (void *)0x1;
	assert(gwp_acl_parse_str(&a,
		"-A OUTPUT -m domain --domain-regexp x -j REJECT\n") < 0);
#endif

	fflush(stderr);
	if (saved >= 0)
		dup2(saved, STDERR_FILENO);
	if (devnull >= 0)
		close(devnull);
	if (saved >= 0)
		close(saved);
}

/*
 * Long runs of single-criterion terminal rules are answered from an index.
 * The answer must be the first matching rule of the run in file order:
 * not the most specific prefix, not a later duplicate, and only rules of
 * the run (a rule that breaks the run is still tested in its place).
 */
static noinline void test_index_first_match(void)
{
	static const char rules[] =
		"-P OUTPUT ACCEPT\n"
		"-A OUTPUT -d 10.0.0.0/8 -j ACCEPT\n"
		"-A OUTPUT -d 10.1.0.0/16 -j REJECT\n"
		"-A OUTPUT -d 10.1.2.3 -j REJECT\n"
		"-A OUTPUT -d 192.0.2.0/24 -j REJECT\n"
		"-A OUTPUT -d 192.0.2.0/24 -j ACCEPT\n"
		"-A OUTPUT -d 2001:db8::/32 -j REJECT\n"
		"-A OUTPUT -d ::ffff:198.51.100.0/120 -j REJECT\n"
		"-A OUTPUT -m domain --domain Bad.Example -j REJECT\n"
		"-A OUTPUT -d 203.0.113.7 -j DNAT --to 127.0.0.1:8080\n"
		"-A OUTPUT -m domain --domain marked.example -j MARK --set-mark 7 --accept\n"
		"-A OUTPUT -s 100.64.0.0/10 -j REJECT\n"
		"-A OUTPUT -m domain --domain bad.example -j ACCEPT\n"
		/* Not indexable: ends the run. */
		"-A OUTPUT -d 172.16.0.0/12 --dports 443 -j ACCEPT\n"
		"-A OUTPUT -d 172.16.0.0/12 -j REJECT\n"
		"-A OUTPUT -d 172.16.1.0/24 -j REJECT\n"
		"-A OUTPUT -d 172.16.2.0/24 -j REJECT\n"
		"-A OUTPUT -d 172.16.3.0/24 -j REJECT\n"
		"-A OUTPUT -d 172.16.4.0/24 -j REJECT\n"
		"-A OUTPUT -d 172.16.5.0/24 -j REJECT\n"
		"-A OUTPUT -d 172.16.6.0/24 -j REJECT\n"
		"-A OUTPUT -d 172.16.7.0/24 -j REJECT\n"
		"-A INPUT -s 10.0.0.0/8 -j REJECT\n"
		"-A INPUT -s 10.9.0.0/16 -j ACCEPT\n"
		"-A INPUT -s 10.8.0.0/16 -j ACCEPT\n"
		"-A INPUT -s 10.7.0.0/16 -j ACCEPT\n"
		"-A INPUT -s 10.6.0.0/16 -j ACCEPT\n"
		"-A INPUT -s 10.5.0.0/16 -j ACCEPT\n"
		"-A INPUT -s 10.4.0.0/16 -j ACCEPT\n"
		"-A INPUT -s 192.0.2.1 -j ACCEPT\n";
	struct gwp_sockaddr t, c;
	struct gwp_acl_req req;
	struct gwp_acl *a;

	assert(!gwp_acl_parse_str(&a, rules));
	/* 12 + 8 OUTPUT rules in two runs, 8 INPUT rules in one. */
	assert(gwp_acl_nr_indexed(a) == 12 + 8 + 8);

	t = sa4("10.1.2.3", 80);
	assert(out(a, &t, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	t = sa4("192.0.2.9", 80);
	assert(out(a, &t, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	t = sa6("2001:db8::1", 80);
	assert(out(a, &t, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	t = sa4mapped("198.51.100.20", 80);
	assert(out(a, &t, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	t = sa4("198.51.100.20", 80);
	assert(out(a, &t, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	t = sa4("198.51.101.20", 80);
	assert(out(a, &t, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);

	/* Domains: case-insensitive, first rule wins, none without a name. */
	t = sa4("93.184.216.34", 80);
	assert(out(a, &t, "BAD.example", 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	assert(out(a, &t, "bad.example.", 80, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	assert(out(a, NULL, "bad.example", 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);

	/* An address rule before a domain rule of the same run wins. */
	t = sa4("192.0.2.1", 80);
	assert(out(a, &t, "bad.example", 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	t = sa4("10.0.0.1", 80);
	assert(out(a, &t, "bad.example", 80, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);

	/* DNAT and MARK --accept from an indexed rule. */
	t = sa4("203.0.113.7", 443);
	memset(&req, 0, sizeof(req));
	req.target = &t;
	req.dport = 443;
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_ACCEPT);
	assert(req.dnat_applied && req.dnat.i4.sin_port == htons(8080));
	t = sa4("93.184.216.34", 443);
	memset(&req, 0, sizeof(req));
	req.target = &t;
	req.domain = "Marked.Example";
	req.dport = 443;
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_ACCEPT);
	assert(req.mark_set && req.mark == 7 && !req.dnat_applied);

	/* -s in OUTPUT needs the client address. */
	c = sa4("100.64.1.1", 5555);
	memset(&req, 0, sizeof(req));
	req.target = &t;
	req.client = &c;
	req.dport = 443;
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_REJECT);
	req.client = NULL;
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_ACCEPT);

	/* The rule that breaks the run is still tested in its place. */
	t = sa4("172.16.1.1", 443);
	assert(out(a, &t, NULL, 443, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	assert(out(a, &t, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	assert(out(a, NULL, "x.example", 80, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);

	/* INPUT: the broad REJECT comes first. */
	c = sa4("10.9.1.1", 1234);
	assert(in(a, &c, 1234, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	c = sa4("192.0.2.1", 1234);
	assert(in(a, &c, 1234, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	c = sa4("192.0.2.2", 1234);
	assert(in(a, &c, 1234, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	gwp_acl_destroy(a);

	/* Seven rules are not worth an index; negated or modifier rules never. */
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -d 10.0.0.1 -j REJECT\n-A OUTPUT -d 10.0.0.2 -j REJECT\n"
		"-A OUTPUT -d 10.0.0.3 -j REJECT\n-A OUTPUT -d 10.0.0.4 -j REJECT\n"
		"-A OUTPUT -d 10.0.0.5 -j REJECT\n-A OUTPUT -d 10.0.0.6 -j REJECT\n"
		"-A OUTPUT -d 10.0.0.7 -j REJECT\n"
		"-A OUTPUT ! -d 10.0.0.8 -j REJECT\n"
		"-A OUTPUT -d 10.0.0.9 -j MARK --set-mark 1\n"
		"-A OUTPUT -d 10.0.0.10 -j REJECT\n"));
	assert(gwp_acl_nr_indexed(a) == 0);
	gwp_acl_destroy(a);
}

/* A small deterministic PRNG, so a failure can be replayed. */
static uint32_t rnd_state;

static uint32_t rnd(uint32_t n)
{
	rnd_state ^= rnd_state << 13;
	rnd_state ^= rnd_state >> 17;
	rnd_state ^= rnd_state << 5;
	return rnd_state % n;
}

static const char *const rnd_v4_nets[] = {
	"10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24", "10.1.2.3", "10.1.2.128/25",
	"10.2.0.0/15", "10.3.3.3/32", "10.0.0.0/7", "0.0.0.0/0", "10.1.3.0/24",
	"::ffff:10.1.2.0/120", "10.2.2.0/23",
};
static const char *const rnd_v6_nets[] = {
	"2001:db8::/32", "2001:db8:1::/48", "2001:db8:1::1", "::/0",
	"2001:db8:1:2::/64", "2001:db9::/16",
	/* The same leading bytes as 10.1.0.0/16 and 10.1.2.3/32. */
	"a01::/16", "a01:203::/32",
};
static const char *const rnd_v4_addrs[] = {
	"10.1.2.3", "10.1.2.200", "10.1.3.1", "10.2.2.1", "10.3.3.3",
	"11.0.0.1", "10.0.0.1", "192.0.2.1",
};
static const char *const rnd_v6_addrs[] = {
	"2001:db8:1::1", "2001:db8:1:2::5", "2001:db8:2::1", "2001:db9::1",
	"fe80::1", "a01:203::1",
};
static const char *const rnd_doms[] = {
	"a.example", "B.example", "c.EXAMPLE", "d.example", "a.example.",
	"xn--bcher-kva.example", "e.example",
};

#define NELEM(x) (sizeof(x) / sizeof((x)[0]))

static const char *rnd_case(const char *s, char *buf)
{
	size_t i;

	for (i = 0; s[i]; i++) {
		char ch = s[i];

		if (ch >= 'a' && ch <= 'z' && rnd(2))
			ch = (char)(ch - 'a' + 'A');
		else if (ch >= 'A' && ch <= 'Z' && rnd(2))
			ch = (char)(ch - 'A' + 'a');
		buf[i] = ch;
	}
	buf[i] = '\0';
	return buf;
}

static const char *rnd_net(void)
{
	return rnd(4) ? rnd_v4_nets[rnd(NELEM(rnd_v4_nets))]
		      : rnd_v6_nets[rnd(NELEM(rnd_v6_nets))];
}

static const char *rnd_action(char *buf, bool output, bool terminal)
{
	static const char *const out_acts[] = {
		"-j ACCEPT", "-j REJECT", "-j DNAT --to 127.0.0.1:81",
		"-j DNAT --to :82", "-j MARK --set-mark 5 --accept",
		"-j BIND --to-source 127.0.0.2 --accept",
		"-j UPSTREAM --to DIRECT --accept", "-j MARK --set-mark 6",
		"-j BIND --to-iface lo", "-j UPSTREAM --to DIRECT",
	};

	if (!output)
		return rnd(2) ? "-j ACCEPT" : "-j REJECT";
	strcpy(buf, out_acts[rnd(terminal || rnd(4) ? 7 : NELEM(out_acts))]);
	return buf;
}

/*
 * Append one random rule for @chain to @p; returns the new end. With
 * @indexable, one an index can answer.
 */
static char *rnd_rule(char *p, bool output, bool indexable)
{
	static const uint32_t ikinds[] = { 0, 6, 7, 8 };
	char cbuf[64], abuf[64];
	const char *chain = output ? "OUTPUT" : "INPUT";
	const char *act = rnd_action(abuf, output, indexable);
	uint32_t kind;

	if (indexable)
		kind = output ? ikinds[rnd(NELEM(ikinds))] : 0;
	else
		kind = rnd(output ? 11 : 6);

	p += sprintf(p, "-A %s ", chain);
	switch (kind) {
	case 0: case 1: case 2:
		p += sprintf(p, "-s %s ", rnd_net());
		break;
	case 3:
		p += sprintf(p, "! -s %s ", rnd_net());
		break;
	case 4:
		/* -j UPSTREAM is TCP's only: a UDP one does not load. */
		p += sprintf(p, "-s %s -p %s ", rnd_net(),
			     rnd(2) || strstr(act, "UPSTREAM") ? "tcp" : "udp");
		break;
	case 5: {
		uint32_t lo = rnd(3) * 1000;

		p += sprintf(p, "--sports %u-%u ", lo, lo + 500 + rnd(2) * 500);
		break;
	}
	case 6: case 7:
		p += sprintf(p, "-d %s ", rnd_net());
		break;
	case 8:
		p += sprintf(p, "-m domain --domain %s ",
			     rnd_case(rnd_doms[rnd(NELEM(rnd_doms))], cbuf));
		break;
	case 9:
		p += sprintf(p, "! -d %s ", rnd_net());
		break;
	default:
		if (rnd(2))
			p += sprintf(p, "-d %s --dports %d ", rnd_net(),
				     rnd(2) ? 80 : 443);
		else
			p += sprintf(p, "-m domain ! --domain %s ",
				     rnd_doms[rnd(NELEM(rnd_doms))]);
		break;
	}
	p += sprintf(p, "%s\n", act);
	return p;
}

static void rnd_addr(struct gwp_sockaddr *s)
{
	uint32_t k = rnd(5);

	if (k < 2)
		*s = sa4(rnd_v4_addrs[rnd(NELEM(rnd_v4_addrs))], 443);
	else if (k < 3)
		*s = sa4mapped(rnd_v4_addrs[rnd(NELEM(rnd_v4_addrs))], 443);
	else
		*s = sa6(rnd_v6_addrs[rnd(NELEM(rnd_v6_addrs))], 443);
	s->i4.sin_port = htons((uint16_t)(rnd(2) ? 80 : 443));
}

static bool same_result(const struct gwp_acl_req *x, enum gwp_acl_verdict vx,
			const struct gwp_acl_req *y, enum gwp_acl_verdict vy)
{
	if (vx != vy || x->dnat_applied != y->dnat_applied ||
	    x->mark_set != y->mark_set || x->bind.set != y->bind.set ||
	    x->upstream != y->upstream)
		return false;
	if (x->dnat_applied && memcmp(&x->dnat, &y->dnat, sizeof(x->dnat)))
		return false;
	if (x->mark_set && x->mark != y->mark)
		return false;
	if (x->bind.set && memcmp(&x->bind, &y->bind, sizeof(x->bind)))
		return false;
	return true;
}

/*
 * gwp_acl_parse_str() with its warnings dropped: a random -j UPSTREAM rule
 * with a -d draws one each time.
 */
static int parse_quiet(struct gwp_acl **a, const char *text)
{
	int saved, null, r;

	fflush(stderr);
	saved = dup(STDERR_FILENO);
	null = open("/dev/null", O_WRONLY);
	assert(saved >= 0 && null >= 0);
	assert(dup2(null, STDERR_FILENO) == STDERR_FILENO);
	close(null);
	r = gwp_acl_parse_str(a, text);
	fflush(stderr);
	assert(dup2(saved, STDERR_FILENO) == STDERR_FILENO);
	close(saved);
	return r;
}

/*
 * Random rule files, each evaluated twice: as written, where long runs
 * are indexed, and with a never-matching two-criterion rule after every
 * rule, which leaves no run to index. Every request must get the same
 * verdict and the same DNAT/MARK/BIND/UPSTREAM result from both.
 */
static noinline void test_index_matches_linear(void)
{
	static const size_t max_rules = 120;
	char *txt, *ref;
	unsigned iter;

	txt = malloc(max_rules * 160);
	ref = malloc(max_rules * 2 * 160);
	assert(txt && ref);
	rnd_state = 0x9e3779b9u;
	for (iter = 0; iter < 300; iter++) {
		struct gwp_acl *a, *b;
		size_t nr = 8 + rnd(max_rules - 8), i, burst = 0;
		char *p = txt, *q = ref, *line;
		bool burst_out = false;
		unsigned k;

		p += sprintf(p, "-P INPUT %s\n-P OUTPUT %s\n",
			     rnd(2) ? "ACCEPT" : "REJECT",
			     rnd(2) ? "ACCEPT" : "REJECT");
		q += sprintf(q, "%s", txt);
		for (i = 0; i < nr; i++) {
			bool output = rnd(3) != 0;

			/* Now and then a run of indexable rules for one chain. */
			if (!burst && !rnd(10)) {
				burst = 6 + rnd(15);
				burst_out = rnd(3) != 0;
			}
			if (burst) {
				burst--;
				output = burst_out;
			}
			line = p;
			p = rnd_rule(p, output, burst != 0);
			q += sprintf(q, "%.*s", (int)(p - line), line);
			q += sprintf(q, output ?
				     "-A OUTPUT -d 0.0.0.0/32 --dports 1 -j REJECT\n" :
				     "-A INPUT -s 0.0.0.0/32 --sports 1 -j REJECT\n");
		}
		assert(!parse_quiet(&a, txt));
		assert(!parse_quiet(&b, ref));
		assert(gwp_acl_nr_indexed(b) == 0);

		for (k = 0; k < 200; k++) {
			struct gwp_sockaddr t, c;
			struct gwp_acl_req x, y;
			enum gwp_acl_verdict vx, vy;
			char dbuf[64];

			rnd_addr(&t);
			rnd_addr(&c);
			memset(&x, 0, sizeof(x));
			x.target = rnd(6) ? &t : NULL;
			x.client = rnd(6) ? &c : NULL;
			x.domain = rnd(3) ? rnd_case(rnd_doms[rnd(NELEM(rnd_doms))], dbuf)
					  : NULL;
			x.dport = (uint16_t)(rnd(2) ? 80 : 443);
			x.sport = (uint16_t)rnd(3000);
			x.proto = (uint8_t)rnd(2);
			y = x;

			vx = gwp_acl_eval_output(a, &x);
			vy = gwp_acl_eval_output(b, &y);
			if (!same_result(&x, vx, &y, vy)) {
				fprintf(stderr, "index mismatch, iter %u req %u:\n%s",
					iter, k, txt);
				abort();
			}
			vx = gwp_acl_eval_input(a, &x);
			vy = gwp_acl_eval_input(b, &y);
			assert(vx == vy);
		}
		gwp_acl_destroy(a);
		gwp_acl_destroy(b);
	}
	free(txt);
	free(ref);
}

/*
 * A domain-only request (no resolved IP, as with a socks5h upstream) carries
 * target == NULL. A target-dependent -d/--dports rule must match NEITHER
 * polarity: otherwise a negated allow-by-exclusion rule flips the unevaluable
 * criterion into a match and fails open past an IP-based REJECT.
 */
static noinline void test_domain_only_target_criteria(void)
{
	struct gwp_acl *a = NULL;

	assert(!gwp_acl_parse_str(&a,
		"-P OUTPUT REJECT\n"
		"-A OUTPUT -d 10.0.0.0/8 -j REJECT\n"
		"-A OUTPUT ! -d 10.0.0.0/8 -j ACCEPT\n"));
	/* Neither -d rule may match a domain-only target -> default REJECT. */
	assert(out(a, NULL, "internal.corp", 0, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	gwp_acl_destroy(a);

	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-P OUTPUT REJECT\n"
		"-A OUTPUT ! --dports 80 -j ACCEPT\n"));
	assert(out(a, NULL, "internal.corp", 0, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	gwp_acl_destroy(a);

	/* -m domain still evaluates for a domain-only request (domain is known). */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -m domain --domain internal.corp -j REJECT\n"
		"-P OUTPUT ACCEPT\n"));
	assert(out(a, NULL, "internal.corp", 0, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	assert(out(a, NULL, "other.com", 0, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	gwp_acl_destroy(a);
}

/* Load "-j MARK --set-mark @v" and return the mark an evaluation sets. */
static noinline uint32_t mark_of(const char *v)
{
	struct gwp_sockaddr t = sa4("1.2.3.4", 80);
	struct gwp_acl *a = NULL;
	struct gwp_acl_req req;
	char *rules;

	assert(asprintf(&rules, "-A OUTPUT -j MARK --set-mark %s\n"
			"-P OUTPUT ACCEPT\n", v) > 0);
	assert(!gwp_acl_parse_str(&a, rules));
	free(rules);
	memset(&req, 0, sizeof(req));
	req.target = &t; req.dport = 80; req.proto = GWP_ACL_PROTO_TCP;
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_ACCEPT);
	assert(req.mark_set);
	gwp_acl_destroy(a);
	return req.mark;
}

/*
 * Load "-m statistic --mode nth --every @every [--packet @packet]" and return
 * which of the first 64 evaluations it selects, one bit each.
 */
static noinline uint64_t nth_hits(const char *every, const char *packet)
{
	struct gwp_sockaddr t = sa4("1.2.3.4", 443);
	struct gwp_acl *a = NULL;
	uint64_t hits = 0;
	char *rules;
	int i;

	assert(asprintf(&rules,
			"-A OUTPUT -m statistic --mode nth --every %s%s%s -j REJECT\n"
			"-P OUTPUT ACCEPT\n", every, packet ? " --packet " : "",
			packet ? packet : "") > 0);
	assert(!gwp_acl_parse_str(&a, rules));
	free(rules);
	for (i = 0; i < 64; i++)
		if (out(a, &t, NULL, 443, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT)
			hits |= (uint64_t)1 << i;
	gwp_acl_destroy(a);
	return hits;
}

/* The bits nth_hits() should return for --every @n --packet @p. */
static uint64_t nth_mask(int n, int p)
{
	uint64_t m = 0;
	int i;

	for (i = 0; i < 64; i++)
		if (i % n == p)
			m |= (uint64_t)1 << i;
	return m;
}

/*
 * Numbers in a rule: a mark, --every and --packet are decimal or 0x
 * hexadecimal (either case), a lone 0 included; ports and prefix lengths are
 * decimal, where a leading 0 never meant octal and still reads as decimal. The
 * forms refused are in test_parse_errors().
 */
static noinline void test_number_bases(void)
{
	struct gwp_sockaddr t = sa4("10.1.2.3", 80);
	struct gwp_acl *a = NULL;

	assert(mark_of("0") == 0);
	assert(mark_of("9") == 9);
	assert(mark_of("10") == 10);
	assert(mark_of("0x10") == 16);
	assert(mark_of("0X1f") == 31);
	assert(mark_of("0x0") == 0);
	assert(mark_of("0x00000010") == 16);
	assert(mark_of("0xDeadBeef") == 0xdeadbeef);
	assert(mark_of("4294967295") == 0xffffffff);
	assert(mark_of("0xffffffff") == 0xffffffff);

	/* --every 10 is ten, not octal 8; 0x10 is sixteen. */
	assert(nth_hits("10", NULL) == nth_mask(10, 0));
	assert(nth_hits("0x10", NULL) == nth_mask(16, 0));
	assert(nth_hits("0x10", "0x0f") == nth_mask(16, 15));
	assert(nth_hits("0XA", "9") == nth_mask(10, 9));
	assert(nth_hits("0x1", "0") == ~(uint64_t)0);

	/* Decimal-only fields keep reading a leading 0 as decimal. */
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -d 10.0.0.0/08 --dports 080,0443-00444 -j REJECT\n"
		"-P OUTPUT ACCEPT\n"));
	assert(out(a, &t, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	assert(out(a, &t, NULL, 444, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	assert(out(a, &t, NULL, 64, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	t = sa4("11.1.2.3", 80);
	assert(out(a, &t, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	gwp_acl_destroy(a);
}

/*
 * -m statistic --mode nth: one evaluation in --every is selected, the one at
 * --packet. The counter lives on the rule, so these walk a fixed number of
 * evaluations and count how many were selected rather than probing one.
 */
static void test_statistic_nth(void)
{
	struct gwp_acl *a = NULL;
	struct gwp_sockaddr t = sa4("1.2.3.4", 443);
	int i, hits;

	/* Every 3rd, default offset 0: exactly one third, and it leads. */
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -m statistic --mode nth --every 3 -j REJECT\n"
		"-P OUTPUT ACCEPT\n"));
	for (i = 0, hits = 0; i < 30; i++)
		if (out(a, &t, NULL, 443, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT)
			hits++;
	assert(hits == 10);
	gwp_acl_destroy(a);

	/* Offset selects which of the three; still one in three. */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -m statistic --mode nth --every 3 --packet 2 -j REJECT\n"
		"-P OUTPUT ACCEPT\n"));
	for (i = 0, hits = 0; i < 30; i++) {
		enum gwp_acl_verdict v = out(a, &t, NULL, 443,
					     GWP_ACL_PROTO_TCP);
		/* The 3rd of each group, i.e. i % 3 == 2. */
		assert((v == GWP_ACL_REJECT) == (i % 3 == 2));
		if (v == GWP_ACL_REJECT)
			hits++;
	}
	assert(hits == 10);
	gwp_acl_destroy(a);

	/* --every 1 selects everything; the degenerate but legal case. */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -m statistic --mode nth --every 1 -j REJECT\n"
		"-P OUTPUT ACCEPT\n"));
	for (i = 0; i < 5; i++)
		assert(out(a, &t, NULL, 443, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	gwp_acl_destroy(a);

	/* Negated: the complement, two in three. */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -m statistic --mode nth ! --every 3 -j REJECT\n"
		"-P OUTPUT ACCEPT\n"));
	for (i = 0, hits = 0; i < 30; i++)
		if (out(a, &t, NULL, 443, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT)
			hits++;
	assert(hits == 20);
	gwp_acl_destroy(a);
}

/*
 * The counter must only advance for connections the rest of the rule already
 * matched, or the split is taken against the wrong population. Two ports share
 * one nth rule here: if the non-matching port were counted, the matching port
 * would not see a clean 1-in-2.
 */
static void test_statistic_counts_only_matches(void)
{
	struct gwp_acl *a = NULL;
	struct gwp_sockaddr t = sa4("1.2.3.4", 0);
	int i, hits = 0;

	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT --dports 443 -m statistic --mode nth --every 2 -j REJECT\n"
		"-P OUTPUT ACCEPT\n"));
	for (i = 0; i < 20; i++) {
		/* Interleave a port the rule does not match. */
		assert(out(a, &t, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
		if (out(a, &t, NULL, 443, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT)
			hits++;
	}
	assert(hits == 10);
	gwp_acl_destroy(a);
}

/*
 * The point of the module: split traffic evenly over several rules.
 *
 * Each rule counts its OWN evaluations, and a rule is only evaluated for the
 * connections earlier rules passed on -- so three rules all saying --every 3
 * do NOT give thirds. Rule 2 would only ever see the 2/3 that rule 1 declined,
 * and take a third of those.
 *
 * The iptables idiom applies unchanged: count down. 1-in-3, then 1-in-2 of the
 * remainder, then everything left.
 */
static void test_statistic_load_balance(void)
{
	struct gwp_acl *a = NULL;
	struct gwp_sockaddr t = sa4("1.2.3.4", 443);
	int i, seen[3] = { 0, 0, 0 };

	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -m statistic --mode nth --every 3 -j BIND --to-source 10.0.0.1 --accept\n"
		"-A OUTPUT -m statistic --mode nth --every 2 -j BIND --to-source 10.0.0.2 --accept\n"
		"-A OUTPUT -j BIND --to-source 10.0.0.3 --accept\n"
		"-P OUTPUT REJECT\n"));
	for (i = 0; i < 30; i++) {
		struct gwp_acl_req req = {
			.target = &t, .dport = 443, .proto = GWP_ACL_PROTO_TCP,
		};
		char ip[INET_ADDRSTRLEN];

		assert(gwp_acl_eval_output(a, &req) == GWP_ACL_ACCEPT);
		assert(req.bind.set && req.bind.have_src);
		assert(inet_ntop(AF_INET, &req.bind.src.i4.sin_addr, ip,
				 sizeof(ip)));
		assert(!strncmp(ip, "10.0.0.", 7));
		seen[ip[7] - '1']++;
	}
	assert(seen[0] == 10);
	assert(seen[1] == 10);
	assert(seen[2] == 10);
	gwp_acl_destroy(a);
}

/*
 * And the trap, pinned so nobody "fixes" the idiom above into the obvious
 * wrong thing: equal --every values do not split equally. Rule 1 takes a third
 * and rule 2 takes a third of the remaining two thirds.
 */
static void test_statistic_equal_every_is_uneven(void)
{
	struct gwp_acl *a = NULL;
	struct gwp_sockaddr t = sa4("1.2.3.4", 443);
	int i, first = 0, second = 0, rest = 0;

	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -m statistic --mode nth --every 3 -j BIND --to-source 10.0.0.1 --accept\n"
		"-A OUTPUT -m statistic --mode nth --every 3 -j BIND --to-source 10.0.0.2 --accept\n"
		"-A OUTPUT -j BIND --to-source 10.0.0.3 --accept\n"
		"-P OUTPUT REJECT\n"));
	for (i = 0; i < 18; i++) {
		struct gwp_acl_req req = {
			.target = &t, .dport = 443, .proto = GWP_ACL_PROTO_TCP,
		};
		char ip[INET_ADDRSTRLEN];

		assert(gwp_acl_eval_output(a, &req) == GWP_ACL_ACCEPT);
		assert(inet_ntop(AF_INET, &req.bind.src.i4.sin_addr, ip,
				 sizeof(ip)));
		if (ip[7] == '1')
			first++;
		else if (ip[7] == '2')
			second++;
		else
			rest++;
	}
	/* 18 -> 6 to the first, 4 to the second (a third of 12), 8 left. */
	assert(first == 6);
	assert(second == 4);
	assert(rest == 8);
	gwp_acl_destroy(a);
}

/*
 * Write @text to a new temporary file and return its malloc'd path, for the
 * tests that need gwp_acl_create()/gwp_acl_reload() on a real file.
 */
static char *write_tmp_rules(const char *text)
{
	const char *dir = getenv("TMPDIR");
	char *path;
	size_t len = strlen(text);
	int fd;

	if (!dir || !*dir)
		dir = "/tmp";
	assert(asprintf(&path, "%s/gwp-acl-test.XXXXXX", dir) > 0);
	fd = mkstemp(path);
	assert(fd >= 0);
	assert(write(fd, text, len) == (ssize_t)len);
	close(fd);
	return path;
}

struct reload_reader {
	struct gwp_acl	*acl;
	atomic_bool	*stop;
};

static void *reload_reader_fn(void *arg)
{
	struct reload_reader *rr = arg;
	struct gwp_sockaddr t = sa4("93.184.216.34", 443);

	while (!atomic_load_explicit(rr->stop, memory_order_relaxed))
		out(rr->acl, &t, NULL, 443, GWP_ACL_PROTO_TCP);
	return NULL;
}

static void reload_watchdog(int sig)
{
	static const char msg[] =
		"test_reload_under_readers: reload starved by readers\n";

	(void)sig;
	if (write(STDERR_FILENO, msg, sizeof(msg) - 1) < 0)
		_exit(1);
	_exit(1);
}

/*
 * A reload must get the write lock while other threads keep evaluating with
 * overlapping read sections, as busy workers do. With a reader-preferring
 * lock it waited for a gap that never came; the watchdog turns that hang
 * into a failure.
 */
static void test_reload_under_readers(void)
{
	struct reload_reader rr;
	pthread_t thr[16];
	atomic_bool stop = false;
	struct gwp_sockaddr t = sa4("10.1.2.3", 80);
	struct gwp_acl *a;
	long nr_cpu = sysconf(_SC_NPROCESSORS_ONLN);
	size_t nr, i;
	char *path;

	nr = nr_cpu > 2 ? (size_t)nr_cpu - 1 : 2;
	if (nr > 16)
		nr = 16;

	path = write_tmp_rules(DEFAULT_RULES);
	assert(!gwp_acl_create(&a, path));
	rr.acl = a;
	rr.stop = &stop;
	for (i = 0; i < nr; i++)
		assert(!pthread_create(&thr[i], NULL, reload_reader_fn, &rr));

	signal(SIGALRM, reload_watchdog);
	alarm(20);
	for (i = 0; i < 50; i++)
		assert(!gwp_acl_reload(a));
	alarm(0);
	signal(SIGALRM, SIG_DFL);

	atomic_store(&stop, true);
	for (i = 0; i < nr; i++)
		pthread_join(thr[i], NULL);

	/* The reloaded rules are the same file, so the verdicts are too. */
	assert(out(a, &t, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	gwp_acl_destroy(a);
	unlink(path);
	free(path);
}

/*
 * Two rulesets that give 10.1.2.3 opposite verdicts, behind a long run of
 * rules that do not match it so that evaluations last and overlap the
 * reloads. Ruleset A is loaded at even generations, B at odd ones.
 */
static char *swap_rules(bool b)
{
	size_t cap = 64 * 2100, len = 0;
	char *s = malloc(cap);
	int i;

	assert(s);
	len += (size_t)sprintf(s + len, "-P OUTPUT %s\n-P INPUT %s\n",
			       b ? "REJECT" : "ACCEPT", b ? "REJECT" : "ACCEPT");
	for (i = 0; i < 2000; i++)
		len += (size_t)sprintf(s + len,
				       "-A OUTPUT -d 172.%d.%d.0/24 --dports 1-9 -j REJECT\n",
				       16 + (i >> 8), i & 255);
	len += (size_t)sprintf(s + len, "-A OUTPUT -d 10.0.0.0/8 -j %s\n",
			       b ? "ACCEPT" : "REJECT");
	len += (size_t)sprintf(s + len, "-A INPUT -s 10.0.0.0/8 -j %s\n",
			       b ? "ACCEPT" : "REJECT");
	assert(len < cap);
	return s;
}

struct swap_reader {
	struct gwp_acl	*acl;
	atomic_bool	*stop;
	atomic_bool	bad;
};

static void *swap_reader_fn(void *arg)
{
	struct swap_reader *sr = arg;
	struct gwp_sockaddr t = sa4("10.1.2.3", 443);
	while (!atomic_load_explicit(sr->stop, memory_order_relaxed)) {
		struct gwp_acl_req req = {
			.target = &t, .dport = 443, .proto = GWP_ACL_PROTO_TCP,
		};
		enum gwp_acl_verdict v = gwp_acl_eval_output(sr->acl, &req);
		enum gwp_acl_verdict want = (req.gen & 1) ? GWP_ACL_ACCEPT
							  : GWP_ACL_REJECT;

		if (v != want)
			atomic_store(&sr->bad, true);
		/* INPUT has no generation; either ruleset's verdict will do. */
		in(sr->acl, &t, 1234, GWP_ACL_PROTO_TCP);
	}
	return NULL;
}

/*
 * Reloads publish a whole ruleset at once and free the old one only after
 * the evaluations still reading it are done: every verdict must be the one
 * of the ruleset it is tagged with, while threads evaluate across 200
 * reloads. A ruleset freed too early is a use-after-free under the
 * sanitizers, and a wrong or mixed verdict without them.
 */
static void test_reload_swaps_whole_ruleset(void)
{
	struct swap_reader sr = { 0 };
	atomic_bool stop = false;
	char *path, *ra, *rb;
	struct gwp_acl *a;
	pthread_t thr[4];
	size_t i;

	ra = swap_rules(false);
	rb = swap_rules(true);
	path = write_tmp_rules(ra);
	assert(!gwp_acl_create(&a, path));
	assert(gwp_acl_generation(a) == 0);
	sr.acl = a;
	sr.stop = &stop;
	for (i = 0; i < 4; i++)
		assert(!pthread_create(&thr[i], NULL, swap_reader_fn, &sr));

	for (i = 1; i <= 200; i++) {
		const char *txt = (i & 1) ? rb : ra;
		size_t len = strlen(txt);
		int fd;

		fd = open(path, O_WRONLY | O_TRUNC);
		assert(fd >= 0);
		assert(write(fd, txt, len) == (ssize_t)len);
		close(fd);
		assert(!gwp_acl_reload(a));
		assert(gwp_acl_generation(a) == i);
	}

	atomic_store(&stop, true);
	for (i = 0; i < 4; i++)
		pthread_join(thr[i], NULL);
	assert(!atomic_load(&sr.bad));
	gwp_acl_destroy(a);
	unlink(path);
	free(path);
	free(ra);
	free(rb);
}

/*
 * Callers cache OUTPUT verdicts keyed on the ruleset generation: it must move
 * on every successful reload and only then, and a chain with a -m statistic
 * rule must mark its verdicts uncacheable.
 */
static void test_generation(void)
{
	struct gwp_sockaddr t = sa4("93.184.216.34", 53);
	struct gwp_acl_req req = {
		.target = &t, .dport = 53, .proto = GWP_ACL_PROTO_UDP,
	};
	struct gwp_acl *a;
	uint32_t g0;
	char *path;
	int fd;

	assert(gwp_acl_generation(NULL) == 0);
	path = write_tmp_rules("-A OUTPUT --dports 53 -j REJECT\n");
	assert(!gwp_acl_create(&a, path));
	g0 = gwp_acl_generation(a);
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_REJECT);
	assert(req.gen == g0 && req.cacheable);

	/* A good reload moves the generation and the verdict with it. */
	fd = open(path, O_WRONLY | O_TRUNC);
	assert(fd >= 0);
	assert(write(fd, "-P OUTPUT REJECT\n-A OUTPUT --dports 53 -j ACCEPT\n",
		     49) == 49);
	close(fd);
	assert(!gwp_acl_reload(a));
	assert(gwp_acl_generation(a) != g0);
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_ACCEPT);
	assert(req.gen == gwp_acl_generation(a) && req.cacheable);
	g0 = req.gen;

	/* A failed reload keeps both the rules and the generation. */
	fd = open(path, O_WRONLY | O_TRUNC);
	assert(fd >= 0);
	assert(write(fd, "-A OUTPUT -j BOGUS\n", 19) == 19);
	close(fd);
	assert(gwp_acl_reload(a) < 0);
	assert(gwp_acl_generation(a) == g0);

	/* A statistic rule anywhere in OUTPUT makes verdicts uncacheable. */
	fd = open(path, O_WRONLY | O_TRUNC);
	assert(fd >= 0);
	assert(write(fd, "-A OUTPUT --dports 80 -m statistic --mode nth --every 2 -j REJECT\n",
		     66) == 66);
	close(fd);
	assert(!gwp_acl_reload(a));
	assert(gwp_acl_eval_output(a, &req) == GWP_ACL_ACCEPT);
	assert(!req.cacheable);

	gwp_acl_destroy(a);
	unlink(path);
	free(path);
}

static enum gwp_acl_verdict out_memo(struct gwp_acl *a, struct gwp_acl_memo *m,
				     const char *dom, const char *ip,
				     uint16_t port)
{
	struct gwp_sockaddr t = sa4(ip, port);
	struct gwp_acl_req req = {
		.target = &t, .domain = dom, .memo = m, .dport = port,
		.proto = GWP_ACL_PROTO_TCP,
	};

	return gwp_acl_eval_output(a, &req);
}

/*
 * The -m domain/-m user memo shared by a connection's candidate addresses:
 * verdicts are the same as without it, the address-dependent criteria are
 * still evaluated per candidate, rules past its capacity still match, and
 * a reset is what makes a new domain take effect.
 */
static void test_memo(void)
{
	static const char rules[] =
		"-A OUTPUT -m domain --domain bad.example --dports 80 -j REJECT\n"
		"-A OUTPUT -m domain --domain bad.example --dports 25 -j REJECT\n"
		"-A OUTPUT -m domain ! --domain bad.example --dports 26 -j REJECT\n";
	struct gwp_acl_memo m = { 0 };
	char *big, *p;
	struct gwp_acl *a;
	int i;

	assert(!gwp_acl_parse_str(&a, rules));
	for (i = 0; i < 2; i++) {
		struct gwp_acl_memo *mp = i ? &m : NULL;

		assert(out_memo(a, mp, "bad.example", "8.8.8.8", 80) == GWP_ACL_REJECT);
		assert(out_memo(a, mp, "bad.example", "8.8.8.8", 443) == GWP_ACL_ACCEPT);
		assert(out_memo(a, mp, "bad.example", "8.8.8.8", 25) == GWP_ACL_REJECT);
		assert(out_memo(a, mp, "bad.example", "8.8.8.8", 26) == GWP_ACL_ACCEPT);
	}
	/* Proof the memo is used: without a reset, a new domain is not seen. */
	assert(out_memo(a, &m, "good.example", "8.8.4.4", 80) == GWP_ACL_REJECT);
	gwp_acl_memo_reset(&m);
	assert(out_memo(a, &m, "good.example", "8.8.4.4", 80) == GWP_ACL_ACCEPT);
	assert(out_memo(a, &m, "good.example", "8.8.8.8", 26) == GWP_ACL_REJECT);
	gwp_acl_destroy(a);

	/* More name rules than memo slots: the rest is evaluated each time. */
	big = malloc(100 * 64);
	assert(big);
	p = big;
	for (i = 0; i < GWP_ACL_MEMO_RULES + 6; i++)
		p += sprintf(p, "-A OUTPUT -m domain --domain h%d.example -p tcp -j REJECT\n", i);
	assert(!gwp_acl_parse_str(&a, big));
	free(big);
	memset(&m, 0, sizeof(m));
	for (i = 0; i < 3; i++) {
		assert(out_memo(a, &m, "h69.example", "8.8.8.8", 80) == GWP_ACL_REJECT);
		assert(out_memo(a, &m, "h69.example", "8.8.4.4", 80) == GWP_ACL_REJECT);
	}
	gwp_acl_memo_reset(&m);
	assert(out_memo(a, &m, "h70.example", "8.8.8.8", 80) == GWP_ACL_ACCEPT);
	gwp_acl_destroy(a);
}

/*
 * An empty chain is answered from a summary published with the rules,
 * without the lock: it must follow both the policy and every reload.
 */
static void test_empty_chain_policy(void)
{
	static const char *const files[] = {
		"-P INPUT REJECT\n",
		"-P OUTPUT REJECT\n-A INPUT -s 10.0.0.0/8 -j REJECT\n",
		"-A OUTPUT --dports 80 -j REJECT\n",
		"# no rules\n",
	};
	/* in(10.1.1.1), in(192.0.2.1), out(:80), out(:443) per file */
	static const enum gwp_acl_verdict want[][4] = {
		{ GWP_ACL_REJECT, GWP_ACL_REJECT, GWP_ACL_ACCEPT, GWP_ACL_ACCEPT },
		{ GWP_ACL_REJECT, GWP_ACL_ACCEPT, GWP_ACL_REJECT, GWP_ACL_REJECT },
		{ GWP_ACL_ACCEPT, GWP_ACL_ACCEPT, GWP_ACL_REJECT, GWP_ACL_ACCEPT },
		{ GWP_ACL_ACCEPT, GWP_ACL_ACCEPT, GWP_ACL_ACCEPT, GWP_ACL_ACCEPT },
	};
	struct gwp_sockaddr c1 = sa4("10.1.1.1", 1234);
	struct gwp_sockaddr c2 = sa4("192.0.2.1", 1234);
	struct gwp_sockaddr t = sa4("93.184.216.34", 80);
	struct gwp_acl *a;
	char *path;
	size_t i;
	int fd;

	path = write_tmp_rules(files[0]);
	assert(!gwp_acl_create(&a, path));
	for (i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
		if (i) {
			size_t len = strlen(files[i]);

			fd = open(path, O_WRONLY | O_TRUNC);
			assert(fd >= 0);
			assert(write(fd, files[i], len) == (ssize_t)len);
			close(fd);
			assert(!gwp_acl_reload(a));
		}
		assert(in(a, &c1, 1234, GWP_ACL_PROTO_TCP) == want[i][0]);
		assert(in(a, &c2, 1234, GWP_ACL_PROTO_TCP) == want[i][1]);
		assert(out(a, &t, NULL, 80, GWP_ACL_PROTO_TCP) == want[i][2]);
		assert(out(a, &t, NULL, 443, GWP_ACL_PROTO_TCP) == want[i][3]);
	}

	/*
	 * An empty file, as a writer that truncates and then refills the file
	 * leaves it in between, is refused and the rules stay.
	 */
	fd = open(path, O_WRONLY | O_TRUNC);
	assert(fd >= 0);
	assert(write(fd, files[0], strlen(files[0])) == (ssize_t)strlen(files[0]));
	close(fd);
	assert(!gwp_acl_reload(a));
	fd = open(path, O_WRONLY | O_TRUNC);
	assert(fd >= 0);
	close(fd);
	assert(gwp_acl_reload(a) == -ENODATA);
	assert(in(a, &c1, 1234, GWP_ACL_PROTO_TCP) == want[0][0]);
	gwp_acl_destroy(a);
	assert(gwp_acl_create(&a, path) == -ENODATA);
	unlink(path);
	free(path);
}

/*
 * A NUL byte in the rule file must refuse the file, at creation and on
 * reload, rather than end it there and drop every rule after it.
 */
static void test_file_nul(void)
{
	static const char nul_rules[] =
		"-A OUTPUT -d 192.0.2.1 -j ACCEPT\n"
		"\0"
		"-P OUTPUT REJECT\n";
	struct gwp_sockaddr t = sa4("93.184.216.34", 80);
	struct gwp_acl *a;
	char *path;
	int fd;

	path = write_tmp_rules("");
	fd = open(path, O_WRONLY | O_TRUNC);
	assert(fd >= 0);
	assert(write(fd, nul_rules, sizeof(nul_rules) - 1) ==
	       (ssize_t)sizeof(nul_rules) - 1);
	close(fd);
	assert(gwp_acl_create(&a, path) == -EINVAL);

	fd = open(path, O_WRONLY | O_TRUNC);
	assert(fd >= 0);
	assert(write(fd, "-P OUTPUT REJECT\n", 17) == 17);
	close(fd);
	assert(!gwp_acl_create(&a, path));
	assert(out(a, &t, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);

	/* A reload that meets a NUL keeps the old rules. */
	fd = open(path, O_WRONLY | O_TRUNC);
	assert(fd >= 0);
	assert(write(fd, nul_rules, sizeof(nul_rules) - 1) ==
	       (ssize_t)sizeof(nul_rules) - 1);
	close(fd);
	assert(gwp_acl_reload(a) == -EINVAL);
	assert(out(a, &t, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);

	gwp_acl_destroy(a);
	unlink(path);
	free(path);
}

/*
 * A FIFO in place of the rule file, at creation or on reload, is refused at
 * once: opening it for reading would otherwise wait for a writer that may
 * never come, and hold up every later reload and shutdown with it.
 */
static void test_file_fifo(void)
{
	struct gwp_sockaddr t = sa4("93.184.216.34", 80);
	char *path, *fifo;
	struct gwp_acl *a;

	path = write_tmp_rules("-P OUTPUT REJECT\n");
	assert(asprintf(&fifo, "%s.fifo", path) > 0);
	assert(!mkfifo(fifo, 0600));
	assert(gwp_acl_create(&a, fifo) == -EINVAL);

	assert(!gwp_acl_create(&a, path));
	assert(!rename(fifo, path));
	assert(gwp_acl_reload(a) == -EINVAL);
	assert(out(a, &t, NULL, 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);

	gwp_acl_destroy(a);
	unlink(path);
	free(fifo);
	free(path);
}

/*
 * ------------------------------------------------------------------------
 * include
 * ------------------------------------------------------------------------
 */

/* A new empty directory for one include test; malloc'd path. */
static char *inc_dir(void)
{
	const char *tmp = getenv("TMPDIR");
	char *dir;

	if (!tmp || !*tmp)
		tmp = "/tmp";
	assert(asprintf(&dir, "%s/gwp-acl-inc.XXXXXX", tmp) > 0);
	assert(mkdtemp(dir));
	return dir;
}

/* Write @text to @dir/@name (truncating it); returns the malloc'd path. */
static char *inc_write(const char *dir, const char *name, const char *text)
{
	size_t len = strlen(text);
	char *path;
	int fd;

	assert(asprintf(&path, "%s/%s", dir, name) > 0);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	assert(fd >= 0);
	assert(write(fd, text, len) == (ssize_t)len);
	close(fd);
	return path;
}

static void inc_put(const char *dir, const char *name, const char *text)
{
	free(inc_write(dir, name, text));
}

/* Remove @dir and everything in it (one level of subdirectories). */
static void inc_rmdir(char *dir)
{
	char *cmd;

	assert(asprintf(&cmd, "rm -rf -- '%s'", dir) > 0);
	assert(!system(cmd));
	free(cmd);
	free(dir);
}

/* @acl's watched files are @dir/<each of @names>, in that order. */
static void inc_files(struct gwp_acl *acl, const char *dir,
		      const char *const *names, size_t nr)
{
	char path[PATH_MAX];
	size_t i;

	for (i = 0; i < nr; i++) {
		snprintf(path, sizeof(path), "%s/%s", dir, names[i]);
		assert(gwp_acl_file(acl, i));
		if (strcmp(gwp_acl_file(acl, i), path))
			fprintf(stderr, "file %zu is %s, not %s\n", i,
				gwp_acl_file(acl, i), path);
		assert(!strcmp(gwp_acl_file(acl, i), path));
	}
	assert(!gwp_acl_file(acl, nr));
}

static enum gwp_acl_verdict inc_out(struct gwp_acl *a, const char *ip)
{
	struct gwp_sockaddr t = sa4(ip, 80);

	return out(a, &t, NULL, 80, GWP_ACL_PROTO_TCP);
}

/*
 * The rules of an included file go in at the include line, so first-match
 * order is the order read top to bottom across the files. A relative path
 * is taken from the including file's directory, at every level; an absolute
 * one as given. A file included twice, but not inside itself, is no cycle.
 */
static noinline void test_include_order(void)
{
	static const char *const names[] = {
		"main.acl", "sub/a.acl", "sub/b.acl", "sub/c.acl", "abs.acl",
	};
	char *dir = inc_dir(), *sub, *main_path, *abs_path, *text;
	char cwd[PATH_MAX];
	struct gwp_acl *a;

	assert(asprintf(&sub, "%s/sub", dir) > 0);
	assert(!mkdir(sub, 0700));
	abs_path = inc_write(dir, "abs.acl",
			     "-A OUTPUT -d 203.0.113.1 -j REJECT\n");
	assert(asprintf(&text,
		"-A OUTPUT -d 192.0.2.1 -j ACCEPT\n"
		"include sub/a.acl;\n"
		"-A OUTPUT -d 192.0.2.0/24 -j ACCEPT\n"
		"include %s ; # an absolute path\n"
		"-A OUTPUT -d 198.51.100.0/24 -j REJECT\n"
		"#include sub/missing.acl;\n"
		"-P OUTPUT ACCEPT\n", abs_path) > 0);
	main_path = inc_write(dir, "main.acl", text);
	free(text);
	inc_put(sub, "a.acl",
		"-A OUTPUT -d 192.0.2.0/25 -j REJECT\n"
		"include b.acl;\n"
		"include c.acl;\n");
	inc_put(sub, "b.acl",
		"-A OUTPUT -d 192.0.2.128/25 -j REJECT\n"
		"include c.acl;\n");
	inc_put(sub, "c.acl", "-A OUTPUT -d 203.0.113.2 -j REJECT\n");

	assert(!gwp_acl_create(&a, main_path));
	/* Before the include, from it, from its include, after it. */
	assert(inc_out(a, "192.0.2.1") == GWP_ACL_ACCEPT);
	assert(inc_out(a, "192.0.2.2") == GWP_ACL_REJECT);
	assert(inc_out(a, "192.0.2.200") == GWP_ACL_REJECT);
	assert(inc_out(a, "198.51.100.7") == GWP_ACL_REJECT);
	assert(inc_out(a, "203.0.113.1") == GWP_ACL_REJECT);
	assert(inc_out(a, "203.0.113.2") == GWP_ACL_REJECT);
	assert(inc_out(a, "203.0.113.3") == GWP_ACL_ACCEPT);
	/* abs.acl is listed by the path it was included by. */
	inc_files(a, dir, names, 5);
	gwp_acl_destroy(a);

	/* A top file named without a directory includes from the cwd. */
	assert(getcwd(cwd, sizeof(cwd)));
	assert(!chdir(dir));
	assert(!gwp_acl_create(&a, "main.acl"));
	assert(!strcmp(gwp_acl_file(a, 0), "main.acl"));
	assert(!strcmp(gwp_acl_file(a, 1), "sub/a.acl"));
	assert(!strcmp(gwp_acl_file(a, 2), "sub/b.acl"));
	assert(inc_out(a, "192.0.2.200") == GWP_ACL_REJECT);
	assert(!chdir(cwd));
	gwp_acl_destroy(a);

	free(abs_path);
	free(main_path);
	free(sub);
	inc_rmdir(dir);
}

/* @text as main.acl in @dir must fail to load with @err. */
static void inc_refused(const char *dir, const char *text, int err)
{
	struct gwp_acl *a = NULL;
	char *path = inc_write(dir, "main.acl", text);

	assert(gwp_acl_create(&a, path) == err);
	assert(!a);
	free(path);
}

/*
 * Every way an include can go wrong refuses the whole load: a bad include
 * line, a missing or unreadable file, an empty one or one with a NUL byte, a
 * bad rule in an included file, a cycle (by any name), or nesting too deep.
 */
static noinline void test_include_errors(void)
{
	static const char nul[] = "-P OUTPUT REJECT\n\0\n";
	char *dir = inc_dir(), *path, name[32], text[64];
	struct gwp_acl *a = NULL;
	int fd, i;

	inc_put(dir, "ok.acl", "-A OUTPUT -d 192.0.2.1 -j REJECT\n");

	/* The syntax: one path, then a ';', which may stand alone. */
	inc_refused(dir, "include ok.acl\n", -EINVAL);
	inc_refused(dir, "include\n", -EINVAL);
	inc_refused(dir, "include ;\n", -EINVAL);
	inc_refused(dir, "include ;;\n", -EINVAL);
	inc_refused(dir, "include ok.acl;;\n", -EINVAL);
	inc_refused(dir, "include ok.acl; ;\n", -EINVAL);
	inc_refused(dir, "include ok.acl other.acl;\n", -EINVAL);
	inc_refused(dir, "include ok.acl ok.acl ;\n", -EINVAL);
	inc_refused(dir, "include ok.acl # no ;\n", -EINVAL);
	inc_refused(dir, "-A OUTPUT -j ACCEPT include ok.acl;\n", -EINVAL);
	path = inc_write(dir, "main.acl", "include ok.acl;\n");
	assert(!gwp_acl_create(&a, path));
	gwp_acl_destroy(a);
	free(path);

	/* No directory to take a path from: refused in text. */
	assert(gwp_acl_parse_str(&a, "include /dev/null;\n") == -EINVAL);

	inc_refused(dir, "include missing.acl;\n", -ENOENT);
	inc_refused(dir, "include .;\n", -EINVAL);
	inc_refused(dir, "include /dev/null;\n", -EINVAL);

	/*
	 * A FIFO, included or as the top file, is refused at once: opening it
	 * for reading would otherwise wait for a writer that never comes.
	 */
	assert(asprintf(&path, "%s/pipe.acl", dir) > 0);
	assert(!mkfifo(path, 0600));
	inc_refused(dir, "include pipe.acl;\n", -EINVAL);
	assert(gwp_acl_create(&a, path) == -EINVAL);
	free(path);

	inc_put(dir, "empty.acl", "");
	inc_refused(dir, "include empty.acl;\n", -ENODATA);
	path = inc_write(dir, "nul.acl", "");
	fd = open(path, O_WRONLY | O_TRUNC);
	assert(fd >= 0);
	assert(write(fd, nul, sizeof(nul) - 1) == (ssize_t)sizeof(nul) - 1);
	close(fd);
	free(path);
	inc_refused(dir, "include nul.acl;\n", -EINVAL);

	inc_put(dir, "bad.acl", "-A OUTPUT -j BOGUS\n");
	inc_refused(dir, "-P OUTPUT REJECT\ninclude bad.acl;\n", -EINVAL);

	/* Cycles: directly, through another file, through another name. */
	inc_refused(dir, "include main.acl;\n", -ELOOP);
	inc_refused(dir, "include ./main.acl;\n", -ELOOP);
	inc_put(dir, "back.acl", "include main.acl;\n");
	inc_refused(dir, "include back.acl;\n", -ELOOP);
	inc_put(dir, "self.acl", "include link.acl;\n");
	assert(asprintf(&path, "%s/link.acl", dir) > 0);
	assert(!symlink("self.acl", path));
	free(path);
	inc_refused(dir, "include self.acl;\n", -ELOOP);

	/*
	 * Depth: dN.acl includes d(N+1).acl and d7.acl includes leaf.acl. From
	 * main.acl (level 0) through d1.acl, leaf.acl is at level 8 and loads;
	 * through d0.acl it is at level 9, one too deep.
	 */
	for (i = 0; i < 7; i++) {
		snprintf(name, sizeof(name), "d%d.acl", i);
		snprintf(text, sizeof(text), "include d%d.acl;\n", i + 1);
		inc_put(dir, name, text);
	}
	inc_put(dir, "d7.acl", "include leaf.acl;\n");
	inc_put(dir, "leaf.acl", "-A OUTPUT -d 192.0.2.8 -j REJECT\n");
	path = inc_write(dir, "main.acl", "include d0.acl;\n");
	assert(gwp_acl_create(&a, path) == -ELOOP);
	free(path);
	path = inc_write(dir, "main.acl", "include d1.acl;\n");
	assert(!gwp_acl_create(&a, path));
	assert(inc_out(a, "192.0.2.8") == GWP_ACL_REJECT);
	gwp_acl_destroy(a);
	free(path);

	/*
	 * At most 64 reads of a file per load, the top file and each repeat
	 * counted: 63 includes load, 64 do not. And a diamond that would
	 * read 2^8 files is stopped by the same cap, not by the depth one.
	 */
	{
		char big[64 * 16 + 1];
		char *p = big;

		for (i = 0; i < 63; i++)
			p += sprintf(p, "include ok.acl;\n");
		path = inc_write(dir, "main.acl", big);
		assert(!gwp_acl_create(&a, path));
		assert(inc_out(a, "192.0.2.1") == GWP_ACL_REJECT);
		gwp_acl_destroy(a);
		free(path);
		p += sprintf(p, "include ok.acl;\n");
		inc_refused(dir, big, -E2BIG);
	}
	for (i = 0; i < 8; i++) {
		snprintf(name, sizeof(name), "w%d.acl", i);
		snprintf(text, sizeof(text), "include w%d.acl;\ninclude w%d.acl;\n",
			 i + 1, i + 1);
		inc_put(dir, name, text);
	}
	inc_put(dir, "w8.acl", "-A OUTPUT -d 192.0.2.8 -j REJECT\n");
	inc_refused(dir, "include w1.acl;\n", -E2BIG);

	inc_rmdir(dir);
}

/*
 * A change to an included file is picked up by a reload of the whole set,
 * a broken one keeps the old rules, and the files to watch follow the
 * includes: every file the last attempt met, even one that was missing.
 */
static noinline void test_include_reload(void)
{
	static const char *const two[] = { "main.acl", "a.acl" };
	static const char *const three[] = { "main.acl", "a.acl", "new.acl" };
	static const char *const one[] = { "main.acl" };
	char *dir = inc_dir(), *main_path, *a_path;
	struct stat st, st_main, st_a;
	struct gwp_acl *a;

	main_path = inc_write(dir, "main.acl",
			      "include a.acl;\n-P OUTPUT ACCEPT\n");
	inc_put(dir, "a.acl", "-A OUTPUT -d 192.0.2.1 -j REJECT\n");
	assert(!stat(main_path, &st_main));
	assert(asprintf(&a_path, "%s/a.acl", dir) > 0);
	assert(!stat(a_path, &st_a));
	assert(!gwp_acl_create(&a, main_path));
	assert(inc_out(a, "192.0.2.1") == GWP_ACL_REJECT);
	assert(inc_out(a, "192.0.2.2") == GWP_ACL_ACCEPT);
	inc_files(a, dir, two, 2);

	/*
	 * Each file's identity is the one it had when it was read, and stays
	 * so after it changes: the reload watch compares against it, so a
	 * change made right after the read is still seen as one.
	 */
	assert(!gwp_acl_file_stat(a, 0, &st));
	assert(st.st_ino == st_main.st_ino && st.st_size == st_main.st_size);
	assert(!gwp_acl_file_stat(a, 1, &st));
	assert(st.st_ino == st_a.st_ino && st.st_size == st_a.st_size);
	inc_put(dir, "a.acl", "-A OUTPUT -d 192.0.2.1 -j REJECT # longer\n");
	assert(!gwp_acl_file_stat(a, 1, &st));
	assert(st.st_size == st_a.st_size);
	assert(gwp_acl_file_stat(a, 2, &st) == -ENOENT);

	inc_put(dir, "a.acl", "-A OUTPUT -d 192.0.2.2 -j REJECT\n");
	assert(!gwp_acl_reload(a));
	assert(inc_out(a, "192.0.2.1") == GWP_ACL_ACCEPT);
	assert(inc_out(a, "192.0.2.2") == GWP_ACL_REJECT);

	/* A broken included file: the old rules stay. */
	inc_put(dir, "a.acl", "-A OUTPUT -j BOGUS\n");
	assert(gwp_acl_reload(a) == -EINVAL);
	assert(inc_out(a, "192.0.2.2") == GWP_ACL_REJECT);
	inc_files(a, dir, two, 2);
	inc_put(dir, "a.acl", "-A OUTPUT -d 192.0.2.3 -j REJECT\n");

	/* An include of a file not there yet: it is watched all the same. */
	inc_put(dir, "main.acl",
		"include a.acl;\ninclude new.acl;\n-P OUTPUT ACCEPT\n");
	assert(gwp_acl_reload(a) == -ENOENT);
	assert(inc_out(a, "192.0.2.2") == GWP_ACL_REJECT);
	inc_files(a, dir, three, 3);
	assert(gwp_acl_file_stat(a, 2, &st) == -ENOENT);
	inc_put(dir, "new.acl", "-A OUTPUT -d 192.0.2.4 -j REJECT\n");
	assert(!gwp_acl_reload(a));
	assert(inc_out(a, "192.0.2.2") == GWP_ACL_ACCEPT);
	assert(inc_out(a, "192.0.2.3") == GWP_ACL_REJECT);
	assert(inc_out(a, "192.0.2.4") == GWP_ACL_REJECT);
	inc_files(a, dir, three, 3);

	/* Includes dropped: so are their files. */
	inc_put(dir, "main.acl", "-P OUTPUT REJECT\n");
	assert(!gwp_acl_reload(a));
	assert(inc_out(a, "192.0.2.5") == GWP_ACL_REJECT);
	inc_files(a, dir, one, 1);

	gwp_acl_destroy(a);
	free(a_path);
	free(main_path);
	inc_rmdir(dir);
}

/*
 * ------------------------------------------------------------------------
 * include patterns
 * ------------------------------------------------------------------------
 */

static void up_capture(void);
static char *up_captured(void);

/* mkdir @dir/@name; returns the malloc'd path. */
static char *inc_mkdir(const char *dir, const char *name)
{
	char *path;

	assert(asprintf(&path, "%s/%s", dir, name) > 0);
	assert(!mkdir(path, 0700));
	return path;
}

static void inc_mkdir_put(const char *dir, const char *name)
{
	free(inc_mkdir(dir, name));
}

/*
 * @text as main.acl in @dir must fail to load with @err, and say @msg (with
 * "%s" standing for main.acl's path).
 */
static void inc_refused_msg(const char *dir, const char *text, int err,
			    const char *msg)
{
	struct gwp_acl *a = NULL;
	char *path = inc_write(dir, "main.acl", text), *said, *want;
	int r;

	assert(asprintf(&want, msg, path) > 0);
	up_capture();
	r = gwp_acl_create(&a, path);
	said = up_captured();
	if (r != err || !strstr(said, want)) {
		fprintf(stderr, "returned %d, not %d; want \"%s\", it said:\n%s",
			r, err, want, said);
		assert(0);
	}
	assert(!a);
	free(said);
	free(want);
	free(path);
}

/* @text as main.acl in @dir loads, and its files are @names in order. */
static struct gwp_acl *inc_loads(const char *dir, const char *text,
				 const char *const *names, size_t nr)
{
	char *path = inc_write(dir, "main.acl", text);
	struct gwp_acl *a;
	int r;

	r = gwp_acl_create(&a, path);
	if (r) {
		fprintf(stderr, "returned %d for:\n%s", r, text);
		assert(0);
	}
	inc_files(a, dir, names, nr);
	free(path);
	return a;
}

/*
 * A pattern includes every file it matches, sorted byte-wise by path
 * whatever the directory order, and '*', '?' and "[...]" work in any
 * component, at any number of levels. A leading '.' is matched only by a
 * pattern that starts with one, '\' makes a character literal, and a
 * relative pattern is taken from the including file's directory.
 */
static noinline void test_include_glob_order(void)
{
	static const char *const conf[] = {
		"main.acl", "conf/B.conf", "conf/a.conf", "conf/b.conf",
	};
	static const char *const hidden[] = {
		"main.acl", "conf/.h.conf",
	};
	static const char *const levels[] = {
		"main.acl", "lv/w/y/3.conf", "lv/x/y/1.conf", "lv/x/z/2.conf",
	};
	static const char *const mid[] = {
		"main.acl", "lv/w/y/3.conf", "lv/x/y/1.conf",
	};
	static const char *const sets[] = {
		"main.acl", "conf/a.conf", "conf/b.conf",
	};
	static const char *const lit[] = { "main.acl", "conf/lit*.lit" };
	static const char *const nested[] = {
		"main.acl", "lv/w/y/3.conf", "lv/x/y/1.conf",
		"lv/x/y/sub/s.conf",
	};
	static const char *const one_dir[] = {
		"main.acl", "lv/x/y/1.conf", "lv/x/y/sub/s.conf",
	};
	char *dir = inc_dir(), *text;
	struct gwp_acl *a;

	inc_mkdir_put(dir, "conf");
	/* Created in an order the sort must not follow. */
	inc_put(dir, "conf/b.conf", "-A OUTPUT -d 192.0.2.1 -j ACCEPT\n");
	inc_put(dir, "conf/a.conf", "-A OUTPUT -d 192.0.2.1 -j REJECT\n"
				    "-A OUTPUT -d 192.0.2.2 -j ACCEPT\n");
	inc_put(dir, "conf/B.conf", "-A OUTPUT -d 192.0.2.2 -j REJECT\n");
	inc_put(dir, "conf/c.txt", "-A OUTPUT -j BOGUS\n");
	inc_put(dir, "conf/.h.conf", "-A OUTPUT -d 192.0.2.3 -j REJECT\n");
	inc_put(dir, "conf/lit*.lit", "-A OUTPUT -d 192.0.2.4 -j REJECT\n");
	inc_put(dir, "conf/litX.lit", "-A OUTPUT -j BOGUS\n");

	/* "B" sorts before "a"; a.conf's REJECT wins over b.conf's ACCEPT. */
	a = inc_loads(dir, "include conf/*.conf;\n-P OUTPUT ACCEPT\n", conf, 4);
	assert(inc_out(a, "192.0.2.1") == GWP_ACL_REJECT);
	assert(inc_out(a, "192.0.2.2") == GWP_ACL_REJECT);
	assert(inc_out(a, "192.0.2.3") == GWP_ACL_ACCEPT);
	gwp_acl_destroy(a);

	/* Only a leading '.' in the pattern matches a hidden name. */
	a = inc_loads(dir, "include conf/.*.conf;\n", hidden, 2);
	assert(inc_out(a, "192.0.2.3") == GWP_ACL_REJECT);
	gwp_acl_destroy(a);
	a = inc_loads(dir, "include conf/\\.h.c?nf;\n", hidden, 2);
	gwp_acl_destroy(a);

	/* '?', sets, ranges and negated sets. */
	a = inc_loads(dir, "include conf/[ab].c?nf;\n", sets, 3);
	gwp_acl_destroy(a);
	a = inc_loads(dir, "include conf/[a-b].conf;\n", sets, 3);
	gwp_acl_destroy(a);
	a = inc_loads(dir, "include conf/[!B.l]*.conf;\n", sets, 3);
	gwp_acl_destroy(a);
	a = inc_loads(dir, "include conf/[^B.l]*.conf;\n", sets, 3);
	gwp_acl_destroy(a);
	a = inc_loads(dir, "include conf/[[:lower:]].conf;\n", sets, 3);
	gwp_acl_destroy(a);

	/* An escaped wildcard is literal, in a path and in a pattern. */
	a = inc_loads(dir, "include conf/lit\\*.lit;\n", lit, 2);
	assert(inc_out(a, "192.0.2.4") == GWP_ACL_REJECT);
	gwp_acl_destroy(a);
	a = inc_loads(dir, "include conf/lit\\*.l?t;\n", lit, 2);
	gwp_acl_destroy(a);

	/* Several levels; hidden directories and plain files do not lead on. */
	inc_mkdir_put(dir, "lv");
	inc_mkdir_put(dir, "lv/x");
	inc_mkdir_put(dir, "lv/x/y");
	inc_mkdir_put(dir, "lv/x/z");
	inc_mkdir_put(dir, "lv/w");
	inc_mkdir_put(dir, "lv/w/y");
	inc_mkdir_put(dir, "lv/.h");
	inc_mkdir_put(dir, "lv/.h/y");
	inc_put(dir, "lv/x/y/1.conf", "-A OUTPUT -d 192.0.2.5 -j REJECT\n");
	inc_put(dir, "lv/x/z/2.conf", "-A OUTPUT -d 192.0.2.6 -j REJECT\n");
	inc_put(dir, "lv/w/y/3.conf", "-A OUTPUT -d 192.0.2.7 -j REJECT\n");
	inc_put(dir, "lv/.h/y/4.conf", "-A OUTPUT -j BOGUS\n");
	inc_put(dir, "lv/file", "-A OUTPUT -j BOGUS\n");
	a = inc_loads(dir, "include lv/*/*/*.conf;\n", levels, 4);
	assert(inc_out(a, "192.0.2.5") == GWP_ACL_REJECT);
	assert(inc_out(a, "192.0.2.6") == GWP_ACL_REJECT);
	assert(inc_out(a, "192.0.2.7") == GWP_ACL_REJECT);
	gwp_acl_destroy(a);
	/* A literal component between wildcards; doubled slashes. */
	a = inc_loads(dir, "include lv/*/y//*.conf;\n", mid, 3);
	gwp_acl_destroy(a);

	/* A match's own includes are relative to the match's directory. */
	inc_put(dir, "lv/x/y/1.conf", "-A OUTPUT -d 192.0.2.5 -j REJECT\n"
				      "include sub/*.conf;\n");
	inc_mkdir_put(dir, "lv/x/y/sub");
	inc_put(dir, "lv/x/y/sub/s.conf", "-A OUTPUT -d 192.0.2.8 -j REJECT\n");
	a = inc_loads(dir, "include lv/?/y/*.conf;\n", nested, 4);
	assert(inc_out(a, "192.0.2.8") == GWP_ACL_REJECT);
	gwp_acl_destroy(a);

	/* An absolute pattern. */
	assert(asprintf(&text, "include %s/lv/x/y/*.conf;\n", dir) > 0);
	a = inc_loads(dir, text, one_dir, 3);
	gwp_acl_destroy(a);
	free(text);

	/*
	 * The including file's directory is taken as it is, even with
	 * characters that would be wildcards in the pattern.
	 */
	inc_mkdir_put(dir, "w[e]*?\\");
	inc_mkdir_put(dir, "w[e]*?\\/x");
	inc_put(dir, "w[e]*?\\/x/1.conf", "-A OUTPUT -d 192.0.2.9 -j REJECT\n");
	inc_mkdir_put(dir, "we");
	inc_mkdir_put(dir, "we/x");
	inc_put(dir, "we/x/1.conf", "-A OUTPUT -j BOGUS\n");
	text = inc_write(dir, "w[e]*?\\/main.acl", "include x/*.conf;\n");
	assert(!gwp_acl_create(&a, text));
	assert(inc_out(a, "192.0.2.9") == GWP_ACL_REJECT);
	assert(!gwp_acl_file(a, 2));
	gwp_acl_destroy(a);
	free(text);

	inc_rmdir(dir);
}

/*
 * A strict include fails the load when its pattern matches nothing, or a
 * match is not a regular file (a directory, a FIFO, a dangling link). The
 * syntax errors, a cycle through a pattern, and the limits.
 */
static noinline void test_include_glob_errors(void)
{
	char *dir = inc_dir(), *path, name[64], text[64];
	struct gwp_acl *a;
	int i;

	inc_mkdir_put(dir, "conf");
	inc_put(dir, "conf/a.conf", "-A OUTPUT -d 192.0.2.1 -j REJECT\n");

	/* Nothing matches: the message names the file, line and pattern. */
	inc_refused_msg(dir, "\ninclude conf/*.acl;\n", -ENOENT,
			"acl: %s: line 2: include conf/*.acl: no file matches");
	inc_refused_msg(dir, "include none/*.conf;\n", -ENOENT,
			"line 1: include none/*.conf: no file matches");
	inc_refused_msg(dir, "include conf/a.conf/*;\n", -ENOENT,
			"line 1: include conf/a.conf/*: no file matches");

	/* Syntax. */
	inc_refused_msg(dir, "include conf/**.conf;\n", -EINVAL,
			"include conf/**.conf: ** is not supported");
	inc_refused_msg(dir, "include conf/[a.conf;\n", -EINVAL,
			"include conf/[a.conf: a [ is not closed");
	inc_refused_msg(dir, "include conf/[a/]b;\n", -EINVAL,
			"a [ is not closed");
	inc_refused_msg(dir, "include conf/[[:alpha:];\n", -EINVAL,
			"a [ is not closed");
	inc_refused_msg(dir, "include conf\\/a.conf;\n", -EINVAL,
			"a \\ ends a path component");
	inc_refused_msg(dir, "include conf/a\\;\n", -EINVAL,
			"a \\ ends a path component");
	inc_refused_msg(dir, "include conf/[\\]].conf;\n", -EINVAL,
			"a \\ inside [...] is not supported");

	/* Every match must be a regular file. */
	inc_mkdir_put(dir, "conf/d.conf");
	inc_refused_msg(dir, "include conf/*.conf;\n", -EINVAL,
			"conf/d.conf: not a regular file");
	assert(asprintf(&path, "%s/conf/d.conf", dir) > 0);
	assert(!rmdir(path));
	assert(!mkfifo(path, 0600));
	inc_refused_msg(dir, "include conf/*.conf;\n", -EINVAL,
			"conf/d.conf: not a regular file");
	assert(!unlink(path));
	assert(!symlink("nowhere.conf", path));
	inc_refused_msg(dir, "include conf/*.conf;\n", -ENOENT,
			"conf/d.conf: No such file or directory");
	assert(!unlink(path));
	free(path);

	/* A pattern that matches the including file is a cycle. */
	inc_refused_msg(dir, "include *.acl;\n", -ELOOP, "include cycle");
	inc_put(dir, "conf/back.conf", "include ../m*.acl;\n");
	inc_refused_msg(dir, "include conf/*.conf;\n", -ELOOP, "include cycle");
	assert(asprintf(&path, "%s/conf/back.conf", dir) > 0);
	assert(!unlink(path));
	free(path);

	/* Depth: a pattern's matches are one level down, as a path's. */
	for (i = 0; i < 7; i++) {
		snprintf(name, sizeof(name), "d%d.acl", i);
		snprintf(text, sizeof(text), "include d[%d].acl;\n", i + 1);
		inc_put(dir, name, text);
	}
	inc_put(dir, "d7.acl", "include lea?.acl;\n");
	inc_put(dir, "leaf.acl", "-A OUTPUT -d 192.0.2.8 -j REJECT\n");
	inc_refused_msg(dir, "include d[0].acl;\n", -ELOOP,
			"includes nest deeper than 8 levels");
	path = inc_write(dir, "main.acl", "include d[1].acl;\n");
	assert(!gwp_acl_create(&a, path));
	assert(inc_out(a, "192.0.2.8") == GWP_ACL_REJECT);
	gwp_acl_destroy(a);
	free(path);

	/*
	 * Each match counts toward the 64 files of a load: 63 matches and the
	 * top file load, 64 do not; 65 are refused before any is read.
	 */
	inc_mkdir_put(dir, "many");
	for (i = 0; i < 63; i++) {
		snprintf(name, sizeof(name), "many/%02d.conf", i);
		inc_put(dir, name, "-A OUTPUT -d 192.0.2.9 -j REJECT\n");
	}
	path = inc_write(dir, "main.acl", "include many/*.conf;\n");
	assert(!gwp_acl_create(&a, path));
	assert(inc_out(a, "192.0.2.9") == GWP_ACL_REJECT);
	gwp_acl_destroy(a);
	free(path);
	inc_put(dir, "many/63.conf", "-A OUTPUT -d 192.0.2.9 -j REJECT\n");
	inc_refused_msg(dir, "include many/*.conf;\n", -E2BIG,
			"more than 64 files in one load");
	inc_put(dir, "many/64.conf", "-A OUTPUT -d 192.0.2.9 -j REJECT\n");
	inc_refused_msg(dir, "include many/*.conf;\n", -E2BIG,
			"include pattern matches more than 64 files");

	/* At most 256 directories read by the patterns of one load. */
	inc_mkdir_put(dir, "wide");
	for (i = 0; i < 255; i++) {
		snprintf(name, sizeof(name), "wide/%03d", i);
		inc_mkdir_put(dir, name);
	}
	inc_put(dir, "wide/000/x.conf", "-A OUTPUT -d 192.0.2.10 -j REJECT\n");
	/* wide itself and 255 below it: 256. */
	path = inc_write(dir, "main.acl", "include wide/*/*.conf;\n");
	assert(!gwp_acl_create(&a, path));
	assert(inc_out(a, "192.0.2.10") == GWP_ACL_REJECT);
	gwp_acl_destroy(a);
	free(path);
	inc_mkdir_put(dir, "wide/255");
	inc_refused_msg(dir, "include wide/*/*.conf;\n", -E2BIG,
			"read more than 256 directories");

	/* A directory that cannot be read fails the load (not as root). */
	if (geteuid()) {
		assert(asprintf(&path, "%s/conf", dir) > 0);
		assert(!chmod(path, 0));
		inc_refused_msg(dir, "include conf/*.conf;\n", -EACCES,
				"conf: Permission denied");
		assert(!chmod(path, 0700));
		free(path);
	}

	inc_rmdir(dir);
}

/*
 * ------------------------------------------------------------------------
 * Upstream pools and -j UPSTREAM
 * ------------------------------------------------------------------------
 */

/*
 * What the code under test writes to stderr between up_capture() and
 * up_captured(), which returns it (malloc'd), so a test can check what a
 * load said: the file and line of an error, and that no password is in it.
 */
static int g_saved_stderr = -1;
static FILE *g_capture;

static void up_capture(void)
{
	fflush(stderr);
	g_capture = tmpfile();
	assert(g_capture);
	g_saved_stderr = dup(STDERR_FILENO);
	assert(g_saved_stderr >= 0);
	assert(dup2(fileno(g_capture), STDERR_FILENO) == STDERR_FILENO);
}

static char *up_captured(void)
{
	long len;
	char *buf;

	fflush(stderr);
	assert(dup2(g_saved_stderr, STDERR_FILENO) == STDERR_FILENO);
	close(g_saved_stderr);
	g_saved_stderr = -1;
	len = ftell(g_capture);
	assert(len >= 0);
	buf = calloc(1, (size_t)len + 1);
	assert(buf);
	rewind(g_capture);
	assert(fread(buf, 1, (size_t)len, g_capture) == (size_t)len);
	fclose(g_capture);
	return buf;
}

/* A captured call returned @r, wanted @want: show what it said if not. */
static void up_check(int r, int want, const char *said)
{
	if (r == want)
		return;
	fprintf(stderr, "returned %d, not %d; it said:\n%s", r, want, said);
	assert(0);
}

/*
 * @text must fail to parse with @err, and the message must contain @msg (and
 * never the password "s3cret" a URL in the text may carry).
 */
static void up_refused(const char *text, int err, const char *msg)
{
	struct gwp_acl *a = NULL;
	char *said;
	int r;

	up_capture();
	r = gwp_acl_parse_str(&a, text);
	said = up_captured();
	if (r != err || !strstr(said, msg) || strstr(said, "s3cret")) {
		fprintf(stderr, "unexpected result %d for:\n%s---\n%s", r,
			text, said);
		assert(0);
	}
	assert(!a);
	free(said);
}

/* Evaluate OUTPUT for user @user to 192.0.2.1:80; fills *@req. */
static enum gwp_acl_verdict up_eval(struct gwp_acl *a, const char *user,
				    struct gwp_acl_req *req)
{
	static struct gwp_sockaddr t;

	t = sa4("192.0.2.1", 80);
	memset(req, 0, sizeof(*req));
	req->target = &t;
	req->user = user;
	req->dport = 80;
	req->proto = GWP_ACL_PROTO_TCP;
	return gwp_acl_eval_output(a, req);
}

/* The pool name OUTPUT chose for @user, "DIRECT", or "" for none. */
static const char *up_choice(struct gwp_acl *a, const char *user)
{
	static char name[80];
	struct gwp_acl_req req;

	assert(up_eval(a, user, &req) == GWP_ACL_ACCEPT);
	switch (req.upstream) {
	case GWP_ACL_UPSTREAM_NONE:
		assert(!req.upstream_pool);
		strcpy(name, "");
		break;
	case GWP_ACL_UPSTREAM_DIRECT:
		assert(!req.upstream_pool);
		strcpy(name, "DIRECT");
		break;
	default:
		assert(req.upstream == GWP_ACL_UPSTREAM_POOL);
		assert(req.upstream_pool);
		snprintf(name, sizeof(name), "%s",
			 gwp_acl_pool_name(req.upstream_pool));
		break;
	}
	gwp_acl_req_release(&req);
	assert(!req.upstream_pool && req.upstream == GWP_ACL_UPSTREAM_NONE);
	gwp_acl_req_release(&req);
	return name;
}

/* "upstream NAME {", N servers, "}", appended at @p; returns the new end. */
static char *up_pool_text(char *p, const char *name, unsigned nr)
{
	unsigned i;

	p += sprintf(p, "upstream %s {\n", name);
	for (i = 0; i < nr; i++)
		p += sprintf(p, "\tserver socks5h://10.0.%u.%u:1080;\n",
			     i / 250, i % 250 + 1);
	p += sprintf(p, "}\n");
	return p;
}

/*
 * A pool's contents as parsed, and what the eval hands out: the pool the
 * last matching rule names, DIRECT, or nothing, with --accept ending the
 * walk, and a pool defined after the rule that names it.
 */
static noinline void test_upstream_pools(void)
{
	static const char text[] =
		"-A OUTPUT -m user --user alice -j UPSTREAM --to pool_a\n"
		"-A OUTPUT -m user --user bob -j UPSTREAM --to-proxy pool-b.2\n"
		"-A OUTPUT -m user --user bob -j UPSTREAM --to pool_a\n"
		"-A OUTPUT -m user --user carol -j UPSTREAM --to pool_a\n"
		"-A OUTPUT -m user --user carol -j UPSTREAM --to DIRECT\n"
		"-A OUTPUT -m user --user dave -j UPSTREAM --to pool-b.2 --accept\n"
		"-A OUTPUT -m user --user dave -j UPSTREAM --to pool_a\n"
		"-A OUTPUT -m user --user dave -j REJECT\n"
		"-A OUTPUT -m user --user erin -j UPSTREAM --to pool_a\n"
		"-A OUTPUT -m user --user erin -j REJECT\n"
		"-A OUTPUT -m user --user frank -j MARK --set-mark 7\n"
		"-A OUTPUT -m user --user frank -j UPSTREAM --to pool_a\n"
		"-A OUTPUT -m user --user frank -j BIND --to-iface lo\n"
		"upstream pool_a {\n"
		"	server socks5h://10.0.0.1:7777;\n"
		"    server http://user:s3cret@10.0.0.3:9999 ;  # a comment\n"
		"	server http://[2001:db8::1]:8080;\n"
		"	server http://proxy.example;\n"
		"}\n"
		"upstream pool-b.2 {\n"
		"	least_conn ;\n"
		"	server socks5://u@[::1]:1;\n"
		"}\n"
		"-P OUTPUT ACCEPT\n";
	struct gwp_acl_pool *p;
	struct gwp_acl_req req;
	struct gwp_acl *a;

	assert(!gwp_acl_parse_str(&a, text));
	assert(!strcmp(up_choice(a, "alice"), "pool_a"));
	assert(!strcmp(up_choice(a, "bob"), "pool_a"));	/* last wins */
	assert(!strcmp(up_choice(a, "carol"), "DIRECT"));
	assert(!strcmp(up_choice(a, "dave"), "pool-b.2"));	/* --accept */
	assert(!strcmp(up_choice(a, "zed"), ""));		/* no rule */

	/* A refused request gets no pool. */
	assert(up_eval(a, "erin", &req) == GWP_ACL_REJECT);
	assert(req.upstream == GWP_ACL_UPSTREAM_NONE && !req.upstream_pool);

	/* Composes with MARK and BIND. */
	assert(up_eval(a, "frank", &req) == GWP_ACL_ACCEPT);
	assert(req.mark_set && req.mark == 7 && req.bind.set);
	assert(req.upstream == GWP_ACL_UPSTREAM_POOL);
	p = req.upstream_pool;
	assert(!strcmp(gwp_acl_pool_name(p), "pool_a"));
	assert(gwp_acl_pool_method(p) == GWP_ACL_POOL_ROUND_ROBIN);
	assert(gwp_acl_pool_remote_dns(p));
	assert(gwp_acl_pool_nr_servers(p) == 4);
	assert(!strcmp(gwp_acl_pool_server_url(p, 0),
		       "socks5h://10.0.0.1:7777"));
	assert(!strcmp(gwp_acl_pool_server_url(p, 1),
		       "http://user:s3cret@10.0.0.3:9999"));
	assert(!strcmp(gwp_acl_pool_server_url(p, 2),
		       "http://[2001:db8::1]:8080"));
	assert(!strcmp(gwp_acl_pool_server_url(p, 3), "http://proxy.example"));
	assert(!gwp_acl_pool_server_url(p, 4));
	/* The cursor counts picks, for every holder of the pool alike. */
	assert(gwp_acl_pool_next(p) == 0);
	assert(gwp_acl_pool_next(p) == 1);
	gwp_acl_req_release(&req);
	assert(up_eval(a, "frank", &req) == GWP_ACL_ACCEPT);
	assert(req.upstream_pool == p);
	assert(gwp_acl_pool_next(req.upstream_pool) == 2);
	gwp_acl_req_release(&req);

	assert(up_eval(a, "dave", &req) == GWP_ACL_ACCEPT);
	p = req.upstream_pool;
	assert(gwp_acl_pool_method(p) == GWP_ACL_POOL_LEAST_CONN);
	assert(!gwp_acl_pool_remote_dns(p));
	assert(gwp_acl_pool_nr_servers(p) == 1);
	assert(!strcmp(gwp_acl_pool_server_url(p, 0), "socks5://u@[::1]:1"));
	gwp_acl_req_release(&req);
	gwp_acl_destroy(a);
}

/*
 * https:// servers load in a pool, alone or with the other remote-DNS
 * schemes, kept as written; the pool resolves names remotely.
 */
static noinline void test_upstream_pool_https(void)
{
	static const char text[] =
		"upstream tls {\n"
		"	server https://u:s3cret@proxy.example:3129;\n"
		"	server https://[2001:db8::2];\n"
		"}\n"
		"upstream mixed {\n"
		"	server http://10.0.0.1:3128;\n"
		"	server https://10.0.0.2:3129;\n"
		"	server socks5h://10.0.0.3:1080;\n"
		"}\n"
		"-A OUTPUT -m user --user alice -j UPSTREAM --to tls\n"
		"-A OUTPUT -m user --user bob -j UPSTREAM --to mixed\n";
	struct gwp_acl_pool *p;
	struct gwp_acl_req req;
	struct gwp_acl *a;

	assert(!gwp_acl_parse_str(&a, text));
	assert(up_eval(a, "alice", &req) == GWP_ACL_ACCEPT);
	assert(req.upstream == GWP_ACL_UPSTREAM_POOL);
	p = req.upstream_pool;
	assert(!strcmp(gwp_acl_pool_name(p), "tls"));
	assert(gwp_acl_pool_remote_dns(p));
	assert(gwp_acl_pool_nr_servers(p) == 2);
	assert(!strcmp(gwp_acl_pool_server_url(p, 0),
		       "https://u:s3cret@proxy.example:3129"));
	assert(!strcmp(gwp_acl_pool_server_url(p, 1), "https://[2001:db8::2]"));
	gwp_acl_req_release(&req);

	assert(up_eval(a, "bob", &req) == GWP_ACL_ACCEPT);
	p = req.upstream_pool;
	assert(!strcmp(gwp_acl_pool_name(p), "mixed"));
	assert(gwp_acl_pool_remote_dns(p));
	assert(gwp_acl_pool_nr_servers(p) == 3);
	assert(!strcmp(gwp_acl_pool_server_url(p, 1), "https://10.0.0.2:3129"));
	gwp_acl_req_release(&req);
	gwp_acl_destroy(a);
}

/*
 * An UPSTREAM rule with --accept is answered by the run index when there
 * are enough such rules in a row; the result is the same. (Run once: its -d
 * draws a warning.)
 */
static noinline void test_upstream_index(void)
{
	struct gwp_acl *a;

	assert(!gwp_acl_parse_str(&a,
		"upstream p { \n server socks5://10.0.0.1:1;\n}\n"
		"-A OUTPUT -d 198.51.100.1 -j REJECT\n"
		"-A OUTPUT -d 198.51.100.2 -j REJECT\n"
		"-A OUTPUT -d 198.51.100.3 -j REJECT\n"
		"-A OUTPUT -d 198.51.100.4 -j REJECT\n"
		"-A OUTPUT -d 198.51.100.5 -j REJECT\n"
		"-A OUTPUT -d 198.51.100.6 -j REJECT\n"
		"-A OUTPUT -d 198.51.100.7 -j REJECT\n"
		"-A OUTPUT -d 192.0.2.1 -j UPSTREAM --to p --accept\n"
		"-A OUTPUT -j REJECT\n"));
	assert(gwp_acl_nr_indexed(a) == 8);
	assert(!strcmp(up_choice(a, NULL), "p"));
	gwp_acl_destroy(a);
}

/*
 * The pool an evaluation handed out stays valid after the ruleset that
 * defined it is gone: a reload, and then the ACL itself. Under the
 * sanitizers a use after free shows here.
 */
static noinline void test_upstream_pool_outlives_reload(void)
{
	char *dir = inc_dir(), *path;
	struct gwp_acl_req req;
	struct gwp_acl *a;

	path = inc_write(dir, "main.acl",
			 "upstream old {\n server http://10.0.0.1:3128;\n}\n"
			 "-A OUTPUT -j UPSTREAM --to old\n");
	assert(!gwp_acl_create(&a, path));
	assert(up_eval(a, NULL, &req) == GWP_ACL_ACCEPT);
	assert(req.upstream == GWP_ACL_UPSTREAM_POOL);

	inc_put(dir, "main.acl",
		"upstream new {\n server http://10.0.0.2:3128;\n}\n"
		"-A OUTPUT -j UPSTREAM --to new\n");
	assert(!gwp_acl_reload(a));
	assert(!strcmp(up_choice(a, NULL), "new"));
	/* The old ruleset is freed; its pool is not. */
	assert(!strcmp(gwp_acl_pool_name(req.upstream_pool), "old"));
	assert(!strcmp(gwp_acl_pool_server_url(req.upstream_pool, 0),
		       "http://10.0.0.1:3128"));

	/* A failed reload keeps the pools in force. */
	inc_put(dir, "main.acl",
		"upstream new {\n server http://10.0.0.2:3128;\n"
		"-A OUTPUT -j UPSTREAM --to new\n");
	assert(gwp_acl_reload(a) == -EINVAL);
	assert(!strcmp(up_choice(a, NULL), "new"));

	gwp_acl_destroy(a);
	assert(!strcmp(gwp_acl_pool_name(req.upstream_pool), "old"));
	gwp_acl_req_release(&req);
	free(path);
	inc_rmdir(dir);
}

/*
 * Pools and rules spread over the files of a set: a pool defined in an
 * included file, used before and after the include, and one used in an
 * included file but defined in the top one. A name is one pool in the whole
 * set, and a block must end in the file that opened it.
 */
static noinline void test_upstream_include(void)
{
	char *dir = inc_dir(), *path, *said;
	struct gwp_acl *a = NULL;
	int r;

	inc_put(dir, "pools.acl",
		"upstream inc {\n server socks5h://10.0.0.1:1080;\n}\n"
		"-A OUTPUT -m user --user b -j UPSTREAM --to top\n");
	path = inc_write(dir, "main.acl",
			 "-A OUTPUT -m user --user a -j UPSTREAM --to inc\n"
			 "include pools.acl;\n"
			 "-A OUTPUT -m user --user c -j UPSTREAM --to inc\n"
			 "upstream top {\n server http://10.0.0.2:1;\n}\n");
	assert(!gwp_acl_create(&a, path));
	assert(!strcmp(up_choice(a, "a"), "inc"));
	assert(!strcmp(up_choice(a, "b"), "top"));
	assert(!strcmp(up_choice(a, "c"), "inc"));
	gwp_acl_destroy(a);
	a = NULL;

	/* The same name in two files of the set. */
	inc_put(dir, "main.acl",
		"upstream inc {\n server http://10.0.0.2:1;\n}\n"
		"include pools.acl;\n");
	up_capture();
	r = gwp_acl_create(&a, path);
	said = up_captured();
	up_check(r, -EINVAL, said);
	assert(strstr(said, "pools.acl: line 1: upstream pool inc is defined twice"));
	assert(strstr(said, "main.acl: line 4: failed to include a file"));
	free(said);

	/* An undefined pool is named with the file and line that use it. */
	inc_put(dir, "main.acl", "include pools.acl;\n");
	up_capture();
	r = gwp_acl_create(&a, path);
	said = up_captured();
	up_check(r, -EINVAL, said);
	assert(strstr(said, "pools.acl: line 4: upstream pool top is not defined"));
	free(said);

	/* A block may not span an include, nor run past its file's end. */
	inc_put(dir, "open.acl", "upstream o {\n server http://10.0.0.2:1;\n");
	inc_put(dir, "main.acl",
		"include open.acl;\n}\n-A OUTPUT -j UPSTREAM --to o\n");
	up_capture();
	r = gwp_acl_create(&a, path);
	said = up_captured();
	up_check(r, -EINVAL, said);
	assert(strstr(said, "open.acl: line 1: upstream pool o is not closed"));
	free(said);
	inc_put(dir, "main.acl",
		"upstream o {\n server http://10.0.0.2:1;\n"
		"include pools.acl;\n}\n");
	up_capture();
	r = gwp_acl_create(&a, path);
	said = up_captured();
	up_check(r, -EINVAL, said);
	assert(strstr(said, "main.acl: line 3: include is not allowed inside an upstream block"));
	free(said);
	assert(!a);

	free(path);
	inc_rmdir(dir);
}

/*
 * A file that holds a password in a server URL is reported when others may
 * read it, once per load, and never with the password.
 */
static noinline void test_upstream_creds_warning(void)
{
	static const char warn[] = "readable by group or others";
	char *dir = inc_dir(), *path, *inc_path, *said, *p;
	struct gwp_acl *a;
	int r;

	inc_path = inc_write(dir, "creds.acl",
			     "upstream c {\n server http://u:s3cret@10.0.0.1:1;\n}\n");
	path = inc_write(dir, "main.acl",
			 "include creds.acl;\n-A OUTPUT -j UPSTREAM --to c\n"
			 "include none.acl;\n");
	inc_put(dir, "none.acl", "upstream n {\n server http://10.0.0.1:1;\n}\n");

	/* 0600 everywhere: nothing to say. */
	up_capture();
	r = gwp_acl_create(&a, path);
	said = up_captured();
	up_check(r, 0, said);
	assert(!strstr(said, warn));
	free(said);

	/* Readable by others: warned once per load, reload included. */
	assert(!chmod(inc_path, 0644));
	assert(!chmod(path, 0640));
	up_capture();
	r = gwp_acl_reload(a);
	said = up_captured();
	up_check(r, 0, said);
	p = strstr(said, warn);
	assert(p && !strstr(p + 1, warn));
	assert(strstr(said, "creds.acl: warning: holds upstream credentials"));
	assert(!strstr(said, "main.acl: warning"));
	assert(!strstr(said, "s3cret"));
	free(said);

	/*
	 * A file without credentials: never. (A file with them cannot be
	 * included twice: its pools would be defined twice.)
	 */
	assert(!chmod(path, 0644));
	assert(!chmod(dir, 0755));
	up_capture();
	r = gwp_acl_reload(a);
	said = up_captured();
	up_check(r, 0, said);
	assert(!strstr(said, "none.acl"));
	free(said);

	/* Group-readable alone counts too. */
	assert(!chmod(inc_path, 0640));
	up_capture();
	r = gwp_acl_reload(a);
	said = up_captured();
	up_check(r, 0, said);
	assert(strstr(said, warn));
	free(said);

	gwp_acl_destroy(a);
	free(inc_path);
	free(path);
	inc_rmdir(dir);
}

/* The URL a message may show: the credentials, and only they, left out. */
static noinline void test_upstream_url_redact(void)
{
	static const struct {
		const char *in, *out;
	} cases[] = {
		{ "http://user:s3cret@10.0.0.1:80", "http://10.0.0.1:80" },
		{ "socks5h://user@host:1", "socks5h://host:1" },
		{ "socks5://u:p@ss@[::1]:9", "socks5://[::1]:9" },
		{ "https://a:b://c@h", "https://h" },
		{ "http://10.0.0.1", "http://10.0.0.1" },
		{ "bogus:s3cret@h", "h" },
		{ "", "" },
		/* Malformed: nothing up to the last '@' but a scheme stays. */
		{ "u:s3cret@h://x", "h://x" },
		{ "u:s3cret@h", "h" },
		{ "http://u:s3cret@", "http://" },
		{ "@", "" },
		{ "u:s3cret://h@x", "x" },
		{ "u:s3cret@x://y@z", "z" },
		{ "://u:s3cret@h", "://h" },
		{ "a b://u:s3cret@h", "h" },
		{ "http:/u:s3cret@h", "h" },
		{ "http://h:1", "http://h:1" },
	};
	char buf[64];
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		assert(!gwp_acl_url_redact(cases[i].in, buf, sizeof(buf)));
		assert(!strcmp(buf, cases[i].out));
	}
	/* Too long: cut short, still without the credentials. */
	assert(gwp_acl_url_redact("http://u:s3cret@abcdefgh:1", buf, 10) ==
	       -ENAMETOOLONG);
	assert(!strcmp(buf, "http://ab"));
	assert(gwp_acl_url_redact("http://h", NULL, 0) == -ENAMETOOLONG);
}

/*
 * The pool reference moves out of a request: the request then holds none,
 * so releasing it (or a copy made afterwards) drops nothing more, and the
 * choice itself is still there to read.
 */
static noinline void test_upstream_take_pool(void)
{
	struct gwp_acl_req req, copy;
	struct gwp_acl_pool *p;
	struct gwp_acl *a;

	assert(!gwp_acl_parse_str(&a,
		"upstream t {\n server http://10.0.0.1:1;\n}\n"
		"-A OUTPUT -j UPSTREAM --to t\n"));
	assert(up_eval(a, NULL, &req) == GWP_ACL_ACCEPT);
	p = gwp_acl_req_take_pool(&req);
	assert(p && !req.upstream_pool);
	assert(req.upstream == GWP_ACL_UPSTREAM_POOL);
	copy = req;
	gwp_acl_req_release(&req);
	gwp_acl_req_release(&copy);
	assert(!gwp_acl_req_take_pool(&req));
	/* The ACL goes; the reference taken over keeps the pool. */
	gwp_acl_destroy(a);
	assert(!strcmp(gwp_acl_pool_name(p), "t"));
	gwp_acl_pool_put(p);
}

/*
 * Readers keep evaluating OUTPUT and holding on to the pools they are handed,
 * a few at a time, while the main thread reloads the set with a new pool each
 * time. Every pool a reader holds must still be whole, however many reloads
 * ago its ruleset went; the sanitizers catch a pool freed too early, or
 * never.
 */
#define UP_READERS	4
#define UP_HELD		8

struct up_reader {
	struct gwp_acl	*acl;
	atomic_bool	*stop;
	unsigned long	nr_pools;
};

/* Pool "gN" has one server, http://10.0.0.1:N. */
static void up_check_pool(const struct gwp_acl_pool *p)
{
	const char *name = gwp_acl_pool_name(p), *url;
	char want[64];

	assert(name[0] == 'g');
	assert(gwp_acl_pool_nr_servers(p) == 1);
	url = gwp_acl_pool_server_url(p, 0);
	snprintf(want, sizeof(want), "http://10.0.0.1:%s", name + 1);
	assert(!strcmp(url, want));
}

static void *up_reader_fn(void *arg)
{
	struct up_reader *ur = arg;
	struct gwp_acl_pool *held[UP_HELD] = { NULL };
	struct gwp_sockaddr t = sa4("192.0.2.1", 80);
	unsigned n = 0, i;

	while (!atomic_load_explicit(ur->stop, memory_order_relaxed)) {
		struct gwp_acl_req req = {
			.target = &t, .dport = 80, .proto = GWP_ACL_PROTO_TCP,
		};

		assert(gwp_acl_eval_output(ur->acl, &req) == GWP_ACL_ACCEPT);
		assert(req.upstream == GWP_ACL_UPSTREAM_POOL);
		up_check_pool(req.upstream_pool);
		gwp_acl_pool_put(held[n % UP_HELD]);
		held[n % UP_HELD] = gwp_acl_req_take_pool(&req);
		n++;
		for (i = 0; i < UP_HELD; i++)
			if (held[i])
				up_check_pool(held[i]);
	}
	for (i = 0; i < UP_HELD; i++)
		gwp_acl_pool_put(held[i]);
	ur->nr_pools = n;
	return NULL;
}

static void up_write_gen(const char *path, unsigned gen)
{
	char text[160];
	int fd, len;

	len = snprintf(text, sizeof(text),
		       "upstream g%u {\n server http://10.0.0.1:%u;\n}\n"
		       "-A OUTPUT -j UPSTREAM --to g%u\n", gen, gen, gen);
	fd = open(path, O_WRONLY | O_TRUNC);
	assert(fd >= 0);
	assert(write(fd, text, (size_t)len) == len);
	close(fd);
}

static noinline void test_upstream_reload_readers(void)
{
	struct up_reader ur[UP_READERS];
	pthread_t thr[UP_READERS];
	atomic_bool stop = false;
	struct gwp_acl *a;
	unsigned gen;
	char *path;
	size_t i;

	path = write_tmp_rules("# empty for now\n");
	up_write_gen(path, 1);
	assert(!gwp_acl_create(&a, path));
	for (i = 0; i < UP_READERS; i++) {
		ur[i].acl = a;
		ur[i].stop = &stop;
		ur[i].nr_pools = 0;
		assert(!pthread_create(&thr[i], NULL, up_reader_fn, &ur[i]));
	}
	for (gen = 2; gen <= 300; gen++) {
		up_write_gen(path, gen);
		assert(!gwp_acl_reload(a));
	}
	atomic_store(&stop, true);
	for (i = 0; i < UP_READERS; i++) {
		pthread_join(thr[i], NULL);
		assert(ur[i].nr_pools > 0);
	}
	assert(!strcmp(up_choice(a, NULL), "g300"));
	gwp_acl_destroy(a);
	unlink(path);
	free(path);
}

/*
 * Pool servers made at load (struct gwp_acl_server_ops): a stand-in for the
 * server objects gwproxy makes, counting how many are alive, so a test can
 * tell that every one made is dropped again, and none too early.
 */
struct up_srv {
	atomic_uint	ref;
	char		url[128];
};

static atomic_int g_up_live;
static int g_up_made;

static int up_srv_make(void *arg, const char *url, void **out, char *why,
		       size_t size)
{
	struct up_srv *s;

	assert(arg == &g_up_live);
	if (strstr(url, "unresolvable")) {
		snprintf(why, size, "the host does not resolve");
		return -EINVAL;
	}
	if (strstr(url, "nowhy"))
		return -EAFNOSUPPORT;
	s = calloc(1, sizeof(*s));
	assert(s);
	atomic_init(&s->ref, 1);
	snprintf(s->url, sizeof(s->url), "%s", url);
	atomic_fetch_add(&g_up_live, 1);
	g_up_made++;
	*out = s;
	return 0;
}

static void up_srv_put(void *arg, void *srv)
{
	struct up_srv *s = srv;

	assert(arg == &g_up_live);
	assert(atomic_load(&s->ref) > 0);
	if (atomic_fetch_sub(&s->ref, 1) != 1)
		return;
	memset(s->url, 'x', sizeof(s->url));
	free(s);
	assert(atomic_fetch_sub(&g_up_live, 1) > 0);
}

/* A pick handle: something the object holds while it lives. */
static void *up_srv_handle(void *arg, void *srv)
{
	struct up_srv *s = srv;

	assert(arg == &g_up_live);
	return s->url;
}

static const struct gwp_acl_server_ops up_srv_ops = {
	.make	= up_srv_make,
	.put	= up_srv_put,
	.handle	= up_srv_handle,
	.arg	= &g_up_live,
};

/*
 * The server object @p's @i-th URL was made into, checked against it, and
 * its pick handle with it.
 */
static struct up_srv *up_srv_of(const struct gwp_acl_pool *p, uint32_t i)
{
	struct up_srv *s = gwp_acl_pool_server(p, i);
	void *const *h = gwp_acl_pool_handles(p);

	assert(s && !strcmp(s->url, gwp_acl_pool_server_url(p, i)));
	assert(h && h[i] == s->url);
	return s;
}

/*
 * Every pool server is made when the set loads, and kept with its pool: a
 * server a connection took a reference to outlives the pool, the reload that
 * dropped it and the ACL. A server that cannot be made fails the load (or
 * the reload, keeping the servers in force) with its file and line, and the
 * servers made before it are dropped.
 */
static noinline void test_upstream_server_ops(void)
{
	char *dir = inc_dir(), *path, *said;
	struct gwp_acl_req req;
	struct up_srv *held;
	struct gwp_acl *a;
	int r;

	g_up_made = 0;
	path = inc_write(dir, "main.acl",
			 "upstream p {\n"
			 " server http://u:s3cret@10.0.0.1:3128;\n"
			 " server http://10.0.0.2:3128;\n"
			 "}\n"
			 "upstream q {\n server socks5://10.0.0.3:1080;\n}\n"
			 "-A OUTPUT -j UPSTREAM --to p\n");
	assert(!gwp_acl_create_ops(&a, path, &up_srv_ops));
	assert(g_up_made == 3 && atomic_load(&g_up_live) == 3);
	assert(up_eval(a, NULL, &req) == GWP_ACL_ACCEPT);
	assert(req.upstream == GWP_ACL_UPSTREAM_POOL);
	assert(up_srv_of(req.upstream_pool, 0) != up_srv_of(req.upstream_pool, 1));
	assert(!gwp_acl_pool_server(req.upstream_pool, 2));
	/* What a connection does: keep the server, not the pool. */
	held = up_srv_of(req.upstream_pool, 1);
	atomic_fetch_add(&held->ref, 1);
	gwp_acl_req_release(&req);

	/* A reload makes the new set's servers and drops the old ones'. */
	inc_put(dir, "main.acl",
		"upstream p {\n server http://10.0.0.4:3128;\n}\n"
		"-A OUTPUT -j UPSTREAM --to p\n");
	assert(!gwp_acl_reload(a));
	assert(g_up_made == 4 && atomic_load(&g_up_live) == 2);
	assert(!strcmp(held->url, "http://10.0.0.2:3128"));

	/* A server that cannot be made fails the reload; the rest go too. */
	inc_put(dir, "main.acl",
		"upstream p {\n"
		" server http://10.0.0.5:3128;\n"
		" server http://u:s3cret@unresolvable.invalid:3128;\n"
		"}\n");
	up_capture();
	r = gwp_acl_reload(a);
	said = up_captured();
	up_check(r, -EINVAL, said);
	assert(strstr(said, "main.acl: line 3: upstream pool p server 2 (http://unresolvable.invalid:3128): the host does not resolve"));
	assert(!strstr(said, "s3cret"));
	free(said);
	assert(g_up_made == 5 && atomic_load(&g_up_live) == 2);
	assert(up_eval(a, NULL, &req) == GWP_ACL_ACCEPT);
	assert(!strcmp(up_srv_of(req.upstream_pool, 0)->url,
		       "http://10.0.0.4:3128"));
	gwp_acl_req_release(&req);

	/* With no reason given, the errno says why. */
	inc_put(dir, "main.acl", "upstream p {\n server http://nowhy:1;\n}\n");
	up_capture();
	r = gwp_acl_reload(a);
	said = up_captured();
	up_check(r, -EINVAL, said);
	assert(strstr(said, "main.acl: line 2: upstream pool p server 1 (http://nowhy:1): "));
	assert(strstr(said, strerror(EAFNOSUPPORT)));
	free(said);

	/* The ACL goes; the server a connection holds stays. */
	gwp_acl_destroy(a);
	assert(atomic_load(&g_up_live) == 1);
	assert(!strcmp(held->url, "http://10.0.0.2:3128"));
	up_srv_put(&g_up_live, held);
	assert(atomic_load(&g_up_live) == 0);

	/* Without ops, a pool has its URLs and no server objects. */
	inc_put(dir, "main.acl", "upstream p {\n server http://10.0.0.1:1;\n}\n"
				 "-A OUTPUT -j UPSTREAM --to p\n");
	assert(!gwp_acl_create(&a, path));
	assert(up_eval(a, NULL, &req) == GWP_ACL_ACCEPT);
	assert(gwp_acl_pool_server_url(req.upstream_pool, 0));
	assert(!gwp_acl_pool_server(req.upstream_pool, 0));
	assert(!gwp_acl_pool_handles(req.upstream_pool));
	gwp_acl_req_release(&req);
	gwp_acl_destroy(a);
	assert(g_up_made == 5);

	free(path);
	inc_rmdir(dir);
}

/*
 * gwp_acl_eval_upstream() for @user to @domain or the address @ip (one of
 * them NULL), port 443: the pool name, "DIRECT" or "".
 */
static const char *up_pick(struct gwp_acl *a, const char *user,
			   const char *domain, const char *ip)
{
	static char name[80];
	struct gwp_sockaddr t;
	struct gwp_acl_req req;
	enum gwp_acl_upstream u;

	memset(&req, 0, sizeof(req));
	if (ip) {
		t = sa4(ip, 443);
		req.target = &t;
	}
	req.domain = domain;
	req.user = user;
	req.dport = 443;
	req.proto = GWP_ACL_PROTO_TCP;
	u = gwp_acl_eval_upstream(a, &req);
	assert(u == req.upstream && !req.upstream_only);
	if (u == GWP_ACL_UPSTREAM_POOL)
		snprintf(name, sizeof(name), "%s",
			 gwp_acl_pool_name(req.upstream_pool));
	else
		snprintf(name, sizeof(name), "%s",
			 u == GWP_ACL_UPSTREAM_DIRECT ? "DIRECT" :
			 u == GWP_ACL_UPSTREAM_UNSURE ? "UNSURE" : "");
	if (u != GWP_ACL_UPSTREAM_POOL)
		assert(!req.upstream_pool);
	gwp_acl_req_release(&req);
	return name;
}

/*
 * The upstream is picked from what is known before the name is resolved:
 * the user, a domain or a literal address. A -d rule matches the address
 * only. The pick does not take a -m statistic turn from the evaluations
 * that follow it, and with no -j UPSTREAM rule at all there is no pick.
 */
static noinline void test_upstream_pick(void)
{
	struct gwp_sockaddr t = sa4("192.0.2.1", 443);
	struct gwp_acl *a = NULL;
	int i;

	assert(!gwp_acl_parse_str(&a,
		"upstream a {\n server socks5h://10.0.0.1:1080;\n}\n"
		"upstream b {\n server socks5://10.0.0.2:1080;\n}\n"
		"-A OUTPUT -m user --user alice -j UPSTREAM --to a\n"
		"-A OUTPUT -m domain --domain example.org -j UPSTREAM --to b\n"
		"-A OUTPUT -d 198.51.100.0/24 -j UPSTREAM --to DIRECT\n"
		"-A OUTPUT -d 203.0.113.0/24 -j REJECT\n"
		"-P OUTPUT ACCEPT\n"));
	assert(!strcmp(up_pick(a, "alice", "example.net", NULL), "a"));
	assert(!strcmp(up_pick(a, "alice", "example.org", NULL), "b"));
	assert(!strcmp(up_pick(a, "bob", "example.net", NULL), ""));
	assert(!strcmp(up_pick(a, NULL, NULL, "198.51.100.7"), "DIRECT"));
	assert(!strcmp(up_pick(a, "alice", NULL, "198.51.100.7"), "DIRECT"));
	/* A name is not an address, whatever it resolves to later. */
	assert(!strcmp(up_pick(a, NULL, "198.51.100.7.nip.example", NULL), ""));
	/* The pick's REJECT is not the request's: the pool stays. */
	assert(!strcmp(up_pick(a, "alice", NULL, "203.0.113.1"), "a"));
	gwp_acl_destroy(a);

	/*
	 * A default-deny set that lets targets through by -d: a name meets
	 * no -d rule and the walk ends on the policy, yet the request keeps
	 * its pool; the evaluations per address then say ACCEPT.
	 */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"upstream a {\n server socks5://10.0.0.1:1080;\n}\n"
		"-A OUTPUT -m user --user alice -j UPSTREAM --to a\n"
		"-A OUTPUT -d 192.0.2.0/24 -j ACCEPT\n"
		"-P OUTPUT REJECT\n"));
	assert(!strcmp(up_pick(a, "alice", "example.net", NULL), "a"));
	assert(!strcmp(up_pick(a, "alice", NULL, "192.0.2.1"), "a"));
	assert(!strcmp(up_pick(a, "bob", "example.net", NULL), ""));
	gwp_acl_destroy(a);

	/* An nth split of the upstream: the pick says what eval will. */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"upstream a {\n server socks5h://10.0.0.1:1080;\n}\n"
		"-A OUTPUT -m statistic --mode nth --every 2 -j UPSTREAM --to a\n"
		"-A OUTPUT -m statistic --mode nth --every 3 -j REJECT\n"
		"-P OUTPUT ACCEPT\n"));
	for (i = 0; i < 30; i++) {
		struct gwp_acl_req req = {
			.target = &t, .dport = 443, .proto = GWP_ACL_PROTO_TCP,
		};
		const char *want = i % 2 ? "" : "a";
		enum gwp_acl_verdict v;

		assert(!strcmp(up_pick(a, NULL, NULL, "192.0.2.1"), want));
		assert(!strcmp(up_pick(a, NULL, NULL, "192.0.2.1"), want));
		v = gwp_acl_eval_output(a, &req);
		assert((v == GWP_ACL_REJECT) == (i % 3 == 0));
		if (v == GWP_ACL_ACCEPT)
			assert((req.upstream == GWP_ACL_UPSTREAM_POOL) ==
			       !(i % 2));
		gwp_acl_req_release(&req);
	}
	gwp_acl_destroy(a);

	/* No -j UPSTREAM rule: nothing to pick, no statistic turn taken. */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"-A OUTPUT -m statistic --mode nth --every 2 -j REJECT\n"
		"-P OUTPUT ACCEPT\n"));
	for (i = 0; i < 10; i++) {
		assert(!strcmp(up_pick(a, NULL, NULL, "192.0.2.1"), ""));
		assert(out(a, &t, NULL, 443, GWP_ACL_PROTO_TCP) ==
		       (i % 2 ? GWP_ACL_ACCEPT : GWP_ACL_REJECT));
	}
	gwp_acl_destroy(a);
	assert(!strcmp(up_pick(NULL, "alice", NULL, "192.0.2.1"), ""));
}

/* gwp_acl_eval_upstream() for @user with no target at all (UDP ASSOCIATE). */
static const char *up_pick_nt(struct gwp_acl *a, const char *user)
{
	struct gwp_sockaddr c = sa4("198.51.100.9", 40000);
	struct gwp_acl_req req;
	enum gwp_acl_upstream u;
	const char *name;

	memset(&req, 0, sizeof(req));
	req.client = &c;
	req.sport = 40000;
	req.user = user;
	req.no_target = true;
	req.proto = GWP_ACL_PROTO_TCP;
	u = gwp_acl_eval_upstream(a, &req);
	if (u == GWP_ACL_UPSTREAM_POOL)
		name = gwp_acl_pool_name(req.upstream_pool);
	else
		name = u == GWP_ACL_UPSTREAM_DIRECT ? "DIRECT" :
		       u == GWP_ACL_UPSTREAM_UNSURE ? "UNSURE" : "";
	if (u != GWP_ACL_UPSTREAM_POOL)
		assert(!req.upstream_pool);
	gwp_acl_req_release(&req);
	return name;
}

/*
 * A pick with no target at all: no rule that tests the target matches, in
 * either polarity, and a pool rule passed over only for that leaves the
 * pick unsure, while a DIRECT one is just passed over. A request to an
 * address keeps "! --domain" matching, as it has no name.
 */
static noinline void test_upstream_pick_no_target(void)
{
	struct gwp_acl *a = NULL;

	assert(!gwp_acl_parse_str(&a,
		"upstream s5 {\n server socks5://10.0.0.1:1080;\n}\n"
		"-A OUTPUT -m user --user alice -m domain ! --domain secret.example -j UPSTREAM --to DIRECT\n"
		"-A OUTPUT -m user --user bob -m domain --domain secret.example -j UPSTREAM --to s5\n"
		"-A OUTPUT -m user --user carol ! -d 10.0.0.0/8 -j UPSTREAM --to DIRECT\n"
		"-A OUTPUT -m user --user dave -j UPSTREAM --to s5\n"
		"-A OUTPUT -m user --user erin --dports 80 -j UPSTREAM --to s5\n"
		"-A OUTPUT -m user --user frank -s 192.0.2.0/24 -d 10.0.0.1 -j UPSTREAM --to s5\n"
		"-A OUTPUT -m user --user gina -j UPSTREAM --to s5\n"
		"-A OUTPUT -m user --user gina ! -d 10.0.0.0/8 -j UPSTREAM --to DIRECT\n"
		"-P OUTPUT ACCEPT\n"));
	assert(!strcmp(up_pick_nt(a, "alice"), ""));
	assert(!strcmp(up_pick_nt(a, "bob"), "UNSURE"));
	assert(!strcmp(up_pick_nt(a, "carol"), ""));
	assert(!strcmp(up_pick_nt(a, "dave"), "s5"));
	assert(!strcmp(up_pick_nt(a, "erin"), "UNSURE"));
	/* Its other criteria fail: the rule says nothing about this one. */
	assert(!strcmp(up_pick_nt(a, "frank"), ""));
	assert(!strcmp(up_pick_nt(a, "gina"), "s5"));
	assert(!strcmp(up_pick_nt(a, NULL), ""));

	/* With a target, the same rules decide as ever. */
	assert(!strcmp(up_pick(a, "alice", NULL, "192.0.2.1"), "DIRECT"));
	assert(!strcmp(up_pick(a, "alice", "secret.example", NULL), ""));
	assert(!strcmp(up_pick(a, "bob", "secret.example", NULL), "s5"));
	assert(!strcmp(up_pick(a, "carol", NULL, "192.0.2.1"), "DIRECT"));
	assert(!strcmp(up_pick(a, "erin", "example.org", NULL), ""));
	gwp_acl_destroy(a);

	/*
	 * A run of pool rules long enough for the index, by name and by
	 * address: with no target the index is not asked, the run is walked,
	 * and its rules leave the pick unsure. A target still finds its rule.
	 */
	{
		char text[4096], *p = text;
		int i;

		p += sprintf(p, "upstream s5 {\n server socks5://10.0.0.1:1080;\n}\n");
		for (i = 1; i <= 8; i++)
			p += sprintf(p, "-A OUTPUT -m domain --domain h%d.example -j UPSTREAM --to s5 --accept\n", i);
		a = NULL;
		assert(!gwp_acl_parse_str(&a, text));
		assert(gwp_acl_nr_indexed(a) == 8);
		assert(!strcmp(up_pick_nt(a, "bob"), "UNSURE"));
		assert(!strcmp(up_pick(a, "bob", "h5.example", NULL), "s5"));
		assert(!strcmp(up_pick(a, "bob", "other.example", NULL), ""));
		gwp_acl_destroy(a);

		p = text;
		p += sprintf(p, "upstream s5 {\n server socks5://10.0.0.1:1080;\n}\n");
		for (i = 1; i <= 8; i++)
			p += sprintf(p, "-A OUTPUT -d 10.0.%d.0/24 -j UPSTREAM --to s5 --accept\n", i);
		a = NULL;
		assert(!gwp_acl_parse_str(&a, text));
		assert(gwp_acl_nr_indexed(a) == 8);
		assert(!strcmp(up_pick_nt(a, "bob"), "UNSURE"));
		assert(!strcmp(up_pick(a, "bob", NULL, "10.0.3.7"), "s5"));
		assert(!strcmp(up_pick(a, "bob", NULL, "10.9.3.7"), ""));
		gwp_acl_destroy(a);
	}

	/* A statistic does not decide it: whether it matches is not known. */
	a = NULL;
	assert(!gwp_acl_parse_str(&a,
		"upstream s5 {\n server socks5://10.0.0.1:1080;\n}\n"
		"-A OUTPUT -m statistic --mode nth --every 1000 --packet 999 --dports 80 -j UPSTREAM --to s5\n"));
	assert(!strcmp(up_pick_nt(a, "bob"), "UNSURE"));
	gwp_acl_destroy(a);
}

/* A -j UPSTREAM rule only UDP matches could never apply: refused. */
static noinline void test_upstream_udp_refused(void)
{
	static const char pool[] = "upstream s5 {\n server socks5://10.0.0.1:1080;\n}\n";
	static const char *const rules[] = {
		"-A OUTPUT -p udp -j UPSTREAM --to s5\n",
		"-A OUTPUT ! -p tcp -m user --user bob -j UPSTREAM --to s5\n",
		"-A OUTPUT -p udp -j UPSTREAM --to DIRECT --accept\n",
	};
	char text[512];
	struct gwp_acl *a = NULL;
	size_t i;

	for (i = 0; i < sizeof(rules) / sizeof(rules[0]); i++) {
		snprintf(text, sizeof(text), "%s%s", pool, rules[i]);
		up_refused(text, -EINVAL, "line 4: -j UPSTREAM applies to TCP; UDP never goes through an upstream");
	}
	snprintf(text, sizeof(text), "%s%s%s", pool,
		 "-A OUTPUT -p tcp -j UPSTREAM --to s5\n",
		 "-A OUTPUT ! -p udp -j UPSTREAM --to DIRECT\n");
	assert(!gwp_acl_parse_str(&a, text));
	gwp_acl_destroy(a);
}

/*
 * A regexp the pick cannot decide (the match limit) leaves it unsure: it
 * may have missed a pool, so it must not fall back on the default.
 */
static noinline void test_upstream_pick_regexp_error(void)
{
#ifdef CONFIG_PCRE
	struct gwp_acl *a = NULL;
	char host[64];

	memset(host, 'a', 30);
	strcpy(host + 30, "!internal.example");
	assert(!gwp_acl_parse_str(&a,
		"upstream s5 {\n server socks5://10.0.0.1:1080;\n}\n"
		"-A OUTPUT -m domain --domain-regexp (\\w+\\.?)+internal\\.example$ -j UPSTREAM --to s5\n"
		"-P OUTPUT ACCEPT\n"));
	assert(!strcmp(up_pick(a, NULL, host, NULL), "UNSURE"));
	assert(!strcmp(up_pick(a, NULL, "a.internal.example", NULL), "s5"));
	assert(!strcmp(up_pick(a, NULL, "other.org", NULL), ""));
	gwp_acl_destroy(a);
#endif
}

/* Every way the pool syntax and -j UPSTREAM can be wrong, one at a time. */
static noinline void test_upstream_errors(void)
{
	static const char srv[] = " server http://10.0.0.1:1;\n";
	char name[80], *text, *p;
	struct gwp_acl_req req;
	struct gwp_acl *a;
	int i;

	/* The block's opening line. */
	up_refused("upstream p\n", -EINVAL, "line 1: expected \"upstream NAME {\"");
	up_refused("upstream p{\n}\n", -EINVAL, "expected \"upstream NAME {\"");
	up_refused("upstream p { server http://h;\n}\n", -EINVAL,
		   "expected \"upstream NAME {\"");
	up_refused("upstream {\n}\n", -EINVAL, "expected \"upstream NAME {\"");

	/* The name. */
	up_refused("upstream p/q {\n server http://h;\n}\n", -EINVAL,
		   "bad upstream pool name");
	memset(name, 'n', 65);
	name[65] = '\0';
	assert(asprintf(&text, "upstream %s {\n%s}\n", name, srv) > 0);
	up_refused(text, -EINVAL, "bad upstream pool name");
	free(text);
	name[64] = '\0';
	assert(asprintf(&text, "upstream %s {\n%s}\n"
			"-A OUTPUT -j UPSTREAM --to %s\n", name, srv, name) > 0);
	assert(!gwp_acl_parse_str(&a, text));
	assert(!strcmp(up_choice(a, NULL), name));
	gwp_acl_destroy(a);
	free(text);
	up_refused("upstream DIRECT {\n server http://h;\n}\n", -EINVAL,
		   "the upstream pool name DIRECT is reserved");
	up_refused("upstream p {\n server http://h;\n}\n"
		   "upstream p {\n server http://h;\n}\n", -EINVAL,
		   "line 4: upstream pool p is defined twice");

	/* The block's contents and end. */
	up_refused("upstream p {\n}\n", -EINVAL,
		   "line 2: upstream pool p has no server");
	up_refused("upstream p {\n server http://h;\n} x\n", -EINVAL,
		   "\"}\" must stand alone on its line");
	up_refused("upstream p {\n server http://h;\n least_conn;\n"
		   " least_conn;\n}\n", -EINVAL,
		   "line 4: least_conn given twice");
	up_refused("upstream p {\n server http://h;\n least_conn x;\n}\n",
		   -EINVAL, "expected \"least_conn;\"");
	up_refused("upstream p {\n server http://h\n}\n", -EINVAL,
		   "line 2: missing ';' at the end of the directive");
	up_refused("upstream p {\n least_conn\n}\n", -EINVAL,
		   "missing ';' at the end of the directive");
	up_refused("upstream p {\n server;\n}\n", -EINVAL,
		   "expected \"server URL;\"");
	up_refused("upstream p {\n server http://a; server http://b;\n}\n",
		   -EINVAL, "expected \"server URL;\"");
	up_refused("upstream p {\n weight 3;\n}\n", -EINVAL,
		   "unknown directive in upstream pool p");
	/* A URL without "server": refused without being quoted. */
	up_refused("upstream p {\n http://u:s3cret@h;\n}\n", -EINVAL,
		   "unknown directive in upstream pool p");
	up_refused("upstream p {\n -A OUTPUT -j ACCEPT\n}\n", -EINVAL,
		   "unknown directive in upstream pool p");
	up_refused("upstream p {\n server http://h;\n upstream q {\n}\n}\n",
		   -EINVAL, "line 3: upstream blocks do not nest");
	up_refused("upstream p {\n server http://h;\n include x.acl;\n}\n",
		   -EINVAL, "include is not allowed inside an upstream block");
	up_refused("upstream p {\n server http://h;\n", -EINVAL,
		   "line 1: upstream pool p is not closed");

	/* The server URLs; no message quotes the password. */
	up_refused("upstream p {\n server ftp://u:s3cret@h:1;\n}\n", -EINVAL,
		   "pool p server 1: the scheme must be");
	up_refused("upstream p {\n server SOCKS5://h:1;\n}\n", -EINVAL,
		   "the scheme must be");
	up_refused("upstream p {\n server http://u:s3cret@;\n}\n", -EINVAL,
		   "the host is empty or malformed");
	up_refused("upstream p {\n server http://;\n}\n", -EINVAL,
		   "the host is empty or malformed");
	up_refused("upstream p {\n server http://:s3cret@h:1;\n}\n", -EINVAL,
		   "the user name is empty");
	memset(name, 'u', 64);
	name[64] = '\0';
	assert(asprintf(&text,
			"upstream p {\n server http://%s%s%s%s:s3cret@h:1;\n}\n",
			name, name, name, name) > 0);
	up_refused(text, -EINVAL, "longer than 255 bytes");
	free(text);
	assert(asprintf(&text,
			"upstream p {\n server http://u:s3cret%s%s%s%s@h:1;\n}\n",
			name, name, name, name) > 0);
	up_refused(text, -EINVAL, "longer than 255 bytes");
	free(text);
	text = malloc(700);
	assert(text);
	p = text + sprintf(text, "upstream p {\n server http://");
	memset(p, 'h', 520);
	strcpy(p + 520, ":1;\n}\n");
	up_refused(text, -EINVAL, "the URL is too long");
	free(text);
	up_refused("upstream p {\n server http://u:s3cret@h:0;\n}\n", -EINVAL,
		   "the port must be a number from 1 to 65535");
	up_refused("upstream p {\n server http://h:65536;\n}\n", -EINVAL,
		   "the port must be a number from 1 to 65535");
	up_refused("upstream p {\n server http://h:99999999999999999999;\n}\n",
		   -EINVAL, "the port must be a number from 1 to 65535");
	up_refused("upstream p {\n server http://h:;\n}\n", -EINVAL,
		   "the port must be a number from 1 to 65535");
	up_refused("upstream p {\n server http://h:8x;\n}\n", -EINVAL,
		   "the port must be a number from 1 to 65535");
	up_refused("upstream p {\n server http://h:+80;\n}\n", -EINVAL,
		   "the port must be a number from 1 to 65535");
	up_refused("upstream p {\n server http://[::1;\n}\n", -EINVAL,
		   "the IPv6 address is malformed");
	up_refused("upstream p {\n server http://[]:1;\n}\n", -EINVAL,
		   "the IPv6 address is malformed");
	up_refused("upstream p {\n server http://[10.0.0.1]:1;\n}\n", -EINVAL,
		   "the IPv6 address is malformed");
	up_refused("upstream p {\n server http://[::1]x;\n}\n", -EINVAL,
		   "unexpected characters after the host");
	up_refused("upstream p {\n server http://::1;\n}\n", -EINVAL,
		   "the host is empty or malformed");
	up_refused("upstream p {\n server http://h:1/;\n}\n", -EINVAL,
		   "the port must be");
	up_refused("upstream p {\n server http://h/x;\n}\n", -EINVAL,
		   "unexpected characters after the host");
	up_refused("upstream p {\n server http://h;x;\n}\n", -EINVAL,
		   "unexpected characters after the host");

	/* One DNS mode a pool; https:// resolves remotely. */
	up_refused("upstream p {\n server socks5h://h:1;\n"
		   " server socks5://u:s3cret@h:1;\n}\n", -EINVAL,
		   "line 3: upstream pool p server 2 (socks5://h:1): resolves names locally, the servers before it remotely");
	up_refused("upstream p {\n server socks5://h:1;\n server http://h:1;\n}\n",
		   -EINVAL, "resolves names remotely, the servers before it locally");
	up_refused("upstream p {\n server socks5://h:1;\n"
		   " server https://u:s3cret@h:1;\n}\n", -EINVAL,
		   "line 3: upstream pool p server 2 (https://h:1): resolves names remotely, the servers before it locally");
	up_refused("upstream p {\n server https://h:1;\n"
		   " server socks5://h:1;\n}\n", -EINVAL,
		   "server 2 (socks5://h:1): resolves names locally, the servers before it remotely");

	/* The limits: 8192 servers a pool, 1024 pools a set. */
	assert(GWP_ACL_POOL_MAX_SERVERS == 8192);
	text = malloc(64 * 8200);
	assert(text);
	p = up_pool_text(text, "p", 8192);
	sprintf(p, "-A OUTPUT -j UPSTREAM --to p\n");
	assert(!gwp_acl_parse_str(&a, text));
	assert(up_eval(a, NULL, &req) == GWP_ACL_ACCEPT);
	assert(req.upstream == GWP_ACL_UPSTREAM_POOL);
	assert(gwp_acl_pool_nr_servers(req.upstream_pool) == 8192);
	assert(!strcmp(gwp_acl_pool_server_url(req.upstream_pool, 0),
		       "socks5h://10.0.0.1:1080"));
	assert(!strcmp(gwp_acl_pool_server_url(req.upstream_pool, 4097),
		       "socks5h://10.0.16.98:1080"));
	assert(!strcmp(gwp_acl_pool_server_url(req.upstream_pool, 8191),
		       "socks5h://10.0.32.192:1080"));
	assert(!gwp_acl_pool_server_url(req.upstream_pool, 8192));
	gwp_acl_req_release(&req);
	gwp_acl_destroy(a);
	up_pool_text(text, "p", 8193);
	up_refused(text, -EINVAL, "line 8194: upstream pool p has more than 8192 servers");
	for (p = text, i = 0; i < 1024; i++) {
		snprintf(name, sizeof(name), "p%d", i);
		p = up_pool_text(p, name, 1);
	}
	p += sprintf(p, "-A OUTPUT -j UPSTREAM --to p1023\n");
	assert(!gwp_acl_parse_str(&a, text));
	assert(!strcmp(up_choice(a, NULL), "p1023"));
	gwp_acl_destroy(a);
	up_pool_text(p, "p1024", 1);
	up_refused(text, -EINVAL, "more than 1024 upstream pools");
	free(text);

	/* The rules. */
	up_refused("upstream p {\n server http://h;\n}\n"
		   "-A INPUT -j UPSTREAM --to p\n", -EINVAL,
		   "line 4: -j UPSTREAM is only valid in the OUTPUT chain");
	up_refused("-A OUTPUT -j UPSTREAM\n", -EINVAL,
		   "-j UPSTREAM needs --to NAME");
	up_refused("-A OUTPUT -j UPSTREAM --to-destination DIRECT\n", -EINVAL,
		   "-j UPSTREAM needs --to NAME");
	up_refused("-A OUTPUT -j UPSTREAM --to p/q\n", -EINVAL,
		   "-j UPSTREAM: bad upstream pool name");
	up_refused("-A OUTPUT -j UPSTREAM --to\n", -EINVAL, "parse error on line 1");
	up_refused("-A OUTPUT -j UPSTREAM --to DIRECT --to-proxy DIRECT\n",
		   -EINVAL, "parse error on line 1");
	up_refused("-A OUTPUT -j UPSTREAM --to DIRECT --set-mark 1\n", -EINVAL,
		   "parse error on line 1");
	up_refused("-A OUTPUT -j UPSTREAM --to-iface lo --to DIRECT\n", -EINVAL,
		   "parse error on line 1");
	up_refused("-A OUTPUT ! -j UPSTREAM --to DIRECT\n", -EINVAL,
		   "parse error on line 1");
	up_refused("-A OUTPUT -j UPSTREAM ! --to DIRECT\n", -EINVAL,
		   "parse error on line 1");
	up_refused("-A OUTPUT -d 10.0.0.1 -j DNAT --to-proxy 10.0.0.2\n",
		   -EINVAL, "parse error on line 1");
	up_refused("-A OUTPUT -j UPSTREAM --to nope\n-P OUTPUT ACCEPT\n",
		   -EINVAL, "line 1: upstream pool nope is not defined");
	up_refused("upstream nope {\n server http://h;\n}\n"
		   "-A OUTPUT -j UPSTREAM --to Nope\n", -EINVAL,
		   "line 4: upstream pool Nope is not defined");

	/* -d in an UPSTREAM rule only warns. */
	up_capture();
	i = gwp_acl_parse_str(&a,
		"-A OUTPUT -d 10.0.0.0/8 -j UPSTREAM --to DIRECT\n");
	text = up_captured();
	up_check(i, 0, text);
	assert(strstr(text, "line 1: warning: -d in a -j UPSTREAM rule"));
	free(text);
	gwp_acl_destroy(a);
}

#ifdef CONFIG_PCRE
/* Linked with --wrap, so a test can fail the context's allocation. */
void *__real_pcre2_match_context_create_8(void *gcontext);
void *__wrap_pcre2_match_context_create_8(void *gcontext);

static bool g_fail_regex_mctx;

void *__wrap_pcre2_match_context_create_8(void *gcontext)
{
	if (g_fail_regex_mctx)
		return NULL;
	return __real_pcre2_match_context_create_8(gcontext);
}

/*
 * The first regexp rule creates the match context, so this must run before any
 * other test parses one. Failing that allocation fails this file only.
 */
static noinline void test_regexp_ctx_oom_recovers(void)
{
	static const char rules[] =
		"-A OUTPUT -m domain --domain-regexp ^blocked$ -j REJECT\n"
		"-P OUTPUT ACCEPT\n";
	struct gwp_acl *a = NULL;
	struct gwp_sockaddr s = sa4("8.8.8.8", 80);

	g_fail_regex_mctx = true;
	assert(gwp_acl_parse_str(&a, rules));
	g_fail_regex_mctx = false;

	assert(!gwp_acl_parse_str(&a, rules));
	assert(out(a, &s, "blocked", 80, GWP_ACL_PROTO_TCP) == GWP_ACL_REJECT);
	assert(out(a, &s, "other", 80, GWP_ACL_PROTO_TCP) == GWP_ACL_ACCEPT);
	gwp_acl_destroy(a);
}
#else
static void test_regexp_ctx_oom_recovers(void)
{
}
#endif

static void run_tests(void)
{
	size_t i;

	test_regexp_ctx_oom_recovers();

	/* Negative cases print the offending line to stderr; run them once. */
	test_parse_errors();
	test_reload_under_readers();
	test_reload_swaps_whole_ruleset();
	test_index_first_match();
	test_index_matches_linear();
	test_generation();
	test_empty_chain_policy();
	test_file_nul();
	test_file_fifo();
	test_include_order();
	test_include_errors();
	test_include_reload();
	test_include_glob_order();
	test_include_glob_errors();
	test_upstream_errors();
	test_upstream_pool_https();
	test_upstream_index();
	test_upstream_include();
	test_upstream_creds_warning();
	test_upstream_url_redact();
	test_upstream_pool_outlives_reload();
	test_upstream_take_pool();
	test_upstream_reload_readers();
	test_upstream_server_ops();
	test_upstream_pick_no_target();
	test_upstream_pick_regexp_error();
	test_upstream_udp_refused();

	for (i = 0; i < 200; i++) {
		test_default_ruleset();
		test_v4mapped_cidr();
		test_ports_and_negation();
		test_input_and_proto();
		test_domain();
		test_domain_regexp();
		test_regexp_limit();
		test_domain_only_target_criteria();
		test_user();
		test_mark();
		test_bind();
		test_dnat();
		test_memo();
		test_comments_and_default_policy();
		test_statistic_nth();
		test_number_bases();
		test_statistic_counts_only_matches();
		test_statistic_load_balance();
		test_statistic_equal_every_is_uneven();
		test_upstream_pools();
		test_upstream_pick();
	}
	printf("All tests passed!\n");
}

int main(void)
{
	run_tests();
	return 0;
}
