// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * Unit tests for the iptables-style ACL parser and matcher (acl.c).
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
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
		"-j BIND --to-source 127.0.0.2 --accept", "-j MARK --set-mark 6",
		"-j BIND --to-iface lo",
	};

	if (!output)
		return rnd(2) ? "-j ACCEPT" : "-j REJECT";
	strcpy(buf, out_acts[rnd(terminal || rnd(4) ? 6 : NELEM(out_acts))]);
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
		p += sprintf(p, "-s %s -p %s ", rnd_net(), rnd(2) ? "tcp" : "udp");
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
	p += sprintf(p, "%s\n", rnd_action(abuf, output, indexable));
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
	    x->mark_set != y->mark_set || x->bind.set != y->bind.set)
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
 * Random rule files, each evaluated twice: as written, where long runs
 * are indexed, and with a never-matching two-criterion rule after every
 * rule, which leaves no run to index. Every request must get the same
 * verdict and the same DNAT/MARK/BIND result from both.
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
		assert(!gwp_acl_parse_str(&a, txt));
		assert(!gwp_acl_parse_str(&b, ref));
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

static void run_tests(void)
{
	size_t i;

	/* Negative cases print the offending line to stderr; run them once. */
	test_parse_errors();
	test_reload_under_readers();
	test_reload_swaps_whole_ruleset();
	test_index_first_match();
	test_index_matches_linear();
	test_generation();
	test_empty_chain_policy();
	test_file_nul();

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
		test_statistic_counts_only_matches();
		test_statistic_load_balance();
		test_statistic_equal_every_is_uneven();
	}
	printf("All tests passed!\n");
}

int main(void)
{
	run_tests();
	return 0;
}
