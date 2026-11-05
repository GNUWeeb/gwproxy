// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 *
 * Whose fault a failed upstream proxy handshake is. A failure says either
 * that the upstream proxy itself is unusable (it cannot be reached, refuses
 * our credentials, answers garbage or nothing), that the destination behind
 * it is (the upstream reached out and was refused), or nothing certain about
 * either (a policy refusal, a generic error). Only the first kind should count
 * against the upstream's health.
 *
 * Also how an upstream URL names its host, for TLS (gwp_upstream_url_host()).
 *
 * Self-contained (libc only) so it can be unit-tested alone.
 */
#ifndef GWP_UPSTREAM_H
#define GWP_UPSTREAM_H

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <arpa/inet.h>

enum gwp_upstream_fail_class {
	GWP_UPSTREAM_FAIL_NEUTRAL	= 0,	/* not counted */
	GWP_UPSTREAM_FAIL_UPSTREAM	= 1,	/* the upstream's fault */
	GWP_UPSTREAM_FAIL_DESTINATION	= 2,	/* the destination's fault */
};

/*
 * How an upstream handshake ended, and what @val in
 * gwp_upstream_fail_classify() then holds.
 */
enum gwp_upstream_end {
	GWP_UPSTREAM_END_CONNECT,	/* TCP connect failed; errno, any sign */
	GWP_UPSTREAM_END_TLS,		/* TLS handshake failed */
	GWP_UPSTREAM_END_S5_METHOD,	/* SOCKS5 method we cannot use */
	GWP_UPSTREAM_END_S5_AUTH,	/* SOCKS5 user/password status */
	GWP_UPSTREAM_END_S5_REP,	/* SOCKS5 CONNECT REP */
	GWP_UPSTREAM_END_HTTP,		/* HTTP CONNECT status code */
	GWP_UPSTREAM_END_MALFORMED,	/* reply does not parse */
	GWP_UPSTREAM_END_HUP,		/* upstream hung up; errno, or 0 */
	/*
	 * Out of time; 0 while the upstream still owed us its part before
	 * our CONNECT request (the TCP connect, the TLS handshake, the
	 * SOCKS5 method and auth), else (waiting for the CONNECT's reply,
	 * which the destination may hold up) not the upstream's fault.
	 */
	GWP_UPSTREAM_END_TIMEOUT,
};

/* How an upstream handshake ended, for a log line. */
static inline const char *gwp_upstream_end_str(enum gwp_upstream_end end)
{
	switch (end) {
	case GWP_UPSTREAM_END_CONNECT:
		return "connect";
	case GWP_UPSTREAM_END_TLS:
		return "tls";
	case GWP_UPSTREAM_END_S5_METHOD:
		return "socks5-method";
	case GWP_UPSTREAM_END_S5_AUTH:
		return "socks5-auth";
	case GWP_UPSTREAM_END_S5_REP:
		return "socks5-rep";
	case GWP_UPSTREAM_END_HTTP:
		return "http-status";
	case GWP_UPSTREAM_END_MALFORMED:
		return "malformed";
	case GWP_UPSTREAM_END_HUP:
		return "hangup";
	case GWP_UPSTREAM_END_TIMEOUT:
	default:
		return "timeout";
	}
}

static inline enum gwp_upstream_fail_class
gwp_upstream_s5_rep_class(int rep)
{
	switch (rep) {
	case 0x00:	/* succeeded */
	case 0x01:	/* general failure: could be either side */
	case 0x02:	/* not allowed by ruleset: policy */
		return GWP_UPSTREAM_FAIL_NEUTRAL;
	case 0x03:	/* network unreachable */
	case 0x04:	/* host unreachable */
	case 0x05:	/* connection refused */
	case 0x06:	/* TTL expired */
		return GWP_UPSTREAM_FAIL_DESTINATION;
	case 0x07:	/* command not supported */
	case 0x08:	/* address type not supported */
	default:	/* unassigned: not a reply we can trust */
		return GWP_UPSTREAM_FAIL_UPSTREAM;
	}
}

static inline enum gwp_upstream_fail_class
gwp_upstream_http_class(int status)
{
	if (status < 100 || status > 599)
		return GWP_UPSTREAM_FAIL_UPSTREAM;	/* not a status code */
	switch (status) {
	case 407:	/* proxy authentication required */
		return GWP_UPSTREAM_FAIL_UPSTREAM;
	case 502:	/* bad gateway */
	case 504:	/* gateway timeout */
		return GWP_UPSTREAM_FAIL_DESTINATION;
	default:	/* 2xx success; 403, 500, 503 and the rest: unclear */
		return GWP_UPSTREAM_FAIL_NEUTRAL;
	}
}

static inline enum gwp_upstream_fail_class
gwp_upstream_connect_class(int err)
{
	switch (err < 0 ? -err : err) {
	case ECONNREFUSED:
	case ETIMEDOUT:
	case ECONNRESET:
	case ECONNABORTED:
	case EPIPE:
	case EHOSTUNREACH:
	case ENETUNREACH:
	case EHOSTDOWN:
	case ENETDOWN:
		return GWP_UPSTREAM_FAIL_UPSTREAM;
	default:	/* local trouble: no memory, no fds, no ports, ... */
		return GWP_UPSTREAM_FAIL_NEUTRAL;
	}
}

/*
 * Classify how an upstream handshake ended (@end, with @val as documented
 * on enum gwp_upstream_end). Pure: no state, no I/O. An outcome that is not
 * a failure (SOCKS5 status or REP 0x00, an HTTP 2xx) is NEUTRAL.
 */
static inline enum gwp_upstream_fail_class
gwp_upstream_fail_classify(enum gwp_upstream_end end, int val)
{
	switch (end) {
	case GWP_UPSTREAM_END_CONNECT:
		return gwp_upstream_connect_class(val);
	case GWP_UPSTREAM_END_S5_AUTH:
		return val ? GWP_UPSTREAM_FAIL_UPSTREAM :
			     GWP_UPSTREAM_FAIL_NEUTRAL;
	case GWP_UPSTREAM_END_S5_REP:
		return gwp_upstream_s5_rep_class(val);
	case GWP_UPSTREAM_END_HTTP:
		return gwp_upstream_http_class(val);
	case GWP_UPSTREAM_END_TIMEOUT:
		/* A destination that never answers holds the CONNECT up. */
		return val ? GWP_UPSTREAM_FAIL_NEUTRAL :
			     GWP_UPSTREAM_FAIL_UPSTREAM;
	case GWP_UPSTREAM_END_TLS:
	case GWP_UPSTREAM_END_S5_METHOD:
	case GWP_UPSTREAM_END_MALFORMED:
	case GWP_UPSTREAM_END_HUP:
	default:
		return GWP_UPSTREAM_FAIL_UPSTREAM;
	}
}

static inline const char *
gwp_upstream_fail_class_str(enum gwp_upstream_fail_class c)
{
	switch (c) {
	case GWP_UPSTREAM_FAIL_UPSTREAM:
		return "upstream";
	case GWP_UPSTREAM_FAIL_DESTINATION:
		return "destination";
	case GWP_UPSTREAM_FAIL_NEUTRAL:
	default:
		return "neutral";
	}
}

/*
 * The host of an upstream URL's "host[:port]" or "[v6addr]:port", without the
 * port and the brackets: the name a TLS upstream's certificate must carry.
 * Copies it to @out (@size bytes, NUL included) and sets *@is_ip when it is an
 * IPv4 or IPv6 address literal, which is checked against the certificate's IP
 * addresses and never sent as SNI, rather than a DNS name. Returns 0, or
 * -EINVAL when the host is empty or does not fit.
 */
static inline int gwp_upstream_url_host(const char *hostport, char *out,
					size_t size, bool *is_ip)
{
	unsigned char addr[16];
	const char *end;
	size_t n;

	if (hostport[0] == '[') {
		end = strchr(++hostport, ']');
		if (!end)
			return -EINVAL;
	} else {
		end = strchr(hostport, ':');
		if (!end)
			end = hostport + strlen(hostport);
	}

	n = (size_t)(end - hostport);
	if (!n || n >= size)
		return -EINVAL;
	memcpy(out, hostport, n);
	out[n] = '\0';
	*is_ip = inet_pton(AF_INET, out, addr) == 1 ||
		 inet_pton(AF_INET6, out, addr) == 1;
	return 0;
}

#endif /* GWP_UPSTREAM_H */
