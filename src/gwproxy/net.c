#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netdb.h>
#include <gwproxy/net.h>
#include <gwproxy/common.h>

/*
 * Copy the port of an "addr:port" string to @out for getaddrinfo(): a decimal
 * number from 0 to 65535, or a service name. Only the number needs checking
 * here. Left to the C library, glibc wraps a number modulo 65536 and takes a
 * signed one, so a typo would quietly mean some other port.
 */
static int copy_port(char *out, size_t size, const char *port)
{
	size_t i, l = strlen(port);
	unsigned int v = 0;

	if (!l || l >= size)
		return -EINVAL;

	if (port[0] >= '0' && port[0] <= '9') {
		for (i = 0; i < l; i++) {
			if (port[i] < '0' || port[i] > '9')
				return -EINVAL;
			v = v * 10 + (unsigned int)(port[i] - '0');
			if (v > 65535)
				return -EINVAL;
		}
	} else if (!((port[0] >= 'a' && port[0] <= 'z') ||
		     (port[0] >= 'A' && port[0] <= 'Z'))) {
		return -EINVAL;
	}

	memcpy(out, port, l + 1);
	return 0;
}

__cold
int convert_str_to_ssaddr(const char *str,
				struct gwp_sockaddr *gs, uint16_t default_port)
{
	static const struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
	};
	char host[NI_MAXHOST], port[32], *p;
	struct addrinfo *res, *ai;
	bool found = false;
	size_t l;
	int r;

	if (*str == '[') {
		p = strchr(++str, ']');
		if (!p)
			return -EINVAL;
		l = p - str;
		p++;
		/* Only a ":port" may follow the closing bracket. */
		if (*p && *p != ':')
			return -EINVAL;
	} else {
		p = strchr(str, ':');
		l = p ? (size_t)(p - str) : strlen(str);
	}

	/*
	 * No port in the string: fall back to the default. @l already spans
	 * the host, without the brackets of an IPv6 literal.
	 */
	if ((!p || *p != ':') && !default_port)
		return -EINVAL;

	if (l >= sizeof(host))
		return -EINVAL;

	strncpy(host, str, l);
	host[l] = '\0';
	/*
	 * A host name or IP literal holds nothing but letters, digits and
	 * "-._" (plus ':' and '%' for an IPv6 literal and its zone). Refuse
	 * anything else here: what getaddrinfo() makes of, say, a space is up
	 * to the C library, and musl sends such a name to the DNS server and
	 * waits for its timeout where glibc refuses it at once.
	 */
	if (!*host || host[strspn(host, "abcdefghijklmnopqrstuvwxyz"
				     "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				     "0123456789-._:%")])
		return -EINVAL;
	if (default_port) {
		snprintf(port, sizeof(port), "%hu", default_port);
	} else {
		r = copy_port(port, sizeof(port), p + 1);
		if (r)
			return r;
	}

	r = getaddrinfo(host, port, &hints, &res);
	if (r)
		return -EINVAL;
	if (!res)
		return -EINVAL;

	memset(gs, 0, sizeof(*gs));
	for (ai = res; ai; ai = ai->ai_next) {
		if (ai->ai_family == AF_INET) {
			gs->i4 = *(struct sockaddr_in *)ai->ai_addr;
			found = true;
			break;
		} else if (ai->ai_family == AF_INET6) {
			gs->i6 = *(struct sockaddr_in6 *)ai->ai_addr;
			found = true;
			break;
		}
	}

	freeaddrinfo(res);
	return found ? 0 : -EINVAL;
}

__cold
int convert_ssaddr_to_str(char buf[FULL_ADDRSTRLEN],
			const struct gwp_sockaddr *gs)
{
	int f = gs->sa.sa_family;
	uint16_t port = 0;
	size_t l;

	if (f == AF_INET) {
		if (!inet_ntop(f, &gs->i4.sin_addr, buf, INET_ADDRSTRLEN))
			return -EINVAL;
		l = strlen(buf);
		port = ntohs(gs->i4.sin_port);
	} else if (f == AF_INET6) {
		buf[0] = '[';
		if (!inet_ntop(f, &gs->i6.sin6_addr, buf + 1, INET6_ADDRSTRLEN))
			return -EINVAL;
		l = strlen(buf);
		buf[l++] = ']';
		port = ntohs(gs->i6.sin6_port);
	} else {
		return -EINVAL;
	}

	buf[l++] = ':';
	snprintf(buf + l, FULL_ADDRSTRLEN - l, "%hu", port);
	return 0;
}
