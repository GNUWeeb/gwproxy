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

__cold
int convert_str_to_ssaddr(const char *str,
				struct gwp_sockaddr *gs, uint16_t default_port)
{
	static const struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
	};
	char host[NI_MAXHOST], port[6], *p;
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
		snprintf(port, 6, "%hu", default_port);
	} else {
		strncpy(port, p + 1, sizeof(port) - 1);
		port[sizeof(port) - 1] = '\0';
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
