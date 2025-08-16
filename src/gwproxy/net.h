/*
 * utility for network-related stuff
 */

#include <arpa/inet.h>

#ifndef GWP_NET_H
#define GWP_NET_H

#define FULL_ADDRSTRLEN (INET6_ADDRSTRLEN + sizeof(":65535[]") - 1)

struct gwp_sockaddr {
	union {
		struct sockaddr		sa;
		struct sockaddr_in	i4;
		struct sockaddr_in6	i6;
	};
};

/*
 * Convert address string to network address
 *
 * @param str source
 * @param gs destination
 * @param default_port fill it with zero if unspecified
 * @return zero on success and a negative integer on failure.
 */
int convert_str_to_ssaddr(const char *str,
				struct gwp_sockaddr *gs, uint16_t default_port);

/*
 * Convert network address to string format
 *
 * @param buf destination
 * @param gs source
 * @return zero on success and a negative integer on failure.
 */
int convert_ssaddr_to_str(char buf[FULL_ADDRSTRLEN],
			const struct gwp_sockaddr *gs);

#endif /* #ifndef GWP_NET_H */