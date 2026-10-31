// SPDX-License-Identifier: GPL-2.0-only
/*
 * Keyed hashing of host names, shared by the DNS cache and the resolver's
 * table of lookups in flight. Both are keyed by names a client chooses, so
 * both need a hash an attacker cannot aim at one bucket.
 */
#ifndef GWPROXY_DNS_HASH_H
#define GWPROXY_DNS_HASH_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <endian.h>
#include <sys/types.h>
#ifdef CONFIG_HAVE_GETRANDOM
#include <sys/random.h>
#endif

/*
 * A random 128-bit key for gwp_siphash13(), so an attacker cannot tell
 * which hostnames share a bucket. getrandom() is preferred; the fallback mixes
 * time/pid/address, which is not cryptographic but still unknown to a remote
 * attacker.
 *
 * The fallback covers two cases: getrandom() failing at run time, and libcs
 * that do not provide it at all (Termux on Android, say), where calling it
 * would not even compile -- hence the configure probe rather than a bare
 * __has_include or a version check.
 */
static inline void gwp_dns_gen_hash_key(uint64_t key[2])
{
	uint64_t s;

#ifdef CONFIG_HAVE_GETRANDOM
	if (getrandom(key, 2 * sizeof(*key), 0) == (ssize_t)(2 * sizeof(*key)))
		return;
#endif

	s = (uint64_t)time(NULL);
	s ^= (uint64_t)getpid() * 0x9e3779b97f4a7c15ULL;
	s ^= (uint64_t)(uintptr_t)&s;
	key[0] = s;
	key[1] = (s ^ (uint64_t)(uintptr_t)key) * 0xbf58476d1ce4e5b9ULL;
}

static inline uint64_t gwp_rotl64(uint64_t x, unsigned int b)
{
	return (x << b) | (x >> (64 - b));
}

#define GWP_SIPROUND(v0, v1, v2, v3)			\
	do {						\
		v0 += v1; v1 = gwp_rotl64(v1, 13);		\
		v1 ^= v0; v0 = gwp_rotl64(v0, 32);		\
		v2 += v3; v3 = gwp_rotl64(v3, 16);		\
		v3 ^= v2;				\
		v0 += v3; v3 = gwp_rotl64(v3, 21);		\
		v3 ^= v0;				\
		v2 += v1; v1 = gwp_rotl64(v1, 17);		\
		v1 ^= v2; v2 = gwp_rotl64(v2, 32);		\
	} while (0)

/*
 * SipHash-1-3 of @len bytes at @in under the 128-bit @key.
 *
 * A keyed PRF, not a seeded hash: DJB2 started from a random seed still made
 * two names of equal length collide under every seed when they collided under
 * one (the seed only scales the whole sum), so an attacker with a wildcard
 * zone could still fill one bucket chain. With a secret key, which names share
 * a bucket cannot be predicted.
 */
static inline uint64_t gwp_siphash13(const uint64_t key[2], const void *in, size_t len)
{
	const unsigned char *p = in;
	uint64_t v0 = 0x736f6d6570736575ULL ^ key[0];
	uint64_t v1 = 0x646f72616e646f6dULL ^ key[1];
	uint64_t v2 = 0x6c7967656e657261ULL ^ key[0];
	uint64_t v3 = 0x7465646279746573ULL ^ key[1];
	uint64_t b = (uint64_t)len << 56, m;
	size_t i, left = len & 7;

	for (i = 0; i + 8 <= len; i += 8) {
		memcpy(&m, p + i, 8);
		m = le64toh(m);
		v3 ^= m;
		GWP_SIPROUND(v0, v1, v2, v3);
		v0 ^= m;
	}

	for (p += i; left--;)
		b |= (uint64_t)p[left] << (8 * left);

	v3 ^= b;
	GWP_SIPROUND(v0, v1, v2, v3);
	v0 ^= b;
	v2 ^= 0xff;
	GWP_SIPROUND(v0, v1, v2, v3);
	GWP_SIPROUND(v0, v1, v2, v3);
	GWP_SIPROUND(v0, v1, v2, v3);
	return v0 ^ v1 ^ v2 ^ v3;
}

/*
 * ASCII-lowercase @key into @buf (capacity @cap) and return the length incl. the
 * NUL terminator, or 0 if it does not fit. DNS is case-insensitive, so keying on
 * the folded name avoids duplicate entries (and lookup misses) for case-varied
 * requests. Only A-Z is folded (hostnames are ASCII; avoids locale tolower()).
 */
static inline size_t gwp_dns_fold_name(const char *key, char *buf, size_t cap)
{
	size_t i;

	for (i = 0; key[i]; i++) {
		unsigned char c = (unsigned char)key[i];

		if (i + 1 >= cap)
			return 0;
		buf[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : (char)c;
	}
	buf[i] = '\0';
	return i + 1;
}

#endif /* #ifndef GWPROXY_DNS_HASH_H */
