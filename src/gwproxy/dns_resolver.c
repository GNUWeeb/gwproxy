/*
 * A new experimental DNS resolver that does not rely on getaddrinfo().
 */

#include <gwproxy/dns_resolver.h>
#include <gwproxy/dns_hash.h>
#include <gwproxy/syscall.h>
#include <gwproxy/net.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/*
 * A fresh transaction ID for every query (RFC 5452): SipHash of a counter
 * under a key from getrandom(), so the IDs cannot be predicted from earlier
 * ones and cost no system call each.
 */
static uint16_t next_txid(struct gwp_dns_resolver *res)
{
	uint64_t n = res->txid_ctr++;

	return (uint16_t)gwp_siphash13(res->txid_key, &n, sizeof(n));
}

static int parse_srv_addr(struct gwp_dns_resolver *gdr, const char *srv_addr)
{
	bool has_port;

	/*
	 * convert_str_to_ssaddr() ignores an explicit port in the string when
	 * a non-zero default_port is passed, so only pass the default when the
	 * address has no port of its own -- the same dance
	 * gwp_parse_upstream_socks5() does. Without it "--dns-server" silently
	 * queried port 53 whatever the user asked for.
	 */
	if (srv_addr[0] == '[') {
		const char *rb = strchr(srv_addr, ']');

		has_port = rb && rb[1] == ':';
	} else {
		has_port = strchr(srv_addr, ':') != NULL;
	}

	return convert_str_to_ssaddr(srv_addr, &gdr->srv, has_port ? 0 : 53);
}

/*
 * Every query has a socket of its own, connected to the server: the kernel
 * gives it a random source port, and only the server can answer on it. A
 * long-lived shared socket kept one port for the life of the worker, which
 * left an off-path attacker only the transaction ID to guess.
 */
static int open_query_sock(struct gwp_dns_resolver *res)
{
	static const int type = SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC;
	socklen_t len;
	int f, r;

	f = __sys_socket(res->srv.sa.sa_family, type, 0);
	if (f < 0)
		return f;

	len = res->srv.sa.sa_family == AF_INET6 ? sizeof(res->srv.i6)
						 : sizeof(res->srv.i4);
	r = __sys_connect(f, &res->srv.sa, len);
	if (r < 0) {
		__sys_close(f);
		return r;
	}

	return f;
}

int gwp_dns_res_init(struct gwp_ctx *ctx, struct gwp_dns_resolver *gdr,
		     const char *srv_addr)
{
	int r;

	gdr->srv_addr = strdup(srv_addr);
	if (!gdr->srv_addr)
		return -ENOMEM;

	r = parse_srv_addr(gdr, gdr->srv_addr);
	if (r) {
		free(gdr->srv_addr);
		gdr->srv_addr = NULL;
		return r;
	}

	gwp_dns_gen_hash_key(gdr->txid_key);
	gdr->txid_ctr = 0;
	(void)ctx;
	return 0;
}

void gwp_dns_res_free(struct gwp_dns_resolver *res)
{
	if (!res)
		return;

	free(res->srv_addr);
	memset(res, 0, sizeof(*res));
}

int gwp_dns_res_prep_query(struct gwp_dns_resolver *res,
			   struct gwp_dns_packet *gdp)
{
	ssize_t tmp;
	int af;

	assert(gdp->gcp);

	if (gdp->fd < 0) {
		gdp->fd = open_query_sock(res);
		if (gdp->fd < 0)
			return gdp->fd;
	}

	if (gdp->restyp == GWP_DNS_RESTYP_PREFER_IPV6) {
		af = AF_INET6;
		gdp->restyp = GWP_DNS_RESTYP_IPV4_ONLY;
		gdp->__in_fallback_attempt = true;
	} else if (gdp->restyp == GWP_DNS_RESTYP_PREFER_IPV4) {
		af = AF_INET;
		gdp->restyp = GWP_DNS_RESTYP_IPV6_ONLY;
		gdp->__in_fallback_attempt = true;
	} else if (gdp->restyp == GWP_DNS_RESTYP_IPV6_ONLY) {
		af = AF_INET6;
		/*
		 * The last family there is to try: if this one fails too,
		 * the lookup fails. Left set, every unusable answer sent
		 * the same query again, until the protocol timeout.
		 */
		gdp->__in_fallback_attempt = false;
	} else if (gdp->restyp == GWP_DNS_RESTYP_IPV4_ONLY) {
		af = AF_INET;
		gdp->__in_fallback_attempt = false;
	} else {
		return -EINVAL;
	}

	/* A new ID for the fallback query too, so no old reply passes. */
	gdp->txid = next_txid(res);
	tmp = gwdns_build_query(gdp->txid, gdp->host, af, gdp->buf,
				sizeof(gdp->buf));
	if (tmp < 0)
		return (int)tmp;

	gdp->buf_len = (uint16_t)tmp;
	return 0;
}

void gwp_dns_res_drop_query(struct gwp_dns_packet *gdp)
{
	/* Idempotent: teardown calls it whether or not a reply came. */
	if (gdp->fd >= 0) {
		__sys_close(gdp->fd);
		gdp->fd = -1;
	}
}

int gwp_dns_res_complete_query(struct gwp_dns_resolver *res,
				struct gwp_dns_packet *gdp,
				uint8_t buf[DNS_EDNS_UDP_SIZE],
				uint16_t len,
				struct gwp_sockaddr *addrs, uint8_t cap,
				uint8_t *nr_addrs)
{
	uint16_t txid;
	ssize_t r;

	/*
	 * Not an answer to the query in flight: an old reply to the first
	 * family, or a forgery, which has to guess the source port and the
	 * ID and also name what we asked about. Ignore it and keep waiting, as RFC 5452
	 * asks, rather than let it end the lookup.
	 */
	if (len < 12)
		return -ESRCH;
	memcpy(&txid, buf, 2);
	if (txid != gdp->txid)
		return -ESRCH;
	if (gwdns_check_question(gdp->buf, gdp->buf_len, buf, len))
		return -ESRCH;

	r = gwdns_parse_query(txid, gdp->port, buf, len, addrs, cap, nr_addrs);
	if (!r) {
		gwp_dns_res_drop_query(gdp);
		return 0;
	}

	/*
	 * A datagram arrives whole, so "need more data" from the parser
	 * means the reply is cut short. Do not pass that on as -EAGAIN,
	 * which the caller reads as "the next query is ready to send".
	 */
	if (r == -EAGAIN)
		r = -EBADMSG;

	/*
	 * A truncated answer would need a retry over TCP, which this
	 * resolver does not do. Asking for the other family over UDP is no
	 * answer to it either: fail the lookup.
	 */
	if (r == -EMSGSIZE)
		gdp->__in_fallback_attempt = false;

	if (gdp->__in_fallback_attempt) {
		int tmp = gwp_dns_res_prep_query(res, gdp);
		if (!tmp)
			return -EAGAIN;

		r = tmp;
	}

	gwp_dns_res_drop_query(gdp);
	return (int)r;
}
