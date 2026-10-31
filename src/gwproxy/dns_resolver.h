#ifndef GWPROXY__DNS_RESOLVER_H
#define GWPROXY__DNS_RESOLVER_H

#include <gwproxy/dns_parser.h>
#include <gwproxy/gwproxy.h>
#include <gwproxy/dns.h>

struct gwp_ctx;

struct gwp_dns_resolver {
	struct gwp_sockaddr	srv;
	char			*srv_addr;
	/* next_txid(): SipHash key and counter. */
	uint64_t		txid_key[2];
	uint64_t		txid_ctr;
};

struct gwp_dns_packet {
	bool			__in_fallback_attempt;
	uint8_t			restyp;
	uint16_t		txid;
	uint16_t		buf_len;
	uint16_t		port;
	/* This query's own socket, or -1 before the first query. */
	int			fd;
	uint8_t			buf[UDP_MSG_LIMIT];
	char			*host;
	struct gwp_conn_pair	*gcp;
};

int gwp_dns_res_init(struct gwp_ctx *ctx, struct gwp_dns_resolver *gdr,
		     const char *srv_addr);
void gwp_dns_res_free(struct gwp_dns_resolver *gdr);

/*
 * Build the next query of @gdp into gdp->buf, under a new random transaction
 * ID, opening the query's socket on the first call.
 */
int gwp_dns_res_prep_query(struct gwp_dns_resolver *res,
			   struct gwp_dns_packet *gdp);

/* Close the query's socket; any reply still on its way is dropped. */
void gwp_dns_res_drop_query(struct gwp_dns_packet *gdp);

/*
 * Take a reply that arrived on the query's socket. Returns 0 with the
 * addresses, -EAGAIN when the next query is built and ready to send, -ESRCH
 * when the datagram does not answer the query in flight (ignore it), or
 * another negative error when the lookup failed.
 */
int gwp_dns_res_complete_query(struct gwp_dns_resolver *res,
				struct gwp_dns_packet *gdp,
				uint8_t buf[DNS_EDNS_UDP_SIZE],
				uint16_t len,
				struct gwp_sockaddr *addrs, uint8_t cap,
				uint8_t *nr_addrs);

#endif /* #ifndef GWPROXY__DNS_RESOLVER_H */
