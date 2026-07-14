#ifndef GWPROXY__DNS_RESOLVER_H
#define GWPROXY__DNS_RESOLVER_H

#include <gwproxy/dns_parser.h>
#include <gwproxy/gwproxy.h>
#include <gwproxy/dns.h>

struct gwp_ctx;
struct gwp_dns_resolver_map;

struct gwp_dns_resolver {
	int				udp_fd;
	char				*srv_addr;
	struct gwp_dns_resolver_map	*sess_map;
};

struct gwp_dns_packet {
	bool			__in_fallback_attempt;
	uint8_t			restyp;
	uint16_t		txid;
	uint16_t		buf_len;
	uint16_t		port;
	uint8_t			buf[UDP_MSG_LIMIT];
	char			*host;
	struct gwp_conn_pair	*gcp;
};

int gwp_dns_res_init(struct gwp_ctx *ctx, struct gwp_dns_resolver *gdr,
		     const char *srv_addr);
void gwp_dns_res_free(struct gwp_dns_resolver *gdr);

int gwp_dns_res_prep_query(struct gwp_dns_resolver *res,
			   struct gwp_dns_packet *gdp);

void gwp_dns_res_drop_query(struct gwp_dns_resolver *res,
			    struct gwp_conn_pair *gcp, uint16_t txid);

int gwp_dns_res_fetch_gcp_by_payload(struct gwp_dns_resolver *res,
				     const uint8_t buf[UDP_MSG_LIMIT],
				     uint16_t len,
				     struct gwp_conn_pair **gcp_p);

int gwp_dns_res_complete_query(struct gwp_dns_resolver *res,
				struct gwp_dns_packet *gdp,
				uint8_t buf[UDP_MSG_LIMIT],
				uint16_t len,
				struct gwp_sockaddr *addr);

#endif /* #ifndef GWPROXY__DNS_RESOLVER_H */
