#ifndef GWPROXY__DNS_RESOLVER_H
#define GWPROXY__DNS_RESOLVER_H

#include <gwproxy/gwproxy.h>

struct gwp_ctx;
struct gwp_dns_resolver_map;

struct gwp_dns_resolver {
	int				udp_fd;
	char				*srv_addr;
	struct gwp_dns_resolver_map	*sess_map;
};

int gwp_dns_res_init(struct gwp_ctx *ctx, struct gwp_dns_resolver *gdr,
		     const char *srv_addr);
void gwp_dns_res_free(struct gwp_dns_resolver *gdr);

#endif /* #ifndef GWPROXY__DNS_RESOLVER_H */
