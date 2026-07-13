/*
 * A new experimental DNS resolver that does not rely on getaddrinfo().
 */

#include <gwproxy/dns_resolver.h>
#include <gwproxy/syscall.h>
#include <gwproxy/net.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct gwp_dns_resolver_map {
	uint32_t		cap;
	uint32_t		sp;
	uint16_t		*stack;
	struct gwp_conn_pair	**sess_map;
};

static int alloc_res_map(struct gwp_dns_resolver_map **map, uint32_t cap)
{
	struct gwp_dns_resolver_map *m;
	uint32_t i, local_cap = 2;

	/*
	 * Keep the capacity a power of 2 for easier doubling to
	 * max size of 65536.
	 */
	while (local_cap < cap)
		local_cap *= 2;

	if (local_cap > 65536)
		return -EINVAL;

	m = malloc(sizeof(*m));
	if (!m)
		return -ENOMEM;

	m->sess_map = calloc(local_cap, sizeof(*m->sess_map));
	if (!m->sess_map)
		goto err_m;

	m->stack = malloc(local_cap * sizeof(*m->stack));
	if (!m->stack)
		goto err_sess;

	m->cap = local_cap;
	m->sp = 0;

	/*
	 * Fill the stack with all available indexes.
	 */
	i = local_cap;
	while (i--)
		m->stack[m->sp++] = i;

	*map = m;
	return 0;

err_sess:
	free(m->sess_map);
err_m:
	free(m);
	return -ENOMEM;
}

static void free_res_map(struct gwp_dns_resolver_map *map)
{
	if (!map)
		return;

	free(map->stack);
	free(map->sess_map);
	free(map);
}

static int expand_res_map(struct gwp_dns_resolver_map *map)
{
	uint32_t new_cap, i, old_cap = map->cap;
	struct gwp_conn_pair **new_sess_map;
	uint16_t *new_stack;

	new_cap = old_cap * 2;
	if (new_cap > 65536)
		return -ENOSPC;

	new_sess_map = realloc(map->sess_map, new_cap * sizeof(*map->sess_map));
	if (!new_sess_map)
		return -ENOMEM;
	map->sess_map = new_sess_map;
	memset(&map->sess_map[old_cap], 0, old_cap * sizeof(*map->sess_map));

	new_stack = realloc(map->stack, new_cap * sizeof(*map->stack));
	if (!new_stack)
		return -ENOMEM;
	map->stack = new_stack;

	i = new_cap;
	while (i-- > old_cap)
		map->stack[map->sp++] = i;

	map->cap = new_cap;
	return 0;
}

static int insert_map(struct gwp_dns_resolver_map *map,
		      struct gwp_conn_pair *pair, uint16_t *txid)
{
	uint32_t x;
	int r;

	if (!map->sp) {
		r = expand_res_map(map);
		if (r)
			return r;
	}

	x = map->stack[--map->sp];
	map->sess_map[x] = pair;
	*txid = x;
	return 0;
}

static struct gwp_conn_pair *lookup_map(struct gwp_dns_resolver_map *map,
					uint16_t txid)
{
	if (txid >= map->cap)
		return NULL;

	return map->sess_map[txid];
}

static void try_reset_map(struct gwp_dns_resolver_map *map)
{
	struct gwp_conn_pair **new_sess_map;
	uint32_t i, new_cap = 16;
	uint16_t *new_stack;

	if (map->cap <= 16)
		return;

	/*
	 * Try to allocate a smaller map first before freeing the
	 * existing one so we don't lose the existing map if
	 * one of reallocations fail.
	 */
	new_sess_map = calloc(new_cap, sizeof(*new_sess_map));
	if (!new_sess_map)
		return;

	new_stack = malloc(new_cap * sizeof(*new_stack));
	if (!new_stack) {
		free(new_sess_map);
		return;
	}

	/*
	 * Ok, we are good to go, free the old map and
	 * replace with the new one.
	 */
	free(map->sess_map);
	free(map->stack);
	map->sess_map = new_sess_map;
	map->stack = new_stack;
	map->cap = new_cap;
	map->sp = 0;

	i = new_cap;
	while (i--)
		map->stack[map->sp++] = i;
}

static void delete_map(struct gwp_dns_resolver_map *map, uint16_t txid)
{
	if (txid >= map->cap)
		return;

	if (!map->sess_map[txid])
		return;

	map->sess_map[txid] = NULL;
	map->stack[map->sp++] = txid;

	/*
	 * If all slots are free, try to shrink the map.
	 */
	if (map->sp == map->cap)
		try_reset_map(map);
}

static int init_udp_sock(struct gwp_dns_resolver *gdr, const char *srv_addr)
{
	static const int type = SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC;
	struct gwp_sockaddr addr;
	int f, r;

	r = convert_str_to_ssaddr(srv_addr, &addr, 53);
	if (r)
		return r;

	f = __sys_socket(addr.sa.sa_family, type, 0);
	if (f < 0)
		return f;

	r = __sys_connect(f, &addr.sa, sizeof(addr));
	if (r < 0) {
		__sys_close(f);
		return r;
	}

	gdr->udp_fd = f;
	return 0;
}

int gwp_dns_res_init(struct gwp_ctx *ctx, struct gwp_dns_resolver *gdr,
		     const char *srv_addr)
{
	int r;

	r = alloc_res_map(&gdr->sess_map, 16);
	if (r)
		return r;

	gdr->srv_addr = strdup(srv_addr);
	if (!gdr->srv_addr) {
		r = -ENOMEM;
		goto err_map;
	}

	r = init_udp_sock(gdr, gdr->srv_addr);
	if (r)
		goto err_srv;

	(void)ctx;
	return 0;

err_srv:
	free(gdr->srv_addr);
err_map:
	free_res_map(gdr->sess_map);
	return r;
}

void gwp_dns_res_free(struct gwp_dns_resolver *res)
{
	if (!res)
		return;

	free_res_map(res->sess_map);
	free(res->srv_addr);
	__sys_close(res->udp_fd);
	memset(res, 0, sizeof(*res));
}
