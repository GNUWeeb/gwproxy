// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWP_SOCKS5_H
#define GWP_SOCKS5_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <linux/types.h>

enum gwp_socks5_state {
	GWP_SOCKS5_ST_INIT		= 0,
	GWP_SOCKS5_ST_CMD		= 100,
	GWP_SOCKS5_ST_CMD_CONNECT	= 101,
	GWP_SOCKS5_ST_AUTH_USERPASS	= 200,
	GWP_SOCKS5_ST_FORWARDING	= 300,
	GWP_SOCKS5_ST_ERR		= 500,
};

enum gwp_socks5_atyp {
	GWP_SOCKS5_ATYP_IPV4		= 0x01,
	GWP_SOCKS5_ATYP_IPV6		= 0x04,
	GWP_SOCKS5_ATYP_DOMAIN		= 0x03,
};

enum gwp_socks5_cmd_rep {
	GWP_SOCKS5_REP_SUCCESS			= 0x00,
	GWP_SOCKS5_REP_FAILURE			= 0x01,
	GWP_SOCKS5_REP_NOT_ALLOWED		= 0x02,
	GWP_SOCKS5_REP_NETWORK_UNREACHABLE	= 0x03,
	GWP_SOCKS5_REP_HOST_UNREACHABLE 	= 0x04,
	GWP_SOCKS5_REP_CONN_REFUSED		= 0x05,
	GWP_SOCKS5_REP_TTL_EXPIRED		= 0x06,
	GWP_SOCKS5_REP_COMMAND_NOT_SUPPORTED	= 0x07,
	GWP_SOCKS5_REP_ATYP_NOT_SUPPORTED 	= 0x08,
	GWP_SOCKS5_REP_UNASSIGNED		= 0x09,
};

struct gwp_auth;

struct gwp_socks5_cfg {
	/* Borrowed credential store, or NULL to disable authentication. */
	struct gwp_auth	*auth;
};

struct gwp_socks5_ctx {
	struct gwp_auth		*auth;
	_Atomic(uint32_t)	nr_clients;
};

struct gwp_socks5_addr {
	/*
	 * 0x01 = IPv4 address.
	 * 0x04 = IPv6 address.
	 * 0x03 = Domain name.
	 */
	uint8_t	ver;
	__be16	port;
	union {
		uint8_t	ip4[4];
		uint8_t	ip6[16];
		struct {
			uint8_t	len;
			char	str[256];
		} domain;
	};
};

struct gwp_socks5_conn {
	int			state;
	struct gwp_socks5_addr	dst_addr;
	struct gwp_socks5_ctx	*ctx;
};

/**
 * Allocate and initialize a new SOCKS5 context with the given
 * configuration. When successful, the context is stored in the
 * pointer provided by `ctx_p`. The pointer must be freed using
 * `gwp_socks5_ctx_free()` when no longer needed.
 *
 * @param ctx_p	Pointer to a pointer where the new context will be stored.
 * @param cfg	Configuration for the SOCKS5 context.
 * @return	0 on success, or a negative error code on failure.
 */
int gwp_socks5_ctx_init(struct gwp_socks5_ctx **ctx_p,
			const struct gwp_socks5_cfg *cfg);

/**
 * Free the resources associated with a SOCKS5 context.
 *
 * @param ctx	The SOCKS5 context to free. If NULL, this function does
 * 		nothing.
 */
void gwp_socks5_ctx_free(struct gwp_socks5_ctx *ctx);

/**
 * Allocate a new SOCKS5 connection associated with the given context.
 * The connection must be freed using `gwp_socks5_conn_free()` when no
 * longer needed.
 *
 * @param ctx	The SOCKS5 context to associate with the new connection.
 * @return	A pointer to the newly allocated connection, or NULL on
 * 		failure.
 */
struct gwp_socks5_conn *gwp_socks5_conn_alloc(struct gwp_socks5_ctx *ctx);

/**
 * Free the resources associated with a SOCKS5 connection.
 *
 * @param conn	The SOCKS5 connection to free.
 */
void gwp_socks5_conn_free(struct gwp_socks5_conn *conn);

/**
 * Handle incoming data and prepare outgoing data for a SOCKS5 connection.
 * It processes the incoming data, updates the connection state, and fills
 * the outgoing buffer with the appropriate response.
 *
 * @param conn		The SOCKS5 connection to handle data for.
 * @param in_buf	Buffer containing incoming data.
 * @param in_len	Pointer to the size of the incoming data buffer.
 * 			After return, it will contain the size of the data
 * 			processed from `in_buf`. The caller should advance
 * 			the buffer by this amount.
 * @param out_buf	Buffer to store outgoing data.
 * @param out_len	Pointer to the size of the outgoing data buffer.
 * 			After return, it will contain the size of the data
 * 			written to `out_buf` or the required size if there
 * 			is not enough space.
 * @return		0 on success, or a negative error code on failure.
 *
 * Error values:
 *
 * -ENOMEM:	Not enough memory to handle the request.
 *
 * -EINVAL:	Invalid input parameters.
 *
 * -EAGAIN:	More data is needed to complete the request.
 *
 * -ENOBUFS:	Not enough space in the outgoing buffer. *out_len will
 * 		contain the required size.
 */
int gwp_socks5_conn_handle_data(struct gwp_socks5_conn *conn,
				const void *in_buf, size_t *in_len,
				void *out_buf, size_t *out_len);

/**
 * Construct a response for a SOCKS5 CONNECT command. After the caller
 * performs connect() and getsockname(), this function is called to
 * prepare the response to send back to the client.
 *
 * If the connection was successful (rep == 0x00), the connection
 * state is set to GWP_SOCKS5_ST_FORWARDING. Otherwise, it is set
 * to GWP_SOCKS5_ST_ERR.
 *
 * @param conn		The SOCKS5 connection to handle data for.
 * @param bind_addr	The local address to bind to (from getsockname()).
 * @param rep		The SOCKS5 reply code.
 * @param out_buf	Buffer to store the outgoing data.
 * @param out_len	Pointer to the size of the outgoing data buffer.
 * 			After return, it will contain the size of the data
 * 			written to `out_buf` or the required size if there
 * 			is not enough space.
 * @return		0 on success, or a negative error code on failure.
 *
 * Error values:
 * -EINVAL:	Invalid input parameters.
 *
 * -ENOBUFS:	Not enough space in the outgoing buffer. *out_len will
 * 		contain the required size.
 */
int gwp_socks5_conn_cmd_connect_res(struct gwp_socks5_conn *conn,
				    const struct gwp_socks5_addr *bind_addr,
				    uint8_t rep, void *out_buf,
				    size_t *out_len);

/*
 * SOCKS5 client-side helpers.
 *
 * These are used when gwproxy itself acts as a SOCKS5 *client* to route
 * outgoing connections through an upstream SOCKS5 proxy. They are stateless
 * message coders: builders serialize a request into @buf, parsers consume a
 * reply from @buf.
 *
 * Builders:
 *   @len is in/out. On input it holds the capacity of @buf. On success it is
 *   set to the number of bytes written. If @buf is too small, -ENOBUFS is
 *   returned and @len is set to the required size.
 *
 * Parsers:
 *   Return -EAGAIN if @buf does not yet hold a complete message (the caller
 *   should read more), -EINVAL on a protocol violation, or 0 on success.
 */

/**
 * Build the version identifier / method selection greeting.
 *
 * @param have_auth	Offer the USERNAME/PASSWORD method in addition to
 *			NO AUTHENTICATION REQUIRED.
 */
int gwp_socks5_cli_build_greeting(bool have_auth, void *buf, size_t *len);

/**
 * Parse the server's METHOD selection message. On success @method is set to
 * the selected method (0x00 = none, 0x02 = user/pass, 0xFF = no acceptable
 * methods).
 */
int gwp_socks5_cli_parse_method(const void *buf, size_t len, uint8_t *method);

/**
 * Build an RFC1929 USERNAME/PASSWORD authentication request.
 */
int gwp_socks5_cli_build_userpass(const char *u, size_t ulen,
				  const char *p, size_t plen,
				  void *buf, size_t *len);

/**
 * Parse the RFC1929 authentication response. On success @status is set
 * (0x00 = success).
 */
int gwp_socks5_cli_parse_userpass(const void *buf, size_t len,
				  uint8_t *status);

/**
 * Build a CONNECT request for the given destination address.
 */
int gwp_socks5_cli_build_connect(const struct gwp_socks5_addr *dst,
				 void *buf, size_t *len);

/**
 * Parse a CONNECT reply. On success @rep is set to the reply code
 * (0x00 = succeeded) and @consumed to the total reply length in bytes.
 */
int gwp_socks5_cli_parse_connect(const void *buf, size_t len,
				 uint8_t *rep, size_t *consumed);

#endif /* #ifndef GWP_SOCKS5_H */
