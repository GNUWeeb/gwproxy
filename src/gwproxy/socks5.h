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
	GWP_SOCKS5_ST_CMD_UDP_ASSOCIATE	= 102,
	GWP_SOCKS5_ST_AUTH_USERPASS	= 200,
	GWP_SOCKS5_ST_FORWARDING	= 300,
	GWP_SOCKS5_ST_UDP_ASSOCIATED	= 400,
	GWP_SOCKS5_ST_ERR		= 500,
};

/*
 * Largest SOCKS5 UDP relay header (RFC 1928 section 7):
 * RSV(2) + FRAG(1) + ATYP(1) + ADDR(1 len + 255 domain) + PORT(2).
 */
#define GWP_SOCKS5_UDP_HDR_MAX	(2 + 1 + 1 + 1 + 255 + 2)

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
	/* Allow the UDP ASSOCIATE command (rejected with REP 0x07 when false). */
	bool		udp_associate;
};

struct gwp_socks5_ctx {
	struct gwp_auth		*auth;
	bool			udp_associate;
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
	uint8_t			user_len;	/* authenticated username len, 0=none */
	uint8_t			bad_user_len;	/* rejected username len, 0=none */
	char			user[256];	/* NUL-terminated when user_len > 0 */
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
 * Return the authenticated username for @conn, or NULL if the connection was
 * not authenticated (no auth store, or no username/password handshake). The
 * pointer stays valid for the connection's life.
 */
const char *gwp_socks5_conn_username(const struct gwp_socks5_conn *conn);

/**
 * Return the username whose credentials were rejected on @conn and store its
 * length in *@len, or return NULL if none was. The bytes are the client's,
 * unchecked: they may hold any value, NUL included.
 */
const char *gwp_socks5_conn_rejected_user(const struct gwp_socks5_conn *conn,
					  size_t *len);

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
 * 			written to `out_buf`, never more than its size.
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
 * -ENOBUFS:	Not enough space in the outgoing buffer. Nothing was
 * 		consumed or produced: *in_len and *out_len are 0 and the
 * 		state is unchanged.
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
 * 			written to `out_buf`, never more than its size.
 * @return		0 on success, or a negative error code on failure.
 *
 * Error values:
 * -EINVAL:	Invalid input parameters.
 *
 * -ENOBUFS:	Not enough space in the outgoing buffer. *out_len is 0
 * 		and the state is unchanged.
 */
int gwp_socks5_conn_cmd_connect_res(struct gwp_socks5_conn *conn,
				    const struct gwp_socks5_addr *bind_addr,
				    uint8_t rep, void *out_buf,
				    size_t *out_len);

/**
 * Construct the reply to a SOCKS5 UDP ASSOCIATE command. @bind_addr is the
 * proxy's UDP relay endpoint (from getsockname() on the relay socket) that the
 * client will send its datagrams to. On a success reply (rep == 0x00) the
 * connection state becomes GWP_SOCKS5_ST_UDP_ASSOCIATED; otherwise
 * GWP_SOCKS5_ST_ERR. Same buffer semantics and errors as
 * gwp_socks5_conn_cmd_connect_res().
 */
int gwp_socks5_conn_cmd_udp_associate_res(struct gwp_socks5_conn *conn,
					  const struct gwp_socks5_addr *bind_addr,
					  uint8_t rep, void *out_buf,
					  size_t *out_len);

/*
 * SOCKS5 UDP relay datagram header codec (RFC 1928 section 7). Stateless.
 *
 *   +----+------+------+----------+----------+----------+
 *   |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
 *   +----+------+------+----------+----------+----------+
 *   | 2  |  1   |  1   | Variable |    2     | Variable |
 */

/**
 * Parse the relay header at the front of a datagram. On success @addr receives
 * the encapsulated address (the target for client->proxy datagrams) and
 * *@hdr_len the offset where DATA begins, and 0 is returned.
 *
 * @return	0 on success; -EAGAIN if @len is shorter than the header;
 *		-EINVAL on a malformed header; -ENOTSUP if FRAG != 0 (this
 *		relay does not reassemble fragments).
 */
int gwp_socks5_udp_parse_hdr(const void *buf, size_t len,
			     struct gwp_socks5_addr *addr, size_t *hdr_len);

/**
 * Build a relay header (RSV = 0, FRAG = 0, then @addr) into @buf, for wrapping a
 * target's reply back to the client. On success *@hdr_len holds the header
 * length. Returns 0, -ENOBUFS if @cap is too small, or -EINVAL on a bad @addr.
 */
int gwp_socks5_udp_build_hdr(const struct gwp_socks5_addr *addr, void *buf,
			     size_t cap, size_t *hdr_len);

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
