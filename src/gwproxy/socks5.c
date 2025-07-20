// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>

#include "socks5.h"

static int copy_cfg(struct gwp_socks5_cfg *dst,
		    const struct gwp_socks5_cfg *src)
{
	if (!src)
		return 0;

	if (src->auth_file && *src->auth_file) {
		dst->auth_file = strdup(src->auth_file);
		if (!dst->auth_file)
			return -ENOMEM;
	}

	return 0;
}

static void free_cfg(struct gwp_socks5_cfg *cfg)
{
	if (!cfg)
		return;

	if (cfg->auth_file)
		free(cfg->auth_file);
}

struct auth_entry {
	char	*u, *p;
	uint8_t	ulen, plen;
};

struct gwp_socks5_auth {
	FILE			*fp;
	pthread_rwlock_t	lock;
	struct auth_entry	*entries;
	size_t			nr;
	size_t			cap;
};

static bool is_space(unsigned char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static char *trim_str(char *str)
{
	char *end;

	while (is_space((unsigned char)*str))
		str++;

	end = str + strlen(str) - 1;
	while (end > str && is_space((unsigned char)*end))
		end--;

	end[1] = '\0';
	return str;
}

static void free_auth_entries(struct gwp_socks5_auth *auth)
{
	size_t i;

	if (!auth)
		return;

	for (i = 0; i < auth->nr; i++)
		free(auth->entries[i].u);

	free(auth->entries);
	auth->entries = NULL;
	auth->nr = 0;
	auth->cap = 0;
}

static int add_auth_entry(struct gwp_socks5_auth *auth, const char *line,
			  size_t len)
{
	struct auth_entry *ae;
	size_t ulen, plen;
	char *u, *p;

	if (auth->nr >= auth->cap) {
		size_t new_cap = auth->cap ? auth->cap * 2 : 16;
		struct auth_entry *new_entries;

		new_entries = realloc(auth->entries,
				      new_cap * sizeof(*new_entries));
		if (!new_entries)
			return -ENOMEM;

		auth->entries = new_entries;
		auth->cap = new_cap;
	}

	u = malloc(len + 1);
	if (!u)
		return -ENOMEM;

	memcpy(u, line, len);
	u[len] = '\0';

	p = strchr(u, ':');
	if (p)
		*p++ = '\0';

	ulen = strlen(u);
	if (ulen > 255)
		goto out_free_u;

	plen = p ? strlen(p) : 0;
	if (plen > 255)
		goto out_free_u;

	ae = &auth->entries[auth->nr++];
	ae->u = u;
	ae->p = p;
	ae->ulen = ulen;
	ae->plen = plen;
	return 0;

out_free_u:
	free(u);
	return -EINVAL;
}

bool gwp_socks5_auth_check(struct gwp_socks5_ctx *ctx, const char *u,
			   size_t ulen, const char *p, size_t plen)
{
	struct gwp_socks5_auth *auth = ctx->auth;
	bool ret = false;
	size_t i;

	if (!auth || !auth->entries)
		return false;

	pthread_rwlock_rdlock(&auth->lock);
	for (i = 0; i < auth->nr; i++) {
		const struct auth_entry *ae = &auth->entries[i];
		if (ulen != ae->ulen)
			continue;
		if (plen != ae->plen)
			continue;
		if (memcmp(u, ae->u, ulen) != 0)
			continue;
		if (memcmp(p, ae->p, plen) != 0)
			continue;
		ret = true;
		break;
	}
	pthread_rwlock_unlock(&auth->lock);
	return ret;
}

int gwp_socks5_auth_reload(struct gwp_socks5_ctx *ctx)
{
	struct gwp_socks5_auth *auth = ctx->auth;
	char buf[4096], *t;
	size_t l;
	int r;

	if (!auth || !auth->fp)
		return -ENOSYS;

	pthread_rwlock_wrlock(&auth->lock);
	free_auth_entries(auth);
	while (1) {
		t = fgets(buf, sizeof(buf), auth->fp);
		if (!t)
			break;

		t = trim_str(buf);
		l = strlen(t);
		if (!l)
			continue;

		r = add_auth_entry(auth, t, l);
		if (r < 0)
			break;
	}
	rewind(auth->fp);
	pthread_rwlock_unlock(&auth->lock);
	return r;
}

static int open_auth_file(struct gwp_socks5_ctx *ctx)
{
	const char *af = ctx->cfg.auth_file;
	struct gwp_socks5_auth *auth = NULL;
	FILE *fp;
	int r;

	if (!af || !*af) {
		ctx->auth = NULL;
		return 0;
	}

	auth = calloc(1, sizeof(*auth));
	if (!auth)
		return -ENOMEM;

	fp = fopen(af, "rb");
	if (!fp) {
		r = -errno;
		goto out_free_auth;
	}

	auth->fp = fp;
	ctx->auth = auth;
	r = gwp_socks5_auth_reload(ctx);
	if (r < 0)
		goto out_free_auth_ent;

	return 0;

out_free_auth_ent:
	free_auth_entries(auth);
	fclose(auth->fp);
out_free_auth:
	free(auth);
	ctx->auth = NULL;
	return r;
}

static void free_auth(struct gwp_socks5_auth *auth)
{
	if (!auth)
		return;

	pthread_rwlock_destroy(&auth->lock);
	free_auth_entries(auth);
	fclose(auth->fp);
	free(auth);
}

int gwp_socks5_ctx_init(struct gwp_socks5_ctx **ctx_p,
			const struct gwp_socks5_cfg *cfg)
{
	struct gwp_socks5_ctx *ctx;
	int r;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return -ENOMEM;

	r = copy_cfg(&ctx->cfg, cfg);
	if (r < 0)
		goto out_free_ctx;

	r = open_auth_file(ctx);
	if (r < 0)
		goto out_free_cfg;

	*ctx_p = ctx;
	return 0;

out_free_cfg:
	free_cfg(&ctx->cfg);
out_free_ctx:
	free(ctx);
	return r;
}

void gwp_socks5_ctx_free(struct gwp_socks5_ctx *ctx)
{
	if (!ctx)
		return;

	free_auth(ctx->auth);
	free_cfg(&ctx->cfg);
	free(ctx);
}

struct gwp_socks5_conn *gwp_socks5_conn_alloc(struct gwp_socks5_ctx *ctx)
{
	struct gwp_socks5_conn *conn;

	if (!ctx)
		return NULL;

	conn = calloc(1, sizeof(*conn));
	if (!conn)
		return NULL;

	conn->state = GWP_SOCKS5_ST_INIT;
	conn->ctx = ctx;
	ctx->nr_clients++;
	return conn;
}

void gwp_socks5_conn_free(struct gwp_socks5_conn *conn)
{
	if (!conn)
		return;

	conn->ctx->nr_clients--;
	free(conn);
}

struct data_arg {
	struct gwp_socks5_ctx	*ctx;
	struct gwp_socks5_conn	*conn;
	const void		*in_buf;
	size_t			*in_len;
	void			*out_buf;
	size_t			*out_len;

	size_t			tot_out_len;
	size_t			tot_advance;
};

static int append_out_buf(struct data_arg *d, const void *buf, size_t len)
{
	size_t old_len = d->tot_out_len;
	uint8_t *dst;

	d->tot_out_len += len;
	if (d->tot_out_len > *d->out_len)
		return -ENOBUFS;

	dst = (uint8_t *)d->out_buf + old_len;
	memcpy(dst, buf, len);
	return 0;
}

static void advance_in_buf(struct data_arg *d, size_t len)
{
	assert(len <= *d->in_len);

	d->in_buf = (const uint8_t *)d->in_buf + len;
	*d->in_len -= len;
	d->tot_advance += len;
}

/*
 *   Link: https://datatracker.ietf.org/doc/html/rfc1928#section-3
 *
 *   3.  Procedure for TCP-based clients
 *
 *      When a TCP-based client wishes to establish a connection to an object
 *      that is reachable only via a firewall (such determination is left up
 *      to the implementation), it must open a TCP connection to the
 *      appropriate SOCKS port on the SOCKS server system.  The SOCKS service
 *      is conventionally located on TCP port 1080.  If the connection
 *      request succeeds, the client enters a negotiation for the
 *      authentication method to be used, authenticates with the chosen
 *      method, then sends a relay request.  The SOCKS server evaluates the
 *      request, and either establishes the appropriate connection or denies
 *      it.
 *
 *      Unless otherwise noted, the decimal numbers appearing in packet-
 *      format diagrams represent the length of the corresponding field, in
 *      octets.  Where a given octet must take on a specific value, the
 *      syntax X'hh' is used to denote the value of the single octet in that
 *      field. When the word 'Variable' is used, it indicates that the
 *      corresponding field has a variable length defined either by an
 *      associated (one or two octet) length field, or by a data type field.
 *
 *      The client connects to the server, and sends a version
 *      identifier/method selection message:
 *
 *                      +----+----------+----------+
 *                      |VER | NMETHODS | METHODS  |
 *                      +----+----------+----------+
 *                      | 1  |    1     | 1 to 255 |
 *                      +----+----------+----------+
 *
 *      The VER field is set to X'05' for this version of the protocol.  The
 *      NMETHODS field contains the number of method identifier octets that
 *      appear in the METHODS field.
 *
 *      The server selects from one of the methods given in METHODS, and
 *      sends a METHOD selection message:
 *
 *                            +----+--------+
 *                            |VER | METHOD |
 *                            +----+--------+
 *                            | 1  |   1    |
 *                            +----+--------+
 *
 *      If the selected METHOD is X'FF', none of the methods listed by the
 *      client are acceptable, and the client MUST close the connection.
 *
 *      The values currently defined for METHOD are:
 *
 *             o  X'00' NO AUTHENTICATION REQUIRED
 *             o  X'01' GSSAPI
 *             o  X'02' USERNAME/PASSWORD
 *             o  X'03' to X'7F' IANA ASSIGNED
 *             o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
 *             o  X'FF' NO ACCEPTABLE METHODS
 *
 *      The client and server then enter a method-specific sub-negotiation.
 *
 *      Descriptions of the method-dependent sub-negotiations appear in
 *      separate memos.
 *
 *      Developers of new METHOD support for this protocol should contact
 *      IANA for a METHOD number.  The ASSIGNED NUMBERS document should be
 *      referred to for a current list of METHOD numbers and their
 *      corresponding protocols.
 *
 *      Compliant implementations MUST support GSSAPI and SHOULD support
 *      USERNAME/PASSWORD authentication methods.
 */
static int handle_state_init(struct data_arg *d)
{
	struct gwp_socks5_conn *conn = d->conn;
	uint8_t nmethods, exp_method, resp[2];
	struct gwp_socks5_ctx *ctx = d->ctx;
	size_t len = *d->in_len, exp_len;
	const uint8_t *buf = d->in_buf;
	bool method_found;
	int next_state;

	/* VER + NMETHODS */
	exp_len = 2;
	if (len < exp_len)
		return -EAGAIN;

	/* VER must be 0x05. */
	if (buf[0] != 0x05)
		return -EINVAL;

	nmethods = buf[1];
	exp_len += nmethods;
	if (len < exp_len)
		return -EAGAIN;

	if (ctx->auth) {
		/* USERNAME/PASSWORD */
		exp_method = 0x02;
		next_state = GWP_SOCKS5_ST_AUTH_USERPASS;
	} else {
		/* NO AUTHENTICATION REQUIRED */
		exp_method = 0x00;
		next_state = GWP_SOCKS5_ST_CMD;
	}

	if (nmethods > 0)
		method_found = !!memchr(&buf[2], exp_method, nmethods);
	else
		method_found = false;

	if (!method_found) {
		/* NO ACCEPTABLE METHODS */
		exp_method = 0xFF;
		next_state = GWP_SOCKS5_ST_ERR;
	}

	resp[0] = 0x05; /* VER */
	resp[1] = exp_method; /* METHOD */
	if (append_out_buf(d, resp, 2))
		return -ENOBUFS;

	conn->state = next_state;
	advance_in_buf(d, exp_len);
	return 0;
}

/*
 *    Link: https://datatracker.ietf.org/doc/html/rfc1929#section-2
 *
 *    2.  Initial negotiation
 *
 *      Once the SOCKS V5 server has started, and the client has selected the
 *      Username/Password Authentication protocol, the Username/Password
 *      subnegotiation begins.  This begins with the client producing a
 *      Username/Password request:
 *
 *              +----+------+----------+------+----------+
 *              |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
 *              +----+------+----------+------+----------+
 *              | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
 *              +----+------+----------+------+----------+
 *
 *      The VER field contains the current version of the subnegotiation,
 *      which is X'01'. The ULEN field contains the length of the UNAME field
 *      that follows. The UNAME field contains the username as known to the
 *      source operating system. The PLEN field contains the length of the
 *      PASSWD field that follows. The PASSWD field contains the password
 *      association with the given UNAME.
 *
 *      The server verifies the supplied UNAME and PASSWD, and sends the
 *      following response:
 *
 *                            +----+--------+
 *                            |VER | STATUS |
 *                            +----+--------+
 *                            | 1  |   1    |
 *                            +----+--------+
 *
 *      A STATUS field of X'00' indicates success. If the server returns a
 *      `failure' (STATUS value other than X'00') status, it MUST close the
 *      connection.
 */
static int handle_state_auth_userpass(struct data_arg *d)
{
	const uint8_t *buf = (uint8_t *)d->in_buf;
	size_t exp_len, ulen, plen;
	size_t len = *d->in_len;
	const char *u, *p;
	uint8_t resp[2];

	/* VER + ULEN */
	exp_len = 2;
	if (len < exp_len)
		return -EAGAIN;

	/* VER must be 0x01. */
	if (buf[0] != 0x01)
		return -EINVAL;

	ulen = buf[1];
	exp_len += ulen;
	if (len < exp_len)
		return -EAGAIN;

	/* UNAME must be non-empty. */
	if (ulen == 0)
		return -EINVAL;

	u = (const char *)&buf[2];

	/* PLEN */
	exp_len += 1;
	if (len < exp_len)
		return -EAGAIN;

	plen = buf[exp_len - 1];
	exp_len += plen;
	if (len < exp_len)
		return -EAGAIN;

	p = plen ? (const char *)&buf[2 + ulen + 1] : NULL;

	resp[0] = 0x01; /* VER */
	if (gwp_socks5_auth_check(d->ctx, u, ulen, p, plen)) {
		/* STATUS = 0x00 (success) */
		resp[1] = 0x00;
		d->conn->state = GWP_SOCKS5_ST_CMD;
	} else {
		/* STATUS = 0x01 (failure) */
		resp[1] = 0x01;
		d->conn->state = GWP_SOCKS5_ST_ERR;
	}

	if (append_out_buf(d, resp, sizeof(resp)))
		return -ENOBUFS;

	advance_in_buf(d, exp_len);
	return 0;
}

static int set_err_reply(struct data_arg *d, uint8_t err_code)
{
	uint8_t resp[10];

	resp[0] = 0x05; /* VER */
	resp[1] = err_code; /* REP */
	resp[2] = 0x00; /* RSV */
	resp[3] = 0x01; /* ATYP: IPv4 address */
	memset(&resp[4], 0, 6); /* BND.ADDR + BND.PORT */
	d->conn->state = GWP_SOCKS5_ST_ERR;

	if (append_out_buf(d, resp, sizeof(resp)))
		return -ENOBUFS;

	return -EINVAL;
}

/*
 *   Link: https://datatracker.ietf.org/doc/html/rfc1928#section-4
 *
 *   4.  Requests
 *
 *      Once the method-dependent subnegotiation has completed, the client
 *      sends the request details.  If the negotiated method includes
 *      encapsulation for purposes of integrity checking and/or
 *      confidentiality, these requests MUST be encapsulated in the method-
 *      dependent encapsulation.
 *
 *      The SOCKS request is formed as follows:
 *
 *           +----+-----+-------+------+----------+----------+
 *           |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
 *           +----+-----+-------+------+----------+----------+
 *           | 1  |  1  | X'00' |  1   | Variable |    2     |
 *           +----+-----+-------+------+----------+----------+
 *
 *        Where:
 *
 *             o  VER    protocol version: X'05'
 *             o  CMD
 *                o  CONNECT X'01'
 *                o  BIND X'02'
 *                o  UDP ASSOCIATE X'03'
 *             o  RSV    RESERVED
 *             o  ATYP   address type of following address
 *                o  IP V4 address: X'01'
 *                o  DOMAINNAME: X'03'
 *                o  IP V6 address: X'04'
 *             o  DST.ADDR       desired destination address
 *             o  DST.PORT desired destination port in network octet
 *                order
 *
 *      The SOCKS server will typically evaluate the request based on source
 *      and destination addresses, and return one or more reply messages, as
 *      appropriate for the request type.
 *
 *
 *   5.  Addressing
 *
 *      In an address field (DST.ADDR, BND.ADDR), the ATYP field specifies
 *      the type of address contained within the field:
 *
 *             o  X'01'
 *
 *      the address is a version-4 IP address, with a length of 4 octets
 *
 *             o  X'03'
 *
 *      the address field contains a fully-qualified domain name.  The first
 *      octet of the address field contains the number of octets of name that
 *      follow, there is no terminating NUL octet.
 *
 *             o  X'04'
 *
 *      the address is a version-6 IP address, with a length of 16 octets.
 *
 *   6.  Replies
 *
 *      The SOCKS request information is sent by the client as soon as it has
 *      established a connection to the SOCKS server, and completed the
 *      authentication negotiations.  The server evaluates the request, and
 *      returns a reply formed as follows:
 *
 *           +----+-----+-------+------+----------+----------+
 *           |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
 *           +----+-----+-------+------+----------+----------+
 *           | 1  |  1  | X'00' |  1   | Variable |    2     |
 *           +----+-----+-------+------+----------+----------+
 *
 *        Where:
 *
 *             o  VER    protocol version: X'05'
 *             o  REP    Reply field:
 *                o  X'00' succeeded
 *                o  X'01' general SOCKS server failure
 *                o  X'02' connection not allowed by ruleset
 *                o  X'03' Network unreachable
 *                o  X'04' Host unreachable
 *                o  X'05' Connection refused
 *                o  X'06' TTL expired
 *                o  X'07' Command not supported
 *                o  X'08' Address type not supported
 *                o  X'09' to X'FF' unassigned
 *             o  RSV    RESERVED
 *             o  ATYP   address type of following address
 *                o  IP V4 address: X'01'
 *                o  DOMAINNAME: X'03'
 *                o  IP V6 address: X'04'
 *             o  BND.ADDR       server bound address
 *             o  BND.PORT       server bound port in network octet order
 *
 *
 *      Fields marked RESERVED (RSV) must be set to X'00'.
 *
 *      If the chosen method includes encapsulation for purposes of
 *      authentication, integrity and/or confidentiality, the replies are
 *      encapsulated in the method-dependent encapsulation.
 *
 *   CONNECT
 *
 *      In the reply to a CONNECT, BND.PORT contains the port number that the
 *      server assigned to connect to the target host, while BND.ADDR
 *      contains the associated IP address.  The supplied BND.ADDR is often
 *      different from the IP address that the client uses to reach the SOCKS
 *      server, since such servers are often multi-homed.  It is expected
 *      that the SOCKS server will use DST.ADDR and DST.PORT, and the
 *      client-side source address and port in evaluating the CONNECT
 *      request.
 *
 *   BIND
 *
 *      The BIND request is used in protocols which require the client to
 *      accept connections from the server.  FTP is a well-known example,
 *      which uses the primary client-to-server connection for commands and
 *      status reports, but may use a server-to-client connection for
 *      transferring data on demand (e.g. LS, GET, PUT).
 *
 *      It is expected that the client side of an application protocol will
 *      use the BIND request only to establish secondary connections after a
 *      primary connection is established using CONNECT.  In is expected that
 *      a SOCKS server will use DST.ADDR and DST.PORT in evaluating the BIND
 *      request.
 *
 *      Two replies are sent from the SOCKS server to the client during a
 *      BIND operation.  The first is sent after the server creates and binds
 *      a new socket.  The BND.PORT field contains the port number that the
 *      SOCKS server assigned to listen for an incoming connection.  The
 *      BND.ADDR field contains the associated IP address.  The client will
 *      typically use these pieces of information to notify (via the primary
 *      or control connection) the application server of the rendezvous
 *      address.  The second reply occurs only after the anticipated incoming
 *      connection succeeds or fails.
 *
 *      In the second reply, the BND.PORT and BND.ADDR fields contain the
 *      address and port number of the connecting host.
 *
 *   UDP ASSOCIATE
 *
 *      The UDP ASSOCIATE request is used to establish an association within
 *      the UDP relay process to handle UDP datagrams.  The DST.ADDR and
 *      DST.PORT fields contain the address and port that the client expects
 *      to use to send UDP datagrams on for the association.  The server MAY
 *      use this information to limit access to the association.  If the
 *      client is not in possesion of the information at the time of the UDP
 *      ASSOCIATE, the client MUST use a port number and address of all
 *      zeros.
 *
 *      A UDP association terminates when the TCP connection that the UDP
 *      ASSOCIATE request arrived on terminates.
 *
 *      In the reply to a UDP ASSOCIATE request, the BND.PORT and BND.ADDR
 *      fields indicate the port number/address where the client MUST send
 *      UDP request messages to be relayed.
 *
 *   Reply Processing
 *
 *      When a reply (REP value other than X'00') indicates a failure, the
 *      SOCKS server MUST terminate the TCP connection shortly after sending
 *      the reply.  This must be no more than 10 seconds after detecting the
 *      condition that caused a failure.
 *
 *      If the reply code (REP value of X'00') indicates a success, and the
 *      request was either a BIND or a CONNECT, the client may now start
 *      passing data.  If the selected authentication method supports
 *      encapsulation for the purposes of integrity, authentication and/or
 *      confidentiality, the data are encapsulated using the method-dependent
 *      encapsulation.  Similarly, when data arrives at the SOCKS server for
 *      the client, the server MUST encapsulate the data as appropriate for
 *      the authentication method in use.
 */
static int handle_cmd_connect(struct data_arg *d);
static int handle_state_cmd(struct data_arg *d)
{
	size_t len = *d->in_len, exp_len;
	const uint8_t *buf = d->in_buf;

	/* VER + CMD + RSV + ATYP */
	exp_len = 4;
	if (len < exp_len)
		return -EAGAIN;

	/* VER must be 0x05. */
	if (buf[0] != 0x05)
		return -EINVAL;

	/* RSV must be 0x00. */
	if (buf[2] != 0x00)
		return -EINVAL;

	/* Check the CMD. */
	switch (buf[1]) {
	case 0x01: /* CONNECT */
		return handle_cmd_connect(d);

	/*
	 * TODO(ammarfaizi2):
	 * Implement BIND and UDP ASSOCIATE commands. For now,
	 * we just return an error.
	 */
	case 0x02: /* BIND */
	case 0x03: /* UDP ASSOCIATE */
	default:
		/*
		 * 0x07 = Command not supported.
		 */
		return set_err_reply(d, GWP_SOCKS5_REP_COMMAND_NOT_SUPPORTED);
	}
}

static int handle_cmd_connect(struct data_arg *d)
{
	struct gwp_socks5_addr *da = &d->conn->dst_addr;
	struct gwp_socks5_conn *conn = d->conn;
	size_t len = *d->in_len, exp_len;
	const uint8_t *buf = d->in_buf;
	uint8_t atyp, domlen = 0;

	exp_len = 4;
	atyp = buf[3];
	switch (atyp) {
	case GWP_SOCKS5_ATYP_IPV4:
		/*
		 * IPv4 address and port.
		 */
		exp_len += 4 + 2;
		break;
	case GWP_SOCKS5_ATYP_IPV6:
		/*
		 * IPv6 address and port.
		 */
		exp_len += 16 + 2;
		break;
	case GWP_SOCKS5_ATYP_DOMAIN:
		/*
		 * Domain name and port.
		 */
		exp_len += 1; /* Length of domain name */
		if (len < exp_len)
			return -EAGAIN;
		domlen = buf[4];
		exp_len += domlen + 2;
		break;
	default:
		return set_err_reply(d, GWP_SOCKS5_REP_ATYP_NOT_SUPPORTED);
	}

	if (len < exp_len)
		return -EAGAIN;

	/* Copy the address and port into the connection structure. */
	switch (atyp) {
	case GWP_SOCKS5_ATYP_IPV4:
		da->ver = GWP_SOCKS5_ATYP_IPV4;
		memcpy(da->ip4, &buf[4], 4);
		memcpy(&da->port, &buf[8], 2);
		break;
	case GWP_SOCKS5_ATYP_IPV6:
		da->ver = GWP_SOCKS5_ATYP_IPV6;
		memcpy(da->ip6, &buf[4], 16);
		memcpy(&da->port, &buf[20], 2);
		break;
	case GWP_SOCKS5_ATYP_DOMAIN:
		da->ver = GWP_SOCKS5_ATYP_DOMAIN;
		da->domain.len = domlen;
		memcpy(da->domain.str, &buf[5], domlen);
		da->domain.str[domlen] = '\0';
		memcpy(&da->port, &buf[5 + domlen], 2);
		break;
	}

	conn->state = GWP_SOCKS5_ST_CMD_CONNECT;
	advance_in_buf(d, exp_len);
	return 0;
}

int gwp_socks5_conn_handle_data(struct gwp_socks5_conn *conn,
				const void *in_buf, size_t *in_len,
				void *out_buf, size_t *out_len)
{
	struct data_arg arg = {
		.ctx = conn->ctx,
		.conn = conn,
		.in_buf = in_buf,
		.in_len = in_len,
		.out_buf = out_buf,
		.out_len = out_len,
		.tot_out_len = 0,
		.tot_advance = 0
	};
	int r, orig_state = conn->state;

repeat:
	switch (conn->state) {
	case GWP_SOCKS5_ST_INIT:
		r = handle_state_init(&arg);
		break;
	case GWP_SOCKS5_ST_AUTH_USERPASS:
		r = handle_state_auth_userpass(&arg);
		break;
	case GWP_SOCKS5_ST_CMD:
		r = handle_state_cmd(&arg);
		break;
	case GWP_SOCKS5_ST_CMD_CONNECT:
		r = 0;
		goto out;
	default:
		return -EINVAL;
	}

	if (!r && *arg.in_len > 0)
		goto repeat;

	if (r && r != -EAGAIN && r != -ENOBUFS)
		conn->state = GWP_SOCKS5_ST_ERR;

out:
	if (r == -ENOBUFS) {
		/*
		 * If we run out of output buffer space, don't change
		 * the connection state as the caller may lose the
		 * partially written data in the output buffer.
		 *
		 * The caller will eventually get the proper state
		 * after it calls this function again with enough
		 * output buffer space.
		 */
		conn->state = orig_state;
		*in_len = 0;
	} else {
		*in_len = arg.tot_advance;
	}

	*out_len = arg.tot_out_len;
	return r;
}

static int __gwp_socks5_conn_cmd_connect_res(struct data_arg *arg,
					     const struct gwp_socks5_addr *ba,
					     uint8_t rep)
{
	size_t resp_len = 0;
	uint8_t resp[1024];

	if (arg->conn->state != GWP_SOCKS5_ST_CMD_CONNECT)
		return -EINVAL;

	resp[0] = 0x05; /* VER */
	resp[1] = rep; /* REP */
	resp[2] = 0x00; /* RSV */
	resp_len = 4;
	if (ba) {
		resp[3] = ba->ver; /* ATYP */
		switch (ba->ver) {
		case GWP_SOCKS5_ATYP_IPV4:
			memcpy(&resp[4], ba->ip4, 4);
			memcpy(&resp[8], &ba->port, 2);
			resp_len += 4 + 2;
			break;
		case GWP_SOCKS5_ATYP_IPV6:
			memcpy(&resp[4], ba->ip6, 16);
			memcpy(&resp[20], &ba->port, 2);
			resp_len += 16 + 2;
			break;
		case GWP_SOCKS5_ATYP_DOMAIN:
			memcpy(&resp[4], &ba->domain.len, 1);
			memcpy(&resp[5], ba->domain.str, resp[4]);
			memcpy(&resp[5 + resp[4]], &ba->port, 2);
			resp_len += 1 + ba->domain.len + 2;
			break;
		default:
			return -EINVAL;
		}
	} else {
		resp[3] = GWP_SOCKS5_ATYP_IPV4; /* ATYP: IPv4 address */
		memset(&resp[4], 0, 6); /* BND.ADDR + BND.PORT */
		resp_len += 4 + 2;
	}

	if (append_out_buf(arg, resp, resp_len))
		return -ENOBUFS;

	return 0;
}

int gwp_socks5_conn_cmd_connect_res(struct gwp_socks5_conn *conn,
				    const struct gwp_socks5_addr *bind_addr,
				    uint8_t rep, void *out_buf,
				    size_t *out_len)
{
	struct data_arg arg = {
		.ctx = conn->ctx,
		.conn = conn,
		.in_buf = NULL,
		.in_len = NULL,
		.out_buf = out_buf,
		.out_len = out_len,
		.tot_out_len = 0,
		.tot_advance = 0
	};
	int r = __gwp_socks5_conn_cmd_connect_res(&arg, bind_addr, rep);
	*out_len = arg.tot_out_len;

	if (r != -ENOBUFS)
		conn->state = (rep == 0x00) ? GWP_SOCKS5_ST_FORWARDING
					    : GWP_SOCKS5_ST_ERR;

	return r;
}
