#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <gwproxy/net.h>

#ifndef GWP_DNS_PARSER_H
#define GWP_DNS_PARSER_H

#ifndef __packed
#define __packed __attribute__((__packed__))
#endif

/*
 * 4. MESSAGES
 * 4.1. Format
 *
 * All communications inside of the domain protocol are carried in a single
 * format called a message. The top-level format of a message is divided
 * into 5 sections (some of which may be empty in certain cases), shown below:
 *
 *     +---------------------+
 *     |        Header       |
 *     +---------------------+
 *     |       Question      | the question for the name server
 *     +---------------------+
 *     |        Answer       | RRs answering the question
 *     +---------------------+
 *     |      Authority      | RRs pointing toward an authority
 *     +---------------------+
 *     |      Additional     | RRs holding additional information
 *     +---------------------+
 *
 * These sections are defined in RFC 1035 §4.1. The Header section is always
 * present and includes fields that specify which of the other sections follow,
 * as well as metadata such as whether the message is a query or response,
 * the opcode, etc.
 */

/* Flag bit position in little-endian machine */
#define DNS_QR_BIT		0xF
#define DNS_OPCODE_BIT		0xB	// 4-bit field
#define DNS_AA_BIT		0xA
#define DNS_TC_BIT		0x9
#define DNS_RD_BIT		0x8
#define DNS_RA_BIT		0x7
#define DNS_Z_BIT		0x4	// 3-bit field
#define DNS_RCODE_BIT		0x0	// 4-bit field
#define DNS_COMPRESSION_BIT	(0x3 << 0xE)

/* Flag extraction macros for listtle-endian machine */
#define DNS_QR(flags)		(((flags) >> DNS_QR_BIT) & 0x1)
#define DNS_OPCODE(flags)	(((flags) >> DNS_OPCODE_BIT) & 0xF)
#define DNS_RCODE(flags)	((flags) & 0xF)
#define DNS_TC(flags)		(((flags) >> DNS_TC_BIT) & 0x1)
#define DNS_IS_COMPRESSED(mask) ((mask) & DNS_COMPRESSION_BIT)

/* Flag construction macros for little-endian machine */
#define DNS_SET_RD(flags, val)	(flags) = ((flags) & ~(1 << DNS_RD_BIT)) | ((!!(val)) << DNS_RD_BIT)

/* as per RFC 1035 §2.3.4. Size limits */
#define DOMAIN_LABEL_LIMIT 63
#define DOMAIN_NAME_LIMIT 255
#define UDP_MSG_LIMIT 512

/*
 * The UDP payload size advertised with EDNS0, and so the most a reply can
 * carry: 1232 avoids IP fragmentation on any path (DNS Flag Day 2020).
 */
#define DNS_EDNS_UDP_SIZE 1232

typedef enum {
	OPCODE_QUERY	= 0,	// Standard query (QUERY)
} gwdns_op;

typedef enum {
	TYPE_A		= 1,	// IPv4 host address
	TYPE_CNAME	= 5,	// the canonical name for an alias
	TYPE_AAAA	= 28,	// IPv6 host address
	TYPE_OPT	= 41,	// EDNS0 pseudo-record (RFC 6891)
} gwdns_type;

typedef enum {
	CLASS_IN	= 1,	// Internet
} gwdns_class;

typedef struct {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __packed gwdns_header_pkt;

typedef struct {
	uint8_t question[UDP_MSG_LIMIT];
	char answr[UDP_MSG_LIMIT];
} gwdns_question_buffer;

typedef struct {
	uint8_t *dst_buffer;
	uint16_t txid;
	uint16_t type;
	size_t dst_len;
	const char *domain;
} gwdns_question_part;

typedef struct {
	gwdns_header_pkt hdr;
	uint8_t body[UDP_MSG_LIMIT];
} gwdns_query_pkt;

/*
 * Build standard query for domain name lookup.
 *
 * The caller may need to check for potential transaction ID collisions.
 *
 * Possible errors are:
 * - ENAMETOOLONG	name is too long.
 * - ENOBUFS		length specified by out_len is not sufficient.
 * - EINVAL		malformed name or unsupported value of family.
 *
 * @param txid		transaction id
 * @param name		domain name
 * @param family	choose request for IPv4 or IPv6
 * @param out		destination buffer for constructed packet
 * @param out_len	available capacity of destination buffer
 * @return		length of bytes written into dst_buffer on success,
 * 			or a negative integer on failure.
 */
ssize_t gwdns_build_query(uint16_t txid, const char *name, int family, uint8_t *out, size_t out_len);

/*
 * Parse name server's answer into at most @cap addresses with port @port, in
 * the order the answer lists them. No memory is allocated. Records past @cap
 * are still checked but not kept.
 *
 * Possible errors are:
 * -EAGAIN	in buffer is not sufficient, no bytes are processed, need more data.
 * -EINVAL	the content of in buffer is not valid.
 * -ENODATA	the packet didn't contain any answers.
 * -EPROTO	the DNS server can't understand your question
 * -EMSGSIZE	the server truncated the answer (TC)
 *
 * @param txid		transaction id of question
 * @param port		port to put in the addresses (host byte order)
 * @param in		a pointer to buffer that need to be parsed
 * @param in_len	length of @in
 * @param addrs		receives the addresses
 * @param cap		capacity of @addrs
 * @param nr_addrs	receives the number of addresses written
 * @return		zero on success or a negative number on failure
 */
int gwdns_parse_query(uint16_t txid, uint16_t port, const uint8_t *in,
		      size_t in_len, struct gwp_sockaddr *addrs, uint8_t cap,
		      uint8_t *nr_addrs);

/*
 * Check that the reply @in answers the question of our own @query: one
 * question, with the same name (letters in any case), QTYPE and QCLASS.
 * Returns 0 when it does, -EINVAL otherwise (RFC 5452 Section 9.1).
 */
int gwdns_check_question(const uint8_t *query, size_t query_len,
			 const uint8_t *in, size_t in_len);

#endif /* #ifndef GWP_DNS_PARSER_H */
