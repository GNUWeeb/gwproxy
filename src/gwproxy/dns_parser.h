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
#define DNS_IS_COMPRESSED(mask) ((mask) & DNS_COMPRESSION_BIT)

/* Flag construction macros for little-endian machine */
#define DNS_SET_RD(flags, val)	(flags) = ((flags) & ~(1 << DNS_RD_BIT)) | ((!!(val)) << DNS_RD_BIT)

/* as per RFC 1035 §2.3.4. Size limits */
#define DOMAIN_LABEL_LIMIT 63
#define DOMAIN_NAME_LIMIT 255
#define UDP_MSG_LIMIT 512

typedef enum {
	OPCODE_QUERY	= 0,	// Standard query (QUERY)
} gwdns_op;

typedef enum {
	TYPE_A		= 1,	// IPv4 host address
	TYPE_CNAME	= 5,	// the canonical name for an alias
	TYPE_AAAA	= 28,	// IPv6 host address
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

/*
 * 4.1.3. Resource record format
 *
 * The answer, authority, and additional sections all share the same
 * format: a variable number of resource records, where the number of
 * records is specified in the corresponding count field in the header.
 */
typedef struct {
	uint8_t  *name;		// DOMAIN NAME: variable‑length sequence of labels (length-byte followed by label, ending in 0), possibly compressed
	uint16_t  rr_type;	// TYPE: two-octet code identifying the RR type (see gwdns_type)
	uint16_t  rr_class;	// CLASS: two-octet code identifying the RR class (see gwdns_class)
	uint32_t  ttl;		// TTL: 32-bit unsigned, time to live in seconds
	uint16_t  rdlength;	// RDLENGTH: length in octets of RDATA
	uint8_t  *rdata;	// RDATA: variable-length data, format depends on TYPE and CLASS
} gwdns_serialized_rr;

typedef struct {
	char qname[DOMAIN_NAME_LIMIT];
	uint16_t qtype;
	uint16_t qclass;
} gwdns_serialized_question;

typedef gwdns_serialized_rr gwdns_serialized_answ;

typedef struct {
	gwdns_header_pkt hdr;
	uint8_t body[UDP_MSG_LIMIT];
} gwdns_query_pkt;

typedef struct {
	gwdns_header_pkt hdr;
	gwdns_serialized_question question;
	gwdns_serialized_answ **rr_answ;
} gwdns_answ_data;

struct gwdns_addrinfo_node {
	int				ai_family;
	int				ai_ttl;
	socklen_t			ai_addrlen;
	struct gwp_sockaddr		ai_addr;
	struct gwdns_addrinfo_node	*ai_next;
};

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
 * Parse name server's answer
 *
 * Possible errors are:
 * -EAGAIN	in buffer is not sufficient, no bytes are processed, need more data.
 * -EINVAL	the content of in buffer is not valid.
 * -ENOMEM	failed to allocate dynamic memory.
 * -ENODATA	the packet didn't contain any answers.
 * -EPROTO	the DNS server can't understand your question
 *
 * @param txid		transaction id of question
 * @param service	port number in ascii
 * @param in		a pointer to buffer that need to be parsed
 * @param in_len	a pointer to buffer that need to be parsed
 * @param ai		a pointer to address info
 * @return		zero on success or a negative number on failure
 */
int gwdns_parse_query(uint16_t txid, const char *service,
			uint8_t *in, size_t in_len,
			struct gwdns_addrinfo_node **ai);
void gwdns_free_parsed_query(struct gwdns_addrinfo_node *addrinfo);

#endif /* #ifndef GWP_DNS_PARSER_H */
