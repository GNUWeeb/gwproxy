#define _DEFAULT_SOURCE
#ifdef RUNTEST
#undef NDEBUG
#endif
#include <endian.h>
#include <stdbool.h>
#include <gwproxy/dns_parser.h>
#include <gwproxy/net.h>

static ssize_t construct_qname(uint8_t *dst, size_t dst_len, const char *qname)
{
	const uint8_t *p = (const uint8_t *)qname;
	uint8_t *lp = dst; /* Length position. */
	uint8_t *sp = lp + 1; /* String position. */
	size_t total = 0;
	uint16_t l = 0;

	while (1) {
		uint8_t c = *p++;

		total++;
		if (total >= dst_len)
			return -ENAMETOOLONG;

		if (c == '.' || c == '\0') {
			if (l < 1 || l > DOMAIN_LABEL_LIMIT)
				return -EINVAL;

			*lp = (uint8_t)l;
			lp = sp++;
			l = 0;
			if (!c)
				break;
		} else {
			l++;
			*sp = c;
			sp++;
		}
	}

	return total;
}

/*
 * Step over a literal (uncompressed) name at @idx, returning the offset just
 * past its terminating zero, or -EINVAL if it runs off the end. A label that
 * turns out to be a compression pointer ends the name too, per RFC 1035
 * Section 4.1.4.
 */
static int skip_literal_name(const uint8_t *in, size_t in_len, size_t idx)
{
	while (idx < in_len) {
		uint8_t len = in[idx];

		if (!len)
			return (int)(idx + 1);

		if (DNS_IS_COMPRESSED((uint16_t)len << 8)) {
			if (idx + 2 > in_len)
				return -EINVAL;
			return (int)(idx + 2);
		}

		if (len > 63)
			return -EINVAL;

		idx += (size_t)len + 1;
	}

	return -EINVAL;
}

static int calculate_question_len(const uint8_t *in, size_t in_len)
{
	const uint8_t *p = in;
	int tot_len, advance_len;

	tot_len = 0;
	while (true) {
		/*
		 * Bound first, dereference second. The other order read *p
		 * after the previous iteration had already stepped past the
		 * end -- a label length byte is up to 255, so one stride was
		 * enough to leave the buffer, and 0xC0 (what a compression
		 * pointer's first byte looks like, which this parser does not
		 * understand) strides 193.
		 */
		if (tot_len >= (int)in_len)
			return -ENOBUFS;

		if (*p == 0x0) {
			tot_len++;
			break;
		}

		advance_len = *p + 1;
		tot_len += advance_len;
		p += advance_len;
	}

	if (tot_len > DOMAIN_NAME_LIMIT)
		return -ENAMETOOLONG;

	tot_len += 4;
	if (tot_len >= (int)in_len)
		return -ENOBUFS;

	return  tot_len;
}

static void put_addr(struct gwp_sockaddr *sa, int family, const uint8_t *rdata,
		     uint16_t port)
{
	memset(sa, 0, sizeof(*sa));
	if (family == AF_INET6) {
		sa->i6.sin6_family = AF_INET6;
		sa->i6.sin6_port = htons(port);
		memcpy(&sa->i6.sin6_addr, rdata, 16);
	} else {
		sa->i4.sin_family = AF_INET;
		sa->i4.sin_port = htons(port);
		memcpy(&sa->i4.sin_addr, rdata, 4);
	}
}

int gwdns_parse_query(uint16_t txid, uint16_t port, const uint8_t *in,
		      size_t in_len, struct gwp_sockaddr *addrs, uint8_t cap,
		      uint8_t *nr_addrs)
{
	uint16_t raw_flags, ancount, i;
	gwdns_header_pkt hdr;
	uint8_t n = 0;
	size_t idx;
	int ret;

	idx = sizeof(hdr);
	if (idx >= in_len)
		return -EAGAIN;

	memcpy(&hdr, in, sizeof(hdr));
	if (memcmp(&txid, &hdr.id, sizeof(txid)))
		return -EINVAL;

	raw_flags = ntohs(hdr.flags);
	/* QR MUST 1 = response from dns server */
	if (!DNS_QR(raw_flags))
		return -EINVAL;

	/* OPCODE MUST 0 = standard query */
	if (DNS_OPCODE(raw_flags))
		return -EINVAL;

	/* RCODE MUST 0 = No error */
	if (DNS_RCODE(raw_flags))
		return -EPROTO;

	/*
	 * TC: the server cut the answer to fit. What is left may end on a
	 * record boundary and look complete, so never use it.
	 */
	if (DNS_TC(raw_flags))
		return -EMSGSIZE;

	ancount = ntohs(hdr.ancount);
	if (!ancount)
		return -ENODATA;

	/*
	 * Check the sizes upfront.
	 *
	 * 1 bytes for variable-length
	 * in[idx] for the length of first name
	 * 1 bytes for null terminator
	 * 2 bytes for qtype
	 * 2 bytes for qclass
	 */
	if ((size_t)(1 + in[idx] + 1 + 2 + 2) >= in_len)
		return -EINVAL;

	ret = calculate_question_len(&in[idx], in_len - idx);
	if (ret <= 0)
		return -EINVAL;

	idx += ret;
	if (idx >= in_len)
		return -EAGAIN;

	for (i = 0; i < ancount; i++) {
		uint16_t w, type, rdlength;

		if (idx + 2 > in_len)
			return -EAGAIN;

		memcpy(&w, &in[idx], 2);
		if (DNS_IS_COMPRESSED(ntohs(w))) {
			idx += 2; // NAME
		} else {
			/*
			 * Compression is an option, not an obligation
			 * (RFC 1035 Section 4.1.4): a responder may write the
			 * owner name out in full, and plenty do. A label
			 * length is 0..63, so its top two bits are always
			 * clear and this arm is what a literal name takes.
			 */
			ret = skip_literal_name(in, in_len, idx);
			if (ret < 0)
				return ret;
			idx = (size_t)ret;
		}

		/*
		 * TYPE, CLASS, TTL and RDLENGTH: ten bytes, all of which
		 * must be there before any is read.
		 */
		if (idx > in_len || in_len - idx < 10)
			return -EAGAIN;

		memcpy(&type, &in[idx], 2);
		type = ntohs(type);
		memcpy(&rdlength, &in[idx + 8], 2);
		rdlength = ntohs(rdlength);
		idx += 10;

		/*
		 * @rdlength is 16 bits of whatever the responder sent, so
		 * check it against what is left before moving by it.
		 */
		if (rdlength > in_len - idx)
			return -EINVAL;

		switch (type) {
		case TYPE_A:
			if (rdlength != 4)
				return -EINVAL;
			if (n < cap)
				put_addr(&addrs[n++], AF_INET, &in[idx], port);
			break;
		case TYPE_AAAA:
			if (rdlength != 16)
				return -EINVAL;
			if (n < cap)
				put_addr(&addrs[n++], AF_INET6, &in[idx], port);
			break;
		case TYPE_CNAME:
			break;
		default:
			return -EINVAL;
		}

		idx += rdlength;
	}

	if (!n)
		return -ENODATA;

	*nr_addrs = n;
	return 0;
}

static ssize_t construct_question(gwdns_question_part *question)
{
	gwdns_header_pkt *hdr;
	gwdns_query_pkt pkt;
	uint16_t qtype, qclass;
	size_t required_len;
	ssize_t bw;

	switch (question->type) {
	case AF_INET6:
		question->type = TYPE_AAAA;
		break;
	case AF_INET:
		question->type = TYPE_A;
		break;
	default:
		return -EINVAL;
	}

	hdr = &pkt.hdr;
	/*
	* the memset implicitly set opcode to OPCODE_QUERY
	*/
	memset(hdr, 0, sizeof(*hdr));
	/*
	 * no need to htons, so no ntohs for comparison in gwdns_parse_query().
	 */
	hdr->id = question->txid;
	DNS_SET_RD(hdr->flags, true);
	hdr->flags = htons(hdr->flags);
	hdr->qdcount = htons(1);
	hdr->arcount = htons(1);	/* the OPT record below */

	/*
	* pkt.body is interpreted as question section
	* for layout and format, see RFC 1035 4.1.2. Question section format
	*/
	bw = construct_qname(pkt.body, sizeof(pkt.body) - 3, question->domain);
	if (bw < 0)
		return bw;

	pkt.body[bw++] = 0x0;
	qtype = htons(question->type);
	qclass = htons(CLASS_IN);
	memcpy(&pkt.body[bw], &qtype, 2);
	bw += 2;
	memcpy(&pkt.body[bw], &qclass, 2);
	bw += 2;

	/*
	 * EDNS0 OPT record (RFC 6891): root owner name, TYPE 41, CLASS is
	 * the UDP payload size we accept, TTL (extended RCODE, version,
	 * flags) and RDLENGTH zero. Without it a server cuts any answer
	 * over 512 bytes and sets TC.
	 */
	if ((size_t)bw + 11 > sizeof(pkt.body))
		return -ENAMETOOLONG;
	{
		static const uint8_t opt[11] = {
			0x00,				/* NAME: root */
			0x00, TYPE_OPT,			/* TYPE */
			DNS_EDNS_UDP_SIZE >> 8,		/* CLASS: size */
			DNS_EDNS_UDP_SIZE & 0xff,
			0x00, 0x00, 0x00, 0x00,		/* TTL */
			0x00, 0x00,			/* RDLENGTH */
		};

		memcpy(&pkt.body[bw], opt, sizeof(opt));
		bw += sizeof(opt);
	}

	required_len = sizeof(pkt.hdr) + bw;
	if (question->dst_len < required_len)
		return -ENOBUFS;

	memcpy(question->dst_buffer, &pkt, required_len);

	return required_len;
}

ssize_t gwdns_build_query(uint16_t txid, const char *name, int family, uint8_t *out, size_t out_len)
{
	gwdns_question_part q;

	q.domain = name;
	q.type = family;
	q.txid = txid;
	q.dst_buffer = out;
	q.dst_len = out_len;
	return construct_question(&q);
}

static uint8_t ascii_lower(uint8_t c)
{
	return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + ('a' - 'A')) : c;
}

int gwdns_check_question(const uint8_t *query, size_t query_len,
			 const uint8_t *in, size_t in_len)
{
	size_t i, end, hdr = sizeof(gwdns_header_pkt);
	uint16_t qdcount;
	int qlen;

	if (query_len <= hdr || in_len <= hdr)
		return -EINVAL;

	memcpy(&qdcount, &in[4], sizeof(qdcount));
	if (ntohs(qdcount) != 1)
		return -EINVAL;

	/* Our own query: a literal name, then QTYPE and QCLASS. */
	qlen = calculate_question_len(&query[hdr], query_len - hdr);
	if (qlen <= 0 || hdr + (size_t)qlen > in_len)
		return -EINVAL;

	end = hdr + (size_t)qlen - 4;
	for (i = hdr; i < end;) {
		uint8_t l = query[i];
		size_t lend = i + 1 + l;

		/* Label lengths as sent; a pointer here is not our name. */
		if (in[i] != l)
			return -EINVAL;
		/* Names compare without regard to case (RFC 4343). */
		for (i++; i < lend; i++) {
			if (ascii_lower(in[i]) != ascii_lower(query[i]))
				return -EINVAL;
		}
	}

	return memcmp(&in[end], &query[end], 4) ? -EINVAL : 0;
}

#ifdef RUNTEST

static void test_parse_ipv4(void)
{
	struct gwp_sockaddr addrs[8];
	uint8_t nr, i;
	uint16_t txid;

	uint8_t recv_pkt[] = {
		0x23, 0xc6, 0x81, 0x80, 0x00, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00,
		0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
		0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x35, 0x00, 0x04, 0x4a, 0x7d, 0x18, 0x8a, 0xc0, 0x0c, 0x00, 0x01,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x35, 0x00, 0x04, 0x4a, 0x7d, 0x18, 0x66,
		0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x35, 0x00, 0x04,
		0x4a, 0x7d, 0x18, 0x64, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x35, 0x00, 0x04, 0x4a, 0x7d, 0x18, 0x8b, 0xc0, 0x0c, 0x00, 0x01,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x35, 0x00, 0x04, 0x4a, 0x7d, 0x18, 0x65,
		0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x35, 0x00, 0x04,
		0x4a, 0x7d, 0x18, 0x71
	};

	memcpy(&txid, recv_pkt, 2);
	assert(!gwdns_parse_query(txid, 80, recv_pkt, sizeof(recv_pkt), addrs, 8, &nr));
	assert(nr == 6);
	for (i = 0; i < nr; i++) {
		char buff[FULL_ADDRSTRLEN];

		assert(addrs[i].sa.sa_family == AF_INET);
		convert_ssaddr_to_str(buff, &addrs[i]);
		printf("IPv4: %s\n", buff);
	}
}

static void test_parse_ipv6(void)
{
	struct gwp_sockaddr addrs[8];
	uint8_t nr, i;
	uint16_t txid;

	uint8_t recv_pkt[] = {
		0x45, 0x67,
		0x81, 0x80,
		0x00, 0x01,
		0x00, 0x04,
		0x00, 0x00,
		0x00, 0x00,

		0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
		0x03, 0x63, 0x6f, 0x6d,
		0x00,
		0x00, 0x1c,
		0x00, 0x01,

		0xc0, 0x0c,
		0x00, 0x1c,
		0x00, 0x01,
		0x00, 0x00, 0x09, 0x06,
		0x00, 0x10,
		0x24, 0x04, 0x68, 0x00, 0x40, 0x03, 0x0c, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71,

		0xc0, 0x0c,
		0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x09, 0x06,
		0x00, 0x10,
		0x24, 0x04, 0x68, 0x00, 0x40, 0x03, 0x0c, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8a,

		0xc0, 0x0c,
		0x00, 0x1c,
		0x00, 0x01,
		0x00, 0x00, 0x09, 0x06,
		0x00, 0x10,
		0x24, 0x04, 0x68, 0x00, 0x40, 0x03, 0x0c, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65,

		0xc0, 0x0c,
		0x00, 0x1c,
		0x00, 0x01,
		0x00, 0x00, 0x0c, 0x16,
		0x00, 0x10,
		0x24, 0x04, 0x68, 0x00, 0x40, 0x03, 0x0c, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71
	};

	memcpy(&txid, recv_pkt, sizeof(txid));

	assert(!gwdns_parse_query(txid, 80, recv_pkt, sizeof(recv_pkt), addrs, 8, &nr));
	assert(nr == 4);
	for (i = 0; i < nr; i++) {
		char buff[FULL_ADDRSTRLEN];

		assert(addrs[i].sa.sa_family == AF_INET6);
		convert_ssaddr_to_str(buff, &addrs[i]);
		printf("IPv6: %s\n", buff);
	}
}

static void test_build_ipv4(void)
{
	uint8_t buff[UDP_MSG_LIMIT];
	gwdns_header_pkt *hdr;
	uint16_t c;
	ssize_t r;

	c = 0xFFFF;
	r = gwdns_build_query(c, "google.com", AF_INET, buff, sizeof(buff));
	assert(r > 0);

	hdr = (void *)buff;
	assert(ntohs(hdr->qdcount) == 1);
	assert(!hdr->nscount);
	assert(!DNS_QR(hdr->flags));
	assert(DNS_OPCODE(hdr->flags) == OPCODE_QUERY);
	c = htons(TYPE_A);
	assert(!memcmp(buff + 12 + 12, &c, 2));
}

static void test_build_ipv6(void)
{
	uint8_t buff[UDP_MSG_LIMIT];
	gwdns_header_pkt *hdr;
	uint16_t c;
	ssize_t r;

	c = 0xFFFF;
	r = gwdns_build_query(c, "google.com", AF_INET6, buff, sizeof(buff));
	assert(r > 0);

	hdr = (void *)buff;
	assert(ntohs(hdr->qdcount) == 1);
	assert(!hdr->nscount);
	assert(!DNS_QR(hdr->flags));
	assert(DNS_OPCODE(hdr->flags) == OPCODE_QUERY);
	c = htons(TYPE_AAAA);
	assert(!memcmp(buff + 12 + 12, &c, 2));
}

/*
 * test mock data of recv in both IPv4 and IPv6
 *
 * the mock data are produced by this script:
 * https://gist.github.com/realyukii/d7b450b4ddc305c66a2d8cd5600f23c4
 */
/*
 * A reply with more addresses than the caller has room for: the extra ones
 * are checked but dropped, and a reply cut short anywhere is refused.
 */
static void test_parse_cap_and_truncation(void)
{
	uint8_t pkt[] = {
		0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
		0x01, 'a', 0x01, 'b', 0x00, 0x00, 0x01, 0x00, 0x01,
		0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
		10, 0, 0, 1,
		0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
		10, 0, 0, 2,
		0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
		10, 0, 0, 3,
	};
	struct gwp_sockaddr addrs[2];
	uint16_t txid;
	uint8_t nr;
	size_t len;

	memcpy(&txid, pkt, 2);
	assert(!gwdns_parse_query(txid, 443, pkt, sizeof(pkt), addrs, 2, &nr));
	assert(nr == 2);
	assert(addrs[0].i4.sin_addr.s_addr == htonl(0x0a000001));
	assert(addrs[1].i4.sin_addr.s_addr == htonl(0x0a000002));
	assert(addrs[1].i4.sin_port == htons(443));

	/* Every shorter prefix fails, and none reads past its end (ASan). */
	for (len = 0; len < sizeof(pkt); len++) {
		uint8_t *cut = malloc(len ? len : 1);

		assert(cut);
		memcpy(cut, pkt, len);
		assert(gwdns_parse_query(txid, 443, cut, len, addrs, 2, &nr));
		free(cut);
	}
}

/*
 * Only a reply about the name, type and class we asked for is ours; the
 * name may come back in another case.
 */
static void test_check_question(void)
{
	uint8_t query[512], reply[512];
	ssize_t qlen;
	size_t rlen;

	qlen = gwdns_build_query(0x1234, "ab.Example", AF_INET, query,
				 sizeof(query));
	assert(qlen > 12);

	/* The reply echoes the question: header, then name + type + class. */
	memcpy(reply, query, 12 + 12 + 4);
	reply[2] = 0x81;
	reply[3] = 0x80;
	rlen = 12 + 12 + 4;
	assert(!gwdns_check_question(query, (size_t)qlen, reply, rlen));

	reply[13] = 'A';		/* "Ab.Example": case only */
	assert(!gwdns_check_question(query, (size_t)qlen, reply, rlen));
	reply[18] = 'x';		/* "Ab.Exxmple" */
	assert(gwdns_check_question(query, (size_t)qlen, reply, rlen));
	reply[18] = 'A';		/* "Ab.ExAmple": case only */
	assert(!gwdns_check_question(query, (size_t)qlen, reply, rlen));

	reply[12 + 12 + 1] = 28;	/* QTYPE AAAA */
	assert(gwdns_check_question(query, (size_t)qlen, reply, rlen));
	reply[12 + 12 + 1] = 1;

	reply[5] = 2;			/* QDCOUNT 2 */
	assert(gwdns_check_question(query, (size_t)qlen, reply, rlen));
	reply[5] = 1;

	/* Cut short anywhere before the class ends. */
	for (rlen = 0; rlen < 12 + 12 + 4; rlen++)
		assert(gwdns_check_question(query, (size_t)qlen, reply, rlen));
}

static void run_all_tests(void)
{
	/*
	 * We can't use gwdns_parse_query() to parse multiple response at once.
	 * The caller MUST call gwdns_parse_query() more than one time if there's
	 * more than one response, because txid is passed to only verify one
	 * response.
	 */
	fprintf(stderr, "test constructing DNS standard query packet for TYPE_A!\n");
	test_build_ipv4();
	fprintf(stderr, "test constructing DNS standard query packet for TYPE_AAAA!\n");
	test_build_ipv6();
	fprintf(stderr, "test parsing DNS standard query packet for TYPE_A!\n");
	test_parse_ipv4();
	fprintf(stderr, "test parsing DNS standard query packet for TYPE_AAAA!\n");
	test_parse_ipv6();
	test_parse_cap_and_truncation();
	test_check_question();
	fprintf(stderr, "all tests passed!\n");
}

int main(void)
{
	run_all_tests();
	return 0;
}

#endif
