#define _DEFAULT_SOURCE
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

static int calculate_question_len(uint8_t *in, size_t in_len)
{
	const uint8_t *p = in;
	int tot_len, advance_len;

	tot_len = 0;
	while (true) {
		if (*p == 0x0) {
			tot_len++;
			break;
		}

		if (tot_len >= (int)in_len)
			return -ENOBUFS;

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

static int serialize_answ(uint16_t txid, uint8_t *in, size_t in_len, gwdns_answ_data *out)
{
	gwdns_header_pkt *hdr;
	uint16_t raw_flags;
	size_t idx, i;
	void *ptr;
	int ret;

	idx = sizeof(*hdr);
	if (idx >= in_len)
		return -EAGAIN;

	hdr = (void *)in;
	if (memcmp(&txid, &hdr->id, sizeof(txid)))
		return -EINVAL;

	memcpy(&raw_flags, &hdr->flags, sizeof(raw_flags));
	raw_flags = ntohs(raw_flags);
	/* QR MUST 1 = response from dns server */
	if (!DNS_QR(raw_flags))
		return -EINVAL;

	/* OPCODE MUST 0 = standard query */
	if (DNS_OPCODE(raw_flags))
		return -EINVAL;

	/* RCODE MUST 0 = No error */
	if (DNS_RCODE(raw_flags))
		return -EPROTO;

	// is it safe or recommended to alter the in buffer directly?
	hdr->ancount = ntohs(hdr->ancount);
	if (!hdr->ancount)
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

	out->hdr.ancount = 0;
	ptr = malloc(hdr->ancount * sizeof(uint8_t *));
	if (!ptr)
		return -ENOMEM;

	out->rr_answ = ptr;
	for (i = 0; i < hdr->ancount; i++) {
		uint16_t is_compressed, rdlength;
		gwdns_serialized_answ *item = malloc(sizeof(gwdns_serialized_answ));
		if (!item) {
			ret = -ENOMEM;
			goto exit_free;
		}

		memcpy(&is_compressed, &in[idx], sizeof(is_compressed));
		is_compressed = ntohs(is_compressed);
		is_compressed = DNS_IS_COMPRESSED(is_compressed);
		assert(is_compressed);
		idx += 2; // NAME
		if (idx >= in_len) {
			ret = -EAGAIN;
			free(item);
			goto exit_free;
		}

		memcpy(&item->rr_type, &in[idx], 2);
		item->rr_type = ntohs(item->rr_type);
		idx += 2; // TYPE
		if (idx >= in_len) {
			ret = -EAGAIN;
			free(item);
			goto exit_free;
		}
		memcpy(&item->rr_class, &in[idx], 2);
		item->rr_class = ntohs(item->rr_class);
		idx += 2; // CLASS
		if (idx >= in_len) {
			ret = -EAGAIN;
			free(item);
			goto exit_free;
		}
		memcpy(&item->ttl, &in[idx], 4);
		item->ttl = be32toh(item->ttl);
		idx += 4; // TTL
		if (idx >= in_len) {
			ret = -EAGAIN;
			free(item);
			goto exit_free;
		}

		memcpy(&rdlength, &in[idx], sizeof(rdlength));
		rdlength = ntohs(rdlength);
		switch (item->rr_type) {
		case TYPE_AAAA:
			if (rdlength != sizeof(struct in6_addr)) {
				ret = -EINVAL;
				free(item);
				goto exit_free;
			}
			break;
		case TYPE_A:
			if (rdlength != sizeof(struct in_addr)) {
				ret = -EINVAL;
				free(item);
				goto exit_free;
			}
			break;
		case TYPE_CNAME:
			idx += 2 + rdlength;
			free(item);
			continue;

		default:
			ret = -EINVAL;
			free(item);
			goto exit_free;
			break;
		}

		item->rdlength = rdlength;
		idx += 2;
		if (idx >= in_len) {
			ret = -EAGAIN;
			free(item);
			goto exit_free;
		}

		ptr = malloc(rdlength);
		if (!ptr) {
			ret = -ENOMEM;
			free(item);
			goto exit_free;
		}

		memcpy(ptr, &in[idx], rdlength);
		idx += rdlength;
		if (idx > in_len) {
			ret = -EINVAL;
			free(item);
			free(ptr);
			goto exit_free;
		}

		item->rdata = ptr;
		out->rr_answ[out->hdr.ancount] = item;
		out->hdr.ancount++;
	}

	if (!out->hdr.ancount) {
		free(out->rr_answ);
		return -ENODATA;
	}

	return 0;
exit_free:
	for (i = 0; i < out->hdr.ancount; i++) {
		free(out->rr_answ[i]->rdata);
		free(out->rr_answ[i]);
	}
	free(out->rr_answ);
	return ret;
}

static void free_serialize_answ(gwdns_answ_data *answ)
{
	size_t i;
	for (i = 0; i < answ->hdr.ancount; i++) {
		free(answ->rr_answ[i]->rdata);
		free(answ->rr_answ[i]);
	}
	free(answ->rr_answ);
}

int gwdns_parse_query(uint16_t txid, const char *service,
			uint8_t *in, size_t in_len,
			struct gwdns_addrinfo_node **ai)
{
	struct gwdns_addrinfo_node *results, *tail;
	gwdns_answ_data raw_answ;
	int r, port;
	size_t i;

	port = atoi(service);
	if (port < 0)
		return -EINVAL;
	port = htons(port);

	r = serialize_answ(txid, in, in_len, &raw_answ);
	if (r)
		return r;

	results = tail = NULL;
	for (i = 0; i < raw_answ.hdr.ancount; i++) {
		struct gwdns_addrinfo_node *new_node;
		gwdns_serialized_answ *answ;
		struct sockaddr_in6 *i6;
		struct sockaddr_in *i4;

		answ = raw_answ.rr_answ[i];
		new_node = malloc(sizeof(*new_node));
		if (!new_node) {
			r = -ENOMEM;
			goto exit_free;
		}
		new_node->ai_next = NULL;

		if (answ->rr_type == TYPE_AAAA) {
			i6 = &new_node->ai_addr.i6;
			new_node->ai_family = AF_INET6;
			new_node->ai_addrlen = sizeof(i6);
			i6->sin6_port = port;
			i6->sin6_family = AF_INET6;
			assert(sizeof(i6->sin6_addr) == answ->rdlength);
			memcpy(&i6->sin6_addr, answ->rdata, answ->rdlength);
		} else {
			i4 = &new_node->ai_addr.i4;
			new_node->ai_family = AF_INET;
			new_node->ai_addrlen = sizeof(i4);
			i4->sin_port = port;
			i4->sin_family = AF_INET;
			assert(sizeof(i4->sin_addr) == answ->rdlength);
			memcpy(&i4->sin_addr, answ->rdata, answ->rdlength);
			new_node->ai_ttl = answ->ttl;
		}

		if (!tail)
			results = new_node;
		else
			tail->ai_next = new_node;
		tail = new_node;
	}

	*ai = results;
	r = 0;
exit_free:
	if (r && results)
		gwdns_free_parsed_query(results);
	free_serialize_answ(&raw_answ);
	return r;
}

void gwdns_free_parsed_query(struct gwdns_addrinfo_node *ai)
{
	struct gwdns_addrinfo_node *tmp, *node = ai;
	while (node) {
		tmp = node->ai_next;
		free(node);
		node = tmp;
	}
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
	 * no need to htons, so no ntohs for comparison in serialize_answ.
	 */
	hdr->id = question->txid;
	DNS_SET_RD(hdr->flags, true);
	hdr->flags = htons(hdr->flags);
	hdr->qdcount = htons(1);

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

#ifdef RUNTEST

void test_parse_ipv4(void)
{
	struct gwdns_addrinfo_node *d, *node;
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
	d = NULL;
	assert(!gwdns_parse_query(txid, "80", recv_pkt, sizeof(recv_pkt), &d));
	assert(d);
	node = d;
	while (node) {
		struct gwdns_addrinfo_node *tmp;
		char buff[FULL_ADDRSTRLEN];

		tmp = node->ai_next;
		assert(node->ai_family == AF_INET);
		convert_ssaddr_to_str(buff, &node->ai_addr);
		printf("IPv4: %s\n", buff);
		node = tmp;
	}

	gwdns_free_parsed_query(d);
}

void test_parse_ipv6(void)
{
	struct gwdns_addrinfo_node *d, *node;
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

	node = NULL;
	assert(!gwdns_parse_query(txid, "80", recv_pkt, sizeof(recv_pkt), &d));
	assert(d);
	node = d;
	while (node) {
		struct gwdns_addrinfo_node *tmp;
		char buff[FULL_ADDRSTRLEN];

		tmp = node->ai_next;
		assert(node->ai_family == AF_INET6);
		convert_ssaddr_to_str(buff, &node->ai_addr);
		printf("IPv6: %s\n", buff);
		node = tmp;
	}

	gwdns_free_parsed_query(d);
}

void test_build_ipv4(void)
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

void test_build_ipv6(void)
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
void run_all_tests(void)
{
	/*
	 * We can't use serialize_answ to parse multiple response at once.
	 * The caller MUST call serialize_answ more than one time if there's
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
	fprintf(stderr, "all tests passed!\n");
}

int main(void)
{
	run_all_tests();
	return 0;
}

#endif
