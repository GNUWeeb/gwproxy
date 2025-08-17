// SPDX-License-Identifier: GPL-2.0-only
/*
 * gwnet_http1.h - HTTP/1.0 and HTTP/1.1 parser.
 *
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWNET_HTTP1_H
#define GWNET_HTTP1_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

enum {
	GWNET_HTTP_HDR_TYPE_REQ	= 0,
	GWNET_HTTP_HDR_TYPE_RES	= 1,
};

enum {
	GWNET_HTTP_HDR_PARSE_ST_INIT		= 0,
	GWNET_HTTP_HDR_PARSE_ST_FIRST_LINE	= 1,
	GWNET_HTTP_HDR_PARSE_ST_FIELDS		= 2,
	GWNET_HTTP_HDR_PARSE_ST_DONE		= 3,
};

enum {
	GWNET_HTTP_HDR_ERR_NONE		= 0,
	GWNET_HTTP_HDR_ERR_INCOMPLETE	= 1,
	GWNET_HTTP_HDR_ERR_MALFORMED	= 2,
	GWNET_HTTP_HDR_ERR_TOO_LONG	= 3,
	GWNET_HTTP_HDR_ERR_INTERNAL	= 100,
};

enum {
	GWNET_HTTP_VER_UNKNOWN	= 0,
	GWNET_HTTP_VER_1_0	= 1,
	GWNET_HTTP_VER_1_1	= 2,
};

enum {
	GWNET_HTTP_METHOD_UNKNOWN	= 0,
	GWNET_HTTP_METHOD_GET		= 1,
	GWNET_HTTP_METHOD_POST		= 2,
	GWNET_HTTP_METHOD_PUT		= 3,
	GWNET_HTTP_METHOD_DELETE	= 4,
	GWNET_HTTP_METHOD_HEAD		= 5,
	GWNET_HTTP_METHOD_OPTIONS	= 6,
	GWNET_HTTP_METHOD_PATCH		= 7,
	GWNET_HTTP_METHOD_TRACE		= 8,
	GWNET_HTTP_METHOD_CONNECT	= 9,
};

struct gwnet_http_hdr_field {
	char	*key;
	char	*val;
};

struct gwnet_http_hdr_fields {
	struct gwnet_http_hdr_field	*ff;
	size_t				nr;
};

struct gwnet_http_req_hdr {
	uint8_t		method;
	uint8_t		version;
	char		*path;
	char		*uri;
	char		*qs;

	struct gwnet_http_hdr_fields fields;
};

struct gwnet_http_res_hdr {
	uint8_t		version;
	uint16_t	code;
	char		*reason;

	struct gwnet_http_hdr_fields fields;
};

struct gwnet_http_hdr_pctx {

	/*
	 * Internally used to track the state of the parsing
	 * operation.
	 */
	uint8_t		state;

	/*
	 * Filled by the parser to indicate the error reason
	 * if the parsing operation fails. The caller may
	 * check this field if the parser returns a negative
	 * value.
	 */
	uint8_t		err;

	/*
	 * Filled by the caller to pass the buffer to be parsed.
	 */
	const char	*buf;

	/*
	 * Filled by the caller to pass the length of the buffer
	 * to be parsed. This is the total length of the buffer
	 * passed in @buf.
	 */
	uint64_t	len;

	/*
	 * Initially set to zero, it will be filled with the length
	 * of the number of bytes that have successfully been
	 * parsed from the buffer. Partially parsed headers will
	 * return -EAGAIN and advance this offset.
	 *
	 * The caller must reset this to zero before continuing the
	 * parsing operation. In that case, the buffer must be
	 * advanced to the next unparsed byte.
	 */
	uint64_t	off;


	/*
	 * Total length of the header section being parsed.
	 * Accumulated from the first line and all header fields.
	 * This is internally used by the parser to determine if the
	 * total length of the header section exceeds the maximum
	 * length.
	 */
	uint64_t	tot_len;

	/*
	 * Filled by the caller to limit the maximum length of the
	 * request or response line. If set to 0, the maximum length
	 * will be set to default by the parser (16384 bytes).
	 */
	uint64_t	max_len;
};

enum {
	GWNET_HTTP_BODY_ERR_NONE		= 0,
	GWNET_HTTP_BODY_ERR_INCOMPLETE		= 1,
	GWNET_HTTP_BODY_ERR_MALFORMED		= 2,
	GWNET_HTTP_BODY_ERR_TOO_LONG		= 3,
	GWNET_HTTP_BODY_ERR_DST_TOO_SMALL	= 4,
	GWNET_HTTP_BODY_ERR_INTERNAL		= 100,
};

enum {
	GWNET_HTTP_BODY_PARSE_ST_INIT		= 0,
	GWNET_HTTP_BODY_PARSE_ST_CHK_LEN	= 1,
	GWNET_HTTP_BODY_PARSE_ST_CHK_DATA	= 2,
	GWNET_HTTP_BODY_PARSE_ST_CHK_TR		= 3,
	GWNET_HTTP_BODY_PARSE_ST_CHK_DONE	= 4,
};

struct gwnet_http_body_pctx {
	/*
	 * Internally used to track the state of the parsing
	 * operation.
	 */
	uint8_t		state;

	/*
	 * Filled by the parser to indicate the error reason
	 * if the parsing operation fails. The caller may
	 * check this field if the parser returns a negative
	 * value.
	 */
	uint8_t		err;

	/*
	 * Internally used to track the end of the chunked
	 * transfer encoding parsing.
	 */
	bool		found_zero_len;

	/*
	 * Filled by the caller to pass the buffer to be parsed.
	 * This is the raw HTTP body data.
	 */
	const char	*buf;

	/*
	 * Filled by the caller to pass the length of the buffer
	 * to be parsed. This is the total length of the buffer
	 * passed in @buf.
	 */
	uint64_t	len;

	/*
	 * Initially set to zero, it will be filled with the length
	 * of the number of bytes that have successfully been
	 * parsed from the buffer. Partially parsed body will
	 * return -EAGAIN and advance this offset.
	 *
	 * The caller must reset this to zero before continuing the
	 * parsing operation. In that case, the buffer must be
	 * advanced to the next unparsed byte.
	 */
	uint64_t	off;

	/*
	 * Length of the remaining data to be parsed in the current
	 * chunk. This is used to track how many bytes are left to
	 * read in the current chunked transfer encoding.
	 */
	uint64_t	rem_len;

	/*
	 * Total accumulated length of the all chunks parsed so far.
	 */
	uint64_t	tot_len;

	/*
	 * Total accumulated length of the parsed bytes. This includes
	 * the chunked hex length, chunk extension, and the chunk data,
	 * trailing CRLF, and the final zero-length chunk.
	 *
	 * The @max_len field will be checked against this value to
	 * determine if the total length of the body exceeds the
	 * maximum length allowed by the parser. If it does, the
	 * parser will return -E2BIG.
	 */
	uint64_t	tot_len_raw;

	/*
	 * Filled by the caller to limit the maximum length of the
	 * body being parsed. If set to 0, the maximum length
	 * will be set to default by the parser (128 KiB).
	 */
	uint64_t	max_len;
};

/**
 * Initialize the HTTP header parsing context.
 *
 * Prepare the given gwnet_http_hdr_pctx structure for use in HTTP
 * header parsing operations.
 *
 * @param ctx Pointer to a gwnet_http_hdr_pctx structure to initialize.
 *            Must not be NULL.
 * @return 0 on success, or a negative value on failure.
 */
int gwnet_http_hdr_pctx_init(struct gwnet_http_hdr_pctx *ctx);

/**
 * Free resources associated with the HTTP header parsing context.
 *
 * This function releases any memory or resources held by the specified
 * gwnet_http_hdr_pctx structure. After calling this function, the context
 * should not be used unless re-initialized.
 *
 * @param ctx Pointer to a gwnet_http_hdr_pctx structure to free.
 *            Must not be NULL.
 */
void gwnet_http_hdr_pctx_free(struct gwnet_http_hdr_pctx *ctx);

/**
 * Parses an HTTP request header from the given parsing context.
 *
 * @param ctx  Pointer to the HTTP header parsing context.
 * @param hdr  Pointer to the structure where the parsed HTTP request
 *             header will be stored.
 * @return     0 on success,
 *             -EAGAIN if more data is needed,
 *             -EINVAL if the request line is malformed,
 *             -ENOMEM if memory allocation fails.
 */
int gwnet_http_req_hdr_parse(struct gwnet_http_hdr_pctx *ctx,
			     struct gwnet_http_req_hdr *hdr);

/**
 * Parses an HTTP response header from the given parsing context.
 *
 * @param ctx  Pointer to the HTTP header parsing context.
 * @param hdr  Pointer to the structure where the parsed HTTP response
 *             header will be stored.
 * @return     0 on success,
 *             -EAGAIN if more data is needed,
 *             -EINVAL if the response line is malformed,
 *             -ENOMEM if memory allocation fails.
 */
int gwnet_http_res_hdr_parse(struct gwnet_http_hdr_pctx *ctx,
			     struct gwnet_http_res_hdr *hdr);

void gwnet_http_req_hdr_free(struct gwnet_http_req_hdr *hdr);
void gwnet_http_res_hdr_free(struct gwnet_http_res_hdr *hdr);

/**
 * Free all memory associated with the given HTTP header fields
 * structure.
 *
 * @param ff Pointer to the HTTP header fields structure to free.
 */
void gwnet_http_hdr_fields_free(struct gwnet_http_hdr_fields *ff);

/**
 * Add a header field with the specified key and value to the HTTP
 * header fields structure.
 *
 * @param ff Pointer to the HTTP header fields structure.
 * @param k  Null-terminated string containing the header key.
 * @param v  Null-terminated string containing the header value.
 * @return   0 on success, or a negative value on error.
 */
int gwnet_http_hdr_fields_add(struct gwnet_http_hdr_fields *ff, const char *k,
			      const char *v);

/**
 * Add a header field with the specified key and a formatted value to
 * the HTTP header fields structure.
 *
 * @param ff  Pointer to the HTTP header fields structure.
 * @param k   Null-terminated string containing the header key.
 * @param fmt printf-style format string for the header value.
 * @param ... Arguments for the format string.
 * @return    0 on success, or a negative value on error.
 */
__attribute__((__format__(printf, 3, 4)))
int gwnet_http_hdr_fields_addf(struct gwnet_http_hdr_fields *ff,
			       const char *k, const char *fmt, ...);

/**
 * Add a header field with the specified key and value, using explicit
 * lengths for both key and value.
 *
 * @param ff   Pointer to the HTTP header fields structure.
 * @param k    Pointer to the header key.
 * @param klen Length of the header key.
 * @param v    Pointer to the header value.
 * @param vlen Length of the header value.
 * @return     0 on success, or a negative value on error.
 */
int gwnet_http_hdr_fields_addl(struct gwnet_http_hdr_fields *ff,
			       const char *k, size_t klen, const char *v,
			       size_t vlen);

/**
 * Retrieve the value of a header field by its key from the HTTP
 * header fields structure.
 *
 * @param ff Pointer to the HTTP header fields structure.
 * @param k  Null-terminated string containing the header key.
 * @return   Pointer to the header value, or NULL if not found.
 */
const char *gwnet_http_hdr_fields_get(const struct gwnet_http_hdr_fields *ff,
				      const char *k);

/**
 * Retrieve the value of a header field by its key, using an explicit
 * key length, from the HTTP header fields structure.
 *
 * @param ff   Pointer to the HTTP header fields structure.
 * @param k    Pointer to the header key.
 * @param klen Length of the header key.
 * @return     Pointer to the header value, or NULL if not found.
 */
const char *gwnet_http_hdr_fields_getl(const struct gwnet_http_hdr_fields *ff,
				       const char *k, size_t klen);


/**
 * Initialize the HTTP body processing context.
 *
 * Set up the provided gwnet_http_body_pctx structure for use in HTTP
 * body processing. It should be called before any operations are
 * performed on the context.
 *
 * @param ctx Pointer to a gwnet_http_body_pctx structure to be
 *            initialized. Must not be NULL.
 *
 * @return 0 on success, or a negative error code on failure.
 */
int gwnet_http_body_pctx_init(struct gwnet_http_body_pctx *ctx);

/**
 * Parses an HTTP body encoded with chunked transfer encoding.
 *
 * @param ctx      Pointer to the HTTP body parsing context structure.
 * @param dst      Buffer where the parsed body data will be written.
 * @param dst_len  Length of the destination buffer in bytes.
 *
 * @return 0 on success,
 *         -EAGAIN if more data is needed,
 *         -EINVAL if the chunked body is malformed,
 *         -ENOBUFS if the destination buffer is not large enough.
 */
int gwnet_http_body_parse_chunked(struct gwnet_http_body_pctx *ctx,
				  char *dst, size_t dst_len);


/**
 * Run all tests related to the HTTP/1.x parser.
 */
void gwnet_http_run_tests(void);

void gwnet_http_body_pctx_free(struct gwnet_http_body_pctx *ctx);

#endif /* #ifndef GWNET_HTTP1_H */
