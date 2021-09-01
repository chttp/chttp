/*
 * Copyright (c) 2021 chttp
 *
 */

#ifndef _CHTTP_H_INCLUDED_
#define _CHTTP_H_INCLUDED_

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define CHTTP_VERSION			"0.1.0"

#define	CHTTP_DEFAULT_METHOD		"GET"
#define CHTTP_DEFAULT_H_VERSION		CHTTP_H_VERSION_1_1
#define CHTTP_USER_AGENT		"chttp " CHTTP_VERSION

enum chttp_version {
	CHTTP_H_VERSION_DEFAULT = 0,
	CHTTP_H_VERSION_1_0,
	CHTTP_H_VERSION_1_1,
	CHTTP_H_VERSION_2_0,
	CHTTP_H_VERSION_3_0,
	_CHTTP_H_VERSION_ERROR
};

enum chttp_state {
	CHTTP_STATE_NONE = 0,
	CHTTP_STATE_INIT_METHOD,
	CHTTP_STATE_INIT_HEADER,
	CHTTP_STATE_CONNECTING,
	CHTTP_STATE_CONNECTED,
	CHTTP_STATE_SENT,
	CHTTP_STATE_RESP_HEADERS,
	CHTTP_STATE_RESP_BODY,
	CHTTP_STATE_IDLE,
	CHTTP_STATE_CLOSED,
	CHTTP_STATE_DONE,
	CHTTP_STATE_DONE_ERROR
};

enum chttp_error {
	CHTTP_ERR_NONE = 0,
	CHTTP_ERR_INIT,
	CHTTP_ERR_DNS,
	CHTTP_ERR_CONNECT,
	CHTTP_ERR_NETOWRK,
	CHTTP_ERR_RESP_PARSE,
	CHTTP_ERR_RESP_LENGTH,
	CHTTP_ERR_RESP_CHUNK,
	CHTTP_ERR_RESP_BODY
};

struct chttp_dpage {
	unsigned int			magic;
#define CHTTP_DPAGE_MAGIC		0xE8F61099

	struct chttp_dpage		*next;

	size_t				length;
	size_t				offset;

	unsigned int			free:1;

	uint8_t				data[];
};

#define CHTTP_DPAGE_MIN_SIZE		2048
#define CHTTP_DPAGE_SIZE		(sizeof(struct chttp_dpage) + CHTTP_DPAGE_MIN_SIZE)

struct chttp_addr {
	unsigned int			magic;
#define CHTTP_ADDR_MAGIC		0x8A7CEC19

	socklen_t			len;

	int				sock;

	union {
		struct sockaddr		sa;
		struct sockaddr_in	sa4;
		struct sockaddr_in6	sa6;
	};
};

struct chttp_context {
	unsigned int			magic;
#define CHTTP_CTX_MAGIC			0x81D0C9BA

	struct chttp_dpage		*data;
	struct chttp_dpage		*data_last;

	uint8_t				*resp_last;

	struct chttp_addr		addr;

	enum chttp_state		state;
	enum chttp_version		version;
	enum chttp_error		error;

	int				status;
	long				length;

	unsigned int			free:1;
	unsigned int			is_head:1;
	unsigned int			has_host:1;
	unsigned int			event_based:1;
	unsigned int			close:1;
	unsigned int			chunked:1;
	unsigned int			seen_first:1;

	uint8_t				_data[CHTTP_DPAGE_SIZE];
};

#define CHTTP_CTX_SIZE			(sizeof(struct chttp_context) - CHTTP_DPAGE_SIZE)

#define __chttp_attr_printf		__chttp_attr_printf_p(2)
#define __chttp_attr_printf_p(fpos)	__attribute__((__format__( \
						__printf__, (fpos), ((fpos) + 1))))

struct chttp_context *chttp_context_alloc();
void chttp_context_init(struct chttp_context *ctx);
struct chttp_context *chttp_context_init_buf(void *buffer, size_t buffer_len);
void chttp_context_free(struct chttp_context *ctx);

size_t chttp_dpage_size(int min);
struct chttp_dpage *chttp_dpage_alloc(size_t dpage_size);
void chttp_dpage_init(struct chttp_dpage *data, size_t dpage_size);
void chttp_dpage_reset(struct chttp_context *ctx);
struct chttp_dpage *chttp_dpage_get(struct chttp_context *ctx, size_t bytes);
void chttp_dpage_append(struct chttp_context *ctx, const void *buffer, size_t buffer_len);
void chttp_dpage_shift_full(struct chttp_context *ctx);
size_t chttp_dpage_resp_start(struct chttp_context *ctx);
void chttp_dpage_free(struct chttp_dpage *data);
extern size_t _DEBUG_CHTTP_DPAGE_MIN_SIZE;

typedef void (chttp_parse_f)(struct chttp_context*, size_t, size_t);
void chttp_set_version(struct chttp_context *ctx, enum chttp_version version);
void chttp_set_method(struct chttp_context *ctx, const char *method);
void chttp_set_url(struct chttp_context *ctx, const char *url);
void chttp_add_header(struct chttp_context *ctx, const char *name, const char *value);
void chttp_delete_header(struct chttp_context *ctx, const char *name);
void chttp_parse_response(struct chttp_context *ctx);
void chttp_parse_headers(struct chttp_context *ctx, chttp_parse_f *func);
const char *chttp_get_header(struct chttp_context *ctx, const char *name);
const char *chttp_get_header_pos(struct chttp_context *ctx, const char *name, size_t pos);
int chttp_find_endline(struct chttp_dpage *data, size_t start, size_t *mid, size_t *end,
	int has_return, int *binary);
extern const char *CHTTP_HEADER_REASON;

void chttp_send(struct chttp_context *ctx, const char *host, int port, int tls);
void chttp_receive(struct chttp_context *ctx);
void chttp_try_close(struct chttp_context *ctx);
void chttp_error(struct chttp_context *ctx, enum chttp_error error);
void chttp_finish(struct chttp_context *ctx);

void chttp_body_length(struct chttp_context *ctx, int do_error);
size_t chttp_get_body(struct chttp_context *ctx, void *buf, size_t buf_len);

void chttp_dns_lookup(struct chttp_context *ctx, const char *host, int port);
void chttp_dns_cache_lookup();
extern long CHTTP_DNS_CACHE_TTL;

void chttp_tcp_import(struct chttp_context *ctx, int sock);
void chttp_tcp_connect(struct chttp_context *ctx);
void chttp_tcp_read(struct chttp_context *ctx);
size_t chttp_tcp_read_buf(struct chttp_context *ctx, void *buf, size_t buf_len);
void chttp_tcp_close(struct chttp_context *ctx);

void chttp_context_debug(struct chttp_context *ctx);
void chttp_dpage_debug(struct chttp_dpage *data);
void chttp_print_hex(void *buf, size_t buf_len);
void chttp_do_abort(const char *function, const char *file, int line, const char *reason);
const char *chttp_error_msg(struct chttp_context *ctx);

#define assert_zero(expr)						\
	assert(!(expr))
#define chttp_context_ok(ctx)						\
	do {								\
		assert(ctx);						\
		assert((ctx)->magic == CHTTP_CTX_MAGIC);		\
	} while (0)
#define chttp_dpage_ok(data)						\
	do {								\
		assert(data);						\
		assert((data)->magic == CHTTP_DPAGE_MAGIC);		\
	} while (0)
#define chttp_addr_ok(ctx)						\
	do {								\
		assert((ctx)->addr.magic == CHTTP_ADDR_MAGIC);		\
		assert((ctx)->addr.sock >= 0);				\
	} while (0)
#define chttp_ABORT(reason)						\
	chttp_do_abort(__func__, __FILE__, __LINE__, reason);

#endif /* _CHTTP_H_INCLUDED_ */
