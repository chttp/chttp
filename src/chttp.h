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

enum chttp_state {
	CHTTP_STATE_NONE = 0,
	CHTTP_STATE_INIT_METHOD,
	CHTTP_STATE_INIT_HEADER,
	CHTTP_STATE_CONNECTING,
	CHTTP_STATE_CONNECTED,
	CHTTP_STATE_SENT,
	CHTTP_STATE_RESP_HEADERS,
	CHTTP_STATE_RESP_BODY,
	CHTTP_STATE_DONE
};

enum chttp_version {
	CHTTP_H_VERSION_DEFAULT = 0,
	CHTTP_H_VERSION_1_0,
	CHTTP_H_VERSION_1_1,
	CHTTP_H_VERSION_2_0,
	CHTTP_H_VERSION_3_0,
	_CHTTP_H_VERSION_ERROR
};

enum chttp_error {
	CHTTP_ERR_NONE = 0,
	CHTTP_ERR_INIT,
	CHTTP_ERR_DNS,
	CHTTP_ERR_CONNECT,
	CHTTP_ERR_RESP_PARSE
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

	unsigned int			free:1;
	unsigned int			has_host:1;
	unsigned int			event_based:1;

	uint8_t				_data[CHTTP_DPAGE_SIZE];
};

#define CHTTP_CTX_SIZE			(sizeof(struct chttp_context) - CHTTP_DPAGE_SIZE)

struct chttp_context *chttp_context_alloc();
void chttp_context_init(struct chttp_context *ctx);
struct chttp_context *chttp_context_init_buf(void *buffer, size_t buffer_len);
void chttp_context_free(struct chttp_context *ctx);

size_t chttp_dpage_size(int min);
void chttp_dpage_init(struct chttp_dpage *data, size_t dpage_size);
void chttp_dpage_reset(struct chttp_context *ctx);
struct chttp_dpage *chttp_dpage_get(struct chttp_context *ctx, size_t bytes);
void chttp_dpage_append(struct chttp_context *ctx, const void *buffer, size_t buffer_len);
void chttp_dpage_free(struct chttp_dpage *data);
extern size_t _DEBUG_CHTTP_DPAGE_MIN_SIZE;

void chttp_set_version(struct chttp_context *ctx, enum chttp_version version);
void chttp_set_method(struct chttp_context *ctx, const char *method);
void chttp_set_url(struct chttp_context *ctx, const char *url);
void chttp_add_header(struct chttp_context *ctx, const char *name, const char *value);
void chttp_delete_header(struct chttp_context *ctx, const char *name);
void chttp_parse_resp(struct chttp_context *ctx);

void chttp_send(struct chttp_context *ctx, const char *host, int port, int tls);
void chttp_recv(struct chttp_context *ctx);

void chttp_dns_lookup(struct chttp_context *ctx, const char *host, int port);
void chttp_dns_cache_lookup();

void chttp_tcp_connect(struct chttp_context *ctx);
void chttp_tcp_close(struct chttp_context *ctx);

void chttp_context_debug(struct chttp_context *ctx);
void chttp_dpage_debug(struct chttp_dpage *data);
void chttp_do_abort(const char *function, const char *file, int line, const char *reason);

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

#endif  /* _CHTTP_H_INCLUDED_ */
