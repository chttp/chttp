/*
 * Copyright (c) 2021 chttp
 *
 */

#ifndef _CHTTP_H_INCLUDED_
#define _CHTTP_H_INCLUDED_

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#define CHTTP_VERSION			"0.1.0"

#define	CHTTP_DEFAULT_METHOD		"GET"
#define CHTTP_DEFAULT_VERSION		CHTTP_VERSION_1_1
#define CHTTP_USER_AGENT		"chttp " CHTTP_VERSION

enum chttp_state {
	CHTTP_STATE_NONE = 0,
	CHTTP_STATE_INIT_METHOD,
	CHTTP_STATE_INIT_HEADER,
	CHTTP_STATE_SENT
};

enum chttp_version {
	CHTTP_VERSION_DEFAULT = 0,
	CHTTP_VERSION_1_0,
	CHTTP_VERSION_1_1,
	CHTTP_VERSION_2_0,
	CHTTP_VERSION_3_0,
	_CHTTP_VERSION_ERROR
};

enum chttp_error {
	CHTTP_ERR_NONE = 0,
	CHTTP_ERR_INIT,
	CHTTP_ERR_DNS
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

struct chttp_context {
	unsigned int			magic;
#define CHTTP_CTX_MAGIC			0x81D0C9BA

	struct chttp_dpage		*data;
	struct chttp_dpage		*last;

	enum chttp_state		state;
	enum chttp_version		version;
	enum chttp_error		error;

	unsigned int			free:1;
	unsigned int			has_host:1;

	uint8_t				_data[CHTTP_DPAGE_SIZE];
};

#define CHTTP_CTX_SIZE			(sizeof(struct chttp_context) - CHTTP_DPAGE_SIZE)

struct chttp_context *chttp_context_alloc();
void chttp_context_init(struct chttp_context *ctx);
struct chttp_context *chttp_context_init_buf(void *buffer, size_t buffer_len);
void chttp_context_free(struct chttp_context *ctx);

void chttp_dpage_init(struct chttp_dpage *data, size_t dpage_size);
struct chttp_dpage *chttp_dpage_get(struct chttp_context *ctx, size_t bytes);
void chttp_dpage_append(struct chttp_context *ctx, const void *buffer, size_t buffer_len);
void chttp_dpage_free(struct chttp_dpage *data);

void chttp_set_version(struct chttp_context *ctx, enum chttp_version version);
void chttp_set_method(struct chttp_context *ctx, const char *method);
void chttp_set_url(struct chttp_context *ctx, const char *url);
void chttp_add_header(struct chttp_context *ctx, const char *name, const char *value);
void chttp_delete_header(struct chttp_context *ctx, const char *name);

void chttp_send(struct chttp_context *ctx, const char *host, int port, int tls);

void chttp_dns_lookup(struct chttp_context *ctx, const char *host);
void chttp_dns_cache_lookup();

int chttp_tcp_connect(const struct sockaddr *sa);

void chttp_context_debug(struct chttp_context *ctx);
void chttp_dpage_debug(struct chttp_dpage *data);
void chttp_do_abort(const char *function, const char *file, int line, const char *reason);

#define chttp_context_ok(ctx)						\
	do {								\
		assert(ctx);						\
		assert(ctx->magic == CHTTP_CTX_MAGIC);			\
	} while (0)

#define chttp_ABORT(reason)						\
	do {								\
		chttp_do_abort(__func__, __FILE__, __LINE__, reason);	\
	} while (0)

#endif  /* _CHTTP_H_INCLUDED_ */
