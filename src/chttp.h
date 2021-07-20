/*
 * Copyright (c) 2021 chttp
 *
 */

#ifndef _CHTTP_H_INCLUDED_
#define _CHTTP_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>

#define CHTTP_VERSION			"0.1.0"

#define CHTTP_DPAGE_DEFAULT		2048
#define CHTTP_DPAGE_MIN			512

enum chttp_version {
	CHTTP_VERSION_DEFAULT = 0,
	CHTTP_1_0,
	CHTTP_1_1,
	CHTTP_2_0,
	CHTTP_3_0
};

struct chttp_dpage {
	unsigned int			magic;
#define CHTTP_DPAGE_MAGIC		0xE8F61099

	struct chttp_dpage		*next;

	size_t				length;

	unsigned int			free:1;

	char				data[];
};

struct chttp_context {
	unsigned int			magic;
#define CHTTP_CTX_MAGIC			0x81D0C9BA

	char				*method;
	char				*url;

	enum chttp_version		version;

	struct chttp_dpage		*data;

	unsigned int			free:1;

	uint8_t				_data[CHTTP_DPAGE_DEFAULT];
};

#define CHTTP_CTX_SIZE			(sizeof(struct chttp_context) - CHTTP_DPAGE_DEFAULT)

struct chttp_context *chttp_context_alloc();
void chttp_context_init(struct chttp_context *ctx);
struct chttp_context *chttp_context_init_buf(void *buffer, size_t buffer_len);
void chttp_context_free(struct chttp_context *ctx);

void chttp_dpage_alloc(struct chttp_context *ctx, size_t dpage_size);
void chttp_dpage_init(struct chttp_dpage *data, size_t dpage_size);
void chttp_dpage_free(struct chttp_dpage *data);

void chttp_context_debug(struct chttp_context *ctx);
void chttp_dpage_debug(struct chttp_dpage *data);

#endif  /* _CHTTP_H_INCLUDED_ */
