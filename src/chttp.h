/*
 * Copyright (c) 2021 chttp
 *
 */

#ifndef _CHTTP_H_INCLUDED_
#define _CHTTP_H_INCLUDED_

#include <assert.h>
#include <stddef.h>

#define CHTTP_VERSION			"0.1.0"

#define CHTTP_DPAGE_DEFAULT		2048
#define CHTTP_DPAGE_SMALL		512
#define CHTTP_DPAGE_LARGE		8192

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

struct chttp_ctx {
	unsigned int			magic;
#define CHTTP_CTX_MAGIC			0x81D0C9BA

	char				*method;
	char				*url;

	enum chttp_version		version;

	struct chttp_dpage		*data;

	unsigned int			free:1;

	char				_data[];
};

struct chttp_context {
	struct chttp_ctx		ctx;

	char				_data[CHTTP_DPAGE_DEFAULT];
};

struct chttp_context_small {
	struct chttp_ctx		ctx;

	char				_data[CHTTP_DPAGE_SMALL];
};

struct chttp_context_large {
	struct chttp_ctx		ctx;

	char				_data[CHTTP_DPAGE_LARGE];
};

struct chttp_context *chttp_context_alloc();
void chttp_context_init(struct chttp_context*);
struct chttp_context *chttp_context_init_small(struct chttp_context_small*);
struct chttp_context *chttp_context_init_large(struct chttp_context_large*);
void chttp_context_free(struct chttp_context*);
void context_debug(struct chttp_context*);

#endif  /* _CHTTP_H_INCLUDED_ */
