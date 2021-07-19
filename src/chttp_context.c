/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <stdlib.h>
#include <string.h>

void chttp_context_data_init(struct chttp_dpage *data, size_t buffer_size);

struct chttp_context *
chttp_context_alloc()
{
	return (chttp_context_alloc_size(CHTTP_DPAGE_DEFAULT));
}

struct chttp_context *
chttp_context_alloc_size(size_t buffer_size)
{
	struct chttp_context *ctx;

	ctx = malloc(sizeof(struct chttp_context) + buffer_size);
	assert(ctx);

	memset(ctx, 0, sizeof(struct chttp_context));

	ctx->magic = CHTTP_CTX_MAGIC;
	ctx->free = 1;

	ctx->data = (struct chttp_dpage*)ctx->_data;

	chttp_context_data_init(ctx->data, buffer_size);

	return (ctx);
}

void
chttp_context_data_init(struct chttp_dpage *data, size_t buffer_size)
{
	assert(data);
	assert(buffer_size > sizeof(struct chttp_dpage));

	memset(data, 0, sizeof(struct chttp_dpage));

	data->magic = CHTTP_DPAGE_MAGIC;
	data->length = buffer_size - sizeof(struct chttp_dpage);
}

void
chttp_context_free(struct chttp_context *ctx)
{
	struct chttp_dpage *data, *next;

	assert(ctx->magic == CHTTP_CTX_MAGIC);

	next = ctx->data;

	while (next) {
		assert(next->magic == CHTTP_DPAGE_MAGIC);

		data = next;
		next = data->next;

		data->magic = 0;

		if (data->free) {
			free(data);
		}
	}

	ctx->magic = 0;

	if (ctx->free) {
		free(ctx);
	}
}
