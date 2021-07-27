/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <stdlib.h>
#include <string.h>

static struct chttp_dpage *
_dpage_alloc(struct chttp_context *ctx, size_t dpage_size)
{
	struct chttp_dpage *data;

	chttp_context_ok(ctx);

	dpage_size += sizeof(struct chttp_dpage);
	assert(dpage_size > sizeof(struct chttp_dpage));

	data = malloc(dpage_size);
	assert(data);

	chttp_dpage_init(data, dpage_size);

	data->free = 1;

	if (!ctx->data) {
		ctx->data = data;
	} else {
		chttp_dpage_ok(ctx->last);
		assert_zero(ctx->last->next);

		ctx->last->next = data;
	}

	ctx->last = data;

	return (data);
}

void
chttp_dpage_init(struct chttp_dpage *data, size_t dpage_size)
{
	assert(data);
	assert(dpage_size > sizeof(struct chttp_dpage));

	memset(data, 0, sizeof(struct chttp_dpage));

	data->magic = CHTTP_DPAGE_MAGIC;
	data->length = dpage_size - sizeof(struct chttp_dpage);
}

void
chttp_dpage_reset(struct chttp_context *ctx)
{
	struct chttp_dpage *data;

	chttp_context_ok(ctx);

	for (data = ctx->data; data; data = data->next) {
		chttp_dpage_ok(data);

		data->offset = 0;
	}
}

struct chttp_dpage *
chttp_dpage_get(struct chttp_context *ctx, size_t bytes)
{
	struct chttp_dpage *data;
	size_t dpage_size;

	chttp_context_ok(ctx);

	if (ctx->last) {
		chttp_dpage_ok(ctx->last);
		assert(ctx->last->offset <= ctx->last->length);

		if (bytes <= (ctx->last->length - ctx->last->offset)) {
			return (ctx->last);
		}
	}

	dpage_size = CHTTP_DPAGE_MIN_SIZE;

	if (bytes >= dpage_size) {
		dpage_size += bytes;
		assert(dpage_size >= bytes);
	}

	data = _dpage_alloc(ctx, dpage_size);
	assert(data == ctx->last);

	return (data);
}

void
chttp_dpage_append(struct chttp_context *ctx, const void *buffer, size_t buffer_len)
{
	struct chttp_dpage *data;

	chttp_context_ok(ctx);
	assert(buffer_len < (1<<20)); // 1MB

	data = chttp_dpage_get(ctx, buffer_len);
	chttp_dpage_ok(data);
	assert(buffer_len <= data->length);
	assert(data->offset + buffer_len <= data->length);

	memcpy(&data->data[data->offset], (uint8_t*)buffer, buffer_len);

	data->offset += buffer_len;
}

void
chttp_dpage_free(struct chttp_dpage *data)
{
	struct chttp_dpage *curr;

	while (data) {
		chttp_dpage_ok(data);

		curr = data;
		data = curr->next;

		curr->magic = 0;
		curr->next = NULL;

		if (curr->free) {
			free(curr);
		}
	}
}
