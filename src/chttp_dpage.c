/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <stdlib.h>
#include <string.h>

static struct chttp_dpage *_dpage_get(struct chttp_context *ctx, size_t bytes);

void
chttp_dpage_alloc(struct chttp_context *ctx, size_t dpage_size)
{
	struct chttp_dpage *data, *curr;

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
		curr = ctx->data;
		curr->locked = 1;

		while (curr->next) {
			curr = curr->next;
			curr->locked = 1;
		}

		curr->next = data;
	}
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

static struct chttp_dpage *
_dpage_get(struct chttp_context *ctx, size_t bytes)
{
	struct chttp_dpage *data;

	chttp_context_ok(ctx);

	data = ctx->data;

	while (data) {
		assert(data->magic == CHTTP_DPAGE_MAGIC);
		assert(data->offset <= data->length);

		if (bytes <= (data->length - data->offset) && !data->locked) {
			return (data);
		}

		data = data->next;
	}

	return (NULL);
}

void
chttp_dpage_append(struct chttp_context *ctx, const void *buffer, size_t buffer_len)
{
	struct chttp_dpage *data;
	size_t dpage_size;

	chttp_context_ok(ctx);
	assert(buffer_len < (1<<20)); // 1MB

	data = _dpage_get(ctx, buffer_len);

	if (!data) {
		dpage_size = CHTTP_DPAGE_MIN_SIZE;

		while (buffer_len > dpage_size) {
			dpage_size *= 2;
		}

		chttp_dpage_alloc(ctx, dpage_size);
		data = _dpage_get(ctx, buffer_len);
		assert(data);
	}

	assert(buffer_len <= data->length);
	assert(buffer_len + data->offset <= data->length);

	memcpy(&data->data[data->offset], (uint8_t*)buffer, buffer_len);

	data->offset += buffer_len;
}

void
chttp_dpage_free(struct chttp_dpage *data)
{
	struct chttp_dpage *curr;

	while (data) {
		assert(data->magic == CHTTP_DPAGE_MAGIC);

		curr = data;
		data = curr->next;

		curr->magic = 0;
		curr->next = NULL;

		if (curr->free) {
			free(curr);
		}
	}
}
