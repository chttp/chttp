/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <stdlib.h>
#include <string.h>

size_t _DEBUG_CHTTP_DPAGE_MIN_SIZE = 0;

size_t
chttp_dpage_size(int min)
{
	if (min) {
		if (_DEBUG_CHTTP_DPAGE_MIN_SIZE) {
			return _DEBUG_CHTTP_DPAGE_MIN_SIZE;
		} else {
			return CHTTP_DPAGE_MIN_SIZE;
		}
	} else {
		if (_DEBUG_CHTTP_DPAGE_MIN_SIZE) {
			return (sizeof(struct chttp_dpage) + _DEBUG_CHTTP_DPAGE_MIN_SIZE);
		} else {
			return CHTTP_DPAGE_SIZE;
		}
	}
}

struct chttp_dpage *
chttp_dpage_alloc(size_t dpage_size)
{
	struct chttp_dpage *data;

	dpage_size += sizeof(struct chttp_dpage);
	assert(dpage_size > sizeof(struct chttp_dpage));

	data = malloc(dpage_size);
	assert(data);

	chttp_dpage_init(data, dpage_size);

	data->free = 1;

	return data;
}

static struct chttp_dpage *
_dpage_alloc_ctx(struct chttp_context *ctx, size_t dpage_size)
{
	struct chttp_dpage *data;

	chttp_context_ok(ctx);

	data = chttp_dpage_alloc(dpage_size);

	if (!ctx->data) {
		ctx->data = data;
	} else {
		chttp_dpage_ok(ctx->data_last);
		assert_zero(ctx->data_last->next);

		ctx->data_last->next = data;
	}

	ctx->data_last = data;

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

	if (ctx->data) {
		ctx->data_last = ctx->data;
	}
}

struct chttp_dpage *
chttp_dpage_get(struct chttp_context *ctx, size_t bytes)
{
	struct chttp_dpage *data;
	size_t dpage_size;

	chttp_context_ok(ctx);

	data = ctx->data_last;

	while (data) {
		chttp_dpage_ok(data);
		assert(data->offset <= data->length);

		ctx->data_last = data;

		if (bytes <= (data->length - data->offset)) {
			return (data);
		}

		data = data->next;
	}

	dpage_size = chttp_dpage_size(1);

	if (bytes >= dpage_size) {
		dpage_size += bytes;
		assert(dpage_size >= bytes);
	}

	data = _dpage_alloc_ctx(ctx, dpage_size);
	assert(data == ctx->data_last);

	return (data);
}

void
chttp_dpage_append(struct chttp_context *ctx, const void *buffer, size_t buffer_len)
{
	struct chttp_dpage *data;

	chttp_context_ok(ctx);
	assert(buffer_len < (1024 * 1024)); // 1MB

	data = chttp_dpage_get(ctx, buffer_len);
	chttp_dpage_ok(data);
	assert(buffer_len <= data->length);
	assert(data->offset + buffer_len <= data->length);

	memcpy(&data->data[data->offset], (uint8_t*)buffer, buffer_len);

	data->offset += buffer_len;
}

void
chttp_dpage_shift_full(struct chttp_context *ctx)
{
	struct chttp_dpage *data;
	size_t start, leftover;

	chttp_context_ok(ctx);
	assert(ctx->resp_last);

	data = ctx->data_last;

	chttp_dpage_ok(data);

	if (data->offset < data->length) {
		return;
	}

	start = chttp_dpage_resp_start(ctx);
	leftover = data->offset - start;

	// Incomplete line
	if (leftover) {
		chttp_dpage_get(ctx, leftover + 1);

		// Move over to a new dpage
		assert(ctx->data_last != data);
		assert(leftover < ctx->data_last->length);
		assert_zero(ctx->data_last->offset);

		chttp_dpage_append(ctx, ctx->resp_last, leftover);

		data->offset -= leftover;
		ctx->resp_last = ctx->data_last->data;
		data = ctx->data_last;
	}

	// Make sure we have an available dpage
	chttp_dpage_get(ctx, 1);

	if (ctx->data_last != data) {
		chttp_dpage_ok(ctx->data_last);
		assert_zero(ctx->data_last->offset);
		assert_zero(leftover);

		ctx->resp_last = ctx->data_last->data;
	}
}

size_t
chttp_dpage_resp_start(struct chttp_context *ctx)
{
	size_t start;

	chttp_context_ok(ctx);
	assert(ctx->resp_last);

	start = ctx->resp_last - ctx->data_last->data;
	assert(start <= ctx->data_last->offset);

	return start;
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
