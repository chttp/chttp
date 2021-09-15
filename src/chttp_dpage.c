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
	struct chttp_dpage *dpage;

	dpage_size += sizeof(struct chttp_dpage);
	assert(dpage_size > sizeof(struct chttp_dpage));

	dpage = malloc(dpage_size);
	assert(dpage);

	chttp_dpage_init(dpage, dpage_size);

	dpage->free = 1;

	return dpage;
}

static struct chttp_dpage *
_dpage_alloc_ctx(struct chttp_context *ctx, size_t dpage_size)
{
	struct chttp_dpage *dpage;

	chttp_context_ok(ctx);

	dpage = chttp_dpage_alloc(dpage_size);

	if (!ctx->dpage) {
		ctx->dpage = dpage;
	} else {
		chttp_dpage_ok(ctx->dpage_last);
		assert_zero(ctx->dpage_last->next);

		ctx->dpage_last->next = dpage;
	}

	ctx->dpage_last = dpage;

	return (dpage);
}

void
chttp_dpage_init(struct chttp_dpage *dpage, size_t dpage_size)
{
	assert(dpage);
	assert(dpage_size > sizeof(struct chttp_dpage));

	memset(dpage, 0, sizeof(struct chttp_dpage));

	dpage->magic = CHTTP_DPAGE_MAGIC;
	dpage->length = dpage_size - sizeof(struct chttp_dpage);
}

void
chttp_dpage_reset_all(struct chttp_context *ctx)
{
	struct chttp_dpage *dpage;

	chttp_context_ok(ctx);

	for (dpage = ctx->dpage; dpage; dpage = dpage->next) {
		chttp_dpage_ok(dpage);
		dpage->offset = 0;
	}

	if (ctx->dpage) {
		ctx->dpage_last = ctx->dpage;
	}

	memset(&ctx->data_start, 0, sizeof(ctx->data_start));
	memset(&ctx->data_end, 0, sizeof(ctx->data_end));
}

void
chttp_dpage_reset_end(struct chttp_context *ctx)
{
	struct chttp_dpage *dpage;

	chttp_context_ok(ctx);
	chttp_dpage_ok(ctx->data_end.dpage);
	assert_zero(ctx->data_start.dpage);

	dpage = ctx->data_end.dpage;
	dpage->offset = ctx->data_end.offset;
	ctx->dpage_last = dpage;

	for (dpage = dpage->next; dpage; dpage = dpage->next) {
		chttp_dpage_ok(dpage);
		dpage->offset = 0;
	}
}

struct chttp_dpage *
chttp_dpage_get(struct chttp_context *ctx, size_t bytes)
{
	struct chttp_dpage *dpage;
	size_t dpage_size;

	chttp_context_ok(ctx);

	dpage = ctx->dpage_last;

	while (dpage) {
		chttp_dpage_ok(dpage);
		assert(dpage->offset <= dpage->length);

		if (ctx->dpage_last != dpage) {
			assert_zero(dpage->offset);
			ctx->dpage_last = dpage;
		}

		if (bytes <= (dpage->length - dpage->offset)) {
			return (dpage);
		}

		dpage = dpage->next;
	}

	dpage_size = chttp_dpage_size(1);

	if (bytes >= dpage_size) {
		dpage_size += bytes;
		assert(dpage_size >= bytes);
	}

	dpage = _dpage_alloc_ctx(ctx, dpage_size);
	assert(dpage == ctx->dpage_last);

	return (dpage);
}

void
chttp_dpage_append(struct chttp_context *ctx, const void *buffer, size_t buffer_len)
{
	struct chttp_dpage *dpage;

	chttp_context_ok(ctx);
	assert(buffer_len < (10 * 1024 * 1024)); // 10MB

	dpage = chttp_dpage_get(ctx, buffer_len);
	chttp_dpage_ok(dpage);
	assert(buffer_len <= dpage->length);
	assert(dpage->offset + buffer_len <= dpage->length);

	memcpy(&dpage->data[dpage->offset], (uint8_t*)buffer, buffer_len);

	dpage->offset += buffer_len;
}

void
chttp_dpage_shift_full(struct chttp_context *ctx)
{
	struct chttp_dpage *dpage;
	size_t start, leftover;

	chttp_context_ok(ctx);
	chttp_dpage_ok(ctx->data_start.dpage);

	dpage = ctx->dpage_last;

	chttp_dpage_ok(dpage);

	if (dpage->offset < dpage->length) {
		return;
	}

	start = chttp_dpage_resp_start(ctx);
	leftover = dpage->offset - start;

	// Incomplete line
	if (leftover) {
		// TODO you can reset_end here and potentially shift back

		chttp_dpage_get(ctx, leftover + 1);

		// Move over to a new dpage
		assert(ctx->dpage_last != dpage);
		assert(leftover < ctx->dpage_last->length);
		assert_zero(ctx->dpage_last->offset);

		chttp_dpage_append(ctx, ctx->data_start.dpage->data + ctx->data_start.offset,
			leftover);

		dpage->offset -= leftover;
		ctx->data_start.dpage = ctx->dpage_last;
		ctx->data_start.offset = 0;
		dpage = ctx->dpage_last;
	}

	// Make sure we have an available dpage
	chttp_dpage_get(ctx, 1);

	if (ctx->dpage_last != dpage) {
		chttp_dpage_ok(ctx->dpage_last);
		assert_zero(ctx->dpage_last->offset);
		assert_zero(leftover);

		ctx->data_start.dpage = ctx->dpage_last;
		ctx->data_start.offset = 0;
	}
}

size_t
chttp_dpage_resp_start(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);
	chttp_dpage_ok(ctx->data_start.dpage);
	assert(ctx->data_start.dpage == ctx->dpage_last);
	assert(ctx->data_start.offset <= ctx->data_start.dpage->offset);

	return ctx->data_start.offset;
}

uint8_t *
chttp_dpage_start_ptr_convert(struct chttp_context *ctx)
{
	size_t start;

	start = chttp_dpage_resp_start(ctx);

	return ctx->data_start.dpage->data + start;
}

void
chttp_dpage_free(struct chttp_dpage *dpage)
{
	struct chttp_dpage *curr;

	while (dpage) {
		chttp_dpage_ok(dpage);

		curr = dpage;
		dpage = curr->next;

		curr->magic = 0;
		curr->next = NULL;

		if (curr->free) {
			free(curr);
		}
	}
}
