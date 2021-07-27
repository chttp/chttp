/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <stdlib.h>
#include <string.h>

static struct chttp_context *_context_alloc_size(size_t buffer_size);
static void _context_init_size(struct chttp_context *ctx, size_t dpage_size);

struct chttp_context *
chttp_context_alloc()
{
	return (_context_alloc_size(CHTTP_DPAGE_SIZE));
}

static struct chttp_context *
_context_alloc_size(size_t dpage_size)
{
	struct chttp_context *ctx;

	ctx = malloc(CHTTP_CTX_SIZE + dpage_size);
	assert(ctx);

	_context_init_size(ctx, dpage_size);

	ctx->free = 1;

	return (ctx);
}

static void
_context_init_size(struct chttp_context *ctx, size_t dpage_size)
{
	memset(ctx, 0, CHTTP_CTX_SIZE);

	ctx->magic = CHTTP_CTX_MAGIC;

	if (dpage_size > sizeof(struct chttp_dpage)) {
		ctx->data = (struct chttp_dpage*)ctx->_data;
		ctx->last = ctx->data;

		chttp_dpage_init(ctx->data, dpage_size);
	}
}

void
chttp_context_init(struct chttp_context *ctx)
{
	assert(ctx);

	_context_init_size(ctx, CHTTP_DPAGE_SIZE);
}

struct chttp_context *
chttp_context_init_buf(void *buffer, size_t buffer_len)
{
	struct chttp_context *ctx;

	assert(buffer);
	assert(buffer_len >= CHTTP_CTX_SIZE);

	ctx = buffer;

	_context_init_size(ctx, buffer_len - CHTTP_CTX_SIZE);

	return (ctx);
}

void
chttp_context_free(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);

	chttp_dpage_free(ctx->data);

	ctx->magic = 0;
	ctx->data = NULL;

	if (ctx->free) {
		free(ctx);
	}
}
