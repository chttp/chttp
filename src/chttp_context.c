/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static struct chttp_context *context_alloc_size(size_t buffer_size);
static void context_init_size(struct chttp_ctx *ctx, size_t dpage_size);
static void context_data_init(struct chttp_dpage *data, size_t buffer_size);

static inline struct chttp_ctx *
cast_ctx(struct chttp_context *context)
{
	struct chttp_ctx *ctx;

	ctx = (struct chttp_ctx*)context;

	assert(ctx);
	assert(ctx->magic == CHTTP_CTX_MAGIC);

	return (ctx);
}

static inline struct chttp_context *
cast_context(struct chttp_ctx *ctx)
{
	assert(ctx);
	assert(ctx->magic == CHTTP_CTX_MAGIC);

	return ((struct chttp_context *)ctx);
}

struct chttp_context *
chttp_context_alloc()
{
	return (context_alloc_size(CHTTP_DPAGE_DEFAULT));
}

static struct chttp_context *
context_alloc_size(size_t dpage_size)
{
	struct chttp_ctx *ctx;

	ctx = malloc(sizeof(struct chttp_ctx) + dpage_size);
	assert(ctx);

	context_init_size(ctx, dpage_size);

	ctx->free = 1;

	return (cast_context(ctx));
}

static void
context_init_size(struct chttp_ctx *ctx, size_t dpage_size)
{
	memset(ctx, 0, sizeof(struct chttp_ctx));

	ctx->magic = CHTTP_CTX_MAGIC;
	ctx->data = (struct chttp_dpage*)ctx->_data;

	context_data_init(ctx->data, dpage_size);
}

void
chttp_context_init(struct chttp_context *context)
{
	struct chttp_ctx *ctx;

	ctx = (struct chttp_ctx*)context;
	assert(ctx);

	context_init_size(ctx, CHTTP_DPAGE_DEFAULT);
}

struct chttp_context *
chttp_context_init_small(struct chttp_context_small *context_small)
{
	struct chttp_ctx *ctx;

	ctx = (struct chttp_ctx*)context_small;

	context_init_size(ctx, CHTTP_DPAGE_SMALL);

	return (cast_context(ctx));
}

struct chttp_context *
chttp_context_init_large(struct chttp_context_large *context_large)
{
	struct chttp_ctx *ctx;

	ctx = (struct chttp_ctx*)context_large;

	context_init_size(ctx, CHTTP_DPAGE_LARGE);

	return (cast_context(ctx));
}

static void
context_data_init(struct chttp_dpage *data, size_t buffer_size)
{
	assert(data);
	assert(buffer_size > sizeof(struct chttp_dpage));

	memset(data, 0, sizeof(struct chttp_dpage));

	data->magic = CHTTP_DPAGE_MAGIC;
	data->length = buffer_size - sizeof(struct chttp_dpage);
}

void
chttp_context_free(struct chttp_context *context)
{
	struct chttp_ctx *ctx;
	struct chttp_dpage *data, *next;

	ctx = cast_ctx(context);

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

void
context_debug(struct chttp_context *context)
{
	struct chttp_ctx *ctx;
	struct chttp_dpage *data;

	printf("sizeof(struct chttp_ctx)=%zu\n", sizeof(struct chttp_ctx));
	printf("sizeof(struct chttp_dpage)=%zu\n", sizeof(struct chttp_dpage));

	ctx = cast_ctx(context);

	printf("chttp_ctx free=%d\n", ctx->free);

	data = ctx->data;

	while (data) {
		assert(data->magic == CHTTP_DPAGE_MAGIC);
		printf("\tchttp_dpage free=%d length=%zu\n", data->free, data->length);
		data = data->next;
	}
}
