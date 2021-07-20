/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static struct chttp_context *context_alloc_size(size_t buffer_size);
static void context_init_size(struct chttp_context *ctx, size_t dpage_size);

struct chttp_context *
chttp_context_alloc()
{
	return (context_alloc_size(CHTTP_DPAGE_DEFAULT));
}

static struct chttp_context *
context_alloc_size(size_t dpage_size)
{
	struct chttp_context *ctx;

	ctx = malloc(CHTTP_CTX_SIZE + dpage_size);
	assert(ctx);

	context_init_size(ctx, dpage_size);

	ctx->free = 1;

	return (ctx);
}

static void
context_init_size(struct chttp_context *ctx, size_t dpage_size)
{
	memset(ctx, 0, CHTTP_CTX_SIZE);

	ctx->magic = CHTTP_CTX_MAGIC;

	if (dpage_size) {
		ctx->data = (struct chttp_dpage*)ctx->_data;
		chttp_dpage_init(ctx->data, dpage_size);
	}
}

void
chttp_context_init(struct chttp_context *ctx)
{
	assert(ctx);

	context_init_size(ctx, CHTTP_DPAGE_DEFAULT);
}

struct chttp_context *
chttp_context_init_buf(void *buffer, size_t buffer_len)
{
	struct chttp_context *ctx;

	assert(buffer);
	assert(buffer_len >= CHTTP_CTX_SIZE + sizeof(struct chttp_dpage) + CHTTP_DPAGE_MIN);

	ctx = buffer;

	context_init_size(ctx, buffer_len - CHTTP_CTX_SIZE);

	return (ctx);
}

void
chttp_context_free(struct chttp_context *ctx)
{
	struct chttp_dpage *data, *next;

	assert(ctx);
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

void
context_debug(struct chttp_context *ctx)
{
	struct chttp_dpage *data;

	printf("sizeof(struct chttp_ctx)=%zu\n", CHTTP_CTX_SIZE);
	printf("sizeof(struct chttp_dpage)=%zu\n", sizeof(struct chttp_dpage));

	assert(ctx);
	assert(ctx->magic == CHTTP_CTX_MAGIC);

	printf("chttp_ctx free=%d\n", ctx->free);

	data = ctx->data;

	while (data) {
		assert(data->magic == CHTTP_DPAGE_MAGIC);
		printf("\tchttp_dpage free=%d length=%zu\n", data->free, data->length);
		data = data->next;
	}
}
