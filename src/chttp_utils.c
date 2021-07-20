/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <assert.h>
#include <stdio.h>

void
chttp_context_debug(struct chttp_context *ctx)
{
	assert(ctx);
	assert(ctx->magic == CHTTP_CTX_MAGIC);

	printf("chttp_ctx free=%d\n", ctx->free);

	chttp_dpage_debug(ctx->data);
}

void
chttp_dpage_debug(struct chttp_dpage *data)
{
	while (data) {
		assert(data->magic == CHTTP_DPAGE_MAGIC);

		printf("\tchttp_dpage free=%d length=%zu\n", data->free, data->length);

		data = data->next;
	}
}
