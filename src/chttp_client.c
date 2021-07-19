/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <stdio.h>

void
context_debug(struct chttp_context *ctx)
{
	struct chttp_dpage *data;

	printf("sizeof(struct chttp_ctx)=%zu\n", sizeof(struct chttp_context));
	printf("sizeof(struct chttp_dpage)=%zu\n", sizeof(struct chttp_dpage));

	assert(ctx->magic == CHTTP_CTX_MAGIC);

	printf("chttp_ctx free=%d\n", ctx->free);

	data = ctx->data;

	while (data) {
		assert(data->magic == CHTTP_DPAGE_MAGIC);
		printf("\tchttp_dpage free=%d length=%zu\n", data->free, data->length);
		data = data->next;
	}
}

int
main(int argc, char **argv) {
	struct chttp_context *context;

	printf("chttp client %s\n", CHTTP_VERSION);

	context = chttp_context_alloc();

	context_debug(context);

	chttp_context_free(context);

	return (0);
}
