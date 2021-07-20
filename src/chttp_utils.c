/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <stdio.h>
#include <stdlib.h>

void
chttp_context_debug(struct chttp_context *ctx)
{
	assert(ctx);
	assert(ctx->magic == CHTTP_CTX_MAGIC);

	printf("chttp_ctx free=%u state=%d version=%d\n",
	    ctx->free, ctx->state, ctx->version);

	chttp_dpage_debug(ctx->data);
}

void
chttp_dpage_debug(struct chttp_dpage *data)
{
	while (data) {
		assert(data->magic == CHTTP_DPAGE_MAGIC);

		printf("\tchttp_dpage free=%u locked=%u length=%zu available=%zu\n",
		    data->free, data->locked, data->length, data->available);

		if (data->available < data->length) {
			printf("\t> '%.*s'\n", (int)(data->length - data->available), data->data);
		}

		data = data->next;
	}
}

void
chttp_do_abort(const char *function, const char *file, int line, const char *reason)
{
	(void)file;
	(void)line;

	fprintf(stderr, "%s(): %s\n", function, reason);
	abort();
}
