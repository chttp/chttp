/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

void
chttp_dpage_alloc(struct chttp_context *ctx, size_t dpage_size)
{
	struct chttp_dpage *data, *curr;

	assert(dpage_size >= sizeof(struct chttp_dpage) + CHTTP_DPAGE_MIN);

	data = malloc(dpage_size);
	assert(data);

	chttp_dpage_init(data, dpage_size);

	data->free = 1;

	if (!ctx->data) {
		ctx->data = data;
	} else {
		curr = ctx->data;
		while (curr->next) {
			curr = curr->next;
		}

		curr->next = data;
	}
}

void
chttp_dpage_init(struct chttp_dpage *data, size_t dpage_size)
{
	assert(data);
	assert(dpage_size >= sizeof(struct chttp_dpage) + CHTTP_DPAGE_MIN);

	memset(data, 0, sizeof(struct chttp_dpage) + 1);

	data->magic = CHTTP_DPAGE_MAGIC;
	data->length = dpage_size - sizeof(struct chttp_dpage);
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
