/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <assert.h>
#include <string.h>

void
chttp_dpage_init(struct chttp_dpage *data, size_t dpage_size)
{
	assert(data);
	assert(dpage_size >= sizeof(struct chttp_dpage) + CHTTP_DPAGE_MIN);

	memset(data, 0, sizeof(struct chttp_dpage));

	data->magic = CHTTP_DPAGE_MAGIC;
	data->length = dpage_size - sizeof(struct chttp_dpage);
}
