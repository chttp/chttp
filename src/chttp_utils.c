/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <stdio.h>
#include <stdlib.h>

static void _print_hex(uint8_t *buffer, size_t buffer_len);

void
chttp_context_debug(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);

	printf("chttp_ctx free=%u state=%d error=%d version=%d last=%p\n",
	    ctx->free, ctx->state, ctx->error, ctx->version, ctx->last);

	chttp_dpage_debug(ctx->data);
}

void
chttp_dpage_debug(struct chttp_dpage *data)
{
	while (data) {
		chttp_dpage_ok(data);

		printf("\tchttp_dpage free=%u length=%zu offset=%zu ptr=%p\n",
		    data->free, data->length, data->offset, data);

		if (data->offset) {
			_print_hex(data->data, data->offset);
		}

		data = data->next;
	}
}

static void
_print_hex(uint8_t *buffer, size_t buffer_len)
{
	size_t i;

	assert(buffer);

	printf("\t> ");

	for (i = 0; i < buffer_len; i++) {
		if (buffer[i] >= ' ' && buffer[i] <= '~') {
			printf("%c", buffer[i]);
			continue;
		}

		switch(buffer[i]) {
			case '\r':
				printf("\\r");
				break;
			case '\n':
				printf("\\n\n\t> ");
				break;
			case '\\':
				printf("\\\\");
				break;
			default:
				printf("\\0x%x", buffer[i]);
		}
	}

	printf("\n");
}

void
chttp_do_abort(const char *function, const char *file, int line, const char *reason)
{
	(void)file;
	(void)line;

	fprintf(stderr, "%s(): %s\n", function, reason);
	abort();
}
