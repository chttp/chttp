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
	chttp_context_ok(ctx);

	printf("chttp_ctx state=%d error=%d version=%d data_last=%p resp_last=%p\n"
	    "\tstatus=%d length=%ld free=%u has_host=%u close=%u chunked=%u\n",
	    ctx->state, ctx->error, ctx->version, ctx->data_last, ctx->resp_last,
	    ctx->status, ctx->length, ctx->free, ctx->has_host, ctx->close, ctx->chunked);

	chttp_dpage_debug(ctx->data);

	if (ctx->state == CHTTP_STATE_RESP_BODY) {
		printf("\tHEADER _reason: '%s'\n",
			chttp_get_header(ctx, CHTTP_HEADER_REASON));
		printf("\tHEADER server: '%s'\n", chttp_get_header(ctx, "server"));
		printf("\tHEADER date: '%s'\n", chttp_get_header(ctx, "DATE"));
		printf("\tHEADER content-type: '%s'\n",
			chttp_get_header(ctx, "content-type"));
		printf("\tHEADER content-length: '%s'\n",
			chttp_get_header(ctx, "content-length"));
		printf("\tHEADER content-encoding: '%s'\n",
			chttp_get_header(ctx, "content-encoding"));
		printf("\tHEADER transfer-encoding: '%s'\n",
			chttp_get_header(ctx, "transfer-encoding"));
		printf("\tHEADER abc: '%s'\n", chttp_get_header(ctx, "abc"));
	}
}

void
chttp_dpage_debug(struct chttp_dpage *data)
{
	while (data) {
		chttp_dpage_ok(data);

		printf("\tchttp_dpage free=%u length=%zu offset=%zu ptr=%p\n",
		    data->free, data->length, data->offset, data);

		if (data->offset) {
			chttp_print_hex(data->data, data->offset);
		}

		data = data->next;
	}
}

void
chttp_print_hex(void *buf, size_t buf_len)
{
	uint8_t *buffer;
	size_t i;

	assert(buf);

	buffer = buf;

	printf("\t> ");

	for (i = 0; i < buf_len; i++) {
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

const char *
chttp_error_msg(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);

	switch (ctx->error) {
		case CHTTP_ERR_NONE:
			return "none";
		case CHTTP_ERR_INIT:
			return "initialization";
		case CHTTP_ERR_DNS:
			return "DNS error";
		case CHTTP_ERR_CONNECT:
			return "cannot make connection";
		case CHTTP_ERR_NETOWRK:
			return "network error";
		case CHTTP_ERR_RESP_PARSE:
			return "cannot parse response";
	}

	return "unknown";
}