/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

void
chttp_body_length(struct chttp_context *ctx)
{
	const char *header;
	char *end;

	chttp_context_ok(ctx);
	assert(ctx->state == CHTTP_STATE_RESP_BODY);

	// TODO special codes, HEAD, 1xx, 204, 304

	header = chttp_get_header(ctx, "transfer-encoding");

	if (header && !strcmp(header, "chunked")) {
		ctx->chunked = 1;

		// TODO read the first chunked length

		return;
	}

	header = chttp_get_header(ctx, "content-length");

	if (header) {
		errno = 0;

		ctx->length = strtol(header, &end, 10);

		if (ctx->length < 0 || ctx->length == LONG_MAX || errno || *end != '\0') {
			ctx->error = CHTTP_ERR_RESP_PARSE;
			chttp_finish(ctx);
		}

		return;
	}

	header = chttp_get_header(ctx, "connection");

	if (header && !strcmp(header, "close")) {
		ctx->close = 1;
		ctx->length = -1;
		return;
	}

	if (ctx->version == CHTTP_H_VERSION_1_0) {
		ctx->close = 1;
		ctx->length = -1;
		return;
	}

	ctx->error = CHTTP_ERR_RESP_PARSE;
	chttp_finish(ctx);

	return;
}