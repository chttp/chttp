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
	size_t start, end;
	int error;
	char *len_end;

	chttp_context_ok(ctx);
	assert(ctx->state == CHTTP_STATE_RESP_BODY);

	// TODO special codes, HEAD, 1xx, 204, 304

	header = chttp_get_header(ctx, "transfer-encoding");

	if (header && !strcmp(header, "chunked")) {
		ctx->chunked = 1;

		chttp_dpage_ok(ctx->data_last);

		if (ctx->resp_last) {
			start = ctx->resp_last - ctx->data_last->data;
			assert(start <= ctx->data_last->offset);

			error = chttp_find_endline(ctx->data_last, start, NULL, &end, 1,
			    NULL);

			if (error > 0) {
				ctx->error = CHTTP_ERR_RESP_PARSE;
				chttp_finish(ctx);

				return;
			} else if (error) {
				chttp_dpage_shift_full(ctx);
			} else if (!error) {
				errno = 0;
				ctx->length = strtol((char*)&ctx->data_last->data[start],
				    &len_end, 16);

				if (ctx->length < 0 || ctx->length == LONG_MAX || errno ||
				    *len_end != '\r') {
					ctx->error = CHTTP_ERR_RESP_PARSE;
					chttp_finish(ctx);
				}

				end++;

				if (end == ctx->data_last->offset) {
					ctx->resp_last = NULL;
				} else {
					ctx->resp_last = &ctx->data_last->data[end];
				}

				return;
			}
		} else {
			chttp_dpage_get(ctx, 1);
			ctx->resp_last = &ctx->data_last->data[ctx->data_last->offset];
		}

		assert(ctx->resp_last);
		chttp_tcp_read(ctx);

		if (ctx->state == CHTTP_STATE_RESP_BODY) {
			return chttp_body_length(ctx);
		}

		return;
	}

	header = chttp_get_header(ctx, "content-length");

	if (header) {
		errno = 0;
		ctx->length = strtol(header, &len_end, 10);

		if (ctx->length < 0 || ctx->length == LONG_MAX || errno ||
		    *len_end != '\0') {
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