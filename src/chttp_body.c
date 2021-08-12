/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static void
_body_end_chunk(struct chttp_context *ctx)
{
	size_t start, end;
	int error;

	chttp_context_ok(ctx);
	assert(ctx->state == CHTTP_STATE_RESP_BODY);
	assert(ctx->chunked);
	chttp_dpage_ok(ctx->data_last);

	if (ctx->resp_last) {
		start = chttp_dpage_resp_start(ctx);

		error = chttp_find_endline(ctx->data_last, start, NULL, &end, 1,
			NULL);

		if (error > 0) {
			ctx->error = CHTTP_ERR_RESP_PARSE;
			chttp_finish(ctx);

			return;
		} else if (error) {
			chttp_dpage_shift_full(ctx);
		} else if (!error) {
			if (end - start != 1) {
				ctx->error = CHTTP_ERR_RESP_PARSE;
				chttp_finish(ctx);

				return;
			} else {
				end++;

				if (end == ctx->data_last->offset) {
					ctx->resp_last = NULL;
				} else {
					ctx->resp_last = &ctx->data_last->data[end];
				}

				return;
			}
		}
	} else {
		chttp_dpage_get(ctx, 1);
		ctx->resp_last = &ctx->data_last->data[ctx->data_last->offset];
	}

	assert(ctx->resp_last);
	chttp_tcp_read(ctx);

	if (ctx->state == CHTTP_STATE_RESP_BODY) {
		return _body_end_chunk(ctx);
	}

	return;
}

void
chttp_body_length(struct chttp_context *ctx)
{
	const char *header = NULL;
	size_t start, end;
	int error;
	char *len_start, *len_end;

	chttp_context_ok(ctx);
	assert(ctx->state == CHTTP_STATE_RESP_BODY);

	if (!ctx->close && !ctx->chunked) {
		header = chttp_get_header(ctx, "connection");

		if (header && !strcmp(header, "close")) {
			ctx->close = 1;
		}
	}

	// TODO special codes, HEAD, 1xx, 204, 304

	if (!ctx->chunked) {
		header = chttp_get_header(ctx, "transfer-encoding");
	}

	if (ctx->chunked || (header && !strcmp(header, "chunked"))) {
		ctx->chunked = 1;

		chttp_dpage_ok(ctx->data_last);

		if (ctx->resp_last) {
			start = chttp_dpage_resp_start(ctx);

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
				len_start = (char*)&ctx->data_last->data[start];
				ctx->length = strtol(len_start, &len_end, 16);

				if (ctx->length < 0 || ctx->length == LONG_MAX || errno ||
				    len_end == len_start || *len_end != '\r') {
					ctx->error = CHTTP_ERR_RESP_PARSE;
					chttp_finish(ctx);
				}

				end++;

				if (end == ctx->data_last->offset) {
					ctx->resp_last = NULL;
				} else {
					ctx->resp_last = &ctx->data_last->data[end];
				}

				if (ctx->length == 0) {
					_body_end_chunk(ctx);

					if (ctx->state == CHTTP_STATE_RESP_BODY) {
						assert_zero(ctx->resp_last);
						ctx->state = CHTTP_STATE_IDLE;
					}
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
		    len_end == header || *len_end != '\0') {
			ctx->error = CHTTP_ERR_RESP_PARSE;
			chttp_finish(ctx);
		}

		return;
	}

	if (ctx->close) {
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

size_t
chttp_get_body(struct chttp_context *ctx, void *buf, size_t buf_len)
{
	size_t start, ret_dpage, ret;

	chttp_context_ok(ctx);
	assert(ctx->state >= CHTTP_STATE_RESP_BODY);
	assert(buf);
	assert(buf_len);

	if (ctx->state >= CHTTP_STATE_IDLE || !buf_len) {
		return 0;
	}

	if (ctx->length == 0 && !ctx->chunked) {
		ctx->state = CHTTP_STATE_IDLE;
		return 0;
	}

	ret_dpage = ret = 0;

	if (ctx->resp_last) {
		chttp_dpage_ok(ctx->data_last);

		start = chttp_dpage_resp_start(ctx);

		// Figure out how much data we have left
		ret_dpage = ctx->data_last->offset - start;

		if (ctx->length >= 0 && ret_dpage > ctx->length) {
			ret_dpage = ctx->length;
		}

		// We can fit everything
		if (ret_dpage < buf_len) {
			if (ret_dpage) {
				memcpy(buf, ctx->resp_last, ret_dpage);
			}

			if (start + ret_dpage < ctx->data_last->offset) {
				ctx->resp_last += ret_dpage;
			} else {
				assert(start + ret_dpage == ctx->data_last->offset);
				ctx->resp_last = NULL;
			}

			if (ctx->length > 0) {
				assert(ret_dpage <= ctx->length);
				ctx->length -= ret_dpage;
			}

			if (ctx->chunked && ctx->length == 0) {
				_body_end_chunk(ctx);

				if (ctx->state == CHTTP_STATE_RESP_BODY) {
					chttp_body_length(ctx);
				}

				// TODO try to read more?
				return ret_dpage;
			}

			buf += ret_dpage;
			buf_len -= ret_dpage;
		} else {
			// Not enough room
			memcpy(buf, ctx->resp_last, buf_len);

			if (ret_dpage == buf_len) {
				ctx->resp_last = NULL;
			} else {
				ctx->resp_last += buf_len;
			}

			if (ctx->length > 0) {
				assert(buf_len <= ctx->length);
				ctx->length -= buf_len;
			}

			return (buf_len);
		}
	}

	if (ctx->length >= 0 && buf_len > ctx->length) {
		buf_len = ctx->length;
	}

	if (buf_len) {
		ret = chttp_tcp_read_buf(ctx, buf, buf_len);
		assert(ret <= buf_len);
	}

	if (ctx->length > 0) {
		assert(ret <= ctx->length);
		ctx->length -= ret;
	}

	if (ctx->chunked && ctx->length == 0) {
		_body_end_chunk(ctx);

		if (ctx->state == CHTTP_STATE_RESP_BODY) {
			chttp_body_length(ctx);
		}
	} else if (ctx->length == 0) {
		ctx->state = CHTTP_STATE_IDLE;
	}

	return ret + ret_dpage;
}