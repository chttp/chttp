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
_body_chunk_end(struct chttp_context *ctx)
{
	size_t start, end;
	int error;

	chttp_context_ok(ctx);
	assert(ctx->state == CHTTP_STATE_RESP_BODY);
	assert(ctx->chunked);
	assert_zero(ctx->length);
	chttp_dpage_ok(ctx->data_last);

	if (ctx->resp_last) {
		start = chttp_dpage_resp_start(ctx);

		error = chttp_find_endline(ctx->data_last, start, NULL, &end, 1,
			NULL);

		if (error > 0) {
			ctx->error = CHTTP_ERR_RESP_LENGTH;
			chttp_finish(ctx);

			return;
		} else if (error < 0) {
			chttp_dpage_shift_full(ctx);
		} else {
			if (end - start != 1) {
				ctx->error = CHTTP_ERR_RESP_LENGTH;
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
		return _body_chunk_end(ctx);
	}

	return;
}

void
_body_chunk_start(struct chttp_context *ctx)
{
	size_t start, end;
	int error;
	char *len_start, *len_end;

	chttp_context_ok(ctx);
	assert(ctx->state == CHTTP_STATE_RESP_BODY);
	assert(ctx->chunked);
	assert_zero(ctx->length);
	chttp_dpage_ok(ctx->data_last);

	if (ctx->resp_last) {
		start = chttp_dpage_resp_start(ctx);

		error = chttp_find_endline(ctx->data_last, start, NULL, &end, 1,
			NULL);

		if (error > 0) {
			ctx->error = CHTTP_ERR_RESP_LENGTH;
			chttp_finish(ctx);

			return;
		} else if (error < 0) {
			chttp_dpage_shift_full(ctx);
		} else {
			errno = 0;
			len_start = (char*)&ctx->data_last->data[start];
			ctx->length = strtol(len_start, &len_end, 16);

			if (ctx->length < 0 || ctx->length == LONG_MAX || errno ||
				len_end == len_start || *len_end != '\r') {
				ctx->error = CHTTP_ERR_RESP_LENGTH;
				chttp_finish(ctx);
			}

			end++;

			if (end == ctx->data_last->offset) {
				ctx->resp_last = NULL;
			} else {
				ctx->resp_last = &ctx->data_last->data[end];
			}

			if (ctx->length == 0) {
				_body_chunk_end(ctx);

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
		return _body_chunk_start(ctx);
	}
}

void
chttp_body_length(struct chttp_context *ctx, int response)
{
	const char *header = NULL;
	char *len_end;

	chttp_context_ok(ctx);
	assert(ctx->state == CHTTP_STATE_RESP_BODY);

	if (ctx->version == CHTTP_H_VERSION_1_0) {
		ctx->close = 1;
	}

	header = chttp_get_header(ctx, "connection");

	if (header && !strcmp(header, "close")) {
		ctx->close = 1;
	} else if (header && !strcmp(header, "keep-alive")) {
		ctx->close = 0;
	}

	if (ctx->is_head) {
		// TODO 1xx, 204, 304 ?
		ctx->state = CHTTP_STATE_IDLE;
		return;
	}

	header = chttp_get_header(ctx, "transfer-encoding");

	if (header && !strcmp(header, "chunked")) {
		ctx->chunked = 1;
		_body_chunk_start(ctx);
		return;
	}

	header = chttp_get_header(ctx, "content-length");

	if (header) {
		errno = 0;
		ctx->length = strtol(header, &len_end, 10);

		if (ctx->length < 0 || ctx->length == LONG_MAX || errno ||
		    len_end == header || *len_end != '\0') {
			ctx->error = CHTTP_ERR_RESP_LENGTH;
			chttp_finish(ctx);
		}

		if (ctx->length == 0) {
			ctx->state = CHTTP_STATE_IDLE;
		}

		return;
	}

	if (!response) {
		ctx->state = CHTTP_STATE_IDLE;
		return;
	}

	if (ctx->close) {
		ctx->length = -1;
		return;
	}

	ctx->error = CHTTP_ERR_RESP_LENGTH;
	chttp_finish(ctx);

	return;
}

size_t
chttp_get_body(struct chttp_context *ctx, void *buf, size_t buf_len)
{
	size_t start, ret_dpage, ret;

	chttp_context_ok(ctx);
	assert(ctx->state >= CHTTP_STATE_RESP_BODY);
	assert(ctx->state < CHTTP_STATE_DONE);
	assert(buf);
	assert(buf_len);

	if (ctx->state >= CHTTP_STATE_IDLE) {
		chttp_try_close(ctx);
		return 0;
	}

	// TODO this might be too strict, see other TODO
	assert(ctx->length || ctx->chunked);

	ret_dpage = ret = 0;

	if (ctx->resp_last) {
		chttp_dpage_ok(ctx->data_last);

		start = chttp_dpage_resp_start(ctx);

		// Figure out how much data we have left
		ret_dpage = ctx->data_last->offset - start;

		if (ctx->length >= 0 && ret_dpage > (size_t)ctx->length) {
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
				assert(ret_dpage <= (size_t)ctx->length);
				ctx->length -= ret_dpage;
			}

			if (ctx->chunked && ctx->length == 0) {
				_body_chunk_end(ctx);

				if (ctx->state == CHTTP_STATE_RESP_BODY) {
					_body_chunk_start(ctx);
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
				assert(buf_len <= (size_t)ctx->length);
				ctx->length -= buf_len;
			}

			return (buf_len);
		}
	}

	if (ctx->length >= 0 && buf_len > (size_t)ctx->length) {
		buf_len = ctx->length;
	}

	if (buf_len) {
		ret = chttp_tcp_read_buf(ctx, buf, buf_len);
		assert(ret <= buf_len);
	}

	if (ctx->length > 0) {
		assert(ret <= (size_t)ctx->length);
		ctx->length -= ret;
	}

	if (ctx->chunked && ctx->length == 0) {
		_body_chunk_end(ctx);

		if (ctx->state == CHTTP_STATE_RESP_BODY) {
			_body_chunk_start(ctx);
		}
	} else if (ctx->length == 0) {
		ctx->state = CHTTP_STATE_IDLE;
	}

	chttp_try_close(ctx);

	return ret + ret_dpage;
}