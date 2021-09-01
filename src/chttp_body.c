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
			chttp_error(ctx, CHTTP_ERR_RESP_CHUNK);
			return;
		} else if (error < 0) {
			chttp_dpage_shift_full(ctx);
		} else {
			if (end - start != 1) {
				chttp_error(ctx, CHTTP_ERR_RESP_CHUNK);
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
		chttp_dpage_get(ctx, 2);
		ctx->resp_last = &ctx->data_last->data[ctx->data_last->offset];
	}

	assert(ctx->resp_last);
	chttp_tcp_read(ctx);

	if (ctx->state == CHTTP_STATE_RESP_BODY) {
		_body_chunk_end(ctx);
		return;
	}

	chttp_error(ctx, CHTTP_ERR_RESP_CHUNK);

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
			chttp_error(ctx, CHTTP_ERR_RESP_CHUNK);
			return;
		} else if (error < 0) {
			chttp_dpage_shift_full(ctx);
		} else {
			errno = 0;
			len_start = (char*)&ctx->data_last->data[start];
			ctx->length = strtol(len_start, &len_end, 16);

			if (ctx->length < 0 || ctx->length == LONG_MAX || errno ||
			    len_end == len_start || *len_end != '\r') {
				chttp_error(ctx, CHTTP_ERR_RESP_CHUNK);
				return;
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
		chttp_dpage_get(ctx, 3);
		ctx->resp_last = &ctx->data_last->data[ctx->data_last->offset];
	}

	assert(ctx->resp_last);
	chttp_tcp_read(ctx);

	if (ctx->state == CHTTP_STATE_RESP_BODY) {
		_body_chunk_start(ctx);
		return;
	}

	chttp_error(ctx, CHTTP_ERR_RESP_CHUNK);
}

void
_body_chunk_parse(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);

	_body_chunk_end(ctx);

	if (ctx->state == CHTTP_STATE_RESP_BODY) {
		_body_chunk_start(ctx);

		if (ctx->state == CHTTP_STATE_IDLE) {
			chttp_try_close(ctx);
		}
	} else {
		assert(ctx->error);
	}
}

void
chttp_body_length(struct chttp_context *ctx, int response)
{
	const char *header = NULL;
	char *len_end;

	chttp_context_ok(ctx);
	assert(ctx->state == CHTTP_STATE_RESP_BODY);
	assert_zero(ctx->length);
	assert_zero(ctx->chunked);

	if (ctx->version == CHTTP_H_VERSION_1_0) {
		ctx->close = 1;
	}

	header = chttp_get_header(ctx, "connection");

	if (header && !strcmp(header, "close")) {
		ctx->close = 1;
	} else if (header && !strcmp(header, "keep-alive")) {
		// TODO request override (ctx->req_close) ?
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
			chttp_error(ctx, CHTTP_ERR_RESP_LENGTH);
			return;
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

	chttp_error(ctx, CHTTP_ERR_RESP_LENGTH);

	return;
}

size_t
chttp_get_body(struct chttp_context *ctx, void *buf, size_t buf_len)
{
	size_t start, ret_dpage, ret, len;

	chttp_context_ok(ctx);
	assert(ctx->state >= CHTTP_STATE_RESP_BODY);
	assert(ctx->state <= CHTTP_STATE_DONE);
	assert(buf);

	if (!buf_len) {
		return 0;
	}

	if (ctx->state >= CHTTP_STATE_IDLE) {
		assert(ctx->state != CHTTP_STATE_IDLE && !ctx->close);
		return 0;
	}

	assert(ctx->length);

	ret_dpage = 0;
	ret = 0;

	if (ctx->resp_last) {
		chttp_dpage_ok(ctx->data_last);
		assert(ctx->length);

		start = chttp_dpage_resp_start(ctx);

		// Figure out how much data we have left
		ret_dpage = ctx->data_last->offset - start;

		if (ctx->length >= 0 && ret_dpage > (size_t)ctx->length) {
			ret_dpage = ctx->length;
		}

		// We can fit everything
		if (ret_dpage <= buf_len) {
			assert(ret_dpage);

			memcpy(buf, ctx->resp_last, ret_dpage);

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
				_body_chunk_parse(ctx);

				if (ctx->error) {
					return 0;
				} else if (ctx->state >= CHTTP_STATE_IDLE) {
					return ret_dpage;
				}
			}

			assert(ctx->state == CHTTP_STATE_RESP_BODY);

			buf = (uint8_t*)buf + ret_dpage;
			buf_len -= ret_dpage;

			if (ctx->resp_last) {
				return ret_dpage + chttp_get_body(ctx, buf, buf_len);
			}
		} else {
			// Not enough room
			memcpy(buf, ctx->resp_last, buf_len);

			ctx->resp_last += buf_len;

			chttp_dpage_resp_start(ctx);

			if (ctx->length > 0) {
				assert(buf_len <= (size_t)ctx->length);
				ctx->length -= buf_len;
			}

			assert(ctx->length);

			return buf_len;
		}
	}

	assert_zero(ctx->resp_last);

	len = buf_len;

	if (ctx->length >= 0 && len > (size_t)ctx->length) {
		len = ctx->length;
	}

	if (len) {
		ret = chttp_tcp_read_buf(ctx, buf, len);
		assert(ret <= buf_len);
	}

	buf = (uint8_t*)buf + ret;
	buf_len -= ret;

	if (ctx->length > 0) {
		assert(ret <= (size_t)ctx->length);
		ctx->length -= ret;
	}

	if (ctx->state == CHTTP_STATE_CLOSED) {
		if (ctx->length > 0 || ctx->chunked) {
			chttp_error(ctx, CHTTP_ERR_RESP_BODY);
			return 0;
		} else {
			ctx->length = 0;
			return ret + ret_dpage;
		}
	}

	if (ctx->chunked && ctx->length == 0) {
		_body_chunk_parse(ctx);

		if (ctx->error) {
			return 0;
		}
	} else if (ctx->length == 0) {
		ctx->state = CHTTP_STATE_IDLE;
		chttp_try_close(ctx);
	}

	if (ctx->length) {
		return ret + ret_dpage + chttp_get_body(ctx, buf, buf_len);
	}

	return ret + ret_dpage;
}