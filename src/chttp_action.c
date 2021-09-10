/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

static void
_finalize_request(struct chttp_context *ctx, const char *host)
{
	chttp_context_ok(ctx);
	assert(host && *host);
	assert(ctx->state == CHTTP_STATE_INIT_HEADER);

	if (!ctx->has_host && ctx->version > CHTTP_H_VERSION_1_0) {
		chttp_add_header(ctx, "Host", host);
		assert(ctx->has_host);
	}

	chttp_dpage_append(ctx, "\r\n", 2);
}

void
chttp_send(struct chttp_context *ctx, const char *host, int port, int tls)
{
	struct chttp_dpage *data;
	ssize_t ret;
	size_t offset;

	chttp_context_ok(ctx);
	assert(ctx->data_start.data);
	assert(host && *host);
	assert(port > 0);
	(void)tls;

	if (ctx->state != CHTTP_STATE_INIT_HEADER) {
		chttp_ABORT("invalid state, request must be setup before sending");
	}

	_finalize_request(ctx, host);

	chttp_dns_lookup(ctx, host, port);

	if (ctx->error) {
		chttp_finish(ctx);
		return;
	}

	chttp_tcp_connect(ctx);

	if (ctx->error) {
		chttp_finish(ctx);
		return;
	}

	assert(ctx->state == CHTTP_STATE_CONNECTED);
	chttp_addr_ok(ctx);

	offset = ctx->data_start.offset;

	for (data = ctx->data_start.data; data; data = data->next) {
		chttp_dpage_ok(data);
		assert(offset < data->offset);

		if (!data->offset) {
			continue;
		}

		// TODO turn into tcp
		ret = send(ctx->addr.sock, data->data + offset, data->offset - offset, MSG_NOSIGNAL);
		assert(ret > 0 && (size_t)ret == (data->offset - offset)); // TODO partial send

		offset = 0;
	}

	ctx->state = CHTTP_STATE_SENT;
}

void
chttp_receive(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);

	if (ctx->state != CHTTP_STATE_SENT) {
		chttp_ABORT("invalid state, request must be setup before sending");
	}

	ctx->state = CHTTP_STATE_RESP_HEADERS;

	chttp_dpage_reset(ctx);

	do {
		chttp_tcp_read(ctx);

		if (ctx->state >= CHTTP_STATE_CLOSED) {
			chttp_error(ctx, CHTTP_ERR_NETOWRK);
			return;
		}

		chttp_parse_response(ctx);

		if (ctx->error) {
			return;
		}
	} while (ctx->state == CHTTP_STATE_RESP_HEADERS);

	assert_zero(ctx->error);
	assert(ctx->state == CHTTP_STATE_RESP_BODY);

	chttp_body_length(ctx, 1);

	if (ctx->error) {
		return;
	}

	chttp_try_close(ctx);
}

void
chttp_try_close(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);
	assert(ctx->state >= CHTTP_STATE_RESP_BODY);
	assert(ctx->state < CHTTP_STATE_CLOSED);

	if (ctx->state == CHTTP_STATE_IDLE && ctx->close) {
		chttp_tcp_close(ctx);
		ctx->state = CHTTP_STATE_CLOSED;
	}
}

void
chttp_error(struct chttp_context *ctx, enum chttp_error error)
{
	chttp_context_ok(ctx);
	assert(error > CHTTP_ERR_NONE);

	ctx->error = error;
	ctx->status = 0;

	chttp_finish(ctx);
	assert(ctx->state == CHTTP_STATE_DONE);

	ctx->state = CHTTP_STATE_DONE_ERROR;
}

void
chttp_finish(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);

	if (ctx->state >= CHTTP_STATE_CONNECTED && ctx->state < CHTTP_STATE_CLOSED) {
		chttp_tcp_close(ctx);
	}

	chttp_dpage_reset(ctx);

	ctx->state = CHTTP_STATE_DONE;
}