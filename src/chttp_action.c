/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <string.h>

static void
_finalize_request(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);
	assert(ctx->state == CHTTP_STATE_INIT_HEADER);

	if (!ctx->has_host && ctx->version > CHTTP_H_VERSION_1_0) {
		if(ctx->hostname.dpage) {
			assert(ctx->hostname.length);
			chttp_add_header(ctx, "Host",
				(char*)chttp_dpage_ptr_convert(ctx, &ctx->hostname));
		} else {
			chttp_ABORT("host header is missing");
		}
		assert(ctx->has_host);
	}

	chttp_dpage_append(ctx, "\r\n", 2);
}

void
chttp_connect(struct chttp_context *ctx, const char *host, int port, int tls)
{
	chttp_context_ok(ctx);
	assert(host && *host);
	assert(port > 0);
	(void)tls;

	if (ctx->addr.state) {
		chttp_addr_ok(ctx);
		chttp_ABORT("invalid state, you can only connect once");
	}

	if (ctx->state == CHTTP_STATE_NONE) {
		assert_zero(ctx->data_start.dpage);
		chttp_dpage_append_mark(ctx, host, strlen(host) + 1, &ctx->hostname);
	} else if (ctx->state == CHTTP_STATE_INIT_HEADER) {
		if (!ctx->has_host && ctx->version > CHTTP_H_VERSION_1_0) {
			chttp_add_header(ctx, "Host", host);
			assert(ctx->has_host);
		}
	} else {
		// TODO explain better
		chttp_ABORT("invalid state, connection must be setup before sending");
	}

	chttp_dns_lookup(ctx, host, port);

	if (ctx->error) {
		chttp_finish(ctx);
		return;
	}

	chttp_addr_ok(ctx);
	assert(ctx->addr.state == CHTTP_ADDR_RESOLVED);
}

void
chttp_send(struct chttp_context *ctx)
{
	struct chttp_dpage *dpage;
	size_t offset;

	chttp_context_ok(ctx);
	assert(ctx->data_start.dpage);

	if (ctx->state != CHTTP_STATE_INIT_HEADER) {
		chttp_ABORT("invalid state, request must be setup before sending");
	}

	if (ctx->addr.state != CHTTP_ADDR_RESOLVED) {
		chttp_ABORT("invalid state, connection must be setup before sending");
	}

	_finalize_request(ctx);

	chttp_tcp_connect(ctx);

	if (ctx->error) {
		chttp_finish(ctx);
		return;
	}

	chttp_addr_connected(ctx);

	offset = ctx->data_start.offset;

	for (dpage = ctx->data_start.dpage; dpage; dpage = dpage->next) {
		chttp_dpage_ok(dpage);
		assert(offset < dpage->offset);

		if (!dpage->offset) {
			continue;
		}

		chttp_tcp_send(ctx, dpage->data + offset, dpage->offset - offset);

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

	chttp_dpage_reset_all(ctx);

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

	assert(ctx->state == CHTTP_STATE_RESP_BODY);
	chttp_dpage_ok(ctx->data_end.dpage);

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

	ctx->state = CHTTP_STATE_DONE_ERROR;
}

void
chttp_finish(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);

	if (ctx->addr.state == CHTTP_ADDR_CONNECTED) {
		chttp_tcp_close(ctx);
	}

	chttp_dpage_reset_all(ctx);

	ctx->state = CHTTP_STATE_DONE;
}