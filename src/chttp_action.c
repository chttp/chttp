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
	int ret;

	chttp_context_ok(ctx);
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

	for (data = ctx->data; data; data = data->next) {
		chttp_dpage_ok(data);

		if (!data->offset) {
			continue;
		}

		ret = send(ctx->addr.sock, data->data, data->offset, MSG_NOSIGNAL);
		assert(ret > 0 && (size_t)ret == data->offset); // TODO partial send
	}

	ctx->state = CHTTP_STATE_SENT;
}

void
chttp_recv(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);

	if (ctx->state != CHTTP_STATE_SENT) {
		chttp_ABORT("invalid state, request must be setup before sending");
	}

	ctx->state = CHTTP_STATE_RESP_HEADERS;

	chttp_dpage_reset(ctx);

	do {
		chttp_tcp_read(ctx);
		chttp_parse_resp(ctx);

		if (ctx->error) {
			chttp_finish(ctx);
			return;
		}
	} while (ctx->state == CHTTP_STATE_RESP_HEADERS);

	assert_zero(ctx->error);

	ctx->state = CHTTP_STATE_RESP_BODY;

	chttp_body_length(ctx);
}

void
chttp_finish(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);

	if (ctx->state >= CHTTP_STATE_CONNECTED && ctx->state <= CHTTP_STATE_IDLE) {
		chttp_tcp_close(ctx);
	}

	chttp_dpage_reset(ctx);

	ctx->state = CHTTP_STATE_DONE;
}