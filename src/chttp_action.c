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

	if (!ctx->has_host) {
		chttp_add_header(ctx, "Host", host);
	}

	assert(ctx->has_host);

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

	if (ctx->state != CHTTP_STATE_INIT_HEADER) {
		chttp_ABORT("invalid state, request must be setup before sending");
	}

	_finalize_request(ctx, host);

	chttp_dns_lookup(ctx, host, port);

	if (ctx->error) {
		return;
	}

	chttp_tcp_connect(ctx);

	if (ctx->error) {
		return;
	}

	assert(ctx->state == CHTTP_STATE_CONNECTED);
	chttp_addr_ok(ctx);

	// TODO use writev()

	for (data = ctx->data; data; data = data->next) {
		chttp_dpage_ok(data);

		if (!data->offset) {
			continue;
		}

		ret = send(ctx->addr.sock, data->data, data->offset, MSG_NOSIGNAL);
		assert(ret == data->offset);
	}

	ctx->state = CHTTP_STATE_SENT;
}

void
chttp_recv(struct chttp_context *ctx)
{
	int ret;

	chttp_context_ok(ctx);

	if (ctx->state != CHTTP_STATE_SENT) {
		chttp_ABORT("invalid state, request must be setup before sending");
	}

	chttp_dpage_reset(ctx);

	chttp_dpage_ok(ctx->data);

	ret = recv(ctx->addr.sock, ctx->data->data, ctx->data->length, 0);
	ctx->data->offset = ret;

	chttp_tcp_close(ctx);

	ctx->state = CHTTP_STATE_DONE;
}
