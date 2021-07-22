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
	chttp_context_ok(ctx);
	assert(host && *host);
	assert(port > 0);

	if (ctx->state != CHTTP_STATE_INIT_HEADER) {
		chttp_ABORT("invalid state, request must be setup before sending");
	}

	_finalize_request(ctx, host);

	chttp_dns_lookup(ctx, host);

	// ...
}
