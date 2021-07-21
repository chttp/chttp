/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <string.h>

static void _setup_request(struct chttp_context *ctx);

void
chttp_set_version(struct chttp_context *ctx, enum chttp_version version)
{
	chttp_context_ok(ctx);

	if (version >= _CHTTP_VERSION_ERROR) {
		chttp_ABORT("invalid version");
	}

	// TODO
	if (version >= CHTTP_VERSION_2_0) {
		chttp_ABORT("HTTP2+ not supported");
	}

	if (ctx->state != CHTTP_STATE_NONE) {
		chttp_ABORT("invalid state, version must be set first");
	}

	ctx->version = version;
}

void
chttp_set_method(struct chttp_context *ctx, const char *method)
{
	chttp_context_ok(ctx);
	assert(method && *method);

	if (ctx->state != CHTTP_STATE_NONE) {
		chttp_ABORT("invalid state, method must before url or headers");
	}

	chttp_dpage_append(ctx, method, strlen(method));

	if (ctx->version == CHTTP_VERSION_DEFAULT) {
		ctx->version = CHTTP_DEFAULT_VERSION;
	}

	ctx->state = CHTTP_STATE_INIT_METHOD;
}

void
chttp_set_url(struct chttp_context *ctx, const char *url)
{
	chttp_context_ok(ctx);
	assert(url && *url);

	if (ctx->state == CHTTP_STATE_NONE) {
		chttp_set_method(ctx, CHTTP_DEFAULT_METHOD);
	}

	if (ctx->state != CHTTP_STATE_INIT_METHOD) {
		chttp_ABORT("invalid state, method must after method and before headers");
	}

	chttp_dpage_append(ctx, " ", 1);
	chttp_dpage_append(ctx, url, strlen(url));

	_setup_request(ctx);
}

static void
_setup_request(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);
	assert(ctx->state == CHTTP_STATE_INIT_METHOD);

	switch(ctx->version) {
		case CHTTP_VERSION_1_0:
			chttp_dpage_append(ctx, " HTTP/1.0\r\n", 11);
			break;
		case CHTTP_VERSION_1_1:
			chttp_dpage_append(ctx, " HTTP/1.1\r\n", 11);
			break;
		default:
			chttp_ABORT("bad version");
	}

	ctx->state = CHTTP_STATE_INIT_HEADER;
}

void
chttp_add_header(struct chttp_context *ctx, const char *name, const char *value)
{
	chttp_context_ok(ctx);
	assert(name && *name);
	assert(value);

	if (ctx->state != CHTTP_STATE_INIT_HEADER) {
		chttp_ABORT("invalid state, headers must be set last before sending");
	}

	chttp_dpage_append(ctx, name, strlen(name));
	chttp_dpage_append(ctx, ": ", 2);
	chttp_dpage_append(ctx, value, strlen(value));
	chttp_dpage_append(ctx, "\r\n", 2);
}
