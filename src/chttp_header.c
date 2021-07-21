/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <string.h>
#include <bits/string_fortified.h>

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
	size_t name_len, value_len;

	chttp_context_ok(ctx);
	assert(name && *name);
	assert(value);

	if (ctx->state != CHTTP_STATE_INIT_HEADER) {
		chttp_ABORT("invalid state, headers must be set last before sending");
	}

	name_len = strlen(name);
	value_len = strlen(value);

	(void)chttp_dpage_get(ctx, name_len + 2 + value_len + 2);

	chttp_dpage_append(ctx, name, name_len);
	chttp_dpage_append(ctx, ": ", 2);
	chttp_dpage_append(ctx, value, value_len);
	chttp_dpage_append(ctx, "\r\n", 2);
}

void
chttp_delete_header(struct chttp_context *ctx, const char *name)
{
	struct chttp_dpage *data;
	size_t name_len, i, start, mid, end, tail;
	int first;

	chttp_context_ok(ctx);
	assert(name && *name);

	if (ctx->state != CHTTP_STATE_INIT_HEADER) {
		chttp_ABORT("invalid state, headers must be deleted last before sending");
	}

	data = ctx->data;
	name_len = strlen(name);
	first = 0;

	while (data) {
		for (i = 0; i < data->offset; i++) {
			start = i;
			mid = 0;

			while (i < data->offset && data->data[i] != '\n') {
				if (data->data[i] == ':') {
					mid = i;
				}
				i++;
			}

			end = i;

			if (end == data->offset) {
				assert(!first);
				break;
			}

			assert(end > start);
			assert(data->data[end] == '\n');
			assert(data->data[end - 1] == '\r');

			if (!first) {
				first = 1;
				continue;
			}

			assert(mid);

			if ((mid - start) != name_len ||
			    strncmp((char*)&data->data[start], name, name_len)) {
				continue;
			}

			// Shift the tail up the dpage
			tail = data->offset - end - 1;
			assert(tail < data->offset);

			if (tail) {
				memmove(&data->data[start], &data->data[end + 1], tail);
			}

			data->offset -= (end - start) + 1;
			assert(data->offset < data->length);

			return;
		}

		data = data->next;
	}
}
