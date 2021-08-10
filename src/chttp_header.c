/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <string.h>

const char *CHTTP_HEADER_REASON	 = "_REASON";

static void _setup_request(struct chttp_context *ctx);

void
chttp_set_version(struct chttp_context *ctx, enum chttp_version version)
{
	chttp_context_ok(ctx);

	if (version >= _CHTTP_H_VERSION_ERROR) {
		chttp_ABORT("invalid version");
	}

	// TODO
	if (version >= CHTTP_H_VERSION_2_0) {
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

	if (ctx->version == CHTTP_H_VERSION_DEFAULT) {
		ctx->version = CHTTP_DEFAULT_H_VERSION;
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
		case CHTTP_H_VERSION_1_0:
			chttp_dpage_append(ctx, " HTTP/1.0\r\n", 11);
			break;
		case CHTTP_H_VERSION_1_1:
			chttp_dpage_append(ctx, " HTTP/1.1\r\n", 11);
			break;
		default:
			chttp_ABORT("bad version");
	}

	ctx->state = CHTTP_STATE_INIT_HEADER;

	chttp_add_header(ctx, "User-Agent", CHTTP_USER_AGENT);
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

	if (!strncasecmp(name, "host", 4)) {
		ctx->has_host = 1;
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

	if (!strncasecmp(name, "host", 4)) {
		ctx->has_host = 0;
	}

	name_len = strlen(name);
	first = 1;

	for (data = ctx->data; data; data = data->next) {
		chttp_dpage_ok(data);

		for (i = 0; i < data->offset; i++) {
			start = i;
			mid = 0;

			while (i < data->offset && data->data[i] != '\n') {
				if (!mid && data->data[i] == ':') {
					mid = i;
				}
				i++;
			}

			end = i;

			if (end == data->offset) {
				assert(first);
				break;
			}

			assert(end > start);
			assert(data->data[end] == '\n');
			assert(data->data[end - 1] == '\r');

			if (first) {
				first = 0;
				continue;
			}

			assert(mid);

			if ((mid - start) != name_len ||
			    strncasecmp((char*)&data->data[start], name, name_len)) {
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

			i = start - 1;
		}
	}
}

void
_parse_resp_status(struct chttp_context *ctx, size_t start, size_t end)
{
	struct chttp_dpage *data;
	size_t len;

	chttp_context_ok(ctx);
	chttp_dpage_ok(ctx->data_last);
	assert_zero(ctx->status);

	data = ctx->data_last;
	len = end - start;

	assert(strlen((char*)&data->data[start]) == len);

	if (len < 14) {
		ctx->error = CHTTP_ERR_RESP_PARSE;
		return;
	}

	if (strncmp((char*)&data->data[start], "HTTP/1.", 7)) {
		ctx->error = CHTTP_ERR_RESP_PARSE;
		return;
	}

	start = 7;

	if (data->data[start] == '0') {
		ctx->version = CHTTP_H_VERSION_1_0;
	} else if (data->data[start] == '1') {
		ctx->version = CHTTP_H_VERSION_1_1;
	} else {
		ctx->error = CHTTP_ERR_RESP_PARSE;
		return;
	}

	start++;

	if (data->data[start] != ' ' ||
	    data->data[start + 1] < '0' || data->data[start + 1] > '9' ||
	    data->data[start + 2] < '0' || data->data[start + 2] > '9' ||
	    data->data[start + 3] < '0' || data->data[start + 3] > '9') {
		ctx->error = CHTTP_ERR_RESP_PARSE;
		return;
	}

	ctx->status = (data->data[start + 1] - '0') * 100;
	ctx->status += (data->data[start + 2] - '0') * 10;
	ctx->status += data->data[start + 3] - '0';

	start += 4;

	if (ctx->status == 0 || data->data[start] != ' ') {
		ctx->error = CHTTP_ERR_RESP_PARSE;
		return;
	}

	start++;
	assert(start == 13);

	while (start < end) {
		if (data->data[start] < ' ' || data->data[start] > '~') {
			ctx->error = CHTTP_ERR_RESP_PARSE;
			return;
		}
		start++;
	}

	return;
}

void
chttp_parse_resp(struct chttp_context *ctx)
{
	struct chttp_dpage *data;
	size_t i, start, end, leftover;
	int first = 0;

	chttp_context_ok(ctx);
	assert(ctx->state == CHTTP_STATE_RESP_HEADERS);
	chttp_dpage_ok(ctx->data_last);

	data = ctx->data_last;

	// First parse
	if (!ctx->resp_last) {
		assert(data == ctx->data);
		assert(data->offset);
		assert_zero(ctx->status);

		ctx->resp_last = data->data;
		first = 1;
	} else if (ctx->resp_last == ctx->data->data) {
		first = 1;
	}

	i = ctx->resp_last - data->data;
	assert(i < data->offset);

	for (; i < data->offset; i++) {
		start = i;

		while (i < data->offset && data->data[i] != '\n') {
			if ((data->data[i] < ' ' && data->data[i] != '\r') ||
			    data->data[i] > '~') {
				ctx->error = CHTTP_ERR_RESP_PARSE;
				return;
			}
			i++;
		}

		end = i;

		// Incomplete line
		if (end == data->offset) {
			break;
		}

		assert(data->data[end] == '\n');

		if (end == start || data->data[end - 1] != '\r') {
			ctx->error = CHTTP_ERR_RESP_PARSE;
			return;
		}

		data->data[end - 1] = '\0';

		if (first) {
			_parse_resp_status(ctx, start, end - 1);

			if (ctx->error) {
				return;
			}

			first = 0;
		} else if (start + 1 == end) {
			ctx->state = CHTTP_STATE_RESP_BODY;

			if (end + 1 < data->offset) {
				ctx->resp_last = &data->data[end + 1];
			} else {
				ctx->resp_last = NULL;
			}

			return;
		}

		ctx->resp_last = &data->data[end + 1];
	}

	start = ctx->resp_last - data->data;
	assert(start <= data->offset);

	leftover = data->offset - start;

	// Incomplete line
	if (leftover) {
		// TODO this 1...
		chttp_dpage_get(ctx, leftover + 1);

		// Move over to a new dpage
		if (ctx->data_last != data) {
			assert(leftover < ctx->data_last->length);
			assert_zero(ctx->data_last->offset);

			chttp_dpage_append(ctx, ctx->resp_last, leftover);

			data->offset -= leftover;
			ctx->resp_last = ctx->data_last->data;
			data = ctx->data_last;
		}
	}

	// Make sure we have an available dpage
	chttp_dpage_get(ctx, 1);

	if (ctx->data_last != data) {
		chttp_dpage_ok(ctx->data_last);
		ctx->resp_last = ctx->data_last->data;
	}
}

const char *
chttp_get_header(struct chttp_context *ctx, const char *name)
{
	struct chttp_dpage *data;
	size_t name_len, i, start, mid, end;
	int first;

	chttp_context_ok(ctx);
	assert(name && *name);

	if (ctx->state != CHTTP_STATE_RESP_BODY) {
		chttp_ABORT("invalid state, headers must be read after receiving");
	}

	name_len = strlen(name);
	first = 1;

	for (data = ctx->data; data; data = data->next) {
		chttp_dpage_ok(data);

		for (i = 0; i < data->offset; i++) {
			start = i;
			mid = 0;

			while (i < data->offset && data->data[i] != '\0') {
				if (!mid && data->data[i] == ':') {
					mid = i;
				}
				i++;
			}

			end = i;

			assert(end != data->offset);
			assert(data->data[end + 1] == '\n');
			i++;

			if (end == start) {
				return NULL;
			}

			if (first && name == CHTTP_HEADER_REASON) {
				assert(data == ctx->data);
				assert_zero(start);
				assert(end >= 14);
				return ((char*)data->data + 13);
			}

			if (first) {
				first = 0;
				continue;
			}

			if (!mid) {
				continue;
			}

			if ((mid - start) != name_len ||
			    strncasecmp((char*)&data->data[start], name, name_len)) {
				continue;
			}

			// Found a match
			mid++;

			while (mid < end && data->data[mid] == ' ') {
				mid++;
			}

			return ((char*)data->data + mid);
		}
	}

	return NULL;
}