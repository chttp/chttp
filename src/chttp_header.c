/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <string.h>

const char *_CHTTP_HEADER_FIRST	 = "_FIRST";
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

	if (!strcmp(method, "HEAD")) {
		ctx->is_head = 1;
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

	if (!strcasecmp(name, "host")) {
		ctx->has_host = 1;
	}

	name_len = strlen(name);
	value_len = strlen(value);

	chttp_dpage_get(ctx, name_len + 2 + value_len + 2);

	chttp_dpage_append(ctx, name, name_len);
	chttp_dpage_append(ctx, ": ", 2);
	chttp_dpage_append(ctx, value, value_len);
	chttp_dpage_append(ctx, "\r\n", 2);
}

int
chttp_find_endline(struct chttp_dpage *data, size_t start, size_t *mid, size_t *end,
	int has_return, int *binary)
{
	chttp_dpage_ok(data);
	assert(start < data->offset);
	assert(end);

	*end = 0;

	if (mid) {
		*mid = 0;
	}
	if (binary) {
		*binary = 0;
	}

	if (data->data[start] == '\n') {
		return 1;
	}

	while (start < data->offset && data->data[start] != '\n') {
		if (mid && !*mid && data->data[start] == ':') {
			*mid = start;
		} else if (binary && ((data->data[start] < ' ' && data->data[start] != '\r') ||
		    data->data[start] > '~')) {
			*binary = 1;
		}
		start++;
	}

	if (start == data->offset) {
		return -1;
	}

	if (has_return && data->data[start - 1] != '\r') {
		return 1;
	} else if (!has_return && data->data[start - 1] != '\0') {
		return 1;
	}

	*end = start;

	return 0;
}

void
chttp_delete_header(struct chttp_context *ctx, const char *name)
{
	struct chttp_dpage *data;
	size_t name_len, start, mid, end, tail;
	int first, error;

	chttp_context_ok(ctx);
	assert(name && *name);

	if (ctx->state != CHTTP_STATE_INIT_HEADER) {
		chttp_ABORT("invalid state, headers must be deleted last before sending");
	}

	if (!strcasecmp(name, "host")) {
		ctx->has_host = 0;
	}

	name_len = strlen(name);
	first = 1;

	for (data = ctx->data; data; data = data->next) {
		chttp_dpage_ok(data);

		for (start = 0; start < data->offset; start++) {
			error = chttp_find_endline(data, start, &mid, &end, 1, NULL);

			if (error) {
				assert(first);
				break;
			}

			if (first) {
				first = 0;
				start = end;
				continue;
			}

			if ((mid - start) != name_len ||
			    strncasecmp((char*)&data->data[start], name, name_len)) {
				start = end;
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

			start--;
		}
	}
}

static void
_parse_resp_status(struct chttp_context *ctx, size_t start, size_t end)
{
	struct chttp_dpage *data;
	size_t len;

	chttp_context_ok(ctx);
	chttp_dpage_ok(ctx->data_last);
	assert_zero(ctx->status);

	data = ctx->data_last;
	len = end - start;

	// TODO remove
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
chttp_parse_response(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);

	return chttp_parse(ctx, &_parse_resp_status);
}
void
chttp_parse(struct chttp_context *ctx, chttp_parse_f *func)
{
	struct chttp_dpage *data;
	size_t start, end;
	int first = 0, binary, error;

	chttp_context_ok(ctx);
	assert(ctx->state == CHTTP_STATE_RESP_HEADERS);
	chttp_dpage_ok(ctx->data_last);
	assert(func);

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

	start = chttp_dpage_resp_start(ctx);

	for (; start < data->offset; start++) {
		error = chttp_find_endline(data, start, NULL, &end, 1, &binary);

		// Incomplete line
		if (error == -1) {
			break;
		}

		if (error || binary) {
			ctx->error = CHTTP_ERR_RESP_PARSE;
			return;
		}

		data->data[end - 1] = '\0';

		if (first) {
			func(ctx, start, end - 1);

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
		start = end;
	}

	chttp_dpage_shift_full(ctx);
}

const char *
chttp_get_header(struct chttp_context *ctx, const char *name)
{
	struct chttp_dpage *data;
	size_t name_len, start, mid, end;
	int first;

	chttp_context_ok(ctx);
	assert(name && *name);

	if (ctx->state < CHTTP_STATE_RESP_BODY || ctx->state > CHTTP_STATE_CLOSED) {
		chttp_ABORT("invalid state, headers must be read after receiving");
	}

	name_len = strlen(name);
	first = 1;

	for (data = ctx->data; data; data = data->next) {
		chttp_dpage_ok(data);

		for (start = 0; start < data->offset; start++) {
			assert_zero(chttp_find_endline(data, start, &mid, &end, 0, NULL));

			end--;

			if (end == start) {
				return NULL;
			}

			if (first && name == _CHTTP_HEADER_FIRST) {
				assert_zero(start);
				return ((char*)data->data);
			} else if (first && name == CHTTP_HEADER_REASON) {
				assert_zero(start);
				assert(end >= 14);
				return ((char*)data->data + 13);
			}

			if (first) {
				first = 0;
				start = end + 1;
				continue;
			}

			if (!mid) {
				start = end + 1;
				continue;
			}

			if ((mid - start) != name_len ||
			    strncasecmp((char*)&data->data[start], name, name_len)) {
				start = end + 1;
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