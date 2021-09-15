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
	size_t method_len;

	chttp_context_ok(ctx);
	assert(method && *method);
	assert_zero(ctx->data_start.dpage);

	if (ctx->state != CHTTP_STATE_NONE) {
		chttp_ABORT("invalid state, method must before url or headers");
	}

	if (!strcmp(method, "HEAD")) {
		ctx->is_head = 1;
	}

	method_len = strlen(method);

	chttp_dpage_append(ctx, method, method_len);

	if (ctx->version == CHTTP_H_VERSION_DEFAULT) {
		ctx->version = CHTTP_DEFAULT_H_VERSION;
	}

	ctx->state = CHTTP_STATE_INIT_METHOD;

	// Mark the start
	chttp_dpage_ok(ctx->dpage_last);
	ctx->data_start.dpage = ctx->dpage_last;
	ctx->data_start.offset = ctx->dpage_last->offset;
	assert(ctx->data_start.offset >= method_len);
	ctx->data_start.offset -= method_len;
	ctx->data_start.length = 0;
	assert_zero(strncmp((char*)&ctx->data_start.dpage->data[ctx->data_start.offset], method,
		method_len));
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

	// TODO close (dont forget delete)

	name_len = strlen(name);
	value_len = strlen(value);

	chttp_dpage_get(ctx, name_len + 2 + value_len + 2);

	chttp_dpage_append(ctx, name, name_len);
	chttp_dpage_append(ctx, ": ", 2);
	chttp_dpage_append(ctx, value, value_len);
	chttp_dpage_append(ctx, "\r\n", 2);
}

/*
 * greater than 0, error
 * less than 0, need more
 * equal to 0, match
 */
int
chttp_find_endline(struct chttp_dpage *dpage, size_t start, size_t *mid, size_t *end,
	int has_return, int *binary)
{
	chttp_dpage_ok(dpage);
	assert(start < dpage->offset);
	assert(end);

	*end = 0;

	if (mid) {
		*mid = 0;
	}
	if (binary) {
		*binary = 0;
	}

	if (dpage->data[start] == '\n') {
		return 1;
	}

	while (start < dpage->offset && dpage->data[start] != '\n') {
		if (mid && !*mid && dpage->data[start] == ':') {
			*mid = start;
		} else if (binary && ((dpage->data[start] < ' ' && dpage->data[start] != '\r') ||
		    dpage->data[start] > '~')) {
			*binary = 1;
		}
		start++;
	}

	if (start == dpage->offset) {
		return -1;
	}

	if (has_return && dpage->data[start - 1] != '\r') {
		return 1;
	} else if (!has_return && dpage->data[start - 1] != '\0') {
		return 1;
	}

	*end = start;

	return 0;
}

void
chttp_delete_header(struct chttp_context *ctx, const char *name)
{
	struct chttp_dpage *dpage;
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

	for (dpage = ctx->dpage; dpage; dpage = dpage->next) {
		chttp_dpage_ok(dpage);

		for (start = 0; start < dpage->offset; start++) {
			error = chttp_find_endline(dpage, start, &mid, &end, 1, NULL);

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
			    strncasecmp((char*)&dpage->data[start], name, name_len)) {
				start = end;
				continue;
			}

			// Shift the tail up the dpage
			tail = dpage->offset - end - 1;
			assert(tail < dpage->offset);

			if (tail) {
				memmove(&dpage->data[start], &dpage->data[end + 1], tail);
			}

			dpage->offset -= (end - start) + 1;
			assert(dpage->offset < dpage->length);

			start--;
		}
	}
}

static void
_parse_resp_status(struct chttp_context *ctx, size_t start, size_t end)
{
	struct chttp_dpage *dpage;
	size_t len;

	chttp_context_ok(ctx);
	chttp_dpage_ok(ctx->dpage_last);
	assert_zero(ctx->status);
	assert_zero(ctx->seen_first);

	dpage = ctx->dpage_last;
	len = end - start;

	// TODO remove
	assert(strlen((char*)&dpage->data[start]) == len);

	if (len < 14) {
		chttp_error(ctx, CHTTP_ERR_RESP_PARSE);
		return;
	}

	if (strncmp((char*)&dpage->data[start], "HTTP/1.", 7)) {
		chttp_error(ctx, CHTTP_ERR_RESP_PARSE);
		return;
	}

	start = 7;

	if (dpage->data[start] == '0') {
		ctx->version = CHTTP_H_VERSION_1_0;
	} else if (dpage->data[start] == '1') {
		ctx->version = CHTTP_H_VERSION_1_1;
	} else {
		chttp_error(ctx, CHTTP_ERR_RESP_PARSE);
		return;
	}

	start++;

	if (dpage->data[start] != ' ' ||
	    dpage->data[start + 1] < '0' || dpage->data[start + 1] > '9' ||
	    dpage->data[start + 2] < '0' || dpage->data[start + 2] > '9' ||
	    dpage->data[start + 3] < '0' || dpage->data[start + 3] > '9') {
		chttp_error(ctx, CHTTP_ERR_RESP_PARSE);
		return;
	}

	ctx->status = (dpage->data[start + 1] - '0') * 100;
	ctx->status += (dpage->data[start + 2] - '0') * 10;
	ctx->status += dpage->data[start + 3] - '0';

	start += 4;

	if (ctx->status == 0 || dpage->data[start] != ' ') {
		chttp_error(ctx, CHTTP_ERR_RESP_PARSE);
		return;
	}

	start++;
	assert(start == 13);

	while (start < end) {
		if (dpage->data[start] < ' ' || dpage->data[start] > '~') {
			chttp_error(ctx, CHTTP_ERR_RESP_PARSE);
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

	chttp_parse_headers(ctx, &_parse_resp_status);
}
void
chttp_parse_headers(struct chttp_context *ctx, chttp_parse_f *func)
{
	struct chttp_dpage *dpage;
	size_t start, end, i;
	int binary, error;

	chttp_context_ok(ctx);
	assert(ctx->state == CHTTP_STATE_RESP_HEADERS);
	chttp_dpage_ok(ctx->dpage_last);
	assert(func);

	dpage = ctx->dpage_last;

	// First parse
	if (!ctx->data_start.dpage) {
		assert(dpage == ctx->dpage);
		assert(dpage->offset);
		assert_zero(ctx->seen_first);

		ctx->data_start.dpage = dpage;
		ctx->data_start.offset = 0;
		ctx->data_start.length = 0;
	}

	start = chttp_dpage_resp_start(ctx);

	for (; start < dpage->offset; start++) {
		error = chttp_find_endline(dpage, start, NULL, &end, 1, &binary);

		// Incomplete line
		if (error < 0) {
			break;
		}

		if (error || binary) {
			chttp_error(ctx, CHTTP_ERR_RESP_PARSE);
			return;
		}

		dpage->data[end - 1] = '\0';

		for (i = end - 2; i > start; i--) {
			if (dpage->data[i] == ' ') {
				dpage->data[i] = '\0';
			} else {
				break;
			}
		}

		if (!ctx->seen_first) {
			func(ctx, start, end - 1);

			if (ctx->error) {
				return;
			}

			ctx->seen_first = 1;
		} else if (start + 1 == end) {
			ctx->state = CHTTP_STATE_RESP_BODY;

			if (end + 1 < dpage->offset) {
				assert(ctx->data_start.dpage == dpage);
				ctx->data_start.offset = end + 1;
			} else {
				ctx->data_start.dpage = NULL;
			}

			return;
		}

		assert(ctx->data_start.dpage == dpage);
		ctx->data_start.offset = end + 1;
		start = end;
	}

	chttp_dpage_shift_full(ctx);
}

const char *
chttp_get_header_pos(struct chttp_context *ctx, const char *name, size_t pos)
{
	struct chttp_dpage *dpage;
	size_t name_len, start, mid, end;
	int first;

	chttp_context_ok(ctx);
	assert(name && *name);

	if (ctx->state < CHTTP_STATE_RESP_BODY || ctx->state > CHTTP_STATE_CLOSED) {
		chttp_ABORT("invalid state, headers must be read after receiving");
	}

	name_len = strlen(name);
	first = 1;

	for (dpage = ctx->dpage; dpage; dpage = dpage->next) {
		chttp_dpage_ok(dpage);

		for (start = 0; start < dpage->offset; start++) {
			assert_zero(chttp_find_endline(dpage, start, &mid, &end, 0, NULL));

			end--;

			if (end == start) {
				return NULL;
			}

			if (first && name == _CHTTP_HEADER_FIRST) {
				assert_zero(start);

				if (pos) {
					return NULL;
				}

				return ((char*)dpage->data);
			} else if (first && name == CHTTP_HEADER_REASON) {
				assert_zero(start);
				assert(end >= 14);

				if (pos) {
					return NULL;
				}

				return ((char*)dpage->data + 13);
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
			    strncasecmp((char*)&dpage->data[start], name, name_len)) {
				start = end + 1;
				continue;
			}

			if (pos > 0) {
				pos--;
				continue;
			}

			// Found a match
			mid++;

			while (mid < end && dpage->data[mid] == ' ') {
				mid++;
			}

			return ((char*)dpage->data + mid);
		}
	}

	return NULL;
}

const char *
chttp_get_header(struct chttp_context *ctx, const char *name)
{
	chttp_context_ok(ctx);

	return chttp_get_header_pos(ctx, name, 0);
}