/*
 * Copyright (c) 2021 chttp
 *
 */

#include "test/chttp_test.h"

#include <stdlib.h>
#include <string.h>

static inline void
_test_context_ok(struct chttp_text_context *ctx)
{
	assert(ctx);
	chttp_test_ERROR(!ctx->chttp, "chttp context does not exist");
	chttp_context_ok(ctx->chttp);
	chttp_test_ok(chttp_test_convert(ctx));
}

static void
_test_client_finish(struct chttp_text_context *ctx)
{
	assert(ctx);
	chttp_test_ERROR(!ctx->chttp, "chttp context does not exist");
	chttp_context_ok(ctx->chttp);
	chttp_test_ERROR(ctx->chttp->error, "chttp context has an error (%s)",
		chttp_error_msg(ctx->chttp));

	chttp_context_free(ctx->chttp);
	ctx->chttp = NULL;

}

void
chttp_test_cmd_chttp_init(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	assert(ctx);

	chttp_test_ERROR_param_count(cmd, 0);
	chttp_test_ERROR(ctx->chttp != NULL, "chttp context exists");

	ctx->chttp = &ctx->chttp_static;

	chttp_context_init(ctx->chttp);
	chttp_context_ok(ctx->chttp);

	chttp_test_register_finish(ctx, "chttp_client", _test_client_finish);

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "context initialized");
}

void
chttp_test_cmd_chttp_init_dynamic(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	long size = 0;

	assert(ctx);

	chttp_test_ERROR(cmd->param_count > 1, "too many parameters");
	chttp_test_ERROR(ctx->chttp != NULL, "chttp context exists");

	if (cmd->param_count == 1) {
		size = chttp_test_parse_long(cmd->params[0].value);
		chttp_test_ERROR(size <= 0, "chttp size must be greater than 0");
	}

	_DEBUG_CHTTP_DPAGE_MIN_SIZE = (size_t)size;

	ctx->chttp = chttp_context_alloc();
	chttp_context_ok(ctx->chttp);

	chttp_test_register_finish(ctx, "chttp_client", _test_client_finish);

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "context initialized");
}

void
chttp_test_cmd_chttp_version(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	long version;

	_test_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 1);

	version = chttp_test_parse_long(cmd->params[0].value);

	switch (version) {
		case 10:
			chttp_set_version(ctx->chttp, CHTTP_H_VERSION_1_0);
			return;
		case 11:
			chttp_set_version(ctx->chttp, CHTTP_H_VERSION_1_1);
			return;
	}

	chttp_test_ERROR(1, "unsupported chttp version %ld", version);
}

void
chttp_test_cmd_chttp_method(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	_test_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 1);

	chttp_set_method(ctx->chttp, cmd->params[0].value);
}

void
chttp_test_cmd_chttp_url(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	_test_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 1);

	chttp_set_url(ctx->chttp, cmd->params[0].value);
}

void
chttp_test_cmd_chttp_add_header(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	_test_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 2);

	chttp_add_header(ctx->chttp, cmd->params[0].value, cmd->params[1].value);
}

void
chttp_test_cmd_chttp_delete_header(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	_test_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 1);

	chttp_delete_header(ctx->chttp, cmd->params[0].value);
}

void
chttp_test_cmd_chttp_send_only(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	long port;

	_test_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 2);

	port = chttp_test_parse_long(cmd->params[1].value);
	chttp_test_ERROR(port <= 0 || port > UINT16_MAX, "invalid port");

	chttp_send(ctx->chttp, cmd->params[0].value, port, 0);

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "request sent");
}

void
chttp_test_cmd_chttp_receive(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_test *test;

	_test_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 0);
	test = chttp_test_convert(ctx);

	chttp_receive(ctx->chttp);

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "request received");

	if (test->verbocity == CHTTP_LOG_VERY_VERBOSE) {
		printf("--- ");
		chttp_context_debug(ctx->chttp);
	}
}

void
chttp_test_cmd_chttp_send(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	_test_context_ok(ctx);

	chttp_test_cmd_chttp_send_only(ctx, cmd);
	chttp_test_ERROR(ctx->chttp->error, "chttp send error");

	cmd->param_count = 0;
	chttp_test_cmd_chttp_receive(ctx, cmd);
}

void
chttp_test_cmd_chttp_status_match(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	long status;

	_test_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 1);

	status = chttp_test_parse_long(cmd->params[0].value);
	chttp_test_ERROR(status <= 0 || status > 999, "invalid status");

	chttp_test_ERROR(ctx->chttp->status != status,
		"invalid status (wanted %ld, found %d)", status, ctx->chttp->status);

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "status OK (%ld)", status);
}

static void
_test_header_match(struct chttp_text_context *ctx, const char *header, const char *expected,
    int sub)
{
	const char *header_value, *dup;

	_test_context_ok(ctx);
	chttp_context_ok(ctx->chttp);
	assert(header);

	header_value = chttp_get_header(ctx->chttp, header);
	chttp_test_ERROR(!header_value, "header %s not found", header);

	dup = chttp_get_header_pos(ctx->chttp, header, 1);
	chttp_test_warn(dup != NULL, "duplicate %s header found", header);

	if (!expected) {
		chttp_test_log(ctx, CHTTP_LOG_VERY_VERBOSE, "header exists %s", header);
		return;
	}

	if (sub) {
		chttp_test_ERROR(!strstr(header_value, expected), "value %s not found in header "
			"%s:%s", expected, header, header_value);
	} else {
		chttp_test_ERROR(strcmp(header_value, expected), "headers dont match, found %s:%s, "
			"expected %s", header, header_value, expected);
	}

	chttp_test_log(ctx, CHTTP_LOG_VERY_VERBOSE, "headers match %s:%s%s%s%s",
		header, header_value, sub ? " (" : "", sub ? expected : "", sub ? ")" : "");
}

void
chttp_test_cmd_chttp_reason_match(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	_test_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 1);

	_test_header_match(ctx, CHTTP_HEADER_REASON, cmd->params[0].value, 0);
}

void
chttp_test_cmd_chttp_header_match(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	_test_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 2);

	_test_header_match(ctx, cmd->params[0].value, cmd->params[1].value, 0);
}

void
chttp_test_cmd_chttp_header_submatch(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	_test_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 2);

	_test_header_match(ctx, cmd->params[0].value, cmd->params[1].value, 1);
}

void
chttp_test_cmd_chttp_header_exists(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	_test_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 1);

	_test_header_match(ctx, cmd->params[0].value, NULL, 1);
}

void
chttp_test_cmd_chttp_version_match(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	long version;
	enum chttp_version expected = -1;

	_test_context_ok(ctx);
	chttp_context_ok(ctx->chttp);
	chttp_test_ERROR_param_count(cmd, 1);

	version = chttp_test_parse_long(cmd->params[0].value);

	switch (version) {
		case 10:
			expected = CHTTP_H_VERSION_1_0;
			break;
		case 11:
			expected = CHTTP_H_VERSION_1_1;
			break;
		default:
			chttp_test_ERROR(1, "unsupported chttp version %ld", version);
	}

	chttp_test_ERROR(expected != ctx->chttp->version, "version mismatch, expected %d, found %d",
		expected, ctx->chttp->version);
}

static void
_test_body_match(struct chttp_text_context *ctx, const char *expected, int sub, size_t size)
{
	char *body;
	size_t body_len, old_size, calls;

	_test_context_ok(ctx);
	chttp_context_ok(ctx->chttp);
	chttp_test_ERROR(ctx->chttp->state != CHTTP_STATE_RESP_BODY, "chttp no body found");

	body = NULL;
	body_len = 0;
	calls = 0;

	if (size == 0) {
		size = 1024;
	}

	do {
		if (calls) {
			old_size = size;
			size *= 2;
			assert(size / 2 == old_size);
		}

		body = realloc(body, size + 1);
		assert(body);

		body_len += chttp_get_body(ctx->chttp, body + body_len,
			size - body_len);

		calls++;
	} while (ctx->chttp->state == CHTTP_STATE_RESP_BODY);

	chttp_test_log(ctx, CHTTP_LOG_VERY_VERBOSE, "read %zu body bytes in %zu call(s)",
		body_len, calls);

	if (!expected) {
		free(body);
		return;
	}

	chttp_test_ERROR(ctx->chttp->error, "chttp error %s", chttp_error_msg(ctx->chttp));

	body[body_len] = '\0';

	if (sub) {
		chttp_test_ERROR(!strstr(body, expected), "value %s not found in body", expected);
	} else if (!sub) {
		chttp_test_ERROR(strcmp(body, expected), "bodies dont match");
	}

	chttp_test_log(ctx, CHTTP_LOG_VERY_VERBOSE, "bodies match");

	free(body);
}

void
chttp_test_cmd_chttp_body_match(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	long size = 0;

	_test_context_ok(ctx);
	chttp_test_ERROR(cmd->param_count > 2, "too many parameters");
	chttp_test_ERROR(cmd->param_count < 1, "missing parameters");

	if (cmd->param_count == 2) {
		size = chttp_test_parse_long(cmd->params[1].value);
		chttp_test_ERROR(size < 0, "invalid size");
	}

	_test_body_match(ctx, cmd->params[0].value, 0, size);
}

void
chttp_test_cmd_chttp_body_submatch(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	_test_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 1);

	_test_body_match(ctx, cmd->params[0].value, 1, 0);
}

void
chttp_test_cmd_chttp_body_read(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	_test_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 0);

	_test_body_match(ctx, NULL, 0, 0);
}

void
chttp_test_cmd_chttp_body_md5(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_test_md5 md5;
	uint8_t buf[8192];
	size_t body_len, len, calls;

	_test_context_ok(ctx);
	chttp_context_ok(ctx->chttp);
	chttp_test_ERROR(ctx->chttp->state != CHTTP_STATE_RESP_BODY, "chttp no body found");
	chttp_test_ERROR_param_count(cmd, 0);

	chttp_test_md5_init(&md5);

	body_len = 0;
	calls = 0;

	do {
		len = chttp_get_body(ctx->chttp, buf, sizeof(buf));

		chttp_test_md5_update(&md5, buf, len);

		body_len += len;
		calls++;
	} while (ctx->chttp->state == CHTTP_STATE_RESP_BODY);

	chttp_test_ERROR(ctx->chttp->error, "chttp error %s", chttp_error_msg(ctx->chttp));

	chttp_test_log(ctx, CHTTP_LOG_VERY_VERBOSE, "read %zu body bytes in %zu call(s)",
		body_len, calls);

	chttp_test_md5_final(&md5);
	chttp_test_md5_store_client(ctx, &md5);

	chttp_test_log(ctx, CHTTP_LOG_VERY_VERBOSE, "body md5 %s", ctx->md5_client);
}

void
chttp_test_cmd_chttp_take_error(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	_test_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 0);

	chttp_context_ok(ctx->chttp);

	chttp_test_ERROR(!ctx->chttp->error, "chttp error not found");

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "chttp error %s",
		chttp_error_msg(ctx->chttp));

	chttp_finish(ctx->chttp);

	ctx->chttp->error = 0;
}