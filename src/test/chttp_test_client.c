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
	chttp_test_ERROR(!ctx->context, "chttp context does not exist");
	chttp_context_ok(ctx->context);
	chttp_test_ok(chttp_test_convert(ctx));
}

static void
_test_client_finish(struct chttp_text_context *ctx)
{
	assert(ctx);
	chttp_test_ERROR(!ctx->context, "chttp context does not exist");
	chttp_context_ok(ctx->context);
	chttp_test_ERROR(ctx->context->error, "chttp context has an error (%s)",
		chttp_error_msg(ctx->context));

	chttp_context_free(ctx->context);
	ctx->context = NULL;

}

void
chttp_test_cmd_chttp_init(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	assert(ctx);

	chttp_test_ERROR_param_count(cmd, 0);
	chttp_test_ERROR(ctx->context != NULL, "chttp context exists");

	ctx->context = &ctx->scontext;

	chttp_context_init(ctx->context);
	chttp_context_ok(ctx->context);

	chttp_test_register_finish(ctx, "chttp_client", _test_client_finish);

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "context initialized");
}

void
chttp_test_cmd_chttp_url(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	char *url;

	_test_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 1);

	url = cmd->params[0];
	chttp_test_ERROR_string(url);

	chttp_set_url(ctx->context, url);
}

void
chttp_test_cmd_chttp_send(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	long port;

	_test_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 2);
	chttp_test_ERROR_string(cmd->params[0]);

	port = chttp_test_parse_long(cmd->params[1]);
	chttp_test_ERROR(port <= 0 || port > UINT16_MAX, "invalid port");

	chttp_send(ctx->context, cmd->params[0], port, 0);
	chttp_test_ERROR(ctx->context->error, "chttp send error");

	chttp_receive(ctx->context);

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "request sent and received");
}

void
chttp_test_cmd_chttp_send_only(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	long port;

	_test_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 2);
	chttp_test_ERROR_string(cmd->params[0]);

	port = chttp_test_parse_long(cmd->params[1]);
	chttp_test_ERROR(port <= 0 || port > UINT16_MAX, "invalid port");

	chttp_send(ctx->context, cmd->params[0], port, 0);

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "request sent");
}

void
chttp_test_cmd_chttp_receive(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	_test_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 0);

	chttp_receive(ctx->context);

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "request received");
}

void
chttp_test_cmd_chttp_status_match(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	long status;

	_test_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 1);

	status = chttp_test_parse_long(cmd->params[0]);
	chttp_test_ERROR(status <= 0 || status > 999, "invalid status");

	chttp_test_ERROR(ctx->context->status != status,
		"invalid status (wanted %ld, found %ld)", status, ctx->context->status);

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "status OK (%ld)", status);
}

static void
_test_header_match(struct chttp_text_context *ctx, const char *header, const char *expected,
    int sub)
{
	const char *header_value;

	_test_context_ok(ctx);
	chttp_context_ok(ctx->context);
	assert(header);
	assert(expected);

	header_value = chttp_get_header(ctx->context, header);
	chttp_test_ERROR(!header_value, "header %s not found", header);

	if (sub && *expected) {
		chttp_test_ERROR(!strstr(header_value, expected), "value %s not found in header "
			"%s:%s", expected, header, header_value);
	} else if (!sub) {
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
	chttp_test_ERROR_string(cmd->params[0]);

	_test_header_match(ctx, CHTTP_HEADER_REASON, cmd->params[0], 0);
}

void
chttp_test_cmd_chttp_header_match(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	_test_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 2);
	chttp_test_ERROR_string(cmd->params[0]);
	chttp_test_ERROR_string(cmd->params[1]);

	_test_header_match(ctx, cmd->params[0], cmd->params[1], 0);
}

void
chttp_test_cmd_chttp_header_submatch(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	_test_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 2);
	chttp_test_ERROR_string(cmd->params[0]);

	_test_header_match(ctx, cmd->params[0], cmd->params[1], 1);
}

static void
_test_body_match(struct chttp_text_context *ctx, const char *expected, int sub)
{
	char *body;
	size_t body_len, size, old_size;

	_test_context_ok(ctx);
	chttp_context_ok(ctx->context);
	chttp_test_ERROR(ctx->context->state != CHTTP_STATE_RESP_BODY, "chttp no body found");
	assert(expected);

	body = NULL;
	body_len = 0;
	size = 1024;

	do {
		old_size = size;
		size *= 2;
		assert(size / 2 == old_size);

		body = realloc(body, size + 1);
		assert(body);

		body_len += chttp_get_body(ctx->context, body + body_len,
			size - body_len);
	} while (ctx->context->state == CHTTP_STATE_RESP_BODY);

	chttp_test_log(ctx, CHTTP_LOG_VERY_VERBOSE, "read %zu body bytes", body_len);

	body[body_len] = '\0';

	if (sub && *expected) {
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
	_test_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 1);

	_test_body_match(ctx, cmd->params[0], 0);
}

void
chttp_test_cmd_chttp_body_submatch(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	_test_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 1);

	_test_body_match(ctx, cmd->params[0], 1);
}