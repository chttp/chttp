/*
 * Copyright (c) 2021 chttp
 *
 */

#include "test/chttp_test.h"

static void
_client_finish(struct chttp_text_context *ctx)
{
	assert(ctx);
	chttp_test_ERROR(!ctx->context, "chttp context does not exist");
	chttp_context_ok(ctx->context);
	chttp_test_ERROR(ctx->context->error, "chttp context has an error");

	chttp_context_free(ctx->context);
	ctx->context = NULL;

}

static inline void
_test_context_ok(struct chttp_text_context *ctx)
{
	assert(ctx);
	chttp_test_ERROR(!ctx->context, "chttp context does not exist");
	chttp_context_ok(ctx->context);
	chttp_test_ok(chttp_test_convert(ctx));
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

	chttp_test_register_finish(ctx, "chttp_client", _client_finish);

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
	chttp_test_ERROR(port <= 0 || port > INT16_MAX, "invalid port");

	chttp_send(ctx->context, cmd->params[0], port, 0);
	chttp_recv(ctx->context);

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "request sent");
}

void
chttp_test_cmd_chttp_status(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
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