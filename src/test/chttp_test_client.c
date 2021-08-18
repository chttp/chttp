/*
 * Copyright (c) 2021 chttp
 *
 */

#include "test/chttp_test.h"

static void
_client_finish(struct chttp_text_context *ctx)
{
	assert(ctx);
	chttp_test_ERROR(!ctx->context, "chttp_init context does not exist");
	chttp_context_ok(ctx->context);
	chttp_test_ERROR(ctx->context->error, "chttp_init context has an error");

	chttp_context_free(ctx->context);
	ctx->context = NULL;

}

void
chttp_test_cmd_chttp_init(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	assert(ctx);
	assert(cmd);

	chttp_test_ERROR(cmd->param_count, "chttp_init invalid parameters");
	chttp_test_ERROR(ctx->context != NULL, "chttp_init context exists");

	chttp_test_register_finish(ctx, _client_finish);

	ctx->context = &ctx->scontext;

	chttp_context_init(ctx->context);
	chttp_context_ok(ctx->context);

	chttp_test_log(CHTTP_LOG_VERBOSE, "context initialized");
}

void
chttp_test_cmd_chttp_url(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	char *url;

	assert(ctx);
	assert(cmd);

	chttp_test_ERROR(cmd->param_count != 1, "chttp_url invalid parameters (1)");

	url = cmd->params[0];

	chttp_test_ERROR(!url || !*url, "chttp_url invalid url");
	chttp_test_ERROR(!ctx->context, "chttp_url context does not exist");
	chttp_context_ok(ctx->context);

	chttp_set_url(ctx->context, url);
}

void
chttp_test_cmd_chttp_send(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	long port;

	assert(ctx);
	assert(cmd);

	chttp_test_ERROR(!ctx->context, "chttp_url context does not exist");
	chttp_context_ok(ctx->context);
	chttp_test_ERROR(cmd->param_count != 2,
		"chttp_url invalid parameter count (2)");
	chttp_test_ERROR(!cmd->params[0] || !*cmd->params[0],
		"chttp_url invalid hostname (1)");

	port = chttp_test_parse_long(cmd->params[1]);

	chttp_test_ERROR(port <= 0 || port > INT16_MAX,
		"chttp_url invalid port (2)");

	chttp_send(ctx->context, cmd->params[0], port, 0);
	chttp_recv(ctx->context);

	chttp_test_log(CHTTP_LOG_VERBOSE, "request sent");
}

void
chttp_test_cmd_chttp_status(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	long status;

	assert(ctx);
	assert(cmd);

	chttp_test_ERROR(!ctx->context, "chttp_status context does not exist");
	chttp_context_ok(ctx->context);
	chttp_test_ERROR(cmd->param_count != 1,
		"chttp_status invalid parameter count (1)");

	status = chttp_test_parse_long(cmd->params[0]);

	chttp_test_ERROR(status <= 0 || status > 999,
		"chttp_status invalid status (1)");

	chttp_test_ERROR(ctx->context->status != status,
		"invalid status (wanted %d, found %d)", status, ctx->context->status);

	chttp_test_log(CHTTP_LOG_VERBOSE, "status OK");
}