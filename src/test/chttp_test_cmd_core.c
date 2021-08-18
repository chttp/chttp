/*
 * Copyright (c) 2021 chttp
 *
 */

#include "test/chttp_test.h"

#include <limits.h>
#include <stdio.h>

void
chttp_test_cmd_chttp_test(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	assert(ctx);
	assert(cmd);

	chttp_test_ERROR(cmd->param_count != 1, "chttp_test invalid parameter count (1)");

	chttp_test_log(CHTTP_LOG_VERBOSE, "%s", cmd->params[0]);
}

void
chttp_test_cmd_connect_or_skip(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_context chttp;
	char *host;
	long port;

	assert(ctx);
	assert(cmd);

	chttp_test_ERROR(cmd->param_count != 2,
		"connect_or_skip invalid parameter count (2)");
	chttp_test_ERROR(!cmd->params[0] || !*cmd->params[0],
		"connect_or_skip invalid hostname (1)");

	host = cmd->params[0];
	port = chttp_test_parse_long(cmd->params[1]);

	chttp_test_ERROR(port <= 0 || port > INT16_MAX,
		"connect_or_skip invalid port (2)");

	chttp_context_init(&chttp);
	chttp_dns_lookup(&chttp, host, port);

	if (chttp.error) {
		chttp_context_free(&chttp);
		chttp_test_skip(ctx);
		chttp_test_log(CHTTP_LOG_VERBOSE, "cannot connect to %s:%d", host, port);
		return;
	}

	chttp_tcp_connect(&chttp);

	if (chttp.error) {
		chttp_context_free(&chttp);
		chttp_test_skip(ctx);
		chttp_test_log(CHTTP_LOG_VERBOSE, "cannot connect to %s:%d", host, port);
		return;
	}

	chttp_context_free(&chttp);

	chttp_test_log(CHTTP_LOG_VERBOSE, "valid address found %s:%d", host, port);

	return;
}