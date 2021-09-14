/*
 * Copyright (c) 2021 chttp
 *
 */

#include "test/chttp_test.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

void
chttp_test_cmd_chttp_test(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_test *test;

	test = chttp_test_convert(ctx);
	chttp_test_ERROR_param_count(cmd, 1);
	chttp_test_ERROR(test->cmds != 1, "test file must begin with chttp_test");

	chttp_test_unescape(&cmd->params[0]);

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "%s", cmd->params[0].value);
}

void
chttp_test_cmd_sleep_ms(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	long ms;

	assert(ctx);
	chttp_test_ERROR_param_count(cmd, 1);

	ms = chttp_test_parse_long(cmd->params[0].value);
	chttp_test_ERROR(ms < 0, "invalid sleep time");

	chttp_test_sleep_ms(ms);

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "slept %ldms", ms);
}

void
chttp_test_cmd_connect_or_skip(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_context *chttp;
	char chttp_buf[CHTTP_CTX_SIZE];
	char *host;
	long port;

	assert(ctx);
	chttp_test_ERROR_param_count(cmd, 2);

	host = cmd->params[0].value;
	port = chttp_test_parse_long(cmd->params[1].value);
	chttp_test_ERROR(port <= 0 || port > UINT16_MAX, "invalid port");

	chttp_context_init_buf(chttp_buf, sizeof(chttp_buf));
	chttp = (struct chttp_context*)chttp_buf;

	chttp_dns_lookup(chttp, host, port);

	if (chttp->error) {
		chttp_context_free(chttp);
		chttp_test_skip(ctx);
		chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "cannot connect to %s:%ld", host, port);
		return;
	}

	chttp_tcp_connect(chttp);

	if (chttp->error) {
		chttp_context_free(chttp);
		chttp_test_skip(ctx);
		chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "cannot connect to %s:%ld", host, port);
		return;
	}

	chttp_context_free(chttp);

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "valid address found %s:%ld", host, port);

	return;
}

void
chttp_test_cmd_equal(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	int ret;

	assert(ctx);
	chttp_test_ERROR_param_count(cmd, 2);

	ret = strcmp(cmd->params[0].value, cmd->params[1].value);

	chttp_test_ERROR(ret, "not equal '%s' != '%s'", cmd->params[0].value, cmd->params[1].value);

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "equal '%s'", cmd->params[0].value);
}