/*
 * Copyright (c) 2021 chttp
 *
 */

#include "test/chttp_test.h"

#include <stdio.h>

void
chttp_test_cmd_chttp_test(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	assert(ctx);
	assert(cmd);

	chttp_test_ERROR(cmd->param_count != 1, "chttp_test invalid parameter");

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "%s", cmd->params[0]);
}