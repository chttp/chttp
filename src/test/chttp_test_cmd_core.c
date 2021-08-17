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
	assert(cmd->param_count == 1);

	printf("SUCCESS: %s\n", cmd->params[0]);
}