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

	printf("SUCCESS\n");
}