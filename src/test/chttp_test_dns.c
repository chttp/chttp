/*
 * Copyright (c) 2021 chttp
 *
 */

#include "test/chttp_test.h"

void
chttp_test_cmd_dns_debug(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_test *test;

	chttp_test_ERROR_param_count(cmd, 0);
	test = chttp_test_convert(ctx);

	if (test->verbocity >= CHTTP_LOG_VERBOSE) {
		chttp_dns_cache_debug();
	}
}