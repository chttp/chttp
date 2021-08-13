/*
 * Copyright (c) 2021 chttp
 *
 */

#ifndef CHTTP_TEST_CMD

#define CHTTP_TEST_MAX_PARAMS		16

struct chttp_test_cmd {
	const char			*name;

	size_t				param_count;
	char				*params[CHTTP_TEST_MAX_PARAMS];
};

struct chttp_text_context {
	struct chttp_context		*context;
};

typedef void (chttp_test_cmd_f)(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd);

#define CHTTP_TEST_CMD(cmd)		chttp_test_cmd_f chttp_test_cmd_##cmd;

#endif /* CHTTP_TEST_CMD */

CHTTP_TEST_CMD(chttp_test)

#undef CHTTP_TEST_CMD