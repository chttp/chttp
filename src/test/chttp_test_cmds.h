/*
 * Copyright (c) 2021 chttp
 *
 */

#ifndef CHTTP_TEST_CMD

#ifndef _CHTTP_TEST_CMDS_H_INCLUDED_
#define _CHTTP_TEST_CMDS_H_INCLUDED_

#define CHTTP_TEST_MAX_PARAMS		16

struct chttp_test_cmd {
	const char			*name;

	size_t				param_count;
	char				*params[CHTTP_TEST_MAX_PARAMS];
};

struct chttp_test_server;

struct chttp_text_context {
	struct chttp_context		scontext;
	struct chttp_context		*context;

	struct chttp_test_server	*server;
};

typedef void (chttp_test_cmd_f)(struct chttp_text_context*, struct chttp_test_cmd*);

#define CHTTP_TEST_CMD(cmd)		chttp_test_cmd_f chttp_test_cmd_##cmd;

#endif /* _CHTTP_TEST_CMDS_H_INCLUDED_ */

#endif /* CHTTP_TEST_CMD */

#ifndef CHTTP_TEST_CMD
#error "CHTTP_TEST_CMD missing"
#endif

CHTTP_TEST_CMD(chttp_test)
CHTTP_TEST_CMD(connect_or_skip)

CHTTP_TEST_CMD(chttp_init)
CHTTP_TEST_CMD(chttp_url)
CHTTP_TEST_CMD(chttp_send)
CHTTP_TEST_CMD(chttp_status)

CHTTP_TEST_CMD(server_init)

#undef CHTTP_TEST_CMD