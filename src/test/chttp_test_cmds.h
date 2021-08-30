/*
 * Copyright (c) 2021 chttp
 *
 */

#ifndef CHTTP_TEST_CMD

#ifndef _CHTTP_TEST_CMDS_H_INCLUDED_
#define _CHTTP_TEST_CMDS_H_INCLUDED_

#define CHTTP_TEST_MAX_PARAMS		16

struct chttp_test_server;
struct chttp_test_random;

struct chttp_text_context {
	struct chttp_context		scontext;
	struct chttp_context		*context;

	struct chttp_test_server	*server;

	struct chttp_test_random	*random;
};

struct chttp_test_cmd;
typedef void (chttp_test_cmd_f)(struct chttp_text_context *, struct chttp_test_cmd *);
typedef char *(chttp_test_var_f)(struct chttp_text_context *);

struct chttp_test_param {
	char				*value;
	size_t				len;

	unsigned int			v_const:1;
};

struct chttp_test_cmd {
	const char			*name;

	size_t				param_count;
	struct chttp_test_param		params[CHTTP_TEST_MAX_PARAMS];

	chttp_test_cmd_f		*func;

	unsigned int			async:1;
};

#define CHTTP_TEST_CMD(cmd)		chttp_test_cmd_f chttp_test_cmd_##cmd;
#define CHTTP_TEST_VAR(var)		chttp_test_var_f chttp_test_var_##var;

#endif /* _CHTTP_TEST_CMDS_H_INCLUDED_ */

#endif /* CHTTP_TEST_CMD */

#ifndef CHTTP_TEST_CMD
#error "CHTTP_TEST_CMD missing"
#endif
#ifndef CHTTP_TEST_VAR
#error "CHTTP_TEST_VAR missing"
#endif

CHTTP_TEST_CMD(chttp_test)
CHTTP_TEST_CMD(sleep_ms)
CHTTP_TEST_CMD(connect_or_skip)

CHTTP_TEST_CMD(chttp_init)
CHTTP_TEST_CMD(chttp_init_dynamic)
CHTTP_TEST_CMD(chttp_url)
CHTTP_TEST_CMD(chttp_send)
CHTTP_TEST_CMD(chttp_send_only)
CHTTP_TEST_CMD(chttp_receive)
CHTTP_TEST_CMD(chttp_status_match)
CHTTP_TEST_CMD(chttp_reason_match)
CHTTP_TEST_CMD(chttp_header_match)
CHTTP_TEST_CMD(chttp_header_submatch)
CHTTP_TEST_CMD(chttp_header_exists)
CHTTP_TEST_CMD(chttp_body_match)
CHTTP_TEST_CMD(chttp_body_submatch)

CHTTP_TEST_CMD(server_init)
CHTTP_TEST_CMD(server_accept)
CHTTP_TEST_CMD(server_read_request)
CHTTP_TEST_CMD(server_method_match)
CHTTP_TEST_CMD(server_url_match)
CHTTP_TEST_CMD(server_header_match)
CHTTP_TEST_CMD(server_header_submatch)
CHTTP_TEST_CMD(server_header_exists)
CHTTP_TEST_CMD(server_send_response)
CHTTP_TEST_CMD(server_send_response_H1_0)
CHTTP_TEST_CMD(server_send_response_partial)
CHTTP_TEST_CMD(server_start_chunked)
CHTTP_TEST_CMD(server_send_chunked)
CHTTP_TEST_CMD(server_end_chunked)
CHTTP_TEST_CMD(server_send_raw)
CHTTP_TEST_VAR(server_host)
CHTTP_TEST_VAR(server_port)

CHTTP_TEST_CMD(random_range)
CHTTP_TEST_VAR(random)

#undef CHTTP_TEST_CMD
#undef CHTTP_TEST_VAR