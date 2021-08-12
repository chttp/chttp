/*
 * Copyright (c) 2021 chttp
 *
 */

#ifndef _CHTTP_TEST_H_INCLUDED_
#define _CHTTP_TEST_H_INCLUDED_

#include "chttp.h"
#include "test/chttp_test_cmds.h"

#include <stdio.h>

#define CHTTP_TEST_MAX_PARAMS		16

struct chttp_test_cmd {
	const char			*cmd;

	size_t				param_count;
	char				*params[CHTTP_TEST_MAX_PARAMS];
};

struct chttp_test {
	unsigned int			magic;
#define CHTTP_TEST_MAGIC		0xD1C4671E

	struct chttp_text_context	context;

	int				argc;
	char				**argv;

	char				*cht_file;
	FILE				*fcht;

	char				*line_raw;
	char				*line_buf;
	size_t				line_raw_len;
	size_t				line_buf_len;
	size_t				lines;

	int				verbocity;

	struct chttp_test_cmd		cmd;
};

int chttp_test_readline(struct chttp_test *test);

#define chttp_test_ok(test)						\
	do {								\
		assert(test);						\
		assert((test)->magic == CHTTP_TEST_MAGIC);		\
	} while (0)

#endif  /* _CHTTP_TEST_H_INCLUDED_ */
