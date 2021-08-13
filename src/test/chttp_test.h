/*
 * Copyright (c) 2021 chttp
 *
 */

#ifndef _CHTTP_TEST_H_INCLUDED_
#define _CHTTP_TEST_H_INCLUDED_

#include "chttp.h"
#include "test/chttp_test_cmds.h"
#include "data/tree.h"

#include <stdio.h>

struct chttp_test_entry {
	unsigned			magic;
#define CHTTP_TEST_ENTRY		0x52C66713

        RB_ENTRY(chttp_test_entry)	entry;

	const char			*name;
	chttp_test_cmd_f		*func;
};

RB_HEAD(chttp_test_tree, chttp_test_entry);

struct chttp_test {
	unsigned int			magic;
#define CHTTP_TEST_MAGIC		0xD1C4671E

	struct chttp_text_context	context;

	int				argc;
	char				**argv;

	int				verbocity;

	struct chttp_test_tree		cmd_tree;

	char				*cht_file;
	FILE				*fcht;

	char				*line_raw;
	char				*line_buf;
	size_t				line_raw_len;
	size_t				line_buf_len;
	size_t				lines;

	struct chttp_test_cmd		cmd;
};

void chttp_test_cmds_init(struct chttp_test *test);
void chttp_test_cmds_setup(struct chttp_test *test);
struct chttp_test_entry *chttp_test_cmds_get(struct chttp_test *test, const char *name);
void chttp_test_cmds_free(struct chttp_test *test);

int chttp_test_readline(struct chttp_test *test);

#define chttp_test_ok(test)						\
	do {								\
		assert(test);						\
		assert((test)->magic == CHTTP_TEST_MAGIC);		\
	} while (0)

#endif  /* _CHTTP_TEST_H_INCLUDED_ */
