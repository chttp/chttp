/*
 * Copyright (c) 2021 chttp
 *
 */

#include "test/chttp_test.h"

#include <stdlib.h>
#include <string.h>

static void
_init_test(struct chttp_test *test)
{
	assert(test);

	memset(test, 0, sizeof(struct chttp_test));

	test->magic = CHTTP_TEST_MAGIC;
	test->verbocity = 1;
	test->line_raw_len = 1024;
	test->line_raw = malloc(test->line_raw_len);
	assert(test->line_raw);

	chttp_test_cmds_init(test);

	chttp_test_ok(test);
}

static void
_finish_test(struct chttp_test *test)
{
	chttp_test_ok(test);

	if (test->fcht) {
		fclose(test->fcht);
		test->fcht = NULL;
	}

	free(test->line_raw);
	test->line_raw = NULL;
	test->line_raw_len = 0;

	test->magic = 0;
}

static void
_usage(char *name)
{
	printf("ERROR usage: %s [-q] [-v] [-vv] CHT_FILE\n", name);
}

int
main(int argc, char **argv)
{
	struct chttp_test test;
	struct chttp_test_entry *cmd;
	int i;

	printf("chttp_test %s\n", CHTTP_VERSION);

	_init_test(&test);
	chttp_test_cmds_setup(&test);

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-q")) {
			test.verbocity = 0;
		} else if (!strcmp(argv[i], "-v")) {
			test.verbocity = 1;
		} else if (!strcmp(argv[i], "-vv")) {
			test.verbocity = 2;
		} else if (test.cht_file == NULL) {
			test.cht_file = argv[i];
		} else {
			_usage(argv[0]);
			return 1;
		}
	}

	if (!test.cht_file) {
		_usage(argv[0]);
		return 1;
	}

	test.fcht = fopen(test.cht_file, "r");

	if (!test.fcht) {
		printf("ERROR invalid file: %s\n", test.cht_file);
		return 1;
	}

	while (chttp_test_readline(&test)) {
		//printf("%zu: %s\n", test.lines, test.line_buf);
		test.cmd.name = test.line_buf;

		cmd = chttp_test_cmds_get(&test, test.cmd.name);
		assert(cmd);

		cmd->func(&test.context, &test.cmd);
	}

	chttp_test_cmds_free(&test);

	_finish_test(&test);

	return 0;
}