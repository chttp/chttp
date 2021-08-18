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
	test->verbocity = CHTTP_LOG_VERBOSE;
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
	struct chttp_test_entry *cmd_entry;
	int i, error;

	_init_test(&test);
	chttp_test_cmds_setup(&test);

	chttp_test_log(&test.context, -1, "chttp_test %s\n", CHTTP_VERSION);

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-q")) {
			test.verbocity = CHTTP_LOG_NONE;
		} else if (!strcmp(argv[i], "-v")) {
			test.verbocity = CHTTP_LOG_VERBOSE;
		} else if (!strcmp(argv[i], "-vv")) {
			test.verbocity = CHTTP_LOG_VERY_VERBOSE;
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
		chttp_test_ERROR(1, "invalid file %s", test.cht_file);
	}

	while (chttp_test_readline(&test, 0)) {
		chttp_test_parse_cmd(&test);

		if (test.verbocity == CHTTP_LOG_VERY_VERBOSE) {
			chttp_test_log(&test.context, 0,
			    "%s (line %zu)", test.cmd.name, test.lines - test.lines_multi);
		} else {
			chttp_test_log(&test.context, 0, "%s", test.cmd.name);
		}

		for (i = 0; i < test.cmd.param_count; i++) {
			chttp_test_log(&test.context, CHTTP_LOG_VERY_VERBOSE, "Arg: %s",
				test.cmd.params[i]);
		}

		cmd_entry = chttp_test_cmds_get(&test, test.cmd.name);

		if (!cmd_entry) {
			chttp_test_ERROR(1, "%s not found", test.cmd.name);
			return 1;
		}

		cmd_entry->func(&test.context, &test.cmd);
	}

	chttp_test_cmds_free(&test);

	error = test.error;

	if (error) {
		printf("FAILED (%s)\n", test.cht_file);
	} else {
		printf("PASSED (%s)\n", test.cht_file);
	}

	_finish_test(&test);

	return error;
}