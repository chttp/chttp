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
	struct chttp_test_entry *cmd_entry;
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

	while (chttp_test_readline(&test, 0)) {
		chttp_test_parse_cmd(&test);

		printf("%zu: %s\n", test.lines - test.lines_multi, test.cmd.name);

		/*
		for (i = 0; i < test.cmd.param_count; i++) {
			printf("  %d: %s\n", i + 1, test.cmd.params[i]);
		}
		*/

		cmd_entry = chttp_test_cmds_get(&test, test.cmd.name);

		if (!cmd_entry) {
			printf("ERROR: %s not found\n", test.cmd.name);
			return 1;
		}

		cmd_entry->func(&test.context, &test.cmd);
	}

	chttp_test_cmds_free(&test);

	_finish_test(&test);

	return 0;
}