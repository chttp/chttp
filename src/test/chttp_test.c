/*
 * Copyright (c) 2021 chttp
 *
 */

#include "test/chttp_test.h"

#include <stdlib.h>
#include <string.h>

struct chttp_test *TEST;

static void
_finish_test(struct chttp_test *test)
{
	chttp_test_ok(test);
	chttp_test_ok(TEST);
	assert(test == TEST);

	if (test->fcht) {
		fclose(test->fcht);
		test->fcht = NULL;
	}

	free(test->line_raw);
	test->line_raw = NULL;
	test->line_raw_len = 0;

	test->magic = 0;

	TEST = NULL;
}

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

	RB_INIT(&test->cmd_tree);
	TAILQ_INIT(&test->finish_list);

	TEST = test;

	chttp_test_ok(test);
	chttp_test_ok(chttp_test_convert(&test->context));

	chttp_test_register_finish(test, _finish_test);
}

static void
_usage(int error)
{
	printf("%ssage: chttp_test [-q] [-v] [-vv] [-h] CHT_FILE\n",
		(error ? "ERROR u" : "U"));
}

int
main(int argc, char **argv)
{
	struct chttp_test test;
	struct chttp_test_cmdentry *cmd_entry;
	int i;

	_init_test(&test);
	chttp_test_cmds_init(&test);

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-q")) {
			test.verbocity = CHTTP_LOG_NONE;
		} else if (!strcmp(argv[i], "-v")) {
			test.verbocity = CHTTP_LOG_VERBOSE;
		} else if (!strcmp(argv[i], "-vv")) {
			test.verbocity = CHTTP_LOG_VERY_VERBOSE;
		} else if (!strcmp(argv[i], "-h")) {
			chttp_test_log(CHTTP_LOG_FORCE, "chttp_test %s", CHTTP_VERSION);
			_usage(0);
			return 0;
		} else if (test.cht_file == NULL) {
			test.cht_file = argv[i];
		} else {
			_usage(1);
			return 1;
		}
	}

	chttp_test_log(CHTTP_LOG_ROOT, "chttp_test %s", CHTTP_VERSION);

	if (!test.cht_file) {
		_usage(1);
		return 1;
	}

	test.fcht = fopen(test.cht_file, "r");

	if (!test.fcht) {
		chttp_test_ERROR(1, "invalid file %s", test.cht_file);
	}

	while (chttp_test_readline(&test, 0)) {
		chttp_test_parse_cmd(&test);

		if (test.verbocity == CHTTP_LOG_VERY_VERBOSE) {
			chttp_test_log(CHTTP_LOG_NONE,
			    "%s (line %zu)", test.cmd.name, test.lines - test.lines_multi);
		} else {
			chttp_test_log(CHTTP_LOG_NONE, "%s", test.cmd.name);
		}

		for (i = 0; i < test.cmd.param_count; i++) {
			chttp_test_log(CHTTP_LOG_VERY_VERBOSE, "Arg: %s",
				test.cmd.params[i]);
		}

		cmd_entry = chttp_test_cmds_get(&test, test.cmd.name);

		if (!cmd_entry) {
			chttp_test_ERROR(1, "%s not found", test.cmd.name);
			return 1;
		}

		cmd_entry->func(&test.context, &test.cmd);

		if (test.error) {
			chttp_test_log(CHTTP_LOG_FORCE, "FAILED (%s)", test.cht_file);
			return 1;
		} else if (test.skip) {
			chttp_test_run_finish(&test);
			chttp_test_log(CHTTP_LOG_FORCE, "SKIPPED");
			return 0;
		}

	}

	chttp_test_run_finish(&test);

	chttp_test_log(CHTTP_LOG_FORCE, "PASSED");

	return 0;
}

void
chttp_test_register_finish(struct chttp_test *test, chttp_test_finish_f *func)
{
	struct chttp_test_finish *finish;

	chttp_test_ok(test);

	TAILQ_FOREACH(finish, &test->finish_list, entry) {
		assert(finish->magic == CHTTP_TEST_FINISH);
		chttp_test_ERROR(finish->func == func,
			"Cannot register the same finish function twice");
	}

	finish = malloc(sizeof(*finish));
	assert(finish);

	finish->magic = CHTTP_TEST_FINISH;
	finish->func = func;

	TAILQ_INSERT_HEAD(&test->finish_list, finish, entry);
}

void
chttp_test_run_finish(struct chttp_test *test)
{
	struct chttp_test_finish *finish, *temp;

	chttp_test_ok(test);

	TAILQ_FOREACH_SAFE(finish, &test->finish_list, entry, temp) {
		assert(finish->magic == CHTTP_TEST_FINISH);

		TAILQ_REMOVE(&test->finish_list, finish, entry);

		finish->func(test);

		finish->magic = 0;
		free(finish);
	}

	assert(TAILQ_EMPTY(&test->finish_list));
}