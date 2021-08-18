/*
 * Copyright (c) 2021 chttp
 *
 */

#include "test/chttp_test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int chttp_test_entry_cmp(const struct chttp_test_entry *k1,
    const struct chttp_test_entry *k2);

RB_GENERATE_STATIC(chttp_test_tree, chttp_test_entry, entry, chttp_test_entry_cmp);

static int chttp_test_entry_cmp(const struct chttp_test_entry *k1,
    const struct chttp_test_entry *k2)
{
	return strcmp(k1->name, k2->name);
}

void
_test_cmd_register(struct chttp_test *test, const char *name, chttp_test_cmd_f *func)
{
	struct chttp_test_entry *entry, *ret;

	chttp_test_ok(test);

	entry = malloc(sizeof(struct chttp_test_entry));
	assert(entry);

	entry->magic = CHTTP_TEST_ENTRY;
	entry->name = name;
	entry->func = func;

	ret = RB_INSERT(chttp_test_tree, &test->cmd_tree, entry);
	assert_zero(ret);
}

void
chttp_test_cmds_init(struct chttp_test *test)
{
	chttp_test_ok(test);
	assert(RB_EMPTY(&test->cmd_tree));

#define CHTTP_TEST_CMD(cmd)					\
	_test_cmd_register(test, #cmd, &chttp_test_cmd_##cmd);
#include "test/chttp_test_cmds.h"
}

struct chttp_test_entry *
chttp_test_cmds_get(struct chttp_test *test, const char *name)
{
        struct chttp_test_entry *result, find;

	chttp_test_ok(test);
	assert(name);

        find.name = name;

        result = RB_FIND(chttp_test_tree, &test->cmd_tree, &find);

	if (!result) {
		return NULL;
	}

        assert(result->magic == CHTTP_TEST_ENTRY);

        return result;
}

void
chttp_test_cmds_free(struct chttp_test *test)
{
	struct chttp_test_entry *entry, *next;

	chttp_test_ok(test);

	RB_FOREACH_SAFE(entry, chttp_test_tree, &test->cmd_tree, next) {
		assert(entry->magic == CHTTP_TEST_ENTRY);

		RB_REMOVE(chttp_test_tree, &test->cmd_tree, entry);

		entry->magic = 0;
		free(entry);
	}
}