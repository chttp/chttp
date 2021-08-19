/*
 * Copyright (c) 2021 chttp
 *
 */

#include "test/chttp_test.h"

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>

struct chttp_test *
chttp_test_convert(struct chttp_text_context *ctx)
{
	struct chttp_test *test;

	assert(ctx);

	test = (struct chttp_test*)((void*)ctx - offsetof(struct chttp_test, context));
	chttp_test_ok(test);

	return test;
}

void
chttp_test_log(struct chttp_text_context *ctx, enum chttp_test_verbocity level,
    const char *fmt, ...)
{
	struct chttp_test *test;
	va_list ap;

	if (ctx) {
		test = chttp_test_convert(ctx);

		if (level != CHTTP_LOG_FORCE && (test->verbocity == CHTTP_LOG_NONE ||
		    test->verbocity < level)) {
			return;
		}
	} else {
		assert(level == CHTTP_LOG_FORCE);
	}

	if (level == CHTTP_LOG_NONE) {
		printf("- ");
	} else if (level == CHTTP_LOG_VERBOSE) {
		printf("-- ");
	} else if (level == CHTTP_LOG_VERY_VERBOSE) {
		printf("--- ");
	}

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);

	printf("\n");
}

void
chttp_test_skip(struct chttp_text_context *ctx)
{
	struct chttp_test *test;

	test = chttp_test_convert(ctx);

	test->skip = 1;
}

void
chttp_test_warn(int condition, const char *fmt, ...)
{
	va_list ap;

	if (!condition) {
		return;
	}

	printf("WARNING: ");

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);

	printf("\n");
}

void
chttp_test_ERROR(int condition, const char *fmt, ...)
{
	va_list ap;

	if (!condition) {
		return;
	}

	printf("ERROR: ");

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);

	printf("\nFAILED\n");

	exit(1);
}

long
chttp_test_parse_long(const char *str)
{
	long ret;
	char *end;

	assert(str);

	errno = 0;

	ret = strtol(str, &end, 10);

	if (ret == LONG_MAX || ret == LONG_MIN || errno || end == str || *end != '\0') {
		chttp_test_ERROR(1, "invalid number '%s'", str);
	}

	return ret;
}

void
chttp_test_ERROR_param_count(struct chttp_test_cmd *cmd, size_t count)
{
	assert(cmd);
	chttp_test_ERROR(cmd->param_count != count,
		"invalid parameter count, found %zu, expected %zu", cmd->param_count, count);
}

void
chttp_test_ERROR_string(const char *str)
{
	chttp_test_ERROR(!str || !*str, "invalid string");
}