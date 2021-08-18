/*
 * Copyright (c) 2021 chttp
 *
 */

#include "test/chttp_test.h"

#include <stdarg.h>
#include <stdlib.h>

struct chttp_test *
chttp_test_convert(struct chttp_text_context *ctx)
{
	struct chttp_test *test;

	assert(ctx);

	test = (struct chttp_test*)((void*)ctx - offsetof(struct chttp_test, context));
	chttp_test_ok(test);
	assert(test == TEST);

	return test;
}

void
chttp_test_log(enum chttp_test_verbocity level, const char *fmt, ...)
{
	va_list ap;

	if (TEST) {
		chttp_test_ok(TEST);

		if (level != CHTTP_LOG_FORCE && (TEST->verbocity == CHTTP_LOG_NONE ||
		    TEST->verbocity < level)) {
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

	chttp_test_ok(TEST);

	if (!condition) {
		return;
	}

	printf("ERROR: ");

	va_start(ap, fmt);

	vprintf(fmt, ap);

	va_end(ap);

	if (TEST->cht_file) {
		printf("\nFAILED (%s)\n", TEST->cht_file);
	} else {
		printf("\nFAILED\n");
	}

	exit(1);
}