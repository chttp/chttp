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
	chttp_test_ERROR_string(cmd->name);
	chttp_test_ERROR(cmd->param_count != count,
		"invalid parameter count, found %zu, expected %zu", cmd->param_count, count);
}

void
chttp_test_ERROR_string(const char *str)
{
	chttp_test_ERROR(!str || !*str, "invalid string");
}

void
chttp_test_sleep_ms(long ms)
{
	struct timespec tspec, rem;

	assert(ms >= 0);

	tspec.tv_sec = ms / 1000;
	tspec.tv_nsec = (ms % 1000) * 1000 * 1000;

	errno = 0;
	while (nanosleep(&tspec, &rem) && errno == EINTR) {
		tspec.tv_sec = rem.tv_sec;
		tspec.tv_nsec = rem.tv_nsec;
		errno = 0;
	}
}

int
chttp_test_join_thread(pthread_t thread, volatile int *stopped, unsigned long timeout_ms)
{
	unsigned long time;

	assert(stopped);
	assert(timeout_ms + CHTTP_TEST_JOIN_INTERVAL_MS > timeout_ms);

	time = 0;

	while (!*stopped) {
		chttp_test_sleep_ms(CHTTP_TEST_JOIN_INTERVAL_MS);

		time += CHTTP_TEST_JOIN_INTERVAL_MS;

		if (time > timeout_ms) {
			return 1;
		}
	}

	assert_zero(pthread_join(thread, NULL));

	return 0;
}

size_t
chttp_test_line_pos(struct chttp_test *test)
{
	chttp_test_ok(test);

	return (test->lines - test->lines_multi);
}