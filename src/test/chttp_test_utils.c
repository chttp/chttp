/*
 * Copyright (c) 2021 chttp
 *
 */

#include "test/chttp_test.h"

#include <stdlib.h>
#include <string.h>

#define _TRIM_STR_LEFT(s, len)				\
	while ((len) > 0 && (s)[0] <= ' ') {		\
		(s)++;					\
		(len)--;				\
	}

#define _TRIM_STR_RIGHT(s, len)				\
	while ((len) > 0 && (s)[(len) - 1] <= ' ') {	\
		(len)--;				\
		(s)[(len)] = '\0';			\
	}

#define	_TRIM_STR(s, len)				\
	do {						\
		_TRIM_STR_LEFT(s, len);			\
		_TRIM_STR_RIGHT(s, len);		\
	} while (0)

int
chttp_test_readline(struct chttp_test *test)
{
	char *ret;
	size_t oldlen;

	chttp_test_ok(test);
	assert(test->line_raw);
	assert(test->line_raw_len > 1);
	assert(test->fcht);

	test->line_buf_len = 0;
	test->line_raw[test->line_raw_len - 2] = '\n';

	ret = fgets(test->line_raw, test->line_raw_len, test->fcht);

	if (!ret) {
		return 0;
	}

	// Didn't reach end of line, expand and read more
	while (test->line_raw[test->line_raw_len - 2] &&
	    test->line_raw[test->line_raw_len - 2] != '\n') {
		oldlen = test->line_raw_len;
		test->line_raw_len *= 2;
		assert(test->line_raw_len / 2 == oldlen);

		test->line_raw = realloc(test->line_raw, test->line_raw_len);
		assert(test->line_raw);

		test->line_raw[test->line_raw_len - 2] = '\n';

		if (!fgets(test->line_raw + oldlen - 1, (test->line_raw_len - oldlen) + 1,
		    test->fcht)) {
			break;
		}
	}

	test->lines++;
	test->line_buf = test->line_raw;
	test->line_buf_len = strlen(test->line_buf);

	_TRIM_STR(test->line_buf, test->line_buf_len);

	if (test->line_buf_len == 0 || *test->line_buf == '#') {
		return chttp_test_readline(test);
	}

	return 1;
}