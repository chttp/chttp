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

static void
_test_unescape(char *buf)
{
	size_t len, offset, i;

	assert(buf);

	len = strlen(buf);

	for (i = 0, offset = 0; i < len; i++) {
		if (buf[i] != '\\') {
			if (offset) {
				buf[i - offset] = buf[i];
			}

			continue;
		}

		assert(i < len - 1);

		switch (buf[i + 1]) {
			case '\\':
				buf[i - offset] = '\\';
				offset++;
				i++;
				continue;
			case '\"':
				buf[i - offset] = '\"';
				offset++;
				i++;
				continue;
			case 'n':
				buf[i - offset] = '\n';
				offset++;
				i++;
				continue;
			case 'r':
				buf[i - offset] = '\r';
				offset++;
				i++;
				continue;
			case 't':
				buf[i - offset] = '\t';
				offset++;
				i++;
				continue;
			default:
				i++;
				continue;
		}
	}

	if (offset) {
		assert(offset < len);
		buf[len - offset] = '\0';
	}
}

int
chttp_test_readline(struct chttp_test *test, size_t append_len)
{
	char *ret;
	size_t oldlen, i;

	chttp_test_ok(test);
	assert(test->line_raw);
	assert(test->line_raw_len > 1);
	assert(append_len < test->line_raw_len);
	assert(test->fcht);

	test->line_buf_len = 0;
	test->line_buf = NULL;

	if (append_len) {
		test->lines_multi++;
	} else {
		test->lines_multi = 0;
	}

	if (test->line_raw_len > append_len + 1) {
		test->line_raw[test->line_raw_len - 2] = '\n';

		ret = fgets(test->line_raw + append_len, test->line_raw_len - append_len,
			test->fcht);

		if (!ret && !append_len) {
			return 0;
		}
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
		return chttp_test_readline(test, 0);
	}

	if (test->line_buf[test->line_buf_len - 1] == '\\') {
		i = 1;
		while (i < test->line_buf_len &&
		    test->line_buf[test->line_buf_len - i - 1] == '\\') {
			i++;
		}

		if (i % 2 == 1) {
			// Read the next line
			test->line_buf[test->line_buf_len - 1] = '\0';
			test->line_buf_len--;

			_TRIM_STR_RIGHT(test->line_buf, test->line_buf_len);

			if (test->line_buf_len) {
				i = test->line_buf - test->line_raw + test->line_buf_len;
				assert(i < test->line_raw_len);

				return chttp_test_readline(test, i);
			} else {
				return chttp_test_readline(test, 0);
			}
		}
	}

	//_test_unescape(test);

	return 1;
}

void
chttp_test_parse_cmd(struct chttp_test *test)
{
	char *buf;
	size_t i, len, count;
	int quote;

	chttp_test_ok(test);
	assert(test->line_buf);
	assert(test->line_buf_len);

	test->cmd.name = test->line_buf;
	test->cmd.param_count = 0;
	memset(test->cmd.params, 0, sizeof(char*) * CHTTP_TEST_MAX_PARAMS);

	buf = test->line_buf;
	len = test->line_buf_len;
	quote = 0;

	for (i = 0; i < len; i++) {
		if (quote && buf[i] == '\"') {
			count = 1;
			while (buf[i - count] == '\\') {
				count++;
			}

			if (count % 2 != 1) {
				continue;
			} else {
				assert(test->cmd.param_count);
				assert(test->cmd.params[test->cmd.param_count - 1][0] ==
					'\"');

				quote = 0;
				buf[i] = ' ';
				test->cmd.params[test->cmd.param_count - 1] += 1;
			}
		}
		if (!quote && buf[i] <= ' ' ) {
			buf[i] = '\0';

			i++;

			while (i < len && buf[i] <= ' ') {
				i++;
			}

			if (i == len) {
				break;
			}

			test->cmd.params[test->cmd.param_count] = &buf[i];
			test->cmd.param_count++;

			if (buf[i] == '\"') {
				quote = 1;
			}
		}
	}

	for (i = 0; i < test->cmd.param_count; i++) {
		_test_unescape(test->cmd.params[i]);
	}
}