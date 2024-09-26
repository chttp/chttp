/*
 * Copyright (c) 2024 chttp
 *
 */

#include "chttp.h"
#include "chttp_zlib.h"

#include <stdlib.h>

#ifdef CHTTP_ZLIB

#define ZLIB_CONST

#include <zlib.h>

struct chttp_zlib *
chttp_zlib_inflate_alloc(void)
{
	struct chttp_zlib *zlib;
	int ret;

	zlib = malloc(sizeof(*zlib));
	assert(zlib);

	chttp_ZERO(zlib);

	zlib->magic = CHTTP_ZLIB_MAGIC;
	zlib->type = CHTTP_ZLIB_INFLATE;
	zlib->do_free = 1;

	zlib->zs.zalloc = Z_NULL;
	zlib->zs.zfree = Z_NULL;
	zlib->zs.next_in = Z_NULL;
	zlib->zs.avail_in = 0;
	zlib->zs.opaque = Z_NULL;

	ret = inflateInit2(&zlib->zs, 15 + 16);
	assert(ret == Z_OK);

	return zlib;
}

/*
 * greater than 0, error
 * less than 0, need more output buffer
 * equal to 0, done
 */
int
chttp_zlib_inflate(struct chttp_zlib *zlib, const unsigned char *input, size_t input_len,
    unsigned char *output, size_t output_len, size_t *written)
{
	chttp_zlib_ok(zlib);
	assert(output);
	assert(output_len);
	assert(written);

	*written = 0;

	if (zlib->state == Z_STREAM_END) {
		return 0;
	} else if (zlib->state == Z_BUF_ERROR) {
		if (output_len <= zlib->zs.avail_out) {
			return 1;
		}
	} else if (zlib->state != Z_OK) {
		return 1;
	}

	if (input) {
		assert(input_len);
		assert_zero(zlib->zs.avail_in);
		zlib->zs.next_in = input;
		zlib->zs.avail_in = input_len;
	} else {
		assert(zlib->zs.next_in);
	}

	zlib->zs.next_out = output;
	zlib->zs.avail_out = output_len;

	zlib->state = inflate(&zlib->zs, Z_NO_FLUSH);

	assert(zlib->zs.avail_out <= output_len);
	*written = output_len - zlib->zs.avail_out;

	if (*written < output_len) {
		assert(zlib->zs.avail_out);

		if (zlib->state == Z_BUF_ERROR) {
			return -1;
		}

		assert_zero(zlib->zs.avail_in);

		return 0;
	} else {
		assert_zero(zlib->zs.avail_out);
		return -1;
	}

	return 0;
}

void
chttp_zlib_free(struct chttp_zlib *zlib)
{
	int ret, do_free;

	chttp_zlib_ok(zlib);

	do_free = zlib->do_free;

	if (zlib->type == CHTTP_ZLIB_INFLATE) {
		ret = inflateEnd(&zlib->zs);
		assert(ret == Z_OK);
	} else if (zlib->type == CHTTP_ZLIB_DEFLATE) {
		ret = deflateEnd(&zlib->zs);
		assert(ret == Z_OK);
	}

	chttp_ZERO(zlib);

	if (do_free) {
		free(zlib);
	}
}

#endif /* CHTTP_ZLIB */
