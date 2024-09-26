/*
 * Copyright (c) 2024 chttp
 *
 */

#include "chttp.h"
#include "chttp_gzip.h"
#include "gzip_zlib.h"

#ifdef CHTTP_ZLIB

#include <stdlib.h>

#define chttp_zlib_ok(zlib)						\
	do {								\
		assert(zlib);						\
		assert((zlib)->magic == CHTTP_ZLIB_MAGIC);		\
	} while (0)

void
chttp_zlib_inflate_init(struct chttp_zlib *zlib)
{
	int ret;

	assert(zlib);

	chttp_ZERO(zlib);

	zlib->magic = CHTTP_ZLIB_MAGIC;
	zlib->type = CHTTP_ZLIB_INFLATE;

	zlib->zs.zalloc = Z_NULL;
	zlib->zs.zfree = Z_NULL;
	zlib->zs.next_in = Z_NULL;
	zlib->zs.avail_in = 0;
	zlib->zs.opaque = Z_NULL;

	ret = inflateInit2(&zlib->zs, 15 + 16);
	assert(ret == Z_OK);

	chttp_zlib_ok(zlib);
}

struct chttp_zlib *
chttp_zlib_inflate_alloc(void)
{
	struct chttp_zlib *zlib;

	zlib = malloc(sizeof(*zlib));
	assert(zlib);

	chttp_zlib_inflate_init(zlib);

	chttp_zlib_ok(zlib);

	zlib->do_free = 1;

	return zlib;
}

enum chttp_gzip_status
chttp_zlib_inflate(struct chttp_zlib *zlib, const unsigned char *input,
    size_t input_len, unsigned char *output, size_t output_len, size_t *written)
{
	chttp_zlib_ok(zlib);
	assert(output);
	assert(output_len);
	assert(written);

	*written = 0;

	if (zlib->state == Z_STREAM_END) {
		return CHTTP_GZIP_DONE;
	} else if (zlib->state == Z_BUF_ERROR) {
		if (output_len <= zlib->zs.avail_out) {
			return CHTTP_GZIP_ERROR;
		}
	} else if (zlib->state != Z_OK) {
		return CHTTP_GZIP_ERROR;
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

	if (*written == output_len) {
		assert_zero(zlib->zs.avail_out);

		return CHTTP_GZIP_MORE_BUFFER;
	}

	assert(*written < output_len);
	assert(zlib->zs.avail_out);

	if (zlib->state == Z_BUF_ERROR) {
		return CHTTP_GZIP_MORE_BUFFER;
	}

	assert_zero(zlib->zs.avail_in);

	return CHTTP_GZIP_DONE;
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
