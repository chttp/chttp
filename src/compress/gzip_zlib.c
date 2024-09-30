/*
 * Copyright (c) 2024 chttp
 *
 */

#include "chttp.h"
#include "chttp_gzip.h"
#include "gzip_zlib.h"

#ifdef CHTTP_ZLIB

#include <stdlib.h>

enum chttp_gzip_status {
	CHTTP_GZIP_MORE_BUFFER = -1,
	CHTTP_GZIP_DONE = 0,
	CHTTP_GZIP_ERROR = 1
};

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

static enum chttp_gzip_status
_zlib_inflate(struct chttp_zlib *zlib, const unsigned char *input,
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
		if (output_len <= zlib->zs.avail_out && !input) {
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

	if (zlib->state == Z_BUF_ERROR && zlib->zs.avail_in) {
		// TODO this will assert chttp_zlib_read()
		return CHTTP_GZIP_MORE_BUFFER;
	}

	assert_zero(zlib->zs.avail_in);

	return CHTTP_GZIP_DONE;
}

size_t
chttp_zlib_read(struct chttp_context *ctx, unsigned char *output, size_t output_len)
{
	struct chttp_gzip *gzip;
	size_t read, written;

	chttp_context_ok(ctx);
	assert(ctx->gzip_priv);
	assert(output);

	if (!output_len) {
		return 0;
	}

	gzip = ctx->gzip_priv;
	assert(gzip->status <= CHTTP_GZIP_DONE);

	if (gzip->status == CHTTP_GZIP_MORE_BUFFER) {
		gzip->status = _zlib_inflate(gzip, NULL, 0, output, output_len, &written);

		if (gzip->status >= CHTTP_GZIP_ERROR) {
			chttp_error(ctx, CHTTP_ERR_GZIP);
			return 0;
		}

		if (gzip->status == CHTTP_GZIP_MORE_BUFFER) {
			assert(written == output_len);
			return written;
		}

		assert(written < output_len);

		return written + chttp_gzip_read(ctx, output + written, output_len - written);
	}

	assert(gzip->status == CHTTP_GZIP_DONE);

	read = chttp_read_body_raw(ctx, gzip->buffer, gzip->buffer_len);

	if (!read) {
		return 0;
	}

	gzip->status = _zlib_inflate(gzip, gzip->buffer, read, output, output_len, &written);

	if (gzip->status >= CHTTP_GZIP_ERROR) {
		chttp_error(ctx, CHTTP_ERR_GZIP);
		return 0;
	}

	if (gzip->status == CHTTP_GZIP_MORE_BUFFER) {
		assert(written == output_len);
		return written;
	}

	assert(written < output_len);

	return written + chttp_gzip_read(ctx, output + written, output_len - written);
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

void
chttp_zlib_register(struct chttp_zlib *zlib, unsigned char *buffer, size_t buffer_len)
{
	chttp_zlib_ok(zlib);
	assert(buffer);
	assert(buffer_len > 0);

	zlib->buffer = buffer;
	zlib->buffer_len = buffer_len;
}

#endif /* CHTTP_ZLIB */
