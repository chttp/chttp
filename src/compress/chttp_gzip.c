/*
 * Copyright (c) 2024 chttp
 *
 */

#include "chttp.h"
#include "chttp_gzip.h"
#include "gzip_zlib.h"

int
chttp_gzip_enabled(void)
{
#ifdef CHTTP_ZLIB
	return 1;
#else
	return 0;
#endif
}

void
chttp_gzip_inflate_init(struct chttp_gzip *gzip)
{
#ifdef CHTTP_ZLIB
	chttp_zlib_inflate_init(gzip);
#else
	(void)gzip;
	chttp_ABORT("gzip not configured")
#endif
}

struct chttp_gzip *
chttp_gzip_inflate_alloc(void)
{
#ifdef CHTTP_ZLIB
	return chttp_zlib_inflate_alloc();
#else
	chttp_ABORT("gzip not configured")
	return NULL;
#endif
}

void
chttp_gzip_free(void *gzip_priv)
{
#ifdef CHTTP_ZLIB
	chttp_zlib_free(gzip_priv);
#else
	(void)gzip_priv;
	chttp_ABORT("gzip not configured")
#endif
}

void
chttp_gzip_register(struct chttp_context *ctx, struct chttp_gzip *gzip,
    char *buffer, size_t buffer_len)
{
	chttp_context_ok(ctx);
	assert(gzip);
	assert(buffer);
	assert(buffer_len > 0);

	chttp_ASSERT(chttp_gzip_enabled(), "gzip not configured");
	chttp_ASSERT(!ctx->gzip_priv, "gzip already registered");
	chttp_ASSERT(ctx->gzip, "gzip not detected");
	chttp_ASSERT(ctx->state >= CHTTP_STATE_RESP_BODY, "bad chttp state");
	chttp_ASSERT(ctx->state < CHTTP_STATE_CLOSED, "bad chttp state");

	if (ctx->state > CHTTP_STATE_RESP_BODY) {
		chttp_gzip_free(gzip);
		return;
	}

#ifdef CHTTP_ZLIB
	chttp_zlib_register(gzip, (unsigned char*)buffer, buffer_len);
#endif

	ctx->gzip_priv = gzip;
}

size_t
chttp_gzip_read(struct chttp_context *ctx, void *output, size_t output_len)
{
#ifdef CHTTP_ZLIB
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
		gzip->status = chttp_zlib_inflate(gzip, NULL, 0, output, output_len, &written);

		if (gzip->status >= CHTTP_GZIP_ERROR) {
			chttp_error(ctx, CHTTP_ERR_GZIP);
			return 0;
		}

		if (gzip->status == CHTTP_GZIP_MORE_BUFFER) {
			assert(written == output_len);
			return written;
		}

		assert(written < output_len);

		return written + chttp_gzip_read(ctx, (uint8_t*)output + written,
			output_len - written);
	}

	assert(gzip->status == CHTTP_GZIP_DONE);

	read = chttp_read_body_raw(ctx, gzip->buffer, gzip->buffer_len);

	if (!read) {
		return 0;
	}

	gzip->status = chttp_zlib_inflate(gzip, gzip->buffer, read, output, output_len, &written);

	if (gzip->status >= CHTTP_GZIP_ERROR) {
		chttp_error(ctx, CHTTP_ERR_GZIP);
		return 0;
	}

	if (gzip->status == CHTTP_GZIP_MORE_BUFFER) {
		assert(written == output_len);
		return written;
	}

	assert(written < output_len);

	return written + chttp_gzip_read(ctx, (uint8_t*)output + written, output_len - written);
#else
	(void)ctx;
	(void)output;
	(void)output_len;
	chttp_ABORT("gzip not configured")
	return 0;
#endif
}
