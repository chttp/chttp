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

void
chttp_gzip_deflate_init(struct chttp_gzip *gzip)
{
#ifdef CHTTP_ZLIB
	chttp_zlib_deflate_init(gzip);
#else
	(void)gzip;
	chttp_ABORT("gzip not configured")
#endif
}

struct chttp_gzip *
chttp_gzip_inflate_alloc(void)
{
#ifdef CHTTP_ZLIB
	return chttp_zlib_alloc(CHTTP_ZLIB_INFLATE);
#else
	chttp_ABORT("gzip not configured")
	return NULL;
#endif
}

struct chttp_gzip *
chttp_gzip_deflate_alloc(void)
{
#ifdef CHTTP_ZLIB
	return chttp_zlib_alloc(CHTTP_ZLIB_DEFLATE);
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
chttp_gzip_register(struct chttp_context *ctx, struct chttp_gzip *gzip, void *buffer,
    size_t buffer_len)
{
	chttp_context_ok(ctx);
	assert(gzip);
	assert(buffer);
	assert(buffer_len);

	chttp_ASSERT(chttp_gzip_enabled(), "gzip not configured");

#ifdef CHTTP_ZLIB
	chttp_ASSERT(!ctx->gzip_priv, "gzip already registered");

	if (gzip->type == CHTTP_ZLIB_INFLATE) {
		chttp_ASSERT(ctx->gzip, "gzip not detected");
		chttp_ASSERT(ctx->state >= CHTTP_STATE_RESP_BODY, "bad chttp state");
		chttp_ASSERT(ctx->state < CHTTP_STATE_CLOSED, "bad chttp state");

		if (ctx->state > CHTTP_STATE_RESP_BODY) {
			chttp_gzip_free(gzip);
			return;
		}
	} else {
		assert(gzip->type == CHTTP_ZLIB_DEFLATE);
		chttp_ABORT("TODO");
	}

	chttp_zlib_register(gzip, buffer, buffer_len);

	ctx->gzip_priv = gzip;
#endif
}

size_t
chttp_gzip_read_body(struct chttp_context *ctx, void *output, size_t output_len)
{
#ifdef CHTTP_ZLIB
	return chttp_zlib_read_body(ctx, output, output_len);
#else
	(void)ctx;
	(void)output;
	(void)output_len;
	chttp_ABORT("gzip not configured")
	return 0;
#endif
}

size_t
chttp_gzip_compress_buffer(struct chttp_gzip *gzip, void *input, size_t input_len,
    void *output, size_t output_len, int finish)
{
#ifdef CHTTP_ZLIB
	size_t written;
	enum chttp_zlib_status status;

	assert(gzip->type == CHTTP_ZLIB_DEFLATE);

	status = chttp_zlib_flate(gzip, input, input_len, output, output_len, &written, finish);
	chttp_ASSERT(status == CHTTP_ZLIB_DONE, "bad gzip compress status %d", status);

	return written;
#else
	(void)gzip;
	(void)input;
	(void)input_len;
	(void)output;
	(void)output_len;
	chttp_ABORT("gzip not configured")
	return 0;
#endif
}
