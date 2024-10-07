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
