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

enum chttp_gzip_status
chttp_gzip_inflate(struct chttp_gzip *gzip, const char *input, size_t input_len,
    char *output, size_t output_len, size_t *written)
{
#ifdef CHTTP_ZLIB
	return chttp_zlib_inflate(gzip, (const unsigned char*)input, input_len,
		(unsigned char*)output, output_len, written);
#else
	(void)gzip;
	(void)input;
	(void)input_len;
	(void)output;
	(void)output_len;
	(void)written;
	chttp_ABORT("gzip not configured")
	return CHTTP_GZIP_ERROR;
#endif
}

void
chttp_gzip_free(struct chttp_gzip *gzip)
{
#ifdef CHTTP_ZLIB
	chttp_zlib_free(gzip);
#else
	(void)gzip;
	chttp_ABORT("gzip not configured")
#endif
}
