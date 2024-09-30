/*
 * Copyright (c) 2024 chttp
 *
 */

#ifndef _CHTTP_GZIP_H_INCLUDED_
#define _CHTTP_GZIP_H_INCLUDED_

#ifdef CHTTP_ZLIB
#include "gzip_zlib.h"
#define chttp_gzip chttp_zlib
#else
struct chttp_gzip {
	int error;
};
#endif

int chttp_gzip_enabled(void);
struct chttp_gzip *chttp_gzip_inflate_alloc(void);
void chttp_gzip_inflate_init(struct chttp_gzip *gzip);
void chttp_gzip_free(void *gzip_priv);
size_t chttp_gzip_read(struct chttp_context *ctx, void *output, size_t output_len);
void chttp_gzip_register(struct chttp_context *ctx, struct chttp_gzip *gzip,
	char *buffer, size_t buffer_len);

#endif /* _CHTTP_GZIP_H_INCLUDED_ */
