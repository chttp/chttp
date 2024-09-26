/*
 * Copyright (c) 2024 chttp
 *
 */

#ifndef _CHTTP_GZIP_H_INCLUDED_
#define _CHTTP_GZIP_H_INCLUDED_

enum chttp_gzip_status {
	CHTTP_GZIP_MORE_BUFFER = -1,
	CHTTP_GZIP_DONE = 0,
	CHTTP_GZIP_ERROR = 1
};

#ifdef CHTTP_ZLIB
#include "gzip_zlib.h"
#define chttp_gzip chttp_zlib
#else
struct chttp_gzip {
	int error;
};
#endif

int chttp_gzip_enabled(void);
void chttp_gzip_inflate_init(struct chttp_gzip *zlib);
void chttp_gzip_free(struct chttp_gzip *zlib);
enum chttp_gzip_status chttp_gzip_inflate(struct chttp_gzip *zlib,
	const unsigned char *input, size_t input_len, unsigned char *output,
	size_t output_len, size_t *written);

#endif /* _CHTTP_GZIP_H_INCLUDED_ */
