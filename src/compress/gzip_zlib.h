/*
 * Copyright (c) 2024 chttp
 *
 */

#ifndef _CHTTP_ZLIB_H_INCLUDED_
#define _CHTTP_ZLIB_H_INCLUDED_

#ifdef CHTTP_ZLIB

#define ZLIB_CONST

#include <stddef.h>
#include <zlib.h>

#include "chttp_gzip.h"

enum chttp_zlib_type {
	CHTTP_ZLIB_NONE = 0,
	CHTTP_ZLIB_INFLATE,
	CHTTP_ZLIB_DEFLATE
};

struct chttp_zlib {
	unsigned int			magic;
#define CHTTP_ZLIB_MAGIC		0xAE59CB8C

	enum chttp_zlib_type		type;
	int				state;

	unsigned int			do_free:1;

	z_stream			zs;
};

void chttp_zlib_inflate_init(struct chttp_zlib *zlib);
struct chttp_zlib *chttp_zlib_inflate_alloc(void);
void chttp_zlib_free(struct chttp_zlib *zlib);
enum chttp_gzip_status chttp_zlib_inflate(struct chttp_zlib *zlib,
	const unsigned char *input, size_t input_len, unsigned char *output,
	size_t output_len, size_t *written);

#endif /* CHTTP_ZLIB */

#endif /* _CHTTP_ZLIB_H_INCLUDED_ */
