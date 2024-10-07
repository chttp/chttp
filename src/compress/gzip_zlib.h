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

#define CHTTP_ZLIB_WINDOW_BITS		(15 + 16)
#define CHTTP_ZLIB_DEFLATE_LEVEL	6
#define CHTTP_ZLIB_DEFLATE_MEM		8

enum chttp_zlib_type {
	CHTTP_ZLIB_NONE = 0,
	CHTTP_ZLIB_INFLATE,
	CHTTP_ZLIB_DEFLATE
};

enum chttp_zlib_status {
	CHTTP_ZLIB_MORE_BUFFER = -1,
	CHTTP_ZLIB_DONE = 0,
	CHTTP_ZLIB_ERROR = 1
};

struct chttp_zlib {
	unsigned int			magic;
#define CHTTP_ZLIB_MAGIC		0xAE59CB8C

	enum chttp_zlib_type		type;
	enum chttp_zlib_status		status;
	int				state;

	unsigned int			do_free:1;

	unsigned char			*buffer;
	size_t				buffer_len;

	z_stream			zs;
};

struct chttp_context;

void chttp_zlib_inflate_init(struct chttp_zlib *zlib);
void chttp_zlib_deflate_init(struct chttp_zlib *zlib);
struct chttp_zlib *chttp_zlib_alloc(enum chttp_zlib_type type);
void chttp_zlib_free(struct chttp_zlib *zlib);
size_t chttp_zlib_read_body(struct chttp_context *ctx, unsigned char *output, size_t output_len);
void chttp_zlib_register(struct chttp_zlib *zlib, unsigned char *buffer, size_t buffer_len);

#endif /* CHTTP_ZLIB */

#endif /* _CHTTP_ZLIB_H_INCLUDED_ */
