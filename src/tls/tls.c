/*
 * Copyright (c) 2024 chttp
 *
 */

#include "chttp.h"
#include "tls_openssl.h"

void
chttp_tls_init(void)
{
	chttp_openssl_init();
}

void
chttp_tls_free(void)
{
	chttp_openssl_free();
}

void
chttp_tls_connect(struct chttp_context *ctx)
{
	chttp_openssl_connect(ctx);
}

void
chttp_tls_close(struct chttp_context *ctx)
{
	chttp_openssl_close(ctx);
}

void
chttp_tls_write(struct chttp_context *ctx, void *buf, size_t buf_len)
{
	chttp_openssl_write(ctx, buf, buf_len);
}

size_t
chttp_tls_read(struct chttp_context *ctx, void *buf, size_t buf_len, int *error)
{
	return chttp_openssl_read(ctx, buf, buf_len, error);
}