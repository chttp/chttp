/*
 * Copyright (c) 2024 chttp
 *
 */

#include "chttp.h"
#include "tls_openssl.h"

void
chttp_tls_free(void)
{
#ifdef CHTTP_OPENSSL
	chttp_openssl_free();
#else
	chttp_ABORT("TLS not configured");
#endif
}

void
chttp_tls_connect(struct chttp_context *ctx)
{
#ifdef CHTTP_OPENSSL
	chttp_openssl_connect(ctx);
#else
	(void)ctx;
	chttp_ABORT("TLS not configured");
#endif
}

void
chttp_tls_close(struct chttp_addr *addr)
{
#ifdef CHTTP_OPENSSL
	chttp_openssl_close(addr);
#else
	(void)addr;
	chttp_ABORT("TLS not configured");
#endif
}

void
chttp_tls_write(struct chttp_context *ctx, void *buf, size_t buf_len)
{
#ifdef CHTTP_OPENSSL
	chttp_openssl_write(ctx, buf, buf_len);
#else
	(void)ctx;
	(void)buf;
	(void)buf_len;
	chttp_ABORT("TLS not configured");
#endif
}

size_t
chttp_tls_read(struct chttp_context *ctx, void *buf, size_t buf_len, int *error)
{
#ifdef CHTTP_OPENSSL
	return chttp_openssl_read(ctx, buf, buf_len, error);
#else
	(void)ctx;
	(void)buf;
	(void)buf_len;
	(void)error;
	chttp_ABORT("TLS not configured");
	return 0;
#endif
}