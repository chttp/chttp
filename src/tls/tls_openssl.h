/*
 * Copyright (c) 2024 chttp
 *
 */

#ifndef _CHTTP_TLS_H_INCLUDED_
#define _CHTTP_TLS_H_INCLUDED_

#ifdef CHTTP_OPENSSL

#include "chttp.h"

void chttp_openssl_free(void);
void chttp_openssl_connect(struct chttp_context *ctx);
void chttp_openssl_close(struct chttp_addr *addr);
void chttp_openssl_write(struct chttp_context *ctx, void *buf, size_t buf_len);
size_t chttp_openssl_read(struct chttp_context *ctx, void *buf, size_t buf_len, int *error);

#endif /* CHTTP_OPENSSL */

#endif /* _CHTTP_TLS_H_INCLUDED_ */
