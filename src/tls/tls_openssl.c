/*
 * Copyright (c) 2024 chttp
 *
 */

#include "chttp.h"
#include "tls_openssl.h"

#include <openssl/ssl.h>
#include <pthread.h>

struct chttp_openssl_ctx {
	unsigned int					magic;
#define CHTTP_OPENSSL_CTX_MAGIC				0x74FF28FB

	pthread_mutex_t					lock;

	int						initialized;
	int						failed;

	SSL_CTX						*ctx;

};

struct chttp_openssl_ctx _OPENSSL_CTX = {
	CHTTP_OPENSSL_CTX_MAGIC,
	PTHREAD_MUTEX_INITIALIZER,
	0,
	0,
	NULL
};

#define chttp_openssl_ctx_ok()							\
	do {									\
		assert(_OPENSSL_CTX.magic == CHTTP_OPENSSL_CTX_MAGIC);		\
	} while (0)
#define chttp_openssl_connected(ctx, ssl_ctx)					\
	do {									\
		assert((ctx)->tls_priv);					\
		ssl_ctx = (SSL*)((ctx)->tls_priv);				\
	} while (0)

static void
_openssl_init(void)
{
	chttp_openssl_ctx_ok();
	assert_zero(_OPENSSL_CTX.ctx);
	assert_zero(_OPENSSL_CTX.initialized);
	assert_zero(_OPENSSL_CTX.failed);

	_OPENSSL_CTX.initialized = 1;

	_OPENSSL_CTX.ctx = SSL_CTX_new(TLS_client_method());
	if (!_OPENSSL_CTX.ctx) {
		_OPENSSL_CTX.failed = 1;
		return;
	}

	// TODO set various TLS settings
}

static void
_openssl_init_lock(void)
{
	chttp_openssl_ctx_ok();

	if (!_OPENSSL_CTX.initialized) {
		assert_zero(pthread_mutex_lock(&_OPENSSL_CTX.lock));
		if (!_OPENSSL_CTX.initialized) {
			_openssl_init();
		}
		assert_zero(pthread_mutex_unlock(&_OPENSSL_CTX.lock));
	}
	assert(_OPENSSL_CTX.initialized);
}

void
chttp_openssl_free(void)
{
	chttp_openssl_ctx_ok();

	if (_OPENSSL_CTX.initialized && !_OPENSSL_CTX.failed) {
		assert(_OPENSSL_CTX.ctx);
		SSL_CTX_free(_OPENSSL_CTX.ctx);

		_OPENSSL_CTX.ctx = NULL;
		_OPENSSL_CTX.failed = 1;
	}
}

void
chttp_openssl_connect(struct chttp_context *ctx)
{
	SSL *ssl;
	int ret;

	chttp_openssl_ctx_ok();
	chttp_context_ok(ctx);
	chttp_caddr_connected(ctx);
	assert(ctx->tls);
	assert_zero(ctx->tls_priv);

	_openssl_init_lock();

	if (_OPENSSL_CTX.failed) {
		ctx->error = CHTTP_ERR_TLS_INIT;
		return;
	}
	assert(_OPENSSL_CTX.ctx);

	ctx->tls_priv = SSL_new(_OPENSSL_CTX.ctx);

	if (!ctx->tls_priv) {
		ctx->error = CHTTP_ERR_TLS_INIT;
		return;
	}

	chttp_openssl_connected(ctx, ssl);

	SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL); // TODO

	ret = SSL_set_fd(ssl, ctx->addr.sock);

	if (ret != 1) {
		ctx->error = CHTTP_ERR_TLS_INIT;
		return;
	}

	SSL_set_connect_state(ssl);

	ret = SSL_do_handshake(ssl);

	if (ret != 1) {
		ctx->error = CHTTP_ERR_TLS_HANDSHAKE;
		return;
	}

	return;
}

void
chttp_openssl_close(struct chttp_context *ctx)
{
	SSL *ssl;

	chttp_context_ok(ctx);

	if (!ctx->tls_priv) {
		return;
	}

	chttp_openssl_connected(ctx, ssl);

	SSL_free(ssl);

	ctx->tls_priv = NULL;
}

void
chttp_openssl_write(struct chttp_context *ctx, void *buf, size_t buf_len)
{
	SSL *ssl;
	size_t bytes;
	int ret;

	chttp_context_ok(ctx);
	chttp_openssl_connected(ctx, ssl);
	assert(buf);
	assert(buf_len);

	ret = SSL_write_ex(ssl, buf, buf_len, &bytes);
	assert(ret > 0);
	assert(bytes == buf_len);
}

size_t
chttp_openssl_read(struct chttp_context *ctx, void *buf, size_t buf_len, int *error)
{
	SSL *ssl;
	size_t bytes;
	int ret, ssl_ret;

	chttp_context_ok(ctx);
	chttp_openssl_connected(ctx, ssl);
	assert(buf);
	assert(buf_len);
	assert(error);

	*error = 0;

	ret = SSL_read_ex(ssl, buf, buf_len, &bytes);
	ssl_ret = SSL_get_error(ssl, ret);

	if (ssl_ret == SSL_ERROR_ZERO_RETURN) {
		assert_zero(bytes);
	} else if (ret <= 0) {
		*error = 1;
	}

	return bytes;
}