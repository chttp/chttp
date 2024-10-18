/*
 * Copyright (c) 2024 chttp
 *
 */

#include "chttp.h"
#include "tls_openssl_test_key.h"
#include "tls_openssl.h"

#ifdef CHTTP_OPENSSL

#include <openssl/ssl.h>
#include <pthread.h>

enum chttp_openssl_type {
	CHTTP_OPENSSL_NONE = 0,
	CHTTP_OPENSSL_CLIENT,
	CHTTP_OPENSSL_SERVER
};

struct chttp_openssl_ctx {
	unsigned int					magic;
#define CHTTP_OPENSSL_CTX_MAGIC				0x74FF28FB

	pthread_mutex_t					lock;

	enum chttp_openssl_type				type;

	int						initialized;
	int						failed;

	SSL_CTX						*ssl_ctx;
};

struct chttp_openssl_ctx _OPENSSL_CLIENT_CTX = {
	CHTTP_OPENSSL_CTX_MAGIC,
	PTHREAD_MUTEX_INITIALIZER,
	CHTTP_OPENSSL_CLIENT,
	0,
	0,
	NULL
};

struct chttp_openssl_ctx _OPENSSL_SERVER_CTX = {
	CHTTP_OPENSSL_CTX_MAGIC,
	PTHREAD_MUTEX_INITIALIZER,
	CHTTP_OPENSSL_SERVER,
	0,
	0,
	NULL
};

#define chttp_openssl_ctx_ok(ctx)						\
	do {									\
		assert((ctx)->magic == CHTTP_OPENSSL_CTX_MAGIC);		\
		assert((ctx)->type > CHTTP_OPENSSL_NONE);			\
	} while (0)
#define chttp_openssl_connected(addr, ssl_ctx)					\
	do {									\
		chttp_addr_ok(addr);						\
		assert((addr)->tls_priv);					\
		ssl_ctx = (SSL*)((addr)->tls_priv);				\
	} while (0)

static void
_openssl_init(struct chttp_openssl_ctx *ctx)
{
	const SSL_METHOD *method = NULL;

	chttp_openssl_ctx_ok(ctx);
	assert_zero(ctx->ssl_ctx);
	assert_zero(ctx->initialized);
	assert_zero(ctx->failed);

	switch (ctx->type) {
		case CHTTP_OPENSSL_CLIENT:
			method = TLS_client_method();
			break;
		case CHTTP_OPENSSL_SERVER:
			method = TLS_server_method();
			break;
		default:
			chttp_ABORT("bad openssl ctx type");
	}

	assert(method);

	ctx->ssl_ctx = SSL_CTX_new(method);

	if (!ctx->ssl_ctx) {
		ctx->failed = 1;
		return;
	}

	// TODO set various client TLS settings

	if (ctx->type == CHTTP_OPENSSL_SERVER) {
		chttp_openssl_test_key(ctx->ssl_ctx);
	}

	ctx->initialized = 1;
}

static void
_openssl_init_lock(struct chttp_openssl_ctx *ctx)
{
	chttp_openssl_ctx_ok(ctx);

	if (!ctx->initialized) {
		assert_zero(pthread_mutex_lock(&ctx->lock));
		if (!ctx->initialized && !ctx->failed) {
			_openssl_init(ctx);
		}
		assert_zero(pthread_mutex_unlock(&ctx->lock));
	}
	assert(ctx->initialized || ctx->failed);
}

void
_openssl_free(struct chttp_openssl_ctx *ctx)
{
	chttp_openssl_ctx_ok(ctx);

	assert_zero(pthread_mutex_lock(&ctx->lock));

	if (ctx->initialized) {
		assert(ctx->ssl_ctx);

		SSL_CTX_free(ctx->ssl_ctx);
		ctx->ssl_ctx = NULL;

		ctx->failed = 1;
	}

	assert_zero(ctx->ssl_ctx);

	assert_zero(pthread_mutex_unlock(&ctx->lock));
}

void
chttp_openssl_free(void)
{
	_openssl_free(&_OPENSSL_CLIENT_CTX);
	_openssl_free(&_OPENSSL_SERVER_CTX);
}

void
_openssl_bind(struct chttp_addr *addr, struct chttp_openssl_ctx *ctx)
{
	SSL *ssl;
	int ret;

	chttp_addr_connected(addr);
	assert(addr->tls);
	assert_zero(addr->tls_priv);
	assert_zero(addr->nonblocking);
	chttp_openssl_ctx_ok(ctx);
	assert(ctx->type);

	_openssl_init_lock(ctx);

	if (ctx->failed) {
		chttp_tcp_error(addr, CHTTP_ERR_TLS_INIT);
		return;
	}
	assert(ctx->ssl_ctx);

	addr->tls_priv = SSL_new(ctx->ssl_ctx);

	if (!addr->tls_priv) {
		chttp_tcp_error(addr, CHTTP_ERR_TLS_INIT);
		return;
	}

	chttp_openssl_connected(addr, ssl);

	ret = SSL_set_fd(ssl, addr->sock);

	if (ret != 1) {
		chttp_tcp_error(addr, CHTTP_ERR_TLS_INIT);
		return;
	}

	switch (ctx->type) {
		case CHTTP_OPENSSL_CLIENT:
			SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL); // TODO
			SSL_set_connect_state(ssl);

			break;
		case CHTTP_OPENSSL_SERVER:
			SSL_set_accept_state(ssl);

			break;
		default:
			chttp_ABORT("bad openssl ctx type");
	}

	ret = SSL_do_handshake(ssl);

	if (ret != 1) {
		chttp_tcp_error(addr, CHTTP_ERR_TLS_HANDSHAKE);
		return;
	}

	return;
}

void
chttp_openssl_connect(struct chttp_addr *addr)
{
	_openssl_bind(addr, &_OPENSSL_CLIENT_CTX);
}

void
chttp_openssl_accept(struct chttp_addr *addr)
{
	_openssl_bind(addr, &_OPENSSL_SERVER_CTX);
}

void
chttp_openssl_close(struct chttp_addr *addr)
{
	SSL *ssl;

	chttp_addr_ok(addr);

	if (!addr->tls_priv) {
		return;
	}

	ssl = (SSL*)addr->tls_priv;

	SSL_free(ssl);

	addr->tls_priv = NULL;
}

void
chttp_openssl_write(struct chttp_addr *addr, const void *buf, size_t buf_len)
{
	SSL *ssl;
	size_t bytes;
	int ret;

	chttp_addr_connected(addr);
	chttp_openssl_connected(addr, ssl);
	assert(buf);
	assert(buf_len);

	ret = SSL_write_ex(ssl, buf, buf_len, &bytes);

	if (ret <= 0) {
		chttp_tcp_error(addr, CHTTP_ERR_NETWORK);
		return;
	}

	assert(bytes == buf_len);
}

size_t
chttp_openssl_read(struct chttp_addr *addr, void *buf, size_t buf_len)
{
	SSL *ssl;
	size_t bytes;
	int ret, ssl_ret;

	chttp_addr_connected(addr);
	chttp_openssl_connected(addr, ssl);
	assert(buf);
	assert(buf_len);

	ret = SSL_read_ex(ssl, buf, buf_len, &bytes);
	ssl_ret = SSL_get_error(ssl, ret);

	if (ssl_ret == SSL_ERROR_ZERO_RETURN) {
		assert_zero(bytes);
	} else if (ret <= 0) {
		chttp_tcp_error(addr, CHTTP_ERR_NETWORK);

		return 0;
	}

	return bytes;
}

#endif /* CHTTP_OPENSSL */
