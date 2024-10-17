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

struct chttp_openssl_ctx {
	unsigned int					magic;
#define CHTTP_OPENSSL_CTX_MAGIC				0x74FF28FB

	pthread_mutex_t					lock;

	int						initialized;
	int						failed;

	SSL_CTX						*client_ctx;
	SSL_CTX						*server_ctx;
};

struct chttp_openssl_ctx _OPENSSL_CTX = {
	CHTTP_OPENSSL_CTX_MAGIC,
	PTHREAD_MUTEX_INITIALIZER,
	0,
	0,
	NULL,
	NULL
};

#define chttp_openssl_ctx_ok()							\
	do {									\
		assert(_OPENSSL_CTX.magic == CHTTP_OPENSSL_CTX_MAGIC);		\
	} while (0)
#define chttp_openssl_connected(addr, ssl_ctx)					\
	do {									\
		chttp_addr_ok(addr);						\
		assert((addr)->tls_priv);					\
		ssl_ctx = (SSL*)((addr)->tls_priv);				\
	} while (0)

static void
_openssl_init(void)
{
	int ret;

	chttp_openssl_ctx_ok();
	assert_zero(_OPENSSL_CTX.client_ctx);
	assert_zero(_OPENSSL_CTX.server_ctx);
	assert_zero(_OPENSSL_CTX.initialized);
	assert_zero(_OPENSSL_CTX.failed);

	// TODO split these inits out

	_OPENSSL_CTX.client_ctx = SSL_CTX_new(TLS_client_method());
	if (!_OPENSSL_CTX.client_ctx) {
		_OPENSSL_CTX.failed = 1;
		return;
	}

	_OPENSSL_CTX.server_ctx = SSL_CTX_new(TLS_server_method());
	if (!_OPENSSL_CTX.server_ctx) {
		_OPENSSL_CTX.failed = 1;

		SSL_CTX_free(_OPENSSL_CTX.client_ctx);
		_OPENSSL_CTX.client_ctx = NULL;

		return;
	}

	// TODO set various TLS settings

	ret = chttp_openssl_test_key(_OPENSSL_CTX.server_ctx);

	if (ret) {
		_OPENSSL_CTX.failed = 1;

		SSL_CTX_free(_OPENSSL_CTX.client_ctx);
		SSL_CTX_free(_OPENSSL_CTX.server_ctx);
		_OPENSSL_CTX.client_ctx = NULL;
		_OPENSSL_CTX.server_ctx = NULL;

		return;
	}

	_OPENSSL_CTX.initialized = 1;
}

static void
_openssl_init_lock(void)
{
	chttp_openssl_ctx_ok();

	if (!_OPENSSL_CTX.initialized) {
		assert_zero(pthread_mutex_lock(&_OPENSSL_CTX.lock));
		if (!_OPENSSL_CTX.initialized && !_OPENSSL_CTX.failed) {
			_openssl_init();
		}
		assert_zero(pthread_mutex_unlock(&_OPENSSL_CTX.lock));
	}
	assert(_OPENSSL_CTX.initialized || _OPENSSL_CTX.failed);
}

void
chttp_openssl_free(void)
{
	chttp_openssl_ctx_ok();

	assert_zero(pthread_mutex_lock(&_OPENSSL_CTX.lock));

	if (_OPENSSL_CTX.initialized && !_OPENSSL_CTX.failed) {
		assert(_OPENSSL_CTX.client_ctx);
		assert(_OPENSSL_CTX.server_ctx);

		SSL_CTX_free(_OPENSSL_CTX.client_ctx);
		SSL_CTX_free(_OPENSSL_CTX.server_ctx);

		_OPENSSL_CTX.client_ctx = NULL;
		_OPENSSL_CTX.server_ctx = NULL;
		_OPENSSL_CTX.failed = 1;
	}

	assert_zero(pthread_mutex_unlock(&_OPENSSL_CTX.lock));
}

void
chttp_openssl_connect(struct chttp_addr *addr)
{
	SSL *ssl;
	int ret;

	chttp_openssl_ctx_ok();
	chttp_addr_connected(addr);
	assert(addr->tls);
	assert_zero(addr->tls_priv);

	_openssl_init_lock();

	if (_OPENSSL_CTX.failed) {
		chttp_tcp_error(addr, CHTTP_ERR_TLS_INIT);
		return;
	}
	assert(_OPENSSL_CTX.client_ctx);

	addr->tls_priv = SSL_new(_OPENSSL_CTX.client_ctx);

	if (!addr->tls_priv) {
		chttp_tcp_error(addr, CHTTP_ERR_TLS_INIT);
		return;
	}

	chttp_openssl_connected(addr, ssl);

	SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL); // TODO

	ret = SSL_set_fd(ssl, addr->sock);

	if (ret != 1) {
		chttp_tcp_error(addr, CHTTP_ERR_TLS_INIT);
		return;
	}

	SSL_set_connect_state(ssl);

	ret = SSL_do_handshake(ssl);

	if (ret != 1) {
		chttp_tcp_error(addr, CHTTP_ERR_TLS_HANDSHAKE);
		return;
	}

	return;
}

void
chttp_openssl_accept(struct chttp_addr *addr)
{
	SSL *ssl;
	int ret;

	chttp_openssl_ctx_ok();
	chttp_addr_connected(addr);
	assert(addr->tls);
	assert_zero(addr->tls_priv);

	_openssl_init_lock();

	if (_OPENSSL_CTX.failed) {
		chttp_tcp_error(addr, CHTTP_ERR_TLS_INIT);
		return;
	}
	assert(_OPENSSL_CTX.server_ctx);

	addr->tls_priv = SSL_new(_OPENSSL_CTX.server_ctx);

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

	SSL_set_accept_state(ssl);

	ret = SSL_do_handshake(ssl);

	if (ret != 1) {
		chttp_tcp_error(addr, CHTTP_ERR_TLS_HANDSHAKE);
		return;
	}

	return;
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
