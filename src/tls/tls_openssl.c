/*
 * Copyright (c) 2024 chttp
 *
 */

#include "chttp.h"
#include "tls.h"

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

void
_openssl_init(void)
{
	chttp_openssl_ctx_ok();
	assert_zero(_OPENSSL_CTX.initialized);

	_OPENSSL_CTX.ctx = SSL_CTX_new(TLS_client_method());
	if (!_OPENSSL_CTX.ctx) {
		_OPENSSL_CTX.failed = 1;
		return;
	}

	// TODO set various TLS settings

	_OPENSSL_CTX.initialized = 1;
}

void
chttp_openssl_init(void)
{
	chttp_openssl_ctx_ok();

	if (!_OPENSSL_CTX.initialized && !_OPENSSL_CTX.failed) {
		assert_zero(pthread_mutex_lock(&_OPENSSL_CTX.lock));
		if (!_OPENSSL_CTX.initialized && !_OPENSSL_CTX.failed) {
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