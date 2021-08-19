/*
 * Copyright (c) 2021 chttp
 *
 */

#include "test/chttp_test.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

struct _server_cmd {
	unsigned int				magic;
#define _SERVER_CMD				0xA50DBA3C

	TAILQ_ENTRY(_server_cmd)		entry;
};

struct chttp_test_server {
	unsigned int				magic;
#define _TEST_SERVER				0xF3969B6A

	struct chttp_text_context		*ctx;

	pthread_t				thread;

	pthread_mutex_t				cmd_lock;
        pthread_cond_t				cmd_signal;
	TAILQ_HEAD(, _server_cmd)		cmd_list;

	volatile int				stop;

	unsigned int				started:1;
	unsigned int				stopped:1;
};

#define _server_ok(server)						\
	do {								\
		assert(server);						\
		assert((server)->magic == _TEST_SERVER);		\
	} while (0)

static void
_server_finish(struct chttp_text_context *ctx)
{
	assert(ctx);
	_server_ok(ctx->server);

	assert_zero(pthread_mutex_lock(&ctx->server->cmd_lock));

	assert_zero(ctx->server->stopped);
	ctx->server->stop = 1;

	// Signal the thread stop
	assert_zero(pthread_cond_signal(&ctx->server->cmd_signal));

	assert_zero(pthread_mutex_unlock(&ctx->server->cmd_lock));

	// Join the thread
	assert_zero(pthread_join(ctx->server->thread, NULL));
	assert(ctx->server->stopped);

	chttp_test_log(ctx, CHTTP_LOG_VERY_VERBOSE, "server thread joined");

	pthread_mutex_destroy(&ctx->server->cmd_lock);
	pthread_cond_destroy(&ctx->server->cmd_signal);

	ctx->server->magic = 0;

	free(ctx->server);
	ctx->server = NULL;
}

static void *
_server_thread(void *arg)
{
	struct chttp_test_server *server = arg;

	_server_ok(server);

	assert_zero(pthread_mutex_lock(&server->cmd_lock));

	// Ack the server init
	server->started = 1;
	assert_zero(pthread_cond_signal(&server->cmd_signal));

	chttp_test_log(server->ctx, CHTTP_LOG_VERY_VERBOSE, "server thread started");

	while (!server->stop) {
		if (TAILQ_EMPTY(&server->cmd_list)) {
			assert_zero(pthread_cond_wait(&server->cmd_signal, &server->cmd_lock));
			continue;
		}

		// Grab work

		assert_zero(pthread_mutex_unlock(&server->cmd_lock));

		// Do work unlocked

		assert_zero(pthread_mutex_lock(&server->cmd_lock));
	}

	assert_zero(server->stopped);
	server->stopped = 1;

	assert_zero(pthread_mutex_unlock(&server->cmd_lock));

	chttp_test_log(server->ctx, CHTTP_LOG_VERY_VERBOSE, "server thread finished");

	return NULL;
}

void
chttp_test_cmd_server_init(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_test_server *server;

	assert(ctx);
	chttp_test_ERROR_param_count(cmd, 0);

	server = malloc(sizeof(*server));
	assert(server);

	memset(server, 0, sizeof(*server));

	server->magic = _TEST_SERVER;
	server->ctx = ctx;
	TAILQ_INIT(&server->cmd_list);
	assert_zero(pthread_mutex_init(&server->cmd_lock, NULL));
	assert_zero(pthread_cond_init(&server->cmd_signal, NULL));

	assert_zero(pthread_mutex_lock(&server->cmd_lock));

	// Start the server thread
	assert_zero(pthread_create(&server->thread, NULL, _server_thread, server));

	// Wait for it to ack
	assert_zero(server->started);
	assert_zero(pthread_cond_wait(&server->cmd_signal, &server->cmd_lock));
	assert(server->started);

	assert_zero(pthread_mutex_unlock(&server->cmd_lock));

	ctx->server = server;

	chttp_test_register_finish(ctx, "server", _server_finish);

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "server init completed");
}