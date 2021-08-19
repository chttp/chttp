/*
 * Copyright (c) 2021 chttp
 *
 */

#include "test/chttp_test.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

enum _server_cmds {
	_SERVER_CMD_LISTEN = 1
};

struct _server_cmdentry {
	unsigned int				magic;
#define _SERVER_CMDENTRY			0xA50DBA3C

	TAILQ_ENTRY(_server_cmdentry)		entry;

	enum _server_cmds			cmd;
};

struct chttp_test_server {
	unsigned int				magic;
#define _TEST_SERVER				0xF3969B6A

	struct chttp_text_context		*ctx;

	pthread_t				thread;

	pthread_mutex_t				cmd_lock;
        pthread_cond_t				cmd_signal;
	TAILQ_HEAD(, _server_cmdentry)		cmd_list;

	volatile int				stop;

	unsigned int				started:1;
	unsigned int				stopped:1;
};

#define _server_ok(server)						\
	do {								\
		assert(server);						\
		assert((server)->magic == _TEST_SERVER);		\
	} while (0)

static void *_server_thread(void *arg);

inline struct chttp_test_server *
_server_context_ok(struct chttp_text_context *ctx)
{
	assert(ctx);
	chttp_test_ERROR(!ctx->server, "server context does not exist");
	_server_ok(ctx->server);
	return ctx->server;
}

static void
_server_cmdentry_free(struct _server_cmdentry *cmdentry)
{
	assert(cmdentry);
	assert(cmdentry->magic == _SERVER_CMDENTRY);

	cmdentry->magic = 0;
	free(cmdentry);
}

static struct _server_cmdentry *
_server_cmdentry_alloc(enum _server_cmds cmd)
{
	struct _server_cmdentry *cmdentry;

	cmdentry = malloc(sizeof(*cmdentry));
	assert(cmdentry);

	cmdentry->magic = _SERVER_CMDENTRY;
	cmdentry->cmd = cmd;

	return cmdentry;
}

static void
_server_finish(struct chttp_text_context *ctx)
{
	struct chttp_test_server *server;
	struct _server_cmdentry *cmdentry, *temp;

	server = _server_context_ok(ctx);

	assert_zero(pthread_mutex_lock(&server->cmd_lock));

	assert_zero(server->stopped);
	server->stop = 1;

	// Signal the thread stop
	assert_zero(pthread_cond_signal(&server->cmd_signal));

	assert_zero(pthread_mutex_unlock(&server->cmd_lock));

	// Join the thread
	assert_zero(pthread_join(server->thread, NULL));
	assert(server->stopped);

	chttp_test_log(ctx, CHTTP_LOG_VERY_VERBOSE, "server thread joined");

	pthread_mutex_destroy(&server->cmd_lock);
	pthread_cond_destroy(&server->cmd_signal);

	TAILQ_FOREACH_SAFE(cmdentry, &server->cmd_list, entry, temp) {
		assert(cmdentry->magic == _SERVER_CMDENTRY);

		TAILQ_REMOVE(&server->cmd_list, cmdentry, entry);

		chttp_test_log(ctx, CHTTP_LOG_VERY_VERBOSE, "server unfinished cmd found %d",
			cmdentry->cmd);

		_server_cmdentry_free(cmdentry);
	}

	assert(TAILQ_EMPTY(&server->cmd_list));

	server->magic = 0;

	free(server);
	ctx->server = NULL;
}

void
chttp_test_cmd_server_init(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_test_server *server;

	assert(ctx);
	chttp_test_ERROR_param_count(cmd, 0);
	chttp_test_ERROR(ctx->server != NULL, "server context exists");

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

void
chttp_test_cmd_server_listen(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_test_server *server;
	struct _server_cmdentry *cmdentry;

	server = _server_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, 0);

	cmdentry = _server_cmdentry_alloc(_SERVER_CMD_LISTEN);

	assert_zero(pthread_mutex_lock(&server->cmd_lock));

	TAILQ_INSERT_TAIL(&server->cmd_list, cmdentry, entry);

	assert_zero(pthread_cond_signal(&server->cmd_signal));

	assert_zero(pthread_mutex_unlock(&server->cmd_lock));
}

static void *
_server_thread(void *arg)
{
	struct chttp_test_server *server = arg;
	struct _server_cmdentry *cmdentry;

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
		assert(!TAILQ_EMPTY(&server->cmd_list));
		cmdentry = TAILQ_FIRST(&server->cmd_list);
		assert(cmdentry && cmdentry->magic == _SERVER_CMDENTRY);
		TAILQ_REMOVE(&server->cmd_list, cmdentry, entry);

		assert_zero(pthread_mutex_unlock(&server->cmd_lock));

		chttp_test_log(server->ctx, CHTTP_LOG_VERY_VERBOSE, "server thread cmd %d",
			cmdentry->cmd);

		_server_cmdentry_free(cmdentry);

		assert_zero(pthread_mutex_lock(&server->cmd_lock));
	}

	assert_zero(server->stopped);
	server->stopped = 1;

	assert_zero(pthread_mutex_unlock(&server->cmd_lock));

	chttp_test_log(server->ctx, CHTTP_LOG_VERY_VERBOSE, "server thread finished");

	return NULL;
}