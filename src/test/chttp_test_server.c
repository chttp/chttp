/*
 * Copyright (c) 2021 chttp
 *
 */

#include "test/chttp_test.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define _SERVER_IP				"127.0.0.1"
#define _SERVER_JOIN_TIMEOUT_MS			2500

struct chttp_test_server;

typedef void (chttp_test_cmd_async_f)(struct chttp_test_server*, struct chttp_test_cmd*);

struct _server_cmdentry {
	unsigned int				magic;
#define _SERVER_CMDENTRY			0xA50DBA3C

	TAILQ_ENTRY(_server_cmdentry)		entry;

	struct chttp_test_cmd			cmd;

	chttp_test_cmd_async_f			*func;
};

struct chttp_test_server {
	unsigned int				magic;
#define _SERVER_MAGIC				0xF3969B6A

	struct chttp_text_context		*ctx;

	pthread_t				thread;

	pthread_mutex_t				cmd_lock;
	pthread_cond_t				cmd_signal;
	TAILQ_HEAD(, _server_cmdentry)		cmd_list;

	volatile int				stop;
	volatile int				started;
	volatile int				stopped;

	int					sock;
	int					port;
	int					http_sock;
	char					port_str[16];

	struct chttp_context			*context;
};

#define _server_ok(server)						\
	do {								\
		assert(server);						\
		assert((server)->magic == _SERVER_MAGIC);		\
	} while (0)

extern const char *_CHTTP_HEADER_FIRST;

static void *_server_thread(void *arg);

static inline struct chttp_test_server *
_server_context_ok(struct chttp_text_context *ctx)
{
	assert(ctx);
	chttp_test_ERROR(!ctx->server, "server context does not exist");
	_server_ok(ctx->server);
	return ctx->server;
}

static inline void
_server_LOCK(struct chttp_test_server *server)
{
	_server_ok(server);
	assert_zero(pthread_mutex_lock(&server->cmd_lock));
}

static inline void
_server_UNLOCK(struct chttp_test_server *server)
{
	_server_ok(server);
	assert_zero(pthread_mutex_unlock(&server->cmd_lock));
}

static inline void
_server_SIGNAL(struct chttp_test_server *server)
{
	_server_ok(server);
	assert_zero(pthread_cond_signal(&server->cmd_signal));
}

static inline void
_server_WAIT(struct chttp_test_server *server)
{
	_server_ok(server);
	assert_zero(pthread_cond_wait(&server->cmd_signal, &server->cmd_lock));
}

static void
_server_cmdentry_free(struct _server_cmdentry *cmdentry)
{
	size_t i;

	assert(cmdentry);
	assert(cmdentry->magic == _SERVER_CMDENTRY);

	free((char*)cmdentry->cmd.name);

	for (i = 0; i < cmdentry->cmd.param_count; i++) {
		free((char*)cmdentry->cmd.params[i]);
	}

	cmdentry->magic = 0;

	free(cmdentry);
}

static struct _server_cmdentry *
_server_cmdentry_alloc()
{
	struct _server_cmdentry *cmdentry;

	cmdentry = malloc(sizeof(*cmdentry));
	assert(cmdentry);

	memset(cmdentry, 0, sizeof(*cmdentry));

	cmdentry->magic = _SERVER_CMDENTRY;

	return cmdentry;
}

static void
_server_cmd_send_async(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd,
    size_t params, chttp_test_cmd_async_f *func)
{
	struct chttp_test_server *server;
	struct _server_cmdentry *cmdentry;
	size_t i;

	server = _server_context_ok(ctx);
	chttp_test_ERROR_param_count(cmd, params);

	cmdentry = _server_cmdentry_alloc();

	cmdentry->cmd.name = strdup(cmd->name);
	cmdentry->cmd.param_count = params;
	cmdentry->func = func;

	for (i = 0; i < params; i++) {
		assert(i < cmd->param_count);
		chttp_test_ERROR_string(cmd->params[i]);

		cmdentry->cmd.params[i] = strdup(cmd->params[i]);
	}

	_server_LOCK(server);

	TAILQ_INSERT_TAIL(&server->cmd_list, cmdentry, entry);

	_server_SIGNAL(server);
	_server_UNLOCK(server);
}

static void
_server_finish(struct chttp_text_context *ctx)
{
	struct chttp_test_server *server;
	struct _server_cmdentry *cmdentry, *temp;
	int ret;

	server = _server_context_ok(ctx);

	_server_LOCK(server);

	assert(server->started);
	assert_zero(server->stop);
	assert_zero(server->stopped);
	server->stop = 1;

	_server_SIGNAL(server);
	_server_UNLOCK(server);

	ret = chttp_test_join_thread(server->thread, &server->stopped, _SERVER_JOIN_TIMEOUT_MS);
	chttp_test_ERROR(ret, "server thread is blocked");

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

	if (server->context) {
		chttp_test_ERROR(server->context->error, "server error detected (%s)",
			chttp_error_msg(server->context));

		server->context->state = CHTTP_STATE_DONE;

		chttp_context_free(server->context);
		server->context = NULL;
	}

	if (server->sock >= 0) {
		close(server->sock);
	}
	if (server->http_sock >= 0) {
		close(server->http_sock);
	}

	server->magic = 0;

	free(server);
	ctx->server = NULL;
}

static void
_server_init_socket(struct chttp_test_server *server)
{
	struct chttp_context *chttp;
	char chttp_buf[CHTTP_CTX_SIZE];
	struct sockaddr_storage saddr;
	struct sockaddr *addr;
	socklen_t len;
	int val;

	_server_ok(server);
	assert(server->sock == -1);

	chttp_context_init_buf(chttp_buf, sizeof(chttp_buf));
	chttp = (struct chttp_context*)chttp_buf;

	chttp_dns_lookup(chttp, _SERVER_IP, 0);
	assert(chttp->addr.magic == CHTTP_ADDR_MAGIC);

	server->sock = socket(chttp->addr.sa.sa_family, SOCK_STREAM, 0);
	assert(server->sock >= 0);

	val = 1;
	assert_zero(setsockopt(server->sock, SOL_SOCKET, SO_REUSEADDR,
		&val, sizeof(val)));

	assert_zero(bind(server->sock, &chttp->addr.sa, chttp->addr.len));
	assert_zero(listen(server->sock, 1));

	addr = (struct sockaddr*)&saddr;
	len = sizeof(saddr);

	assert_zero(getsockname(server->sock, addr, &len));
	assert(addr->sa_family == chttp->addr.sa.sa_family);

	switch (addr->sa_family) {
		case AF_INET:
			server->port = ntohs(((struct sockaddr_in*)addr)->sin_port);
			break;
		case AF_INET6:
			server->port = ntohs(((struct sockaddr_in6*)addr)->sin6_port);
			break;
		default:
			chttp_test_ERROR(1, "Invalid server socket family");
	}

	assert(server->port >= 0);
	snprintf(server->port_str, sizeof(server->port_str), "%d", server->port);

	chttp_test_log(server->ctx, CHTTP_LOG_VERY_VERBOSE, "server socket port: %d",
		server->port);

	chttp_context_free(chttp);
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

	server->magic = _SERVER_MAGIC;
	server->ctx = ctx;
	server->sock = -1;
	server->port = -1;
	server->http_sock = -1;
	TAILQ_INIT(&server->cmd_list);
	assert_zero(pthread_mutex_init(&server->cmd_lock, NULL));
	assert_zero(pthread_cond_init(&server->cmd_signal, NULL));

	_server_LOCK(server);

	// Start the server thread
	assert_zero(pthread_create(&server->thread, NULL, _server_thread, server));

	// Wait for it to ack
	assert_zero(server->started);
	_server_WAIT(server);
	assert(server->started);

	_server_UNLOCK(server);

	_server_init_socket(server);

	ctx->server = server;

	chttp_test_register_finish(ctx, "server", _server_finish);

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "server init completed");
}

static void
_server_accept(struct chttp_test_server *server, struct chttp_test_cmd *cmd)
{
	struct sockaddr_storage saddr;
	struct sockaddr *addr;
	socklen_t len;
	char remote[128] = {0};
	int remote_port = -1;

	_server_ok(server);
	assert(server->sock >= 0);
	assert(server->port >= 0);
	assert(server->http_sock == -1);
	assert(cmd);

	addr = (struct sockaddr*)&saddr;
	len = sizeof(saddr);

	server->http_sock = accept(server->sock, addr, &len);
	assert(server->http_sock >= 0);

	switch (addr->sa_family) {
		case AF_INET:
			inet_ntop(AF_INET, &(((struct sockaddr_in*)addr)->sin_addr),
				remote, sizeof(remote));
			remote_port = ntohs(((struct sockaddr_in*)addr)->sin_port);
			break;
		case AF_INET6:
			inet_ntop(AF_INET6, &(((struct sockaddr_in6*)addr)->sin6_addr),
				remote, sizeof(remote));
			remote_port = ntohs(((struct sockaddr_in6*)addr)->sin6_port);
			break;
		default:
			chttp_test_ERROR(1, "Invalid server remote family");
	}

	chttp_test_log(server->ctx, CHTTP_LOG_VERY_VERBOSE, "server remote client %s:%d",
		remote, remote_port);
}

void
chttp_test_cmd_server_accept(struct chttp_text_context *ctx, struct chttp_test_cmd *cmd)
{
	_server_cmd_send_async(ctx, cmd, 0, &_server_accept);
}

char *
chttp_test_var_server_host(struct chttp_text_context *ctx)
{
	struct chttp_test_server *server;

	server = _server_context_ok(ctx);
	assert(server->sock >= 0);

	return _SERVER_IP;
}

char *
chttp_test_var_server_port(struct chttp_text_context *ctx)
{
	struct chttp_test_server *server;

	server = _server_context_ok(ctx);
	assert(server->port >= 0);

	return server->port_str;
}

static void
_server_parse_request_url(struct chttp_context *ctx, size_t start, size_t end)
{
	struct chttp_dpage *data;
	size_t len, count, i;

	chttp_context_ok(ctx);
	chttp_dpage_ok(ctx->data_last);

	data = ctx->data_last;
	len = end - start;

	assert(strlen((char*)&data->data[start]) == len);

	for (i = start, count = 0; i < end; i++) {
		if (data->data[i] < ' ') {
			ctx->error = CHTTP_ERR_RESP_PARSE;
			return;
		} else if (data->data[i] == ' ') {
			data->data[i] = '\0';
			count++;

			if (data->data[i + 1] <= ' ') {
				ctx->error = CHTTP_ERR_RESP_PARSE;
				return;
			}
		}
	}

	if (count != 2) {
		ctx->error = CHTTP_ERR_RESP_PARSE;
		return;
	}
}

static void
_server_read_headers(struct chttp_test_server *server, struct chttp_test_cmd *cmd)
{
	_server_ok(server);
	assert(server->http_sock >= 0);
	assert_zero(server->context);
	assert(cmd);

	server->context = chttp_context_alloc();
	server->context->state = CHTTP_STATE_RESP_HEADERS;

	chttp_tcp_import(server->context, server->http_sock);

	do {
		chttp_tcp_read(server->context);
		chttp_test_ERROR(server->context->state == CHTTP_STATE_DONE,
			"network error");

		chttp_parse(server->context, &_server_parse_request_url);
		chttp_test_ERROR(server->context->error, "%s",
			chttp_error_msg(server->context));
	} while (server->context->state == CHTTP_STATE_RESP_HEADERS);

	assert_zero(server->context->error);
	assert(server->context->state == CHTTP_STATE_RESP_BODY);

	chttp_body_length(server->context, 0);

	server->context->state = CHTTP_STATE_IDLE;

	server->http_sock = server->context->addr.sock;
	server->context->addr.sock = -1;
}

void
chttp_test_cmd_server_read_headers(struct chttp_text_context *ctx,
    struct chttp_test_cmd *cmd)
{
	_server_cmd_send_async(ctx, cmd, 0, &_server_read_headers);
}

static void
_server_match_header(struct chttp_test_server *server, struct chttp_test_cmd *cmd)
{
	const char *header, *header_value, *expected;
	size_t len;
	int sub = 0;

	_server_ok(server);
	chttp_context_ok(server->context);
	assert(cmd);
	assert(cmd->name);

	header = header_value = expected = NULL;

	if (!strcmp(cmd->name, "server_method_match")) {
		assert(cmd->param_count == 1);

		header = "_METHOD";
		expected = cmd->params[0];
		header_value = chttp_get_header(server->context, _CHTTP_HEADER_FIRST);
	} else if (!strcmp(cmd->name, "server_url_match")) {
		assert(cmd->param_count == 1);

		header = "_URL";
		expected = cmd->params[0];

		header_value = chttp_get_header(server->context, _CHTTP_HEADER_FIRST);
		assert(header_value);
		len = strlen(header_value);
		header_value += len + 1;
	} else if (!strcmp(cmd->name, "server_header_match")) {
		assert(cmd->param_count == 2);

		header = cmd->params[0];
		expected = cmd->params[1];
		header_value = chttp_get_header(server->context, header);
	} else if (!strcmp(cmd->name, "server_header_submatch")) {
		assert(cmd->param_count == 2);

		header = cmd->params[0];
		expected = cmd->params[1];
		header_value = chttp_get_header(server->context, header);
		sub = 1;
	} else {
		assert_zero("INVALID SERVER MATCH");
	}

	chttp_test_ERROR(!header_value, "header %s not found", header);

	if (sub) {
		chttp_test_ERROR(!strstr(header_value, expected), "value %s not found in header %s:%s",
			expected, header, header_value);
	} else {
		chttp_test_ERROR(strcmp(header_value, expected), "headers dont match, found %s:%s, "
			"expected %s", header, header_value, expected);
	}

	chttp_test_log(server->ctx, CHTTP_LOG_VERY_VERBOSE, "headers match %s:%s",
		header, header_value);
}

void
chttp_test_cmd_server_method_match(struct chttp_text_context *ctx,
    struct chttp_test_cmd *cmd)
{
	_server_cmd_send_async(ctx, cmd, 1, &_server_match_header);
}

void
chttp_test_cmd_server_url_match(struct chttp_text_context *ctx,
    struct chttp_test_cmd *cmd)
{
	_server_cmd_send_async(ctx, cmd, 1, &_server_match_header);
}

void
chttp_test_cmd_server_header_match(struct chttp_text_context *ctx,
    struct chttp_test_cmd *cmd)
{
	_server_cmd_send_async(ctx, cmd, 2, &_server_match_header);
}

void
chttp_test_cmd_server_header_submatch(struct chttp_text_context *ctx,
    struct chttp_test_cmd *cmd)
{
	_server_cmd_send_async(ctx, cmd, 2, &_server_match_header);
}

static void
_server_send_response(struct chttp_test_server *server, struct chttp_test_cmd *cmd)
{
	ssize_t ret;
	size_t len;
	char *buf;

	_server_ok(server);
	assert(server->http_sock >= 0);
	assert(cmd);

	buf = "HTTP/1.1 200 OK\r\n";
	len = strlen(buf);
	ret = send(server->http_sock, buf, len, MSG_NOSIGNAL);
	assert(ret > 0 && (size_t)ret == len);

	buf = "Content-Length: 5\r\n\r\nDONE!";
	len = strlen(buf);
	ret = send(server->http_sock, buf, len, MSG_NOSIGNAL);
	assert(ret > 0 && (size_t)ret == len);
}

void
chttp_test_cmd_server_send_response(struct chttp_text_context *ctx,
    struct chttp_test_cmd *cmd)
{
	_server_cmd_send_async(ctx, cmd, 0, &_server_send_response);
}

static void
_server_cmd(struct chttp_test_server *server, struct _server_cmdentry *cmdentry)
{
	_server_ok(server);
	assert(cmdentry);
	assert(cmdentry->magic == _SERVER_CMDENTRY);
	assert(cmdentry->func);

	cmdentry->func(server, &cmdentry->cmd);

	chttp_test_log(server->ctx, CHTTP_LOG_VERY_VERBOSE, "server thread cmd %s completed",
		cmdentry->cmd.name);
}

static void *
_server_thread(void *arg)
{
	struct chttp_test_server *server = arg;
	struct _server_cmdentry *cmdentry;

	_server_ok(server);

	_server_LOCK(server);

	// Ack the server init
	server->started = 1;
	_server_SIGNAL(server);

	chttp_test_log(server->ctx, CHTTP_LOG_VERY_VERBOSE, "server thread started");

	while (!server->stop) {
		if (TAILQ_EMPTY(&server->cmd_list)) {
			_server_WAIT(server);
			continue;
		}

		// Grab work
		assert(!TAILQ_EMPTY(&server->cmd_list));
		cmdentry = TAILQ_FIRST(&server->cmd_list);
		assert(cmdentry);
		assert(cmdentry->magic == _SERVER_CMDENTRY);
		TAILQ_REMOVE(&server->cmd_list, cmdentry, entry);

		_server_UNLOCK(server);

		_server_cmd(server, cmdentry);
		_server_cmdentry_free(cmdentry);

		_server_LOCK(server);
	}

	assert_zero(server->stopped);
	server->stopped = 1;

	_server_UNLOCK(server);

	chttp_test_log(server->ctx, CHTTP_LOG_VERY_VERBOSE, "server thread finished");

	return NULL;
}